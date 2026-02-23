import childProcess from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import express from "express";
import httpProxy from "http-proxy";
import pty from "node-pty";
import { WebSocketServer } from "ws";

import radio from "./radio.js";

// Prevent unhandled rejections from crashing the process silently
process.on("unhandledRejection", (err) => {
  console.error("[wrapper] unhandled rejection:", err);
});

const PORT = Number.parseInt(process.env.PORT ?? "8080", 10);
const STATE_DIR =
  process.env.OPENCLAW_STATE_DIR?.trim() ||
  path.join(os.homedir(), ".openclaw");
const WORKSPACE_DIR =
  process.env.OPENCLAW_WORKSPACE_DIR?.trim() ||
  path.join(STATE_DIR, "workspace");

const SETUP_PASSWORD = process.env.SETUP_PASSWORD?.trim();

function resolveGatewayToken() {
  const envTok = process.env.OPENCLAW_GATEWAY_TOKEN?.trim();
  if (envTok) return envTok;

  const tokenPath = path.join(STATE_DIR, "gateway.token");
  try {
    const existing = fs.readFileSync(tokenPath, "utf8").trim();
    if (existing) return existing;
  } catch (err) {
    console.warn(
      `[gateway-token] could not read existing token: ${err.code || err.message}`,
    );
  }

  const generated = crypto.randomBytes(32).toString("hex");
  try {
    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.writeFileSync(tokenPath, generated, { encoding: "utf8", mode: 0o600 });
  } catch (err) {
    console.warn(
      `[gateway-token] could not persist token: ${err.code || err.message}`,
    );
  }
  return generated;
}

const OPENCLAW_GATEWAY_TOKEN = resolveGatewayToken();
process.env.OPENCLAW_GATEWAY_TOKEN = OPENCLAW_GATEWAY_TOKEN;

let cachedOpenclawVersion = null;
let cachedChannelsHelp = null;

async function getOpenclawInfo() {
  if (!cachedOpenclawVersion) {
    const [version, channelsHelp] = await Promise.all([
      runCmd(OPENCLAW_NODE, clawArgs(["--version"])),
      runCmd(OPENCLAW_NODE, clawArgs(["channels", "add", "--help"])),
    ]);
    cachedOpenclawVersion = version.output.trim();
    cachedChannelsHelp = channelsHelp.output;
  }
  return { version: cachedOpenclawVersion, channelsHelp: cachedChannelsHelp };
}

const INTERNAL_GATEWAY_PORT = Number.parseInt(
  process.env.INTERNAL_GATEWAY_PORT ?? "18789",
  10,
);
const INTERNAL_GATEWAY_HOST = process.env.INTERNAL_GATEWAY_HOST ?? "127.0.0.1";
const GATEWAY_TARGET = `http://${INTERNAL_GATEWAY_HOST}:${INTERNAL_GATEWAY_PORT}`;

const OPENCLAW_ENTRY =
  process.env.OPENCLAW_ENTRY?.trim() || "/openclaw/dist/entry.js";
const OPENCLAW_NODE = process.env.OPENCLAW_NODE?.trim() || "node";

const ENABLE_WEB_TUI = process.env.ENABLE_WEB_TUI?.toLowerCase() === "true";
const TUI_IDLE_TIMEOUT_MS = Number.parseInt(
  process.env.TUI_IDLE_TIMEOUT_MS ?? "300000",
  10,
);
const TUI_MAX_SESSION_MS = Number.parseInt(
  process.env.TUI_MAX_SESSION_MS ?? "1800000",
  10,
);

function clawArgs(args) {
  return [OPENCLAW_ENTRY, ...args];
}

function configPath() {
  return (
    process.env.OPENCLAW_CONFIG_PATH?.trim() ||
    path.join(STATE_DIR, "openclaw.json")
  );
}

function isConfigured() {
  try {
    return fs.existsSync(configPath());
  } catch {
    return false;
  }
}

let gatewayProc = null;
let gatewayStarting = null;
let shuttingDown = false;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForGatewayReady(opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const start = Date.now();
  const endpoints = ["/openclaw", "/", "/health"];

  while (Date.now() - start < timeoutMs) {
    for (const endpoint of endpoints) {
      const ac = new AbortController();
      const timer = setTimeout(() => ac.abort(), 3000);
      try {
        const res = await fetch(`${GATEWAY_TARGET}${endpoint}`, {
          method: "GET",
          signal: ac.signal,
        });
        clearTimeout(timer);
        if (res) {
          console.log(`[gateway] ready at ${endpoint}`);
          return true;
        }
      } catch (err) {
        clearTimeout(timer);
        if (err.name === "AbortError") continue; // fetch timed out, retry
        if (err.code !== "ECONNREFUSED" && err.cause?.code !== "ECONNREFUSED") {
          const msg = err.code || err.message;
          if (msg !== "fetch failed" && msg !== "UND_ERR_CONNECT_TIMEOUT") {
            console.warn(`[gateway] health check error: ${msg}`);
          }
        }
      }
    }
    await sleep(250);
  }
  console.error(`[gateway] failed to become ready after ${timeoutMs / 1000} seconds`);
  return false;
}

async function startGateway() {
  if (gatewayProc) return;
  if (!isConfigured()) throw new Error("Gateway cannot start: not configured");

  fs.mkdirSync(STATE_DIR, { recursive: true });
  fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

  // Skip OpenClaw's built-in gateway lock entirely — we manage the single
  // gateway process ourselves via gatewayProc.  This avoids stale lock files
  // left on the persistent volume from a previous container causing an
  // infinite "gateway already running" restart loop.
  process.env.OPENCLAW_ALLOW_MULTI_GATEWAY = "1";

  // Kill any leftover gateway processes before starting
  try {
    childProcess.execSync("pkill -f 'openclaw.*gateway' 2>/dev/null || true", { timeout: 5000 });
  } catch {}

  // Clean up ALL possible lock file locations (belt-and-suspenders).
  // OpenClaw stores locks in /tmp/openclaw-<uid>/gateway.<hash>.lock
  try {
    childProcess.execSync("rm -rf /tmp/openclaw-*/gateway.*.lock 2>/dev/null || true", { timeout: 5000 });
  } catch {}
  for (const lockPath of [
    path.join(STATE_DIR, "gateway.lock"),
    path.join(STATE_DIR, "gateway.pid"),
  ]) {
    try {
      fs.rmSync(lockPath, { force: true });
    } catch {}
  }

  const args = [
    "gateway",
    "run",
    "--bind",
    "loopback",
    "--port",
    String(INTERNAL_GATEWAY_PORT),
    "--auth",
    "token",
    "--token",
    OPENCLAW_GATEWAY_TOKEN,
    "--allow-unconfigured",
  ];

  gatewayProc = childProcess.spawn(OPENCLAW_NODE, clawArgs(args), {
    stdio: "inherit",
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: STATE_DIR,
      OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
    },
  });

  const safeArgs = args.map((arg, i) =>
    args[i - 1] === "--token" ? "[REDACTED]" : arg
  );
  console.log(
    `[gateway] starting with command: ${OPENCLAW_NODE} ${clawArgs(safeArgs).join(" ")}`,
  );
  console.log(`[gateway] STATE_DIR: ${STATE_DIR}`);
  console.log(`[gateway] WORKSPACE_DIR: ${WORKSPACE_DIR}`);
  console.log(`[gateway] config path: ${configPath()}`);

  gatewayProc.on("error", (err) => {
    console.error(`[gateway] spawn error: ${String(err)}`);
    gatewayProc = null;
  });

  gatewayProc.on("exit", (code, signal) => {
    console.error(`[gateway] exited code=${code} signal=${signal}`);
    gatewayProc = null;
    if (!shuttingDown && isConfigured()) {
      console.log("[gateway] scheduling auto-restart in 2s...");
      setTimeout(() => {
        if (!shuttingDown && !gatewayProc && isConfigured()) {
          ensureGatewayRunning().catch((err) => {
            console.error(`[gateway] auto-restart failed: ${err.message}`);
          });
        }
      }, 2000);
    }
  });
}

async function ensureGatewayRunning() {
  if (!isConfigured()) return { ok: false, reason: "not configured" };
  if (gatewayProc) return { ok: true };
  if (!gatewayStarting) {
    gatewayStarting = (async () => {
      await startGateway();
      const ready = await waitForGatewayReady({ timeoutMs: 60_000 });
      if (!ready) {
        throw new Error("Gateway did not become ready in time");
      }
    })().finally(() => {
      gatewayStarting = null;
    });
  }
  await gatewayStarting;
  return { ok: true };
}

function isGatewayStarting() {
  return gatewayStarting !== null;
}

function isGatewayReady() {
  return gatewayProc !== null && gatewayStarting === null;
}

async function restartGateway() {
  if (gatewayProc) {
    try {
      gatewayProc.kill("SIGTERM");
    } catch (err) {
      console.warn(`[gateway] kill error: ${err.message}`);
    }
    await sleep(750);
    gatewayProc = null;
  }
  return ensureGatewayRunning();
}

const setupRateLimiter = {
  attempts: new Map(),
  windowMs: 60_000,
  maxAttempts: 50,
  cleanupInterval: setInterval(function () {
    const now = Date.now();
    for (const [ip, data] of setupRateLimiter.attempts) {
      if (now - data.windowStart > setupRateLimiter.windowMs) {
        setupRateLimiter.attempts.delete(ip);
      }
    }
  }, 60_000),

  isRateLimited(ip) {
    const now = Date.now();
    const data = this.attempts.get(ip);
    if (!data || now - data.windowStart > this.windowMs) {
      this.attempts.set(ip, { windowStart: now, count: 1 });
      return false;
    }
    data.count++;
    return data.count > this.maxAttempts;
  },
};

function requireSetupAuth(req, res, next) {
  if (!SETUP_PASSWORD) {
    return res
      .status(500)
      .type("text/plain")
      .send(
        "SETUP_PASSWORD is not set. Set it in Railway Variables before using /setup.",
      );
  }

  const ip = req.ip || req.socket?.remoteAddress || "unknown";
  if (setupRateLimiter.isRateLimited(ip)) {
    return res.status(429).type("text/plain").send("Too many requests. Try again later.");
  }

  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) {
    res.set("WWW-Authenticate", 'Basic realm="OpenClaw Setup"');
    return res.status(401).send("Auth required");
  }
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const password = idx >= 0 ? decoded.slice(idx + 1) : "";
  const passwordHash = crypto.createHash("sha256").update(password).digest();
  const expectedHash = crypto.createHash("sha256").update(SETUP_PASSWORD).digest();
  const isValid = crypto.timingSafeEqual(passwordHash, expectedHash);
  if (!isValid) {
    res.set("WWW-Authenticate", 'Basic realm="OpenClaw Setup"');
    return res.status(401).send("Invalid password");
  }
  return next();
}

const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

app.get("/healthz", async (_req, res) => {
  let gateway = "unconfigured";
  if (isConfigured()) {
    gateway = isGatewayReady() ? "ready" : "starting";
  }
  res.json({ ok: true, gateway });
});


app.get("/setup/healthz", async (_req, res) => {
  const configured = isConfigured();
  const gatewayRunning = isGatewayReady();
  const starting = isGatewayStarting();
  let gatewayReachable = false;

  if (gatewayRunning) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3000);
      const r = await fetch(`${GATEWAY_TARGET}/`, { signal: controller.signal });
      clearTimeout(timeout);
      gatewayReachable = r !== null;
    } catch {}
  }

  res.json({
    ok: true,
    wrapper: true,
    configured,
    gatewayRunning,
    gatewayStarting: starting,
    gatewayReachable,
  });
});

app.get("/setup", requireSetupAuth, (_req, res) => {
  res.sendFile(path.join(process.cwd(), "src", "public", "setup.html"));
});

app.get("/setup/api/status", requireSetupAuth, async (_req, res) => {
  const { version, channelsHelp } = await getOpenclawInfo();

  const authGroups = [
    {
      value: "openai",
      label: "OpenAI",
      hint: "Codex OAuth + API key",
      options: [
        { value: "codex-cli", label: "OpenAI Codex OAuth (Codex CLI)" },
        { value: "openai-codex", label: "OpenAI Codex (ChatGPT OAuth)" },
        { value: "openai-api-key", label: "OpenAI API key" },
      ],
    },
    {
      value: "anthropic",
      label: "Anthropic",
      hint: "Claude Code CLI + API key",
      options: [
        { value: "claude-cli", label: "Anthropic token (Claude Code CLI)" },
        { value: "token", label: "Anthropic token (paste setup-token)" },
        { value: "apiKey", label: "Anthropic API key" },
      ],
    },
    {
      value: "google",
      label: "Google",
      hint: "Gemini API key + OAuth",
      options: [
        { value: "gemini-api-key", label: "Google Gemini API key" },
        { value: "google-antigravity", label: "Google Antigravity OAuth" },
        { value: "google-gemini-cli", label: "Google Gemini CLI OAuth" },
      ],
    },
    {
      value: "openrouter",
      label: "OpenRouter",
      hint: "API key",
      options: [{ value: "openrouter-api-key", label: "OpenRouter API key" }],
    },
    {
      value: "ai-gateway",
      label: "Vercel AI Gateway",
      hint: "API key",
      options: [
        { value: "ai-gateway-api-key", label: "Vercel AI Gateway API key" },
      ],
    },
    {
      value: "moonshot",
      label: "Moonshot AI",
      hint: "Kimi K2 + Kimi Code",
      options: [
        { value: "moonshot-api-key", label: "Moonshot AI API key" },
        { value: "kimi-code-api-key", label: "Kimi Code API key" },
      ],
    },
    {
      value: "zai",
      label: "Z.AI (GLM 4.7)",
      hint: "API key",
      options: [{ value: "zai-api-key", label: "Z.AI (GLM 4.7) API key" }],
    },
    {
      value: "minimax",
      label: "MiniMax",
      hint: "M2.1 (recommended)",
      options: [
        { value: "minimax-api", label: "MiniMax M2.1" },
        { value: "minimax-api-lightning", label: "MiniMax M2.1 Lightning" },
      ],
    },
    {
      value: "qwen",
      label: "Qwen",
      hint: "OAuth",
      options: [{ value: "qwen-portal", label: "Qwen OAuth" }],
    },
    {
      value: "copilot",
      label: "Copilot",
      hint: "GitHub + local proxy",
      options: [
        {
          value: "github-copilot",
          label: "GitHub Copilot (GitHub device login)",
        },
        { value: "copilot-proxy", label: "Copilot Proxy (local)" },
      ],
    },
    {
      value: "synthetic",
      label: "Synthetic",
      hint: "Anthropic-compatible (multi-model)",
      options: [{ value: "synthetic-api-key", label: "Synthetic API key" }],
    },
    {
      value: "opencode-zen",
      label: "OpenCode Zen",
      hint: "API key",
      options: [
        { value: "opencode-zen", label: "OpenCode Zen (multi-model proxy)" },
      ],
    },
  ];

  res.json({
    configured: isConfigured(),
    gatewayTarget: GATEWAY_TARGET,
    openclawVersion: version,
    channelsAddHelp: channelsHelp,
    authGroups,
    tuiEnabled: ENABLE_WEB_TUI,
  });
});

function buildOnboardArgs(payload) {
  const args = [
    "onboard",
    "--non-interactive",
    "--accept-risk",
    "--json",
    "--no-install-daemon",
    "--skip-health",
    "--workspace",
    WORKSPACE_DIR,
    "--gateway-bind",
    "loopback",
    "--gateway-port",
    String(INTERNAL_GATEWAY_PORT),
    "--gateway-auth",
    "token",
    "--gateway-token",
    OPENCLAW_GATEWAY_TOKEN,
    "--flow",
    payload.flow || "quickstart",
  ];

  if (payload.authChoice) {
    args.push("--auth-choice", payload.authChoice);

    const secret = (payload.authSecret || "").trim();
    const map = {
      "openai-api-key": "--openai-api-key",
      apiKey: "--anthropic-api-key",
      "openrouter-api-key": "--openrouter-api-key",
      "ai-gateway-api-key": "--ai-gateway-api-key",
      "moonshot-api-key": "--moonshot-api-key",
      "kimi-code-api-key": "--kimi-code-api-key",
      "gemini-api-key": "--gemini-api-key",
      "zai-api-key": "--zai-api-key",
      "minimax-api": "--minimax-api-key",
      "minimax-api-lightning": "--minimax-api-key",
      "synthetic-api-key": "--synthetic-api-key",
      "opencode-zen": "--opencode-zen-api-key",
    };
    const flag = map[payload.authChoice];
    if (flag && secret) {
      args.push(flag, secret);
    }

    if (payload.authChoice === "token" && secret) {
      args.push("--token-provider", "anthropic", "--token", secret);
    }
  }

  return args;
}

function runCmd(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const proc = childProcess.spawn(cmd, args, {
      ...opts,
      env: {
        ...process.env,
        OPENCLAW_STATE_DIR: STATE_DIR,
        OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
      },
    });

    let out = "";
    proc.stdout?.on("data", (d) => (out += d.toString("utf8")));
    proc.stderr?.on("data", (d) => (out += d.toString("utf8")));

    proc.on("error", (err) => {
      out += `\n[spawn error] ${String(err)}\n`;
      resolve({ code: 127, output: out });
    });

    proc.on("close", (code) => resolve({ code: code ?? 0, output: out }));
  });
}

const VALID_FLOWS = ["quickstart", "advanced", "manual"];
const VALID_AUTH_CHOICES = [
  "codex-cli",
  "openai-codex",
  "openai-api-key",
  "claude-cli",
  "token",
  "apiKey",
  "gemini-api-key",
  "google-antigravity",
  "google-gemini-cli",
  "openrouter-api-key",
  "ai-gateway-api-key",
  "moonshot-api-key",
  "kimi-code-api-key",
  "zai-api-key",
  "minimax-api",
  "minimax-api-lightning",
  "qwen-portal",
  "github-copilot",
  "copilot-proxy",
  "synthetic-api-key",
  "opencode-zen",
];

function validatePayload(payload) {
  if (payload.flow && !VALID_FLOWS.includes(payload.flow)) {
    return `Invalid flow: ${payload.flow}. Must be one of: ${VALID_FLOWS.join(", ")}`;
  }
  if (payload.authChoice && !VALID_AUTH_CHOICES.includes(payload.authChoice)) {
    return `Invalid authChoice: ${payload.authChoice}`;
  }
  const stringFields = [
    "telegramToken",
    "discordToken",
    "slackBotToken",
    "slackAppToken",
    "authSecret",
    "model",
  ];
  for (const field of stringFields) {
    if (payload[field] !== undefined && typeof payload[field] !== "string") {
      return `Invalid ${field}: must be a string`;
    }
  }
  return null;
}

app.post("/setup/api/run", requireSetupAuth, async (req, res) => {
  try {
    if (isConfigured()) {
      await ensureGatewayRunning();
      return res.json({
        ok: true,
        output:
          "Already configured.\nUse Reset setup if you want to rerun onboarding.\n",
      });
    }

    fs.mkdirSync(STATE_DIR, { recursive: true });
    fs.mkdirSync(WORKSPACE_DIR, { recursive: true });

    const payload = req.body || {};
    const validationError = validatePayload(payload);
    if (validationError) {
      return res.status(400).json({ ok: false, output: validationError });
    }
    const onboardArgs = buildOnboardArgs(payload);
    const onboard = await runCmd(OPENCLAW_NODE, clawArgs(onboardArgs));

    let extra = "";
    extra += `\n[setup] Onboarding exit=${onboard.code} configured=${isConfigured()}\n`;

    const ok = onboard.code === 0 && isConfigured();

    if (ok) {
      extra += "\n[setup] Configuring gateway settings...\n";

      const allowInsecureResult = await runCmd(
        OPENCLAW_NODE,
        clawArgs([
          "config",
          "set",
          "gateway.controlUi.allowInsecureAuth",
          "true",
        ]),
      );
      extra += `[config] gateway.controlUi.allowInsecureAuth=true exit=${allowInsecureResult.code}\n`;

      const tokenResult = await runCmd(
        OPENCLAW_NODE,
        clawArgs([
          "config",
          "set",
          "gateway.auth.token",
          OPENCLAW_GATEWAY_TOKEN,
        ]),
      );
      extra += `[config] gateway.auth.token exit=${tokenResult.code}\n`;

      const proxiesResult = await runCmd(
        OPENCLAW_NODE,
        clawArgs([
          "config",
          "set",
          "--json",
          "gateway.trustedProxies",
          '["127.0.0.1"]',
        ]),
      );
      extra += `[config] gateway.trustedProxies exit=${proxiesResult.code}\n`;

      if (payload.model?.trim()) {
        extra += `[setup] Setting model to ${payload.model.trim()}...\n`;
        const modelResult = await runCmd(
          OPENCLAW_NODE,
          clawArgs(["models", "set", payload.model.trim()]),
        );
        extra += `[models set] exit=${modelResult.code}\n${modelResult.output || ""}`;
      }

      async function configureChannel(name, cfgObj) {
        const set = await runCmd(
          OPENCLAW_NODE,
          clawArgs([
            "config",
            "set",
            "--json",
            `channels.${name}`,
            JSON.stringify(cfgObj),
          ]),
        );
        const get = await runCmd(
          OPENCLAW_NODE,
          clawArgs(["config", "get", `channels.${name}`]),
        );
        return (
          `\n[${name} config] exit=${set.code} (output ${set.output.length} chars)\n${set.output || "(no output)"}` +
          `\n[${name} verify] exit=${get.code} (output ${get.output.length} chars)\n${get.output || "(no output)"}`
        );
      }

      if (payload.telegramToken?.trim()) {
        extra += await configureChannel("telegram", {
          enabled: true,
          dmPolicy: "pairing",
          botToken: payload.telegramToken.trim(),
          groupPolicy: "allowlist",
          streamMode: "partial",
        });
      }

      if (payload.discordToken?.trim()) {
        extra += await configureChannel("discord", {
          enabled: true,
          token: payload.discordToken.trim(),
          groupPolicy: "allowlist",
          dm: { policy: "pairing" },
        });
      }

      if (payload.slackBotToken?.trim() || payload.slackAppToken?.trim()) {
        extra += await configureChannel("slack", {
          enabled: true,
          botToken: payload.slackBotToken?.trim() || undefined,
          appToken: payload.slackAppToken?.trim() || undefined,
        });
      }

      extra += "\n[setup] Starting gateway...\n";
      await restartGateway();
      extra += "[setup] Gateway started.\n";
    }

    return res.status(ok ? 200 : 500).json({
      ok,
      output: `${onboard.output}${extra}`,
    });
  } catch (err) {
    console.error("[/setup/api/run] error:", err);
    return res
      .status(500)
      .json({ ok: false, output: `Internal error: ${String(err)}` });
  }
});

app.get("/setup/api/debug", requireSetupAuth, async (_req, res) => {
  const v = await runCmd(OPENCLAW_NODE, clawArgs(["--version"]));
  const help = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["channels", "add", "--help"]),
  );
  res.json({
    wrapper: {
      node: process.version,
      port: PORT,
      stateDir: STATE_DIR,
      workspaceDir: WORKSPACE_DIR,
      configPath: configPath(),
      gatewayTokenFromEnv: Boolean(process.env.OPENCLAW_GATEWAY_TOKEN?.trim()),
      gatewayTokenPersisted: fs.existsSync(
        path.join(STATE_DIR, "gateway.token"),
      ),
      railwayCommit: process.env.RAILWAY_GIT_COMMIT_SHA || null,
    },
    openclaw: {
      entry: OPENCLAW_ENTRY,
      node: OPENCLAW_NODE,
      version: v.output.trim(),
      channelsAddHelpIncludesTelegram: help.output.includes("telegram"),
    },
  });
});

app.post("/setup/api/pairing/approve", requireSetupAuth, async (req, res) => {
  const { channel, code } = req.body || {};
  if (!channel || !code) {
    return res
      .status(400)
      .json({ ok: false, error: "Missing channel or code" });
  }
  const r = await runCmd(
    OPENCLAW_NODE,
    clawArgs(["pairing", "approve", String(channel), String(code)]),
  );
  return res
    .status(r.code === 0 ? 200 : 500)
    .json({ ok: r.code === 0, output: r.output });
});

app.post("/setup/api/reset", requireSetupAuth, async (_req, res) => {
  try {
    fs.rmSync(configPath(), { force: true });
    res
      .type("text/plain")
      .send("OK - deleted config file. You can rerun setup now.");
  } catch (err) {
    res.status(500).type("text/plain").send(String(err));
  }
});

app.post("/setup/api/doctor", requireSetupAuth, async (_req, res) => {
  const args = ["doctor", "--non-interactive", "--repair"];
  const result = await runCmd(OPENCLAW_NODE, clawArgs(args));
  return res.status(result.code === 0 ? 200 : 500).json({
    ok: result.code === 0,
    output: result.output,
  });
});

app.get("/tui", requireSetupAuth, (_req, res) => {
  if (!ENABLE_WEB_TUI) {
    return res
      .status(403)
      .type("text/plain")
      .send("Web TUI is disabled. Set ENABLE_WEB_TUI=true to enable it.");
  }
  if (!isConfigured()) {
    return res.redirect("/setup");
  }
  res.sendFile(path.join(process.cwd(), "src", "public", "tui.html"));
});

let activeTuiSession = null;

function verifyTuiAuth(req) {
  if (!SETUP_PASSWORD) return false;
  const header = req.headers.authorization || "";
  const [scheme, encoded] = header.split(" ");
  if (scheme !== "Basic" || !encoded) return false;
  const decoded = Buffer.from(encoded, "base64").toString("utf8");
  const idx = decoded.indexOf(":");
  const password = idx >= 0 ? decoded.slice(idx + 1) : "";
  const passwordHash = crypto.createHash("sha256").update(password).digest();
  const expectedHash = crypto.createHash("sha256").update(SETUP_PASSWORD).digest();
  return crypto.timingSafeEqual(passwordHash, expectedHash);
}

function createTuiWebSocketServer(httpServer) {
  const wss = new WebSocketServer({ noServer: true });

  wss.on("connection", (ws, req) => {
    const clientIp = req.socket?.remoteAddress || "unknown";
    console.log(`[tui] session started from ${clientIp}`);

    let ptyProcess = null;
    let idleTimer = null;
    let maxSessionTimer = null;

    activeTuiSession = {
      ws,
      pty: null,
      startedAt: Date.now(),
      lastActivity: Date.now(),
    };

    function resetIdleTimer() {
      if (activeTuiSession) {
        activeTuiSession.lastActivity = Date.now();
      }
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => {
        console.log("[tui] session idle timeout");
        ws.close(4002, "Idle timeout");
      }, TUI_IDLE_TIMEOUT_MS);
    }

    function spawnPty(cols, rows) {
      if (ptyProcess) return;

      console.log(`[tui] spawning PTY with ${cols}x${rows}`);
      ptyProcess = pty.spawn(OPENCLAW_NODE, clawArgs(["tui"]), {
        name: "xterm-256color",
        cols,
        rows,
        cwd: WORKSPACE_DIR,
        env: {
          ...process.env,
          OPENCLAW_STATE_DIR: STATE_DIR,
          OPENCLAW_WORKSPACE_DIR: WORKSPACE_DIR,
          TERM: "xterm-256color",
        },
      });

      if (activeTuiSession) {
        activeTuiSession.pty = ptyProcess;
      }

      idleTimer = setTimeout(() => {
        console.log("[tui] session idle timeout");
        ws.close(4002, "Idle timeout");
      }, TUI_IDLE_TIMEOUT_MS);

      maxSessionTimer = setTimeout(() => {
        console.log("[tui] max session duration reached");
        ws.close(4002, "Max session duration");
      }, TUI_MAX_SESSION_MS);

      ptyProcess.onData((data) => {
        if (ws.readyState === ws.OPEN) {
          ws.send(data);
        }
      });

      ptyProcess.onExit(({ exitCode, signal }) => {
        console.log(`[tui] PTY exited code=${exitCode} signal=${signal}`);
        if (ws.readyState === ws.OPEN) {
          ws.close(1000, "Process exited");
        }
      });
    }

    ws.on("message", (message) => {
      resetIdleTimer();
      try {
        const msg = JSON.parse(message.toString());
        if (msg.type === "resize" && msg.cols && msg.rows) {
          const cols = Math.min(Math.max(msg.cols, 10), 500);
          const rows = Math.min(Math.max(msg.rows, 5), 200);
          if (!ptyProcess) {
            spawnPty(cols, rows);
          } else {
            ptyProcess.resize(cols, rows);
          }
        } else if (msg.type === "input" && msg.data && ptyProcess) {
          ptyProcess.write(msg.data);
        }
      } catch (err) {
        console.warn(`[tui] invalid message: ${err.message}`);
      }
    });

    ws.on("close", () => {
      console.log("[tui] session closed");
      clearTimeout(idleTimer);
      clearTimeout(maxSessionTimer);
      if (ptyProcess) {
        try {
          ptyProcess.kill();
        } catch {}
      }
      activeTuiSession = null;
    });

    ws.on("error", (err) => {
      console.error(`[tui] WebSocket error: ${err.message}`);
    });
  });

  return wss;
}

const proxy = httpProxy.createProxyServer({
  target: GATEWAY_TARGET,
  ws: true,
  xfwd: true,
  proxyTimeout: 120_000,
  timeout: 120_000,
});

proxy.on("error", (err, _req, res) => {
  console.error("[proxy]", err);
  if (res && typeof res.headersSent !== "undefined" && !res.headersSent) {
    res.writeHead(503, { "Content-Type": "text/html" });
    try {
      const html = fs.readFileSync(
        path.join(process.cwd(), "src", "public", "loading.html"),
        "utf8",
      );
      res.end(html);
    } catch {
      res.end("Gateway unavailable. Retrying...");
    }
  }
});

proxy.on("proxyReq", (proxyReq, req, res) => {
  proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
});

proxy.on("proxyReqWs", (proxyReq, req, socket, options, head) => {
  proxyReq.setHeader("Authorization", `Bearer ${OPENCLAW_GATEWAY_TOKEN}`);
});

// ─── Radio routes ───────────────────────────────────────────────────────

// Web player page
app.get("/radio", (_req, res) => {
  res.type("text/html").send(RADIO_HTML);
});

// Audio stream endpoint
app.get("/radio/stream", (_req, res) => {
  res.writeHead(200, {
    "Content-Type": "audio/mpeg",
    "Cache-Control": "no-cache, no-store",
    "Connection": "keep-alive",
    "Transfer-Encoding": "chunked",
    "Access-Control-Allow-Origin": "*",
    "ICY-Name": "Crowbot Radio",
  });
  radio.addClient(res);
});

// Add song to queue
app.post("/radio/play", async (req, res) => {
  const { query } = req.body || {};
  if (!query || typeof query !== "string") {
    return res.status(400).json({ ok: false, error: "Missing query" });
  }
  const result = await radio.addToQueue(query.trim());
  return res.json(result);
});

// Skip current track
app.post("/radio/skip", (_req, res) => {
  return res.json(radio.skip());
});

// Like current track
app.post("/radio/like", (_req, res) => {
  return res.json(radio.like());
});

// Set volume
app.post("/radio/volume", (req, res) => {
  const { volume } = req.body || {};
  if (volume === undefined) {
    return res.status(400).json({ ok: false, error: "Missing volume (0-100)" });
  }
  return res.json(radio.setVolume(volume));
});

// Now playing
app.get("/radio/now", (_req, res) => {
  return res.json(radio.getNowPlaying());
});

// Queue info
app.get("/radio/queue", (_req, res) => {
  return res.json(radio.getQueue());
});

// Register webhook
app.post("/radio/webhook", (req, res) => {
  const { url } = req.body || {};
  if (!url) {
    return res.status(400).json({ ok: false, error: "Missing url" });
  }
  return res.json(radio.setWebhook(url));
});

// Radio web player HTML
const RADIO_HTML = `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>NOIR FM</title>
<script src="https://cdn.tailwindcss.com"></script>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&family=Playfair+Display:ital,wght@0,400;0,600;0,700;1,400&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/icon?family=Material+Icons+Round" rel="stylesheet">
<script>
tailwind.config = {
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        primary: "#D32F2F",
        "accent-red": "#FF3B30",
        "background-dark": "#1A1A1C",
        "surface-dark": "#232325",
        "surface-card": "#252527",
      },
      fontFamily: {
        sans: ["Inter", "sans-serif"],
        display: ["Playfair Display", "serif"],
      },
      boxShadow: {
        vinyl: "0 25px 60px -15px rgba(0,0,0,0.8), 0 0 0 1px rgba(255,255,255,0.03)",
        glow: "0 0 20px rgba(211,47,47,0.3), 0 0 60px rgba(211,47,47,0.1)",
      },
      borderRadius: {
        DEFAULT: "12px",
        xl: "20px",
        "2xl": "32px",
      },
    },
  },
};
</script>
<style>
body { font-family: "Inter", sans-serif; min-height: 100dvh; }
.vinyl-texture {
  background: repeating-radial-gradient(#111 0, #111 2px, #1c1c1c 3px, #1c1c1c 4px);
}
.tonearm {
  transform-origin: top right;
  transform: rotate(-20deg);
  transition: transform 0.5s ease-in-out;
}
.tonearm.active { transform: rotate(12deg); }
.vinyl-spin { animation: spin 8s linear infinite; animation-play-state: paused; }
.vinyl-spin.playing { animation-play-state: running; }
@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
@keyframes pulse-dot { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
.playlist-scroll { -webkit-overflow-scrolling: touch; overscroll-behavior: contain; }
.playlist-scroll::-webkit-scrollbar { width: 3px; }
.playlist-scroll::-webkit-scrollbar-track { background: transparent; }
.playlist-scroll::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 3px; }
@keyframes heartBounce {
  0%   { transform: scale(1); }
  15%  { transform: scale(0.75); }
  40%  { transform: scale(1.25); }
  60%  { transform: scale(0.95); }
  80%  { transform: scale(1.05); }
  100% { transform: scale(1); }
}
.heart-bounce { animation: heartBounce 0.5s ease-out; }
@keyframes heartFall {
  0%   { transform: translateY(-20px) translateX(0) rotate(0deg); opacity: 0; }
  10%  { opacity: 1; }
  90%  { opacity: 0.6; }
  100% { transform: translateY(105vh) translateX(var(--sway)) rotate(var(--rot)); opacity: 0; }
}
</style>
</head>
<body class="bg-background-dark text-white h-screen flex flex-col relative overflow-hidden">

<!-- Background gradients + red glow -->
<div class="absolute inset-0 bg-gradient-to-b from-[#2a2c30] via-[#1A1A1C] to-[#0d0d0f]"></div>
<div class="absolute top-[-20%] left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full bg-primary/10 blur-[120px] pointer-events-none"></div>

<!-- Header -->
<div class="w-full flex justify-between items-center px-6 pt-14 pb-2 z-20 relative">
  <div class="w-12 flex items-center space-x-1.5 opacity-50">
    <span class="block w-1.5 h-1.5 rounded-full bg-accent-red" style="animation: pulse-dot 2s ease-in-out infinite"></span>
    <span class="text-[10px] font-mono" id="listenersText">0</span>
  </div>
  <span class="text-xs tracking-[0.25em] font-semibold text-gray-300 uppercase opacity-80">NOIR FM</span>
  <div class="w-12"></div>
</div>

<!-- Vinyl -->
<div class="flex-none w-full flex items-center justify-center z-10 relative" style="padding-top:8px">
  <div class="relative w-80 h-72 flex items-center justify-center">
    <!-- Tonearm -->
    <div class="tonearm absolute -top-4 right-2 z-30 pointer-events-none" id="needle">
      <div class="relative w-14 h-14">
        <div class="absolute top-0 right-0 w-14 h-14 rounded-full bg-gradient-to-br from-gray-300 to-gray-500 shadow-lg border border-gray-400 flex items-center justify-center z-10">
          <div class="w-5 h-5 rounded-full bg-gray-600 shadow-inner"></div>
        </div>
        <div class="absolute top-[50%] right-[26px] w-[2.5px] h-36 bg-gradient-to-b from-gray-400 via-gray-300 to-gray-400 rounded-full origin-top rotate-[15deg] shadow-md">
          <div class="absolute bottom-0 left-1/2 -translate-x-1/2 w-3 h-4 bg-gradient-to-b from-gray-300 to-gray-500 rounded-sm shadow-md">
            <div class="absolute bottom-0 left-1/2 -translate-x-1/2 w-[2px] h-2 bg-black/60"></div>
          </div>
        </div>
      </div>
    </div>
    <!-- Record -->
    <div class="vinyl-spin w-72 h-72 rounded-full bg-[#0a0a0a] shadow-vinyl relative flex items-center justify-center overflow-hidden border-[6px] border-[#222]" id="vinyl">
      <div class="absolute inset-1 rounded-full vinyl-texture opacity-90"></div>
      <div class="absolute inset-0 rounded-full bg-gradient-to-tr from-transparent via-white/5 to-transparent opacity-40 pointer-events-none"></div>
      <div class="relative z-10 w-28 h-28 rounded-full bg-gradient-to-br from-[#2a2a2a] to-[#3a3a3a] flex items-center justify-center shadow-inner border-4 border-[#181818] overflow-hidden" id="vinylCover">
        <div class="w-full h-full flex items-center justify-center text-3xl text-white/20" id="coverPlaceholder">&#9835;</div>
      </div>
    </div>
  </div>
</div>

<!-- Track Info (centered, below vinyl) -->
<div class="w-full text-center px-8 pt-5 pb-2 z-20 relative">
  <h2 class="font-display text-3xl font-semibold text-white tracking-wide mb-1 truncate" id="trackTitle">&mdash;</h2>
  <p class="text-gray-400 uppercase tracking-widest text-xs truncate" id="trackArtist">&mdash;</p>
</div>

<!-- Progress Bar -->
<div class="w-full px-8 pt-2 pb-1 z-20 relative">
  <div class="h-1 bg-gray-700/50 rounded-full overflow-hidden">
    <div class="h-full bg-white rounded-full shadow-[0_0_8px_rgba(255,255,255,0.4)] transition-all duration-1000 ease-linear" id="progressBar" style="width:0%"></div>
  </div>
  <div class="flex justify-between mt-1.5">
    <span class="font-mono text-[10px] text-gray-500" id="progressCurrent">0:00</span>
    <span class="font-mono text-[10px] text-gray-500" id="progressTotal">0:00</span>
  </div>
</div>

<!-- Controls -->
<div class="grid grid-cols-[1fr,auto,1fr] items-center px-8 pt-2 pb-3 z-20 relative">
  <div class="flex justify-end pr-6">
    <button class="text-white/60 hover:text-red-400 transition-colors p-4 active:scale-90" id="likeBtn">
      <span class="material-icons-round text-3xl" id="likeIcon">favorite_border</span>
    </button>
  </div>
  <button class="p-4 rounded-full bg-white/10 border border-white/10 backdrop-blur-md shadow-glow flex items-center justify-center hover:scale-105 active:scale-95 transition-all" id="playBtn">
    <span class="material-icons-round text-3xl text-white" id="playIcon">play_arrow</span>
  </button>
  <div class="flex justify-start pl-6">
    <button class="text-white/40 hover:text-white transition-colors p-4 active:scale-90" id="skipBtn">
      <span class="material-icons-round text-4xl">skip_next</span>
    </button>
  </div>
</div>

<!-- Playlist Panel -->
<div class="w-full rounded-t-2xl bg-[#151517] shadow-[0_-15px_40px_rgba(0,0,0,0.6)] z-20 flex flex-col relative flex-1">
  <div class="w-10 h-1 bg-gray-600 rounded-full mx-auto mt-3 mb-1"></div>
  <div class="w-full px-6 overflow-y-auto playlist-scroll pb-8" style="max-height:40vh">
    <div class="sticky top-0 pt-2 pb-3 z-10 flex justify-between items-center bg-[#151517]">
      <span class="text-xs font-bold text-white/30 uppercase tracking-widest">Playlist</span>
      <span class="text-[10px] font-mono text-white/20 bg-white/5 px-2 py-1 rounded" id="playlistCount">0 songs</span>
    </div>
    <div class="space-y-1" id="playlistItems">
      <div class="text-center py-10 text-white/20 text-sm">Tell Crowbot what to play</div>
    </div>
  </div>
</div>

<!-- Home indicator -->
<div class="absolute bottom-1 left-1/2 -translate-x-1/2 w-32 h-1 bg-white/20 rounded-full z-50"></div>

<audio id="audio" preload="none"></audio>

<script>
const audio = document.getElementById('audio');
const playBtn = document.getElementById('playBtn');
const playIcon = document.getElementById('playIcon');
const skipBtn = document.getElementById('skipBtn');
const likeBtn = document.getElementById('likeBtn');
const likeIcon = document.getElementById('likeIcon');
const trackTitle = document.getElementById('trackTitle');
const trackArtist = document.getElementById('trackArtist');
const vinyl = document.getElementById('vinyl');
const vinylCover = document.getElementById('vinylCover');
const needle = document.getElementById('needle');
const listenersText = document.getElementById('listenersText');
const playlistCount = document.getElementById('playlistCount');
const playlistItems = document.getElementById('playlistItems');
const progressBar = document.getElementById('progressBar');
const progressCurrent = document.getElementById('progressCurrent');
const progressTotal = document.getElementById('progressTotal');

let isAudioPlaying = false;
let currentStartedAt = null;
let currentDuration = 0;

function formatDuration(s) {
  if (!s) return '0:00';
  const m = Math.floor(s / 60);
  const sec = Math.floor(s % 60);
  return m + ':' + (sec < 10 ? '0' : '') + sec;
}

// Progress bar update
function updateProgress() {
  if (currentStartedAt && currentDuration > 0) {
    const elapsed = (Date.now() - currentStartedAt) / 1000;
    const pct = Math.min(100, (elapsed / currentDuration) * 100);
    progressBar.style.width = pct + '%';
    progressCurrent.textContent = formatDuration(Math.min(elapsed, currentDuration));
    progressTotal.textContent = formatDuration(currentDuration);
  } else {
    progressBar.style.width = '0%';
    progressCurrent.textContent = '0:00';
    progressTotal.textContent = '0:00';
  }
}
setInterval(updateProgress, 1000);

playBtn.addEventListener('click', () => {
  if (isAudioPlaying) {
    audio.pause();
    audio.src = '';
    isAudioPlaying = false;
    playIcon.textContent = 'play_arrow';
    vinyl.classList.remove('playing');
    needle.classList.remove('active');
  } else {
    audio.src = '/radio/stream?' + Date.now();
    audio.play().catch(e => console.log('play error:', e));
    isAudioPlaying = true;
    playIcon.textContent = 'pause';
    vinyl.classList.add('playing');
    needle.classList.add('active');
  }
});

skipBtn.addEventListener('click', async () => {
  await fetch('/radio/skip', { method: 'POST' });
  // Reconnect stream immediately so audio starts without waiting for stalled event
  if (isAudioPlaying) {
    audio.src = '/radio/stream?' + Date.now();
    audio.play().catch(() => {});
  }
  updateNow();
});

let likedTrackId = null;
likeBtn.addEventListener('click', () => {
  const nowId = trackTitle.textContent;
  if (!nowId || nowId === '\\u2014' || likedTrackId === nowId) return;

  // 1. Optimistic UI — red heart immediately
  likedTrackId = nowId;
  likeIcon.textContent = 'favorite';
  likeBtn.classList.remove('text-white/60');
  likeBtn.classList.add('text-red-400');

  // 2. Bounce animation (Spotify-style)
  likeBtn.classList.remove('heart-bounce');
  void likeBtn.offsetWidth;
  likeBtn.classList.add('heart-bounce');

  // 3. Heart rain
  showHeartRain();

  // 4. Fire-and-forget request — rollback on failure
  fetch('/radio/like', { method: 'POST' }).catch(() => {
    likedTrackId = null;
    likeIcon.textContent = 'favorite_border';
    likeBtn.classList.remove('text-red-400');
    likeBtn.classList.add('text-white/60');
  });
});

function showHeartRain() {
  const colors = ['#FF1744','#FF4081','#FF6B6B','#E91E63','#FF8A80','#F48FB1','#CE93D8'];
  for (let i = 0; i < 30; i++) {
    const h = document.createElement('div');
    h.textContent = '\\u2764';
    const size = 14 + Math.random() * 22;
    const sway = (Math.random() - 0.5) * 60;
    const rot = (Math.random() - 0.5) * 90;
    h.style.cssText = 'position:fixed;top:-20px;z-index:9999;pointer-events:none;' +
      'font-size:' + size + 'px;' +
      'left:' + (Math.random() * 100) + 'vw;' +
      'color:' + colors[Math.floor(Math.random() * colors.length)] + ';' +
      '--sway:' + sway + 'px;--rot:' + rot + 'deg;' +
      'animation:heartFall ' + (2.5 + Math.random() * 2) + 's ease-in forwards;' +
      'animation-delay:' + (Math.random() * 0.8) + 's;';
    document.body.appendChild(h);
    h.addEventListener('animationend', () => h.remove());
  }
}

async function updateNow() {
  try {
    const [nowRes, qRes] = await Promise.all([
      fetch('/radio/now'),
      fetch('/radio/queue')
    ]);
    const data = await nowRes.json();
    const qData = await qRes.json();

    listenersText.textContent = data.listeners || 0;

    let items = [];
    if (data.isPlaying && data.currentTrack) {
      // Reset like button when track changes
      if (trackTitle.textContent !== data.currentTrack.title) {
        likedTrackId = null;
        likeIcon.textContent = 'favorite_border';
        likeBtn.classList.remove('text-red-400');
        likeBtn.classList.add('text-white/60');
      }
      trackTitle.textContent = data.currentTrack.title;
      trackArtist.textContent = data.currentTrack.artist;
      currentStartedAt = data.currentTrack.startedAt || null;
      currentDuration = data.currentTrack.duration || 0;

      if (data.currentTrack.thumbnail) {
        vinylCover.innerHTML = '<img src="' + data.currentTrack.thumbnail + '" alt="" class="w-full h-full object-cover">';
      } else {
        vinylCover.innerHTML = '<div class="w-full h-full flex items-center justify-center text-3xl text-white/20 bg-gradient-to-br from-[#2a2a2a] to-[#3a3a3a]">&#9835;</div>';
      }

      items.push({
        title: data.currentTrack.title,
        artist: data.currentTrack.artist,
        duration: data.currentTrack.duration,
        thumbnail: data.currentTrack.thumbnail,
        isCurrent: true
      });
    } else {
      trackTitle.textContent = '\\u2014';
      trackArtist.textContent = '\\u2014';
      currentStartedAt = null;
      currentDuration = 0;
      vinylCover.innerHTML = '<div class="w-full h-full flex items-center justify-center text-3xl text-white/20 bg-gradient-to-br from-[#2a2a2a] to-[#3a3a3a]">&#9835;</div>';
      if (isAudioPlaying) {
        vinyl.classList.remove('playing');
        needle.classList.remove('active');
      }
    }

    if (qData.queue) {
      qData.queue.forEach(t => {
        items.push({
          title: t.title,
          artist: t.artist,
          duration: t.duration,
          thumbnail: null,
          isCurrent: false
        });
      });
    }

    playlistCount.textContent = items.length + (items.length === 1 ? ' song' : ' songs');

    if (items.length > 0) {
      playlistItems.innerHTML = items.map((t, i) => {
        if (t.isCurrent) {
          return '<div class="p-4 rounded-2xl bg-surface-card border border-white/5 shadow-lg">'
            + '<div class="flex items-center justify-between">'
            + '<div class="flex items-center space-x-3 overflow-hidden">'
            + '<div class="w-4 h-4 flex items-center justify-center">'
            + '<span class="block w-1.5 h-1.5 bg-accent-red rounded-full" style="animation:pulse-dot 2s ease-in-out infinite"></span>'
            + '</div>'
            + '<div class="flex flex-col overflow-hidden">'
            + '<p class="text-sm text-white font-medium truncate">' + t.title + '</p>'
            + '<p class="text-[10px] text-white/40 truncate">' + t.artist + '</p>'
            + '</div></div>'
            + '<span class="text-xs font-mono text-accent-red font-medium">' + formatDuration(t.duration) + '</span>'
            + '</div></div>';
        } else {
          return '<div class="flex items-center justify-between px-4 py-3 opacity-50 hover:opacity-80 transition-opacity cursor-pointer">'
            + '<div class="flex items-center space-x-3 overflow-hidden">'
            + '<span class="text-xs font-mono text-white/30 w-4 text-center">' + String(i).padStart(2, '0') + '</span>'
            + '<div class="flex flex-col overflow-hidden">'
            + '<p class="text-sm text-white/70 font-medium truncate">' + t.title + '</p>'
            + '<p class="text-[10px] text-white/30 truncate">' + t.artist + '</p>'
            + '</div></div>'
            + '<span class="text-xs font-mono text-white/30">' + formatDuration(t.duration) + '</span>'
            + '</div>';
        }
      }).join('');
    } else {
      playlistItems.innerHTML = '<div class="text-center py-10 text-white/20 text-sm">Tell Crowbot what to play</div>';
    }
    updateProgress();
  } catch (e) {
    console.log('update error:', e);
  }
}

updateNow();
setInterval(updateNow, 3000);

// Auto-play on page load
function autoPlay() {
  audio.src = '/radio/stream?' + Date.now();
  audio.play().then(() => {
    isAudioPlaying = true;
    playIcon.textContent = 'pause';
    vinyl.classList.add('playing');
    needle.classList.add('active');
  }).catch(() => {
    isAudioPlaying = false;
    playIcon.textContent = 'play_arrow';
    document.addEventListener('click', function once() {
      if (!isAudioPlaying) {
        audio.src = '/radio/stream?' + Date.now();
        audio.play().then(() => {
          isAudioPlaying = true;
          playIcon.textContent = 'pause';
          vinyl.classList.add('playing');
          needle.classList.add('active');
        }).catch(() => {});
      }
      document.removeEventListener('click', once);
    }, { once: true });
  });
}
autoPlay();

// Auto-reconnect on stream error/stall
audio.addEventListener('error', () => {
  if (isAudioPlaying) {
    setTimeout(() => {
      audio.src = '/radio/stream?' + Date.now();
      audio.play().catch(() => {});
    }, 1000);
  }
});
audio.addEventListener('stalled', () => {
  if (isAudioPlaying) {
    setTimeout(() => {
      audio.src = '/radio/stream?' + Date.now();
      audio.play().catch(() => {});
    }, 1000);
  }
});
</script>
</body>
</html>`;

// ─── End radio routes ───────────────────────────────────────────────────

app.use(async (req, res) => {
  if (!isConfigured() && !req.path.startsWith("/setup")) {
    return res.redirect("/setup");
  }

  if (isConfigured()) {
    if (!isGatewayReady()) {
      try {
        await ensureGatewayRunning();
      } catch {
        return res
          .status(503)
          .sendFile(path.join(process.cwd(), "src", "public", "loading.html"));
      }

      if (!isGatewayReady()) {
        return res
          .status(503)
          .sendFile(path.join(process.cwd(), "src", "public", "loading.html"));
      }
    }
  }

  // Inject gateway token into any Control UI page so the JS client can
  // authenticate its WebSocket "connect" message.  The Control UI reads
  // the token from either ?token= or #token= on first load, then stores
  // it in localStorage for subsequent visits.  We redirect once so the
  // browser's URL contains the token fragment.
  const gatewayPages = ["/openclaw", "/cron", "/control", "/chat"];
  const isGatewayPage = req.path === "/" || gatewayPages.includes(req.path) || gatewayPages.some((p) => req.path.startsWith(p + "/"));
  if (!req.query.token && isGatewayPage) {
    // Use hash fragment (#token=) so the token doesn't get sent to CDNs or
    // logged in access logs on intermediate proxies.
    const sep = req.url.includes("?") ? "&" : "?";
    return res.redirect(`${req.url}${sep}token=${OPENCLAW_GATEWAY_TOKEN}`);
  }

  return proxy.web(req, res, { target: GATEWAY_TARGET });
});

const server = app.listen(PORT, () => {
  console.log(`[wrapper] listening on port ${PORT}`);
  console.log(`[wrapper] setup wizard: http://localhost:${PORT}/setup`);
  console.log(`[wrapper] web TUI: ${ENABLE_WEB_TUI ? "enabled" : "disabled"}`);
  console.log(`[wrapper] configured: ${isConfigured()}`);

  if (isConfigured()) {
    (async () => {
      try {
        console.log("[wrapper] running openclaw doctor --fix...");
        const dr = await runCmd(OPENCLAW_NODE, clawArgs(["doctor", "--fix"]));
        console.log(`[wrapper] doctor --fix exit=${dr.code}`);
        if (dr.output) console.log(dr.output);
      } catch (err) {
        console.warn(`[wrapper] doctor --fix failed: ${err.message}`);
      }

      // Write OpenAI Codex OAuth token to auth-profiles.json for ALL agents
      // OpenClaw stores auth profiles per-agent under agents/<id>/agent/auth-profiles.json.
      // Telegram may use a different agentId than "main", so we inject into every agent dir.
      try {
        const codexProfile = {
          type: "oauth",
          provider: "openai-codex",
          access: process.env.OPENAI_OAUTH_ACCESS_TOKEN || "",
          refresh: process.env.OPENAI_OAUTH_REFRESH_TOKEN || "",
          expires: Number(process.env.OPENAI_OAUTH_EXPIRES) || 0,
        };

        if (!process.env.OPENAI_OAUTH_REFRESH_TOKEN) {
          console.log("[wrapper] no OPENAI_OAUTH_REFRESH_TOKEN set, skipping codex auth");
        } else {
          // Find ALL agent directories that have auth-profiles.json (or create for main)
          const agentsDir = path.join(STATE_DIR, "agents");
          const agentDirsToUpdate = [];

          // Always include "main" agent
          agentDirsToUpdate.push(path.join(agentsDir, "main", "agent"));

          // Also scan for any other agent dirs (e.g. "default", telegram-specific agents)
          try {
            const agentIds = fs.readdirSync(agentsDir);
            for (const id of agentIds) {
              const agentDir = path.join(agentsDir, id, "agent");
              if (id !== "main" && fs.existsSync(agentDir)) {
                agentDirsToUpdate.push(agentDir);
              }
            }
          } catch {}

          console.log(`[wrapper] injecting openai-codex auth into ${agentDirsToUpdate.length} agent dir(s): ${agentDirsToUpdate.map(d => d.replace(STATE_DIR + "/", "")).join(", ")}`);

          for (const agentAuthDir of agentDirsToUpdate) {
            const authProfilesPath = path.join(agentAuthDir, "auth-profiles.json");
            try {
              fs.mkdirSync(agentAuthDir, { recursive: true });
              let authProfiles = { version: 1, profiles: {} };
              try {
                authProfiles = JSON.parse(fs.readFileSync(authProfilesPath, "utf8"));
              } catch {}

              // Check if already has correct codex profile
              const existing = authProfiles.profiles?.["openai-codex:default"];
              if (existing?.refresh === codexProfile.refresh && existing?.provider === "openai-codex") {
                console.log(`[wrapper] openai-codex:default already correct in ${authProfilesPath.replace(STATE_DIR + "/", "")}`);
                continue;
              }

              authProfiles.profiles["openai-codex:default"] = codexProfile;
              fs.writeFileSync(authProfilesPath, JSON.stringify(authProfiles, null, 2));
              console.log(`[wrapper] wrote openai-codex:default to ${authProfilesPath.replace(STATE_DIR + "/", "")}`);

              // Verify write
              const verify = JSON.parse(fs.readFileSync(authProfilesPath, "utf8"));
              const profileKeys = Object.keys(verify.profiles || {});
              console.log(`[wrapper] verified profiles in ${authProfilesPath.replace(STATE_DIR + "/", "")}: ${profileKeys.join(", ")}`);
            } catch (err) {
              console.warn(`[wrapper] failed to write auth to ${agentAuthDir}: ${err.message}`);
            }
          }
        }
      } catch (err) {
        console.warn(`[wrapper] auth-profiles.json write failed: ${err.message}`);
      }

      // Register openai-codex:default in openclaw.json config
      // CRITICAL: auth-profiles.json holds the credentials, but openclaw.json
      // holds the auth.profiles config that tells OpenClaw which profiles exist
      // and what mode they use. Without this, OpenClaw won't discover the profile.
      try {
        const configPath = path.join(STATE_DIR, "openclaw.json");
        let config = {};
        try {
          config = JSON.parse(fs.readFileSync(configPath, "utf8"));
        } catch {}

        if (!config.auth) config.auth = {};
        if (!config.auth.profiles) config.auth.profiles = {};

        const needsConfigUpdate = !config.auth.profiles["openai-codex:default"]
          || config.auth.profiles["openai-codex:default"].provider !== "openai-codex"
          || config.auth.profiles["openai-codex:default"].mode !== "oauth";

        if (needsConfigUpdate) {
          config.auth.profiles["openai-codex:default"] = {
            provider: "openai-codex",
            mode: "oauth",
          };
          fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
          console.log(`[wrapper] registered openai-codex:default in openclaw.json auth.profiles`);

          // Verify
          const verify = JSON.parse(fs.readFileSync(configPath, "utf8"));
          const configProfiles = Object.keys(verify.auth?.profiles || {});
          console.log(`[wrapper] openclaw.json auth.profiles: ${configProfiles.join(", ")}`);
        } else {
          console.log(`[wrapper] openai-codex:default already in openclaw.json auth.profiles`);
        }
      } catch (err) {
        console.warn(`[wrapper] openclaw.json auth config update failed: ${err.message}`);
      }

      // Patch OpenClaw cooldown: 60s → 5min → 30min (cap), default is 60min.
      try {
        const clawDist = path.join(path.dirname(process.env.OPENCLAW_ENTRY || ""), "dist");
        const files = fs.readdirSync(clawDist).filter(f => f.startsWith("model-selection"));
        for (const f of files) {
          const fp = path.join(clawDist, f);
          let src = fs.readFileSync(fp, "utf8");
          const old = "return Math.min(3600 * 1e3, 60 * 1e3 * 5 ** Math.min(normalized - 1, 3));";
          if (src.includes(old)) {
            const patched = "if (normalized === 1) return 60e3; if (normalized === 2) return 300e3; return 1800e3;";
            src = src.replace(old, patched);
            fs.writeFileSync(fp, src);
            console.log(`[wrapper] patched cooldown: 60s → 5min → 30min cap`);
          }
        }
      } catch (err) {
        console.warn(`[wrapper] cooldown patch failed: ${err.message}`);
      }

      // Clear cooldowns on startup for fresh state
      try {
        const authStatsPath = path.join(STATE_DIR, "agents", "main", "agent", "auth-profiles.json");
        const store = JSON.parse(fs.readFileSync(authStatsPath, "utf8"));
        if (store.usageStats) {
          const now = Date.now();
          const cleared = [];
          for (const [profileId, stats] of Object.entries(store.usageStats)) {
            if (stats?.cooldownUntil > now || stats?.disabledUntil > now) {
              delete stats.cooldownUntil;
              delete stats.disabledUntil;
              delete stats.consecutiveErrors;
              cleared.push(profileId);
            }
          }
          if (cleared.length > 0) {
            fs.writeFileSync(authStatsPath, JSON.stringify(store, null, 2));
            console.log(`[wrapper] cleared cooldowns: ${cleared.join(", ")}`);
          } else {
            console.log(`[wrapper] no stale cooldowns found`);
          }
        }
      } catch {}

      // Set model fallback to OpenAI Codex (gpt-5.3-codex)
      // IMPORTANT: provider must be "openai-codex" (not "openai") to match
      // the auth profile registered in auth-profiles.json as "openai-codex:default"
      try {
        // Remove old incorrect fallback (openai/gpt-5.3-codex) if present
        await runCmd(
          OPENCLAW_NODE,
          clawArgs(["models", "fallbacks", "remove", "openai/gpt-5.3-codex"]),
        ).catch(() => {});
        const fb = await runCmd(
          OPENCLAW_NODE,
          clawArgs(["models", "fallbacks", "add", "openai-codex/gpt-5.3-codex"]),
        );
        console.log(`[wrapper] model fallback set exit=${fb.code}`);
        if (fb.output) console.log(fb.output);
      } catch (err) {
        console.warn(`[wrapper] model fallback failed: ${err.message}`);
      }

      await ensureGatewayRunning();
    })().catch((err) => {
      console.error(`[wrapper] failed to start gateway at boot: ${err.message}`);
    });
  }
});

// Periodic disk cleanup every 6 hours to prevent ENOSPC
setInterval(() => {
  try {
    // Clear Chrome cache
    childProcess.execSync('rm -rf /data/.openclaw/browser/*/Cache /data/.openclaw/browser/*/Code\\ Cache /data/.openclaw/browser/*/GPUCache 2>/dev/null || true', { timeout: 10000 });
    // Clear radio temp files
    childProcess.execSync('rm -rf /tmp/radio/* 2>/dev/null || true', { timeout: 5000 });
    const df = childProcess.execSync('df -h /data 2>/dev/null || true', { timeout: 5000 }).toString().trim();
    console.log(`[cleanup] periodic disk cleanup done. ${df.split("\n").pop()}`);
  } catch (err) {
    console.warn(`[cleanup] failed: ${err.message}`);
  }
}, 6 * 60 * 60 * 1000);

const tuiWss = createTuiWebSocketServer(server);

server.on("upgrade", async (req, socket, head) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === "/tui/ws") {
    if (!ENABLE_WEB_TUI) {
      socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
      socket.destroy();
      return;
    }

    if (!verifyTuiAuth(req)) {
      socket.write("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"OpenClaw TUI\"\r\n\r\n");
      socket.destroy();
      return;
    }

    if (activeTuiSession) {
      socket.write("HTTP/1.1 409 Conflict\r\n\r\n");
      socket.destroy();
      return;
    }

    tuiWss.handleUpgrade(req, socket, head, (ws) => {
      tuiWss.emit("connection", ws, req);
    });
    return;
  }

  if (!isConfigured()) {
    socket.destroy();
    return;
  }
  try {
    await ensureGatewayRunning();
  } catch (err) {
    console.warn(`[websocket] gateway not ready: ${err.message}`);
    socket.destroy();
    return;
  }
  // Inject gateway token into the URL so OpenClaw accepts the WebSocket.
  // The proxyReqWs header injection alone isn't enough — newer OpenClaw
  // versions check the URL query parameter for WebSocket auth.
  const wsUrl = new URL(req.url, `http://${req.headers.host}`);
  if (!wsUrl.searchParams.has("token")) {
    wsUrl.searchParams.set("token", OPENCLAW_GATEWAY_TOKEN);
    req.url = wsUrl.pathname + wsUrl.search;
  }
  proxy.ws(req, socket, head, { target: GATEWAY_TARGET });
});

async function gracefulShutdown(signal) {
  console.log(`[wrapper] received ${signal}, shutting down`);
  shuttingDown = true;

  // Shutdown radio
  radio.destroy();

  if (setupRateLimiter.cleanupInterval) {
    clearInterval(setupRateLimiter.cleanupInterval);
  }

  if (activeTuiSession) {
    try {
      activeTuiSession.ws.close(1001, "Server shutting down");
      activeTuiSession.pty.kill();
    } catch {}
    activeTuiSession = null;
  }

  server.close();

  if (gatewayProc) {
    try {
      gatewayProc.kill("SIGTERM");
      await Promise.race([
        new Promise((resolve) => gatewayProc.on("exit", resolve)),
        new Promise((resolve) => setTimeout(resolve, 2000)),
      ]);
      if (gatewayProc && !gatewayProc.killed) {
        gatewayProc.kill("SIGKILL");
      }
    } catch (err) {
      console.warn(`[wrapper] error killing gateway: ${err.message}`);
    }
  }

  process.exit(0);
}

process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
process.on("SIGINT", () => gracefulShutdown("SIGINT"));
