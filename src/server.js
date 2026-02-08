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

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function waitForGatewayReady(opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 60_000;
  const start = Date.now();
  const endpoints = ["/openclaw", "/openclaw", "/", "/health"];

  while (Date.now() - start < timeoutMs) {
    for (const endpoint of endpoints) {
      try {
        const res = await fetch(`${GATEWAY_TARGET}${endpoint}`, {
          method: "GET",
        });
        if (res) {
          console.log(`[gateway] ready at ${endpoint}`);
          return true;
        }
      } catch (err) {
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

app.get("/setup/healthz", (_req, res) => res.json({ ok: true }));

app.get("/setup/styles.css", (_req, res) => {
  res.type("text/css");
  res.sendFile(path.join(process.cwd(), "src", "public", "styles.css"));
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

      const channelsHelp = await runCmd(
        OPENCLAW_NODE,
        clawArgs(["channels", "add", "--help"]),
      );
      const helpText = channelsHelp.output || "";

      async function configureChannel(name, cfgObj) {
        if (!helpText.includes(name)) {
          return `\n[${name}] skipped (this openclaw build does not list ${name} in \`channels add --help\`)\n`;
        }
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
});

proxy.on("error", (err, _req, _res) => {
  console.error("[proxy]", err);
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
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<title>Crowbot FM</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --red: #ec4141;
    --red-dark: #c93b3b;
    --bg: #1a1a2e;
    --bg-card: #16213e;
    --bg-item: #1c2a4a;
    --bg-item-hover: #243354;
    --text: #f0f0f0;
    --text-sub: #8a8a9a;
    --text-dim: #5a5a6a;
    --needle: #b8860b;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Hiragino Sans GB', 'Microsoft YaHei', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    min-height: 100dvh;
    overflow-x: hidden;
  }

  /* Header */
  .header {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 16px 20px;
    position: relative;
  }
  .header h1 {
    font-size: 17px;
    font-weight: 600;
    letter-spacing: 1px;
  }
  .header .listeners-badge {
    position: absolute;
    right: 20px;
    font-size: 11px;
    color: var(--text-sub);
    display: flex;
    align-items: center;
    gap: 4px;
  }
  .live-dot {
    width: 6px; height: 6px;
    border-radius: 50%;
    background: var(--red);
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.3; }
  }

  /* Vinyl record */
  .vinyl-container {
    position: relative;
    width: 280px;
    height: 280px;
    margin: 10px auto 0;
  }
  .vinyl {
    width: 280px;
    height: 280px;
    border-radius: 50%;
    background: radial-gradient(circle at center,
      #111 0%, #111 15%,
      #222 15.5%, #1a1a1a 20%,
      #222 25%, #1d1d1d 30%,
      #252525 35%, #1e1e1e 40%,
      #222 45%, #1a1a1a 48%,
      #111 48.5%, #111 100%
    );
    position: relative;
    animation: spin 8s linear infinite;
    animation-play-state: paused;
    box-shadow: 0 0 40px rgba(0,0,0,0.5);
  }
  .vinyl.playing { animation-play-state: running; }
  .vinyl-cover {
    position: absolute;
    top: 50%; left: 50%;
    width: 120px; height: 120px;
    border-radius: 50%;
    transform: translate(-50%, -50%);
    overflow: hidden;
    background: #333;
    border: 3px solid #111;
  }
  .vinyl-cover img {
    width: 100%; height: 100%;
    object-fit: cover;
  }
  .vinyl-cover .placeholder-icon {
    width: 100%; height: 100%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 36px;
    color: #555;
    background: linear-gradient(135deg, #2a2a2a, #3a3a3a);
  }
  .vinyl-hole {
    position: absolute;
    top: 50%; left: 50%;
    width: 12px; height: 12px;
    border-radius: 50%;
    background: var(--bg);
    transform: translate(-50%, -50%);
    z-index: 2;
    border: 2px solid #333;
  }
  /* Needle arm */
  .needle {
    position: absolute;
    top: -10px; right: 30px;
    width: 80px; height: 120px;
    transform-origin: top right;
    transform: rotate(-25deg);
    transition: transform 0.8s cubic-bezier(0.4, 0, 0.2, 1);
    z-index: 3;
  }
  .needle.active { transform: rotate(0deg); }
  .needle-arm {
    width: 3px; height: 100px;
    background: linear-gradient(to bottom, var(--needle), #8B6914);
    margin-left: auto;
    margin-right: 10px;
    border-radius: 2px;
    box-shadow: 1px 1px 3px rgba(0,0,0,0.5);
  }
  .needle-head {
    width: 10px; height: 16px;
    background: #666;
    margin-left: auto;
    margin-right: 7px;
    border-radius: 0 0 3px 3px;
  }
  .needle-pivot {
    width: 18px; height: 18px;
    border-radius: 50%;
    background: radial-gradient(circle, #ddd, #999);
    position: absolute;
    top: -5px; right: 2px;
    box-shadow: 0 2px 4px rgba(0,0,0,0.4);
  }
  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

  /* Track info */
  .track-section {
    text-align: center;
    padding: 20px 24px 10px;
  }
  .track-title {
    font-size: 18px;
    font-weight: 600;
    margin-bottom: 6px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    max-width: 340px;
    margin-left: auto;
    margin-right: auto;
  }
  .track-artist {
    font-size: 13px;
    color: var(--text-sub);
  }

  /* Controls */
  .controls {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 32px;
    padding: 16px 0;
  }
  .ctrl-btn {
    border: none;
    background: none;
    color: var(--text);
    cursor: pointer;
    padding: 8px;
    -webkit-tap-highlight-color: transparent;
  }
  .ctrl-btn svg { display: block; }
  .ctrl-btn.play-btn {
    width: 56px; height: 56px;
    border-radius: 50%;
    background: var(--red);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background 0.2s, transform 0.1s;
  }
  .ctrl-btn.play-btn:active { transform: scale(0.93); background: var(--red-dark); }

  /* Volume */
  .volume-bar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 0 36px 12px;
  }
  .vol-icon { color: var(--text-dim); font-size: 14px; }
  .volume-slider {
    flex: 1;
    -webkit-appearance: none;
    appearance: none;
    height: 3px;
    border-radius: 2px;
    background: #333;
    outline: none;
  }
  .volume-slider::-webkit-slider-thumb {
    -webkit-appearance: none;
    width: 14px; height: 14px;
    border-radius: 50%;
    background: var(--red);
    border: 2px solid #fff;
    box-shadow: 0 0 4px rgba(0,0,0,0.3);
  }

  /* Playlist */
  .playlist {
    background: var(--bg-card);
    border-radius: 20px 20px 0 0;
    min-height: 200px;
    padding: 20px 0 40px;
    margin-top: 8px;
  }
  .playlist-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 20px 14px;
    border-bottom: 1px solid rgba(255,255,255,0.05);
    margin-bottom: 4px;
  }
  .playlist-header h2 {
    font-size: 15px;
    font-weight: 600;
  }
  .playlist-count {
    font-size: 12px;
    color: var(--text-dim);
  }
  .playlist-item {
    display: flex;
    align-items: center;
    padding: 12px 20px;
    gap: 12px;
    transition: background 0.15s;
  }
  .playlist-item:active { background: var(--bg-item-hover); }
  .playlist-item.now-playing { background: var(--bg-item); }
  .pl-index {
    width: 24px;
    font-size: 13px;
    color: var(--text-dim);
    text-align: center;
    flex-shrink: 0;
  }
  .pl-index.active { color: var(--red); }
  .pl-thumb {
    width: 42px; height: 42px;
    border-radius: 6px;
    overflow: hidden;
    flex-shrink: 0;
    background: #2a2a3a;
  }
  .pl-thumb img { width: 100%; height: 100%; object-fit: cover; }
  .pl-info {
    flex: 1;
    min-width: 0;
  }
  .pl-title {
    font-size: 14px;
    font-weight: 500;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .pl-title.active { color: var(--red); }
  .pl-artist {
    font-size: 12px;
    color: var(--text-sub);
    margin-top: 2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
  .pl-duration {
    font-size: 12px;
    color: var(--text-dim);
    flex-shrink: 0;
  }
  .pl-eq {
    display: flex;
    align-items: flex-end;
    gap: 2px;
    height: 16px;
  }
  .pl-eq span {
    width: 3px;
    background: var(--red);
    border-radius: 1px;
    animation: eqBar 0.8s ease-in-out infinite alternate;
  }
  .pl-eq span:nth-child(1) { height: 8px; animation-delay: 0s; }
  .pl-eq span:nth-child(2) { height: 14px; animation-delay: 0.2s; }
  .pl-eq span:nth-child(3) { height: 6px; animation-delay: 0.4s; }
  @keyframes eqBar {
    0% { height: 4px; }
    100% { height: 16px; }
  }

  .empty-playlist {
    text-align: center;
    padding: 40px 20px;
    color: var(--text-dim);
    font-size: 13px;
  }

  .idle-state {
    text-align: center;
    padding: 8px 0;
    color: var(--text-dim);
    font-size: 12px;
  }
</style>
</head>
<body>

<div class="header">
  <h1>Crowbot FM</h1>
  <div class="listeners-badge" id="listenersBadge">
    <span class="live-dot"></span>
    <span id="listenersText">0</span>
  </div>
</div>

<div class="vinyl-container">
  <div class="needle" id="needle">
    <div class="needle-pivot"></div>
    <div class="needle-arm"></div>
    <div class="needle-head"></div>
  </div>
  <div class="vinyl" id="vinyl">
    <div class="vinyl-cover" id="vinylCover">
      <div class="placeholder-icon">&#9835;</div>
    </div>
    <div class="vinyl-hole"></div>
  </div>
</div>

<div class="track-section">
  <div class="track-title" id="trackTitle">Crowbot FM</div>
  <div class="track-artist" id="trackArtist">&#8212;</div>
</div>

<div class="controls">
  <button class="ctrl-btn" id="skipBtn" title="Next">
    <svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor"><path d="M6 18l8.5-6L6 6v12zM16 6v12h2V6h-2z"/></svg>
  </button>
  <button class="ctrl-btn play-btn" id="playBtn" title="Play">
    <svg width="28" height="28" viewBox="0 0 24 24" fill="#fff" id="playIcon"><polygon points="9,6 9,18 18,12"/></svg>
  </button>
  <button class="ctrl-btn" style="visibility:hidden">
    <svg width="28" height="28" viewBox="0 0 24 24"></svg>
  </button>
</div>

<div class="volume-bar">
  <span class="vol-icon">&#128264;</span>
  <input type="range" class="volume-slider" id="volumeSlider" min="0" max="100" value="80">
</div>

<div class="playlist" id="playlist">
  <div class="playlist-header">
    <h2>&#127926; Playlist</h2>
    <span class="playlist-count" id="playlistCount">0 songs</span>
  </div>
  <div id="playlistItems">
    <div class="empty-playlist">Tell Crowbot what to play</div>
  </div>
</div>

<audio id="audio" preload="none"></audio>

<script>
const audio = document.getElementById('audio');
const playBtn = document.getElementById('playBtn');
const playIcon = document.getElementById('playIcon');
const skipBtn = document.getElementById('skipBtn');
const volumeSlider = document.getElementById('volumeSlider');
const trackTitle = document.getElementById('trackTitle');
const trackArtist = document.getElementById('trackArtist');
const vinyl = document.getElementById('vinyl');
const vinylCover = document.getElementById('vinylCover');
const needle = document.getElementById('needle');
const listenersText = document.getElementById('listenersText');
const playlistCount = document.getElementById('playlistCount');
const playlistItems = document.getElementById('playlistItems');

let isAudioPlaying = false;

function formatDuration(s) {
  if (!s) return '';
  const m = Math.floor(s / 60);
  const sec = Math.floor(s % 60);
  return m + ':' + (sec < 10 ? '0' : '') + sec;
}

playBtn.addEventListener('click', () => {
  if (isAudioPlaying) {
    audio.pause();
    audio.src = '';
    isAudioPlaying = false;
    playIcon.innerHTML = '<polygon points="9,6 9,18 18,12"/>';
    vinyl.classList.remove('playing');
    needle.classList.remove('active');
  } else {
    audio.src = '/radio/stream?' + Date.now();
    audio.play().catch(e => console.log('play error:', e));
    isAudioPlaying = true;
    playIcon.innerHTML = '<rect x="7" y="6" width="3.5" height="12" rx="1"/><rect x="13.5" y="6" width="3.5" height="12" rx="1"/>';
    vinyl.classList.add('playing');
    needle.classList.add('active');
  }
});

skipBtn.addEventListener('click', async () => {
  await fetch('/radio/skip', { method: 'POST' });
  updateNow();
});

let volTimer = null;
volumeSlider.addEventListener('input', (e) => {
  clearTimeout(volTimer);
  volTimer = setTimeout(async () => {
    await fetch('/radio/volume', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ volume: Number(e.target.value) }),
    });
  }, 300);
});

async function updateNow() {
  try {
    const [nowRes, qRes] = await Promise.all([
      fetch('/radio/now'),
      fetch('/radio/queue')
    ]);
    const data = await nowRes.json();
    const qData = await qRes.json();

    listenersText.textContent = data.listeners || 0;
    volumeSlider.value = data.volume;

    // Build full playlist: current + queue
    let items = [];
    if (data.isPlaying && data.currentTrack) {
      trackTitle.textContent = data.currentTrack.title;
      trackArtist.textContent = data.currentTrack.artist;

      if (data.currentTrack.thumbnail) {
        vinylCover.innerHTML = '<img src="' + data.currentTrack.thumbnail + '" alt="">';
      } else {
        vinylCover.innerHTML = '<div class="placeholder-icon">&#9835;</div>';
      }

      items.push({
        title: data.currentTrack.title,
        artist: data.currentTrack.artist,
        duration: data.currentTrack.duration,
        thumbnail: data.currentTrack.thumbnail,
        isCurrent: true
      });
    } else {
      trackTitle.textContent = 'Crowbot FM';
      trackArtist.textContent = '\\u2014';
      vinylCover.innerHTML = '<div class="placeholder-icon">&#9835;</div>';
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
        const cls = t.isCurrent ? ' now-playing' : '';
        const idxCls = t.isCurrent ? ' active' : '';
        const titleCls = t.isCurrent ? ' active' : '';
        const idx = t.isCurrent
          ? '<div class="pl-eq"><span></span><span></span><span></span></div>'
          : '<span>' + (i + 1) + '</span>';
        const thumb = t.thumbnail
          ? '<img src="' + t.thumbnail + '" alt="">'
          : '<div style="width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:#555;font-size:16px">&#9835;</div>';
        return '<div class="playlist-item' + cls + '">'
          + '<div class="pl-index' + idxCls + '">' + idx + '</div>'
          + '<div class="pl-thumb">' + thumb + '</div>'
          + '<div class="pl-info">'
          + '<div class="pl-title' + titleCls + '">' + t.title + '</div>'
          + '<div class="pl-artist">' + t.artist + '</div>'
          + '</div>'
          + '<div class="pl-duration">' + formatDuration(t.duration) + '</div>'
          + '</div>';
      }).join('');
    } else {
      playlistItems.innerHTML = '<div class="empty-playlist">Tell Crowbot what to play</div>';
    }
  } catch (e) {
    console.log('update error:', e);
  }
}

updateNow();
setInterval(updateNow, 3000);
</script>
</body>
</html>`;

// ─── End radio routes ───────────────────────────────────────────────────

app.use(async (req, res) => {
  if (!isConfigured() && !req.path.startsWith("/setup")) {
    return res.redirect("/setup");
  }

  if (isConfigured()) {
    if (isGatewayStarting() && !isGatewayReady()) {
      return res.sendFile(path.join(process.cwd(), "src", "public", "loading.html"));
    }

    try {
      await ensureGatewayRunning();
    } catch (err) {
      return res
        .status(503)
        .type("text/plain")
        .send(`Gateway not ready: ${String(err)}`);
    }
  }

  if (req.path === "/openclaw" && !req.query.token) {
    return res.redirect(`/openclaw?token=${OPENCLAW_GATEWAY_TOKEN}`);
  }

  return proxy.web(req, res, { target: GATEWAY_TARGET });
});

const server = app.listen(PORT, () => {
  console.log(`[wrapper] listening on port ${PORT}`);
  console.log(`[wrapper] setup wizard: http://localhost:${PORT}/setup`);
  console.log(`[wrapper] web TUI: ${ENABLE_WEB_TUI ? "enabled" : "disabled"}`);
  console.log(`[wrapper] configured: ${isConfigured()}`);

  if (isConfigured()) {
    ensureGatewayRunning().catch((err) => {
      console.error(`[wrapper] failed to start gateway at boot: ${err.message}`);
    });
  }
});

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
  proxy.ws(req, socket, head, { target: GATEWAY_TARGET });
});

async function gracefulShutdown(signal) {
  console.log(`[wrapper] received ${signal}, shutting down`);

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
