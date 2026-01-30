import { spawn, spawnSync } from "node:child_process";

const PORT = process.env.PORT || 8080;

const versionCheck = spawnSync("openclaw", ["--version"], { encoding: "utf8" });
if (versionCheck.status !== 0) {
  console.error(versionCheck.stdout || versionCheck.stderr);
  process.exit(versionCheck.status ?? 1);
}
console.log("✓ openclaw version:", versionCheck.stdout.trim());

console.log(`Starting server on port ${PORT}...`);
const serverProc = spawn("node", ["src/server.js"], {
  env: { ...process.env, PORT: String(PORT), SETUP_PASSWORD: "smoke-test" },
  stdio: ["ignore", "pipe", "pipe"],
});

let serverOutput = "";
serverProc.stdout.on("data", (d) => (serverOutput += d.toString()));
serverProc.stderr.on("data", (d) => (serverOutput += d.toString()));

async function waitForServer(maxWaitMs = 10000) {
  const start = Date.now();
  while (Date.now() - start < maxWaitMs) {
    try {
      const res = await fetch(`http://localhost:${PORT}/setup/healthz`);
      if (res.ok) return true;
    } catch {
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  return false;
}

async function runTests() {
  try {
    const ready = await waitForServer();
    if (!ready) {
      console.error("✗ Server did not become ready");
      console.error("Server output:", serverOutput);
      process.exit(1);
    }
    console.log("✓ Server started on port", PORT);

    const healthRes = await fetch(`http://localhost:${PORT}/setup/healthz`);
    if (!healthRes.ok) {
      console.error("✗ /setup/healthz returned", healthRes.status);
      process.exit(1);
    }
    const healthBody = await healthRes.json();
    if (!healthBody.ok) {
      console.error("✗ /setup/healthz returned unexpected body:", healthBody);
      process.exit(1);
    }
    console.log("✓ /setup/healthz returns 200 with { ok: true }");

    console.log("\n✓ All smoke tests passed");
  } finally {
    serverProc.kill("SIGTERM");
  }
}

runTests().catch((err) => {
  console.error("Smoke test error:", err);
  serverProc.kill("SIGTERM");
  process.exit(1);
});
