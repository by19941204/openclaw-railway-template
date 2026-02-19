#!/bin/bash
set -e

# ── Disk cleanup (prevent ENOSPC) ──────────────────────────────────
echo "[entrypoint] disk before cleanup:"
df -h /data 2>/dev/null || true
echo "[entrypoint] top space consumers:"
du -sh /data/* /data/.openclaw/* /data/.linuxbrew 2>/dev/null | sort -rh | head -15 || true

# Clear Chrome cache (cookies/localStorage survive, cache is expendable)
rm -rf /data/.openclaw/browser/*/Cache 2>/dev/null || true
rm -rf /data/.openclaw/browser/*/Code\ Cache 2>/dev/null || true
rm -rf /data/.openclaw/browser/*/GPUCache 2>/dev/null || true
rm -rf /data/.openclaw/browser/*/Service\ Worker/CacheStorage 2>/dev/null || true
rm -rf /data/.openclaw/browser/*/blob_storage 2>/dev/null || true
rm -rf /data/.openclaw/browser/*/IndexedDB 2>/dev/null || true

# Clear radio temp files
rm -rf /tmp/radio/* 2>/dev/null || true

# Clear stale gateway lock files (prevents "gateway already running" deadloop)
rm -rf /tmp/openclaw-*/gateway.*.lock 2>/dev/null || true
rm -f /data/.openclaw/gateway.lock /data/.openclaw/gateway.pid 2>/dev/null || true
pkill -f 'openclaw.*gateway' 2>/dev/null || true

# Clear old config backups
find /data/.openclaw -name "*.bak" -o -name "*.bak.*" | head -20 | xargs rm -f 2>/dev/null || true

# Clear openclaw update/cache dirs
rm -rf /data/.openclaw/cache 2>/dev/null || true
rm -rf /data/.openclaw/tmp 2>/dev/null || true

# If still >90% full, remove old session data (keeps last 5)
USAGE=$(df /data 2>/dev/null | tail -1 | awk '{print int($5)}')
if [ "${USAGE:-0}" -gt 90 ]; then
  echo "[entrypoint] WARNING: disk ${USAGE}% full, aggressive cleanup..."
  # Remove old sessions (keep most recent 5)
  ls -dt /data/.openclaw/agents/*/sessions/*/ 2>/dev/null | tail -n +6 | xargs rm -rf 2>/dev/null || true
  # Remove linuxbrew cache
  rm -rf /data/.linuxbrew/Homebrew/Library/Taps/homebrew/homebrew-core 2>/dev/null || true
  rm -rf /data/.linuxbrew/Homebrew/Library/Homebrew/vendor/bundle 2>/dev/null || true
fi

echo "[entrypoint] disk after cleanup:"
df -h /data 2>/dev/null || true
# ── End cleanup ────────────────────────────────────────────────────

chown -R openclaw:openclaw /data
chmod 700 /data

# Persist Homebrew installs on the Railway Volume.
if [ ! -d /data/.linuxbrew ]; then
  cp -a /home/linuxbrew/.linuxbrew /data/.linuxbrew
fi

rm -rf /home/linuxbrew/.linuxbrew
ln -sfn /data/.linuxbrew /home/linuxbrew/.linuxbrew

# Persist Chrome/Playwright browser profile on the Railway Volume.
# OpenClaw stores Chrome user-data under $HOME/.openclaw/browser/ by default,
# which lives in the ephemeral container filesystem and is wiped on every deploy.
# By symlinking it to /data/.openclaw/browser/ (on the persistent volume),
# cookies, login sessions, and localStorage survive across deployments.
BROWSER_VOLUME_DIR="/data/.openclaw/browser"
BROWSER_HOME_DIR="/home/openclaw/.openclaw/browser"

mkdir -p "$BROWSER_VOLUME_DIR"
mkdir -p "$(dirname "$BROWSER_HOME_DIR")"
# Fix ownership of ~/.openclaw parent dir (may be root-owned from previous runs)
chown openclaw:openclaw "$(dirname "$BROWSER_HOME_DIR")"

# If the home dir already exists as a real directory (not a symlink), remove it
# so we can replace it with a symlink to the volume.
if [ -d "$BROWSER_HOME_DIR" ] && [ ! -L "$BROWSER_HOME_DIR" ]; then
  rm -rf "$BROWSER_HOME_DIR"
fi

# Create symlink: ~/.openclaw/browser -> /data/.openclaw/browser
if [ ! -L "$BROWSER_HOME_DIR" ]; then
  ln -s "$BROWSER_VOLUME_DIR" "$BROWSER_HOME_DIR"
fi

chown -R openclaw:openclaw "$BROWSER_VOLUME_DIR"
chown -h openclaw:openclaw "$BROWSER_HOME_DIR"
chown openclaw:openclaw "$(dirname "$BROWSER_HOME_DIR")"

exec gosu openclaw node src/server.js
