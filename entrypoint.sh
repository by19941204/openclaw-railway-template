#!/bin/bash
set -e

chown -R openclaw:openclaw /data

# Start Cloudflare WARP proxy in background (for yt-dlp to bypass YouTube IP blocks)
# Failures here should NOT prevent the main app from starting
if command -v sing-box &>/dev/null; then
  echo "[entrypoint] Starting WARP proxy..."
  bash /app/src/warp-setup.sh &

  # Wait for WARP proxy to be ready (up to 15 seconds)
  for i in $(seq 1 15); do
    if curl -sf --socks5 127.0.0.1:9091 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"; then
      echo "[entrypoint] WARP proxy is ready (warp=on)"
      break
    fi
    if [ "$i" -eq 15 ]; then
      echo "[entrypoint] WARNING: WARP proxy not ready after 15s, continuing anyway..."
    fi
    sleep 1
  done
else
  echo "[entrypoint] WARNING: sing-box not found, WARP proxy disabled. yt-dlp may fail on YouTube."
fi

exec gosu openclaw node src/server.js
