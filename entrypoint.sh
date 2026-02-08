#!/bin/bash
set -e

chown -R openclaw:openclaw /data

# Start Cloudflare WARP proxy in background (for yt-dlp to bypass YouTube IP blocks)
echo "[entrypoint] Starting WARP proxy..."
bash /app/src/warp-setup.sh &
WARP_PID=$!

# Wait for WARP proxy to be ready (up to 15 seconds)
for i in $(seq 1 15); do
  if curl -sf --socks5 127.0.0.1:9091 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"; then
    echo "[entrypoint] WARP proxy is ready (warp=on)"
    break
  fi
  if [ $i -eq 15 ]; then
    echo "[entrypoint] WARNING: WARP proxy may not be ready, continuing anyway..."
  fi
  sleep 1
done

exec gosu openclaw node src/server.js
