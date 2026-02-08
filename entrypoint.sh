#!/bin/bash
set -e

chown -R openclaw:openclaw /data

# Install sing-box at runtime if not already present (avoids Docker cache issues)
if ! command -v sing-box &>/dev/null; then
  echo "[entrypoint] Installing sing-box..."
  SING_BOX_VERSION=$(curl -sf https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d'"' -f4 | sed 's/v//') || true
  if [ -n "$SING_BOX_VERSION" ]; then
    curl -sfLo /tmp/sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box_${SING_BOX_VERSION}_linux_amd64.deb" \
      && dpkg -i /tmp/sing-box.deb \
      && rm -f /tmp/sing-box.deb \
      && mkdir -p /etc/sing-box \
      && echo "[entrypoint] sing-box v${SING_BOX_VERSION} installed"
  else
    echo "[entrypoint] WARNING: Could not fetch sing-box version"
  fi
fi

# Start Cloudflare WARP proxy in background (for yt-dlp to bypass YouTube IP blocks)
if command -v sing-box &>/dev/null; then
  echo "[entrypoint] Starting WARP proxy..."
  bash /app/src/warp-setup.sh &

  # Wait for WARP proxy to be ready (up to 20 seconds)
  for i in $(seq 1 20); do
    if curl -sf --socks5 127.0.0.1:9091 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null | grep -q "warp=on"; then
      echo "[entrypoint] WARP proxy is ready (warp=on)"
      break
    fi
    if [ "$i" -eq 20 ]; then
      echo "[entrypoint] WARNING: WARP proxy not ready after 20s, continuing anyway..."
    fi
    sleep 1
  done
else
  echo "[entrypoint] WARNING: sing-box not available, WARP proxy disabled."
fi

exec gosu openclaw node src/server.js
