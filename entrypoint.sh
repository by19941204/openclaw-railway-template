#!/bin/bash
set -e
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
