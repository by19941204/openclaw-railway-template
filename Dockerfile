FROM node:22-bookworm
# cache-bust: 2026-02-09b

# 1. Install system dependencies (including Chrome/Playwright libs)
RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    gosu \
    procps \
    python3 \
    build-essential \
    # Chrome/Playwright dependencies
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libgbm1 \
    libpango-1.0-0 \
    libcairo2 \
    libasound2 \
    libxshmfence1 \
    libx11-xcb1 \
    libxcb-dri3-0 \
    libxfixes3 \
    libdbus-1-3 \
    libexpat1 \
    libxext6 \
    libx11-6 \
    libxcb1 \
    libxau6 \
    libxdmcp6 \
    fonts-liberation \
    fonts-noto-cjk \
    # Audio tools for radio feature
    ffmpeg \
    python3-pip \
  && rm -rf /var/lib/apt/lists/* \
  && pip3 install --break-system-packages yt-dlp \
  && curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh

# 1b. Install sing-box for Cloudflare WARP proxy (bypasses YouTube IP blocks)
RUN SING_BOX_VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest | grep tag_name | cut -d'"' -f4 | sed 's/v//') \
  && echo "Installing sing-box v${SING_BOX_VERSION}..." \
  && curl -Lo /tmp/sing-box.deb "https://github.com/SagerNet/sing-box/releases/download/v${SING_BOX_VERSION}/sing-box_${SING_BOX_VERSION}_linux_amd64.deb" \
  && (dpkg -i /tmp/sing-box.deb || true) \
  && rm /tmp/sing-box.deb \
  && mkdir -p /etc/sing-box \
  && sing-box version

# 2. Install OpenClaw globally (as root)
RUN npm install -g openclaw@latest

# 3. Create openclaw user BEFORE installing Playwright
RUN useradd -m -s /bin/bash openclaw \
  && mkdir -p /data && chown openclaw:openclaw /data \
  && mkdir -p /home/linuxbrew/.linuxbrew && chown -R openclaw:openclaw /home/linuxbrew \
  && mkdir -p /tmp/radio && chown openclaw:openclaw /tmp/radio

# 4. Install Playwright Chromium as openclaw user so it goes to /home/openclaw/.cache/ms-playwright/
USER openclaw
RUN npx playwright install chromium

# 5. Install Homebrew as openclaw user
RUN NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

ENV PATH="/home/linuxbrew/.linuxbrew/bin:/home/linuxbrew/.linuxbrew/sbin:${PATH}"
ENV HOMEBREW_PREFIX="/home/linuxbrew/.linuxbrew"
ENV HOMEBREW_CELLAR="/home/linuxbrew/.linuxbrew/Cellar"
ENV HOMEBREW_REPOSITORY="/home/linuxbrew/.linuxbrew/Homebrew"

# 6. Copy app files (switch to root for file operations)
USER root
WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile --prod

COPY src ./src
COPY entrypoint.sh ./entrypoint.sh
RUN chown -R openclaw:openclaw /app

ENV PORT=8080
ENV OPENCLAW_ENTRY=/usr/local/lib/node_modules/openclaw/openclaw.mjs
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD curl -f http://localhost:8080/setup/healthz || exit 1

ENTRYPOINT ["./entrypoint.sh"]
