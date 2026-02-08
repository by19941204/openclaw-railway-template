#!/bin/sh
# WARP proxy setup - connects to Cloudflare WARP via sing-box userspace WireGuard
# Exposes a SOCKS5/HTTP proxy on 127.0.0.1:9091 for yt-dlp
set -e

WARP_SERVER="${WARP_SERVER:-engage.cloudflareclient.com}"
WARP_PORT="${WARP_PORT:-2408}"
NET_PORT="${NET_PORT:-9091}"

echo "[warp] Registering with Cloudflare WARP..."
RESPONSE=$(curl -fsSL bit.ly/create-cloudflare-warp | sh -s 2>/dev/null)

CF_CLIENT_ID=$(echo "$RESPONSE" | grep -o '"client":"[^"]*' | cut -d'"' -f4 | head -n 1)
CF_ADDR_V4=$(echo "$RESPONSE" | grep -o '"v4":"[^"]*' | cut -d'"' -f4 | tail -n 1)
CF_ADDR_V6=$(echo "$RESPONSE" | grep -o '"v6":"[^"]*' | cut -d'"' -f4 | tail -n 1)
CF_PUBLIC_KEY=$(echo "$RESPONSE" | grep -o '"key":"[^"]*' | cut -d'"' -f4 | head -n 1)
CF_PRIVATE_KEY=$(echo "$RESPONSE" | grep -o '"secret":"[^"]*' | cut -d'"' -f4 | head -n 1)

if [ -z "$CF_PRIVATE_KEY" ]; then
  echo "[warp] ERROR: Failed to register with Cloudflare WARP"
  exit 1
fi

reserved=$(echo "$CF_CLIENT_ID" | base64 -d | od -An -t u1 | awk '{print "["$1", "$2", "$3"]"}' | head -n 1)

echo "[warp] Got WARP credentials, generating sing-box config..."

cat <<EOF > /etc/sing-box/config.json
{
    "dns": {
        "servers": [
            {
                "tag": "remote",
                "type": "tls",
                "server": "dns.quad9.net",
                "domain_resolver": "local",
                "detour": "direct-out"
            },
            {
                "tag": "local",
                "type": "udp",
                "server": "1.1.1.1",
                "detour": "direct-out"
            }
        ],
        "final": "remote",
        "reverse_mapping": true
    },
    "route": {
        "default_domain_resolver": {
            "server": "local",
            "rewrite_ttl": 60
        },
        "rules": [
            {
                "inbound": "mixed-in",
                "action": "sniff"
            },
            {
                "protocol": "dns",
                "action": "hijack-dns"
            },
            {
                "ip_is_private": true,
                "outbound": "direct-out"
            }
        ],
        "auto_detect_interface": true,
        "final": "WARP"
    },
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": ${NET_PORT}
        }
    ],
    "endpoints": [
        {
            "tag": "WARP",
            "type": "wireguard",
            "address": [
                "${CF_ADDR_V4}/32",
                "${CF_ADDR_V6}/128"
            ],
            "private_key": "${CF_PRIVATE_KEY}",
            "peers": [
                {
                    "address": "${WARP_SERVER}",
                    "port": ${WARP_PORT},
                    "public_key": "${CF_PUBLIC_KEY}",
                    "allowed_ips": [
                        "0.0.0.0/0"
                    ],
                    "persistent_keepalive_interval": 30,
                    "reserved": ${reserved}
                }
            ],
            "mtu": 1408,
            "udp_fragment": true
        }
    ],
    "outbounds": [
        {
            "tag": "direct-out",
            "type": "direct",
            "udp_fragment": true
        }
    ]
}
EOF

echo "[warp] Starting sing-box WARP proxy on 127.0.0.1:${NET_PORT}..."
exec sing-box -c /etc/sing-box/config.json run
