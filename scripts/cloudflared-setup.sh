#!/usr/bin/env bash
# Cloudflare Tunnel setup helper.
#
# Installs cloudflared and creates a tunnel pointing at http://localhost:10000.
# Run on the VPS AFTER `docker compose up -d`.
#
# Usage:
#   bash scripts/cloudflared-setup.sh your-tunnel-name yourdomain.com
#
# Prereqs:
#   - Cloudflare account with the target domain added
#   - cloudflared authenticated: `cloudflared tunnel login`
set -euo pipefail

TUNNEL_NAME="${1:-smtp-verify}"
DOMAIN="${2:-api.example.com}"

if ! command -v cloudflared >/dev/null 2>&1; then
    echo "Installing cloudflared..."
    curl -fsSL https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 -o /usr/local/bin/cloudflared
    chmod +x /usr/local/bin/cloudflared
fi

echo "Creating tunnel: $TUNNEL_NAME"
TUNNEL_ID=$(cloudflared tunnel create "$TUNNEL_NAME" | grep -oE '[a-f0-9-]{36}' | head -1)
echo "Tunnel ID: $TUNNEL_ID"

echo "Routing $DOMAIN -> tunnel"
cloudflared tunnel route dns "$TUNNEL_NAME" "$DOMAIN"

CONFIG_FILE="$HOME/.cloudflared/config.yml"
cat > "$CONFIG_FILE" <<EOF
tunnel: $TUNNEL_ID
credentials-file: $HOME/.cloudflared/$TUNNEL_ID.json

ingress:
  - hostname: $DOMAIN
    service: http://localhost:10000
    originRequest:
      noTLSVerify: true
  - service: http_status:404
EOF

echo "Config written to $CONFIG_FILE"
echo ""
echo "Start tunnel (foreground for testing):"
echo "  cloudflared tunnel run $TUNNEL_NAME"
echo ""
echo "Or install as systemd service (recommended):"
echo "  sudo cloudflared service install"
echo "  sudo systemctl start cloudflared"
echo "  sudo systemctl enable cloudflared"
