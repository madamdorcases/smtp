#!/usr/bin/env bash
# Issue a Let's Encrypt cert for the mail subdomain on the VPS host.
#
# Run this ON THE VPS HOST (not inside the container), as root, BEFORE
# starting the smtp-relay container.
#
# Prerequisites:
#   - DNS A record for mail.api-solv-rix-ai.top → 51.38.40.174 (your VPS IP)
#   - Port 80 reachable from the internet (certbot --standalone uses it)
#   - Stop anything else using port 80 first (e.g. `docker stop smtp-relay`)
#
# After this script runs:
#   - Cert files are at /etc/letsencrypt/live/mail.api-solv-rix-ai.top/
#   - The smtp-relay container will auto-load them on next start
#   - Add a cron job to renew every 60 days (see bottom of this script)

set -euo pipefail

DOMAIN="${1:-mail.api-solv-rix-ai.top}"
EMAIL="${2:-admin@api-solv-rix-ai.top}"

echo "[1/4] Installing certbot..."
if ! command -v certbot >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq certbot
fi

echo "[2/4] Checking DNS for ${DOMAIN}..."
IP=$(dig +short "${DOMAIN}" A | head -1 || true)
if [ -z "${IP}" ]; then
    echo "ERROR: ${DOMAIN} does not resolve. Add an A record pointing to this VPS first."
    exit 1
fi
echo "  ${DOMAIN} → ${IP}"

# Get the VPS's public IP
PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org || \
            curl -s --max-time 5 http://ifconfig.me || true)
if [ -n "${PUBLIC_IP}" ] && [ "${IP}" != "${PUBLIC_IP}" ]; then
    echo "WARNING: ${DOMAIN} resolves to ${IP}, but this VPS's public IP is ${PUBLIC_IP}"
    echo "         DNS may not have propagated yet, or the A record is wrong."
    echo "         Continuing anyway (certbot will fail if DNS is wrong)..."
fi

echo "[3/4] Making sure port 80 is free..."
# Stop the smtp-relay container if it's running (it doesn't use port 80 normally,
# but check anyway in case something else does)
if docker ps --format '{{.Names}}' | grep -q '^smtp-relay$'; then
    echo "  Stopping smtp-relay container to free port 80..."
    docker stop smtp-relay || true
    RESTART_RELAY=1
else
    RESTART_RELAY=0
fi

# Anything else on port 80?
if ss -tlnp | grep -q ':80\s'; then
    PID_80=$(ss -tlnp | grep ':80\s' | grep -oP 'pid=\K[0-9]+' | head -1 || true)
    if [ -n "${PID_80}" ]; then
        echo "  Port 80 is in use by PID ${PID_80} ($(cat /proc/${PID_80}/cmdline | tr '\0' ' '))"
        echo "  Stop it and re-run this script."
        exit 1
    fi
fi

echo "[4/4] Requesting cert from Let's Encrypt..."
certbot certonly \
    --standalone \
    --non-interactive \
    --agree-tos \
    --email "${EMAIL}" \
    --domains "${DOMAIN}" \
    --keep-until-expiring

echo
echo "==================================================================="
echo "SUCCESS — cert issued for ${DOMAIN}"
echo "==================================================================="
echo
echo "Cert files:"
echo "  /etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
echo "  /etc/letsencrypt/live/${DOMAIN}/privkey.pem"
echo

# Note: the smtp-relay container expects the cert at
# /etc/letsencrypt/live/<DOMAIN>/ where <DOMAIN> is the value of DOMAIN in .env.
# If your .env DOMAIN is `api-solv-rix-ai.top` (not `mail.api-solv-rix-ai.top`),
# we need to either:
#   (a) issue the cert for api-solv-rix-ai.top (and add a SAN for mail.api-solv-rix-ai.top)
#   (b) symlink /etc/letsencrypt/live/api-solv-rix-ai.top → mail.api-solv-rix-ai.top
# The smtp_server.py looks up /etc/letsencrypt/live/<DOMAIN>/ where DOMAIN is
# the bare domain (api-solv-rix-ai.top), so let's issue a cert for BOTH:
ROOT_DOMAIN="${DOMAIN#mail.}"
if [ "${ROOT_DOMAIN}" != "${DOMAIN}" ]; then
    echo "Also issuing cert for root domain ${ROOT_DOMAIN} (and SAN ${DOMAIN})..."
    certbot certonly \
        --standalone \
        --non-interactive \
        --agree-tos \
        --email "${EMAIL}" \
        --domains "${ROOT_DOMAIN},${DOMAIN}" \
        --keep-until-expiring
fi

# Set up auto-renewal
echo "Setting up auto-renewal cron job..."
cat > /etc/cron.d/certbot-renew <<EOF
# Auto-renew Let's Encrypt certs every 60 days at 03:00 UTC
0 3 */60 * * root certbot renew --quiet --deploy-hook "docker restart smtp-relay" >> /var/log/certbot-renew.log 2>&1
EOF
chmod 644 /etc/cron.d/certbot-renew
echo "  Added /etc/cron.d/certbot-renew"
echo

# Restart the smtp-relay container if we stopped it
if [ "${RESTART_RELAY}" = "1" ]; then
    echo "Restarting smtp-relay container..."
    docker start smtp-relay || true
fi

echo "Done. You can now start the smtp-relay container (if not already running):"
echo "  cd /app && docker compose up -d --build"
