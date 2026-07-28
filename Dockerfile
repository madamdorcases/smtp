# Pure SMTP relay — slim Python image with openssl for cert handling.
# No internal Redis, no HTTP server. Only ports 465 and 587 are exposed.
#
# Build:
#   docker build -t smtp-relay .
#
# Run (use docker-compose.yml instead — it handles Redis + restart policy):
#   docker run -d --name smtp-relay \
#     --restart always \
#     -p 465:465 -p 587:587 \
#     -v /etc/letsencrypt:/etc/letsencrypt:ro \
#     -v /app/.env:/app/.env:ro \
#     --env-file /app/.env \
#     --link smtp-redis:redis \
#     smtp-relay

FROM python:3.12-slim AS base

# --- System deps ---
# openssl    → DKIM key generation, self-signed cert fallback
# ca-certificates → TLS verification for outbound SMTP
# tini       → proper PID 1 signal handling (so SIGTERM works)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
        tini \
        && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# --- Python deps (cached layer) ---
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# --- App code ---
COPY . .

# Create the in-container log directory. The host directory is mounted over
# this at runtime, but we create it here so the image works standalone too.
RUN mkdir -p /var/log/smtp-relay

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_DIR=/var/log/smtp-relay

# Only SMTP ports — NO HTTP port exposed
EXPOSE 465 587

# tini ensures SIGTERM propagates so docker stop triggers clean shutdown
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "smtp_main.py"]
