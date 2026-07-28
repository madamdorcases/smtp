FROM python:3.12-slim AS base

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
        tini \
        && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

RUN mkdir -p /var/log/smtp-relay

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_DIR=/var/log/smtp-relay

EXPOSE 465 587
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "smtp_main.py"]
