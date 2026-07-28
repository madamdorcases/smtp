# Pure SMTP Relay — Verification Email Server (RocketVPS)

A clean, minimal SMTP relay server for **sending verification emails only**.

**No HTTP API. No admin panel. No Render code. No FastAPI. No receiving.**

## What this is

- **SMTP server** on port `465` (implicit TLS) + port `587` (STARTTLS)
- **Authenticated** — SMTP users with username + password (Argon2-hashed, Redis-backed)
- **DKIM-signed** outbound mail
- **Spam-protected** (see below)
- **Send-only** — refuses any RCPT TO addressed to your own domain
- **1000 emails/minute** per-user rate limit
- **24/7 operation** — Docker `restart: always`, no sleep mechanism
- **Standard SSL** — Let's Encrypt cert via certbot
- **15-min auto-delete** — ALL data (logs, queue, Redis, temp files) wiped every 15 min
- **Logs on VPS disk** at `/var/log/smtp-relay/` (host-mounted, not inside container)

## Spam protections (all enabled)

| # | Check | Default | Configurable via |
|---|-------|---------|------------------|
| 1 | Per-user rate limit | **1000/min**, 60000/hour | `RATE_PER_MINUTE_PER_KEY`, `RATE_PER_HOUR_PER_KEY` |
| 2 | Send-only enforcement | refuse RCPT to own domain | always on |
| 3 | Blocked recipient domains | (none) | `BLOCKED_RECIPIENT_DOMAINS=spam.com,bad.tld` |
| 4 | Allowed recipient domains | (allow all) | `ALLOWED_RECIPIENT_DOMAINS=gmail.com,outlook.com` |
| 5 | Max recipients per message | 50 | (edit `_MAX_RECIPIENTS_PER_MESSAGE`) |
| 6 | Max message size | 100 KB | `SMTP_MAX_MESSAGE_BYTES` |
| 7 | Header-injection check | reject malformed headers | always on |
| 8 | Dangerous attachment filter | blocks .exe/.zip/.scr/.bat/etc. (23 exts) | always on |
| 9 | Spam keyword filter | built-in 16-keyword list | (edit `_DEFAULT_SPAM_KEYWORDS`) |
| 10 | DNSBL check on client IP | disabled | `AUTO_PAUSE_ON_BLACKLIST=true` |
| 11 | Brute-force lockout | 5 attempts → 15 min lock | `BRUTE_FORCE_MAX_ATTEMPTS` |
| 12 | From-header domain spoof check | must match `DOMAIN` | always on |
| 13 | TLS required on outbound | yes | `OUTBOUND_TLS_REQUIRED=true` |

## 15-minute auto-delete (no persistent data)

Every 15 minutes, the cleanup worker (`core/cleanup.py`):

1. **`FLUSHDB`** on Redis — wipes ALL keys (queue, rate-limit counters, user records)
2. **Re-creates SMTP users** from `SMTP_USERS` env var (so you don't get locked out)
3. **Truncates** all `*.log` files in `/var/log/smtp-relay/`
4. **Removes** any `/tmp/smtp-relay-*` temp files

Result: after 15 minutes, the server has **zero memory** of what it sent. No logs, no queue, no user data (until re-bootstrap).

Redis is also configured with `--save ""` and `--appendonly no` — no on-disk persistence even between cleanup passes.

## Deploy steps

### 1. Upload to VPS

```bash
scp -P 20051 smtp-relay.zip root@51.38.40.174:/root/
ssh -p 20051 root@51.38.40.174
cd /root
unzip smtp-relay.zip
cd smtp-relay
```

### 2. Create the log directory on the host

```bash
mkdir -p /var/log/smtp-relay
```

### 3. Edit `.env` (change the default SMTP password!)

```bash
nano .env
# Find: SMTP_USERS=alice:ChangeMe123!@#
# Change to: SMTP_USERS=alice:YOUR_STRONG_PASSWORD
```

### 4. Issue Let's Encrypt SSL cert (BEFORE starting the container)

```bash
chmod +x scripts/get_cert.sh
./scripts/get_cert.sh mail.api-solv-rix-ai.top admin@api-solv-rix-ai.top
```

### 5. Stop the OLD container (if running)

```bash
docker stop solvmate-smtp 2>/dev/null
docker rm solvmate-smtp 2>/dev/null
```

### 6. Open firewall ports

```bash
ufw allow 465/tcp    # SMTP implicit TLS (PRIMARY)
ufw allow 587/tcp    # SMTP STARTTLS (optional)
ufw reload
```

### 7. Start the SMTP relay

```bash
docker compose up -d --build
```

### 8. Watch the logs

```bash
docker compose logs -f smtp-relay
```

You should see:

```
{"domain": "api-solv-rix-ai.top", "environment": "production", "event": "app.starting", ...}
{"url": "redis://smtp-redis:6379/0", "event": "redis.connected", ...}
{"event": "users.bootstrapped", "count": 1, ...}
{"event": "ssl.letsencrypt", "domain": "api-solv-rix-ai.top", ...}
{"event": "smtp.listening", "port": 465, "mode": "implicit_tls", ...}
{"event": "smtp.listening", "port": 587, "mode": "starttls", ...}
{"event": "cleanup.starting", "interval_s": 900, "log_dir": "/var/log/smtp-relay", ...}
{"event": "app.ready", "ports": [465, 587], "domain": "api-solv-rix-ai.top", "ttl_seconds": 900, ...}
```

After 15 minutes, you'll see:

```
{"event": "cleanup.completed", "redis_keys_deleted": 5, "users_recreated": 1, "logs_truncated": 1, ...}
```

### 9. Check the host log file

```bash
ls -la /var/log/smtp-relay/
cat /var/log/smtp-relay/smtp-relay.log | tail -50
```

### 10. Test the SMTP server

From your local machine:

```bash
openssl s_client -connect mail.api-solv-rix-ai.top:465 -crlf
# Should show real Let's Encrypt cert + "220 mail.api-solv-rix-ai.top ESMTP"
```

Or use a mail client (Thunderbird, your app's SMTP library) with:

| Field | Value |
|-------|-------|
| SMTP server | `mail.api-solv-rix-ai.top` |
| Port | `465` |
| Security | SSL/TLS (implicit) |
| Username | `alice` |
| Password | (whatever you set in `.env`) |

### 11. Test sending a verification email

```bash
# From the VPS host (or any machine with python)
python3 -c "
import smtplib
from email.mime.text import MIMEText

msg = MIMEText('Your verification code is 123456')
msg['Subject'] = 'Verify your email'
msg['From'] = 'noreply@api-solv-rix-ai.top'
msg['To'] = 'your-personal-email@gmail.com'

with smtplib.SMTP_SSL('mail.api-solv-rix-ai.top', 465) as s:
    s.login('alice', 'YOUR_STRONG_PASSWORD')
    s.send_message(msg)
print('sent')
"
```

## Managing SMTP users

```bash
# List users
docker exec -it smtp-relay python scripts/manage_user.py list

# Add a user
docker exec -it smtp-relay python scripts/manage_user.py add bob 'S3cure!Pass#99'

# Add a user with random 20-char password
docker exec -it smtp-relay python scripts/manage_user.py generate charlie

# Reset a user's password
docker exec -it smtp-relay python scripts/manage_user.py reset alice 'NewPass!2026'

# Remove a user
docker exec -it smtp-relay python scripts/manage_user.py remove bob
```

> **Note:** Because the cleanup worker wipes Redis every 15 min, users created
> via the CLI will be lost at the next cleanup pass. Only users defined in the
> `SMTP_USERS` env var (in `.env`) are automatically re-created. To make a
> user permanent, add them to `.env` and run `docker compose up -d`.

## 24/7 operation

- **`restart: always`** on both `smtp-redis` and `smtp-relay` services — Docker restarts them on crash, reboot, or OOM.
- **Health check** on port `465` — if SMTP stops accepting TLS, Docker restarts the container.
- **No sleep mechanism anywhere** — no self-ping, no auto-sleep code.
- **Log rotation** — `max-size: 10m`, `max-file: 3` for Docker stdout logs.

## SSL certificate renewal

`scripts/get_cert.sh` installs `/etc/cron.d/certbot-renew`:

```
0 3 */60 * * root certbot renew --quiet --deploy-hook "docker restart smtp-relay"
```

Every 60 days at 03:00 UTC, certbot renews if needed and restarts the container to load new files.

## File structure

```
smtp-relay/
├── config.py              # Config class (verbatim) + typed adapter
├── smtp_main.py           # Entry point — pure SMTP + cleanup worker
├── core/
│   ├── redis_client.py    # Redis connection
│   ├── smtp_users.py      # SMTP user CRUD (Argon2-hashed, Redis-backed)
│   ├── smtp_server.py     # aiosmtpd handler + AUTH + DKIM sign + enqueue
│   ├── dkim_signer.py     # DKIM sign outbound messages
│   ├── outbound.py        # MX lookup + TLS delivery + retry
│   ├── queue.py           # Redis queue + background worker (15-min TTL)
│   ├── spam.py            # 13 spam checks incl. send-only + injection + attachments
│   └── cleanup.py         # 15-min auto-delete (Redis FLUSHDB + log truncate)
├── scripts/
│   ├── manage_user.py     # CLI: add/remove/list/reset SMTP users
│   └── get_cert.sh        # Let's Encrypt cert + auto-renewal cron
├── Dockerfile             # Slim Python image, ports 465+587, log dir
├── docker-compose.yml     # smtp-redis + smtp-relay, restart: always, log mount
├── requirements.txt       # No FastAPI/uvicorn/jinja2/pydantic-settings
├── .env                   # Fixed domain, 1000/min, 15-min cleanup, no Render
└── README.md              # This file
```

## Troubleshooting

### `ssl.self_signed` in logs
Cert files missing at `/etc/letsencrypt/live/api-solv-rix-ai.top/`. Run `scripts/get_cert.sh`.

### Mail goes to spam
1. Check PTR: `dig -x 51.38.40.174 +short` → must return `mail.api-solv-rix-ai.top.`
2. Check SPF/DKIM/DMARC at https://www.mail-tester.com/
3. Check IP not blacklisted: https://check.spamhaus.org/

### "Send-only — cannot deliver to @api-solv-rix-ai.top"
This is intentional. The server refuses to deliver mail to your own domain. Use a different SMTP server (or no server) to receive replies — this one is for sending verification emails only.

### Users disappear after 15 min
The cleanup worker wipes Redis every 15 min. Only users in the `SMTP_USERS` env var are re-created automatically. To make a user permanent, add them to `.env` and run `docker compose up -d`.

### Logs are empty
Check the host directory is mounted: `ls /var/log/smtp-relay/`. If empty, verify `docker compose ps` shows smtp-relay as `Up`. The in-container log file is at `/var/log/smtp-relay/smtp-relay.log` (same path thanks to the volume mount).
