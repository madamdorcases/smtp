# SMTP Verification Service

Privacy-focused, send-only SMTP microservice for **transactional verification emails**
(signup codes, 2FA, login links, withdrawal confirmations). Designed for a 512MB / 1GB
VPS with MongoDB Atlas free tier as the persistent store.

**Not a bulk mailer. Not a spam relay. Not an inbox.** Built for high-security,
low-volume one-to-one emails to your own users, where every request must be
end-to-end encrypted and cryptographically signed.

---

## Design Principles

| Principle | Implementation |
|---|---|
| Empty terminal | uvicorn `--log-level critical --no-access-log`; all Python loggers set to `CRITICAL` |
| All logs → MongoDB only | Custom `smtp/logger.py` writes to `email_logs`, `api_debug_logs`, `smtp_debug_logs`. Never stdout / stderr / files |
| Auto-expiring logs | TTL indexes: 24h for logs, 1h for `temp_storage` |
| Permanent config | `allowed_apps`, `api_keys`, `admin_settings`, `dkim_keys`, `permanent_events` — no TTL |
| Ephemeral queue | Redis with `--save "" --appendonly no` (no disk). Keys auto-expire |
| Temp data cleanup | Context managers + explicit `del` + `gc.collect()` per request and worker iteration |
| Request encryption | AES-256-GCM envelope. Key = `bytes.fromhex(ADMIN_CURVE_KEY)` |
| Request signing | Bitcoin-style ECDSA secp256k1 (r, s, z) over canonical JSON of the message |
| IP allowlist | Per-request `allowed_ip` must match (a) client real IP, (b) stored value in MongoDB |
| Admin auth | `api_pub_key` in request must equal admin's derived pub key from `.env` |
| SMTP isolation | Send-only via relay (port 465 TLS). No inbound SMTP, no port mapping |
| No Cloudflare Tunnel | App listens on `0.0.0.0:15484` — admin secures VPS firewall manually |

---

## File Layout

```
smtp_project/
├── .env                    # Your real config (DO NOT commit)
├── .env.example            # Template
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── README.md
├── app.py                  # FastAPI entrypoint (0.0.0.0:15484)
├── smtp/
│   ├── __init__.py
│   ├── config.py           # python-dotenv + os.environ.get
│   ├── database.py         # Motor + TTL indexes + collection helpers
│   ├── redis_client.py     # Async Redis (BLPOP queue)
│   ├── security.py         # AES-256-GCM + ECDSA secp256k1 (r/s/z) + SHA-256
│   ├── logger.py           # MongoDB-only logger (zero stdout)
│   ├── auth.py             # Unified decrypt + signature + IP verify
│   ├── worker.py           # Background queue processor with gc.collect()
│   ├── email_sender.py     # aiosmtplib relay on port 465 + DKIM sign
│   ├── dkim_signer.py      # dkimpy, keypair stored in MongoDB
│   └── models.py           # Pydantic request/response schemas
├── routes/
│   ├── __init__.py
│   ├── health.py           # GET  /api/health          (public, no auth)
│   ├── send.py             # POST /api/send            (encrypted + signed)
│   ├── status.py           # GET  /api/status/{id}     (encrypted + signed)
│   └── admin.py            # /admin/*                  (encrypted + signed, admin key)
└── scripts/
    ├── init_db.py          # One-time: indexes + DKIM keypair + DNS records
    └── example_client.py   # Reference client (signs + encrypts requests)
```

---

## Request Flow (every authenticated endpoint)

```
Client                                Server
  │                                     │
  │  1. Build message dict              │
  │     {                               │
  │       api_pub_key: "<hex>",         │
  │       allowed_ip: "1.2.3.4",        │
  │       to_email: "...",              │
  │       subject: "...",               │
  │       discription: "..."            │
  │     }                               │
  │                                     │
  │  2. z = SHA-256(canonical(message)) │
  │  3. (r,s) = ECDSA-sign(z, priv)     │
  │  4. envelope = {                    │
  │       signatures: {_r, _s, _z},     │
  │       message: {...}                │
  │     }                               │
  │  5. secrate_data = AES-GCM(         │
  │       key = ADMIN_CURVE_KEY bytes,  │
  │       plaintext = JSON(envelope))   │
  │                                     │
  │  POST {"secrate_data": "<base64>"}  │
  │ ─────────────────────────────────→  │
  │                                     │
  │                       Decrypt AES   │
  │                       Verify z      │
  │                       Verify (r,s)  │
  │                       Lookup pub    │
  │                       Verify IP     │
  │                                     │
  │  ← 200 {"secrate_data": "<base64>"} │
  │  (or 401 on any failure)            │
  │                                     │
  │  Client decrypts response with      │
  │  same ADMIN_CURVE_KEY               │
```

**Failure → 401 Unauthorized.** Always.

---

## Setup

### 1. VPS prep

Provision a 512MB+ VPS (Debian/Ubuntu). Install Docker + Docker Compose.

**Firewall:** only allow inbound TCP 15484 from trusted IPs (your office, your app servers). Do NOT expose it to 0.0.0.0/0 — the API is private.

```bash
ufw allow 22/tcp
ufw allow from <your-app-server-ip> to any port 15484
ufw enable
```

### 2. Configure environment

```bash
cd smtp_project
# .env is already filled in with your values. Edit if needed.
nano .env
```

To generate a fresh `ADMIN_CURVE_KEY` (if you ever want to rotate):
```bash
docker run --rm python:3.11-slim python -c "from cryptography.hazmat.primitives.asymmetric import ec; print(ec.generate_private_key(ec.SECP256K1()).private_numbers().private_value.to_bytes(32,'big').hex())"
```

### 3. Start services

```bash
docker compose up -d --build
```

Terminal stays empty by design.

### 4. Initialize DB + print DNS records

```bash
docker compose exec smtp-app python scripts/init_db.py
```

Publish:
- DKIM TXT record at `smtp1._domainkey.api-solv-rix-ai.top`
- SPF TXT at `api-solv-rix-ai.top` → `"v=spf1 a mx -all"`
- DMARC TXT at `_dmarc.api-solv-rix-ai.top` → `"v=DMARC1; p=quarantine; rua=mailto:admin@api-solv-rix-ai.top"`

Verify with `dig TXT smtp1._domainkey.api-solv-rix-ai.top`.

### 5. Register your first allowed_app

Use `scripts/example_client.py` (run from your local machine, not the VPS):

```bash
# Generate an ECDSA keypair for your app
python3 -c "from cryptography.hazmat.primitives.asymmetric import ec; \
  k=ec.generate_private_key(ec.SECP256K1()); \
  print('PRIV:', k.private_numbers().private_value.to_bytes(32,'big').hex()); \
  print('PUB :', k.public_key().public_bytes(__import__('cryptography.hazmat.primitives.serialization',fromlist=['*']).Encoding.X962, __import__('cryptography.hazmat.primitives.serialization',fromlist=['*']).PublicFormat.UncompressedPoint).hex())"
```

Register the app with the admin:

```bash
python3 scripts/example_client.py \
  --url http://YOUR-VPS-IP:15484/admin/allowed-apps \
  --method POST \
  --privkey 8510e43ccf7b33e4f39ff5147a4e985b9c806430a003277e671527e9898f990d \
  --admin-curvehex 8510e43ccf7b33e4f39ff5147a4e985b9c806430a003277e671527e9898f990d \
  --client-ip YOUR.PUBLIC.IP.ADDRESS \
  --message '{"payload":{"app_name":"my-app","api_pub_key":"<APP_PUB_HEX>","allowed_ips":["YOUR.APP.SERVER.IP"]}}'
```

### 6. Send a verification email

From your app server (its IP must be in `allowed_ips`):

```bash
python3 scripts/example_client.py \
  --url http://YOUR-VPS-IP:15484/api/send \
  --method POST \
  --privkey <APP_ECC_PRIV_HEX> \
  --admin-curvehex 8510e43ccf7b33e4f39ff5147a4e985b9c806430a003277e671527e9898f990d \
  --client-ip YOUR.APP.SERVER.IP \
  --message '{"to_email":"user@gmail.com","subject":"Your verification code","discription":"123456"}'
```

Response (decrypted):
```json
{"message_id": "abc-123", "status": "queued"}
```

---

## API Reference

### `GET /api/health` (public)
Returns `{"status":"ok"}`. No auth, no logging.

### `POST /api/send` (encrypted + signed)
**Message fields:** `api_pub_key`, `allowed_ip`, `to_email`, `subject`, `discription`
**Response:** `{"message_id": "...", "status": "queued"}`

### `GET /api/status/{message_id}` (encrypted + signed)
**Message fields:** `api_pub_key`, `allowed_ip` (path param provides message_id)
**Response:** `{"status": "sent|failed|queued|sending|expired", "error": null, "to": "...", "subject": "..."}`

### `/admin/*` (encrypted + signed, admin key required)

| Method | Path | Purpose |
|---|---|---|
| GET | `/admin/allowed-apps` | List registered apps |
| POST | `/admin/allowed-apps` | Register new app. Payload: `{app_name, api_pub_key, allowed_ips, enabled}` |
| DELETE | `/admin/allowed-apps/{id}` | Remove app |
| GET | `/admin/api-keys` | List admin API keys |
| POST | `/admin/api-keys` | Create admin API key (returns private_key once) |
| DELETE | `/admin/api-keys/{id}` | Remove API key |
| GET | `/admin/logs?type=email\|api\|smtp&hours=24` | View 24h logs (max 500 rows) |
| GET | `/admin/stats` | sent_24h / failed_24h / queued_now / api_requests_24h |
| GET | `/admin/settings` | View admin_allowed_ips + rate limits |
| PUT | `/admin/settings` | Update. Payload: `{settings: {admin_allowed_ips: [...], ...}}` |
| GET | `/admin/dkim` | View DKIM DNS record to publish |

Admin requests use the same envelope format. The `api_pub_key` field must match the admin's public key derived from `ADMIN_CURVE_KEY` in `.env`.

---

## MongoDB Collections

| Collection | TTL | Purpose |
|---|---|---|
| `allowed_apps` | — | Registered external apps (api_pub_key + allowed_ips) |
| `api_keys` | — | Admin's own API keys (permanent) |
| `admin_settings` | — | admin_allowed_ips, rate limits (permanent) |
| `dkim_keys` | — | DKIM private keys per selector (permanent) |
| `permanent_events` | — | Audit log: app creation, key rotation, settings changes (permanent) |
| `email_logs` | 24h | Per-email: to, subject, status, error |
| `api_debug_logs` | 24h | Per-request: endpoint, IP, sig_valid, ip_valid, latency |
| `smtp_debug_logs` | 24h | Per-SMTP-attempt: relay used, DKIM signed, delivery time |
| `temp_storage` | 1h | Transient operation state (deleted immediately on completion) |

Query from Atlas UI or mongo shell:
```js
db.email_logs.find().sort({created_at:-1}).limit(50)
db.api_debug_logs.find({status_code:{$gte:400}}).sort({created_at:-1})
db.permanent_events.find({event_type:"allowed_app_created"}).sort({ts:-1})
```

---

## Security Notes

1. **The `.env` file contains the master key.** Anyone with `ADMIN_CURVE_KEY` can decrypt any request and impersonate the admin. Restrict file permissions (`chmod 600 .env`) and never commit to git.

2. **`allowed_ip` must equal the client's real IP.** The server checks both:
   - The `allowed_ip` field in the decrypted message
   - The actual client IP (`Cf-Connecting-IP` → `X-Forwarded-For` → `request.client.host`)
   - For `/api/send`: also checks the IP stored in `allowed_apps.allowed_ips`
   - For `/admin/*`: also checks `admin_settings.admin_allowed_ips`

3. **Bitcoin-style ECDSA:** `z = SHA-256(canonical_json(message))`, then `(r,s) = ECDSA-sign(z, private_key)`. The server verifies `_z` matches its own re-computation before verifying the signature — this prevents z-forgery attacks.

4. **DKIM private key lives in MongoDB.** Necessary so the running container can sign mail. Restrict Atlas Network Access to your VPS IP only.

5. **Port 465 is outbound-only.** The service connects to your SMTP relay (e.g. `mail.api-solv-rix-ai.top:465`) with TLS + AUTH. No inbound SMTP port is opened.

6. **App listens on `0.0.0.0:15484`.** You are responsible for firewalling it. Recommended: only allow your app server IPs.

7. **`permanent_events` is not auto-deleted.** This is intentional — you want a permanent audit trail of admin actions.

8. **Redis has no persistence.** If Redis restarts, queued-but-unsent emails are lost. Their `email_logs` entries will remain in `queued` status.

---

## Troubleshooting

### Terminal shows output
Bug. Expected output is **nothing** under normal operation. Run `docker compose logs smtp-app` to see what uvicorn emitted, fix, redeploy.

### 401 on every request
Most likely causes:
1. **`allowed_ip` doesn't match real IP** — check what your client sends vs. what the server sees (`db.api_debug_logs.find({status_code:401}).sort({created_at:-1})`).
2. **Signature z mismatch** — your client's canonical JSON must match the server's. Use `sort_keys=True, separators=(",", ":")`.
3. **Wrong AES key** — for `/admin/*`, AES key = `bytes.fromhex(ADMIN_CURVE_KEY)`. For `/api/send`, also `ADMIN_CURVE_KEY` (server uses the same key for all envelopes).
4. **api_pub_key not registered** — for `/api/send`, the `api_pub_key` must exist in `allowed_apps` collection.

### Emails not arriving
1. Check DKIM: `dig TXT smtp1._domainkey.api-solv-rix-ai.top`
2. Check SPF: `dig TXT api-solv-rix-ai.top`
3. Check `/admin/logs?type=smtp&hours=1` → `error_details`
4. Verify SMTP relay credentials: try connecting manually with `openssl s_client -connect mail.api-solv-rix-ai.top:465`

### MongoDB connection failures
- Verify `MONGO_URI` in `.env`
- In Atlas Network Access, add your VPS IP (do NOT use `0.0.0.0/0` in production)
- DB user needs `readWrite` on the database named in the URI

---

## What This Is Not

- ❌ Not a bulk mailer (one recipient per request, no batching)
- ❌ Not a spam relay (admin-controlled allowlist of apps)
- ❌ Not an inbox / IMAP server (send-only, no inbound SMTP)
- ❌ Not anonymous (admin actions are permanently audited)

---

## License

Private / internal use. No warranty.
