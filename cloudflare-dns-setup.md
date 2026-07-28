# Cloudflare DNS Setup — `api-solv-rix-ai.top` on VPS `51.38.40.174`

This guide sets up all DNS records for your send-only SMTP server running on the OVH VPS at `51.38.40.174` (SSH: `ssh -p 20051 root@51.38.40.174`).

> **Total time:** ~30 min (most of it is DNS propagation)
> **Result:** Email sent from your VPS will pass SPF, DKIM, and DMARC checks at Gmail/Outlook/Yahoo/etc.

---

## TL;DR — the 6 records to add

| # | Type | Name | Value | Proxy |
|---|------|------|-------|-------|
| 1 | `A` | `mail` | `51.38.40.174` | **DNS only** (grey cloud) |
| 2 | `A` | `@` (root) | `51.38.40.174` | Proxied (orange) or DNS only |
| 3 | `A` | `admin` | `51.38.40.174` | Proxied (orange) |
| 4 | `TXT` | `@` | `v=spf1 a:mail.api-solv-rix-ai.top -all` | — |
| 5 | `TXT` | `default._domainkey` | `v=DKIM1; k=rsa; p=MIIBIjANBgkq...QIDAQAB` (full value below) | — |
| 6 | `TXT` | `_dmarc` | `v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:admin@api-solv-rix-ai.top` | — |

**Do NOT add an `MX` record.** This is a send-only mail system — adding MX would invite inbound spam.

---

## STEP 1 — Open Cloudflare DNS panel

1. Go to **https://dash.cloudflare.com/login**
2. Click on **`api-solv-rix-ai.top`** in your site list.
   - If it isn't added yet: click **"Add a Site"** → enter `api-solv-rix-ai.top` → select the **Free** plan → follow the wizard to change your registrar's nameservers to Cloudflare's. Wait for NS propagation (5–30 min) before continuing.
3. In the left sidebar click **DNS → Records**.
4. Click **"Add record"**.

---

## STEP 2 — Add Record 1: `mail` subdomain (A record, DNS only)

This is the **most important record** — it's what SPF uses and what your mail server announces in EHLO.

| Field | Value |
|-------|-------|
| **Type** | `A` |
| **Name** | `mail` |
| **IPv4 address** | `51.38.40.174` |
| **Proxy status** | **DNS only** (grey cloud) ← CRITICAL — orange cloud will break SMTP |
| **TTL** | Auto |

Click **Save**.

> Why grey cloud? Cloudflare's proxy only handles HTTP/HTTPS. If you proxy `mail`, outbound SMTP from `51.38.40.174` will fail reverse-DNS checks and receivers will reject your mail.

---

## STEP 3 — Add Record 2: root domain `@` (A record)

So `api-solv-rix-ai.top` itself resolves (used by SPF `a:` mechanism and the admin panel root).

| Field | Value |
|-------|-------|
| **Type** | `A` |
| **Name** | `@` |
| **IPv4 address** | `51.38.40.174` |
| **Proxy status** | Proxied (orange cloud) **or** DNS only — either works |
| **TTL** | Auto |

Click **Save**.

---

## STEP 4 — Add Record 3: `admin` subdomain (A record, Proxied)

Optional but recommended — gives you a clean URL like `https://admin.api-solv-rix-ai.top` for the admin panel.

| Field | Value |
|-------|-------|
| **Type** | `A` |
| **Name** | `admin` |
| **IPv4 address** | `51.38.40.174` |
| **Proxy status** | **Proxied** (orange cloud) — benefits from Cloudflare's SSL + DDoS protection |
| **TTL** | Auto |

Click **Save**.

---

## STEP 5 — Add Record 4: SPF (TXT on root domain)

Tells receivers which IP is authorized to send mail from `api-solv-rix-ai.top`.

| Field | Value |
|-------|-------|
| **Type** | `TXT` |
| **Name** | `@` |
| **Content** | `v=spf1 a:mail.api-solv-rix-ai.top -all` |
| **TTL** | Auto |

Click **Save**.

> The `-all` means "reject anything else". The `a:mail.api-solv-rix-ai.top` means "allow the IP that `mail.api-solv-rix-ai.top` resolves to" (which is `51.38.40.174`).

---

## STEP 6 — Add Record 5: DKIM (TXT on `default._domainkey`)

Lets receivers verify your mail wasn't tampered with. The value below was extracted directly from the DKIM private key in your project (`.env` `DKIM_PRIVATE_KEY_PEM`), so it already matches — no need to fetch from `/api/health`.

| Field | Value |
|-------|-------|
| **Type** | `TXT` |
| **Name** | `default._domainkey` |
| **Content** | (see the long value just below — copy ALL of it, one line) |
| **TTL** | Auto |

**DKIM value to paste (one single line, 410 chars):**

```
v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6ZMtldWn/Wk0rEdR2pM0X5qeNj7tAIfi77+ZFyuk+rAfqmt7fsb/brVcJD4vzJ+pVfh0NvY/NqEqg6CEYH/mkQJrMYRhYohbMRZ0v4HPWpQoR4l8zFTqywY9KoWYWcJWpsZmzclkFPS2wGWTan63czhyNpaqCT8bFCZPWZ6ArghRqLMRecbMlRdxuHqezzRv3/CFunsJPLC4PEIMwy1cx3TisxdY7Lbhfi8czhwsXkq+YpvnTfISSZzeJDtoKy2Y/EZNMu8MqlQzhYC2+RhMLCpMIA7mtwKwej4/4p/TU2ApmgiRls3CN9TmX6+1gb7q8grfwV+0208FBe1veX9NEQIDAQAB
```

Click **Save**.

> If Cloudflare shows a "Wildcard Domain Override" warning, click **Confirm** — that's normal and expected.

---

## STEP 7 — Add Record 6: DMARC (TXT on `_dmarc`)

Tells receivers what to do if SPF or DKIM fails. `p=reject` is the strictest policy.

| Field | Value |
|-------|-------|
| **Type** | `TXT` |
| **Name** | `_dmarc` |
| **Content** | `v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:admin@api-solv-rix-ai.top` |
| **TTL** | Auto |

Click **Save**.

> The `rua=mailto:...` is where receivers send daily DMARC reports. You can change it to any address you control.

---

## STEP 8 — Set PTR / rDNS on OVH (CRITICAL — not in Cloudflare)

This is the #1 reason mail goes to spam. **A PTR record maps your IP back to a hostname.** It must be set on the **VPS provider side (OVH)**, not Cloudflare.

The PTR value must **exactly match** your mail server's EHLO hostname = `mail.api-solv-rix-ai.top`.

### How to set PTR on OVH:

1. Log in to **https://www.ovh.com/manager/dedicated/**
2. Go to **Bare Metal Cloud** → **Server** → select your VPS (`vps-xxxxx.ovh.net`)
3. Click the **IP** tab (or "IPv4" section)
4. Find your IP `51.38.40.174` → click the **⋯** menu → **Add a reverse DNS** (or "Modify reverse")
5. Enter: `mail.api-solv-rix-ai.top`
6. Save. OVH verifies the forward A record matches before accepting.

### Verify PTR is set (after ~5 min):

```bash
dig -x 51.38.40.174 +short
# Expected: mail.api-solv-rix-ai.top.
```

If you don't see `mail.api-solv-rix-ai.top.` come back, wait 10 min and try again. OVH propagation can take up to 30 min.

---

## STEP 9 — Open firewall ports on the VPS

SSH in: `ssh -p 20051 root@51.38.40.174`

Then run **ONE** of these depending on your firewall:

### If using `ufw`:

```bash
ufw allow 22/tcp           # SSH (you're using port 20051 — adjust if needed)
ufw allow 20051/tcp        # SSH custom port (as in your command)
ufw allow 80/tcp           # HTTP (Caddy redirect + ACME)
ufw allow 443/tcp          # HTTPS (admin panel + API)
ufw allow 25/tcp           # SMTP (outbound + some inbound bounces)
ufw allow 587/tcp          # SMTP submission (STARTTLS)
ufw allow 465/tcp          # SMTP SSL (implicit TLS)
ufw reload
ufw status verbose
```

### If using `iptables` directly (no ufw):

```bash
iptables -A INPUT -p tcp --dport 20051 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 25 -j ACCEPT
iptables -A INPUT -p tcp --dport 587 -j ACCEPT
iptables -A INPUT -p tcp --dport 465 -j ACCEPT
# Save rules (Debian/Ubuntu):
netfilter-persistent save
```

### Verify ports are listening:

```bash
ss -tlnp | grep -E ':(25|587|465|80|443|10000)\s'
```

You should see `uvicorn` on 10000 (or 80/443 if Caddy is in front) and `aiosmtpd` on 25/587/465.

---

## STEP 10 — Verify everything (after DNS propagates, ~10–30 min)

Run these from any terminal:

```bash
# A records
dig +short mail.api-solv-rix-ai.top           # → 51.38.40.174
dig +short api-solv-rix-ai.top                # → 51.38.40.174 (or Cloudflare IP if proxied)
dig +short admin.api-solv-rix-ai.top          # → 51.38.40.174 (or Cloudflare IP)

# SPF
dig +short TXT api-solv-rix-ai.top            # → "v=spf1 a:mail.api-solv-rix-ai.top -all"

# DKIM
dig +short TXT default._domainkey.api-solv-rix-ai.top
# → "v=DKIM1; k=rsa; p=MIIBIjANBgkq...QIDAQAB"

# DMARC
dig +short TXT _dmarc.api-solv-rix-ai.top
# → "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:admin@api-solv-rix-ai.top"

# PTR / reverse DNS
dig -x 51.38.40.174 +short                    # → mail.api-solv-rix-ai.top.

# MX (should be empty — send-only)
dig +short MX api-solv-rix-ai.top             # → (no output)
```

### Check the live service can see the new DNS:

```bash
# After DNS propagates, the /api/health endpoint should report all green:
curl -sk https://api-solv-rix-ai.top/api/health | python3 -m json.tool
```

Look for `"dkim": {...}` and `"current_ip": "51.38.40.174"` in the output.

---

## STEP 11 — Deliverability test

1. Go to **https://www.mail-tester.com/**
2. Copy the unique test email address they show (e.g. `abc-123-xyz@mail-tester.com`).
3. Send a test email from your admin panel:
   - Open `https://api-solv-rix-ai.top/admin/send-test-page` (or whatever your test-page route is)
   - Send to the mail-tester address
4. Click "Then check your score" on mail-tester.
5. **Target: 10/10.** If you get less, mail-tester tells you exactly what's missing.

### Common deductions and fixes:

| Deduction | Fix |
|-----------|-----|
| -1 for "Missing PTR" | OVH reverse DNS not set yet (Step 8) — wait 30 min |
| -1 for "SPF not aligned" | Check the `From:` header uses `@api-solv-rix-ai.top` (not `@gmail.com` etc.) |
| -1 for "DKIM not signed" | Restart the SMTP service so it picks up the new `MAIL_HOSTNAME` env |
| -2 for "Listed on Spamhaus" | Your VPS IP may be on a blacklist from a previous owner — request delisting at https://check.spamhaus.org/ |

---

## Quick checklist

- [ ] Cloudflare nameservers set at your registrar (if not already)
- [ ] `mail` A record → `51.38.40.174` (DNS only / grey cloud)
- [ ] `@` A record → `51.38.40.174`
- [ ] `admin` A record → `51.38.40.174` (Proxied / orange)
- [ ] `@` TXT record → SPF
- [ ] `default._domainkey` TXT record → DKIM public key
- [ ] `_dmarc` TXT record → DMARC policy
- [ ] **No MX record added** (intentional)
- [ ] OVH reverse DNS (PTR) → `mail.api-solv-rix-ai.top`
- [ ] VPS firewall open: 22, 20051, 25, 80, 443, 465, 587
- [ ] `dig -x 51.38.40.174` returns `mail.api-solv-rix-ai.top.`
- [ ] Mail-tester score ≥ 9/10

---

## Post-setup — keeping the system healthy

### Daily checks (automated by your project):

The project already has built-in monitors:
- **Self-ping every 5 min** (`SELF_PING_ENABLED=true`) — keeps the service alive
- **Auto IP detection every 5 min** (`AUTO_IP_DETECTION_ENABLED=true`) — fires the system-alert webhook if `51.38.40.174` changes (it shouldn't on a VPS, but the safety net is there)
- **Daily summary email** — set `DAILY_SUMMARY_TO=admin@api-solv-rix-ai.top` in `.env` to receive

### DKIM rotation:

Your project auto-rotates the DKIM key every 7 days (`DKIM_ROTATION_DAYS=7`). When this happens:
1. The new public key appears at `/api/health`
2. You must update the `default._domainkey` TXT record in Cloudflare with the new value
3. Until you do, mail will fail DKIM checks

> **Recommendation:** For a VPS with stable IP, set `DKIM_ROTATION_DAYS=365` in `.env` (rotate yearly) so you don't have to update DNS weekly. The security trade-off is minimal for a send-only system.

### Blacklist monitoring:

`AUTO_PAUSE_ON_BLACKLIST=true` — if your IP gets listed on Spamhaus/SORBS/SpamCop, the project auto-pauses sending and fires the system-alert webhook (set `SYSTEM_ALERT_WEBHOOK_URL` to a Slack/Discord webhook to get notified).
