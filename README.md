```
febfrmn
****   
    ***
       
       
  *    
       
     * 
 *    *
*  *   
       
       
    *  
          xAI / Grok Mass Regist · full-HTTP farm + 9router inject
          https://saweria.co/febfrmn
```

# x-farm — xAI / Grok Mass Registration

Full-HTTP mass signup for xAI / Grok accounts, device-code OAuth, and optional
auto-inject into **9router** / **grok-cli**.

> Research / personal automation. Use at your own risk. Respect xAI ToS.
> Support: [https://saweria.co/febfrmn](https://saweria.co/febfrmn)

---

## Pipeline (per account)

```
email (pure-HTTP, local free Turnstile)
  → temp-mail OTP
  → createUser + SSO cookies
  → device-code OAuth approve
  → poll token → inject 9router (optional)

google (browser SSO — Playwright/Camoufox)
  → getAuthUrl → Google login → SSO cookies
  → device-code OAuth approve
  → poll token → inject 9router (optional)
```

Default solver path is **local free Turnstile** on `:8877` (no Capsolver required).
Paid Capsolver remains optional via env / solver service.

## Auto-install

`mass_regist.py` auto-installs missing Python deps (`curl_cffi`, `requests`) on
first run — no manual pip needed. `--auth-mode google` additionally installs
**Playwright + Chromium** automatically. For extra stealth, set
`GOOGLE_ENGINE=camoufox` (needs `pip install camoufox`, optional).

Quick setup (recommended):

```bash
./setup.sh          # venv + all deps + playwright chromium + solver venv
```

---

## Requirements

| Component | Notes |
|-----------|--------|
| Python 3.10+ | `pip install -r requirements.txt` |
| Local captcha solver | `http://127.0.0.1:8877` (Turnstile free pool) |
| 9router DB | Optional inject target |

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
cp proxies.txt.example proxies.txt   # optional
```

---

## Quick start

```bash
# interactive (speed + accounts + proxy)
python3 mass_regist.py

# CLI
python3 mass_regist.py --speed normal -n 50
python3 mass_regist.py --speed maximum -n 100 --proxy-file proxies.txt
python3 mass_regist.py --speed fast -n 20 --proxy 'http://user:pass@host:port'

# register only (skip 9router inject)
python3 mass_regist.py --speed normal -n 10 --skip-inject
```

### Google SSO mode (accounts)

Interactive wizard will ask **Auth mode → [2] google**, then you can either
point to an account file or **type accounts directly** (`email|password`,
empty line = done). The typed accounts are saved to `run/accounts.interactive.txt`.

CLI equivalents:

```bash
# account file
python3 mass_regist.py -n 10 --auth-mode google --account-file gsuite_accounts.txt

# no file → interactive prompt asks you to type accounts
python3 mass_regist.py -n 10 --auth-mode google
```

Account file format (one per line, `|` or `:`):

```
user1@example.com|secret1
user2@example.com:secret2
```

### Speed profiles

| Speed | workers | live est (local free TS) |
|-------|--------:|--------------------------|
| Slow | 1 | ~3–5/min |
| Normal | 3 | ~9–12/min (default) |
| Fast | 5 | ~16–20/min |
| Maximum | 7 | ~18–24/min |

Wall rate depends on OTP latency, turnstile, and IP heat. One VPS IP without
proxies can soft-block after ~100–130 accounts in a burst.

---

## Interactive UX

Three prompts only:

1. **Speed** `[1–4]` (default Normal)
2. **Accounts** — type a number (no default 20)
3. **Proxy** — file path **or** paste 1+ proxy lines (HTTP / SOCKS5)

### Proxy paste examples

**A) File path**
```
Proxy line 1 / file path (empty=none): ./proxies.txt
```

**B) Single string**
```
Proxy line 1 / file path (empty=none): user:pass@proxy.example.com:50100
Proxy line 2 (empty=done): <Enter>
```

**C) Multi-line (HTTP + SOCKS5)**
```
Proxy line 1 / file path (empty=none): http://user:pass@proxy.example.com:50100
Proxy line 2 (empty=done): socks5://user:pass@proxy.example.com:50101
Proxy line 3 (empty=done): <Enter>
```

Password is never printed (masked as `auth@host:port`).

---

## Proxy formats

One per line in `proxies.txt` (or interactive multi-line paste):

```
host:port
user:pass@host:port
host:port:user:pass
http://user:pass@host:port
socks5://user:pass@host:port
socks5h://user:pass@host:port
```

```bash
# pool sticky until 429/block (default)
python3 mass_regist.py -n 200 --speed maximum --proxy-file proxies.txt

# single proxy for all
python3 mass_regist.py -n 20 --proxy http://user:pass@host:port
python3 mass_regist.py -n 20 --proxy socks5://user:pass@host:port
```

Default `--proxy-mode limit` = sticky IP until limit/block. Optional
`--proxy-mode every --proxy-every 50` rotates every N accounts.

---

## Demo / self-test

```bash
python3 mass_regist.py demo
# or
python3 demo_test.py
```

Offline checks: banner + Saweria, proxy parse/rotate, stop/cancel/resume state,
worker queue, OTP extract, password generator, optional solver health.

---

## Run control

```bash
python3 mass_regist.py status
python3 mass_regist.py stop
python3 mass_regist.py cancel
python3 mass_regist.py resume
python3 mass_regist.py restart
python3 mass_regist.py log
```

State lives under `./run/` (`state.json`, `control.json`, `mass.pid`, `mass.log`).

After each run the summary prints wall time + **accounts/min**, then:

```
[1] Start again  [2] Exit
```

---

## Outputs

| Path | Content |
|------|---------|
| `accounts.jsonl` | one JSON line per attempt |
| `run/state.json` | job progress |
| 9router DB | OAuth rows when inject is on |

**Never commit** `accounts.jsonl`, `.env`, `proxies.txt`, or `run/`.

---

## createUser 404 (Server action not found)

xAI signup uses a Next.js **Server Action** hash in header `next-action`.
That hash is **not permanent** — it rotates on every frontend deploy.

| Symptom | Meaning |
|---------|---------|
| OTP + Turnstile OK, then `createUser HTTP 404: Server action not found` | stale `next-action` hash |
| Mass `ok=0 fail=N` same error | whole batch on dead seed |

**This build auto-handles this:**

- seed hash refreshed to live id
- on 404 → scrape signup JS (`createServerReference`) → update hash → **1 retry**
- outer create-loop also force-refreshes on 404

Manual check:

```bash
python3 - <<'PY'
from mass_regist import refresh_create_user_action, current_create_user_action
print(refresh_create_user_action(force=True))
print(current_create_user_action())
PY
```

---

## Honest limits

- One VPS IP without proxies can soft-block under aggressive mass runs
  (turnstile verify fails after a clean burst).
- Batch ~80–100 per IP, or use a proxy pool, for sustained farming.
- Local free Turnstile tokens can still be rejected by xAI under IP heat.
- Success is not guaranteed if xAI changes Turnstile / device consent / gRPC.

---

## License

**FEB-FRMN Source-Available (Non-Commercial / No Resale)** — free personal /
edu / research use with attribution. No sell, rent, paid redistrib, or
repack-for-sale. See [LICENSE](./LICENSE).

Support: **https://saweria.co/febfrmn**
