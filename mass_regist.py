#!/usr/bin/env python3
"""
xAI / Grok mass registration + 9router / grok-cli inject.

Private full-HTTP pipeline (default, ALL LOCAL free turnstile):
  email  : pure GET → empty Castle → temp-mail OTP → Turnstile(:8877 free)
           → createUser → SSO → device OAuth → inject
  google : CF/Castle optional → getAuthUrl → Google SSO → device OAuth → inject

Speed modes (pick each run — English labels):
  Slow | Normal | Fast | Maximum
  --speed slow|normal|fast|maximum
  -i / bare CLI → interactive menu

Control: status | stop | cancel | resume | restart
Support: https://saweria.co/febfrmn
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import random
import re
import string
import sys
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import quote

# Control commands must work on bare system python (no curl_cffi).
# Dispatch BEFORE heavy deps so `status|stop|cancel|...` never import them.
if __name__ == "__main__" and len(sys.argv) > 1:
    _cmd = sys.argv[1].lower()
    if _cmd in {"status", "stop", "cancel", "kill", "resume", "restart", "log", "help"}:
        from run_ctl import main as _ctl_main

        raise SystemExit(_ctl_main(sys.argv[1:]))
    if _cmd in {"demo", "selftest", "self-test"}:
        # demo still needs project modules; try/import later after deps
        pass


def _auto_install() -> None:
    """Check & install missing Python deps (curl_cffi, requests, playwright).

    Runs before heavy imports so a fresh machine just works. Playwright is
    only required for --auth-mode google (browser SSO); email mode is pure
    HTTP and skips the browser install.
    """
    import importlib.util
    import subprocess

    required = ["curl_cffi", "requests"]
    # playwright: only needed for google SSO mode; install lazily on demand
    missing = [p for p in required if importlib.util.find_spec(p) is None]
    if missing:
        print(f"⚙️  Installing missing deps: {', '.join(missing)} ...")
        for pkg in missing:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", pkg, "-q"],
                capture_output=True, timeout=120,
            )
            if r.returncode != 0:
                r = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg, "-q", "--break-system-packages"],
                    capture_output=True, timeout=120,
                )
            if r.returncode != 0:
                print(f"  ⚠️  pip install {pkg} failed: {r.stderr.decode()[-200:]}")
            else:
                print(f"  ✅ {pkg} installed")


if __name__ == "__main__":
    _auto_install()

from curl_cffi import requests as creq

from castle_token import castle_max_concurrent, get_castle_token, pool_status
from google_login import apply_cookies_to_session, load_account_file, login_google_sso
from inject_9router import count_provider, inject_connection, test_chat_token
from mail_tm import EmailBox
from proto_util import (
    build_create_email_validation_code,
    build_validate_password,
    build_verify_email_validation_code,
    parse_fields,
    unwrap_grpc_web,
)

# GSuite / pre-provisioned accounts for --auth-mode google (email, password)
_ACCOUNT_QUEUE: list[tuple[str, str]] = []
_ACCOUNT_LOCK = threading.Lock()
from proxy_pool import (
    ProxyPool,
    acquire_proxy,
    is_limit_error,
    rotate_proxy_on_limit,
    set_global_pool,
)
from run_ctl import (
    Cancelled,
    bump,
    check_cancel,
    finish,
    init_run,
    load_state,
    resume_state,
    should_cancel,
    should_stop,
    status_text,
)
import run_ctl
from solver_client import solve_cloudflare
from turnstile_token import get_turnstile_token

_print_lock = threading.Lock()
_file_lock = threading.Lock()
_inject_lock = threading.Lock()
# serialize device_code requests — concurrent workers hit 429/slow_down hard
_device_code_lock = threading.Lock()
_device_code_last = 0.0
_DEVICE_CODE_MIN_GAP = float(os.getenv("DEVICE_CODE_MIN_GAP", "1.0"))
_DEVICE_CODE_GAP_MAX = float(os.getenv("DEVICE_CODE_GAP_MAX", "5.0"))
_device_code_gap = _DEVICE_CODE_MIN_GAP  # adaptive, raised on 429

# shared CF clearance: 1 solve → many workers (keyed by proxy host or "direct")
_CF_SHARE_TTL = float(os.getenv("CF_SHARE_TTL", "600"))  # seconds
_CF_SHARE_MAX_USES = int(os.getenv("CF_SHARE_MAX_USES", "20"))
_cf_share_lock = threading.Lock()
_cf_share_cond = threading.Condition(_cf_share_lock)
# key -> {ua, cookies, ts, uses, solving:bool, err:str|None}
_cf_share: dict[str, dict] = {}

SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com&return_to=%2F"
TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
CASTLE_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
# Next.js server-action id for createUser (rotates on every xAI frontend deploy).
# NOT a permanent API key — scraped live from signup JS createServerReference.
# old 2026-07-22a: 7f7f6cee188bd9cc17a3fb9dbde4abe224f21af0e3 → 404 Server action not found
# seed 2026-07-23: 7fed37ced5aa8209c16a0b5c7ee4f9913d80883a14
NEXT_ACTION_CREATE_USER = "7f6a7be18e5b7fb17cddbead4a2c3a895a6cfc3ae7"
_NEXT_ACTION_LOCK = threading.Lock()
_NEXT_ACTION_LAST_REFRESH = 0.0
_NEXT_ACTION_MIN_REFRESH_GAP = 30.0  # seconds — avoid stampede on mass 404

GRPC_BASE = "https://accounts.x.ai/auth_mgmt.AuthManagement"
CREATE_EMAIL = f"{GRPC_BASE}/CreateEmailValidationCode"
VERIFY_EMAIL = f"{GRPC_BASE}/VerifyEmailValidationCode"
VALIDATE_PW = f"{GRPC_BASE}/ValidatePassword"

GROK_CLI_CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828"
GROK_CLI_SCOPE = (
    "openid profile email offline_access grok-cli:access "
    "api:access conversations:read conversations:write"
)
DEVICE_CODE_URL = "https://auth.x.ai/oauth2/device/code"
TOKEN_URL = "https://auth.x.ai/oauth2/token"
DEVICE_CONSENT_URL = "https://accounts.x.ai/oauth2/device/consent"
DEVICE_DONE_URL = "https://accounts.x.ai/oauth2/device/done"
DEVICE_PAGE = "https://accounts.x.ai/oauth2/device"

DEFAULT_DB = os.path.expanduser("~/.9router/db/data.sqlite") if os.path.exists(os.path.expanduser("~/.9router/db/data.sqlite")) else "/var/lib/9router/db/data.sqlite"
ACCOUNTS_FILE = Path(__file__).resolve().parent / "accounts.jsonl"

UA_FALLBACK = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

# ─── Banner (static icl-1900; no pyfiglet required) ─────────────────────────
BANNER = r"""
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
"""

VERSION = "1.2.0"


def print_banner() -> None:
    print(BANNER, flush=True)
    print("  Speed   : Slow | Normal | Fast | Maximum  (--speed / interactive)", flush=True)
    print("  Control : python3 mass_regist.py status|stop|cancel|resume|restart", flush=True)
    print("  Support : https://saweria.co/febfrmn", flush=True)


def _castle_banner_status() -> str:
    """Quick pool readiness for run banner (never blocks long)."""
    try:
        st = pool_status(timeout_s=1.5)
        if st.get("ok") and int(st.get("ready") or 0) > 0:
            return f"pool ready {st.get('ready')}/{st.get('workers')} tok={st.get('tokens')} ~{st.get('last_ms')}ms"
        if st.get("ok"):
            return f"pool booting 0/{st.get('workers')}"
        return f"pool down → harvest ({st.get('error', '?')[:40]})"
    except Exception as e:
        return f"pool down → harvest ({e})"


# Speed profiles — ALL LOCAL free turnstile (:8877). No Capsolver picker.
# Labels are English. Values tuned for pure-HTTP + single local TS engine.
SPEED_PROFILES: dict[str, dict[str, Any]] = {
    "slow": {
        "label": "Slow",
        "workers": 1,
        "pool": 1,
        "concurrent": 1,
        "stagger": 1.0,
        "delay": 1.5,
        "device_gap": "1.5",
        "otp_poll": "1.2",
        "est": "~3–5/min",
        "blurb": "gentle · debug · lowest load",
    },
    "normal": {
        "label": "Normal",
        "workers": 3,
        "pool": 3,
        "concurrent": 3,
        "stagger": 0.3,
        "delay": 0.3,
        "device_gap": "1.2",
        "otp_poll": "1.0",
        "est": "~9–12/min",
        "blurb": "daily free · stable default",
    },
    "fast": {
        "label": "Fast",
        "workers": 5,
        "pool": 5,
        "concurrent": 5,
        "stagger": 0.15,
        "delay": 0.1,
        "device_gap": "1.0",
        "otp_poll": "0.8",
        "est": "~16–20/min",
        "blurb": "snappy · local TS queue ok",
    },
    "maximum": {
        "label": "Maximum",
        "workers": 7,
        # local solver health reports pool=6 pages — keep TS at 6, workers can be higher
        "pool": 6,
        "concurrent": 6,
        "stagger": 0.05,  # faster start wave than Fast (0.15); single-place only
        "delay": 0.05,
        # bottleneck is serialized device_code — must be tighter than Fast (1.0)
        "device_gap": "0.75",
        "otp_poll": "0.7",
        "est": "~18–24/min",
        "blurb": "max local · w=7 · ts=6 · gap=0.75 · stagger=0.05",
    },
}


def normalize_speed(raw: str | None) -> str:
    s = (raw or "normal").strip().lower()
    aliases = {
        "1": "slow",
        "s": "slow",
        "lambat": "slow",
        "2": "normal",
        "n": "normal",
        "3": "fast",
        "f": "fast",
        "cepat": "fast",
        "4": "maximum",
        "m": "maximum",
        "max": "maximum",
        "maksimal": "maximum",
        "maks": "maximum",
    }
    s = aliases.get(s, s)
    if s not in SPEED_PROFILES:
        return "normal"
    return s


def apply_local_mode(*, speed: str = "normal", force_timing: bool = True) -> dict:
    """Force full-HTTP + LOCAL free turnstile only. Apply speed profile env.

    No Capsolver path. PURE_HTTP always on (CF/Castle skip).
    """
    sp = normalize_speed(speed)
    prof = SPEED_PROFILES[sp]

    os.environ["PURE_HTTP"] = "1"
    os.environ["NO_BROWSER"] = "1"
    os.environ["SKIP_CF"] = "1"
    os.environ["SKIP_CASTLE"] = "1"
    os.environ["SKIP_VALIDATE_PASSWORD"] = "1"
    os.environ["XAI_SOLVER"] = "local"
    os.environ["TURNSTILE_FREE_ONLY"] = "1"
    # hard-disable paid path
    os.environ.pop("TURNSTILE_FORCE_CAPSOLVER", None)
    os.environ.pop("TURNSTILE_CAPSOLVER_DIRECT", None)

    if force_timing:
        os.environ["DEVICE_CODE_MIN_GAP"] = str(prof["device_gap"])
        os.environ["OTP_POLL_S"] = str(prof["otp_poll"])
        os.environ["TURNSTILE_POOL_SIZE"] = str(prof["pool"])
        os.environ["TURNSTILE_MAX_CONCURRENT"] = str(prof["concurrent"])
    else:
        os.environ.setdefault("DEVICE_CODE_MIN_GAP", str(prof["device_gap"]))
        os.environ.setdefault("OTP_POLL_S", str(prof["otp_poll"]))
        os.environ.setdefault("TURNSTILE_POOL_SIZE", str(prof["pool"]))
        os.environ.setdefault("TURNSTILE_MAX_CONCURRENT", str(prof["concurrent"]))

    # CRITICAL: request_device_code() uses module globals, NOT env re-read.
    # Without this, Fast/Maximum both stuck at import default gap=1.0 and
    # Maximum (more workers) loses to Fast purely from contention.
    global _DEVICE_CODE_MIN_GAP, _device_code_gap
    _DEVICE_CODE_MIN_GAP = float(os.environ["DEVICE_CODE_MIN_GAP"])
    _device_code_gap = _DEVICE_CODE_MIN_GAP  # reset adaptive floor to profile

    # reconfigure warm pool AFTER env set (import-time constants are wrong)
    ts_cfg: dict = {}
    try:
        from turnstile_token import configure_from_env as _ts_cfg

        ts_cfg = _ts_cfg()
    except Exception as e:
        ts_cfg = {"error": str(e)[:80]}

    health = _solver_health_quick()
    return {
        "speed": sp,
        "label": prof["label"],
        "workers": int(prof["workers"]),
        "pool": int(prof["pool"]),
        "concurrent": int(prof["concurrent"]),
        "stagger": float(prof["stagger"]),
        "delay": float(prof["delay"]),
        "est": prof["est"],
        "solver": "local",
        "pure_http": True,
        "local_health": health,
        "ts_cfg": ts_cfg,
        "solver_pages": health.get("pool"),
    }


def apply_speed_to_args(args: argparse.Namespace, speed: str | None = None) -> dict:
    """Apply speed profile onto args + env. Returns snapshot."""
    sp = normalize_speed(speed or getattr(args, "speed", None) or "normal")
    snap = apply_local_mode(speed=sp, force_timing=True)
    # only override workers/stagger/delay if user didn't explicitly pass custom
    # interactive always applies; CLI --speed applies unless -w was non-default? always apply for clarity
    args.workers = int(snap["workers"])
    args.stagger = float(snap["stagger"])
    args.delay = float(snap["delay"])
    args.speed = sp
    args.solver = "local"
    return snap


def _solver_health_quick() -> dict:
    """Best-effort GET :8877/health (no throw)."""
    try:
        import urllib.request

        with urllib.request.urlopen(
            os.getenv("SOLVER_URL", "http://127.0.0.1:8877") + "/health", timeout=2
        ) as r:
            return json.loads(r.read())
    except Exception as e:
        return {"status": "down", "error": str(e)[:80]}


def _prompt(msg: str, default: str | None = None) -> str:
    """Interactive prompt with optional default."""
    suffix = f" [{default}]" if default is not None and default != "" else ""
    try:
        raw = input(f"{msg}{suffix}: ").strip()
    except EOFError:
        raw = ""
    if not raw and default is not None:
        return str(default)
    return raw


def prompt_accounts_interactive() -> list[tuple[str, str]]:
    """Collect Google SSO accounts line by line (email|password or email:password).
    Empty line = done. Returns list of (email, password)."""
    print("  Accounts (Google SSO) — one per line:  email|password", flush=True)
    print("  Empty line = done.  Example:  user1@gmail.com|secret123", flush=True)
    out: list[tuple[str, str]] = []
    i = 0
    while True:
        i += 1
        raw = _prompt(f"Account {i} (empty=done)", None)
        raw = (raw or "").strip()
        if not raw:
            break
        if raw.startswith("#"):
            continue
        if "|" in raw:
            email, pw = raw.split("|", 1)
        elif ":" in raw and "@" in raw.split(":", 1)[0]:
            email, pw = raw.split(":", 1)
        else:
            print("  ⚠ skip — use format email|password", flush=True)
            continue
        email, pw = email.strip(), pw.strip()
        if email and pw:
            out.append((email, pw))
        else:
            print("  ⚠ skip — empty email/password", flush=True)
    return out


def interactive_config(args: argparse.Namespace) -> argparse.Namespace:
    """Minimal interactive: speed + count + optional proxy. Default speed=Normal."""
    print()
    print("  [1] Slow     w=1  ~3–5/min")
    print("  [2] Normal   w=3  ~9–12/min  (default)")
    print("  [3] Fast     w=5  ~16–20/min")
    print("  [4] Maximum  w=7  ~18–24/min")
    choice = _prompt("Speed", "2")  # default Normal
    speed = normalize_speed(choice)
    snap = apply_speed_to_args(args, speed)

    # Accounts: no prefilled default number. On "start again", soft-default previous n.
    n_default = None
    if getattr(args, "interactive_done", False) and getattr(args, "count", None):
        try:
            n_default = str(int(args.count))
        except Exception:
            n_default = None
    while True:
        n_raw = _prompt("Accounts", n_default)
        try:
            n_val = int((n_raw or "").strip())
            if n_val < 1:
                raise ValueError("min 1")
            args.count = n_val
            break
        except Exception:
            print("  ⚠ enter a number > 0 (e.g. 10)", flush=True)
            n_default = None

    # Proxy: path OR paste 1+ lines (http + socks5)
    print("  Proxy (optional, Enter = no proxy)", flush=True)
    print("  Paste either:", flush=True)
    print("    A) path to .txt   e.g. ./proxies.txt", flush=True)
    print("    B) 1+ proxy lines (HTTP / SOCKS5). Empty line = done", flush=True)
    print("  Formats:", flush=True)
    print("    host:port", flush=True)
    print("    user:pass@host:port", flush=True)
    print("    host:port:user:pass", flush=True)
    print("    http://user:pass@host:port", flush=True)
    print("    socks5://user:pass@host:port", flush=True)
    print("  Multi example:", flush=True)
    print("    http://user:pass@1.2.3.4:50100", flush=True)
    print("    socks5://user:pass@1.2.3.4:50101", flush=True)
    print("    <Enter empty to finish>", flush=True)

    args.proxy_file = None
    args.proxy = None
    first = _prompt("Proxy line 1 / file path (empty=none)", None)
    first = (first or "").strip()
    if first:
        from proxy_pool import ProxyPool, normalize_proxy, mask_proxy

        p = Path(first).expanduser()
        if p.is_file():
            try:
                pool = ProxyPool.from_file(
                    p, mode=getattr(args, "proxy_mode", None) or "limit"
                )
                if not pool.proxies:
                    print(
                        f"  ⚠ proxy file empty/invalid: {p} — running without proxy",
                        flush=True,
                    )
                else:
                    args.proxy_file = str(p)
                    print(
                        f"  → proxy file: {len(pool)} line(s) first={pool.current_masked()}",
                        flush=True,
                    )
            except Exception as e:
                print(f"  ⚠ proxy load fail: {e} — running without proxy", flush=True)
        else:
            # Collect line 1 + extra lines until empty Enter
            raw_lines: list[str] = []
            # first line may also be comma/semicolon multi
            for part in re.split(r"[,;]+", first):
                part = part.strip()
                if part:
                    raw_lines.append(part)
            n_extra = 1
            while True:
                n_extra += 1
                more = _prompt(f"Proxy line {n_extra} (empty=done)", None)
                more = (more or "").strip()
                if not more:
                    break
                for part in re.split(r"[,;]+", more):
                    part = part.strip()
                    if part:
                        raw_lines.append(part)
                if n_extra >= 50:
                    print("  ⚠ max 50 proxy lines", flush=True)
                    break

            norms: list[str] = []
            seen: set[str] = set()
            for part in raw_lines:
                n = normalize_proxy(part)
                if n and n not in seen:
                    seen.add(n)
                    norms.append(n)
            if not norms:
                print("  ⚠ proxy string invalid — running without proxy", flush=True)
            elif len(norms) == 1:
                args.proxy = norms[0]
                print(f"  → proxy string: {mask_proxy(norms[0])}", flush=True)
            else:
                run_dir = Path("run")
                run_dir.mkdir(parents=True, exist_ok=True)
                tmp = run_dir / "proxies.interactive.txt"
                tmp.write_text("\n".join(norms) + "\n", encoding="utf-8")
                args.proxy_file = str(tmp)
                pool = ProxyPool(
                    norms, mode=getattr(args, "proxy_mode", None) or "limit"
                )
                schemes = sorted(
                    {
                        (x.split("://", 1)[0] if "://" in x else "http")
                        for x in norms
                    }
                )
                print(
                    f"  → proxy pool: {len(norms)} line(s) schemes={','.join(schemes)} "
                    f"first={pool.current_masked()}",
                    flush=True,
                )

    # Auth mode: email (temp-mail) or google (GSuite SSO)
    print()
    print("  Auth mode:")
    print("    [1] email  — temp-mail regist (default)")
    print("    [2] google — Google SSO (needs accounts)")
    m_choice = _prompt("Auth mode", "1")
    args.auth_mode = "google" if str(m_choice).strip().startswith("2") else "email"
    if args.auth_mode == "google":
        afile = _prompt("Account file path (empty = type accounts)", None)
        afile = (afile or "").strip()
        p = Path(afile).expanduser() if afile else None
        if p and p.is_file():
            args.account_file = str(p)
            n_acc = len(load_account_file(p))
            print(f"  → account file: {p} ({n_acc} accounts)", flush=True)
            if n_acc and args.count == 1:
                args.count = n_acc
        else:
            if p and not p.is_file():
                print(f"  ⚠ file not found: {afile} — entering accounts manually", flush=True)
            accounts = prompt_accounts_interactive()
            if accounts:
                run_dir = Path("run")
                run_dir.mkdir(parents=True, exist_ok=True)
                tmp = run_dir / "accounts.interactive.txt"
                tmp.write_text(
                    "\n".join(f"{e}|{pw}" for e, pw in accounts) + "\n",
                    encoding="utf-8",
                )
                args.account_file = str(tmp)
                args.count = len(accounts)
                print(f"  → {len(accounts)} account(s) saved to {tmp}", flush=True)
            else:
                print("  ⚠ no accounts entered — falling back to email mode", flush=True)
                args.auth_mode = "email"

    # fixed defaults — no prompts
    args.mail_provider = getattr(args, "mail_provider", None) or None
    args.inject_policy = getattr(args, "inject_policy", None) or "token"
    args.provider = getattr(args, "provider", None) or "grok-cli"
    args.auth_mode = getattr(args, "auth_mode", None) or "email"
    args.solver = "local"
    args.speed = speed
    args.interactive_done = True
    # fresh run each interactive cycle
    args.resume_run = False
    args.fresh_run = True

    line = (
        f"  → {snap['label']} · n={args.count} · w={args.workers} "
        f"· est={snap.get('est', '?')}"
    )
    if args.proxy_file:
        line += f" · proxy_file={args.proxy_file}"
    elif getattr(args, "proxy", None):
        from proxy_pool import mask_proxy as _mask_px

        line += f" · proxy={_mask_px(args.proxy)}"
    print(line)
    return args


def post_run_menu() -> str:
    """After a run finishes: start again or exit. Returns 'again' | 'exit'."""
    print(flush=True)
    print("─" * 40, flush=True)
    print("  RUN FINISHED", flush=True)
    print("  [1] Start again  [2] Exit", flush=True)
    print("─" * 40, flush=True)
    choice = _prompt("Next", "1").strip().lower()
    if choice in ("2", "e", "exit", "q", "quit", "n", "no"):
        return "exit"
    return "again"


def _run_rate_line(ok: int, fail: int, st: dict | None = None) -> str:
    """Compute wall time + accounts/min from run state."""
    st = st or load_state() or {}
    started = st.get("started_at") or st.get("resumed_at")
    finished = st.get("finished_at") or st.get("updated_at")
    wall_s = None
    if started and finished:
        try:
            from datetime import datetime

            def _parse(ts: str) -> datetime:
                ts = str(ts).replace("Z", "+00:00")
                return datetime.fromisoformat(ts)

            wall_s = max(0.001, (_parse(finished) - _parse(started)).total_seconds())
        except Exception:
            wall_s = None
    if wall_s is None:
        return f"rate=n/a  ok={ok} fail={fail}"
    rate = ok / (wall_s / 60.0)
    return (
        f"wall={wall_s:.0f}s ({wall_s/60:.1f}m)  "
        f"ok={ok} fail={fail}  "
        f"→ {rate:.1f} akun/menit"
    )



# ── quiet live progress box ──────────────────────────────────────────
# During a run: only the status box is shown (rewritten in-place on TTY).
# Per-account process logs are silenced. START plan + DONE box still print.
_quiet_run = False
_box_active = False
_box_lines = 0
_BOX_H = 6  # fixed rows: top + head + bar + OK/FAIL/RUN + rate + bottom


def set_quiet_run(on: bool) -> None:
    """Enable/disable quiet mode (box-only UI during farm run)."""
    global _quiet_run, _box_active, _box_lines
    with _print_lock:
        if not on and _box_active and _box_lines > 0:
            # leave the last box on screen, then a blank line
            print(flush=True)
        _quiet_run = bool(on)
        if not on:
            _box_active = False
            _box_lines = 0


atexit.register(lambda: set_quiet_run(False))

def _bar(done: int, total: int, width: int = 28) -> str:
    """ASCII progress bar."""
    total = max(1, int(total or 1))
    done = max(0, min(int(done or 0), total))
    filled = int(round(width * done / total))
    return "█" * filled + "░" * (width - filled)


def _live_rate_per_min(ok: int, started_ts: float | None = None) -> float | None:
    """Accounts/min from wall clock since run start (ok only)."""
    if not started_ts:
        st = load_state() or {}
        started = st.get("started_at") or st.get("resumed_at")
        if not started:
            return None
        try:
            from datetime import datetime, timezone

            ts = str(started).replace("Z", "+00:00")
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            started_ts = dt.timestamp()
        except Exception:
            return None
    wall = max(0.001, time.time() - float(started_ts))
    return float(ok) / (wall / 60.0)


def _build_status_lines(
    ok: int,
    fail: int,
    total: int,
    *,
    in_flight: int = 0,
    title: str = "x-farm",
    final: bool = False,
    rate_override: float | None = None,
) -> list[str]:
    done = int(ok) + int(fail)
    total = max(1, int(total or 1))
    pct = min(100, int(done * 100 / total))
    bar = _bar(done, total, width=28)
    rate = rate_override
    if rate is None:
        rate = _live_rate_per_min(ok)
    if rate is None:
        rate_s = "—.— /min"
    else:
        rate_s = f"{rate:.1f} /min"
    head = "DONE" if final else title
    W = 40

    def row(s: str) -> str:
        # strip ANSI for width calc; keep plain for box
        s = s[:W]
        return "│ " + s + " " * (W - len(s)) + " │"

    return [
        "┌" + "─" * (W + 2) + "┐",
        row(f"{head}  {done}/{total}  {pct}%"),
        row(f"{bar}"),
        row(f"OK {ok:<6} FAIL {fail:<5} RUN {in_flight}"),
        row(f"rate  {rate_s}"),
        "└" + "─" * (W + 2) + "┘",
    ]


def print_status_box(
    ok: int,
    fail: int,
    total: int,
    *,
    in_flight: int = 0,
    title: str = "x-farm",
    final: bool = False,
    rate_override: float | None = None,
) -> None:
    """Live boxed progress: bar + OK/FAIL/RUN + rate/min.

    On TTY: rewrite in-place (no scroll spam).
    Non-TTY (pipe/log file): print a fresh box each time.
    final=True always prints a permanent DONE box (no cursor rewrite).
    """
    global _box_active, _box_lines
    lines = _build_status_lines(
        ok, fail, total,
        in_flight=in_flight, title=title, final=final, rate_override=rate_override,
    )
    assert len(lines) == _BOX_H
    body = "\n".join(lines)
    tty = False
    try:
        tty = bool(sys.stdout.isatty())
    except Exception:
        tty = False

    with _print_lock:
        if final or not tty:
            # permanent print (DONE or redirected stdout)
            if _box_active and _box_lines > 0 and tty:
                # move past previous live box first
                print(flush=True)
            print(body, flush=True)
            _box_active = False
            _box_lines = 0
            return

        # live TTY rewrite
        if _box_active and _box_lines > 0:
            # cursor up N lines, then rewrite
            sys.stdout.write(f"\033[{_box_lines}A")
            sys.stdout.write("\033[J")  # clear to end of screen
        print(body, end="", flush=True)
        # ensure trailing newline so cursor sits under box
        sys.stdout.write("\n")
        sys.stdout.flush()
        _box_active = True
        _box_lines = _BOX_H


def print_run_plan(args: argparse.Namespace, total: int, workers: int, providers: list[str]) -> None:
    """Human-readable run description printed once at start."""
    mode = "sequential" if workers == 1 else f"parallel ({workers} workers)"
    proxy = "none (VPS IP)"
    if args.proxy_file:
        pmode = getattr(args, "proxy_mode", "limit") or "limit"
        if pmode == "every":
            proxy = f"file={args.proxy_file} mode=every/{args.proxy_every}"
        else:
            proxy = f"file={args.proxy_file} mode=limit (sticky until 429/block)"
    elif args.proxy:
        proxy = f"fixed={args.proxy.split('@')[-1]}"
    pol = _normalize_inject_policy(
        getattr(args, "inject_policy", None),
        skip_inject=bool(getattr(args, "skip_inject", False)),
    )
    pol_label = {
        "token": f"ON token (no chat gate) → {args.db}",
        "usable": f"ON usable-gate → {args.db}",
        "off": "OFF",
    }.get(pol, pol)

    speed = normalize_speed(getattr(args, "speed", None) or os.getenv("XAI_SPEED") or "normal")
    prof = SPEED_PROFILES[speed]
    W = 40

    def row(s: str) -> str:
        s = s[:W]
        return "│ " + s + " " * (W - len(s)) + " │"

    short_inj = {"token": "token", "usable": "usable", "off": "off"}.get(pol, pol)
    # show actual mail mode: pinned provider or auto fallback chain
    _mp = getattr(args, "mail_provider", None)
    if _mp:
        mail = _mp
    else:
        mail = "auto (tempmail.lol→smailpro→mail.tm→...)"
    lines = [
        "┌" + "─" * (W + 2) + "┐",
        row(f"START  n={total}  {prof['label']}  w={workers}"),
        row(f"est {prof['est']}"),
        row(f"proxy {proxy}"),
        row(f"inject {short_inj}  mail={mail}"),
        "└" + "─" * (W + 2) + "┘",
    ]
    with _print_lock:
        print("\n".join(lines), flush=True)


def log(msg: str, worker: int | None = None) -> None:
    """Process log. Silent during quiet run (box-only UI)."""
    if _quiet_run:
        return
    prefix = f"[W{worker}] " if worker is not None else ""
    with _print_lock:
        # if a live box is on screen, print below it without breaking rewrite
        global _box_active, _box_lines
        if _box_active and _box_lines > 0:
            # leave box, print log under it — next box redraw starts fresh below
            _box_active = False
            _box_lines = 0
        print(f"{prefix}{msg}", flush=True)



def _normalize_inject_policy(policy: str | None, skip_inject: bool = False) -> str:
    """token (default) | usable | off. --skip-inject maps to off."""
    if skip_inject:
        return "off"
    p = (policy or "token").strip().lower()
    if p in ("usable", "gate", "chat", "yes"):
        return "usable"
    if p in ("token", "always", "force", "all"):
        return "token"
    if p in ("off", "none", "skip", "no"):
        return "off"
    return "token"


def gated_inject(
    *,
    tokens: dict,
    email: str | None,
    user_id: str | None,
    display_name: str | None,
    db_path: str,
    inject_providers: list[str],
    skip_inject: bool,
    log_fn,
    tag: str = "9",
    inject_policy: str | None = None,
) -> tuple[dict, list]:
    """
    inject_policy:
      token  (default) — inject on token OK, NO chat probe
      usable           — chat-test first, inject only if usable
      off              — never inject (--skip-inject)
    Returns (chat_meta, inject_rows).
    """
    policy = _normalize_inject_policy(inject_policy, skip_inject=skip_inject)
    chat_meta: dict = {"inject_policy": policy, "usable": None, "skipped": False}

    # token/off: skip chat entirely (no chat gate)
    if policy in ("token", "off"):
        chat_meta["skipped"] = True
        chat_meta["reason"] = "chat_probe_skipped"
        if policy == "off":
            log_fn(f"[{tag}b] inject OFF (policy=off)")
            return chat_meta, []
        log_fn(f"[{tag}a] chat probe SKIP (policy=token)")
    else:
        chat = test_chat_token(tokens, email=email, user_id=user_id)
        chat_meta = {
            k: chat.get(k)
            for k in ("ok", "usable", "status", "code", "reason", "model", "error", "text_head")
        }
        chat_meta["inject_policy"] = policy
        status = chat_meta.get("status")
        reason = chat_meta.get("reason")
        code = chat_meta.get("code") or "-"
        if chat.get("usable"):
            log_fn(
                f"[{tag}a] chat {chat_meta.get('model') or 'grok-4.5'} "
                f"usable=YES status={status} reason={reason} code={code}"
            )
        else:
            err = (chat_meta.get("error") or "")[:100]
            log_fn(
                f"[{tag}a] chat {chat_meta.get('model') or 'grok-4.5'} "
                f"usable=NO status={status} reason={reason} code={code} err={err}"
            )
            log_fn(f"[{tag}b] SKIP inject (chat gate failed, policy=usable)")
            return chat_meta, []

    inject_rows: list = []
    for prov in inject_providers:
        try:
            with _inject_lock:
                row = inject_connection(
                    db_path,
                    prov,
                    tokens,
                    email=email,
                    display_name=display_name,
                    user_id=user_id,
                    fetch_profile=True,
                )
            slim = {
                k: row.get(k)
                for k in (
                    "id",
                    "provider",
                    "email",
                    "action",
                    "updated",
                    "userId",
                    "hasGrokCodeAccess",
                    "subscriptionTier",
                    "profileOk",
                    "priority",
                    "error",
                )
                if k in row or k in ("id", "provider", "action")
            }
            inject_rows.append(slim)
            action = row.get("action") or ("updated" if row.get("updated") else "created")
            log_fn(
                f"[{tag}b] injected {prov} id={str(row.get('id') or '')[:8]}… "
                f"action={action} uid={(str(row.get('userId') or '')[:8] or '-')} "
                f"code={row.get('hasGrokCodeAccess')} "
                f"tier={row.get('subscriptionTier') or '-'} "
                f"profile={'ok' if row.get('profileOk') else 'skip'}"
            )
        except Exception as e:
            log_fn(f"[{tag}b] inject {prov} FAIL: {e}")
            inject_rows.append({"provider": prov, "error": str(e)})
    return chat_meta, inject_rows


def maybe_rotate_proxy(err: object, worker: int | None = None) -> None:
    """Sticky pool: advance IP only when error looks like limit/block."""
    if not is_limit_error(err):
        return
    new_p = rotate_proxy_on_limit(err)
    if new_p:
        log(f"proxy ROTATE on limit → next IP", worker=worker)
    else:
        # still log detection even if single proxy / no pool
        log(f"limit signal (no pool rotate): {str(err)[:120]}", worker=worker)


def current_create_user_action() -> str:
    """Live next-action id (may be refreshed after 404)."""
    with _NEXT_ACTION_LOCK:
        return NEXT_ACTION_CREATE_USER


def discover_create_user_action(
    session: "XaiSession | None" = None,
    *,
    log_fn=None,
) -> str | None:
    """Scrape live createUser next-action hash from accounts.x.ai signup JS.

    xAI ships Next.js Server Actions — the ``next-action`` header is a deploy-time
    content hash, NOT a permanent API key. Every frontend deploy rotates it and
    the old id returns HTTP 404 ``Server action not found``.

    Strategy:
      1. GET signup HTML → collect /_next/static/chunks/*.js
      2. Download chunks that mention createUserAndSession / turnstileToken
      3. Prefer createServerReference(\"HASH\") bound as mutationFn for createUser
         (chunk that also contains createUserAndSessionRequest payload shape)
      4. Fallback: any createServerReference hash in those chunks
    """
    L = log_fn or (lambda m: log(m))
    xs = session or XaiSession(worker=0)
    try:
        if not getattr(xs, "ua", None):
            xs.bootstrap_cf()
        r = xs.s.get(
            SIGNUP_URL,
            headers=xs._headers({"Accept": "text/html"}),
            **xs._req_kw(timeout=45),
        )
        html = r.text or ""
    except Exception as e:
        L(f"discover action: signup GET fail: {e}")
        return None

    scripts = re.findall(r'src="(/_next/static/[^"]+)"', html)
    if not scripts:
        L("discover action: no scripts in signup HTML")
        return None

    preferred: list[str] = []
    fallback: list[str] = []
    for src in scripts:
        url = "https://accounts.x.ai" + src
        try:
            jr = xs.s.get(
                url,
                headers=xs._headers({"Accept": "*/*"}),
                **xs._req_kw(timeout=30),
            )
            t = jr.text or ""
        except Exception:
            continue
        if "createServerReference" not in t:
            continue
        ids = re.findall(
            r'createServerReference\)\("([a-f0-9]{40,44})"',
            t,
        )
        if not ids:
            ids = re.findall(
                r'createServerReference\("([a-f0-9]{40,44})"',
                t,
            )
        if not ids:
            continue
        # Strong signal: same chunk builds createUserAndSessionRequest payload
        if "createUserAndSessionRequest" in t or (
            "createUserAndSession" in t and "turnstileToken" in t
        ):
            preferred.extend(ids)
        elif any(
            k in t
            for k in (
                "createUserAndSession",
                "emailValidationCode",
                "clearTextPassword",
                "turnstileToken",
            )
        ):
            fallback.extend(ids)

    # de-dupe preserve order
    def _uniq(seq: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for x in seq:
            if x not in seen:
                seen.add(x)
                out.append(x)
        return out

    cands = _uniq(preferred) or _uniq(fallback)
    if not cands:
        L("discover action: no createServerReference candidates")
        return None
    # Prefer first preferred; if current seed still listed keep it unless forced
    chosen = cands[0]
    L(f"discover action: candidates={cands[:5]} chosen={chosen}")
    return chosen


def refresh_create_user_action(
    session: "XaiSession | None" = None,
    *,
    force: bool = False,
    log_fn=None,
) -> str:
    """Thread-safe refresh of NEXT_ACTION_CREATE_USER. Returns current id."""
    global NEXT_ACTION_CREATE_USER, _NEXT_ACTION_LAST_REFRESH
    L = log_fn or (lambda m: log(m))
    with _NEXT_ACTION_LOCK:
        now = time.time()
        if (
            not force
            and _NEXT_ACTION_LAST_REFRESH
            and (now - _NEXT_ACTION_LAST_REFRESH) < _NEXT_ACTION_MIN_REFRESH_GAP
        ):
            return NEXT_ACTION_CREATE_USER
        # mark attempt early to collapse concurrent 404 stampedes
        _NEXT_ACTION_LAST_REFRESH = now

    new_id = discover_create_user_action(session, log_fn=L)
    with _NEXT_ACTION_LOCK:
        if new_id and new_id != NEXT_ACTION_CREATE_USER:
            old = NEXT_ACTION_CREATE_USER
            NEXT_ACTION_CREATE_USER = new_id
            L(f"createUser next-action refreshed: {old[:12]}… → {new_id[:12]}…")
        elif new_id:
            L(f"createUser next-action still current: {new_id[:16]}…")
        else:
            L("createUser next-action refresh failed — keep seed")
        return NEXT_ACTION_CREATE_USER


def rand_password(n: int = 18) -> str:
    base = (
        random.choice(string.ascii_uppercase)
        + random.choice(string.ascii_lowercase)
        + random.choice(string.digits)
        + random.choice("!@#$%&*")
        + "".join(random.choices(string.ascii_letters + string.digits, k=max(8, n - 4)))
    )
    return base + "#xAI"


def rand_name() -> tuple[str, str]:
    firsts = ["Alex", "Sam", "Jordan", "Casey", "Riley", "Avery", "Quinn", "Morgan"]
    lasts = ["Reed", "Blake", "Hayes", "Cole", "Brooks", "Lane", "West", "Stone"]
    return random.choice(firsts), random.choice(lasts)


def _cf_share_key(proxy: str | None) -> str:
    """Share CF by exit IP: proxy host:port, else direct."""
    if not proxy:
        return "direct"
    try:
        from urllib.parse import urlparse

        u = urlparse(proxy if "://" in proxy else f"http://{proxy}")
        host = u.hostname or "proxy"
        port = u.port or ""
        return f"{host}:{port}" if port else host
    except Exception:
        return proxy.split("@")[-1][:80]


def _cf_entry_fresh(ent: dict | None) -> bool:
    if not ent or ent.get("err"):
        return False
    if not ent.get("cookies"):
        return False
    age = time.time() - float(ent.get("ts") or 0)
    if age > _CF_SHARE_TTL:
        return False
    if int(ent.get("uses") or 0) >= max(1, _CF_SHARE_MAX_USES):
        return False
    return True


def acquire_shared_cf(proxy: str | None = None, force: bool = False) -> dict:
    """1 CF solve → many workers (same proxy key / direct IP).

    Returns {ua, cookies, source: cache|fresh, uses, age_s}.
    Concurrent callers for same key wait on one solve (single-flight).
    """
    key = _cf_share_key(proxy)
    deadline = time.time() + 120.0
    with _cf_share_cond:
        while True:
            ent = _cf_share.get(key)
            if not force and _cf_entry_fresh(ent):
                ent["uses"] = int(ent.get("uses") or 0) + 1
                return {
                    "ua": ent.get("ua"),
                    "cookies": dict(ent.get("cookies") or {}),
                    "source": "cache",
                    "uses": ent["uses"],
                    "age_s": round(time.time() - float(ent.get("ts") or 0), 1),
                    "key": key,
                }
            if ent and ent.get("solving"):
                remaining = deadline - time.time()
                if remaining <= 0:
                    raise RuntimeError(f"CF share wait timeout key={key}")
                _cf_share_cond.wait(timeout=min(2.0, remaining))
                continue
            # become solver
            _cf_share[key] = {
                "ua": None,
                "cookies": {},
                "ts": 0.0,
                "uses": 0,
                "solving": True,
                "err": None,
            }
            break

    # solve outside lock
    try:
        sol = solve_cloudflare(SIGNUP_URL, timeout=90, proxy=proxy)
        if not sol.get("solved"):
            raise RuntimeError(f"CF solve failed: {sol}")
        ua = sol.get("user_agent") or UA_FALLBACK
        cookies: dict[str, str] = {}
        tok = sol.get("cf_clearance") or sol.get("token")
        if tok:
            cookies["cf_clearance"] = str(tok)
        raw = sol.get("cookies")
        if isinstance(raw, str):
            for part in raw.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    cookies[k] = v
        elif isinstance(raw, dict):
            cookies.update({str(k): str(v) for k, v in raw.items()})
        if not cookies.get("cf_clearance") and not cookies:
            raise RuntimeError(f"CF solve empty cookies: {list(sol.keys())}")
        with _cf_share_cond:
            _cf_share[key] = {
                "ua": ua,
                "cookies": cookies,
                "ts": time.time(),
                "uses": 1,
                "solving": False,
                "err": None,
            }
            _cf_share_cond.notify_all()
        return {
            "ua": ua,
            "cookies": dict(cookies),
            "source": "fresh",
            "uses": 1,
            "age_s": 0.0,
            "key": key,
        }
    except Exception as e:
        with _cf_share_cond:
            _cf_share[key] = {
                "ua": None,
                "cookies": {},
                "ts": 0.0,
                "uses": 0,
                "solving": False,
                "err": str(e)[:200],
            }
            _cf_share_cond.notify_all()
        raise


def invalidate_shared_cf(proxy: str | None = None) -> None:
    key = _cf_share_key(proxy)
    with _cf_share_cond:
        _cf_share.pop(key, None)
        _cf_share_cond.notify_all()


class XaiSession:
    def __init__(
        self,
        impersonate: str = "chrome131",
        worker: int | None = None,
        proxy: str | None = None,
    ):
        self.s = creq.Session()
        self.impersonate = impersonate
        self.ua = UA_FALLBACK
        self.cf_clearance: str | None = None
        self.worker = worker
        self.proxy = proxy  # scheme://[user:pass@]host:port

    def _log(self, msg: str) -> None:
        log(msg, worker=self.worker)

    def _req_kw(self, **extra) -> dict:
        """Common curl_cffi kwargs including optional proxy."""
        kw = {"impersonate": self.impersonate, **extra}
        if self.proxy:
            kw["proxy"] = self.proxy
        return kw

    def bootstrap_cf(self, force: bool = False) -> None:
        """Bootstrap session cookies for accounts.x.ai.

        PURE_HTTP / SKIP_CF / NO_BROWSER=1 → plain GET only (no Camoufox CF solver).
        Proven: __cf_bm from HTML GET is enough; cf_clearance not required today.
        """
        pure = (
            os.getenv("PURE_HTTP", "0") == "1"
            or os.getenv("NO_BROWSER", "0") == "1"
            or os.getenv("SKIP_CF", "0") == "1"
        )
        if pure:
            self._log("[1] bootstrap…")
            r = self.s.get(
                SIGNUP_URL,
                headers={"User-Agent": self.ua, "Accept": "text/html"},
                **self._req_kw(timeout=45),
            )
            if r.status_code != 200 or "Attention Required" in (r.text or ""):
                raise RuntimeError(
                    f"signup blocked status={r.status_code}"
                )
            self.cf_clearance = None
            self._log(f"    ok status={r.status_code}")
            if self.proxy:
                from urllib.parse import urlparse

                u = urlparse(self.proxy)
                self._log(f"    proxy={u.scheme}://{u.hostname}:{u.port}")
            return

        self._log("[1] CF clearance…")
        last_err: Exception | None = None
        for attempt in range(2):
            try:
                shared = acquire_shared_cf(self.proxy, force=force or attempt > 0)
                self.ua = shared.get("ua") or self.ua
                cookies = dict(shared.get("cookies") or {})
                self.cf_clearance = cookies.get("cf_clearance")
                r = self.s.get(
                    SIGNUP_URL,
                    cookies=cookies,
                    headers={"User-Agent": self.ua, "Accept": "text/html"},
                    **self._req_kw(timeout=45),
                )
                blocked = r.status_code != 200 or "Attention Required" in (r.text or "")
                if blocked:
                    invalidate_shared_cf(self.proxy)
                    last_err = RuntimeError(f"signup page blocked status={r.status_code}")
                    force = True
                    continue
                src = shared.get("source")
                uses = shared.get("uses")
                age = shared.get("age_s")
                self._log(
                    f"    CF ok status={r.status_code} src={src} uses={uses} "
                    f"age={age}s cookies={list(self.s.cookies.keys())}"
                )
                if self.proxy:
                    from urllib.parse import urlparse

                    u = urlparse(self.proxy)
                    self._log(f"    proxy={u.scheme}://{u.hostname}:{u.port}")
                return
            except Exception as e:
                last_err = e
                invalidate_shared_cf(self.proxy)
                force = True
        raise RuntimeError(f"CF bootstrap failed: {last_err}")
    def _headers(self, extra: dict | None = None) -> dict:
        h = {
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Origin": "https://accounts.x.ai",
            "Referer": SIGNUP_URL,
        }
        if extra:
            h.update(extra)
        return h

    def grpc(self, url: str, body: bytes) -> tuple[int, bytes, dict]:
        r = self.s.post(
            url,
            data=body,
            headers=self._headers(
                {
                    "Content-Type": "application/grpc-web+proto",
                    "x-grpc-web": "1",
                    "x-user-agent": "connect-es/2.1.1",
                    "Accept": "application/grpc-web+proto",
                }
            ),
            **self._req_kw(timeout=45),
        )
        return r.status_code, r.content, {k.lower(): v for k, v in r.headers.items()}

    def create_email_code(self, email: str, castle: str) -> dict:
        body = build_create_email_validation_code(email, castle)
        status, raw, headers = self.grpc(CREATE_EMAIL, body)
        payload = unwrap_grpc_web(raw)
        fields = parse_fields(payload) if payload else []
        self._log(f"[3] CreateEmailValidationCode status={status} body={len(raw)} fields={len(fields)}")
        if status >= 400:
            raise RuntimeError(f"CreateEmailValidationCode HTTP {status}: {raw[:200]!r}")
        grpc_status = headers.get("grpc-status")
        if grpc_status and str(grpc_status) not in ("0", "0.0"):
            raise RuntimeError(
                f"CreateEmailValidationCode grpc-status={grpc_status} "
                f"msg={headers.get('grpc-message')}"
            )
        return {"status": status, "fields": fields, "raw": raw, "headers": headers}

    def verify_email_code(self, email: str, code: str) -> dict:
        # API may accept HPN-7Z9 or HPN7Z9 — try as-is first, then stripped
        candidates = [code]
        stripped = code.replace("-", "").replace(" ", "")
        if stripped != code:
            candidates.append(stripped)
        last_err = None
        for c in candidates:
            body = build_verify_email_validation_code(email, c)
            status, raw, headers = self.grpc(VERIFY_EMAIL, body)
            grpc_status = headers.get("grpc-status")
            # trailer-only success (HAR empty body + grpc-status header/trailer)
            if raw and b"grpc-status:0" in raw and not grpc_status:
                grpc_status = "0"
            self._log(
                f"[4] VerifyEmailValidationCode code={c} status={status} "
                f"body={len(raw)} grpc={grpc_status}"
            )
            if status >= 400:
                last_err = f"HTTP {status}"
                continue
            if grpc_status and str(grpc_status) not in ("0", "0.0"):
                last_err = (
                    f"grpc={grpc_status} msg={headers.get('grpc-message')}"
                )
                continue
            # success: no error status, or explicit trailer 0
            return {"status": status, "raw": raw, "code_used": c}
        raise RuntimeError(f"Verify failed: {last_err}")

    def validate_password(self, email: str, password: str) -> None:
        body = build_validate_password(email, password)
        status, raw, _ = self.grpc(VALIDATE_PW, body)
        self._log(f"[5] ValidatePassword status={status} body={len(raw)}")

    def create_user(
        self,
        email: str,
        code: str,
        given: str,
        family: str,
        password: str,
        turnstile: str,
        castle: str,
    ) -> dict:
        conversion_id = str(uuid.uuid4())
        payload = [
            {
                "emailValidationCode": code,
                "createUserAndSessionRequest": {
                    "email": email,
                    "givenName": given,
                    "familyName": family,
                    "clearTextPassword": password,
                    "tosAcceptedVersion": 1,
                },
                "turnstileToken": turnstile,
                "conversionId": conversion_id,
                "castleRequestToken": castle,
            },
            {"client": "$T", "meta": "$undefined", "mutationKey": "$undefined"},
        ]
        router_tree = quote(
            '["",{"children":["(app)",{"children":["(auth)",{"children":["sign-up",'
            '{"children":["__PAGE__",{},null,null]},null,null]},null,null]},null,null]},'
            "null,null,true]",
            safe="",
        )
        action_id = current_create_user_action()
        r = self.s.post(
            SIGNUP_URL,
            data=json.dumps(payload, separators=(",", ":")),
            headers=self._headers(
                {
                    "Accept": "text/x-component",
                    "Content-Type": "text/plain;charset=UTF-8",
                    "next-action": action_id,
                    "next-router-state-tree": router_tree,
                }
            ),
            **self._req_kw(timeout=60),
        )
        self._log(
            f"[6] createUser status={r.status_code} len={len(r.content)} "
            f"cookies={list(self.s.cookies.keys())} action={action_id[:12]}…"
        )
        text = r.text if r.text else ""
        if r.status_code == 404 or "Server action not found" in text:
            # Next.js action hash rotated — scrape + retry once with new id
            new_id = refresh_create_user_action(self, force=True, log_fn=self._log)
            if new_id and new_id != action_id:
                r = self.s.post(
                    SIGNUP_URL,
                    data=json.dumps(payload, separators=(",", ":")),
                    headers=self._headers(
                        {
                            "Accept": "text/x-component",
                            "Content-Type": "text/plain;charset=UTF-8",
                            "next-action": new_id,
                            "next-router-state-tree": router_tree,
                        }
                    ),
                    **self._req_kw(timeout=60),
                )
                self._log(
                    f"[6] createUser retry status={r.status_code} len={len(r.content)} "
                    f"action={new_id[:12]}…"
                )
                text = r.text if r.text else ""
        if r.status_code >= 400:
            raise RuntimeError(f"createUser HTTP {r.status_code}: {text[:300]}")

        # Existing email (emailnator gmail alias already registered) — no set-cookie redirect
        if "ExistingEmailSignInMethods" in text or "ExistingUserWithEmail" in text:
            m = re.search(r'"pwEmail":"([^"]+)"', text)
            m2 = re.search(r'"pwNormalizedEmail":"([^"]+)"', text)
            raise RuntimeError(
                "createUser existing email"
                + (f" email={m.group(1)}" if m else "")
                + (f" norm={m2.group(1)}" if m2 else "")
            )

        # Next.js RSC action errors look like: 1:{"error":"...","traceId":"..."}
        first_json_err = None
        for line in text.splitlines()[:30]:
            line = line.strip()
            if not line:
                continue
            payload_line = line
            if len(line) > 2 and line[0].isdigit() and line[1] == ":":
                payload_line = line[2:]
            if not (payload_line.startswith("{") and '"error"' in payload_line):
                continue
            try:
                obj = json.loads(payload_line)
            except Exception:
                continue
            if isinstance(obj, dict) and obj.get("error") and obj.get("error") != "$undefined":
                # real action error object (turnstile/castle/etc)
                if "traceId" in obj or "Failed" in str(obj.get("error")) or "[internal]" in str(
                    obj.get("error")
                ):
                    first_json_err = str(obj["error"])
                    break
        if first_json_err:
            raise RuntimeError(f"createUser action error: {first_json_err}")

        sso = self._establish_sso_from_create_response(text)
        return {
            "status": r.status_code,
            "location": r.headers.get("x-action-redirect") or r.headers.get("Location"),
            "body": text[:1000],
            "headers": {k: v for k, v in r.headers.items() if k.lower() != "set-cookie"},
            "cookies": list(dict.fromkeys(self.s.cookies.keys())),
            "sso": sso,
            "full_body": text,
        }

    def _establish_sso_from_create_response(self, text: str) -> dict:
        """Success createUser returns a set-cookie chain URL (string action result).

        Flow (browser): window.location.href = set-cookie URL
          auth.grokipedia.com → often 400 from VPS
          auth.grokusercontent.com → sets sso / sso-rw → redirect accounts.x.ai/account
        Prefer grokusercontent (direct or nested success_url).
        """
        import base64
        import re
        from urllib.parse import unquote

        out: dict[str, Any] = {"ok": False, "urls": [], "final": None, "cookies": []}
        # normalize JS/JSON escapes so regex can see real URLs
        raw = text or ""
        norm = (
            raw.replace("\\/", "/")
            .replace("\\u0026", "&")
            .replace("\\u003d", "=")
            .replace("\\u003f", "?")
            .replace("\\u002F", "/")
            .replace("\\u003A", ":")
        )
        norm = unquote(norm)
        urls = re.findall(
            r"https://auth\.(?:grok|grokipedia|grokusercontent)\.com/set-cookie\?q=[A-Za-z0-9_\-\.]+",
            norm,
        )
        # also recover nested success_url from JWT payload
        nested: list[str] = []
        for u in urls:
            try:
                q = u.split("q=", 1)[1]
                part = q.split(".")[1]
                part += "=" * ((4 - len(part) % 4) % 4)
                cfg = json.loads(base64.urlsafe_b64decode(part))
                su = (cfg.get("config") or cfg).get("success_url")
                if su and su.startswith("http"):
                    nested.append(su)
            except Exception:
                pass
        # order: grokusercontent first, then nested, then grokipedia
        ordered: list[str] = []
        for u in urls + nested:
            if u not in ordered:
                ordered.append(u)
        ordered.sort(key=lambda u: (0 if "grokusercontent" in u else 1, u))
        out["urls"] = [u[:120] for u in ordered]

        for u in ordered:
            try:
                rr = self.s.get(
                    u,
                    headers=self._headers(
                        {
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Referer": SIGNUP_URL,
                            "Upgrade-Insecure-Requests": "1",
                        }
                    ),
                    **self._req_kw(timeout=45, allow_redirects=True),
                )
                out["final"] = str(rr.url)[:200]
                out.setdefault("attempts", []).append(
                    {"host": u.split("/")[2], "status": rr.status_code, "final": str(rr.url)[:120]}
                )
            except Exception as e:
                out.setdefault("attempts", []).append({"url": u[:80], "error": str(e)[:120]})
                continue

        cookie_names = list(dict.fromkeys(self.s.cookies.keys()))
        out["cookies"] = cookie_names
        has_sso = any(n in cookie_names for n in ("sso", "sso-rw", "sso-session", "sso-refresh-token"))
        out["ok"] = has_sso
        self._log(f"    SSO establish ok={out['ok']} cookies={cookie_names}")
        if not has_sso:
            # dump small fingerprint of body so we can see format drift
            snip = re.sub(r"\s+", " ", norm)[:240]
            out["body_snip"] = snip
            try:
                dump = Path("/tmp") / f"xai-createuser-fail-{int(time.time())}.txt"
                dump.write_text(raw, encoding="utf-8", errors="replace")
                out["body_dump"] = str(dump)
                self._log(f"    SSO fail body dumped → {dump} len={len(raw)}")
            except Exception as e:
                out["body_dump_err"] = str(e)[:80]
            raise RuntimeError(f"createUser OK but SSO cookies missing: {out}")
        return out

    def request_device_code(self, retries: int = 6) -> dict:
        """Global schedule gap for device_code. HTTP runs outside the lock.

        Holding the lock across the POST made effective spacing = gap + RTT and
        parked every extra worker behind one slow request — Maximum (more workers)
        lost to Fast purely from lock queueing.
        """
        global _device_code_last, _device_code_gap
        last_err = "no attempts"
        for i in range(max(1, retries)):
            with _device_code_lock:
                gap_need = max(_DEVICE_CODE_MIN_GAP, float(_device_code_gap))
                gap = time.time() - _device_code_last
                if gap < gap_need:
                    time.sleep(gap_need - gap)
                # reserve slot at attempt start (spacing between starts, not end→start)
                _device_code_last = time.time()
            r = creq.post(
                DEVICE_CODE_URL,
                data={
                    "client_id": GROK_CLI_CLIENT_ID,
                    "scope": GROK_CLI_SCOPE,
                    "referrer": "grok-build",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "User-Agent": "grok-pager/0.2.93 grok-shell/0.2.93 (linux; x86_64)",
                },
                **self._req_kw(timeout=30),
            )
            if r.status_code < 400:
                try:
                    data = r.json()
                except Exception as e:
                    last_err = f"device_code bad json: {e}"
                    time.sleep(1.0 + i)
                    continue
                # success → gently shrink gap toward min
                with _device_code_lock:
                    _device_code_gap = max(
                        _DEVICE_CODE_MIN_GAP,
                        float(_device_code_gap) * 0.9,
                    )
                return data
            body = (r.text or "")[:200]
            last_err = f"device_code {r.status_code}: {body}"
            # rate limit / slow_down → raise adaptive gap + backoff
            if r.status_code in (429, 503) or "slow_down" in body.lower() or "too many" in body.lower():
                with _device_code_lock:
                    _device_code_gap = min(
                        _DEVICE_CODE_GAP_MAX,
                        max(_DEVICE_CODE_MIN_GAP, float(_device_code_gap) * 1.6 + 0.4),
                    )
                    cur_gap = float(_device_code_gap)
                wait = min(45.0, cur_gap * (1.2 + i * 0.5) + random.uniform(0.3, 1.2))
                self._log(
                    f"    device_code rate-limit, sleep {wait:.1f}s "
                    f"gap→{cur_gap:.2f}s (try {i+1}/{retries})"
                )
                time.sleep(wait)
                continue
            raise RuntimeError(last_err)
        raise RuntimeError(last_err)

    def poll_token(self, device_code: str, interval: int = 2, timeout: int = 60) -> dict:
        """Poll device_code → tokens. Keep timeout SHORT — long hangs kill wall rate."""
        deadline = time.time() + max(5.0, float(timeout))
        # after consent we can poll fast; server interval often 5 but pending is quick
        sleep_s = min(1.5, max(0.8, float(interval or 2)))
        while time.time() < deadline:
            r = creq.post(
                TOKEN_URL,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": GROK_CLI_CLIENT_ID,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                    "User-Agent": "grok-pager/0.2.93 grok-shell/0.2.93 (linux; x86_64)",
                },
                **self._req_kw(timeout=20),
            )
            try:
                data = r.json()
            except Exception:
                data = {"error": "bad_json", "error_description": r.text[:200]}
            if "access_token" in data:
                return data
            err = data.get("error")
            if err in ("authorization_pending", "slow_down"):
                time.sleep(sleep_s + (1.0 if err == "slow_down" else 0))
                continue
            if err in ("expired_token", "access_denied", "invalid_grant"):
                raise RuntimeError(f"token poll denied: {data}")
            if err:
                raise RuntimeError(f"token poll error: {data}")
            time.sleep(sleep_s)
        raise TimeoutError("device code poll timeout")

    def try_device_consent(self, user_code: str) -> dict:
        """Approve device code with SSO cookies via real form endpoints.

        Browser flow:
          1) GET /oauth2/device?user_code=XXXX-XXXX
          2) POST https://auth.x.ai/oauth2/device/verify  {user_code}
          3) GET  /oauth2/device/consent?user_code=...  (extract userId)
          4) POST https://auth.x.ai/oauth2/device/approve
             {user_code, action=allow, principal_type=User, principal_id=<userId>}
        """
        import re

        # normalize display form XXXX-XXXX
        raw = user_code.replace("-", "").replace(" ", "").strip().upper()
        if len(raw) == 8:
            user_code = raw[:4] + "-" + raw[4:]
        else:
            user_code = user_code.strip().upper()

        result: dict[str, Any] = {"user_code": user_code, "approved": False}

        # 1) open device page (pre-fills form)
        r = self.s.get(
            f"{DEVICE_PAGE}?user_code={user_code}",
            headers=self._headers({"Accept": "text/html", "Referer": SIGNUP_URL}),
            **self._req_kw(timeout=45, allow_redirects=True),
        )
        result["device_get"] = {"status": r.status_code, "url": str(r.url)[:160]}

        # 2) verify user_code (auth.x.ai)
        verify_url = "https://auth.x.ai/oauth2/device/verify"
        rv = self.s.post(
            verify_url,
            data={"user_code": user_code},
            headers=self._headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Origin": "https://accounts.x.ai",
                    "Referer": f"{DEVICE_PAGE}?user_code={user_code}",
                    "Upgrade-Insecure-Requests": "1",
                }
            ),
            **self._req_kw(timeout=45, allow_redirects=True),
        )
        result["verify"] = {
            "status": rv.status_code,
            "url": str(rv.url)[:200],
            "history": [f"{h.status_code}:{str(h.url)[:80]}" for h in (rv.history or [])],
        }
        # ONLY trust URL — consent HTML embeds i18n "Device Authorized" strings
        if "device/done" in str(rv.url).lower():
            result["approved"] = True
            result["cookies"] = list(dict.fromkeys(self.s.cookies.keys()))
            return result

        # 3) consent page — extract principal_id (= userId)
        consent_url = f"{DEVICE_CONSENT_URL}?user_code={user_code}"
        # if verify redirected to consent already, reuse body
        if "device/consent" in str(rv.url) and rv.status_code == 200:
            rc = rv
        else:
            rc = self.s.get(
                consent_url,
                headers=self._headers({"Accept": "text/html", "Referer": str(rv.url)}),
                **self._req_kw(timeout=45, allow_redirects=True),
            )
        html = rc.text or ""
        result["consent_get"] = {"status": rc.status_code, "url": str(rc.url)[:200], "len": len(html)}

        user_id = None
        # RSC flight embeds user as heavily-escaped JSON: \\"userId\\":\\"uuid\\"
        for pat in (
            r'\\+"userId\\+"\s*:\s*\\+"([0-9a-fA-F-]{36})\\+"',
            r'"userId"\s*:\s*"([0-9a-fA-F-]{36})"',
            r'userId\\?":\\?"([0-9a-fA-F-]{36})',
            r'name="principal_id"\s+value="([0-9a-fA-F-]{36})"',
        ):
            m = re.search(pat, html)
            if m and m.group(1):
                user_id = m.group(1)
                break
        result["principal_id"] = user_id
        result["principal_type"] = "User"

        if not user_id:
            # save snippet for debug
            result["error"] = "principal_id/userId not found on consent page"
            # quick probe: is session actually logged in?
            if "Signed in as" not in html and "signed in as" not in html.lower():
                result["error"] += " (no Signed-in banner — SSO may not bind to accounts.x.ai)"
            result["cookies"] = list(dict.fromkeys(self.s.cookies.keys()))
            return result

        # 4) approve form POST — action must be "allow" (from DeviceConsentForm)
        approve_url = "https://auth.x.ai/oauth2/device/approve"
        ra = self.s.post(
            approve_url,
            data={
                "user_code": user_code,
                "action": "allow",
                "principal_type": "User",
                "principal_id": user_id,
            },
            headers=self._headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Origin": "https://accounts.x.ai",
                    "Referer": str(rc.url),
                    "Upgrade-Insecure-Requests": "1",
                }
            ),
            **self._req_kw(timeout=45, allow_redirects=True),
        )
        body_head = (ra.text or "")[:400]
        result["approve"] = {
            "status": ra.status_code,
            "url": str(ra.url)[:200],
            "history": [f"{h.status_code}:{str(h.url)[:100]}" for h in (ra.history or [])],
            "body_head": body_head,
            "set_cookie": bool(ra.headers.get("set-cookie") or ra.headers.get("Set-Cookie")),
        }
        final = str(ra.url).lower()
        body_l = (ra.text or "").lower()
        body_short = (ra.text or "").strip()
        # hard deny: real 401/403 OR plain-text Session expired (not i18n in HTML)
        hard_session = (
            ra.status_code in (401, 403)
            or body_short.lower() == "session expired"
            or (
                len(body_short) < 80
                and "session expired" in body_short.lower()
                and "<html" not in body_l
            )
        )
        if hard_session:
            result["approved"] = False
            result["error"] = result.get("error") or f"approve {ra.status_code}: {body_head[:60]}"
        # Success: landed on device/done OR explicit authorized page
        elif "device/done" in final:
            result["approved"] = True
        elif "device authorized" in body_l or "has been authorized" in body_l:
            result["approved"] = True
        elif (
            ra.status_code < 400
            and "device/consent" not in final
            and "error=" not in final
            and "sign-in" not in final
            and "login" not in final
        ):
            # redirected somewhere useful (account / done / etc)
            result["approved"] = True
            result["approve_soft"] = True

        # 5) hit done page (best-effort)
        try:
            rd = self.s.get(
                DEVICE_DONE_URL,
                headers=self._headers({"Accept": "text/html"}),
                **self._req_kw(timeout=30, allow_redirects=True),
            )
            result["done"] = {"status": rd.status_code, "url": str(rd.url)[:160]}
        except Exception as e:
            result["done"] = {"error": str(e)[:120]}

        result["cookies"] = list(dict.fromkeys(self.s.cookies.keys()))
        return result


def save_account(rec: dict) -> None:
    with _file_lock:
        with open(ACCOUNTS_FILE, "a") as f:
            f.write(json.dumps(rec) + "\n")


def _take_account(index: int | None = None) -> tuple[str, str]:
    """Pop next (email, password) from GSuite queue (thread-safe)."""
    with _ACCOUNT_LOCK:
        if not _ACCOUNT_QUEUE:
            raise RuntimeError("account queue empty — provide --account-file")
        if index is not None and 0 <= index < len(_ACCOUNT_QUEUE):
            return _ACCOUNT_QUEUE.pop(index)
        return _ACCOUNT_QUEUE.pop(0)


def login_one_google(
    *,
    db_path: str,
    inject_providers: list[str],
    skip_inject: bool = False,
    email: str | None = None,
    password: str | None = None,
    worker: int | None = None,
    proxy: str | None = None,
    inject_policy: str | None = None,
) -> dict:
    """Google SSO path (no email regist). GSuite domain-required accounts."""

    def L(msg: str) -> None:
        log(msg, worker=worker)

    if proxy is None:
        proxy = acquire_proxy()
    if not email or not password:
        email, password = _take_account()
    given, family = rand_name()
    L(f"[g1] Google SSO login email={email}")

    g = login_google_sso(email, password, proxy=proxy, worker=worker, headless=True)
    if not g.get("ok") and not g.get("cookies"):
        raise RuntimeError(g.get("error") or "google login failed (no cookies)")

    xs = XaiSession(worker=worker, proxy=proxy)
    check_cancel(worker)
    # still need CF for device pages; seed SSO from browser
    xs.bootstrap_cf()
    applied = apply_cookies_to_session(xs.s, g.get("cookies") or {})
    L(f"    sso cookies applied={applied} names={g.get('cookie_names')}")
    if not any(n in (g.get("cookies") or {}) for n in ("sso", "sso-rw", "sso-session", "sso-refresh-token")):
        # try set-cookie URLs if browser returned them without jar SSO
        for u in g.get("set_cookie_urls") or []:
            try:
                xs.s.get(
                    u,
                    headers=xs._headers({"Accept": "text/html", "Referer": SIGNUP_URL}),
                    **xs._req_kw(timeout=45, allow_redirects=True),
                )
            except Exception as e:
                L(f"    set-cookie soft-fail: {e}")
        cnames = list(dict.fromkeys(xs.s.cookies.keys()))
        if not any(n in cnames for n in ("sso", "sso-rw", "sso-session", "sso-refresh-token")):
            raise RuntimeError(
                f"google login no SSO cookies final={g.get('final_url')} err={g.get('error')}"
            )

    check_cancel(worker)
    L("[g7] device code…")
    dc = None
    consent: dict[str, Any] = {}
    for dtry in range(2):
        check_cancel(worker)
        dc = xs.request_device_code()
        L(f"    user_code={dc.get('user_code')} expires={dc.get('expires_in')} try={dtry+1}/2")
        consent = xs.try_device_consent(dc["user_code"])
        approve_body = str((consent.get("approve") or {}).get("body_head") or "")[:80]
        L(
            f"    consent approved={consent.get('approved')} "
            f"principal={consent.get('principal_id')} "
            f"err={consent.get('error')}"
        )
        if consent.get("approved"):
            break
        if "session expired" in approve_body.lower() or (consent.get("approve") or {}).get("status") in (401, 403):
            L(f"    consent session bad — retry device flow")
            time.sleep(0.4 + 0.3 * dtry)
            continue
        time.sleep(0.3)

    tokens = None
    token_err = None
    if not consent.get("approved"):
        ap = consent.get("approve") or {}
        token_err = (
            f"consent not approved status={ap.get('status')} "
            f"body={(ap.get('body_head') or consent.get('error') or '')[:80]}"
        )
        L(f"[g8] token SKIP fail-fast: {token_err}")
    else:
        try:
            tokens = xs.poll_token(
                dc["device_code"],
                interval=int(dc.get("interval") or 2),
                timeout=45,
            )
            L("[g8] token OK")
        except Exception as e:
            token_err = str(e)
            L(f"[g8] token FAIL: {e}")

    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "auth_mode": "google",
        "email": email,
        "password_len": len(password or ""),
        "givenName": given,
        "familyName": family,
        "worker": worker,
        "proxy": (proxy.split("@")[-1] if proxy else None),
        "google": {
            "ok": g.get("ok"),
            "cookie_names": g.get("cookie_names"),
            "final_url": g.get("final_url"),
            "elapsed_s": g.get("elapsed_s"),
            "error": g.get("error"),
        },
        "device": {
            "user_code": dc.get("user_code"),
            "device_code_len": len(dc.get("device_code") or ""),
            "consent": {
                k: consent.get(k)
                for k in (
                    "approved",
                    "principal_id",
                    "error",
                    "verify",
                    "approve",
                    "device_get",
                    "consent_get",
                )
            },
        },
        "tokens": None,
        "chat": None,
        "usable": None,
        "inject": [],
        "inject_policy": _normalize_inject_policy(inject_policy, skip_inject=skip_inject),
        "error": token_err,
    }
    if tokens:
        rec["tokens"] = {
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
            "id_token": tokens.get("id_token"),
            "token_type": tokens.get("token_type"),
            "access_token_len": len(tokens.get("access_token") or ""),
            "refresh_token_len": len(tokens.get("refresh_token") or ""),
            "expires_in": tokens.get("expires_in"),
            "scope": tokens.get("scope"),
            "has_id_token": bool(tokens.get("id_token")),
        }
        principal = consent.get("principal_id")
        chat_meta, inject_rows = gated_inject(
            tokens=tokens,
            email=email,
            user_id=principal,
            display_name=f"{given} {family}".strip(),
            db_path=db_path,
            inject_providers=inject_providers,
            skip_inject=skip_inject,
            inject_policy=inject_policy,
            log_fn=L,
            tag="g9",
        )
        rec["chat"] = chat_meta
        rec["usable"] = bool(chat_meta.get("usable"))
        rec["inject"] = inject_rows
        if not chat_meta.get("usable"):
            # only mark error if policy=usable (token policy still succeeds)
            pol = rec["inject_policy"]
            if pol == "usable":
                rec["error"] = rec.get("error") or f"chat_gate:{chat_meta.get('reason')}"

    save_account(rec)
    return rec


def register_one(
    db_path: str,
    inject_providers: list[str],
    skip_inject: bool = False,
    email: str | None = None,
    password: str | None = None,
    worker: int | None = None,
    proxy: str | None = None,
    mail_prefer: list[str] | None = None,
    mail_pinned: bool = False,
    inject_policy: str | None = None,
) -> dict:
    def L(msg: str) -> None:
        log(msg, worker=worker)

    # acquire rotating proxy if global pool set and no explicit proxy
    if proxy is None:
        proxy = acquire_proxy()
    xs = XaiSession(worker=worker, proxy=proxy)
    check_cancel(worker)
    xs.bootstrap_cf()
    check_cancel(worker)

    pure_http = (
        os.getenv("PURE_HTTP", "0") == "1"
        or os.getenv("NO_BROWSER", "0") == "1"
        or os.getenv("SKIP_CASTLE", "0") == "1"
    )
    if pure_http:
        castle1 = ""
    else:
        L("[2a] token…")
        castle1 = get_castle_token(CASTLE_PK, SIGNUP_URL, timeout_s=50, proxy=proxy)
        L(f"    tok len={len(castle1)}")

    mail = EmailBox(prefer=mail_prefer, pinned=mail_pinned)
    if email:
        addr = email
        otp_provider = "external"
        password = password or rand_password()
        given, family = rand_name()
        L(f"[2b] email={addr} via={otp_provider} name={given} {family}")
        created_email = xs.create_email_code(addr, castle1)
        L(
            f"    create_email headers grpc-status="
            f"{created_email.get('headers', {}).get('grpc-status')}"
        )
    else:
        # try providers until xAI accepts the domain
        last_err = None
        addr = None
        otp_provider = None
        max_mail_try = 1 if mail_pinned else 6
        for attempt in range(max_mail_try):
            try:
                if mail_pinned:
                    order = list(mail.prefer)
                else:
                    order = (
                        mail.prefer[attempt % len(mail.prefer) :]
                        + mail.prefer[: attempt % len(mail.prefer)]
                    )
                mail = EmailBox(prefer=order, pinned=mail_pinned)
                addr = mail.create_account()
                otp_provider = mail.provider_name or "temp"
                password = password or rand_password()
                given, family = rand_name()
                L(f"[2b] email={addr} via={otp_provider} name={given} {family}")
                if attempt > 0 and not pure_http:
                    castle1 = get_castle_token(CASTLE_PK, SIGNUP_URL, timeout_s=50, proxy=proxy)
                    L(f"    castle refresh len={len(castle1)}")
                created_email = xs.create_email_code(addr, castle1)
                L(
                    f"    create_email headers grpc-status="
                    f"{created_email.get('headers', {}).get('grpc-status')}"
                )
                break
            except Exception as e:
                last_err = e
                msg = str(e)
                L(f"    email attempt {attempt+1} fail: {msg[:180]}")
                if "email-domain-rejected" in msg or "email domain" in msg.lower() or "rejected" in msg.lower():
                    continue
                if attempt < 2:
                    continue
                raise
        else:
            raise RuntimeError(f"no accepted email domain: {last_err}")

    if otp_provider != "external":
        L("[3b] wait OTP…")
        # prefetch turnstile while OTP lands (biggest free parallel win)
        from concurrent.futures import ThreadPoolExecutor

        # warm free-local pool (runtime env from apply_local_mode)
        try:
            from turnstile_token import ensure_turnstile_pool as _ensure_ts

            _ensure_ts(SIGNUP_URL, TURNSTILE_SITEKEY, mode="free")
        except Exception:
            pass

        ts_holder: dict = {"tok": None, "err": None}
        castle2_holder: dict = {"tok": None, "err": None}

        def _prefetch_ts() -> None:
            try:
                ts_holder["tok"] = get_turnstile_token(
                    SIGNUP_URL, TURNSTILE_SITEKEY, timeout_s=90
                )
            except Exception as e:
                ts_holder["err"] = e

        def _prefetch_castle2() -> None:
            if pure_http:
                castle2_holder["tok"] = ""
                return
            try:
                castle2_holder["tok"] = get_castle_token(
                    CASTLE_PK, SIGNUP_URL, timeout_s=50, proxy=proxy
                )
            except Exception as e:
                castle2_holder["err"] = e

        with ThreadPoolExecutor(max_workers=3) as ex:
            f_otp = ex.submit(mail.wait_code, 120)
            f_ts = ex.submit(_prefetch_ts)
            f_c2 = ex.submit(_prefetch_castle2)
            code = f_otp.result()
            # OTP done — wait for prefetches fully (they ran in parallel)
            try:
                f_ts.result(timeout=90)
            except Exception as e:
                ts_holder["err"] = ts_holder.get("err") or e
            try:
                f_c2.result(timeout=50)
            except Exception as e:
                castle2_holder["err"] = castle2_holder.get("err") or e
    else:
        if worker is not None and worker != 1:
            raise RuntimeError("external OTP not supported in multi-worker mode")
        code = input("OTP code: ").strip()
        ts_holder = {"tok": None, "err": None}
        castle2_holder = {"tok": None, "err": None}
    L(f"    OTP={code}")
    check_cancel(worker)

    vres = xs.verify_email_code(addr, code)
    code = vres.get("code_used") or code
    L(f"    verified with code={code}")

    check_cancel(worker)
    L("[5b] Turnstile…")
    ts = ts_holder.get("tok")
    if not ts:
        ts = get_turnstile_token(SIGNUP_URL, TURNSTILE_SITEKEY, timeout_s=90)
    if not ts:
        raise RuntimeError(f"Turnstile solve failed err={ts_holder.get('err')}")
    L(f"    turnstile len={len(ts)} head={ts[:28]}…")

    if pure_http:
        castle2 = ""
    else:
        L("[5c] token #2…")
        castle2 = castle2_holder.get("tok")
        if not castle2:
            castle2 = get_castle_token(CASTLE_PK, SIGNUP_URL, timeout_s=50, proxy=proxy)
        L(f"    tok2 len={len(castle2)}")

    # ValidatePassword is optional UX check — skip for throughput
    if os.getenv("SKIP_VALIDATE_PASSWORD", "1") != "1":
        try:
            xs.validate_password(addr, password)
        except Exception as e:
            L(f"    ValidatePassword soft-fail: {e}")

    # emailnator gmail aliases are often already registered — retry with next provider
    created = None
    last_create_err: Exception | None = None
    # pinned provider: fewer tries, never leave the pin list
    if email:
        max_create_tries = 1
    elif mail_pinned:
        max_create_tries = 5
    else:
        max_create_tries = 10
    for ctry in range(max_create_tries):
        try:
            if ctry > 0:
                msg_prev = str(last_create_err or "").lower()
                prefer = list(mail.prefer or EmailBox.DEFAULT_PREFER)
                bad = otp_provider or ""
                if mail_pinned:
                    # stay on the same provider only
                    order = list(prefer)
                elif "existing email" in msg_prev:
                    # emailnator gmail norms are heavily burned — only 2 alias tries then unique domains
                    if ctry < 2:
                        order = ["emailnator"] + [p for p in prefer if p != "emailnator"]
                    else:
                        order = [p for p in prefer if p not in ("emailnator", "gmailnator")] + [
                            "emailnator"
                        ]
                elif any(
                    k in msg_prev
                    for k in (
                        "email-domain-rejected",
                        "domain has been rejected",
                        "disposable-email",
                        "provider not permitted",
                    )
                ):
                    order = [p for p in prefer if p != bad] + ([bad] if bad in prefer else [])
                else:
                    order = prefer[ctry % len(prefer) :] + prefer[: ctry % len(prefer)]
                    if bad:
                        order = [p for p in order if p != bad] + [bad]

                mail = EmailBox(prefer=order or None, pinned=mail_pinned)
                addr = mail.create_account()
                otp_provider = mail.provider_name or "temp"
                password = rand_password()
                given, family = rand_name()
                L(f"[2b-retry{ctry}] email={addr} via={otp_provider} name={given} {family}")
                if pure_http:
                    castle1 = ""
                else:
                    castle1 = get_castle_token(CASTLE_PK, SIGNUP_URL, timeout_s=50, proxy=proxy)
                xs.create_email_code(addr, castle1)
                L("[3b] wait OTP…")
                # parallel OTP + turnstile + castle2 again
                from concurrent.futures import ThreadPoolExecutor

                def _pf_ts():
                    return get_turnstile_token(SIGNUP_URL, TURNSTILE_SITEKEY, timeout_s=90)

                def _pf_c2():
                    if pure_http:
                        return ""
                    return get_castle_token(CASTLE_PK, SIGNUP_URL, timeout_s=50, proxy=proxy)

                with ThreadPoolExecutor(max_workers=3) as ex:
                    f_otp = ex.submit(mail.wait_code, 120)
                    f_ts = ex.submit(_pf_ts)
                    f_c2 = ex.submit(_pf_c2)
                    code = f_otp.result()
                    try:
                        ts = f_ts.result(timeout=5) or ts
                    except Exception:
                        ts = get_turnstile_token(SIGNUP_URL, TURNSTILE_SITEKEY, timeout_s=90)
                    try:
                        castle2 = f_c2.result(timeout=5)
                        if castle2 is None:
                            castle2 = ""
                    except Exception:
                        castle2 = "" if pure_http else get_castle_token(
                            CASTLE_PK, SIGNUP_URL, timeout_s=50, proxy=proxy
                        )
                L(f"    OTP={code}")
                vres = xs.verify_email_code(addr, code)
                code = vres.get("code_used") or code
                L(f"    verified with code={code}")
                if not ts:
                    raise RuntimeError("Turnstile solve failed")
                L(f"    turnstile len={len(ts)} head={ts[:28]}…")
            created = xs.create_user(addr, code, given, family, password, ts, castle2)
            last_create_err = None
            break
        except Exception as e:
            last_create_err = e
            msg = str(e)
            L(f"    createUser try {ctry+1}/{max_create_tries} fail: {msg[:180]}")
            # Action hash rotated mid-run → refresh then retry same email/OTP/ts
            if (
                "server action not found" in msg.lower()
                or "createuser http 404" in msg.lower()
            ):
                try:
                    refresh_create_user_action(xs, force=True, log_fn=L)
                except Exception as re:
                    L(f"    action refresh err: {re}")
                if ctry + 1 < max_create_tries:
                    continue
            retryable = any(
                k in msg.lower()
                for k in (
                    "existing email",
                    "email-domain-rejected",
                    "domain has been rejected",
                    "disposable-email",
                    "provider not permitted",
                    "email domain",
                    "server action not found",
                    "createuser http 404",
                )
            )
            if retryable and ctry + 1 < max_create_tries:
                continue
            raise
    if created is None:
        raise RuntimeError(f"createUser failed: {last_create_err}")
    L(
        f"    createUser sso={created.get('sso', {}).get('ok')} "
        f"cookies={created.get('cookies')}"
    )

    check_cancel(worker)
    L("[7] device code…")
    # consent can race / Session expired under high concurrency — 1 full retry
    dc = None
    consent: dict[str, Any] = {}
    for dtry in range(2):
        check_cancel(worker)
        dc = xs.request_device_code()
        L(f"    user_code={dc.get('user_code')} expires={dc.get('expires_in')} try={dtry+1}/2")
        consent = xs.try_device_consent(dc["user_code"])
        approve_body = str((consent.get("approve") or {}).get("body_head") or "")[:80]
        L(
            f"    consent approved={consent.get('approved')} "
            f"principal={consent.get('principal_id')} "
            f"approve_status={(consent.get('approve') or {}).get('status')} "
            f"err={consent.get('error')}"
        )
        if consent.get("approved"):
            break
        # fail-fast reasons that never become approved by waiting
        soft = approve_body.lower()
        ap_status = (consent.get("approve") or {}).get("status")
        if "session expired" in soft and "<!doctype" not in soft and "<html" not in soft:
            L(f"    consent session bad ({approve_body or 'no body'}) — retry device flow")
            time.sleep(0.4 + 0.3 * dtry)
            continue
        if ap_status in (401, 403):
            L(f"    consent HTTP {ap_status} — retry device flow")
            time.sleep(0.4 + 0.3 * dtry)
            continue
        if consent.get("error") and "principal" in str(consent.get("error")).lower():
            L(f"    consent error — retry device flow: {consent.get('error')}")
            time.sleep(0.4)
            continue
        # unknown not-approved: one more try then fail
        L(f"    consent not approved yet — retry once")
        time.sleep(0.3)

    tokens = None
    token_err = None
    if not consent.get("approved"):
        # NEVER long-poll an unapproved device_code — that was the 4.4/min wall killer
        ap = consent.get("approve") or {}
        token_err = (
            f"consent not approved status={ap.get('status')} "
            f"body={(ap.get('body_head') or consent.get('error') or '')[:80]}"
        )
        L(f"[8] token SKIP fail-fast: {token_err}")
    else:
        try:
            tokens = xs.poll_token(
                dc["device_code"],
                interval=int(dc.get("interval") or 2),
                timeout=45,  # approved → token should land fast
            )
            L("[8] token OK")
        except Exception as e:
            token_err = str(e)
            L(f"[8] token FAIL: {e}")

    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "email": addr,
        "password": password,
        "givenName": given,
        "familyName": family,
        "worker": worker,
        "mail_provider": otp_provider,
        "proxy": (proxy.split("@")[-1] if proxy else None),
        "createUser": {
            "status": created.get("status"),
            "location": created.get("location"),
            "body_head": (created.get("body") or "")[:300],
            "cookies": created.get("cookies"),
            "sso": {
                k: created.get("sso", {}).get(k)
                for k in ("ok", "final", "cookies", "urls", "attempts")
            },
        },
        "device": {
            "user_code": dc.get("user_code"),
            "device_code_len": len(dc.get("device_code") or ""),
            "consent": {
                k: consent.get(k)
                for k in (
                    "approved",
                    "principal_id",
                    "error",
                    "verify",
                    "approve",
                    "device_get",
                    "consent_get",
                )
            },
        },
        "tokens": None,
        "chat": None,
        "usable": None,
        "inject": [],
        "inject_policy": _normalize_inject_policy(inject_policy, skip_inject=skip_inject),
        "error": token_err,
    }
    if tokens:
        rec["tokens"] = {
            "access_token": tokens.get("access_token"),
            "refresh_token": tokens.get("refresh_token"),
            "id_token": tokens.get("id_token"),
            "token_type": tokens.get("token_type"),
            "access_token_len": len(tokens.get("access_token") or ""),
            "refresh_token_len": len(tokens.get("refresh_token") or ""),
            "expires_in": tokens.get("expires_in"),
            "scope": tokens.get("scope"),
            "has_id_token": bool(tokens.get("id_token")),
        }
        principal = consent.get("principal_id")
        chat_meta, inject_rows = gated_inject(
            tokens=tokens,
            email=addr,
            user_id=principal,
            display_name=f"{given} {family}".strip(),
            db_path=db_path,
            inject_providers=inject_providers,
            skip_inject=skip_inject,
            inject_policy=inject_policy,
            log_fn=L,
            tag="9",
        )
        rec["chat"] = chat_meta
        rec["usable"] = bool(chat_meta.get("usable"))
        rec["inject"] = inject_rows
        if not chat_meta.get("usable"):
            pol = rec["inject_policy"]
            if pol == "usable":
                rec["error"] = rec.get("error") or f"chat_gate:{chat_meta.get('reason')}"

    save_account(rec)
    return rec



def _rec_ok(rec: dict, inject_policy: str | None = None, skip_inject: bool = False) -> bool:
    """Success criteria by inject policy.

    - token (default): real access token only (no chat gate)
    - usable: token + chat usable
    - off / skip_inject: real access token only

    Accepts either live token dict (access_token) or redacted save shape
    (access_token_len > 0). Empty/zero-length tokens count as FAIL.
    """
    tok = rec.get("tokens") or {}
    if not isinstance(tok, dict) or not tok:
        return False
    # live shape
    at = tok.get("access_token") or tok.get("accessToken") or ""
    if isinstance(at, str) and len(at) > 20:
        has_token = True
    else:
        # redacted save shape from accounts.jsonl
        try:
            has_token = int(tok.get("access_token_len") or 0) > 20
        except (TypeError, ValueError):
            has_token = False
    if not has_token:
        return False
    pol = _normalize_inject_policy(
        inject_policy or rec.get("inject_policy"),
        skip_inject=skip_inject,
    )
    if pol == "usable":
        return bool(rec.get("usable"))
    # token / off
    return True


def _worker_job(idx: int, total: int, args_ns: argparse.Namespace, providers: list[str]) -> dict:
    try:
        check_cancel(idx)
        # stagger is applied once in the submit queue — do NOT sleep again here
        # (double-stagger made Maximum's larger first-wave start later than Fast)
        mode = (getattr(args_ns, "auth_mode", None) or "email").lower()
        pol = getattr(args_ns, "inject_policy", None)
        if mode == "google":
            rec = login_one_google(
                db_path=args_ns.db,
                inject_providers=providers,
                skip_inject=args_ns.skip_inject,
                email=None,
                password=None,
                worker=idx,
                inject_policy=pol,
            )
        else:
            mail_pref = getattr(args_ns, "mail_provider", None)
            rec = register_one(
                db_path=args_ns.db,
                inject_providers=providers,
                skip_inject=args_ns.skip_inject,
                email=None,
                password=args_ns.password,
                worker=idx,
                mail_prefer=[mail_pref] if mail_pref else None,
                mail_pinned=bool(mail_pref),
                inject_policy=pol,
            )
        rec["_ok"] = _rec_ok(rec, inject_policy=pol, skip_inject=args_ns.skip_inject)
        return rec
    except Cancelled as e:
        log(f"CANCELLED: {e}", worker=idx)
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "worker": idx,
            "error": str(e),
            "_ok": False,
            "_cancelled": True,
        }
        save_account(rec)
        return rec
    except Exception as e:
        log(f"FAIL hard: {e}", worker=idx)
        maybe_rotate_proxy(e, worker=idx)
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "worker": idx,
            "error": str(e),
            "_ok": False,
        }
        save_account(rec)
        return rec



def _args_to_dict(args: argparse.Namespace) -> dict:
    return {
        "count": args.count,
        "workers": args.workers,
        "stagger": args.stagger,
        "delay": args.delay,
        "db": args.db,
        "provider": args.provider,
        "skip_inject": bool(args.skip_inject),
        "inject_policy": getattr(args, "inject_policy", "token"),
        "proxy_file": args.proxy_file,
        "proxy_every": args.proxy_every,
        "proxy_mode": getattr(args, "proxy_mode", "limit"),
        "proxy": args.proxy,
        "password": args.password,
        "auth_mode": getattr(args, "auth_mode", "email"),
        "account_file": getattr(args, "account_file", None),
        "mail_provider": getattr(args, "mail_provider", None),
        "speed": getattr(args, "speed", None) or "normal",
        "solver": "local",
    }


def _setup_proxy(args: argparse.Namespace) -> None:
    mode = (getattr(args, "proxy_mode", None) or "limit").lower()
    if args.proxy_file:
        pool = ProxyPool.from_file(
            args.proxy_file,
            mode=mode,
            every=args.proxy_every,
        )
        set_global_pool(pool)
        if mode == "every":
            log(
                f"proxy pool: {len(pool)} proxies, mode=every/{args.proxy_every}"
            )
        else:
            log(
                f"proxy pool: {len(pool)} proxies, mode=limit "
                f"(sticky until 429/block/CF)"
            )
        log(f"    first={pool.current_masked()}")
    elif args.proxy:
        pool = ProxyPool([args.proxy], mode="limit", every=10**9)
        set_global_pool(pool)
        log(f"proxy fixed: {pool.current_masked()}")
    else:
        set_global_pool(None)


def _run_queue(args: argparse.Namespace, providers: list[str], total: int) -> tuple[int, int]:
    """Dispatch up to `total` accounts with worker pool; honor stop/cancel.

    Unlike fire-all-futures, we only keep `workers` in flight and pull next
    slot only when under limit and stop flag is clear. Resume uses remaining.
    """
    workers = max(1, min(12, int(args.workers or 8), total))
    ok = 0
    fail = 0
    next_idx = 1
    in_flight: dict = {}

    # stop on SIGTERM → cancel
    def _on_sigterm(signum, frame):
        log(f"signal {signum} → cancel")
        run_ctl.save_control("cancel", f"signal {signum}")

    try:
        import signal as _signal

        _signal.signal(_signal.SIGTERM, _on_sigterm)
        _signal.signal(_signal.SIGINT, _on_sigterm)
    except Exception:
        pass

    with ThreadPoolExecutor(max_workers=workers) as pool:
        def _submit(slot: int):
            return pool.submit(_worker_job, slot, total, args, providers)

        # prime
        while next_idx <= total and len(in_flight) < workers:
            if should_stop():
                break
            fut = _submit(next_idx)
            in_flight[fut] = next_idx
            next_idx += 1
            if args.stagger > 0 and next_idx <= total and len(in_flight) < workers:
                time.sleep(min(args.stagger, 45.0))

        while in_flight:
            # wait any
            done = None
            for fut in list(in_flight.keys()):
                if fut.done():
                    done = fut
                    break
            if done is None:
                if should_stop() and not any(not f.done() for f in in_flight):
                    break
                time.sleep(0.25)
                # still allow filling if not stopping
                while (
                    not should_stop()
                    and next_idx <= total
                    and len(in_flight) < workers
                ):
                    fut = _submit(next_idx)
                    in_flight[fut] = next_idx
                    next_idx += 1
                    if args.stagger > 0:
                        time.sleep(min(args.stagger, 45.0))
                continue

            slot = in_flight.pop(done)
            try:
                rec = done.result()
            except Cancelled as e:
                fail += 1
                bump(fail=True, error=str(e))
                log(f"CANCELLED slot={slot}: {e}", worker=slot)
                continue
            except Exception as e:
                fail += 1
                bump(fail=True, error=str(e))
                log(f"FAIL hard slot={slot}: {e}", worker=slot)
                continue

            if rec.get("_ok"):
                ok += 1
                bump(ok=True)
            else:
                fail += 1
                err = str(rec.get("error") or "soft fail")
                bump(fail=True, error=err)
                maybe_rotate_proxy(err, worker=slot)
                log(f"FAIL soft slot={slot}: {rec.get('error')}", worker=slot)

            done_n = ok + fail
            print_status_box(ok, fail, total, in_flight=len(in_flight))

            # fill next if allowed
            if not should_stop() and next_idx <= total and len(in_flight) < workers:
                if args.delay > 0:
                    time.sleep(args.delay)
                fut = _submit(next_idx)
                in_flight[fut] = next_idx
                next_idx += 1

            if should_cancel():
                # don't wait for the rest — they will check_cancel
                log("cancel active — draining in-flight only")
                break

        # drain remaining in-flight after cancel/stop
        for fut, slot in list(in_flight.items()):
            try:
                rec = fut.result(timeout=1)
                if rec and rec.get("_ok"):
                    ok += 1
                    bump(ok=True)
                else:
                    fail += 1
                    bump(fail=True, error=str((rec or {}).get("error") or "drain"))
                print_status_box(ok, fail, total, in_flight=0)
            except Exception:
                # still running — leave it; process exit will kill
                pass

    return ok, fail


def main() -> None:
    # control subcommands: status / stop / cancel / resume / restart / demo
    if len(sys.argv) > 1 and sys.argv[1].lower() in {
        "status", "stop", "cancel", "kill", "resume", "restart", "log", "help"
    }:
        raise SystemExit(run_ctl.main(sys.argv[1:]))
    if len(sys.argv) > 1 and sys.argv[1].lower() in {"demo", "selftest", "self-test"}:
        from demo_test import run_demo

        raise SystemExit(run_demo())

    ap = argparse.ArgumentParser(description="xAI mass regist + 9router inject")
    ap.add_argument("-n", "--count", type=int, default=1)
    ap.add_argument(
        "-w",
        "--workers",
        type=int,
        default=3,  # Normal default
        choices=range(1, 13),
        metavar="N",
        help="parallel workers 1–12 (default 3 = Normal speed)",
    )
    ap.add_argument("--stagger", type=float, default=0.3, help="seconds between worker starts")
    ap.add_argument("--db", default=os.getenv("NINEROUTER_DB", DEFAULT_DB))
    ap.add_argument("--provider", default="grok-cli", help="comma list: grok-cli,xai")
    ap.add_argument("--skip-inject", action="store_true", help="alias for --inject-policy off")
    ap.add_argument(
        "--inject-policy",
        choices=("token", "usable", "off"),
        default="token",
        help="token=inject on token OK, no chat probe (default); usable=chat-gate; off=no inject",
    )
    ap.add_argument(
        "--mail-provider",
        default=None,
        help="pin one tempmail provider (no fallback): ncaori,zoromail,tempmail.lol,temp-mail.io,emailnator,smailpro,guerrilla,mail.tm,tempmail.plus,maildrop",
    )
    ap.add_argument("--email", default=None, help="fixed email (OTP stdin / google pair with --password)")
    ap.add_argument("--password", default=None)
    ap.add_argument(
        "--auth-mode",
        choices=("email", "google"),
        default="email",
        help="email=tempmail regist (default); google=GSuite Google SSO (no email regist)",
    )
    ap.add_argument(
        "--account-file",
        default=None,
        help="email|password list for --auth-mode google (e.g. gsuite_accounts.txt)",
    )
    ap.add_argument("--delay", type=float, default=0.3)
    ap.add_argument(
        "--proxy-file",
        default=None,
        help="proxy list file (sticky IP; rotate only on limit)",
    )
    ap.add_argument(
        "--proxy-mode",
        choices=("limit", "every"),
        default="limit",
        help="limit=sticky until 429/block (default); every=legacy rotate each N accounts",
    )
    ap.add_argument(
        "--proxy-every",
        type=int,
        default=50,
        help="only used with --proxy-mode every (default 50)",
    )
    ap.add_argument("--proxy", default=None, help="single proxy URL for all accounts")
    ap.add_argument("--dry-run-device", action="store_true")
    ap.add_argument(
        "--demo",
        action="store_true",
        help="offline self-test (banner/proxy/control/workers; no live signup)",
    )
    ap.add_argument(
        "--speed",
        choices=("slow", "normal", "fast", "maximum"),
        default=None,
        help="run speed: slow|normal|fast|maximum (ALL local free turnstile). "
        "Sets workers/pool/stagger/delay. Default normal if omitted.",
    )
    ap.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="interactive menu: pick Speed (Slow/Normal/Fast/Maximum) each run",
    )
    ap.add_argument(
        "--no-pure-http",
        action="store_true",
        help="disable PURE_HTTP (use CF browser + Castle). Default is pure HTTP local free.",
    )
    ap.add_argument("--resume-run", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--fresh-run", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    if args.demo:
        from demo_test import run_demo

        raise SystemExit(run_demo())

    if args.dry_run_device:
        xs = XaiSession()
        print(json.dumps(xs.request_device_code(), indent=2))
        return

    bare_cli = len(sys.argv) == 1
    interactive = bool(args.interactive or bare_cli)

    if interactive:
        print_banner()
        while True:
            args = interactive_config(args)
            try:
                _execute_run(args)
            except SystemExit:
                raise
            except KeyboardInterrupt:
                print("\ninterrupted.")
            except Exception as e:
                set_quiet_run(False)
                log(f"run error: {e}")
            if post_run_menu() == "exit":
                print("bye.")
                return
            # loop → ask speed/n/proxy again
    else:
        # Non-interactive: always LOCAL free + pure HTTP (unless --no-pure-http)
        speed = args.speed or os.getenv("XAI_SPEED") or "normal"
        if args.no_pure_http:
            os.environ["XAI_SOLVER"] = "local"
            os.environ["TURNSTILE_FREE_ONLY"] = "1"
            os.environ.pop("TURNSTILE_FORCE_CAPSOLVER", None)
            os.environ.pop("TURNSTILE_CAPSOLVER_DIRECT", None)
            args.speed = normalize_speed(speed)
            prof = SPEED_PROFILES[args.speed]
            if args.speed is not None or os.getenv("XAI_SPEED"):
                args.workers = int(prof["workers"])
                args.stagger = float(prof["stagger"])
                args.delay = float(prof["delay"])
                os.environ["TURNSTILE_POOL_SIZE"] = str(prof["pool"])
                os.environ["TURNSTILE_MAX_CONCURRENT"] = str(prof["concurrent"])
                os.environ["DEVICE_CODE_MIN_GAP"] = str(prof["device_gap"])
                os.environ["OTP_POLL_S"] = str(prof["otp_poll"])
                # keep device_code globals in sync (same bug as apply_local_mode)
                global _DEVICE_CODE_MIN_GAP, _device_code_gap
                _DEVICE_CODE_MIN_GAP = float(prof["device_gap"])
                _device_code_gap = _DEVICE_CODE_MIN_GAP
            log(f"speed={SPEED_PROFILES[args.speed]['label']} solver=local (no pure-http)")
        else:
            user_set_w = any(a in ("-w", "--workers") for a in sys.argv)
            user_set_speed = args.speed is not None or bool(os.getenv("XAI_SPEED"))
            snap = apply_local_mode(
                speed=speed if (user_set_speed or not user_set_w) else "normal",
                force_timing=True,
            )
            args.speed = snap["speed"]
            args.solver = "local"
            if user_set_speed or not user_set_w:
                args.workers = int(snap["workers"])
                args.stagger = float(snap["stagger"])
                args.delay = float(snap["delay"])
            log(
                f"speed={snap['label']} solver=local pure_http=1 "
                f"w={args.workers} pool={snap['pool']} est={snap['est']}"
            )
        print_banner()
        _execute_run(args)


def _ensure_playwright() -> None:
    """Install playwright package + chromium browser for google SSO mode."""
    import importlib.util
    import subprocess

    if importlib.util.find_spec("playwright") is None:
        print("⚙️  Installing playwright (google SSO browser)...")
        for extra in ([], ["--break-system-packages"]):
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", "playwright", "-q"] + extra,
                capture_output=True, timeout=300,
            )
            if r.returncode == 0:
                break
        else:
            print("  ⚠️  playwright install failed — google mode may not work")
    # browser binary (idempotent — playwright skips if already installed)
    print("⚙️  Ensuring chromium browser for playwright...")
    r = subprocess.run(
        [sys.executable, "-m", "playwright", "install", "chromium"],
        capture_output=True, timeout=600,
    )
    if r.returncode != 0:
        print("  ⚠️  chromium install failed (need root?):", r.stderr.decode()[-300:])


def _ensure_local_solver() -> None:
    """Auto-check and launch local captcha solver if not running."""
    import urllib.request
    import subprocess
    solver_url = os.getenv("SOLVER_URL", "http://127.0.0.1:8877")
    try:
        with urllib.request.urlopen(f"{solver_url}/health", timeout=1.5) as r:
            if r.status == 200:
                return
    except Exception:
        pass

    solver_script = Path(__file__).parent / "local-solver" / "universal_solver.py"
    if not solver_script.exists():
        return

    print("⚙️  Starting local Turnstile/CF solver on :8877 in background...", flush=True)
    try:
        # Determine python executable (prefer current virtualenv or solver venv)
        solver_venv_py = Path(__file__).parent / "local-solver" / "venv" / "bin" / "python"
        if not solver_venv_py.exists():
            solver_venv_py = Path(__file__).parent / "local-solver" / "venv" / "Scripts" / "python.exe"
        py_exe = str(solver_venv_py) if solver_venv_py.exists() else sys.executable

        run_dir = Path(__file__).parent / "run"
        run_dir.mkdir(parents=True, exist_ok=True)
        log_file = open(run_dir / "solver.log", "a", encoding="utf-8")

        env = os.environ.copy()
        env["SOLVER_HEADLESS"] = "1"
        env["PORT"] = "8877"
        env["HOST"] = "127.0.0.1"

        proc = subprocess.Popen(
            [py_exe, str(solver_script)],
            stdout=log_file,
            stderr=log_file,
            env=env,
            start_new_session=True if os.name != "nt" else False,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        )
        # Wait up to 6s for solver startup
        for _ in range(12):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(f"{solver_url}/health", timeout=1) as r:
                    if r.status == 200:
                        print("  [+] Local solver is active and ready on :8877!", flush=True)
                        return
            except Exception:
                pass
    except Exception as e:
        print(f"  ⚠️  Could not auto-start solver: {e}", flush=True)


def _execute_run(args: argparse.Namespace) -> None:
    """One full farm run (shared by interactive loop + CLI)."""
    _ensure_local_solver()
    mode = (args.auth_mode or "email").lower()
    if mode == "google":
        _ensure_playwright()
        global _ACCOUNT_QUEUE
        if args.email and args.password:
            _ACCOUNT_QUEUE = [(args.email, args.password)]
        elif args.account_file:
            _ACCOUNT_QUEUE = load_account_file(args.account_file)
            if not _ACCOUNT_QUEUE:
                log(f"ERROR: no accounts in {args.account_file}")
                sys.exit(2)
            if not args.resume_run and args.count == 1 and len(_ACCOUNT_QUEUE) > 1:
                args.count = len(_ACCOUNT_QUEUE)
                log(f"google mode: auto count={args.count} from account-file")
        else:
            # No --account-file / --email given → interactive account entry
            log("google mode: no account file — interactive account input")
            print("\n  No account file given.", flush=True)
            _ACCOUNT_QUEUE = prompt_accounts_interactive()
            if not _ACCOUNT_QUEUE:
                log("ERROR: no accounts entered")
                print("  ERROR: no accounts entered. Aborting.", flush=True)
                sys.exit(2)
            if not args.resume_run and args.count == 1 and len(_ACCOUNT_QUEUE) > 1:
                args.count = len(_ACCOUNT_QUEUE)
                log(f"google mode: auto count={args.count} from interactive input")
        if args.email and (args.count > 1 or args.workers > 1) and not args.account_file:
            log("ERROR: single --email only works with -n 1 -w 1 (or use --account-file)")
            sys.exit(2)
    else:
        if args.email and (args.count > 1 or args.workers > 1):
            log("ERROR: --email only works with -n 1 -w 1")
            sys.exit(2)

    providers = [p.strip() for p in args.provider.split(",") if p.strip()]
    _setup_proxy(args)

    if args.resume_run:
        st = resume_state(_args_to_dict(args))
        target = int(st.get("target") or args.count)
        total = int(args.count)
        log(f"RESUME target={target} remaining={total} prior_ok={st.get('ok')}")
    else:
        target = int(args.count)
        total = target
        init_run(_args_to_dict(args), target=target)
        log(f"START target={target} auth_mode={mode}")

    workers = max(1, min(12, int(args.workers or 3), max(1, total)))
    args.workers = workers
    print_run_plan(args, total=total, workers=workers, providers=providers)
    set_quiet_run(True)
    print_status_box(0, 0, total, in_flight=0)  # initial empty box
    log(f"run n={total} workers={workers} auth_mode={mode} providers={providers}")
    log("control: python3 mass_regist.py status|stop|cancel|resume|restart")

    if total <= 0:
        finish("done")
        log("nothing to do")
        return

    ok = 0
    fail = 0
    if workers == 1:
        for i in range(total):
            if should_stop():
                log("stop flag — no new accounts")
                break
            log(f"\n===== account {i+1}/{total} =====")
            try:
                check_cancel(i + 1)
                pol = getattr(args, "inject_policy", "token")
                if mode == "google":
                    if args.email and args.password and i == 0 and not args.account_file:
                        rec = login_one_google(
                            db_path=args.db,
                            inject_providers=providers,
                            skip_inject=args.skip_inject,
                            email=args.email,
                            password=args.password,
                            worker=i + 1,
                            inject_policy=pol,
                        )
                    else:
                        rec = login_one_google(
                            db_path=args.db,
                            inject_providers=providers,
                            skip_inject=args.skip_inject,
                            worker=i + 1,
                            inject_policy=pol,
                        )
                else:
                    rec = register_one(
                        db_path=args.db,
                        inject_providers=providers,
                        skip_inject=args.skip_inject,
                        email=args.email if i == 0 else None,
                        password=args.password,
                        worker=i + 1,
                        mail_prefer=[args.mail_provider] if args.mail_provider else None,
                        mail_pinned=bool(args.mail_provider),
                        inject_policy=pol,
                    )
                if _rec_ok(rec, inject_policy=pol, skip_inject=args.skip_inject):
                    ok += 1
                    bump(ok=True)
                    if rec.get("usable") and rec.get("inject"):
                        log(
                            f"USABLE+INJECT email={rec.get('email')} "
                            f"chat={((rec.get('chat') or {}).get('reason'))}",
                            worker=i + 1,
                        )
                    elif rec.get("inject") and not rec.get("usable"):
                        log(
                            f"TOKEN+INJECT (chat not usable) email={rec.get('email')} "
                            f"chat={((rec.get('chat') or {}).get('reason'))}",
                            worker=i + 1,
                        )
                    elif rec.get("usable"):
                        log(
                            f"USABLE (no inject) email={rec.get('email')} "
                            f"chat={((rec.get('chat') or {}).get('reason'))}",
                            worker=i + 1,
                        )
                    else:
                        log(
                            f"TOKEN ok email={rec.get('email')} policy={pol}",
                            worker=i + 1,
                        )
                else:
                    fail += 1
                    err = str(rec.get("error") or "soft")
                    bump(fail=True, error=err)
                    maybe_rotate_proxy(err, worker=i + 1)
                    log(f"FAIL soft: {rec.get('error')}", worker=i + 1)
            except Cancelled as e:
                fail += 1
                bump(fail=True, error=str(e))
                log(f"CANCELLED: {e}", worker=i + 1)
                break
            except Exception as e:
                fail += 1
                bump(fail=True, error=str(e))
                maybe_rotate_proxy(e, worker=i + 1)
                log(f"FAIL hard: {e}", worker=i + 1)
                save_account(
                    {
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "error": str(e),
                        "auth_mode": mode,
                    }
                )
            print_status_box(ok, fail, total, in_flight=0)
            if i + 1 < total:
                end = time.time() + args.delay
                while time.time() < end:
                    if should_stop():
                        break
                    time.sleep(min(0.5, end - time.time()))
    else:
        ok, fail = _run_queue(args, providers, total)

    st = load_state() or {}
    attempted = int(st.get("attempted") or 0) or (ok + fail)
    target = int(st.get("target") or args.count or 0)
    # remaining is target-ok (fails don't count as done toward target) —
    # but if we already attempted all slots, treat as finished run.
    if should_cancel():
        finish("cancelled")
    elif should_stop() and attempted < max(1, target):
        finish("stopped")
    elif attempted < max(1, target) and int(st.get("remaining") or 0) > 0:
        finish("stopped")
    else:
        finish("done")

    pol = _normalize_inject_policy(
        getattr(args, "inject_policy", None),
        skip_inject=bool(args.skip_inject),
    )
    ok_meaning = {
        "token": "token OK + inject (no chat gate)",
        "usable": "token + chat usable (+ inject if enabled)",
        "off": "token OK (inject off)",
    }.get(pol, pol)
    st = load_state() or {}
    rate_line = _run_rate_line(ok, fail, st)
    speed = normalize_speed(getattr(args, "speed", None) or "normal")
    est = SPEED_PROFILES[speed]["est"]
    # final rate from wall line if possible
    final_rate = None
    try:
        # parse "→ X.X akun/menit" from rate_line
        import re as _re
        m = _re.search(r"→\s*([0-9.]+)\s*akun", rate_line)
        if m:
            final_rate = float(m.group(1))
    except Exception:
        final_rate = None
    set_quiet_run(False)
    print_status_box(
        ok, fail, max(target, ok + fail, 1),
        in_flight=0, title="x-farm", final=True, rate_override=final_rate,
    )
    log(f"speed={SPEED_PROFILES[speed]['label']}  est={est}  {rate_line}")
    log(f"policy={pol}: {ok_meaning}")
    try:
        log(status_text())
    except Exception as e:
        log(f"status: {e}")
    for p in providers:
        try:
            n = count_provider(args.db, p)
            log(f"active {p}: {n}")
        except Exception as e:
            log(f"count {p}: {e}")
    log("===== end =====")
    sys.stdout.flush()
    sys.stderr.flush()


if __name__ == "__main__":
    main()
