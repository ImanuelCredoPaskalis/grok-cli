#!/usr/bin/env python3
"""Castle request token wrapper.

Order:
  1) Warm pool  (CASTLE_POOL_URL, ~200ms/token after boot)  — preferred
  2) One-shot Camoufox harvest subprocess (fallback)

Env:
  CASTLE_MAX_CONCURRENT   cap for one-shot harvest (default 5, max 8)
  CASTLE_POOL_URL         default http://127.0.0.1:8878
  CASTLE_POOL_DISABLE=1   skip pool, force harvest
  CAMOUFOX_PYTHON         solver venv python for harvest
"""
from __future__ import annotations

import json
import os
import subprocess
import threading
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
DEFAULT_URL = "https://accounts.x.ai/sign-up?redirect=grok-com&return_to=%2F"
def _default_camoufox_python() -> str:
    """Prefer local-solver venv, then CAMOUFOX_PYTHON, then current python."""
    here = Path(__file__).resolve().parent
    for cand in (
        here / "local-solver" / "venv" / "bin" / "python",
        here / ".venv" / "bin" / "python",
        here / "venv" / "bin" / "python",
    ):
        if cand.is_file():
            return str(cand)
    return os.getenv("CAMOUFOX_PYTHON") or os.sys.executable


SOLVER_VENV_PY = os.getenv("CAMOUFOX_PYTHON") or _default_camoufox_python()
HARVEST_SCRIPT = Path(__file__).resolve().parent / "castle_harvest.py"
POOL_URL = os.getenv("CASTLE_POOL_URL", "http://127.0.0.1:8878").rstrip("/")
POOL_DISABLE = os.getenv("CASTLE_POOL_DISABLE", "").strip() in ("1", "true", "yes")

# Cap concurrent Camoufox harvests. Each account needs ~2 tokens (pre+post turnstile).
# Default 8 matches castle pool. Override via CASTLE_MAX_CONCURRENT (hard ceiling 12).
_MAX_CASTLE = max(1, min(12, int(os.getenv("CASTLE_MAX_CONCURRENT", "8"))))
_castle_sem = threading.Semaphore(_MAX_CASTLE)

# track which path last succeeded (for banners)
_last_via_lock = threading.Lock()
_last_via = "unknown"


def castle_max_concurrent() -> int:
    """Current Castle harvest concurrency cap (for status/plan banners)."""
    return _MAX_CASTLE


def castle_last_via() -> str:
    with _last_via_lock:
        return _last_via


def _set_via(via: str) -> None:
    global _last_via
    with _last_via_lock:
        _last_via = via


def pool_status(timeout_s: float = 2.0) -> dict:
    try:
        with urllib.request.urlopen(f"{POOL_URL}/status", timeout=timeout_s) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _get_from_pool(timeout_s: int = 20) -> str | None:
    if POOL_DISABLE:
        return None
    data = json.dumps({"timeout_s": timeout_s}).encode()
    req = urllib.request.Request(
        f"{POOL_URL}/token",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s + 5) as resp:
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            return None
    except Exception:
        return None
    if body.get("ok") and body.get("token"):
        _set_via(f"pool:{body.get('ms', '?')}ms")
        return body["token"]
    return None


def _get_from_harvest(
    public_key: str,
    page_url: str,
    timeout_s: int,
    proxy: str | None,
) -> str:
    if not HARVEST_SCRIPT.exists():
        raise RuntimeError(f"missing harvest script: {HARVEST_SCRIPT}")
    cmd = [SOLVER_VENV_PY, str(HARVEST_SCRIPT), public_key, page_url, str(timeout_s)]
    if proxy:
        cmd.append(proxy)
    with _castle_sem:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 90,
            env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":0")},
        )
    stdout = (proc.stdout or "").strip().splitlines()
    if not stdout:
        raise RuntimeError(
            f"castle harvest empty stdout rc={proc.returncode} err={(proc.stderr or '')[:400]}"
        )
    data = None
    for line in reversed(stdout):
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                data = json.loads(line)
                break
            except Exception:
                continue
    if data is None:
        raise RuntimeError(
            f"castle harvest no json stdout={stdout[-3:]!r} err={(proc.stderr or '')[:300]}"
        )
    if not data.get("ok") or not data.get("token"):
        raise RuntimeError(f"castle harvest failed: {data}")
    _set_via("harvest")
    return data["token"]


def get_castle_token(
    public_key: str = DEFAULT_PK,
    page_url: str = DEFAULT_URL,
    timeout_s: int = 45,
    proxy: str | None = None,
) -> str:
    # 1) warm pool first (ignore proxy — pool owns its own browser/proxy)
    pool_timeout = min(25, max(8, timeout_s // 2))
    tok = _get_from_pool(timeout_s=pool_timeout)
    if tok:
        return tok
    # 2) one-shot harvest fallback
    return _get_from_harvest(public_key, page_url, timeout_s, proxy)


if __name__ == "__main__":
    import time

    st = pool_status()
    print("pool_status", json.dumps(st))
    t0 = time.time()
    tok = get_castle_token()
    print(f"via={castle_last_via()} token_len={len(tok)} head={tok[:40]}... t={time.time()-t0:.2f}s")
