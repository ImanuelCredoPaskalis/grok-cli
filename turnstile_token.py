#!/usr/bin/env python3
"""Turnstile token — FREE local first (:8877), Capsolver fallback, optional harvest.

Warm prefetch pool works for BOTH free-local and Capsolver-direct (PURE_HTTP).
Note: tokens are one-shot server-side on createUser — pool hides latency only,
cannot share 1 token across accounts.

CRITICAL: pool size / concurrency are read LIVE from env (not import-time),
because mass_regist.apply_local_mode() sets TURNSTILE_* after import.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import threading
import time
from pathlib import Path

from solver_client import solve

HARVEST = Path(__file__).resolve().parent / "turnstile_harvest.py"
def _default_camoufox_python() -> str:
    here = Path(__file__).resolve().parent
    for cand in (
        here / "local-solver" / "venv" / "bin" / "python",
        here / ".venv" / "bin" / "python",
        here / "venv" / "bin" / "python",
    ):
        if cand.is_file():
            return str(cand)
    return os.getenv("CAMOUFOX_PYTHON") or __import__("sys").executable


VENV_PY = os.getenv("CAMOUFOX_PYTHON") or _default_camoufox_python()

# runtime-configurable (import-time defaults only)
_sem_lock = threading.Lock()
_sem: threading.Semaphore | None = None
_sem_n = 0

_pool: queue.Queue | None = None
_pool_max = 0
_pool_lock = threading.Lock()
_pool_started = False
_pool_mode: str | None = None  # "free" | "capsolver"
_pool_stats = {"hits": 0, "miss": 0, "fresh": 0, "expired": 0, "mode": None}
_pool_workers: list[threading.Thread] = []


def _pool_size() -> int:
    try:
        return max(0, int(os.getenv("TURNSTILE_POOL_SIZE", "6")))
    except Exception:
        return 6


def _pool_ttl() -> float:
    try:
        return float(os.getenv("TURNSTILE_POOL_TTL", "240"))
    except Exception:
        return 240.0


def _max_concurrent() -> int:
    try:
        return max(1, int(os.getenv("TURNSTILE_MAX_CONCURRENT", "8")))
    except Exception:
        return 8


def _get_sem() -> threading.Semaphore:
    """Semaphore that resizes if TURNSTILE_MAX_CONCURRENT changes after import."""
    global _sem, _sem_n
    n = _max_concurrent()
    with _sem_lock:
        if _sem is None or _sem_n != n:
            _sem = threading.Semaphore(n)
            _sem_n = n
        return _sem


def _ensure_queue(size: int) -> queue.Queue:
    global _pool, _pool_max
    with _pool_lock:
        if _pool is None or _pool_max != max(1, size or 1):
            # rebuild queue if size changed (drop old tokens — safe, one-shot)
            _pool = queue.Queue(maxsize=max(1, size or 1))
            _pool_max = max(1, size or 1)
        return _pool


def configure_from_env() -> dict:
    """Re-read env into pool knobs. Call after apply_local_mode / --speed."""
    size = _pool_size()
    conc = _max_concurrent()
    _ensure_queue(size)
    _get_sem()  # resize semaphore
    return {
        "pool_size": size,
        "max_concurrent": conc,
        "ttl": _pool_ttl(),
        "started": _pool_started,
        "mode": _pool_mode,
    }


def harvest_turnstile(url: str, sitekey: str, timeout_s: int = 70) -> str | None:
    cmd = [VENV_PY, str(HARVEST), url, sitekey, str(timeout_s)]
    with _get_sem():
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 40,
            env={**os.environ, "HOME": os.environ.get("HOME") or str(Path.home())},
        )
    line = (p.stdout or "").strip().splitlines()
    raw = line[-1] if line else ""
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if data.get("ok") and data.get("token") and len(data["token"]) > 100:
        return data["token"]
    return None


def _solve_free(url: str, sitekey: str, timeout_s: int) -> str | None:
    with _get_sem():
        res = solve(
            "turnstile",
            url=url,
            sitekey=sitekey,
            timeout_s=timeout_s,
            force_capsolver=False,
            retries=3,
        )
    tok = res.get("token") if res.get("solved") else None
    if tok and len(tok) > 100:
        return tok
    return None


def _solve_capsolver(url: str, sitekey: str, timeout_s: int) -> str | None:
    with _get_sem():
        res = solve(
            "turnstile",
            url=url,
            sitekey=sitekey,
            timeout_s=timeout_s,
            force_capsolver=True,
            retries=2,
        )
    tok = res.get("token") if res.get("solved") else None
    if tok and len(tok) > 100:
        return tok
    return None


def _is_capsolver_direct() -> bool:
    """True only when we explicitly want Capsolver HTTP (paid).

    PURE_HTTP / NO_BROWSER only skip CF/Castle browsers in mass_regist —
    they do NOT force paid turnstile. Free local :8877 still works under pure HTTP.
    """
    if (os.getenv("XAI_SOLVER") or "").strip().lower() in ("capsolver", "paid", "cap"):
        return True
    return (
        os.getenv("TURNSTILE_FORCE_CAPSOLVER", "0") == "1"
        or os.getenv("TURNSTILE_CAPSOLVER_DIRECT", "0") == "1"
    )


def _pool_worker(url: str, sitekey: str, mode: str) -> None:
    """Background: keep tokens warm (free local or Capsolver)."""
    while True:
        try:
            size = _pool_size()
            if size <= 0:
                time.sleep(1.0)
                continue
            q = _ensure_queue(size)
            if q.full():
                time.sleep(0.3)
                continue
            if mode == "capsolver":
                tok = _solve_capsolver(url, sitekey, timeout_s=60)
            else:
                tok = _solve_free(url, sitekey, timeout_s=70)
            if tok:
                try:
                    q.put_nowait((tok, time.time()))
                    with _pool_lock:
                        _pool_stats["fresh"] += 1
                except queue.Full:
                    pass
            else:
                time.sleep(0.8)
        except Exception:
            time.sleep(1.2)


def ensure_turnstile_pool(url: str, sitekey: str, mode: str | None = None) -> None:
    """Start prefetch workers once (no-op if pool size 0)."""
    global _pool_started, _pool_mode
    size = _pool_size()
    if size <= 0:
        return
    if mode is None:
        mode = "capsolver" if _is_capsolver_direct() else "free"
    configure_from_env()
    with _pool_lock:
        if _pool_started:
            return
        _pool_started = True
        _pool_mode = mode
        _pool_stats["mode"] = mode
        # don't spawn more prefetchers than pool size; cap 6 to avoid thrash
        n = max(1, min(6, size))
        for _ in range(n):
            t = threading.Thread(
                target=_pool_worker,
                args=(url, sitekey, mode),
                name=f"ts-pool-{mode}",
                daemon=True,
            )
            t.start()
            _pool_workers.append(t)


def _take_pooled() -> str | None:
    size = _pool_size()
    if size <= 0:
        return None
    q = _ensure_queue(size)
    now = time.time()
    ttl = _pool_ttl()
    while True:
        try:
            tok, ts = q.get_nowait()
        except queue.Empty:
            return None
        if now - ts > ttl:
            with _pool_lock:
                _pool_stats["expired"] += 1
            continue
        with _pool_lock:
            _pool_stats["hits"] += 1
        return tok


def turnstile_pool_stats() -> dict:
    with _pool_lock:
        qsize = 0
        try:
            if _pool is not None:
                qsize = _pool.qsize()
        except Exception:
            pass
        return {
            **_pool_stats,
            "qsize": qsize,
            "pool_size": _pool_size(),
            "max_concurrent": _max_concurrent(),
            "started": _pool_started,
            "mode": _pool_mode,
        }


def get_turnstile_token(
    url: str,
    sitekey: str,
    timeout_s: int = 90,
    *,
    prefer_free: bool = True,
) -> str | None:
    """Prefer warm pool → free local solver → Capsolver → optional harvest.

    Env (read live every call):
      TURNSTILE_FORCE_CAPSOLVER / TURNSTILE_CAPSOLVER_DIRECT / XAI_SOLVER=capsolver
        → Capsolver direct (+ warm Capsolver pool)
      TURNSTILE_FREE_ONLY=1 / XAI_SOLVER=local
        → free local :8877 only
      TURNSTILE_HARVEST=1          → try Camoufox harvest after solver fails
      TURNSTILE_POOL_SIZE=N        → warm tokens (default 6)
      TURNSTILE_MAX_CONCURRENT=N   → parallel solves (default 8)
    """
    force_paid = os.getenv("TURNSTILE_FORCE_CAPSOLVER", "0") == "1"
    free_only = (
        os.getenv("TURNSTILE_FREE_ONLY", "0") == "1"
        or (os.getenv("XAI_SOLVER") or "").strip().lower() in ("local", "free")
    )
    allow_harvest = os.getenv("TURNSTILE_HARVEST", "0") == "1"
    cap_direct = _is_capsolver_direct()

    # Capsolver-direct path (paid HTTP, no browser) — warm pool hides latency
    if cap_direct or force_paid:
        ensure_turnstile_pool(url, sitekey, mode="capsolver")
        pooled = _take_pooled()
        if pooled:
            return pooled
        with _pool_lock:
            _pool_stats["miss"] += 1
        tok = _solve_capsolver(url, sitekey, timeout_s=timeout_s)
        if tok:
            return tok
        return None

    # Free local :8877 (Camoufox turnstile) + warm pool
    if prefer_free:
        ensure_turnstile_pool(url, sitekey, mode="free")
        pooled = _take_pooled()
        if pooled:
            return pooled
        with _pool_lock:
            _pool_stats["miss"] += 1
        tok = _solve_free(url, sitekey, timeout_s=timeout_s)
        if tok:
            return tok

    if free_only:
        if allow_harvest:
            h = harvest_turnstile(url, sitekey, timeout_s=min(70, timeout_s))
            if h:
                return h
        return None

    # Capsolver fallback when free fails
    tok = _solve_capsolver(url, sitekey, timeout_s=timeout_s)
    if tok:
        return tok

    if allow_harvest:
        h = harvest_turnstile(url, sitekey, timeout_s=min(70, timeout_s))
        if h:
            return h
    return None
