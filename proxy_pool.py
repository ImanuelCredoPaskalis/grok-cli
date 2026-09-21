#!/usr/bin/env python3
"""Sticky proxy pool — rotate only on limit / hard failure.

Modes:
  limit  (default) — sticky IP until rotate_on_limit() is called
  every  — legacy: switch after N account acquisitions (opt-in only)

Never print passwords in labels.
"""
from __future__ import annotations

import os
import re
import threading
from pathlib import Path
from urllib.parse import quote, urlparse


def normalize_proxy(raw: str) -> str | None:
    """Return curl/camoufox-friendly URL: scheme://[user:pass@]host:port.

    Supports HTTP + SOCKS5 (and socks4/socks5h if given with scheme).
    Formats:
      host:port
      user:pass@host:port
      host:port:user:pass
      http://user:pass@host:port
      socks5://user:pass@host:port
      socks5h://user:pass@host:port
    """
    s = (raw or "").strip()
    if not s or s.startswith("#"):
        return None
    # strip wrapping quotes
    if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
        s = s[1:-1].strip()
    if not s:
        return None

    # host:port:user:pass  (common residential format) — default http
    if "://" not in s and s.count(":") == 3 and "@" not in s:
        host, port, user, pwd = s.split(":", 3)
        if host and port.isdigit():
            return (
                f"http://{quote(user, safe='')}:{quote(pwd, safe='')}@{host}:{port}"
            )
    # user:pass@host:port — default http
    if "://" not in s and "@" in s:
        return f"http://{s}"
    # host:port — default http
    if "://" not in s:
        return f"http://{s}"

    # already has scheme — keep socks5 / socks5h / http / https as-is
    scheme = s.split("://", 1)[0].lower()
    if scheme in ("http", "https", "socks4", "socks4a", "socks5", "socks5h"):
        return s
    # unknown scheme — still return raw (caller may reject)
    return s


def camoufox_proxy_dict(proxy_url: str | None) -> dict | None:
    if not proxy_url:
        return None
    p = urlparse(proxy_url)
    if not p.hostname or not p.port:
        return None
    server = f"{p.scheme or 'http'}://{p.hostname}:{p.port}"
    d: dict = {"server": server}
    if p.username:
        d["username"] = p.username
    if p.password:
        d["password"] = p.password
    return d


def is_limit_error(err: object) -> bool:
    """Heuristic: rate-limit / IP block / CF challenge / soft ban.

    Intentionally IGNORES account-class / entitlement fails that are NOT proxy issues:
      chat_gate:*, usable=NO, free-usage-exhausted, permission-denied on chat.
    Rotating proxy on those just burns IPs for nothing.
    """
    if err is None:
        return False
    if isinstance(err, dict):
        parts = [str(err.get(k) or "") for k in ("error", "status", "msg", "message", "body")]
        text = " ".join(parts).lower()
        code = err.get("status") or err.get("status_code")
        if code in (403, 429, 503):
            # still check entitlement false-positives below
            pass
    else:
        text = str(err).lower()
        # bare status ints
        if isinstance(err, int) and err in (403, 429, 503):
            return True

    # account-class / chat entitlement — NOT a proxy limit
    if any(
        n in text
        for n in (
            "chat_gate",
            "chat gate",
            "usable=no",
            "usable=false",
            "free-usage-exhausted",
            "permission-denied",
            "subscription:free",
            "access to the chat endpoint is denied",
        )
    ):
        return False

    needles = (
        "429",
        "rate limit",
        "ratelimit",
        "too many requests",
        "slow_down",
        "attention required",
        "cf solve failed",
        "cloudflare",
        "access denied",
        "ip ban",
        "ip blocked",
        "blocked",
        "forbidden",
        "signup page blocked",
        "just a moment",
        "captcha",
        "temporarily unavailable",
        "try again later",
        "unusual traffic",
        "proxy error",
        "proxyconnect",
        "tunnel connection failed",
        "connection reset",
        "socks connect",
        "pool full",
    )
    return any(n in text for n in needles)


def mask_proxy(proxy_url: str | None) -> str | None:
    if not proxy_url:
        return None
    u = urlparse(proxy_url)
    host = u.hostname or "?"
    port = u.port or ""
    auth = "auth@" if u.username else ""
    return f"{u.scheme or 'http'}://{auth}{host}:{port}"


class ProxyPool:
    """Thread-safe sticky pool. Default mode=limit (no auto every-N)."""

    def __init__(
        self,
        proxies: list[str],
        *,
        mode: str = "limit",
        every: int = 50,
    ):
        self.proxies = [p for p in (normalize_proxy(x) for x in proxies) if p]
        self.mode = (mode or "limit").lower()
        if self.mode not in ("limit", "every"):
            self.mode = "limit"
        self.every = max(1, int(every))
        self._lock = threading.Lock()
        self._idx = 0
        self._uses = 0  # successful acquires on current (for mode=every)
        self._rotations = 0
        self._last_reason: str | None = None

    @classmethod
    def from_file(
        cls,
        path: str | Path,
        *,
        mode: str = "limit",
        every: int = 50,
    ) -> "ProxyPool":
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"proxy file not found: {p}")
        lines = p.read_text(errors="ignore").splitlines()
        return cls(lines, mode=mode, every=every)

    @classmethod
    def from_env_or_file(
        cls,
        path: str | Path | None = None,
        *,
        mode: str | None = None,
        every: int | None = None,
    ) -> "ProxyPool | None":
        every = int(every or os.getenv("PROXY_ROTATE_EVERY", "50"))
        mode = (mode or os.getenv("PROXY_MODE", "limit")).lower()
        path = path or os.getenv("PROXY_FILE")
        if not path:
            return None
        pool = cls.from_file(path, mode=mode, every=every)
        if not pool.proxies:
            return None
        return pool

    def __len__(self) -> int:
        return len(self.proxies)

    def current(self) -> str | None:
        if not self.proxies:
            return None
        with self._lock:
            return self.proxies[self._idx % len(self.proxies)]

    def current_masked(self) -> str | None:
        return mask_proxy(self.current())

    def acquire(self) -> str | None:
        """Sticky current proxy.

        mode=limit: never advances index here.
        mode=every: advances after `every` acquires (legacy opt-in).
        """
        if not self.proxies:
            return None
        with self._lock:
            if self.mode == "every" and self._uses >= self.every:
                self._idx = (self._idx + 1) % len(self.proxies)
                self._uses = 0
                self._rotations += 1
                self._last_reason = f"every={self.every}"
            proxy = self.proxies[self._idx % len(self.proxies)]
            self._uses += 1
            return proxy

    def force_rotate(self, reason: str = "manual") -> str | None:
        """Advance to next proxy immediately (limit / hard fail path)."""
        if not self.proxies:
            return None
        with self._lock:
            if len(self.proxies) == 1:
                self._uses = 0
                self._last_reason = f"limit:{reason} (only 1 proxy)"
                return self.proxies[0]
            old = self._idx
            self._idx = (self._idx + 1) % len(self.proxies)
            self._uses = 0
            self._rotations += 1
            self._last_reason = f"limit:{reason}"
            return self.proxies[self._idx]

    def rotate_on_limit(self, err: object = None, reason: str | None = None) -> str | None:
        """Rotate only if error looks like a limit/block. Returns new proxy or None."""
        if not is_limit_error(err) and not reason:
            return None
        why = reason or re.sub(r"\s+", " ", str(err)[:80])
        return self.force_rotate(why)

    def status(self) -> dict:
        with self._lock:
            return {
                "count": len(self.proxies),
                "index": self._idx % max(1, len(self.proxies)),
                "uses_on_current": self._uses,
                "mode": self.mode,
                "every": self.every if self.mode == "every" else None,
                "rotations": self._rotations,
                "last_reason": self._last_reason,
                "current": mask_proxy(
                    self.proxies[self._idx % len(self.proxies)] if self.proxies else None
                ),
            }


_GLOBAL: ProxyPool | None = None
_GLOBAL_LOCK = threading.Lock()


def set_global_pool(pool: ProxyPool | None) -> None:
    global _GLOBAL
    with _GLOBAL_LOCK:
        _GLOBAL = pool


def get_global_pool() -> ProxyPool | None:
    return _GLOBAL


def acquire_proxy() -> str | None:
    pool = _GLOBAL
    if not pool:
        return None
    return pool.acquire()


def rotate_proxy_on_limit(err: object = None, reason: str | None = None) -> str | None:
    """Global helper: sticky rotate only on limit signals."""
    pool = _GLOBAL
    if not pool:
        return None
    if reason:
        return pool.force_rotate(reason)
    return pool.rotate_on_limit(err)
