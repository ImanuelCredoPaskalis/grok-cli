#!/usr/bin/env python3
"""Local captcha solver client (:8877) + direct Capsolver HTTP (no browser)."""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

SOLVER_URL = os.getenv("SOLVER_URL", "http://127.0.0.1:8877")


def _load_capsolver_key() -> str:
    k = (os.getenv("CAPSOLVER_API_KEY") or "").strip()
    if k:
        return k
    for p in (
        os.getenv("SOLVER_ENV", ""),
        os.path.join(os.path.dirname(__file__), "local-solver", "solver.env"),
        os.path.join(os.path.dirname(__file__), "solver.env"),
        os.path.join(os.path.dirname(__file__), ".env"),
    ):
        if not p or not os.path.isfile(p):
            continue
        try:
            for line in open(p):
                line = line.strip()
                if line.startswith("CAPSOLVER_API_KEY="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
        except Exception:
            pass
    return ""


def _post(payload: dict, timeout: int = 120) -> dict:
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{SOLVER_URL}/solve",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return {"solved": False, "error": e.read().decode()[:200]}
        except Exception:
            return {"solved": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"solved": False, "error": str(e)}


def _cap_post(endpoint: str, data: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(
        f"https://api.capsolver.com/{endpoint}",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def capsolver_turnstile(url: str, sitekey: str, timeout_s: int = 90) -> dict:
    """Pure-HTTP Capsolver AntiTurnstileTaskProxyLess — no local browser."""
    key = _load_capsolver_key()
    if not key:
        return {"solved": False, "error": "no CAPSOLVER_API_KEY"}
    t0 = time.time()
    try:
        cr = _cap_post(
            "createTask",
            {
                "clientKey": key,
                "task": {
                    "type": "AntiTurnstileTaskProxyLess",
                    "websiteURL": url,
                    "websiteKey": sitekey,
                },
            },
        )
    except Exception as e:
        return {"solved": False, "error": f"capsolver create: {e}"}
    if cr.get("errorId"):
        return {"solved": False, "error": cr.get("errorDescription") or str(cr)}
    tid = cr.get("taskId")
    if not tid:
        return {"solved": False, "error": f"capsolver no taskId: {cr}"}
    deadline = t0 + timeout_s
    while time.time() < deadline:
        try:
            pr = _cap_post("getTaskResult", {"clientKey": key, "taskId": tid})
        except Exception:
            time.sleep(1.0)
            continue
        if pr.get("status") == "ready":
            sol = pr.get("solution") or {}
            tok = sol.get("token") or sol.get("gRecaptchaResponse") or ""
            if tok and len(tok) > 50:
                return {
                    "solved": True,
                    "token": tok,
                    "note": "capsolver_direct",
                    "ms": int((time.time() - t0) * 1000),
                }
            return {"solved": False, "error": "capsolver ready but empty token"}
        if pr.get("errorId") or pr.get("status") == "failed":
            return {
                "solved": False,
                "error": pr.get("errorDescription") or str(pr)[:200],
            }
        time.sleep(0.6)
    return {"solved": False, "error": "capsolver timeout"}


def solve(ctype: str, retries: int = 3, **kw) -> dict:
    pure = os.getenv("PURE_HTTP", "0") == "1" or os.getenv("NO_BROWSER", "0") == "1"
    force_paid = bool(kw.get("force_capsolver")) or os.getenv(
        "TURNSTILE_FORCE_CAPSOLVER", "0"
    ) == "1"
    # Capsolver direct ONLY when explicitly forced — not merely PURE_HTTP
    # (PURE_HTTP skips CF/Castle; free local turnstile still uses :8877)
    if ctype == "turnstile" and (
        force_paid or os.getenv("TURNSTILE_CAPSOLVER_DIRECT", "0") == "1"
    ):
        url = kw.get("url") or ""
        sitekey = kw.get("sitekey") or ""
        timeout_s = int(kw.get("timeout_s", 90))
        last = {"solved": False, "error": "no attempts"}
        for i in range(max(1, retries)):
            last = capsolver_turnstile(url, sitekey, timeout_s=timeout_s)
            if last.get("solved"):
                return last
            time.sleep(0.8 + i)
        return last

    payload = {"type": ctype}
    for k in (
        "url",
        "sitekey",
        "timeout_s",
        "action",
        "cdata",
        "proxy",
        "user_agent",
        "text",
        "image",
        "bg_image",
        "puzzle_image",
        "real_page",
        "force_capsolver",
    ):
        if k in kw and kw[k] is not None:
            payload[k] = kw[k]
    timeout = int(kw.get("timeout_s", 90)) + 30
    last = {"solved": False, "error": "no attempts"}
    attempts = max(1, retries)
    for i in range(attempts):
        last = _post(payload, timeout=timeout)
        if last.get("solved"):
            return last
        err = str(last.get("error") or last.get("value") or last.get("note") or "")
        if i + 1 < attempts:
            if "pool full" in err.lower() or "429" in err:
                time.sleep(2.5 + i * 2.0)
            else:
                time.sleep(1.5 + i * 1.5)
            continue
    return last


def solve_turnstile(url: str, sitekey: str | None = None, timeout: int = 90, **kw):
    res = solve(
        "turnstile",
        url=url,
        sitekey=sitekey,
        timeout_s=timeout,
        retries=kw.pop("retries", 3),
        **kw,
    )
    return res.get("token") if res.get("solved") else None


def solve_cloudflare(url: str, timeout: int = 90, **kw) -> dict:
    if (
        os.getenv("PURE_HTTP", "0") == "1"
        or os.getenv("NO_BROWSER", "0") == "1"
        or os.getenv("SKIP_CF", "0") == "1"
    ):
        return {
            "solved": True,
            "note": "cf_skipped_pure_http",
            "cookies": {},
            "ua": None,
        }
    return solve(
        "cloudflare",
        url=url,
        timeout_s=timeout,
        retries=kw.pop("retries", 12),
        **kw,
    )
