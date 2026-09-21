#!/usr/bin/env python3
"""Google SSO login for accounts.x.ai (GSuite / consumer Google).

Flow:
  1) CF clearance on accounts.x.ai/sign-in
  2) Castle request token
  3) POST /api/rpc getAuthUrl {provider: GOOGLE, castleRequestToken}
  4) Playwright: Google OAuth (email+password) → redirect /exchange-token/
  5) Capture SSO cookies (sso / sso-rw / …) for device-code consent

Never logs passwords or raw tokens.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from castle_token import get_castle_token
from solver_client import solve_cloudflare

SIGNIN_URL = "https://accounts.x.ai/sign-in?redirect=grok-com&return_to=%2F"
EXCHANGE_HOST = "accounts.x.ai"
# Public Castle key used by accounts.x.ai auth UI (sign-in / oauth buttons)
CASTLE_PK_SIGNIN = "pk_vYYwgshT91ne1xqtTw9bYp"
# Fallback: mass-regist signup key (still accepted by some endpoints)
CASTLE_PK_SIGNUP = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"

SSO_COOKIE_NAMES = ("sso", "sso-rw", "sso-session", "sso-refresh-token")

# Camoufox sync API is not thread-safe — serialize browser launches.
_CAMOUFOX_LOCK = threading.Lock()


def _log(msg: str, worker: int | None = None) -> None:
    tag = f"[W{worker}] " if worker is not None else ""
    print(f"{tag}{msg}", flush=True)


def _cookie_dict_from_cf(sol: dict) -> dict[str, str]:
    cookies: dict[str, str] = {}
    tok = sol.get("cf_clearance") or sol.get("token")
    if tok:
        cookies["cf_clearance"] = tok
    raw = sol.get("cookies")
    if isinstance(raw, str):
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k] = v
    elif isinstance(raw, dict):
        cookies.update({str(k): str(v) for k, v in raw.items()})
    return cookies


def get_google_auth_url(
    *,
    proxy: str | None = None,
    worker: int | None = None,
    castle_pk: str = CASTLE_PK_SIGNIN,
    user_agent: str | None = None,
) -> dict[str, Any]:
    """Return {authUrl, cookies, ua, castle_len, fp?} via CF + castle + /api/rpc.

    user_agent: override UA (from fingerprint_gen) so CF solve + browser match.
    """
    from curl_cffi import requests as creq

    sol = solve_cloudflare(SIGNIN_URL, timeout=90, proxy=proxy, user_agent=user_agent)
    if not sol.get("solved"):
        raise RuntimeError(f"CF solve failed: {sol}")
    ua = user_agent or sol.get("user_agent") or (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
    )
    cookies = _cookie_dict_from_cf(sol)
    s = creq.Session(impersonate="chrome131")
    s.cookies.update(cookies)
    kw: dict[str, Any] = {"timeout": 45}
    if proxy:
        kw["proxy"] = proxy
    r = s.get(SIGNIN_URL, headers={"User-Agent": ua, "Accept": "text/html"}, **kw)
    if r.status_code != 200:
        raise RuntimeError(f"sign-in page status={r.status_code}")

    castle = None
    last_err = None
    for pk in (castle_pk, CASTLE_PK_SIGNIN, CASTLE_PK_SIGNUP):
        try:
            castle = get_castle_token(pk, SIGNIN_URL, timeout_s=50, proxy=proxy)
            if castle:
                break
        except Exception as e:
            last_err = e
            continue
    if not castle:
        raise RuntimeError(f"castle failed: {last_err}")

    rr = s.post(
        "https://accounts.x.ai/api/rpc",
        json={"rpc": "getAuthUrl", "req": {"provider": "GOOGLE", "castleRequestToken": castle}},
        headers={
            "User-Agent": ua,
            "Origin": "https://accounts.x.ai",
            "Referer": SIGNIN_URL,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        **kw,
    )
    if rr.status_code >= 400:
        raise RuntimeError(f"getAuthUrl HTTP {rr.status_code}: {rr.text[:200]}")
    data = rr.json()
    auth_url = data.get("authUrl") or data.get("auth_url")
    if not auth_url:
        raise RuntimeError(f"getAuthUrl missing authUrl: {str(data)[:200]}")
    # merge session cookies after rpc
    out_cookies = {k: v for k, v in s.cookies.items()}
    _log(f"    getAuthUrl ok len={len(auth_url)} castle={len(castle)}", worker)
    return {
        "authUrl": auth_url,
        "cookies": out_cookies,
        "ua": ua,
        "castle_len": len(castle),
        "oauth2_cookie": data.get("oauth2Cookie") or data.get("oauth2_cookie"),
    }


def _proxy_for_playwright(proxy: str | None) -> dict | None:
    if not proxy:
        return None
    # http://user:pass@host:port or host:port:user:pass
    p = proxy.strip()
    if "://" not in p and p.count(":") >= 3:
        host, port, user, pwd = p.split(":", 3)
        p = f"http://{user}:{pwd}@{host}:{port}"
    u = urlparse(p if "://" in p else f"http://{p}")
    server = f"{u.scheme}://{u.hostname}:{u.port or 80}"
    out: dict[str, str] = {"server": server}
    if u.username:
        out["username"] = u.username
    if u.password:
        out["password"] = u.password
    return out


def _on_xai(url: str) -> bool:
    """True when post-Google flow landed on xAI property (not google.com itself)."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    # google pages sometimes embed app_domain=accounts.x.ai in query — host stays google
    if "google." in host:
        return False
    return (
        host.endswith("accounts.x.ai")
        or host.endswith("auth.x.ai")
        or host.endswith("auth.grokusercontent.com")
        or host.endswith("auth.grokipedia.com")
        or host == "grok.com"
        or host.endswith(".grok.com")
        or host.endswith("x.ai")
    )


def _harvest_sso(context, page, worker: int | None = None) -> dict[str, str]:
    """Collect xAI SSO cookies; if missing, hit accounts.x.ai/account once."""
    def jar() -> dict[str, str]:
        out: dict[str, str] = {}
        for c in context.cookies():
            dom = (c.get("domain") or "").lower()
            if any(x in dom for x in ("x.ai", "grok.com", "grokusercontent", "grokipedia")):
                out[c["name"]] = c["value"]
        return out

    cookies = jar()
    if any(n in cookies for n in SSO_COOKIE_NAMES):
        return cookies
    # bounce through accounts to materialize sso cookies after grok.com redirect
    try:
        _log("[glogin] harvest SSO via /account…", worker)
        page.goto("https://accounts.x.ai/account", wait_until="domcontentloaded", timeout=45000)
        page.wait_for_timeout(2500)
    except Exception as e:
        _log(f"    /account soft-fail: {e}", worker)
    cookies = jar()
    if any(n in cookies for n in SSO_COOKIE_NAMES):
        return cookies
    try:
        page.goto("https://accounts.x.ai/sign-in", wait_until="domcontentloaded", timeout=30000)
        page.wait_for_timeout(1500)
    except Exception:
        pass
    return jar()


def _launch_browser(p, headless: bool):
    """Launch Chromium (default) or Camoufox (anti-detect) via GOOGLE_ENGINE=camoufox."""
    engine = os.getenv("GOOGLE_ENGINE", "chromium").lower()
    if engine == "camoufox":
        from camoufox.sync_api import Camoufox

        _log("[glogin] engine=camoufox (anti-detect)")
        return Camoufox(headless=headless).start()
    return p.chromium.launch(
        headless=headless,
        args=[
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
            "--disable-dev-shm-usage",
        ],
    )


def _gen_fingerprint() -> dict | None:
    """Generate a self-consistent Chrome fingerprint (UA/screen/WebGL/canvas)."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import fingerprint_gen

        fp = fingerprint_gen.generate_fingerprint(chrome_only=True)
        return fp
    except Exception as e:
        _log(f"    fingerprint gen soft: {str(e)[:100]}")
        return None


def _fp_init_js(fp: dict) -> str:
    """CDP init-script JS from fingerprint_gen to run on every new document."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import fingerprint_gen

        return fingerprint_gen.inject_cdp_js(fp)
    except Exception:
        # minimal fallback: kill webdriver + match UA
        ua = fp.get("navigator", {}).get("userAgent", "")
        return (
            f"Object.defineProperty(navigator,'webdriver',{{get:()=>false}});"
            f"Object.defineProperty(navigator,'userAgent',{{get:()=>{json.dumps(ua)}}});"
        )


@contextlib.contextmanager
def _browser_ctx(p, headless: bool):
    """Context manager: Chromium via p, or standalone Camoufox (no sync_playwright loop)."""
    engine = os.getenv("GOOGLE_ENGINE", "chromium").lower()
    if engine == "camoufox":
        from camoufox.sync_api import Camoufox

        # Camoufox sync API is NOT thread-safe (asyncio loop conflict when
        # multiple workers launch simultaneously) — serialize browser launch.
        with _CAMOUFOX_LOCK:
            _log("[glogin] engine=camoufox (anti-detect)")
            browser = Camoufox(headless=headless).start()
        try:
            yield browser
        finally:
            try:
                browser.close()
            except Exception:
                pass
    else:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as sp:
            browser = sp.chromium.launch(
                headless=headless,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                ],
            )
            try:
                yield browser
            finally:
                try:
                    browser.close()
                except Exception:
                    pass


def _visible_password(page):
    loc = page.locator('input[type="password"]')
    n = loc.count()
    for i in range(n):
        el = loc.nth(i)
        try:
            if el.is_visible(timeout=1500):
                return el
        except Exception:
            continue
    return None


def _click_named(page, names: tuple[str, ...], role: str = "button") -> bool:
    for text in names:
        try:
            btn = page.get_by_role(role, name=re.compile(rf"^{re.escape(text)}$", re.I))
            if btn.count():
                btn.first.click(timeout=2500)
                return True
        except Exception:
            pass
        # partial match fallback
        try:
            btn = page.get_by_role(role, name=re.compile(text, re.I))
            if btn.count():
                btn.first.click(timeout=2500)
                return True
        except Exception:
            pass
    return False


def _fill_google_login(page, email: str, password: str, worker: int | None = None) -> None:
    """Drive Google identifier → password → optional workspace continue."""
    # Email step
    page.wait_for_selector('input[type="email"], #identifierId', timeout=45000)
    email_sel = "#identifierId" if page.locator("#identifierId").count() else 'input[type="email"]'
    page.fill(email_sel, "")
    page.fill(email_sel, email)
    page.wait_for_timeout(400)
    if not _click_named(page, ("Next", "Lanjut", "Berikutnya")):
        page.keyboard.press("Enter")
    page.wait_for_timeout(1500)

    password_done = False
    for _ in range(50):
        url = page.url
        if _on_xai(url):
            return

        pw = _visible_password(page)
        if pw is not None and not password_done:
            try:
                pw.click(timeout=2000)
                # short timeout — hidden twin password inputs hang at page default 120s
                pw.fill("", timeout=5000)
                pw.fill(password, timeout=5000)
                page.wait_for_timeout(300)
                if not _click_named(page, ("Next", "Lanjut", "Berikutnya", "Sign in", "Masuk")):
                    page.keyboard.press("Enter")
                password_done = True
                page.wait_for_timeout(2000)
                continue
            except Exception as e:
                _log(f"    password fill soft: {str(e).splitlines()[0][:120]}", worker)
                # try type() fallback on first password input
                try:
                    page.locator('input[type="password"]').first.click(timeout=2000)
                    page.keyboard.type(password, delay=30)
                    page.keyboard.press("Enter")
                    password_done = True
                    page.wait_for_timeout(2000)
                    continue
                except Exception as e2:
                    _log(f"    password type soft: {str(e2).splitlines()[0][:100]}", worker)

        # consent / continue / account chooser
        if _click_named(
            page,
            (
                "Next",
                "Continue",
                "I understand",
                "Yes",
                "Confirm",
                "Allow",
                "Accept",
                "Lanjut",
                "Berikutnya",
                "Sign in",
                "Masuk",
            ),
        ):
            page.wait_for_timeout(1200)
            continue

        for text in ("Continue", "Use another account", "Try again"):
            try:
                link = page.get_by_role("link", name=re.compile(text, re.I))
                if link.count():
                    link.first.click(timeout=1500)
                    page.wait_for_timeout(1000)
            except Exception:
                pass

        body = ""
        try:
            body = page.inner_text("body")[:600]
        except Exception:
            pass
        low = body.lower()
        if any(
            x in low
            for x in (
                "couldn't sign you in",
                "couldn’t sign you in",
                "this browser or app may not be secure",
                "unusual activity",
                "verify it’s you",
                "verify it's you",
                "2-step",
                "2-step verification",
                "account disabled",
                "wrong password",
                "incorrect password",
                "couldn't find your google account",
                "couldn’t find your google account",
            )
        ):
            raise RuntimeError(f"google_challenge: {body[:180].replace(chr(10), ' ')}")
        page.wait_for_timeout(800)

    if not _on_xai(page.url):
        raise RuntimeError(f"google_login stuck url={page.url[:180]}")


def login_google_sso(
    email: str,
    password: str,
    *,
    proxy: str | None = None,
    worker: int | None = None,
    headless: bool = True,
    timeout_s: int = 120,
    screenshot_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Full Google SSO → accounts.x.ai session cookies.

    Returns:
      {
        ok, email, cookies: {name: value}, cookie_names,
        final_url, auth_url_host, elapsed_s, error?
      }
    """
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout

    t0 = time.time()
    out: dict[str, Any] = {
        "ok": False,
        "email": email,
        "cookies": {},
        "cookie_names": [],
        "final_url": None,
        "elapsed_s": 0,
    }
    shot_dir = Path(screenshot_dir) if screenshot_dir else Path(__file__).resolve().parent / "run" / "google_shots"
    shot_dir.mkdir(parents=True, exist_ok=True)

    _log(f"[glogin] getAuthUrl for {email}", worker)
    engine = os.getenv("GOOGLE_ENGINE", "chromium").lower()
    if engine == "camoufox":
        # Camoufox = Firefox TLS fingerprint, matches :8877 cf_clearance.
        # Do NOT override UA/fingerprint — Camoufox is stealth by default.
        fp = None
        fp_ua = None
    else:
        # Chromium: generate consistent Chrome profile so Google doesn't
        # flag UA/webdriver mismatch ("This browser or app may not be secure").
        fp = _gen_fingerprint()
        fp_ua = fp["navigator"]["userAgent"] if fp else None
    auth = get_google_auth_url(proxy=proxy, worker=worker, user_agent=fp_ua)
    auth_url = auth["authUrl"]
    out["auth_url_host"] = urlparse(auth_url).hostname
    seed_cookies = auth.get("cookies") or {}
    # oauth2_cookie from response if present (sometimes needed for exchange)
    if auth.get("oauth2_cookie"):
        seed_cookies.setdefault("oauth2", auth["oauth2_cookie"])

    pw_proxy = _proxy_for_playwright(proxy)
    try:
        with _browser_ctx(None, headless) as browser:
            fp_viewport = fp["screen"] if fp else None
            context = browser.new_context(
                user_agent=auth.get("ua") or (fp_ua or None),
                viewport={"width": fp_viewport["width"] if fp_viewport else 1280,
                          "height": fp_viewport["height"] if fp_viewport else 800},
                locale=(fp["navigator"]["language"] if fp else "en-US"),
                proxy=pw_proxy,
            )
            # inject fingerprint anti-detection on every new document
            if fp:
                try:
                    context.add_init_script(_fp_init_js(fp))
                except Exception as e:
                    _log(f"    fp init script soft: {str(e)[:100]}", worker)
            # seed CF / anon cookies on accounts.x.ai
            cookie_list = []
            for name, value in seed_cookies.items():
                cookie_list.append(
                    {
                        "name": name,
                        "value": value,
                        "domain": ".x.ai",
                        "path": "/",
                    }
                )
            if cookie_list:
                try:
                    context.add_cookies(cookie_list)
                except Exception:
                    # domain-specific fallback
                    for c in cookie_list:
                        c["domain"] = "accounts.x.ai"
                    try:
                        context.add_cookies(cookie_list)
                    except Exception:
                        pass

            page = context.new_page()
            page.set_default_timeout(timeout_s * 1000)

            _log("[glogin] open Google OAuth…", worker)
            try:
                page.goto(auth_url, wait_until="domcontentloaded", timeout=min(90000, timeout_s * 1000))
            except Exception as e:
                if pw_proxy:
                    _log(f"[glogin] proxy goto fail → retry direct: {str(e).splitlines()[0][:100]}", worker)
                    try:
                        context.close()
                    except Exception:
                        pass
                    context = browser.new_context(
                        user_agent=auth.get("ua"),
                        viewport={"width": 1280, "height": 800},
                        locale="en-US",
                        # no proxy
                    )
                    if cookie_list:
                        try:
                            context.add_cookies(cookie_list)
                        except Exception:
                            for c in cookie_list:
                                c["domain"] = "accounts.x.ai"
                            try:
                                context.add_cookies(cookie_list)
                            except Exception:
                                pass
                    page = context.new_page()
                    page.set_default_timeout(timeout_s * 1000)
                    page.goto(auth_url, wait_until="domcontentloaded", timeout=timeout_s * 1000)
                else:
                    raise

            try:
                _fill_google_login(page, email, password, worker=worker)
            except Exception as e:
                # still try harvest if we somehow left google
                try:
                    out["final_url"] = page.url[:240]
                    jar = _harvest_sso(context, page, worker=worker)
                    if any(n in jar for n in SSO_COOKIE_NAMES):
                        out["cookies"] = jar
                        out["cookie_names"] = sorted(jar.keys())
                        out["ok"] = True
                        out["error"] = f"soft:{str(e)[:120]}"
                        browser.close()
                        out["elapsed_s"] = round(time.time() - t0, 1)
                        _log(
                            f"[glogin] recovered ok cookies={out['cookie_names']} "
                            f"final={out.get('final_url')} t={out['elapsed_s']}s",
                            worker,
                        )
                        return out
                except Exception:
                    pass
                try:
                    page.screenshot(path=str(shot_dir / f"fail_{email.split('@')[0]}.png"))
                except Exception:
                    pass
                raise

            # wait for exchange-token / account / signed-in landing
            deadline = time.time() + timeout_s
            while time.time() < deadline:
                url = page.url
                out["final_url"] = url[:240]
                if _on_xai(url):
                    # give set-cookie chain time
                    page.wait_for_timeout(2500)
                    if "/exchange-token" in url:
                        try:
                            page.wait_for_url(
                                re.compile(r"https://(accounts\.x\.ai|grok\.com)"),
                                timeout=20000,
                            )
                        except PWTimeout:
                            pass
                        page.wait_for_timeout(1500)
                    break
                # consent allow on google
                try:
                    for text in ("Continue", "Allow", "Confirm", "Yes"):
                        btn = page.get_by_role("button", name=re.compile(rf"^{re.escape(text)}$", re.I))
                        if btn.count():
                            btn.first.click(timeout=1500)
                            page.wait_for_timeout(1000)
                except Exception:
                    pass
                page.wait_for_timeout(500)

            out["final_url"] = page.url[:240]
            jar = _harvest_sso(context, page, worker=worker)
            out["cookies"] = jar
            out["cookie_names"] = sorted(jar.keys())
            has_sso = any(n in jar for n in SSO_COOKIE_NAMES)
            out["ok"] = has_sso
            if not has_sso:
                try:
                    page.screenshot(path=str(shot_dir / f"nosso_{email.split('@')[0]}.png"))
                except Exception:
                    pass
                body = ""
                try:
                    body = page.content()[:3000]
                except Exception:
                    pass
                m = re.findall(
                    r"https://auth\.(?:grokipedia|grokusercontent)\.com/set-cookie\?q=[A-Za-z0-9_\-\.]+",
                    body,
                )
                out["set_cookie_urls"] = [u[:120] for u in m[:5]]
                if not has_sso and not m:
                    out["error"] = f"no SSO cookies after google login final={out['final_url']}"
            browser.close()
    except Exception as e:
        out["error"] = str(e)[:300]
        out["ok"] = False

    out["elapsed_s"] = round(time.time() - t0, 1)
    _log(
        f"[glogin] done ok={out['ok']} cookies={out['cookie_names']} "
        f"final={(out.get('final_url') or '')[:80]} t={out['elapsed_s']}s "
        f"err={out.get('error')}",
        worker,
    )
    return out


def apply_cookies_to_session(session, cookies: dict[str, str]) -> list[str]:
    """Apply cookie dict onto curl_cffi/requests session. Returns names set."""
    set_names = []
    for name, value in (cookies or {}).items():
        try:
            session.cookies.set(name, value, domain=".x.ai")
            set_names.append(name)
        except Exception:
            try:
                session.cookies.set(name, value)
                set_names.append(name)
            except Exception:
                pass
    return set_names


def load_account_file(path: str | Path) -> list[tuple[str, str]]:
    """Parse email|password or email:password lines. Skips blanks/#."""
    p = Path(path)
    out: list[tuple[str, str]] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "|" in line:
            email, pw = line.split("|", 1)
        elif ":" in line and "@" in line.split(":", 1)[0]:
            email, pw = line.split(":", 1)
        else:
            continue
        email, pw = email.strip(), pw.strip()
        if email and pw:
            out.append((email, pw))
    return out


if __name__ == "__main__":
    import argparse
    import sys

    ap = argparse.ArgumentParser(description="xAI Google SSO login smoke")
    ap.add_argument("email")
    ap.add_argument("password")
    ap.add_argument("--proxy", default=None)
    ap.add_argument("--headed", action="store_true")
    args = ap.parse_args()
    res = login_google_sso(
        args.email,
        args.password,
        proxy=args.proxy,
        headless=not args.headed,
    )
    # redact cookie values
    safe = {
        **res,
        "cookies": {k: f"<len={len(v)}>" for k, v in (res.get("cookies") or {}).items()},
    }
    print(json.dumps(safe, indent=2))
    sys.exit(0 if res.get("ok") else 1)
