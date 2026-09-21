#!/usr/bin/env python3
"""Harvest Cloudflare Turnstile token on live accounts.x.ai origin.

xAI only mounts the widget on the credentials step, but the Turnstile JS is
already loaded on /sign-up. We inject a flexible widget via turnstile.render
with the real sitekey so the token is origin-bound (stub tokens get rejected).
"""
from __future__ import annotations

import json
import sys
import time

from camoufox.sync_api import Camoufox

DEFAULT_URL = "https://accounts.x.ai/sign-up?redirect=grok-com&return_to=%2F"
DEFAULT_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"

INJECT_AND_RENDER = """async (sitekey) => {
  const out = {token: null, error: null, via: null, hasApi: !!window.turnstile};
  if (!window.turnstile || typeof window.turnstile.render !== 'function') {
    out.error = 'turnstile api missing';
    return out;
  }
  // reuse existing token if any
  try {
    const existing = document.querySelector('input[name="cf-turnstile-response"]');
    if (existing && existing.value && existing.value.length > 100) {
      out.token = existing.value;
      out.via = 'existing_input';
      return out;
    }
  } catch (e) {}

  return await new Promise((resolve) => {
    const deadline = Date.now() + 45000;
    const host = document.createElement('div');
    host.id = 'xai-ts-host';
    host.style.cssText = 'position:fixed;left:8px;bottom:8px;z-index:999999;width:300px;height:70px;';
    document.body.appendChild(host);

    let done = false;
    const finish = (tok, via, err) => {
      if (done) return;
      done = true;
      resolve({token: tok || null, error: err || null, via: via || null, hasApi: true});
    };

    try {
      const wid = window.turnstile.render(host, {
        sitekey: sitekey,
        theme: 'dark',
        size: 'flexible',
        callback: (token) => finish(token, 'render_callback', null),
        'error-callback': (e) => finish(null, 'error_callback', String(e)),
        'expired-callback': () => {},
        'timeout-callback': () => finish(null, 'timeout_callback', 'widget_timeout'),
      });
      // poll getResponse as backup
      const t = setInterval(() => {
        try {
          const r = window.turnstile.getResponse(wid);
          if (r && r.length > 100) {
            clearInterval(t);
            finish(r, 'getResponse', null);
          }
        } catch (e) {}
        if (Date.now() > deadline) {
          clearInterval(t);
          finish(null, 'poll_timeout', 'no token in 45s');
        }
      }, 400);
    } catch (e) {
      finish(null, 'render_exception', String(e && e.message || e));
    }
  });
}"""


def accept_cookies(page) -> None:
    try:
        page.evaluate(
            """() => {
              const b = [...document.querySelectorAll('button')].find(x =>
                /accept all cookies/i.test(x.innerText || '')
              );
              if (b) b.click();
            }"""
        )
        page.wait_for_timeout(300)
    except Exception:
        pass


def main() -> int:
    url = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_URL
    sitekey = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SITEKEY
    timeout_s = int(sys.argv[3]) if len(sys.argv) > 3 else 70
    out = {"ok": False, "token": None, "error": None, "via": None, "sitekey": sitekey}

    try:
        with Camoufox(headless=True) as browser:
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=90000)
            accept_cookies(page)
            try:
                page.wait_for_load_state("networkidle", timeout=25000)
            except Exception:
                page.wait_for_timeout(2500)

            # wait for turnstile global
            deadline = time.time() + min(30, timeout_s)
            while time.time() < deadline:
                has = page.evaluate("() => !!(window.turnstile && window.turnstile.render)")
                if has:
                    break
                page.wait_for_timeout(400)
            else:
                out["error"] = "turnstile api not loaded"
                print(json.dumps(out))
                return 1

            # open email form (keeps SPA warm; not strictly required)
            try:
                page.evaluate(
                    """() => {
                      const t = [...document.querySelectorAll('button, a, [role=button]')].find(b =>
                        /sign up with email/i.test(b.innerText || '')
                      );
                      if (t) t.click();
                    }"""
                )
                page.wait_for_timeout(800)
            except Exception:
                pass

            result = page.evaluate(INJECT_AND_RENDER, sitekey)
            tok = (result or {}).get("token")
            if tok and len(tok) > 100:
                out = {
                    "ok": True,
                    "token": tok,
                    "error": None,
                    "via": result.get("via"),
                    "sitekey": sitekey,
                    "len": len(tok),
                }
                print(json.dumps(out))
                return 0
            out = {
                "ok": False,
                "token": None,
                "error": (result or {}).get("error") or "empty token",
                "via": (result or {}).get("via"),
                "sitekey": sitekey,
                "debug": result,
            }
    except Exception as e:
        out = {"ok": False, "token": None, "error": str(e)[:300], "via": "exception"}

    print(json.dumps(out))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
