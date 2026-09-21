#!/usr/bin/env python3
"""Harvest Castle createRequestToken via Camoufox + React fiber walk.

xAI loads Castle inside React context (useCastle), not as window.Castle.
We open sign-up → email form → walk React fiber for createRequestToken.
"""
from __future__ import annotations

import json
import sys
import time

from camoufox.sync_api import Camoufox

DEFAULT_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
DEFAULT_URL = "https://accounts.x.ai/sign-up?redirect=grok-com&return_to=%2F"

FIBER_JS = """async () => {
  const out = { via: null, token: null, error: null, steps: 0 };
  const root = document.getElementById('__next') || document.body;
  if (!root) { out.error = 'no root'; return out; }
  const key = Object.keys(root).find(
    k => k.startsWith('__reactFiber') || k.startsWith('__reactContainer')
  );
  if (!key) { out.error = 'no fiber'; return out; }

  let found = null;
  const q = [root[key]];
  let steps = 0;
  while (q.length && steps < 12000) {
    const n = q.shift();
    steps++;
    if (!n) continue;
    try {
      const props = n.memoizedProps || {};
      for (const pv of Object.values(props)) {
        if (pv && typeof pv.createRequestToken === 'function') {
          found = pv;
          break;
        }
      }
      if (found) break;
      let st = n.memoizedState;
      let h = 0;
      while (st && h < 60) {
        const mq = st.memoizedState;
        if (mq && typeof mq.createRequestToken === 'function') {
          found = mq;
          break;
        }
        if (Array.isArray(mq)) {
          for (const item of mq) {
            if (item && typeof item.createRequestToken === 'function') {
              found = item;
              break;
            }
          }
        }
        if (found) break;
        st = st.next;
        h++;
      }
    } catch (e) {}
    if (found) break;
    if (n.child) q.push(n.child);
    if (n.sibling) q.push(n.sibling);
  }
  out.steps = steps;
  if (!found) {
    out.error = 'createRequestToken not found in fiber';
    return out;
  }
  try {
    const tok = await found.createRequestToken();
    if (!tok || typeof tok !== 'string' || tok.length < 100) {
      out.error = 'empty/short token: ' + String(tok).slice(0, 40);
      return out;
    }
    out.token = tok;
    out.via = 'react_fiber';
  } catch (e) {
    out.error = String(e && e.message || e);
  }
  return out;
}"""


def open_email_form(page) -> None:
    # cookie banner
    try:
        page.evaluate(
            """() => {
              const b = [...document.querySelectorAll('button')].find(x =>
                /accept all cookies/i.test(x.innerText || '')
              );
              if (b) b.click();
            }"""
        )
        page.wait_for_timeout(400)
    except Exception:
        pass
    # sign up with email
    page.evaluate(
        """() => {
          const t = [...document.querySelectorAll('button, a, [role=button]')].find(b =>
            /sign up with email/i.test(b.innerText || '')
          );
          if (t) t.click();
        }"""
    )
    page.wait_for_timeout(2000)


def _proxy_dict(proxy: str | None) -> dict | None:
    if not proxy:
        return None
    from urllib.parse import urlparse

    p = urlparse(proxy if "://" in proxy else f"http://{proxy}")
    if not p.hostname or not p.port:
        return None
    d: dict = {"server": f"{p.scheme or 'http'}://{p.hostname}:{p.port}"}
    if p.username:
        d["username"] = p.username
    if p.password:
        d["password"] = p.password
    return d


def main() -> int:
    pk = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PK
    url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_URL
    timeout_s = int(sys.argv[3]) if len(sys.argv) > 3 else 45
    proxy = sys.argv[4] if len(sys.argv) > 4 else None
    _ = pk  # pk comes from page SDK; kept for CLI compat

    out = {"ok": False, "token": None, "error": None, "via": None}
    try:
        px = _proxy_dict(proxy)
        # Camoufox accepts proxy via playwright-style dict
        cf_kw = {"headless": True}
        if px:
            cf_kw["proxy"] = px
        with Camoufox(**cf_kw) as browser:
            page = browser.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=90000)
            try:
                page.wait_for_load_state("networkidle", timeout=30000)
            except Exception:
                page.wait_for_timeout(3000)

            open_email_form(page)

            # retry fiber walk a few times while SDK boots
            deadline = time.time() + timeout_s
            last = None
            while time.time() < deadline:
                last = page.evaluate(FIBER_JS)
                if last and last.get("token"):
                    out = {
                        "ok": True,
                        "token": last["token"],
                        "error": None,
                        "via": last.get("via") or "react_fiber",
                        "steps": last.get("steps"),
                    }
                    print(json.dumps(out))
                    return 0
                page.wait_for_timeout(800)

            out = {
                "ok": False,
                "token": None,
                "error": (last or {}).get("error") or "timeout",
                "via": "react_fiber",
                "steps": (last or {}).get("steps"),
            }
    except Exception as e:
        out = {"ok": False, "token": None, "error": str(e)[:300], "via": "exception"}

    print(json.dumps(out))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
