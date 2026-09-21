#!/usr/bin/env python3
"""
Universal Captcha Solver Client — drop into any farming script.
Talks to local solver (:8877). Local-first, Capsolver fallback handled server-side.
By FEB-FRMN · https://saweria.co/febfrmn
"""
import json, os, urllib.request, urllib.error

SOLVER_URL = os.getenv("SOLVER_URL", "http://127.0.0.1:8877")


def _post(payload: dict, timeout: int = 120):
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(f"{SOLVER_URL}/solve", data=data,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return {"solved": False, "error": e.read().decode()[:200]}
        except Exception:
            return {"solved": False, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"solved": False, "error": str(e)}


def solve(ctype: str, **kw) -> dict:
    """Generic solve. Returns full result dict.
    kw may include: url, sitekey, image, text, bg_image, puzzle_image,
    version, enterprise, action, public_key, gt, challenge, captcha_id,
    proxy, user_agent, timeout_s, real_page, pre_actions.
    """
    payload = {"type": ctype}
    payload.update({k: v for k, v in kw.items() if v is not None})
    return _post(payload, timeout=kw.get("timeout_s", 90) + 20)


# ── Token-based convenience wrappers (return token str | None) ──
def solve_turnstile(url, sitekey=None, timeout=60, **kw):
    return solve("turnstile", url=url, sitekey=sitekey, timeout_s=timeout, **kw).get("token")

def solve_recaptcha(url, sitekey, version="v2", timeout=90, **kw):
    return solve("recaptcha", url=url, sitekey=sitekey, version=version, timeout_s=timeout, **kw).get("token")

def solve_recaptcha_v3(url, sitekey, action="verify", timeout=90, **kw):
    return solve("recaptchav3", url=url, sitekey=sitekey, action=action, timeout_s=timeout, **kw).get("token")

def solve_hcaptcha(url, sitekey, timeout=120, **kw):
    return solve("hcaptcha", url=url, sitekey=sitekey, timeout_s=timeout, **kw).get("token")

def solve_funcaptcha(url, public_key, timeout=120, **kw):
    return solve("funcaptcha", url=url, public_key=public_key, timeout_s=timeout, **kw).get("token")

def solve_geetest(url, captcha_id=None, gt=None, challenge=None, timeout=120, **kw):
    return solve("geetest", url=url, captcha_id=captcha_id, gt=gt, challenge=challenge, timeout_s=timeout, **kw).get("solution")

def solve_datadome(url, proxy=None, user_agent=None, timeout=120, **kw):
    return solve("datadome", url=url, proxy=proxy, user_agent=user_agent, timeout_s=timeout, **kw).get("token")

def solve_awswaf(url, timeout=90, **kw):
    return solve("awswaf", url=url, timeout_s=timeout, **kw).get("token")

def solve_cloudflare(url, timeout=90, **kw):
    return solve("cloudflare", url=url, timeout_s=timeout, **kw)  # returns full (cf_clearance+cookies)


# ── Image-based convenience wrappers (return solution str | None) ──
def solve_math(text=None, image=None):
    return solve("math", text=text, image=image).get("solution")

def solve_text(image):
    return solve("text", image=image).get("solution")

def solve_slider(bg_image, puzzle_image):
    return solve("slider", bg_image=bg_image, puzzle_image=puzzle_image).get("solution")


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python3 solver_client.py <type> [args...]")
        print("  turnstile <url> <sitekey>")
        print("  recaptcha <url> <sitekey> [v2|v3]")
        print("  hcaptcha  <url> <sitekey>")
        print("  math      --text '5+3=?'   |   --image /path.png")
        print("  text      <image_path_or_url>")
        print("  slider    <bg.png> <piece.png>")
        sys.exit(1)
    cmd = sys.argv[1]
    if cmd == "math":
        if "--text" in sys.argv:
            print(solve_math(text=sys.argv[sys.argv.index("--text") + 1]))
        elif "--image" in sys.argv:
            print(solve_math(image=sys.argv[sys.argv.index("--image") + 1]))
    elif cmd == "text" and len(sys.argv) >= 3:
        print(solve_text(sys.argv[2]))
    elif cmd == "slider" and len(sys.argv) >= 4:
        print(solve_slider(sys.argv[2], sys.argv[3]))
    elif cmd in ("turnstile", "hcaptcha") and len(sys.argv) >= 4:
        fn = solve_turnstile if cmd == "turnstile" else solve_hcaptcha
        t = fn(sys.argv[2], sys.argv[3])
        print(f"Token: {t[:40] if t else 'None'}...")
    elif cmd == "recaptcha" and len(sys.argv) >= 4:
        ver = sys.argv[4] if len(sys.argv) >= 5 else "v2"
        t = solve_recaptcha(sys.argv[2], sys.argv[3], version=ver)
        print(f"Token: {t[:40] if t else 'None'}...")
    else:
        print("bad args")
