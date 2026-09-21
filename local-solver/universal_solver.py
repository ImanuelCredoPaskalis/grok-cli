#!/usr/bin/env python3
"""
UNIVERSAL CAPTCHA SOLVER — single local endpoint (:8877)
Merge of Boterdrop (Camoufox anti-detect page-pool) + free local + Capsolver.

ENGINE  : Camoufox (Firefox anti-detect) page-pool
          → Turnstile / cf_clearance / aws-waf-token / reCAPTCHA / hCaptcha (native)
FREE     : math (eval), text/image (tesseract OCR), slider (opencv)
FALLBACK : Capsolver → funcaptcha/arkose, geetest, datadome + failed browser types
           (hCaptcha prefers local first; Capsolver often blocks sitekeys)

Solve ANY captcha through one API. Sync (POST /solve) + async (GET /turnstile → GET /result?id=) both supported.
By FEB-FRMN · https://saweria.co/febfrmn
"""
import os, sys, io, re, json, time, uuid, base64, asyncio, logging
import urllib.request, urllib.error
from urllib.parse import urlparse
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from loguru import logger
import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ─── Config ───────────────────────────────────────────────────────────────
PORT              = int(os.getenv("PORT", "8877"))
HOST              = os.getenv("HOST", "0.0.0.0")
HEADLESS          = os.getenv("SOLVER_HEADLESS", "1") != "0"
THREADS           = int(os.getenv("SOLVER_THREADS", "2"))
PAGES_PER_THREAD  = int(os.getenv("SOLVER_PAGES", "1"))
CLEANUP_MIN       = int(os.getenv("SOLVER_CLEANUP_MIN", "10"))
PROXY_SUPPORT     = os.getenv("SOLVER_PROXY_SUPPORT", "0") == "1"
PROXY_FILE        = os.getenv("SOLVER_PROXY_FILE", "proxies.txt")
ALLOW_PRIVATE     = os.getenv("SOLVER_ALLOW_PRIVATE", "0") == "1"
CAPSOLVER_API_KEY = os.getenv("CAPSOLVER_API_KEY", "")
SOLVER_MODE       = os.getenv("SOLVER_MODE", "auto").lower()   # auto | local | capsolver

DEMO_TOKENS = {
    "1x00000000000000000000AA": "XXXX.DUMMY.TOKEN.XXXX",
    "3x00000000000000000000AA": "XXXX.DUMMY.TOKEN.XXXX",
    "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI": "03AGdBq25H3K...",
}

SUPPORTED = ["math", "text", "image", "slider", "turnstile", "recaptcha",
             "recaptchav3", "hcaptcha", "funcaptcha", "geetest", "datadome",
             "cloudflare", "awswaf"]

log = logging.getLogger("solver")

# ─── SSRF guard ─────────────────────────────────────────────────────────────
_PRIV = [re.compile(p) for p in [
    r"^127\.\d+\.\d+\.\d+", r"^10\.\d+\.\d+\.\d+",
    r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", r"^192\.168\.\d+\.\d+",
    r"^0\.0\.0\.0$", r"^localhost$", r"^::1$"]]
def check_ssrf(u):
    if ALLOW_PRIVATE or not u:
        return
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        raise HTTPException(400, f"Bad scheme: {p.scheme}")
    for r in _PRIV:
        if r.search(p.hostname or ""):
            raise HTTPException(400, f"Private host: {p.hostname}")

# ─── image helpers ──────────────────────────────────────────────────────────
def load_image_bytes(src: str) -> bytes:
    if not src:
        raise ValueError("no image provided")
    s = src.strip()
    if s.startswith("data:"):
        s = s.split(",", 1)[1]
    if s.startswith("http://") or s.startswith("https://"):
        req = urllib.request.Request(s, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    if os.path.exists(s):
        with open(s, "rb") as f:
            return f.read()
    return base64.b64decode(s)

def image_to_b64(src: str) -> str:
    s = src.strip()
    if s.startswith("data:"):
        return s.split(",", 1)[1]
    if s.startswith("http") or os.path.exists(s):
        return base64.b64encode(load_image_bytes(s)).decode()
    return s

# ─── FREE: math ─────────────────────────────────────────────────────────────
_WORDS = {"zero":0,"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,
          "eight":8,"nine":9,"ten":10,"eleven":11,"twelve":12,
          "plus":"+","minus":"-","times":"*","multiplied":"*","divided":"/"}
def solve_math(text: str):
    if not text:
        return {"solved": False, "error": "no text"}
    raw = text.lower()
    for w, v in _WORDS.items():
        raw = re.sub(rf"\b{w}\b", str(v), raw)
    expr = re.sub(r"[^0-9+\-*/(). ]", " ", raw)
    m = re.search(r"[-+]?\d[\d\s+\-*/().]*\d", expr)
    if not m:
        m2 = re.search(r"[-+]?\d+", expr)
        return ({"solved": True, "solution": m2.group(), "answer": m2.group()}
                if m2 else {"solved": False, "error": "no expression"})
    e = m.group().replace(" ", "")
    if not re.fullmatch(r"[0-9+\-*/(). ]+", e):
        return {"solved": False, "error": "unsafe expression"}
    try:
        val = eval(e, {"__builtins__": {}}, {})
        if isinstance(val, float) and val.is_integer():
            val = int(val)
        return {"solved": True, "solution": str(val), "answer": str(val), "expr": e}
    except Exception as ex:
        return {"solved": False, "error": f"eval failed: {ex}"}

# ─── FREE: OCR ──────────────────────────────────────────────────────────────
def solve_ocr(image_src: str, is_math=False):
    try:
        import pytesseract
        from PIL import Image, ImageFilter, ImageOps
    except Exception as e:
        return {"solved": False, "error": f"OCR deps missing: {e}"}
    try:
        img = Image.open(io.BytesIO(load_image_bytes(image_src))).convert("L")
        img = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)
        img = ImageOps.autocontrast(img)
        img = img.point(lambda p: 255 if p > 140 else 0)
        img = img.filter(ImageFilter.MedianFilter(3))
        txt = pytesseract.image_to_string(img, config="--psm 8 --oem 3").strip()
        txt = re.sub(r"\s+", "", txt)
        if is_math:
            return solve_math(txt)
        clean = re.sub(r"[^A-Za-z0-9]", "", txt)
        return ({"solved": True, "solution": clean, "answer": clean, "raw": txt}
                if clean else {"solved": False, "error": "OCR empty", "raw": txt})
    except Exception as e:
        return {"solved": False, "error": str(e)}

# ─── FREE: slider ───────────────────────────────────────────────────────────
def solve_slider(bg_src: str, puzzle_src: str):
    try:
        import cv2, numpy as np
    except Exception as e:
        return {"solved": False, "error": f"opencv missing: {e}"}
    try:
        bg = cv2.imdecode(np.frombuffer(load_image_bytes(bg_src), np.uint8), cv2.IMREAD_COLOR)
        pz = cv2.imdecode(np.frombuffer(load_image_bytes(puzzle_src), np.uint8), cv2.IMREAD_COLOR)
        res = cv2.matchTemplate(cv2.Canny(bg, 100, 200), cv2.Canny(pz, 100, 200), cv2.TM_CCOEFF_NORMED)
        _, maxv, _, maxloc = cv2.minMaxLoc(res)
        return {"solved": True, "solution": str(int(maxloc[0])), "answer": str(int(maxloc[0])),
                "x": int(maxloc[0]), "y": int(maxloc[1]), "confidence": round(float(maxv), 3)}
    except Exception as e:
        return {"solved": False, "error": str(e)}

# ─── UNIVERSAL Capsolver fallback ────────────────────────────────────────────
def _cap_post(endpoint, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(f"https://api.capsolver.com/{endpoint}",
        data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def _extract_solution(sol):
    if not isinstance(sol, dict):
        return None, sol
    for k in ("gRecaptchaResponse", "token", "text", "value"):
        if sol.get(k):
            return sol[k], sol
    if sol.get("cookie"):
        return sol["cookie"], sol
    if any(k in sol for k in ("challenge", "captcha_output", "lot_number")):
        return sol, sol
    return None, sol

def build_cap_task(req):
    t = req.type.lower()
    ent = req.enterprise
    if t in ("math", "text", "image"):
        return {"type": "ImageToTextTask", "body": image_to_b64(req.image or "")}, True
    if t == "turnstile":
        meta = {"action": req.action or ""}
        if req.cdata:
            meta["cdata"] = req.cdata
        return {"type": "AntiTurnstileTaskProxyLess", "websiteURL": req.url,
                "websiteKey": req.sitekey or "", "metadata": meta}, False
    if t == "recaptchav3" or (t == "recaptcha" and req.version == "v3"):
        tt = "ReCaptchaV3EnterpriseTaskProxyLess" if ent else "ReCaptchaV3TaskProxyLess"
        return {"type": tt, "websiteURL": req.url, "websiteKey": req.sitekey or "",
                "pageAction": req.action or "verify"}, False
    if t == "recaptcha":
        tt = "ReCaptchaV2EnterpriseTaskProxyLess" if ent else "ReCaptchaV2TaskProxyLess"
        return {"type": tt, "websiteURL": req.url, "websiteKey": req.sitekey or ""}, False
    if t == "hcaptcha":
        tt = "HCaptchaEnterpriseTaskProxyLess" if ent else "HCaptchaTaskProxyLess"
        return {"type": tt, "websiteURL": req.url, "websiteKey": req.sitekey or ""}, False
    if t in ("funcaptcha", "arkose"):
        return {"type": "FunCaptchaTaskProxyLess", "websiteURL": req.url,
                "websitePublicKey": req.public_key or req.sitekey or ""}, False
    if t == "geetest":
        if req.captcha_id:
            return {"type": "GeeTestTaskProxyLess", "websiteURL": req.url, "captchaId": req.captcha_id}, False
        return {"type": "GeeTestTaskProxyLess", "websiteURL": req.url,
                "gt": req.gt or "", "challenge": req.challenge or ""}, False
    if t == "datadome":
        task = {"type": "DatadomeSliderTask", "websiteURL": req.url, "captchaUrl": req.url,
                "userAgent": req.user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"}
        if req.proxy:
            task["proxy"] = req.proxy
        return task, False
    if t == "awswaf":
        return {"type": "AntiAwsWafTaskProxyLess", "websiteURL": req.url}, False
    if t == "cloudflare":
        return {"type": "AntiCloudflareTask", "websiteURL": req.url, "proxy": req.proxy or ""}, False
    raise ValueError(f"no capsolver mapping for type={t}")

def capsolver_solve(req):
    if not CAPSOLVER_API_KEY:
        return {"solved": False, "error": "no CAPSOLVER_API_KEY", "note": "capsolver_skipped"}
    try:
        task, _ = build_cap_task(req)
    except ValueError as e:
        return {"solved": False, "error": str(e)}
    try:
        cr = _cap_post("createTask", {"clientKey": CAPSOLVER_API_KEY, "task": task})
        if cr.get("errorId"):
            return {"solved": False, "error": cr.get("errorDescription", "createTask error")}
        if cr.get("status") == "ready" and cr.get("solution"):
            tok, sol = _extract_solution(cr["solution"])
            return {"solved": bool(tok), "token": tok, "solution": sol, "note": "capsolver_immediate"}
        tid = cr.get("taskId")
        if not tid:
            return {"solved": False, "error": "no taskId"}
        start = time.time()
        while time.time() - start < req.timeout_s:
            time.sleep(2)
            pr = _cap_post("getTaskResult", {"clientKey": CAPSOLVER_API_KEY, "taskId": tid})
            if pr.get("errorId"):
                return {"solved": False, "error": pr.get("errorDescription", "getTaskResult error")}
            if pr.get("status") == "ready":
                tok, sol = _extract_solution(pr.get("solution", {}))
                return {"solved": bool(tok), "token": tok, "solution": sol, "note": "capsolver"}
            if pr.get("status") == "failed":
                return {"solved": False, "error": pr.get("errorDescription", "capsolver failed")}
        return {"solved": False, "error": "capsolver timeout"}
    except Exception as e:
        return {"solved": False, "error": f"capsolver: {e}"}

# ─── Request model ──────────────────────────────────────────────────────────
class SolveRequest(BaseModel):
    type: str
    url: str = ""
    sitekey: Optional[str] = None
    action: Optional[str] = None
    cdata: Optional[str] = None
    version: Optional[str] = "v2"
    enterprise: bool = False
    image: Optional[str] = None
    bg_image: Optional[str] = None
    puzzle_image: Optional[str] = None
    text: Optional[str] = None
    public_key: Optional[str] = None
    gt: Optional[str] = None
    challenge: Optional[str] = None
    captcha_id: Optional[str] = None
    timeout_s: int = 90
    proxy: Optional[str] = None
    user_agent: Optional[str] = None
    real_page: bool = False  # hCaptcha: open live URL instead of stub inject
    force_capsolver: bool = False  # skip local browser for this request

# ─── Camoufox engine (page-pool) ─────────────────────────────────────────────
class CamoufoxEngine:
    HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" async defer></script>
</head><body><!-- cf turnstile --><p id="ip-display"></p></body></html>"""

    def __init__(self, headless, threads, pages, proxy_support, proxy_file, cleanup_min):
        self.headless = headless
        self.threads = threads
        self.pages = pages
        self.proxy_support = proxy_support
        self.proxy_file = proxy_file
        self.cleanup_min = cleanup_min
        self.page_pool = asyncio.Queue()
        self.browser_args = ["--no-sandbox", "--disable-setuid-sandbox"]
        self.camoufox = None
        self.browser = None
        self.results = {}
        self.contexts = []
        self.proxies = []
        self._pidx = 0
        self.max_task = threads * pages
        self.ready = False

    def _load_proxies(self):
        if not self.proxy_support or not os.path.isfile(self.proxy_file):
            return
        with open(self.proxy_file) as f:
            self.proxies = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        logger.info(f"Loaded {len(self.proxies)} proxies")

    def _next_proxy(self):
        if not self.proxies:
            return None
        p = self.proxies[self._pidx % len(self.proxies)]
        self._pidx += 1
        return p

    async def _ctx(self, proxy=None):
        if not proxy:
            return await self.browser.new_context()
        pr = urlparse(proxy)
        if not pr.scheme or not pr.hostname:
            return await self.browser.new_context()
        server = f"{pr.scheme}://{pr.hostname}:{pr.port}"
        if pr.username and pr.password:
            return await self.browser.new_context(proxy={"server": server, "username": pr.username, "password": pr.password})
        return await self.browser.new_context(proxy={"server": server})

    async def start(self):
        from camoufox import DefaultAddons
        from camoufox.async_api import AsyncCamoufox
        self._load_proxies()
        self.camoufox = AsyncCamoufox(headless=self.headless, exclude_addons=[DefaultAddons.UBO], args=self.browser_args)
        self.browser = await self.camoufox.start()
        await self._build_pool()
        self.ready = True
        logger.success(f"Camoufox pool ready: {self.page_pool.qsize()} pages")
        asyncio.create_task(self._cleanup_expired())
        asyncio.create_task(self._periodic_restart(self.cleanup_min))

    async def stop(self):
        try:
            await self.browser.close()
        except Exception:
            pass

    async def _build_pool(self):
        self.contexts = []
        self._pidx = 0
        for _ in range(self.threads):
            proxy = self._next_proxy() if self.proxy_support else None
            ctx = await self._ctx(proxy)
            self.contexts.append(ctx)
            for _ in range(self.pages):
                page = await ctx.new_page()
                await self.page_pool.put((page, ctx))

    async def _cleanup_expired(self):
        while True:
            await asyncio.sleep(300)
            now = time.time()
            for tid in list(self.results.keys()):
                res = self.results.get(tid)
                if not isinstance(res, dict):
                    continue
                age = now - res.get("start_time", now)
                if res.get("status") == "process" and age > 300:
                    self.results[tid] = {"status": "error", "value": "timeout",
                                         "message": "task timeout 300s", "start_time": res.get("start_time", now)}
                elif res.get("status") != "process" and age > 600:
                    self.results.pop(tid, None)

    async def _periodic_restart(self, minutes):
        while True:
            await asyncio.sleep(minutes * 60)
            collected = []
            try:
                while True:
                    collected.append(self.page_pool.get_nowait())
            except asyncio.QueueEmpty:
                pass
            deadline = time.time() + 60
            while len(collected) < self.max_task and time.time() < deadline:
                try:
                    collected.append(await asyncio.wait_for(self.page_pool.get(), timeout=max(0.1, deadline - time.time())))
                except asyncio.TimeoutError:
                    break
            old = list(self.contexts)
            self.contexts = []
            for page, _ in collected:
                try: await page.close()
                except Exception: pass
            for ctx in old:
                try: await ctx.close()
                except Exception: pass
            try:
                while True:
                    sp, _ = self.page_pool.get_nowait()
                    try: await sp.close()
                    except Exception: pass
            except asyncio.QueueEmpty:
                pass
            try:
                await self._build_pool()
                logger.success(f"Pool restarted: {self.page_pool.qsize()} pages")
            except Exception as e:
                logger.error(f"Rebuild failed: {e}, restarting browser")
                try:
                    await self.browser.close()
                except Exception:
                    pass
                self.browser = await self.camoufox.start()
                await self._build_pool()

    # ── Turnstile (in-session, most reliable) ──
    async def solve_turnstile(self, task_id, url, sitekey, action=None, cdata=None):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            url_slash = url if url.endswith("/") else url + "/"
            div = (f'<div class="cf-turnstile" style="background:white;" data-sitekey="{sitekey}"'
                   + (f' data-action="{action}"' if action else "")
                   + (f' data-cdata="{cdata}"' if cdata else "") + "></div>")
            page_data = self.HTML.replace("<!-- cf turnstile -->", div)
            for rnd in range(1, 3):
                if rnd > 1 and self.proxy_support and self.proxies:
                    proxy = self._next_proxy()
                    try:
                        nc = await self._ctx(proxy)
                        np_ = await nc.new_page()
                        try: await page.close()
                        except Exception: pass
                        try: await ctx.close()
                        except Exception: pass
                        page, ctx = np_, nc
                    except Exception:
                        pass
                try: await page.unroute_all()
                except Exception: pass
                await page.route(url_slash, lambda route: route.fulfill(body=page_data, status=200))
                await page.goto(url_slash)
                try:
                    await page.eval_on_selector("//div[@class='cf-turnstile']", "el => el.style.width = '70px'")
                except Exception:
                    pass
                for _ in range(80):
                    try:
                        val = await page.input_value("[name=cf-turnstile-response]", timeout=400)
                        if val == "":
                            await page.locator("//div[@class='cf-turnstile']").click(timeout=400)
                            await asyncio.sleep(0.3)
                        else:
                            self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3), "value": val}
                            return
                    except Exception:
                        pass
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "message": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await page.unroute_all()
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── cf_clearance ──
    async def solve_clearance(self, task_id, url, timeout=30):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            ua = await page.evaluate("navigator.userAgent")
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            deadline = time.time() + timeout
            cf = None
            while time.time() < deadline:
                title = await page.title()
                cookie = next((c for c in await ctx.cookies() if c["name"] == "cf_clearance"), None)
                if cookie and "just a moment" not in title.lower():
                    cf = cookie["value"]
                    break
                await asyncio.sleep(1)
            if cf:
                cookies = await ctx.cookies()
                self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3),
                    "cf_clearance": cf, "user_agent": ua,
                    "cookies": "; ".join(f"{c['name']}={c['value']}" for c in cookies)}
            else:
                self.results[task_id] = {"status": "error", "value": "clearance_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await ctx.clear_cookies()
            except Exception: pass
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── aws-waf-token ──
    async def solve_aws(self, task_id, url, timeout=30):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            deadline = time.time() + timeout
            waf = None
            while time.time() < deadline:
                waf = next((c for c in await ctx.cookies() if c["name"] == "aws-waf-token"), None)
                if waf:
                    break
                await asyncio.sleep(1)
            if waf:
                ua = await page.evaluate("navigator.userAgent")
                cookies = await ctx.cookies()
                self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3),
                    "aws_waf_token": waf["value"], "user_agent": ua,
                    "cookies": "; ".join(f"{c['name']}={c['value']}" for c in cookies)}
            else:
                self.results[task_id] = {"status": "error", "value": "waf_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await ctx.clear_cookies()
            except Exception: pass
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── reCAPTCHA v3 (real page, grecaptcha.execute) ──
    async def solve_recaptcha_v3(self, task_id, url, sitekey, action="submit"):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            try:
                await page.wait_for_function(
                    "() => typeof grecaptcha!=='undefined' && typeof grecaptcha.execute==='function'", timeout=15000)
            except Exception:
                await page.evaluate("""(key)=>new Promise((res,rej)=>{const s=document.createElement('script');
                    s.src='https://www.google.com/recaptcha/api.js?render='+key;
                    s.onload=()=>{const i=setInterval(()=>{if(typeof grecaptcha!=='undefined'&&grecaptcha.execute){clearInterval(i);res(1)}},100);
                    setTimeout(()=>{clearInterval(i);rej(0)},10000)};s.onerror=()=>rej(0);document.head.appendChild(s)})""", sitekey)
            token = await page.evaluate("""([key,act])=>new Promise((res,rej)=>{grecaptcha.ready(()=>{
                grecaptcha.execute(key,{action:act}).then(res).catch(rej)})})""", [sitekey, action])
            self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3), "value": token}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "message": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── reCAPTCHA v2 (stub page, checkbox click) ──
    async def solve_recaptcha_v2(self, task_id, url, sitekey):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            html = f"""<html><head><script src="https://www.google.com/recaptcha/api.js" async defer></script></head>
<body><div class="g-recaptcha" data-sitekey="{sitekey}"></div></body></html>"""
            target = (url if url.endswith("/") else url + "/") if url else "https://local.test/"
            try: await page.unroute_all()
            except Exception: pass
            await page.route(target, lambda route: route.fulfill(body=html, status=200))
            await page.goto(target)
            token = ""
            try:
                frame = page.frame_locator("iframe[title*='recaptcha']")
                await frame.locator(".recaptcha-checkbox-border").click(timeout=6000)
                await asyncio.sleep(3)
            except Exception:
                pass
            token = await page.evaluate("document.getElementById('g-recaptcha-response')?.value || ''")
            if token:
                self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3), "value": token}
            else:
                self.results[task_id] = {"status": "error", "value": "captcha_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "message": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await page.unroute_all()
            except Exception: pass
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── hCaptcha (native Camoufox — checkbox / real-page widget) ──
    async def solve_hcaptcha(self, task_id, url, sitekey, timeout=120, real_page=False):
        """Solve hCaptcha locally via Camoufox.

        Strategy:
          A) real_page=True  → open live URL, find existing hCaptcha, click checkbox
          B) default         → inject stub page with sitekey on origin URL (route fulfill)
          C) fallback        → hcaptcha.render() API on blank page at target origin

        Works well on easy checkbox challenges with clean residential IP.
        Image-grid challenges usually fail without paid vision solver.
        """
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        token = ""
        err = ""
        try:
            if not sitekey:
                raise ValueError("hcaptcha needs sitekey")
            base = (url or "https://accounts.hcaptcha.com").strip()
            if not base.startswith("http"):
                base = "https://" + base
            # keep origin for domain binding of the token
            parsed = urlparse(base)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            target = base if base.endswith("/") else base + "/"

            async def _read_token():
                """Pull response token from textarea / data-hcaptcha-response / callback."""
                js = """() => {
                    const areas = [
                      ...document.querySelectorAll('textarea[name="h-captcha-response"]'),
                      ...document.querySelectorAll('textarea[name="g-recaptcha-response"]'),
                      ...document.querySelectorAll('[data-hcaptcha-response]'),
                      ...document.querySelectorAll('iframe[data-hcaptcha-response]'),
                    ];
                    for (const el of areas) {
                      const v = el.value || el.getAttribute('data-hcaptcha-response') || '';
                      if (v && v.length > 20) return v;
                    }
                    // widget container attribute
                    const w = document.querySelector('[data-hcaptcha-widget-id]');
                    if (w) {
                      const v = w.getAttribute('data-hcaptcha-response') || '';
                      if (v && v.length > 20) return v;
                    }
                    if (window.__hcaptcha_token && window.__hcaptcha_token.length > 20)
                      return window.__hcaptcha_token;
                    return '';
                }"""
                try:
                    return await page.evaluate(js) or ""
                except Exception:
                    return ""

            async def _click_checkbox():
                """Click hCaptcha checkbox inside iframe (several selectors)."""
                selectors = [
                    "iframe[src*='hcaptcha.com'][src*='frame=checkbox']",
                    "iframe[src*='newassets.hcaptcha.com']",
                    "iframe[title*='checkbox' i]",
                    "iframe[data-hcaptcha-widget-id]",
                    "iframe[src*='hcaptcha.com']",
                ]
                for sel in selectors:
                    try:
                        n = await page.locator(sel).count()
                        if n == 0:
                            continue
                        frame = page.frame_locator(sel).first
                        for inner in (
                            "#checkbox",
                            "div#checkbox",
                            ".check",
                            "[role='checkbox']",
                            "#anchor-state",
                            "body",
                        ):
                            try:
                                box = frame.locator(inner).first
                                await box.wait_for(state="visible", timeout=2500)
                                await box.click(timeout=2500, force=True)
                                logger.info(f"hcaptcha clicked {sel} → {inner}")
                                return True
                            except Exception:
                                continue
                        try:
                            await page.locator(sel).first.click(timeout=2000, force=True)
                            logger.info(f"hcaptcha clicked iframe box {sel}")
                            return True
                        except Exception:
                            pass
                    except Exception:
                        continue
                return False

            async def _poll_token(seconds, early_challenge_fail=True):
                deadline = time.time() + seconds
                clicked = False
                challenge_seen_at = None
                while time.time() < deadline:
                    tok = await _read_token()
                    if tok:
                        return tok
                    # challenge iframe present → image grid, local can't solve
                    try:
                        ch = await page.locator("iframe[src*='frame=challenge']").count()
                        if ch > 0:
                            if challenge_seen_at is None:
                                challenge_seen_at = time.time()
                            # give 6s for auto-pass, then bail (free pool)
                            if early_challenge_fail and (time.time() - challenge_seen_at) > 6:
                                raise RuntimeError("image_challenge")
                    except RuntimeError:
                        raise
                    except Exception:
                        pass
                    if not clicked or (int(time.time() - t0) % 4 == 0):
                        try:
                            clicked = await _click_checkbox() or clicked
                        except Exception:
                            pass
                    await asyncio.sleep(0.45)
                return await _read_token()

            # ── A) real page ──
            if real_page:
                await page.goto(base, wait_until="domcontentloaded", timeout=45000)
                await asyncio.sleep(1.5)
                # inject callback sniffer
                await page.evaluate(
                    """() => {
                    window.__hcaptcha_token = '';
                    const wrap = (name) => {
                      try {
                        if (window.hcaptcha && window.hcaptcha.render && !window.__hc_wrapped) {
                          const orig = window.hcaptcha.render.bind(window.hcaptcha);
                          window.hcaptcha.render = function(el, opts) {
                            opts = opts || {};
                            const prev = opts.callback;
                            opts.callback = function(t) {
                              window.__hcaptcha_token = t || '';
                              if (typeof prev === 'function') prev(t);
                              if (typeof prev === 'string' && window[prev]) window[prev](t);
                            };
                            return orig(el, opts);
                          };
                          window.__hc_wrapped = true;
                        }
                      } catch(e) {}
                    };
                    wrap();
                    setInterval(wrap, 500);
                }"""
                )
                token = await _poll_token(min(timeout, 90))
            else:
                # ── B) stub inject on target origin ──
                html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<script src="https://js.hcaptcha.com/1/api.js?render=explicit&onload=__onHcaptchaLoad" async defer></script>
<script>
window.__hcaptcha_token = '';
window.__onHcaptchaLoad = function() {{
  try {{
    hcaptcha.render('hc-box', {{
      sitekey: '{sitekey}',
      size: 'normal',
      callback: function(t) {{ window.__hcaptcha_token = t || ''; }},
      'expired-callback': function() {{ window.__hcaptcha_token = ''; }},
      'error-callback': function(e) {{ window.__hcaptcha_err = String(e||'err'); }}
    }});
  }} catch(e) {{ window.__hcaptcha_err = String(e); }}
}};
</script>
</head>
<body style="margin:40px;background:#fff">
<div id="hc-box"></div>
<textarea id="dump" name="h-captcha-response" style="width:1px;height:1px;opacity:0"></textarea>
</body></html>"""
                try:
                    await page.unroute_all()
                except Exception:
                    pass
                # fulfill exact URL + origin root so relative script loads ok
                async def _fulfill(route):
                    await route.fulfill(
                        status=200,
                        content_type="text/html; charset=utf-8",
                        body=html,
                    )

                await page.route(target, _fulfill)
                # also catch bare origin/
                root = origin.rstrip("/") + "/"
                if root != target:
                    await page.route(root, _fulfill)
                try:
                    await page.goto(target, wait_until="domcontentloaded", timeout=45000)
                except Exception as e1:
                    err = f"goto_stub:{e1}"
                    try:
                        await page.goto(root, wait_until="domcontentloaded", timeout=30000)
                    except Exception as e2:
                        raise RuntimeError(f"goto failed: {e1} / {e2}")

                # wait for hcaptcha api
                try:
                    await page.wait_for_function(
                        "() => typeof hcaptcha !== 'undefined' && typeof hcaptcha.render === 'function'",
                        timeout=20000,
                    )
                except Exception:
                    # manual script inject fallback
                    await page.evaluate(
                        """(key) => new Promise((res, rej) => {
                        if (typeof hcaptcha !== 'undefined') return res(1);
                        const s = document.createElement('script');
                        s.src = 'https://js.hcaptcha.com/1/api.js?render=explicit';
                        s.onload = () => {
                          const i = setInterval(() => {
                            if (typeof hcaptcha !== 'undefined') { clearInterval(i); res(1); }
                          }, 100);
                          setTimeout(() => { clearInterval(i); rej('hcaptcha api timeout'); }, 15000);
                        };
                        s.onerror = () => rej('script load fail');
                        document.head.appendChild(s);
                    })""",
                        sitekey,
                    )
                    await page.evaluate(
                        """(key) => {
                        window.__hcaptcha_token = '';
                        if (!document.getElementById('hc-box')) {
                          const d = document.createElement('div'); d.id='hc-box'; document.body.appendChild(d);
                        }
                        hcaptcha.render('hc-box', {
                          sitekey: key,
                          callback: (t) => { window.__hcaptcha_token = t || ''; }
                        });
                    }""",
                        sitekey,
                    )

                await asyncio.sleep(1.2)
                # debug snapshot of frames
                try:
                    frames = [f.url[:120] for f in page.frames]
                    logger.info(f"hcaptcha frames({len(frames)}): {frames[:8]}")
                    has_api = await page.evaluate("() => typeof hcaptcha !== 'undefined'")
                    hc_err = await page.evaluate("() => window.__hcaptcha_err || ''")
                    logger.info(f"hcaptcha api={has_api} err={hc_err!r}")
                except Exception as e:
                    logger.warning(f"hcaptcha debug fail: {e}")

                token = await _poll_token(min(timeout, 100))

                # ── C) if still empty, try execute/render again ──
                if not token:
                    try:
                        await page.evaluate(
                            """(key) => {
                            window.__hcaptcha_token = window.__hcaptcha_token || '';
                            try {
                              const id = hcaptcha.render('hc-box', {
                                sitekey: key,
                                callback: (t) => { window.__hcaptcha_token = t || ''; }
                              });
                              window.__hc_id = id;
                            } catch(e) {
                              try { hcaptcha.execute(window.__hc_id); } catch(e2) {}
                            }
                        }""",
                            sitekey,
                        )
                        await _click_checkbox()
                        token = await _poll_token(25)
                    except Exception as e:
                        err = f"{err}|rerender:{e}"

            if token and len(token) > 20:
                self.results[task_id] = {
                    "status": "success",
                    "elapsed_time": round(time.time() - t0, 3),
                    "value": token,
                    "note": "camoufox_hcaptcha",
                }
            else:
                # detect challenge type for better error
                challenge = False
                try:
                    challenge = (await page.locator("iframe[src*='frame=challenge']").count()) > 0
                except Exception:
                    pass
                # dump fail artifacts
                try:
                    import pathlib
                    d = pathlib.Path("/tmp/hc_fail")
                    d.mkdir(exist_ok=True)
                    ts = int(time.time())
                    await page.screenshot(path=str(d / f"{ts}.png"), full_page=True)
                    (d / f"{ts}.html").write_text(await page.content(), encoding="utf-8", errors="ignore")
                    frames = [f.url for f in page.frames]
                    (d / f"{ts}.frames.txt").write_text("\n".join(frames), encoding="utf-8")
                    logger.warning(f"hcaptcha fail dump → {d}/{ts}.* frames={len(frames)}")
                except Exception as e:
                    logger.warning(f"hcaptcha dump fail: {e}")
                msg = "image_challenge" if challenge else (err or "captcha_fail")
                self.results[task_id] = {
                    "status": "error",
                    "value": msg,
                    "message": msg,
                    "elapsed_time": round(time.time() - t0, 3),
                }
        except asyncio.CancelledError:
            # hard-cancelled by await timeout — still mark result + free page
            try:
                if task_id in self.results and self.results[task_id].get("status") == "process":
                    self.results[task_id] = {
                        "status": "error",
                        "value": "cancelled",
                        "message": "cancelled",
                        "elapsed_time": round(time.time() - t0, 3),
                    }
            except Exception:
                pass
            raise
        except Exception as e:
            self.results[task_id] = {
                "status": "error",
                "value": "captcha_fail",
                "message": str(e),
                "elapsed_time": round(time.time() - t0, 3),
            }
        finally:
            try:
                await page.unroute_all()
            except Exception:
                pass
            try:
                await page.goto("about:blank")
            except Exception:
                pass
            try:
                if ctx in self.contexts:
                    await self.page_pool.put((page, ctx))
            except Exception:
                pass


engine: Optional[CamoufoxEngine] = None
app = FastAPI(title="Universal Captcha Solver FEB-FRMN", version="5.1")
solve_log = []


@app.on_event("startup")
async def _startup():
    global engine
    engine = CamoufoxEngine(HEADLESS, THREADS, PAGES_PER_THREAD, PROXY_SUPPORT, PROXY_FILE, CLEANUP_MIN)
    await engine.start()

@app.on_event("shutdown")
async def _shutdown():
    if engine:
        await engine.stop()


# ─── async browser-task dispatcher (returns task_id) ──
async def _spawn_browser(req: SolveRequest):
    if not engine or not engine.ready:
        raise HTTPException(503, "browser engine not ready")
    if engine.page_pool.qsize() == 0:
        raise HTTPException(429, "pool full, retry")
    tid = str(uuid.uuid4())
    engine.results[tid] = {"status": "process", "start_time": time.time()}
    t = req.type.lower()
    if t == "turnstile":
        task = asyncio.create_task(engine.solve_turnstile(tid, req.url, req.sitekey, req.action, req.cdata))
    elif t == "cloudflare":
        task = asyncio.create_task(engine.solve_clearance(tid, req.url, req.timeout_s))
    elif t == "awswaf":
        task = asyncio.create_task(engine.solve_aws(tid, req.url, req.timeout_s))
    elif t == "recaptchav3" or (t == "recaptcha" and req.version == "v3"):
        task = asyncio.create_task(engine.solve_recaptcha_v3(tid, req.url, req.sitekey, req.action or "submit"))
    elif t == "recaptcha":
        task = asyncio.create_task(engine.solve_recaptcha_v2(tid, req.url, req.sitekey))
    elif t == "hcaptcha":
        task = asyncio.create_task(
            engine.solve_hcaptcha(
                tid,
                req.url,
                req.sitekey,
                timeout=req.timeout_s or 120,
                real_page=bool(req.real_page),
            )
        )
    else:
        engine.results.pop(tid, None)
        return None
    engine.tasks = getattr(engine, "tasks", {})
    engine.tasks[tid] = task
    return tid


async def _await_task(tid, timeout_s):
    deadline = time.time() + max(5, int(timeout_s or 60))
    while time.time() < deadline:
        res = engine.results.get(tid)
        if res and res.get("status") != "process":
            engine.results.pop(tid, None)
            try:
                getattr(engine, "tasks", {}).pop(tid, None)
            except Exception:
                pass
            return res
        await asyncio.sleep(0.4)
    # hard stop stuck browser task so page returns to pool
    task = getattr(engine, "tasks", {}).pop(tid, None)
    if task and not task.done():
        task.cancel()
        try:
            # Do NOT use shield() here — cancelled task must finish its finally
            # (return page to pool). Catch CancelledError so it never bubbles to FastAPI.
            await asyncio.wait_for(task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass
    stuck = engine.results.pop(tid, None) or {}
    if stuck.get("status") and stuck.get("status") != "process":
        return stuck
    return {"status": "error", "value": "timeout", "message": "await timeout"}


def _normalize(res, ctype):
    """Map engine result → uniform {solved, token, ...}."""
    ok = res.get("status") == "success"
    out = {"solved": ok, "type": ctype}
    # Only trust value as token on success — error paths reuse "value" for reason codes
    tok = None
    if ok:
        tok = res.get("value") or res.get("aws_waf_token") or res.get("cf_clearance")
        if isinstance(tok, str) and tok.lower() in {
            "timeout", "captcha_fail", "image_challenge", "clearance_fail", "waf_fail", ""
        }:
            tok = None
            ok = False
            out["solved"] = False
    if tok:
        out["token"] = tok
    for k in ("cf_clearance", "aws_waf_token", "user_agent", "cookies", "elapsed_time", "message", "note"):
        if k in res:
            out[k] = res[k]
    if not ok and "error" not in out:
        out["error"] = res.get("message") or res.get("value") or "failed"
    return out


# ─── unified dispatcher ──
async def dispatch(req: SolveRequest):
    t = req.type.lower()
    # 1) free local (no browser)
    if t == "math":
        if req.text:
            return solve_math(req.text)
        if req.image:
            return await asyncio.to_thread(solve_ocr, req.image, True)
        return {"solved": False, "error": "math needs text or image"}
    if t in ("text", "image"):
        return await asyncio.to_thread(solve_ocr, req.image, False)
    if t == "slider":
        return await asyncio.to_thread(solve_slider, req.bg_image, req.puzzle_image)
    # 2) demo tokens
    if req.sitekey in DEMO_TOKENS:
        return {"solved": True, "token": DEMO_TOKENS[req.sitekey], "note": "demo_key"}
    # 3) browser-solvable via Camoufox (local-first)
    # hCaptcha is local-first now (Capsolver blocks many sitekeys incl. Forge)
    browser_types = ("turnstile", "recaptcha", "recaptchav3", "cloudflare", "awswaf", "hcaptcha")
    # Turnstile: local stub-page tokens (~666 chars) get rejected by real sites
    # (e.g. accounts.x.ai). Prefer Capsolver when key is present unless
    # TURNSTILE_LOCAL=1 is set. force_capsolver=true on the request also skips local.
    force_cap = bool(getattr(req, "force_capsolver", False))
    prefer_cap_ts = (
        t == "turnstile"
        and bool(CAPSOLVER_API_KEY)
        and SOLVER_MODE in ("auto", "capsolver")
        and (force_cap or os.getenv("TURNSTILE_LOCAL", "0") != "1")
    )
    if prefer_cap_ts:
        cap = await asyncio.to_thread(capsolver_solve, req)
        cap.setdefault("type", req.type)
        if cap.get("solved"):
            return cap
        # if Capsolver fails, fall through to local as last resort
    if t in browser_types and SOLVER_MODE in ("auto", "local") and not force_cap:
        tid = await _spawn_browser(req)
        if tid:
            res = await _await_task(tid, req.timeout_s)
            norm = _normalize(res, req.type)
            if norm.get("solved"):
                note = res.get("note") or "camoufox_local"
                norm["note"] = note
                tok = norm.get("token") or ""
                # Short stub tokens: try Capsolver fallback instead of returning junk
                if (
                    t == "turnstile"
                    and CAPSOLVER_API_KEY
                    and SOLVER_MODE in ("auto", "capsolver")
                    and len(tok) < 700
                ):
                    pass  # fall through
                else:
                    return norm
            elif SOLVER_MODE == "local":
                return norm
            # hCaptcha: only fall through to Capsolver if explicitly wanted
            # (many sitekeys return "We don't support this service")
            elif t == "hcaptcha" and os.getenv("HCAPTCHA_CAPSOLVER_FALLBACK", "0") != "1":
                return norm
            # else fall through to capsolver
    # 4) Capsolver universal fallback (funcaptcha/geetest/datadome + failed browser types)
    if SOLVER_MODE in ("auto", "capsolver"):
        cap = await asyncio.to_thread(capsolver_solve, req)
        cap.setdefault("type", req.type)
        return cap
    return {"solved": False, "error": f"no solver available for {t}"}


# ─── API ──
@app.get("/health")
async def health():
    return {"status": "ok", "supported": SUPPORTED, "engine": "camoufox",
            "pool": engine.page_pool.qsize() if engine and engine.ready else 0,
            "capsolver": bool(CAPSOLVER_API_KEY), "mode": SOLVER_MODE,
            "hcaptcha_local": True,
            "version": "5.1", "by": "FEB-FRMN", "saweria": "https://saweria.co/febfrmn"}

@app.get("/status")
async def status():
    solved = sum(1 for e in solve_log if e.get("solved"))
    return {"log_size": len(solve_log), "solved": solved, "mode": SOLVER_MODE,
            "pool": engine.page_pool.qsize() if engine and engine.ready else 0,
            "capsolver_enabled": bool(CAPSOLVER_API_KEY)}

@app.get("/logs")
async def logs(lines: int = 50):
    return {"total": len(solve_log), "entries": solve_log[-lines:]}

@app.post("/solve")
async def solve(req: SolveRequest):
    t0 = time.time()
    if req.url:
        check_ssrf(req.url)
    if req.type.lower() not in SUPPORTED:
        raise HTTPException(400, f"Unsupported type: {req.type}. Supported: {SUPPORTED}")
    logger.info(f"Solve {req.type} sitekey={str(req.sitekey)[:12] if req.sitekey else '-'} url={req.url[:50]}")
    result = await dispatch(req)
    result["type"] = req.type
    result["elapsed"] = round(time.time() - t0, 2)
    solve_log.append({"type": req.type, "solved": result.get("solved", False),
                      "note": result.get("note", ""), "elapsed": result["elapsed"]})
    if len(solve_log) > 100:
        solve_log.pop(0)
    return result

# ─── Boterdrop-compatible async endpoints (backward-compat with bai-farmer) ──
@app.get("/turnstile")
async def r_turnstile(url: str = Query(...), sitekey: str = Query(...),
                      action: str = Query(None), cdata: str = Query(None)):
    tid = await _spawn_browser(SolveRequest(type="turnstile", url=url, sitekey=sitekey, action=action, cdata=cdata))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.get("/clearance")
async def r_clearance(url: str = Query(...), timeout: int = Query(30)):
    tid = await _spawn_browser(SolveRequest(type="cloudflare", url=url, timeout_s=timeout))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.get("/aws-token")
async def r_aws(url: str = Query(...), timeout: int = Query(30)):
    tid = await _spawn_browser(SolveRequest(type="awswaf", url=url, timeout_s=timeout))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.api_route("/recaptchaV3", methods=["GET", "POST"])
async def r_recaptcha(url: str = Query(...), sitekey: str = Query(...), action: str = Query("submit")):
    tid = await _spawn_browser(SolveRequest(type="recaptchav3", url=url, sitekey=sitekey, action=action))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.get("/result")
async def r_result(task_id: str = Query(..., alias="id")):
    if not engine or task_id not in engine.results:
        return JSONResponse({"status": "error", "message": "task_id invalid/expired"}, status_code=404)
    res = engine.results[task_id]
    if res.get("status") == "process":
        if time.time() - res.get("start_time", time.time()) > 300:
            engine.results[task_id] = {"status": "error", "value": "timeout"}
        else:
            return JSONResponse(res, status_code=202)
    res = engine.results.pop(task_id)
    code = 200 if res.get("status") == "success" else (408 if res.get("value") == "timeout" else 422)
    return JSONResponse(res, status_code=code)


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════╗
║        UNIVERSAL CAPTCHA SOLVER v5.1              ║
║        Camoufox engine + free local + Capsolver   ║
║        BY FEB-FRMN                                ║
║        https://saweria.co/febfrmn                 ║
╚══════════════════════════════════════════════════╝
  http://{HOST}:{PORT}   mode={SOLVER_MODE}  headless={HEADLESS}
  camoufox : turnstile | recaptcha | hcaptcha | cloudflare | awswaf
  free     : math | text | image (OCR) | slider (opencv)
  capsolver: funcaptcha | geetest | datadome (+ optional hcaptcha fallback)
  compat   : GET /turnstile /clearance /aws-token /recaptchaV3 → poll GET /result?id=
""")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
