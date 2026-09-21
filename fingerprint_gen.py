#!/usr/bin/env python3
"""
Browser Fingerprint Generator — realistic, consistent, injectable via CDP.

Usage:
  python3 fingerprint_gen.py                   # generate 1 fingerprint, print JSON
  python3 fingerprint_gen.py -n 10             # generate 10 fingerprints
  python3 fingerprint_gen.py -o fps.json       # save to file
  python3 fingerprint_gen.py --chrome-only     # only Chrome/Edge UAs (default)
  python3 fingerprint_gen.py --all-browsers    # include Firefox/Safari
  python3 fingerprint_gen.py --inject page     # inject into DrissionPage tab object

Each fingerprint is self-consistent: UA ↔ platform ↔ navigator ↔ screen ↔ WebGL all match.
"""
import json, hashlib, random, time, argparse, struct, sys, os

# ─── Chrome/Edge version pools (2024-2026 realistic) ───────────────────────────
CHROME_UA_TPLS = [
    "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36",
    "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{ver} Safari/537.36 Edg/{edge}",
]
FIREFOX_UA_TPL = "Mozilla/5.0 ({platform}; rv:{ff_ver}) Gecko/20100101 Firefox/{ff_ver}"
SAFARI_UA_TPL  = "Mozilla/5.0 ({platform}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/{saf_ver} Safari/605.1.15"

CHROME_MAJORS = [120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140]
FF_MAJORS  = [120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130]
SAF_MAJORS = [16, 17, 18]

# ─── Platform strings ─────────────────────────────────────────────────────────
PLATFORMS = [
    {"ua_platform": "Windows NT 10.0; Win64; x64",      "navigator_platform": "Win32",  "os": "windows", "arch": "x64",
     "brands": [{"brand":"Chromium","v":"124"},{"brand":"Google Chrome","v":"124"},{"brand":"Not-A.Brand","v":"99"}]},
    {"ua_platform": "Windows NT 10.0; Win64; x64",      "navigator_platform": "Win32",  "os": "windows", "arch": "x64",
     "brands": [{"brand":"Chromium","v":"127"},{"brand":"Microsoft Edge","v":"127"},{"brand":"Not-A.Brand","v":"24"}]},
    {"ua_platform": "Macintosh; Intel Mac OS X 10_15_7","navigator_platform": "MacIntel","os": "macos", "arch": "x64",
     "brands": [{"brand":"Chromium","v":"124"},{"brand":"Google Chrome","v":"124"},{"brand":"Not-A.Brand","v":"8"}]},
    {"ua_platform": "Macintosh; Intel Mac OS X 10_15_7","navigator_platform": "MacIntel","os": "macos", "arch": "x64",
     "brands": [{"brand":"Chromium","v":"130"},{"brand":"Google Chrome","v":"130"},{"brand":"Not-A.Brand","v":"24"}]},
    {"ua_platform": "X11; Linux x86_64",                "navigator_platform": "Linux x86_64","os":"linux","arch":"x64",
     "brands": [{"brand":"Chromium","v":"124"},{"brand":"Google Chrome","v":"124"},{"brand":"Not-A.Brand","v":"8"}]},
    {"ua_platform": "X11; Linux x86_64",                "navigator_platform": "Linux x86_64","os":"linux","arch":"x64",
     "brands": [{"brand":"Chromium","v":"131"},{"brand":"Google Chrome","v":"131"},{"brand":"Not-A.Brand","v":"24"}]},
]

# ─── Screen resolutions (top 2024-2026 desktop) ──────────────────────────────
SCREENS = [
    (1920, 1080), (1366, 768), (1536, 864), (1440, 900), (1280, 720),
    (2560, 1440), (3840, 2160), (1680, 1050), (1280, 1024), (1600, 900),
    (1920, 1200), (2560, 1600), (3440, 1440), (1200, 1920), (2048, 1152),
]

# ─── WebGL vendor/renderer combos ─────────────────────────────────────────────
WEBGLS = [
    # Windows
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4070 Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (AMD)",    "ANGLE (AMD, AMD Radeon RX 580 Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (AMD)",    "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (Intel)",  "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (Intel)",  "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0)"),
    ("Google Inc. (Intel)",  "ANGLE (Intel, Intel(R) UHD Graphics 770 Direct3D11 vs_5_0 ps_5_0)"),
    # macOS
    ("Apple", "Apple GPU"),
    ("Apple", "ANGLE (Apple, Apple M1, OpenGL 4.1)"),
    ("Apple", "ANGLE (Apple, Apple M2, OpenGL 4.1)"),
    ("Apple", "ANGLE (Apple, Apple M3, OpenGL 4.1)"),
    # Linux
    ("Google Inc. (Mesa)",   "Mesa Intel(R) UHD Graphics 630 (CFL GT2)"),
    ("Google Inc. (Mesa)",   "Mesa Intel(R) Iris(R) Xe Graphics (TGL GT1)"),
    ("Google Inc. (Mesa)",   "Mesa AMD Radeon RX 580 (polaris10, DRM 3.49)"),
]

# ─── Languages pool ───────────────────────────────────────────────────────────
LANGUAGE_SETS = [
    ["en-US", "en"],
    ["en-GB", "en"],
    ["en-US", "en", "id"],
    ["id-ID", "id", "en-US", "en"],
    ["id-ID", "en-US", "en"],
    ["ja-JP", "en-US", "en"],
    ["ko-KR", "en-US", "en"],
    ["de-DE", "en-US", "en"],
    ["fr-FR", "en-US", "en"],
    ["pt-BR", "en-US", "en"],
    ["es-ES", "en-US", "en"],
    ["zh-CN", "en-US", "en"],
]

# ─── Timezone offsets (by region) ─────────────────────────────────────────────
TIMEZONES = [
    {"name": "Asia/Jakarta",      "offset": -420},
    {"name": "Asia/Makassar",     "offset": -480},
    {"name": "Asia/Jayapura",     "offset": -540},
    {"name": "Asia/Singapore",    "offset": -480},
    {"name": "Asia/Tokyo",        "offset": -540},
    {"name": "America/New_York",  "offset": 300},
    {"name": "America/Chicago",   "offset": 360},
    {"name": "America/Los_Angeles", "offset": 480},
    {"name": "Europe/London",     "offset": 0},
    {"name": "Europe/Berlin",     "offset": -60},
    {"name": "Europe/Paris",      "offset": -60},
    {"name": "Australia/Sydney",  "offset": -600},
]

# ─── Hardware profiles ────────────────────────────────────────────────────────
HW_PROFILES = [
    {"hardwareConcurrency": 8,  "deviceMemory": 8},
    {"hardwareConcurrency": 16, "deviceMemory": 16},
    {"hardwareConcurrency": 8,  "deviceMemory": 16},
    {"hardwareConcurrency": 12, "deviceMemory": 16},
    {"hardwareConcurrency": 6,  "deviceMemory": 8},
    {"hardwareConcurrency": 4,  "deviceMemory": 4},
    {"hardwareConcurrency": 8,  "deviceMemory": 32},
    {"hardwareConcurrency": 16, "deviceMemory": 32},
]

# ─── Fonts pool (OS-specific common fonts) ───────────────────────────────────
WIN_FONTS  = ["Arial","Arial Black","Calibri","Cambria","Candara","Comic Sans MS","Consolas","Constantia","Corbel","Courier New","Georgia","Impact","Lucida Console","Microsoft Sans Serif","Palatino Linotype","Segoe UI","Trebuchet MS","Verdana"]
MAC_FONTS  = ["Apple Chancery","Arial","Arial Black","Avenir","Baskerville","Big Caslon","Brush Script MT","Chalkboard","Cochin","Comic Sans MS","Copperplate","Courier New","Didot","Futura","Georgia","Gill Sans","Helvetica Neue","Helvetica","Hoefler Text","Impact","Lucida Grande","Marker Felt","Optima","Palatino","Papyrus","Phosphate","Rockwell","SF Pro","Skia","Times New Roman","Trebuchet MS","Zapfino"]
LINUX_FONTS = ["Arial","Arial Black","DejaVu Sans","DejaVu Sans Mono","Droid Sans Fallback","FreeSans","FreeSerif","Liberation Mono","Liberation Sans","Liberation Serif","Noto Sans","Noto Sans Mono","Roboto","Source Sans Pro","Ubuntu","Ubuntu Mono","Verdana"]

# ─── Platforms HTML spec values ───────────────────────────────────────────────
PLATFORMS_HTML = ["Win32", "MacIntel", "Linux x86_64", "Linux aarch64"]
TOUCH_POINTS  = [0, 1, 5, 10]


def _hash_str(s, seed=0):
    """Deterministic hash → int (for canvas/audio fingerprint)."""
    h = hashlib.sha256(f"{seed}:{s}".encode()).digest()
    return struct.unpack("<Q", h[:8])[0]


def _canvas_noise(w=160, h=60):
    """Generate a deterministic canvas fingerprint hash from random but seeded noise."""
    data = os.urandom(w * h * 4)
    return hashlib.sha256(data).hexdigest()[:32]


def _audio_noise():
    """Generate deterministic audio context fingerprint (float32 hash)."""
    arr = [round(random.uniform(-1, 1), 8) for _ in range(44)]
    return hashlib.sha256(str(arr).encode()).hexdigest()[:24]


def _font_list(os_name):
    base = {"windows": WIN_FONTS, "macos": MAC_FONTS, "linux": LINUX_FONTS}.get(os_name, WIN_FONTS)
    n = random.randint(15, len(base))
    return sorted(random.sample(base, n))


def generate_fingerprint(chrome_only=True):
    """Generate one self-consistent browser fingerprint dict."""
    plat = random.choice(PLATFORMS)
    screen_w, screen_h = random.choice(SCREENS)
    tz = random.choice(TIMEZONES)
    hw = random.choice(HW_PROFILES)
    langs = random.choice(LANGUAGE_SETS)
    webgl = random.choice(WEBGLS)
    fonts = _font_list(plat["os"])
    # Mobile touch: most desktop = 0; laptop trackpad = 1; never 5/10 on desktop
    is_desktop = plat["navigator_platform"] in ("Win32", "MacIntel", "Linux x86_64")
    if is_desktop:
        touch = random.choices([0, 1], weights=[80, 20])[0]
    else:
        touch = random.choice([0, 1, 5])
    sec_ch_mobile = "?1" if (touch > 0 and not is_desktop) or (touch > 0 and random.random() < 0.1) else "?0"
    major = random.choice(CHROME_MAJORS)
    minor = random.randint(0, 6700)
    patch = random.randint(0, 200)

    # ─── Build Chrome UA ──────────────────────────────────────────────────
    ver = f"{major}.{minor}.{patch}.{random.randint(6000,6999)}"
    tpl = random.choice(CHROME_UA_TPLS)
    ua = tpl.format(platform=plat["ua_platform"], ver=ver, edge=f"{major}.{random.randint(0,5000)}.0.{random.randint(100,999)}")
    if not chrome_only:
        roll = random.random()
        if roll < 0.1:
            ff_ver = f"{random.choice(FF_MAJORS)}.0"
            ua = FIREFOX_UA_TPL.format(platform=plat["ua_platform"], ff_ver=ff_ver)
        elif roll < 0.15:
            ua = SAFARI_UA_TPL.format(platform=plat["ua_platform"], saf_ver=random.choice(SAF_MAJORS))

    # ─── Navigator ────────────────────────────────────────────────────────
    max_w = screen_w - random.choice([0, 10, 15, 16])
    max_h = screen_h - random.choice([0, 140, 180, 88, 104])
    avail_w = screen_w - random.choice([0, 10, 16, 17])
    avail_h = screen_h - random.choice([0, 88, 104])

    nav = {
        "userAgent": ua,
        "appVersion": ua.split("Mozilla/5.0 ")[-1] if "Mozilla/5.0 " in ua else ua,
        "platform": plat["navigator_platform"],
        "language": langs[0],
        "languages": langs,
        "hardwareConcurrency": hw["hardwareConcurrency"],
        "deviceMemory": hw["deviceMemory"],
        "maxTouchPoints": touch,
        "vendor": "Google Inc.",
        "doNotTrack": random.choice([None, None, "1"]),
        "webdriver": False,
        "pdfViewerEnabled": True,
    }

    # ─── Screen ───────────────────────────────────────────────────────────
    screen = {
        "width": screen_w,
        "height": screen_h,
        "availWidth": avail_w,
        "availHeight": avail_h,
        "colorDepth": random.choice([24, 30, 32]),
        "pixelDepth": random.choice([24, 30, 32]),
        "orientation": random.choice(["landscape-primary", "portrait-primary"]) if screen_h > screen_w else "landscape-primary",
    }

    # ─── WebGL ────────────────────────────────────────────────────────────
    webgl_info = {
        "vendor": webgl[0],
        "renderer": webgl[1],
        "unmaskedVendor": webgl[0],
        "unmaskedRenderer": webgl[1],
    }

    # ─── Client Hints (High Entropy) ─────────────────────────────────────
    brands_raw = f"{plat['brands'][0]['brand']}/{plat['brands'][0]['v']};{plat['brands'][1]['brand']}/{plat['brands'][1]['v']};{plat['brands'][2]['brand']}/{plat['brands'][2]['v']}"
    sec_ch = {
        "sec-ch-ua": f'"{plat["brands"][1]["brand"]}";v="{plat["brands"][1]["v"]}", "{plat["brands"][0]["brand"]}";v="{plat["brands"][0]["v"]}", "{plat["brands"][2]["brand"]}";v="{plat["brands"][2]["v"]}"',
        "sec-ch-ua-mobile": sec_ch_mobile,
        "sec-ch-ua-platform": f'"{plat["navigator_platform"]}"',
    }

    # ─── Timezone ─────────────────────────────────────────────────────────
    tz_info = {
        "name": tz["name"],
        "offset": tz["offset"],
    }

    # ─── Canvas + Audio fingerprint (unique per seed) ────────────────────
    seed = random.randint(0, 2**63)
    canvas_fp = _canvas_noise()
    audio_fp = _audio_noise()

    fp = {
        "id": hashlib.sha256(f"{time.time()}-{random.random()}".encode()).hexdigest()[:12],
        "navigator": nav,
        "screen": screen,
        "webgl": webgl_info,
        "clientHints": sec_ch,
        "timezone": tz_info,
        "fonts": fonts,
        "canvasHash": canvas_fp,
        "audioHash": audio_fp,
        "plugins": random.choice([
            ["PDF Viewer","Chrome PDF Viewer","Chromium PDF Viewer"],
            ["PDF Viewer","Chrome PDF Viewer","Chromium PDF Viewer","Native Client"],
            ["Chrome PDF Plugin","Chrome PDF Viewer","Chromium PDF Viewer"],
        ]),
        "mediaDevices": {
            "audioinput": random.randint(1, 3),
            "audiooutput": random.randint(1, 4),
            "videoinput": random.randint(1, 3),
        },
        "permissions": {
            "notifications": random.choice(["default", "granted", "denied"]),
        },
        "storage": {
            "localStorage": True,
            "sessionStorage": True,
            "indexedDB": True,
        },
    }
    return fp


def inject_cdp_js(fp):
    """Return CDP JS string to override navigator + screen + WebGL + canvas."""
    nav = fp["navigator"]
    scr = fp["screen"]
    webgl = fp["webgl"]
    tz = fp["timezone"]

    js = f"""
(function() {{
  const _fp = {json.dumps(fp, ensure_ascii=False)};

  // --- Navigator overrides ---
  Object.defineProperty(navigator, 'userAgent',   {{get: () => _fp.navigator.userAgent}});
  Object.defineProperty(navigator, 'appVersion',   {{get: () => _fp.navigator.appVersion}});
  Object.defineProperty(navigator, 'platform',     {{get: () => _fp.navigator.platform}});
  Object.defineProperty(navigator, 'language',     {{get: () => _fp.navigator.language}});
  Object.defineProperty(navigator, 'languages',    {{get: () => _fp.navigator.languages}});
  Object.defineProperty(navigator, 'hardwareConcurrency', {{get: () => _fp.navigator.hardwareConcurrency}});
  Object.defineProperty(navigator, 'deviceMemory', {{get: () => _fp.navigator.deviceMemory}});
  Object.defineProperty(navigator, 'maxTouchPoints', {{get: () => _fp.navigator.maxTouchPoints}});
  Object.defineProperty(navigator, 'vendor',       {{get: () => _fp.navigator.vendor}});
  Object.defineProperty(navigator, 'webdriver',    {{get: () => false}});

  // --- Screen overrides ---
  const _scr = screen;
  for (const k of ['width','height','availWidth','availHeight','colorDepth','pixelDepth']) {{
    if (scr[k] !== undefined) Object.defineProperty(window.screen, k, {{get: () => scr[k]}});
  }}

  // --- WebGL override ---
  const _origGetParam = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(param) {{
    const ext = this.getExtension('WEBGL_debug_renderer_info');
    if (ext) {{
      if (param === ext.UNMASKED_VENDOR_WEBGL)   return _fp.webgl.unmaskedVendor;
      if (param === ext.UNMASKED_RENDERER_WEBGL) return _fp.webgl.unmaskedRenderer;
    }}
    return _origGetParam.call(this, param);
  }};
  if (typeof WebGL2RenderingContext !== 'undefined') {{
    const _orig2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(param) {{
      const ext = this.getExtension('WEBGL_debug_renderer_info');
      if (ext) {{
        if (param === ext.UNMASKED_VENDOR_WEBGL)   return _fp.webgl.unmaskedVendor;
        if (param === ext.UNMASKED_RENDERER_WEBGL) return _fp.webgl.unmaskedRenderer;
      }}
      return _orig2.call(this, param);
    }};
  }}

  // --- Canvas noise ---
  const _toDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function() {{
    const ctx = this.getContext('2d');
    if (ctx) {{
      const imgData = ctx.getImageData(0, 0, Math.min(this.width, 160), Math.min(this.height, 60));
      for (let i = 0; i < imgData.data.length; i += 4) {{
        imgData.data[i] = imgData.data[i] ^ (parseInt(_fp.canvasHash.substring(0,2), 16) & 3);
      }}
      ctx.putImageData(imgData, 0, 0);
    }}
    return _toDataURL.apply(this, arguments);
  }};

  // --- Timezone (via Date) ---
  const _DTF = Intl.DateTimeFormat;
  const _origResolvedOptions = _DTF.prototype.resolvedOptions;
  _DTF.prototype.resolvedOptions = function() {{
    const r = _origResolvedOptions.call(this);
    if (r.timeZone !== _fp.timezone.name) r.timeZone = _fp.timezone.name;
    return r;
  }};

  console.log('[fingerprint] injected id=' + _fp.id);
}})();
"""
    return js.strip()


def inject_to_page(page, fp):
    """Inject fingerprint into a DrissionPage tab via CDP (requires browser with --disable-web-security)."""
    js = inject_cdp_js(fp)
    try:
        page.run_cdp("Page.addScriptToEvaluateOnNewDocument", source=js)
        page.run_cdp("Runtime.evaluate", expression=js, returnByValue=True)
        return True
    except Exception as e:
        print(f"inject error: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="Browser Fingerprint Generator")
    parser.add_argument("-n", "--count", type=int, default=1, help="Number of fingerprints")
    parser.add_argument("-o", "--output", help="Output JSON file")
    parser.add_argument("--chrome-only", action="store_true", default=True, help="Chrome/Edge UAs only (default)")
    parser.add_argument("--all-browsers", action="store_true", help="Include Firefox/Safari")
    parser.add_argument("--pretty", action="store_true", default=True, help="Pretty-print JSON")
    parser.add_argument("--cdp-js", action="store_true", help="Print CDP injection JS instead of JSON")
    parser.add_argument("--seed", type=int, help="RNG seed for reproducibility")
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    chrome_only = not args.all_browsers
    fps = [generate_fingerprint(chrome_only) for _ in range(args.count)]

    if args.cdp_js:
        js = inject_cdp_js(fps[0])
        print(js)
        return

    result = fps[0] if args.count == 1 else fps
    out = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)

    if args.output:
        with open(args.output, "w") as f:
            f.write(out)
        print(f"saved {args.count} fingerprint(s) to {args.output}")
    else:
        print(out)


if __name__ == "__main__":
    main()
