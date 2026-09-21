#!/usr/bin/env python3
"""Warm Castle token pool — one Camoufox page mints many tokens (~200ms each).

Background daemon keeps N warm pages on accounts.x.ai (email form open),
then serves createRequestToken via Unix HTTP / JSON-RPC over HTTP.

CLI:
  python castle_pool.py serve [--workers 2] [--port 8878]
  python castle_pool.py get [--pk PK] [--url URL] [--timeout 20]
  python castle_pool.py status
  python castle_pool.py stop

Env:
  CASTLE_POOL_URL   default http://127.0.0.1:8878
  CASTLE_POOL_WORKERS default 2
  CASTLE_POOL_PORT    default 8878
"""
from __future__ import annotations

import argparse
import json
import os
import queue
import signal
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_PK = "pk_p8GGWvD3TmFJZRsX3BQcqAv9aFVispNz"
DEFAULT_URL = "https://accounts.x.ai/sign-up?redirect=grok-com&return_to=%2F"
DEFAULT_PORT = int(os.getenv("CASTLE_POOL_PORT", "8878"))
DEFAULT_WORKERS = max(1, min(8, int(os.getenv("CASTLE_POOL_WORKERS", "8"))))
POOL_URL = os.getenv("CASTLE_POOL_URL", f"http://127.0.0.1:{DEFAULT_PORT}").rstrip("/")
PID_FILE = Path(__file__).resolve().parent / "run" / "castle_pool.pid"
LOG_FILE = Path(__file__).resolve().parent / "run" / "castle_pool.log"
STATE_FILE = Path(__file__).resolve().parent / "run" / "castle_pool_state.json"

# Fiber walk — same as castle_harvest.py
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
    out.via = 'react_fiber_pool';
  } catch (e) {
    out.error = String(e && e.message || e);
  }
  return out;
}"""


def _log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def _proxy_dict(proxy: str | None) -> dict | None:
    if not proxy:
        return None
    p = urlparse(proxy if "://" in proxy else f"http://{proxy}")
    if not p.hostname or not p.port:
        return None
    d: dict = {"server": f"{p.scheme or 'http'}://{p.hostname}:{p.port}"}
    if p.username:
        d["username"] = p.username
    if p.password:
        d["password"] = p.password
    return d


def open_email_form(page) -> None:
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
    page.evaluate(
        """() => {
          const t = [...document.querySelectorAll('button, a, [role=button]')].find(b =>
            /sign up with email/i.test(b.innerText || '')
          );
          if (t) t.click();
        }"""
    )
    page.wait_for_timeout(1500)


@dataclass
class WorkerStats:
    id: int
    ready: bool = False
    tokens: int = 0
    errors: int = 0
    last_ms: float = 0.0
    last_error: str | None = None
    restarts: int = 0


@dataclass
class PoolState:
    started_at: float = field(default_factory=time.time)
    workers: int = 0
    ready: int = 0
    tokens: int = 0
    errors: int = 0
    last_ms: float = 0.0
    via: str = "pool"


class CastleWorker(threading.Thread):
    def __init__(
        self,
        wid: int,
        req_q: queue.Queue,
        page_url: str,
        proxy: str | None = None,
    ):
        super().__init__(daemon=True, name=f"castle-w{wid}")
        self.wid = wid
        self.req_q = req_q
        self.page_url = page_url
        self.proxy = proxy
        self.stats = WorkerStats(id=wid)
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                self._session_loop()
            except Exception as e:
                self.stats.ready = False
                self.stats.errors += 1
                self.stats.last_error = str(e)[:200]
                self.stats.restarts += 1
                _log(f"W{self.wid} session crash: {e}")
                time.sleep(2)

    def _session_loop(self) -> None:
        from camoufox.sync_api import Camoufox

        px = _proxy_dict(self.proxy)
        kw: dict[str, Any] = {"headless": True}
        if px:
            kw["proxy"] = px
        _log(f"W{self.wid} boot Camoufox…")
        with Camoufox(**kw) as browser:
            page = browser.new_page()
            page.goto(self.page_url, wait_until="domcontentloaded", timeout=90000)
            try:
                page.wait_for_load_state("networkidle", timeout=25000)
            except Exception:
                page.wait_for_timeout(2500)
            open_email_form(page)

            # warm until first token
            deadline = time.time() + 60
            warmed = False
            while time.time() < deadline and not self._stop.is_set():
                last = page.evaluate(FIBER_JS)
                if last and last.get("token"):
                    warmed = True
                    break
                page.wait_for_timeout(400)
            if not warmed:
                raise RuntimeError(f"warm failed: {(last or {}).get('error')}")

            self.stats.ready = True
            _log(f"W{self.wid} ready")

            idle_reloads = 0
            while not self._stop.is_set():
                try:
                    job = self.req_q.get(timeout=1.0)
                except queue.Empty:
                    idle_reloads += 1
                    # soft keep-alive every ~2 min
                    if idle_reloads >= 120:
                        try:
                            page.evaluate("() => true")
                        except Exception as e:
                            raise RuntimeError(f"keepalive dead: {e}") from e
                        idle_reloads = 0
                    continue
                idle_reloads = 0
                if job is None:
                    return
                resp_q: queue.Queue = job["resp"]
                t0 = time.time()
                try:
                    last = page.evaluate(FIBER_JS)
                    ms = (time.time() - t0) * 1000
                    self.stats.last_ms = ms
                    if not last or not last.get("token"):
                        raise RuntimeError((last or {}).get("error") or "no token")
                    self.stats.tokens += 1
                    resp_q.put(
                        {
                            "ok": True,
                            "token": last["token"],
                            "via": "pool",
                            "worker": self.wid,
                            "ms": round(ms, 1),
                            "steps": last.get("steps"),
                        }
                    )
                except Exception as e:
                    self.stats.errors += 1
                    self.stats.last_error = str(e)[:200]
                    resp_q.put(
                        {
                            "ok": False,
                            "token": None,
                            "error": str(e)[:300],
                            "via": "pool",
                            "worker": self.wid,
                        }
                    )
                    # if page died, break to restart session
                    if "Target closed" in str(e) or "has been closed" in str(e):
                        self.stats.ready = False
                        raise


class CastlePool:
    def __init__(
        self,
        n_workers: int = DEFAULT_WORKERS,
        page_url: str = DEFAULT_URL,
        proxy: str | None = None,
    ):
        self.n_workers = max(1, min(8, n_workers))
        self.page_url = page_url
        self.proxy = proxy
        self.req_q: queue.Queue = queue.Queue()
        self.workers: list[CastleWorker] = []
        self.state = PoolState(workers=self.n_workers)
        self._lock = threading.Lock()

    def start(self) -> None:
        for i in range(1, self.n_workers + 1):
            w = CastleWorker(i, self.req_q, self.page_url, self.proxy)
            w.start()
            self.workers.append(w)
        _log(f"pool started workers={self.n_workers}")

    def stop(self) -> None:
        for w in self.workers:
            w.stop()
        for _ in self.workers:
            self.req_q.put(None)
        for w in self.workers:
            w.join(timeout=5)

    def status(self) -> dict:
        ready = sum(1 for w in self.workers if w.stats.ready)
        tokens = sum(w.stats.tokens for w in self.workers)
        errors = sum(w.stats.errors for w in self.workers)
        last_ms = max((w.stats.last_ms for w in self.workers), default=0.0)
        return {
            "ok": True,
            "workers": self.n_workers,
            "ready": ready,
            "tokens": tokens,
            "errors": errors,
            "last_ms": round(last_ms, 1),
            "uptime_s": round(time.time() - self.state.started_at, 1),
            "queue": self.req_q.qsize(),
            "detail": [
                {
                    "id": w.stats.id,
                    "ready": w.stats.ready,
                    "tokens": w.stats.tokens,
                    "errors": w.stats.errors,
                    "last_ms": round(w.stats.last_ms, 1),
                    "restarts": w.stats.restarts,
                    "last_error": w.stats.last_error,
                }
                for w in self.workers
            ],
        }

    def get_token(self, timeout_s: float = 20.0) -> dict:
        # wait for at least one ready worker (boot)
        deadline = time.time() + min(45.0, max(timeout_s, 15.0))
        while time.time() < deadline:
            if any(w.stats.ready for w in self.workers):
                break
            if all(not w.is_alive() for w in self.workers):
                return {"ok": False, "error": "all workers dead", "via": "pool"}
            time.sleep(0.1)
        else:
            return {"ok": False, "error": "pool not ready", "via": "pool"}

        resp_q: queue.Queue = queue.Queue(maxsize=1)
        self.req_q.put({"resp": resp_q})
        try:
            return resp_q.get(timeout=timeout_s)
        except queue.Empty:
            return {"ok": False, "error": f"timeout {timeout_s}s", "via": "pool"}


# --- HTTP API ---
_POOL: CastlePool | None = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:  # quiet
        return

    def _json(self, code: int, obj: dict) -> None:
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in ("/", "/status", "/health"):
            if _POOL is None:
                self._json(503, {"ok": False, "error": "no pool"})
            else:
                self._json(200, _POOL.status())
            return
        self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw.decode() or "{}")
        except Exception:
            req = {}
        if path in ("/token", "/get"):
            if _POOL is None:
                self._json(503, {"ok": False, "error": "no pool"})
                return
            timeout_s = float(req.get("timeout_s") or 20)
            out = _POOL.get_token(timeout_s=timeout_s)
            self._json(200 if out.get("ok") else 500, out)
            return
        self._json(404, {"ok": False, "error": "not found"})


def serve(port: int, workers: int, page_url: str, proxy: str | None) -> int:
    global _POOL
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(os.getpid()))
    _POOL = CastlePool(n_workers=workers, page_url=page_url, proxy=proxy)
    _POOL.start()

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)

    def _stop(*_a):
        _log("stopping…")
        try:
            httpd.shutdown()
        except Exception:
            pass
        if _POOL:
            _POOL.stop()
        try:
            PID_FILE.unlink(missing_ok=True)
        except Exception:
            pass

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    _log(f"listening http://127.0.0.1:{port} workers={workers}")
    try:
        httpd.serve_forever()
    finally:
        _stop()
    return 0


def client_get(timeout_s: float = 20.0, base: str = POOL_URL) -> dict:
    data = json.dumps({"timeout_s": timeout_s}).encode()
    req = urllib.request.Request(
        f"{base}/token",
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s + 5) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        try:
            return json.loads(body)
        except Exception:
            return {"ok": False, "error": f"http {e.code}: {body[:200]}", "via": "pool"}
    except Exception as e:
        return {"ok": False, "error": str(e), "via": "pool"}


def client_status(base: str = POOL_URL) -> dict:
    try:
        with urllib.request.urlopen(f"{base}/status", timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"ok": False, "error": str(e)}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Castle warm token pool")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("serve", help="run pool daemon")
    sp.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, choices=range(1, 9))
    sp.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    sp.add_argument("--url", default=DEFAULT_URL)
    sp.add_argument("--proxy", default=None)

    gp = sub.add_parser("get", help="request one token")
    gp.add_argument("--timeout", type=float, default=20.0)
    gp.add_argument("--url", default=POOL_URL)

    sub.add_parser("status")
    sub.add_parser("stop")

    args = ap.parse_args(argv)

    if args.cmd == "serve":
        return serve(args.port, args.workers, args.url, args.proxy)
    if args.cmd == "get":
        out = client_get(timeout_s=args.timeout, base=args.url)
        print(json.dumps(out))
        return 0 if out.get("ok") else 1
    if args.cmd == "status":
        print(json.dumps(client_status(), indent=2))
        return 0
    if args.cmd == "stop":
        if PID_FILE.exists():
            pid = int(PID_FILE.read_text().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                print(json.dumps({"ok": True, "killed": pid}))
            except ProcessLookupError:
                PID_FILE.unlink(missing_ok=True)
                print(json.dumps({"ok": True, "already_dead": pid}))
        else:
            print(json.dumps({"ok": False, "error": "no pid file"}))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
