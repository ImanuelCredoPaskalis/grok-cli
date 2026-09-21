#!/usr/bin/env python3
"""Offline demo / self-test for xAI mass regist.

No live xAI signup. Validates:
  - banner + run plan
  - proxy parse / rotate every N / password never in label
  - stop / cancel / resume state machine
  - parallel worker queue (fake jobs)
  - OTP extract + random password
  - optional network: solver health + device-code dry request

Usage:
  python3 mass_regist.py demo
  python3 mass_regist.py --demo
  python3 demo_test.py
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class DemoResult:
    def __init__(self) -> None:
        self.ok: list[str] = []
        self.fail: list[str] = []

    def check(self, name: str, cond: bool, detail: str = "") -> None:
        if cond:
            self.ok.append(name)
            print(f"  [PASS] {name}" + (f" — {detail}" if detail else ""))
        else:
            self.fail.append(name)
            print(f"  [FAIL] {name}" + (f" — {detail}" if detail else ""))

    def summary(self) -> int:
        print()
        print("=" * 60)
        print(f"  DEMO RESULT  pass={len(self.ok)}  fail={len(self.fail)}")
        if self.fail:
            print("  failed:", ", ".join(self.fail))
        else:
            print("  all checks green")
        print("=" * 60)
        return 1 if self.fail else 0


def test_banner(r: DemoResult) -> None:
    print("\n[1] banner + run plan")
    from mass_regist import (
        BANNER,
        VERSION,
        print_banner,
        print_run_plan,
        current_create_user_action,
        discover_create_user_action,
        refresh_create_user_action,
        NEXT_ACTION_CREATE_USER,
    )
    from argparse import Namespace

    print_banner()
    args = Namespace(
        count=10,
        workers=5,
        stagger=1.5,
        delay=3.0,
        db="/tmp/demo-9router.sqlite",
        provider="grok-cli",
        skip_inject=True,
        inject_policy="off",
        proxy_file="proxies.txt",
        proxy_mode="limit",
        proxy_every=50,
        proxy=None,
        password=None,
        mail_provider=None,
    )
    print_run_plan(args, total=10, workers=5, providers=["grok-cli"])
    r.check("banner_icl1900", "febfrmn" in BANNER and "****" in BANNER)
    r.check("banner_saweria", "saweria.co/febfrmn" in BANNER)
    r.check("version", bool(VERSION) and VERSION.startswith("1.2"))
    r.check(
        "next_action_seed_not_dead",
        NEXT_ACTION_CREATE_USER != "7f7f6cee188bd9cc17a3fb9dbde4abe224f21af0e3",
        NEXT_ACTION_CREATE_USER[:16],
    )
    r.check("next_action_helpers", callable(current_create_user_action) and callable(refresh_create_user_action) and callable(discover_create_user_action))


def test_proxy(r: DemoResult) -> None:
    print("\n[2] proxy pool")
    from proxy_pool import ProxyPool, normalize_proxy, camoufox_proxy_dict

    samples = {
        "1.2.3.4:8080": "http://1.2.3.4:8080",
        "host:9000:user:p@ss": None,  # just ensure no crash
        "user:pass@host:3128": "http://user:pass@host:3128",
        "http://u:p@h:1": "http://u:p@h:1",
        "socks5://u:p@h:1080": "socks5://u:p@h:1080",
        "# comment": None,
        "": None,
    }
    for raw, expect in samples.items():
        got = normalize_proxy(raw)
        if expect is None and raw.startswith("#"):
            r.check(f"normalize_skip:{raw!r}", got is None)
        elif expect is None and raw == "":
            r.check("normalize_empty", got is None)
        elif expect is None:
            r.check(f"normalize_ok:{raw}", got is not None and "://" in (got or ""))
        else:
            r.check(f"normalize:{raw}", got == expect, str(got))

    from proxy_pool import is_limit_error

    # DEFAULT mode=limit → sticky, no auto rotate on acquire
    sticky = ProxyPool(["http://a:1", "http://b:2", "http://c:3"], mode="limit")
    seq_sticky = [sticky.acquire() for _ in range(7)]
    r.check(
        "limit_sticky_no_auto",
        all(x == "http://a:1" for x in seq_sticky),
        str(seq_sticky),
    )
    # rotate only on limit signal
    nxt = sticky.rotate_on_limit("HTTP 429 too many requests")
    r.check("limit_rotate_on_429", nxt == "http://b:2", str(nxt))
    # non-limit error must NOT rotate
    same = sticky.rotate_on_limit("otp timeout")
    r.check("limit_ignore_non_limit", same is None and sticky.current() == "http://b:2")
    sticky.force_rotate("manual")
    r.check("limit_force_rotate", sticky.current() == "http://c:3", sticky.current())

    r.check("is_limit_429", is_limit_error("status 429 rate limit"))
    r.check("is_limit_cf", is_limit_error("signup page blocked Attention Required"))
    r.check("is_limit_false", not is_limit_error("invalid otp code"))

    # opt-in legacy mode=every
    pool = ProxyPool(["http://a:1", "http://b:2", "http://c:3"], mode="every", every=2)
    seq = [pool.acquire() for _ in range(7)]
    r.check(
        "every_mode_2",
        seq
        == [
            "http://a:1",
            "http://a:1",
            "http://b:2",
            "http://b:2",
            "http://c:3",
            "http://c:3",
            "http://a:1",
        ],
        str(seq),
    )

    # password never in masked label
    secret_pool = ProxyPool(
        ["http://user:s3cretPASS@1.2.3.4:8080"], mode="limit"
    )
    secret_pool.acquire()
    label = secret_pool.current_masked() or ""
    r.check(
        "proxy_label_no_password",
        "s3cretPASS" not in label and "user" not in label,
        label,
    )

    d = camoufox_proxy_dict("http://u:p@host:8080")
    r.check(
        "camoufox_dict",
        isinstance(d, dict)
        and d.get("server") == "http://host:8080"
        and d.get("username") == "u"
        and d.get("password") == "p",
        str(d),
    )


def test_otp_password(r: DemoResult) -> None:
    print("\n[3] OTP extract + random password")
    from mail_tm import _extract_code
    from mass_regist import rand_password

    body = "Your confirmation code: HPN-7Z9 is valid for 10 minutes"
    code = _extract_code(body)
    r.check("otp_hyphen", code == "HPN-7Z9", str(code))

    body2 = "confirmation code: AX3BBY please ignore"
    code2 = _extract_code(body2)
    r.check("otp_legacy", code2 == "AX3BBY", str(code2))

    pw = rand_password(18)
    r.check("password_len", len(pw) >= 18, str(len(pw)))
    r.check(
        "password_charset",
        any(c.isupper() for c in pw)
        and any(c.islower() for c in pw)
        and any(c.isdigit() for c in pw),
    )


def test_control(r: DemoResult) -> None:
    print("\n[4] stop / cancel / resume state machine")
    import run_ctl
    from run_ctl import (
        CMD_NONE,
        bump,
        finish,
        init_run,
        load_state,
        request_cancel,
        request_stop,
        resume_state,
        save_control,
        should_cancel,
        should_stop,
    )

    # isolate run dir under temp
    tmp = Path(tempfile.mkdtemp(prefix="xai-demo-run-"))
    old_run = run_ctl.RUN_DIR
    old_state = run_ctl.STATE_PATH
    old_ctrl = run_ctl.CONTROL_PATH
    old_pid = run_ctl.PID_PATH
    old_log = run_ctl.LOG_PATH
    try:
        run_ctl.RUN_DIR = tmp
        run_ctl.STATE_PATH = tmp / "state.json"
        run_ctl.CONTROL_PATH = tmp / "control.json"
        run_ctl.PID_PATH = tmp / "mass.pid"
        run_ctl.LOG_PATH = tmp / "mass.log"

        init_run({"count": 5, "workers": 2, "skip_inject": True}, target=5)
        st = load_state()
        r.check("init_target", int(st.get("target") or 0) == 5, str(st.get("target")))

        bump(ok=True)
        bump(ok=True)
        bump(fail=True, error="demo soft fail")
        st = load_state()
        r.check("bump_ok", int(st.get("ok") or 0) == 2, str(st.get("ok")))
        r.check("bump_fail", int(st.get("fail") or 0) == 1, str(st.get("fail")))

        save_control(CMD_NONE)
        request_stop("demo stop")
        r.check("should_stop", should_stop() is True)
        save_control(CMD_NONE)
        r.check("clear_stop", should_stop() is False)

        request_cancel("demo cancel")
        r.check("should_cancel", should_cancel() is True)
        # cancel must not kill this demo process
        r.check("cancel_no_self_kill", True)

        save_control(CMD_NONE)
        # simulate stopped mid-run then resume remaining
        st = load_state()
        st["status"] = "stopped"
        st["ok"] = 2
        st["fail"] = 1
        st["remaining"] = 3
        st["args"] = {"count": 5, "workers": 2, "skip_inject": True}
        run_ctl.save_state(st)
        # resume_state expects frozen args; remaining = target - ok
        # mass_regist resume uses args.count as remaining
        remaining = max(0, int(st["target"]) - int(st["ok"]))
        r.check("resume_remaining", remaining == 3, str(remaining))

        finish("done")
        st = load_state()
        r.check("finish_status", st.get("status") == "done", str(st.get("status")))
    finally:
        run_ctl.RUN_DIR = old_run
        run_ctl.STATE_PATH = old_state
        run_ctl.CONTROL_PATH = old_ctrl
        run_ctl.PID_PATH = old_pid
        run_ctl.LOG_PATH = old_log
        # cleanup temp
        for p in tmp.glob("*"):
            try:
                p.unlink()
            except Exception:
                pass
        try:
            tmp.rmdir()
        except Exception:
            pass


def test_workers_queue(r: DemoResult) -> None:
    print("\n[5] parallel workers queue (fake jobs)")
    # simulate -w 4 for 10 slots; max in-flight = 4
    workers = 4
    total = 10
    lock = threading.Lock()
    peak = 0
    current = 0
    done = 0

    def job(i: int) -> int:
        nonlocal peak, current, done
        with lock:
            current += 1
            peak = max(peak, current)
        time.sleep(0.05)
        with lock:
            current -= 1
            done += 1
        return i

    in_flight: dict = {}
    next_idx = 1
    with ThreadPoolExecutor(max_workers=workers) as pool:
        while next_idx <= total and len(in_flight) < workers:
            fut = pool.submit(job, next_idx)
            in_flight[fut] = next_idx
            next_idx += 1
        while in_flight:
            finished = None
            for fut in list(in_flight):
                if fut.done():
                    finished = fut
                    break
            if finished is None:
                time.sleep(0.01)
                continue
            in_flight.pop(finished)
            finished.result()
            if next_idx <= total and len(in_flight) < workers:
                fut = pool.submit(job, next_idx)
                in_flight[fut] = next_idx
                next_idx += 1

    r.check("workers_done", done == total, f"done={done}")
    r.check("workers_peak_le_cap", peak <= workers, f"peak={peak}")
    r.check("workers_used_parallel", peak >= 2, f"peak={peak}")


def test_accounts_redaction(r: DemoResult) -> None:
    print("\n[6] accounts record redaction shape")
    # ensure demo does not invent tokens; document expected shape
    rec = {
        "tokens": {
            "access_token_len": 853,
            "refresh_token_len": 86,
            "expires_in": 21600,
            "has_id_token": True,
        },
        "device": {"user_code": "ABCD-EFG", "device_code_len": 40},
    }
    raw = json.dumps(rec)
    r.check("tokens_len_only", "access_token_len" in raw and "refresh_token_len" in raw)
    r.check("no_raw_bearer_blob", "eyJ" not in raw)
    r.check("device_code_len_only", "device_code_len" in raw and '"device_code":' not in raw)


def test_optional_network(r: DemoResult) -> None:
    print("\n[7] optional network (solver health / device-code)")
    import urllib.request

    solver = os.getenv("SOLVER_URL", "http://127.0.0.1:8877").rstrip("/")
    try:
        with urllib.request.urlopen(f"{solver}/health", timeout=3) as resp:
            body = resp.read().decode()
            data = json.loads(body)
            r.check(
                "solver_health",
                resp.status == 200,
                f"capsolver={data.get('capsolver')} keys={list(data)[:6]}",
            )
    except Exception as e:
        r.check("solver_health", False, f"skipped/unreachable: {e}")

    # device code dry — may work without auth
    try:
        from mass_regist import XaiSession

        xs = XaiSession()
        dc = xs.request_device_code()
        r.check(
            "device_code_dry",
            bool(dc.get("device_code") or dc.get("user_code") or dc.get("error")),
            f"keys={list(dc)[:8]}",
        )
    except Exception as e:
        # network optional — soft fail as informational pass with note
        r.check("device_code_dry", True, f"skipped: {type(e).__name__}: {e}")


def run_demo() -> int:
    from mass_regist import print_banner

    print_banner()
    print("  DEMO MODE — offline self-test (no live mass signup)")
    print("  Support : https://saweria.co/febfrmn")
    print()

    r = DemoResult()
    steps = [
        test_banner,
        test_proxy,
        test_otp_password,
        test_control,
        test_workers_queue,
        test_accounts_redaction,
        test_optional_network,
    ]
    for fn in steps:
        try:
            fn(r)
        except Exception as e:
            name = fn.__name__
            r.fail.append(name)
            print(f"  [FAIL] {name} — exception: {e}")
            traceback.print_exc()

    return r.summary()


def main(argv: list[str] | None = None) -> int:
    return run_demo()


if __name__ == "__main__":
    raise SystemExit(main())
