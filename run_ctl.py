#!/usr/bin/env python3
"""Run control for mass_regist: stop / cancel / resume / restart / status.

State lives under ./run/ :
  run/state.json   — progress + frozen CLI args
  run/control.json — live flags (stop / cancel / pause)
  run/mass.pid     — worker pid
  run/mass.log     — optional log path when daemonized via restart
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent

BANNER = r"""
febfrmn
****   
    ***
       
       
  *    
       
     * 
 *    *
*  *   
       
       
    *  
          xAI / Grok Mass Regist · run control
          https://saweria.co/febfrmn
"""

RUN_DIR = ROOT / "run"
STATE_PATH = RUN_DIR / "state.json"
CONTROL_PATH = RUN_DIR / "control.json"
PID_PATH = RUN_DIR / "mass.pid"
LOG_PATH = RUN_DIR / "mass.log"

# control commands
CMD_NONE = "run"
CMD_STOP = "stop"       # finish in-flight, no new accounts
CMD_CANCEL = "cancel"   # abort ASAP
CMD_PAUSE = "pause"     # same as stop (alias)


def _ensure_dir() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)


def load_state() -> dict[str, Any]:
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text())
    except Exception:
        return {}


def save_state(state: dict[str, Any]) -> None:
    _ensure_dir()
    tmp = STATE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True))
    tmp.replace(STATE_PATH)


def load_control() -> dict[str, Any]:
    if not CONTROL_PATH.exists():
        return {"cmd": CMD_NONE, "ts": None}
    try:
        return json.loads(CONTROL_PATH.read_text())
    except Exception:
        return {"cmd": CMD_NONE, "ts": None}


def save_control(cmd: str, note: str = "") -> None:
    _ensure_dir()
    CONTROL_PATH.write_text(
        json.dumps(
            {
                "cmd": cmd,
                "note": note,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            indent=2,
        )
    )


def clear_control() -> None:
    save_control(CMD_NONE)


def write_pid(pid: int | None = None) -> None:
    _ensure_dir()
    PID_PATH.write_text(str(pid or os.getpid()))


def read_pid() -> int | None:
    if not PID_PATH.exists():
        return None
    try:
        return int(PID_PATH.read_text().strip())
    except Exception:
        return None


def clear_pid() -> None:
    try:
        PID_PATH.unlink(missing_ok=True)  # type: ignore[call-arg]
    except TypeError:
        if PID_PATH.exists():
            PID_PATH.unlink()
    except Exception:
        pass


def pid_alive(pid: int | None) -> bool:
    if not pid or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def is_running() -> bool:
    return pid_alive(read_pid())


def should_stop() -> bool:
    """No new accounts (finish in-flight)."""
    cmd = str(load_control().get("cmd") or CMD_NONE).lower()
    return cmd in (CMD_STOP, CMD_PAUSE, CMD_CANCEL)


def should_cancel() -> bool:
    """Abort ASAP — workers should bail before next heavy step."""
    return str(load_control().get("cmd") or CMD_NONE).lower() == CMD_CANCEL


class Cancelled(Exception):
    """Raised when cancel flag is set mid-account."""


def check_cancel(worker: int | None = None) -> None:
    if should_cancel():
        raise Cancelled("cancel requested")


def init_run(args_dict: dict[str, Any], target: int) -> dict[str, Any]:
    """Start a fresh run state (or overwrite)."""
    clear_control()
    write_pid()
    state = {
        "status": "running",
        "target": int(target),
        "ok": 0,
        "fail": 0,
        "attempted": 0,
        "remaining": int(target),
        "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "finished_at": None,
        "pid": os.getpid(),
        "args": args_dict,
        "last_error": None,
    }
    save_state(state)
    return state


def resume_state(args_dict: dict[str, Any] | None = None) -> dict[str, Any]:
    """Continue previous run — remaining = target - ok."""
    st = load_state()
    if not st:
        raise RuntimeError("no previous run state — nothing to resume")
    target = int(st.get("target") or 0)
    ok = int(st.get("ok") or 0)
    remaining = max(0, target - ok)
    if remaining <= 0:
        raise RuntimeError(f"run already complete ok={ok}/{target}")
    clear_control()
    write_pid()
    st["status"] = "running"
    st["remaining"] = remaining
    st["pid"] = os.getpid()
    st["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    st["finished_at"] = None
    st["resumed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if args_dict:
        # keep frozen args but allow override of live flags
        base = dict(st.get("args") or {})
        base.update(args_dict)
        st["args"] = base
    save_state(st)
    return st


def bump(ok: bool = False, fail: bool = False, error: str | None = None) -> dict[str, Any]:
    st = load_state() or {}
    if ok:
        st["ok"] = int(st.get("ok") or 0) + 1
    if fail:
        st["fail"] = int(st.get("fail") or 0) + 1
    st["attempted"] = int(st.get("attempted") or 0) + 1
    target = int(st.get("target") or 0)
    st["remaining"] = max(0, target - int(st.get("ok") or 0))
    st["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if error:
        st["last_error"] = error[:300]
    save_state(st)
    return st


def finish(status: str = "done") -> dict[str, Any]:
    st = load_state() or {}
    st["status"] = status
    st["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    st["updated_at"] = st["finished_at"]
    st["pid"] = None
    save_state(st)
    clear_pid()
    clear_control()
    return st


def status_text() -> str:
    st = load_state()
    ctl = load_control()
    pid = read_pid()
    alive = pid_alive(pid)
    if not st:
        return "no run state"
    lines = [
        f"status   : {st.get('status')} (proc={'alive' if alive else 'dead'} pid={pid})",
        f"progress : ok={st.get('ok')} fail={st.get('fail')} attempted={st.get('attempted')} "
        f"target={st.get('target')} remaining={st.get('remaining')}",
        f"control  : {ctl.get('cmd')} @ {ctl.get('ts')}",
        f"started  : {st.get('started_at')}",
        f"updated  : {st.get('updated_at')}",
        f"finished : {st.get('finished_at')}",
    ]
    if st.get("last_error"):
        lines.append(f"last_err : {st.get('last_error')}")
    args = st.get("args") or {}
    if args:
        lines.append(
            f"args     : n={args.get('count')} w={args.get('workers')} "
            f"delay={args.get('delay')} stagger={args.get('stagger')} "
            f"proxy_file={args.get('proxy_file')} every={args.get('proxy_every')}"
        )
    return "\n".join(lines)


def request_stop(note: str = "") -> str:
    if not is_running():
        save_control(CMD_STOP, note or "stop (no live pid)")
        st = load_state()
        if st and st.get("status") == "running":
            st["status"] = "stopped"
            st["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            save_state(st)
        return "stop flagged (process not running)"
    save_control(CMD_STOP, note or "stop")
    return f"stop sent to pid={read_pid()} — finishing in-flight, no new accounts"


def request_cancel(note: str = "") -> str:
    pid = read_pid()
    save_control(CMD_CANCEL, note or "cancel")
    # Never SIGTERM ourselves — control CLI may share no relation, but
    # unit tests / accidental same-pid must stay alive after flagging.
    if pid_alive(pid) and pid != os.getpid():
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass
        return f"cancel sent + SIGTERM pid={pid}"
    if pid == os.getpid():
        return f"cancel flagged (self pid={pid} — no SIGTERM)"
    st = load_state()
    if st and st.get("status") == "running":
        st["status"] = "cancelled"
        st["finished_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        save_state(st)
        clear_pid()
    return "cancel flagged (process not running)"


def _resolve_python() -> str:
    """Prefer a Python that has mass_regist deps (curl_cffi).

    Control commands (status/stop/resume) often run under system
    /usr/bin/python3 which lacks curl_cffi — never spawn the farm with that.
    """
    candidates: list[str] = []
    env_py = os.environ.get("MASS_REGIST_PYTHON") or os.environ.get("XAI_MASS_PYTHON")
    if env_py:
        candidates.append(env_py)
    # project venv first, then known working envs on this host
    candidates.extend(
        [
            str(ROOT / ".venv" / "bin" / "python"),
            str(ROOT / "venv" / "bin" / "python"),
            sys.executable,
            "python3",
        ]
    )
    seen: set[str] = set()
    for py in candidates:
        if not py or py in seen:
            continue
        seen.add(py)
        p = Path(py)
        if p.is_absolute() and not p.exists():
            continue
        try:
            r = subprocess.run(
                [py, "-c", "import curl_cffi"],
                capture_output=True,
                timeout=8,
                check=False,
            )
            if r.returncode == 0:
                return py
        except Exception:
            continue
    # last resort — may fail at import; better than silent wrong pick
    return sys.executable


def spawn_run(cli_args: list[str], background: bool = True) -> str:
    """Spawn mass_regist with given args (used by restart)."""
    py = _resolve_python()
    mass = str(ROOT / "mass_regist.py")
    cmd = [py, mass, *cli_args]
    _ensure_dir()
    if background:
        logf = open(LOG_PATH, "a")
        proc = subprocess.Popen(
            cmd,
            cwd=str(ROOT),
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        # pid written by child; also track parent spawn
        return f"spawned pid={proc.pid} log={LOG_PATH} cmd={' '.join(cmd)}"
    else:
        subprocess.check_call(cmd, cwd=str(ROOT))
        return "finished foreground"


def args_dict_to_cli(args: dict[str, Any]) -> list[str]:
    """Rebuild CLI from frozen state args for resume/restart."""
    cli: list[str] = []
    n = int(args.get("count") or 1)
    # resume uses remaining; restart uses full count
    cli += ["-n", str(n)]
    if args.get("workers"):
        cli += ["-w", str(args["workers"])]
    if args.get("stagger") is not None:
        cli += ["--stagger", str(args["stagger"])]
    if args.get("delay") is not None:
        cli += ["--delay", str(args["delay"])]
    if args.get("db"):
        cli += ["--db", str(args["db"])]
    if args.get("provider"):
        cli += ["--provider", str(args["provider"])]
    if args.get("skip_inject"):
        cli.append("--skip-inject")
    if args.get("proxy_file"):
        cli += ["--proxy-file", str(args["proxy_file"])]
    if args.get("proxy_mode"):
        cli += ["--proxy-mode", str(args["proxy_mode"])]
    if args.get("proxy_every"):
        cli += ["--proxy-every", str(args["proxy_every"])]
    if args.get("proxy"):
        cli += ["--proxy", str(args["proxy"])]
    if args.get("password"):
        cli += ["--password", str(args["password"])]
    return cli


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(BANNER)
        print(
            """xAI mass-regist run control

  python3 run_ctl.py status
  python3 run_ctl.py stop          # graceful: no new accounts
  python3 run_ctl.py cancel        # hard stop + SIGTERM
  python3 run_ctl.py resume        # continue remaining (target-ok)
  python3 run_ctl.py restart       # cancel live run, start fresh same args
  python3 run_ctl.py log           # tail run/mass.log

Also works as:
  python3 mass_regist.py status|stop|cancel|resume|restart
"""
        )
        return 0

    cmd = argv[0].lower()
    if cmd == "status":
        print(BANNER)
        print(status_text())
        return 0
    if cmd == "stop":
        print(request_stop())
        print(status_text())
        return 0
    if cmd in ("cancel", "kill"):
        print(request_cancel())
        time.sleep(0.5)
        print(status_text())
        return 0
    if cmd == "log":
        if LOG_PATH.exists():
            lines = LOG_PATH.read_text(errors="ignore").splitlines()
            print("\n".join(lines[-80:]))
        else:
            print(f"no log at {LOG_PATH}")
        return 0
    if cmd == "resume":
        if is_running():
            print(f"already running pid={read_pid()}")
            print(status_text())
            return 1
        st = load_state()
        if not st:
            print("no state to resume")
            return 1
        remaining = max(0, int(st.get("target") or 0) - int(st.get("ok") or 0))
        if remaining <= 0:
            print(f"nothing left (ok={st.get('ok')}/{st.get('target')})")
            return 0
        args = dict(st.get("args") or {})
        # override count with remaining; mark resume so mass_regist keeps target
        args["count"] = remaining
        cli = args_dict_to_cli(args)
        cli.append("--resume-run")
        print(f"resume remaining={remaining} → {' '.join(cli)}")
        print(spawn_run(cli, background=True))
        time.sleep(0.8)
        print(status_text())
        return 0
    if cmd == "restart":
        if is_running():
            print(request_cancel("restart"))
            # wait up to 15s
            for _ in range(30):
                if not is_running():
                    break
                time.sleep(0.5)
        st = load_state()
        if not st or not st.get("args"):
            print("no frozen args — start manually: python3 mass_regist.py -n N -w W ...")
            return 1
        args = dict(st["args"])
        # full target restart
        target = int(st.get("target") or args.get("count") or 1)
        args["count"] = target
        cli = args_dict_to_cli(args)
        cli.append("--fresh-run")
        print(f"restart target={target} → {' '.join(cli)}")
        print(spawn_run(cli, background=True))
        time.sleep(0.8)
        print(status_text())
        return 0

    print(f"unknown cmd: {cmd}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
