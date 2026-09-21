#!/usr/bin/env bash
cd "$(dirname "$0")"
# prefer system python for control (no heavy deps)
if command -v python3 >/dev/null; then
  /usr/bin/python3 run_ctl.py status 2>/dev/null || python3 run_ctl.py status
else
  python3 run_ctl.py status
fi
