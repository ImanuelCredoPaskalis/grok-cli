#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

stop_pidfile() {
  local f="$1" name="$2"
  if [[ -f "$f" ]]; then
    local pid
    pid="$(cat "$f" 2>/dev/null || true)"
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      sleep 0.5
      kill -9 "$pid" 2>/dev/null || true
      echo "stopped $name pid=$pid"
    fi
    rm -f "$f"
  fi
}

stop_pidfile "$ROOT/run/solver.pid" "solver"
stop_pidfile "$ROOT/run/castle_pool.pid" "castle_pool"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  "$ROOT/.venv/bin/python" "$ROOT/castle_pool.py" stop 2>/dev/null || true
elif [[ -x "$ROOT/local-solver/venv/bin/python" ]]; then
  "$ROOT/local-solver/venv/bin/python" "$ROOT/castle_pool.py" stop 2>/dev/null || true
fi

echo "helpers stopped"
