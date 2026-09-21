#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p run
ENVF="$ROOT/local-solver/solver.env"
if [[ -f "$ENVF" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENVF"
  set +a
fi
export SOLVER_MODE="${SOLVER_MODE:-local}"
export SOLVER_HEADLESS="${SOLVER_HEADLESS:-1}"
export PORT="${PORT:-8877}"
export HOST="${HOST:-127.0.0.1}"
export SOLVER_ALLOW_PRIVATE="${SOLVER_ALLOW_PRIVATE:-1}"

PY="$ROOT/local-solver/venv/bin/python"
if [[ ! -x "$PY" ]]; then
  echo "missing local-solver venv — run ./setup.sh first" >&2
  exit 1
fi

if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 || \
   curl -fsS "http://127.0.0.1:${PORT}/status" >/dev/null 2>&1; then
  echo "solver already up on :${PORT}"
  exit 0
fi

echo "starting local free Turnstile/CF solver on ${HOST}:${PORT} (mode=${SOLVER_MODE})"
nohup "$PY" "$ROOT/local-solver/universal_solver.py" \
  >>"$ROOT/run/solver.log" 2>&1 &
echo $! >"$ROOT/run/solver.pid"
sleep 2
if curl -fsS "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1 || \
   curl -fsS "http://127.0.0.1:${PORT}/status" >/dev/null 2>&1; then
  echo "solver ready pid=$(cat "$ROOT/run/solver.pid")"
else
  echo "solver started pid=$(cat "$ROOT/run/solver.pid") — check run/solver.log if health fails"
fi
