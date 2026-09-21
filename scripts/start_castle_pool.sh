#!/usr/bin/env bash
# Optional Castle warm pool — NOT required for default pure-HTTP email path.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
mkdir -p run

if [[ -x "$ROOT/local-solver/venv/bin/python" ]]; then
  PY="$ROOT/local-solver/venv/bin/python"
elif [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
else
  echo "missing venv — run ./setup.sh first" >&2
  exit 1
fi
export CAMOUFOX_PYTHON="${CAMOUFOX_PYTHON:-$PY}"
export CASTLE_POOL_PORT="${CASTLE_POOL_PORT:-8878}"
export CASTLE_POOL_WORKERS="${CASTLE_POOL_WORKERS:-2}"

if curl -fsS "http://127.0.0.1:${CASTLE_POOL_PORT}/status" >/dev/null 2>&1; then
  echo "castle pool already up on :${CASTLE_POOL_PORT}"
  exit 0
fi

echo "starting castle pool workers=${CASTLE_POOL_WORKERS} port=${CASTLE_POOL_PORT}"
nohup "$PY" "$ROOT/castle_pool.py" serve \
  --workers "$CASTLE_POOL_WORKERS" --port "$CASTLE_POOL_PORT" \
  >>"$ROOT/run/castle_pool.log" 2>&1 &
echo $! >"$ROOT/run/castle_pool.pid"
sleep 3
if curl -fsS "http://127.0.0.1:${CASTLE_POOL_PORT}/status" >/dev/null 2>&1; then
  echo "castle pool ready pid=$(cat "$ROOT/run/castle_pool.pid")"
else
  echo "castle pool started pid=$(cat "$ROOT/run/castle_pool.pid") — check run/castle_pool.log"
fi
