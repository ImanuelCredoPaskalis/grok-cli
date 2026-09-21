#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "=== local free solver :8877 ==="
curl -sS --max-time 3 http://127.0.0.1:8877/health 2>/dev/null \
  || curl -sS --max-time 3 http://127.0.0.1:8877/status 2>/dev/null \
  || echo "(down)"
echo
echo "=== castle pool :8878 (optional) ==="
curl -sS --max-time 3 http://127.0.0.1:8878/status 2>/dev/null || echo "(down / not required for pure-HTTP)"
echo
echo "=== farm control ==="
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  "$ROOT/.venv/bin/python" "$ROOT/run_ctl.py" status || true
else
  python3 "$ROOT/run_ctl.py" status || true
fi
