#!/usr/bin/env bash
# One-shot install for x-farm (xAI / Grok full-HTTP tempmail farm)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "==> [1/4] Python venv"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install -U pip wheel setuptools >/dev/null
python -m pip install -r requirements.txt

echo "==> [1b/4] Playwright chromium (google SSO mode)"
python -m playwright install chromium 2>/dev/null || echo "  (skip — install nanti otomatis pas google mode)"

echo "==> [2/4] Local free Turnstile / CF solver venv (:8877)"
python3 -m venv local-solver/venv
# shellcheck disable=SC1091
source local-solver/venv/bin/activate
python -m pip install -U pip wheel setuptools >/dev/null
python -m pip install -r local-solver/requirements.txt
python - <<'PY'
try:
    from camoufox.sync_api import Camoufox
    print("camoufox import ok")
except Exception as e:
    print("camoufox import warn:", e)
PY
deactivate
# shellcheck disable=SC1091
source .venv/bin/activate

echo "==> [3/4] Example configs"
if [[ ! -f proxies.txt ]]; then
  cp proxies.txt.example proxies.txt
fi
if [[ ! -f local-solver/solver.env ]]; then
  cp local-solver/solver.env.example local-solver/solver.env
fi
if [[ ! -f .env ]]; then
  cp .env.example .env
fi
mkdir -p run

echo "==> [4/4] Smoke imports"
python - <<'PY'
import importlib
for m in ("curl_cffi", "requests", "mail_tm", "mass_regist", "run_ctl", "turnstile_token", "solver_client", "proxy_pool"):
    importlib.import_module(m)
    print("ok", m)
print("ALL IMPORTS OK")
PY

cat <<'EOF'

========================================
  INSTALL DONE — x-farm
========================================
Default path: full-HTTP email regist + auto tempmail OTP.
No GSuite required. No Capsolver required (local free Turnstile).

1) Start local solver (keep running):
     ./scripts/start_solver.sh

2) Run farm:
     source .venv/bin/activate
     python mass_regist.py -n 10 --skip-inject
     # or interactive:
     python mass_regist.py -i

3) Control:
     python mass_regist.py status|stop|cancel|resume|restart
     python mass_regist.py demo

Optional proxy: edit proxies.txt then --proxy-file proxies.txt
Optional inject: --db /path/to/9router.sqlite

Support: https://saweria.co/febfrmn
EOF
