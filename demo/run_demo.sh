#!/usr/bin/env bash
# End-to-end curl demo: register and log in with a real software authenticator.
# Usage: ./demo/run_demo.sh [username] [base_url]
set -euo pipefail

USERNAME="${1:-demo_user}"
BASE_URL="${2:-http://127.0.0.1:8000}"
ORIGIN="${WEBAUTHN_ORIGIN:-http://localhost:8000}"
RP_ID="${WEBAUTHN_RP_ID:-localhost}"
PY=".venv/bin/python"
WORK="demo/.tmp"

mkdir -p "$WORK"
rm -f demo/authenticator_state.json

jwt() { python3 -c "import sys,json;print(json.load(sys.stdin)$1)"; }

echo "== 1. health =="
curl -fsS "$BASE_URL/healthz"; echo

echo "== 2. registration options =="
curl -fsS -X POST "$BASE_URL/register/options" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\"}" | tee "$WORK/reg_options.json"; echo

echo "== 3. authenticator creates credential (real ES256/P-256 signature material) =="
WEBAUTHN_RP_ID="$RP_ID" WEBAUTHN_ORIGIN="$ORIGIN" \
  "$PY" demo/soft_authenticator.py register \
  "$WORK/reg_options.json" "$WORK/reg_finish.json"

echo "== 4. registration finish =="
curl -fsS -X POST "$BASE_URL/register/finish" \
  -H 'Content-Type: application/json' \
  --data @"$WORK/reg_finish.json"; echo

echo "== 5. login options (allowCredentials scoped to $USERNAME) =="
curl -fsS -X POST "$BASE_URL/login/options" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\"}" | tee "$WORK/login_options.json"; echo

# Attach userHandle from the registration options for the demo authenticator.
"$PY" - "$WORK/reg_options.json" "$WORK/login_options.json" <<'PYEOF'
import json, sys
reg = json.load(open(sys.argv[1]))
lg = json.load(open(sys.argv[2]))
lg["__user_handle"] = reg["user"]["id"]
json.dump(lg, open(sys.argv[2], "w"))
PYEOF

echo "== 6. authenticator signs assertion =="
DEMO_USERNAME="$USERNAME" WEBAUTHN_RP_ID="$RP_ID" WEBAUTHN_ORIGIN="$ORIGIN" \
  "$PY" demo/soft_authenticator.py login \
  "$WORK/login_options.json" "$WORK/login_finish.json"

echo "== 7. login finish -> opaque token =="
curl -fsS -X POST "$BASE_URL/login/finish" \
  -H 'Content-Type: application/json' \
  --data @"$WORK/login_finish.json" | tee "$WORK/login_result.json"; echo

TOKEN=$("$PY" -c "import json;print(json.load(open('$WORK/login_result.json'))['token'])")

echo "== 8. identity query /me =="
curl -fsS "$BASE_URL/me" -H "Authorization: Bearer $TOKEN"; echo

echo "== 9. logout =="
curl -fsS -X POST "$BASE_URL/logout" -H "Authorization: Bearer $TOKEN"; echo

echo "== 10. /me after logout (expect HTTP 401) =="
curl -sS -o /dev/null -w 'HTTP %{http_code}\n' "$BASE_URL/me" -H "Authorization: Bearer $TOKEN"

echo "demo complete"
