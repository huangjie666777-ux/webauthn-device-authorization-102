#!/usr/bin/env bash
# End-to-end RFC 8628 device authorization demo with curl and the software
# authenticator: register/login on a browser-capable host, approve a device,
# exchange the device code, read the profile, then revoke the grant.
# Usage: ./demo/run_device_demo.sh [username] [base_url]
set -euo pipefail

USERNAME="${1:-device_owner}"
BASE_URL="${2:-http://127.0.0.1:8000}"
ORIGIN="${WEBAUTHN_ORIGIN:-http://localhost:8000}"
RP_ID="${WEBAUTHN_RP_ID:-localhost}"
PY=".venv/bin/python"
WORK="demo/.tmp"
CLIENT_ID="device-public"

mkdir -p "$WORK"

echo "== 1. health =="
curl -fsS "$BASE_URL/healthz"; echo

echo "== 2. register $USERNAME with the software authenticator (ignore 409 if exists) =="
curl -fsS -X POST "$BASE_URL/register/options" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\"}" > "$WORK/d_reg_options.json" 2>/dev/null || true
if [ -s "$WORK/d_reg_options.json" ] && grep -q challenge "$WORK/d_reg_options.json"; then
  WEBAUTHN_RP_ID="$RP_ID" WEBAUTHN_ORIGIN="$ORIGIN" \
    "$PY" demo/soft_authenticator.py register \
    "$WORK/d_reg_options.json" "$WORK/d_reg_finish.json"
  curl -fsS -X POST "$BASE_URL/register/finish" \
    -H 'Content-Type: application/json' \
    --data @"$WORK/d_reg_finish.json"; echo
else
  echo "   user already registered, reusing it"
fi

echo "== 3. login -> user consent token =="
curl -fsS -X POST "$BASE_URL/login/options" \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"$USERNAME\"}" > "$WORK/d_login_options.json"
"$PY" - "$WORK/d_reg_options.json" "$WORK/d_login_options.json" <<'PYEOF'
import json, os, sys
reg_path, login_path = sys.argv[1], sys.argv[2]
if os.path.exists(reg_path):
    try:
        reg = json.load(open(reg_path))
        handle = reg.get("user", {}).get("id")
        if handle:
            lg = json.load(open(login_path))
            lg["__user_handle"] = handle
            json.dump(lg, open(login_path, "w"))
            sys.exit(0)
    except Exception:
        pass
print("registration options unavailable; demo needs a fresh username", file=sys.stderr)
sys.exit(1)
PYEOF
DEMO_USERNAME="$USERNAME" WEBAUTHN_RP_ID="$RP_ID" WEBAUTHN_ORIGIN="$ORIGIN" \
  "$PY" demo/soft_authenticator.py login \
  "$WORK/d_login_options.json" "$WORK/d_login_finish.json"
TOKEN=$(curl -fsS -X POST "$BASE_URL/login/finish" \
  -H 'Content-Type: application/json' \
  --data @"$WORK/d_login_finish.json" | "$PY" -c 'import sys,json;print(json.load(sys.stdin)["token"])')
echo "   consent token: ${TOKEN:0:12}..."

echo "== 4. device requests authorization (RFC 8628 device endpoint, form-encoded) =="
curl -fsS -X POST "$BASE_URL/oauth/device_authorization" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "scope=profile" | tee "$WORK/device_auth.json"; echo

USER_CODE=$("$PY" -c 'import json;print(json.load(open("demo/.tmp/device_auth.json"))["user_code"])')
DEVICE_CODE=$("$PY" -c 'import json;print(json.load(open("demo/.tmp/device_auth.json"))["device_code"])')
INTERVAL=$("$PY" -c 'import json;print(json.load(open("demo/.tmp/device_auth.json"))["interval"])')
echo "   user_code=$USER_CODE interval=${INTERVAL}s"

echo "== 5. user inspects the code (identity taken from the login session) =="
curl -fsS "$BASE_URL/device/consent?user_code=$USER_CODE" \
  -H "Authorization: Bearer $TOKEN"; echo

echo "== 6. device polls once (expect authorization_pending) =="
curl -sS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "device_code=$DEVICE_CODE" \
  --data-urlencode "client_id=$CLIENT_ID"; echo

echo "== 7. user approves =="
curl -fsS -X POST "$BASE_URL/device/decision" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"user_code\":\"$USER_CODE\",\"approve\":true}"; echo

echo "== 8. device waits the ${INTERVAL}s interval and exchanges the code =="
sleep "$((INTERVAL + 1))"
curl -fsS -X POST "$BASE_URL/oauth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  --data-urlencode "device_code=$DEVICE_CODE" \
  --data-urlencode "client_id=$CLIENT_ID" | tee "$WORK/token.json"; echo
ACCESS_TOKEN=$("$PY" -c 'import json;print(json.load(open("demo/.tmp/token.json"))["access_token"])')

echo "== 9. device reads the resource owner profile =="
curl -fsS "$BASE_URL/oauth/profile" -H "Authorization: Bearer $ACCESS_TOKEN"; echo

echo "== 10. owner lists device grants =="
curl -fsS "$BASE_URL/oauth/grants" -H "Authorization: Bearer $TOKEN" | tee "$WORK/grants.json"; echo
GRANT_ID=$("$PY" -c 'import json;print(json.load(open("demo/.tmp/grants.json"))["grants"][0]["id"])')

echo "== 11. owner revokes the grant; device token fails immediately =="
curl -fsS -X DELETE "$BASE_URL/oauth/grants/$GRANT_ID" \
  -H "Authorization: Bearer $TOKEN"; echo
curl -sS -o /dev/null -w 'profile after revoke: HTTP %{http_code}\n' \
  "$BASE_URL/oauth/profile" -H "Authorization: Bearer $ACCESS_TOKEN"

echo "== 12. original login session still works =="
curl -fsS "$BASE_URL/me" -H "Authorization: Bearer $TOKEN"; echo

echo "device demo complete"
