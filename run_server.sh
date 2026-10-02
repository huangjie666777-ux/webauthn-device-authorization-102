#!/usr/bin/env bash
# Start the WebAuthn backend with the locked virtualenv.
set -euo pipefail
export WEBAUTHN_RP_ID="${WEBAUTHN_RP_ID:-localhost}"
export WEBAUTHN_ORIGIN="${WEBAUTHN_ORIGIN:-http://localhost:8000}"
export WEBAUTHN_DB="${WEBAUTHN_DB:-$(pwd)/webauthn.sqlite}"
exec .venv/bin/uvicorn app.http_api:app --host 0.0.0.0 --port "${PORT:-8000}"
