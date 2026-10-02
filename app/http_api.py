"""FastAPI routes: registration/login options+finish, identity query, logout."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, Header, Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .db import connect, init_db
from .device_service import DeviceService, OAuthError
from .service import AuthService, FinishError
from .webauthn import WebAuthnError


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="WebAuthn Level 2 Login Backend", version="1.0.0", lifespan=lifespan)


def get_service(request: Request):
    # The inner generator runs entirely inside the request worker thread,
    # so the SQLite connection is created and closed on the same thread.
    def _gen():
        settings = get_settings()
        conn = connect(settings.db_path)
        try:
            yield AuthService(conn, settings)
        finally:
            conn.close()
    yield from _gen()


def get_device_service(request: Request):
    def _gen():
        settings = get_settings()
        conn = connect(settings.db_path)
        try:
            yield DeviceService(conn, settings)
        finally:
            conn.close()
    yield from _gen()


@app.exception_handler(FinishError)
async def finish_error_handler(request: Request, exc: FinishError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc)})


@app.exception_handler(WebAuthnError)
async def webauthn_error_handler(request: Request, exc: WebAuthnError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})


@app.exception_handler(OAuthError)
async def oauth_error_handler(request: Request, exc: OAuthError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.code, "error_description": str(exc)},
    )


def _username(payload: dict) -> str:
    username = (payload or {}).get("username")
    if not isinstance(username, str) or not username:
        raise FinishError("username is required")
    return username


@app.post("/register/options")
async def register_options(request: Request,
                           svc: AuthService = Depends(get_service)) -> dict:
    payload = await request.json()
    return svc.register_options(_username(payload))


@app.post("/register/finish")
async def register_finish(request: Request,
                          svc: AuthService = Depends(get_service)) -> dict:
    payload = await request.json()
    return svc.register_finish(payload)


@app.post("/login/options")
async def login_options(request: Request,
                        svc: AuthService = Depends(get_service)) -> dict:
    payload = await request.json()
    return svc.login_options(_username(payload))


@app.post("/login/finish")
async def login_finish(request: Request,
                       svc: AuthService = Depends(get_service)) -> dict:
    payload = await request.json()
    return svc.login_finish(payload)


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise FinishError("missing bearer token", 401)
    token = authorization[len("Bearer "):].strip()
    if not token:
        raise FinishError("missing bearer token", 401)
    return token


@app.get("/me")
async def me(authorization: str | None = Header(default=None),
             svc: AuthService = Depends(get_service)) -> dict:
    return svc.whoami(_bearer_token(authorization))


# ---------------------------------------------------------------------------
# OAuth 2.0 Device Authorization Grant (RFC 8628)
# ---------------------------------------------------------------------------

def _login_session(svc: AuthService, authorization: str | None) -> dict:
    """Identity comes from the existing WebAuthn login session."""
    return svc.session_identity(_bearer_token(authorization))


@app.post("/oauth/device_authorization")
async def device_authorization(
    client_id: str | None = Form(default=None),
    scope: str | None = Form(default=None),
    svc: DeviceService = Depends(get_device_service),
) -> dict:
    return svc.authorize_device(client_id, scope)


@app.post("/oauth/token")
async def token(
    grant_type: str | None = Form(default=None),
    device_code: str | None = Form(default=None),
    client_id: str | None = Form(default=None),
    svc: DeviceService = Depends(get_device_service),
) -> dict:
    return svc.poll_token(grant_type, device_code, client_id)


@app.get("/device/consent")
async def device_consent(
    user_code: str,
    authorization: str | None = Header(default=None),
    auth: AuthService = Depends(get_service),
    svc: DeviceService = Depends(get_device_service),
) -> dict:
    _login_session(auth, authorization)
    return svc.lookup_user_code(user_code)


@app.post("/device/decision")
async def device_decision(
    request: Request,
    authorization: str | None = Header(default=None),
    auth: AuthService = Depends(get_service),
    svc: DeviceService = Depends(get_device_service),
) -> dict:
    identity = _login_session(auth, authorization)
    payload = await request.json()
    user_code = payload.get("user_code")
    approve = bool(payload.get("approve"))
    return svc.decide_user_code(user_code, approve, identity["user_rowid"])


@app.get("/oauth/profile")
async def oauth_profile(
    authorization: str | None = Header(default=None),
    svc: DeviceService = Depends(get_device_service),
) -> dict:
    # Device tokens may read only the resource owner's own profile.
    return svc.device_profile(_bearer_token(authorization))


@app.get("/oauth/grants")
async def oauth_grants(
    authorization: str | None = Header(default=None),
    auth: AuthService = Depends(get_service),
    svc: DeviceService = Depends(get_device_service),
) -> dict:
    identity = _login_session(auth, authorization)
    return {"grants": svc.list_grants(identity["user_rowid"])}


@app.delete("/oauth/grants/{grant_id}")
async def oauth_revoke_grant(
    grant_id: int,
    authorization: str | None = Header(default=None),
    auth: AuthService = Depends(get_service),
    svc: DeviceService = Depends(get_device_service),
) -> dict:
    identity = _login_session(auth, authorization)
    if not svc.revoke_grant(grant_id, identity["user_rowid"]):
        raise FinishError("grant not found", 404)
    return {"status": "revoked", "id": grant_id}


@app.post("/logout")
async def logout(authorization: str | None = Header(default=None),
                 svc: AuthService = Depends(get_service)) -> dict:
    token = _bearer_token(authorization)
    svc.logout(token)
    return {"status": "logged_out"}


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}
