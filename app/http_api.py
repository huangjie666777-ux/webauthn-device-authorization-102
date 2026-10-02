"""FastAPI routes: registration/login options+finish, identity query, logout."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from .config import get_settings
from .db import connect, init_db
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


@app.exception_handler(FinishError)
async def finish_error_handler(request: Request, exc: FinishError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"error": str(exc)})


@app.exception_handler(WebAuthnError)
async def webauthn_error_handler(request: Request, exc: WebAuthnError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})


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


@app.post("/logout")
async def logout(authorization: str | None = Header(default=None),
                 svc: AuthService = Depends(get_service)) -> dict:
    token = _bearer_token(authorization)
    svc.logout(token)
    return {"status": "logged_out"}


@app.get("/healthz")
async def healthz() -> dict:
    return {"status": "ok"}
