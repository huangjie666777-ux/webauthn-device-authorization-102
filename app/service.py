"""Application services orchestrating challenge lifecycle, verification and sessions."""

from __future__ import annotations
import hashlib
import secrets

from .config import Settings
from .db import transaction
from .repository import Repo, UserExistsError
from .webauthn import (
    WebAuthnError,
    b64url_decode,
    b64url_encode,
    check_rp_id_hash,
    check_sign_count,
    parse_attested_credential,
    parse_authenticator_data,
    parse_client_data,
    verify_assertion_signature,
    verify_auth_data_flags,
    verify_none_attestation,
)


class FinishError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.status_code = status_code


class AuthService:
    def __init__(self, conn, settings: Settings) -> None:
        self.conn = conn
        self.settings = settings

    # ---- helpers ----

    @staticmethod
    def _require_username(payload: dict) -> str:
        username = payload.get("username")
        if not isinstance(username, str) or not username:
            raise FinishError("username is required")
        if len(username) > 64:
            raise FinishError("username too long")
        return username

    # ---- registration options ----

    def register_options(self, username: str) -> dict:
        with transaction(self.conn) as c:
            repo = Repo(c)
            user = repo.find_user_by_name(username)
            if user is not None:
                # Every username may register exactly one credential; never overwrite.
                raise FinishError("user already registered", 409)
            challenge = secrets.token_bytes(32)
            user_id = secrets.token_bytes(32)
            repo.store_challenge(
                challenge_id=secrets.token_bytes(16),
                username=username,
                operation="register",
                challenge=challenge,
                ttl_seconds=self.settings.challenge_ttl_seconds,
                user_handle=user_id,
            )
        return {
            "challenge": b64url_encode(challenge),
            "rp": {"id": self.settings.rp_id, "name": self.settings.rp_name},
            "user": {
                "id": b64url_encode(user_id),
                "name": username,
                "displayName": username,
            },
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "timeout": 60000,
            "attestation": "none",
            "excludeCredentials": [],
            "extensions": {},
        }

    # ---- registration finish ----

    def register_finish(self, payload: dict) -> dict:
        username = self._require_username(payload)
        try:
            client_data_raw = b64url_decode(payload.get("clientDataJSON", ""))
            att_obj_raw = b64url_decode(payload.get("attestationObject", ""))
        except WebAuthnError as exc:
            raise FinishError(str(exc)) from exc
        if not client_data_raw or not att_obj_raw:
            raise FinishError("clientDataJSON and attestationObject are required")

        from cbor2 import loads as cbor_loads
        try:
            att_obj = cbor_loads(att_obj_raw)
            auth_data_raw = att_obj["authData"]
        except Exception as exc:
            raise FinishError("invalid attestation object") from exc

        challenge = self._extract_challenge_or_fail(client_data_raw)

        with transaction(self.conn) as c:
            repo = Repo(c)
            if repo.find_user_by_name(username) is not None:
                raise FinishError("user already registered", 409)

            # Atomically consume the challenge; concurrent replays get None at most
            # once because the row is marked consumed inside this transaction.
            taken = repo.take_challenge(username, "register", challenge)
            if taken is None:
                raise FinishError("no valid pending registration challenge", 400)

            parse_client_data(
                client_data_raw, "webauthn.create", challenge, self.settings.origin
            )
            try:
                auth_data = parse_authenticator_data(auth_data_raw)
            except WebAuthnError as exc:
                raise FinishError(str(exc)) from exc
            check_rp_id_hash(auth_data, self.settings.rp_id)
            verify_auth_data_flags(auth_data, registration=True)
            verify_none_attestation(att_obj_raw, auth_data)
            attested = parse_attested_credential(auth_data)

            user_handle = payload.get("userHandle")
            if not isinstance(user_handle, str) or not user_handle:
                raise FinishError("userHandle is required")
            user_id = b64url_decode(user_handle)
            if taken["user_handle"] is None or user_id != taken["user_handle"]:
                raise FinishError("userHandle does not match registration options")
            try:
                user_rowid = repo.create_user(user_id, username)
                repo.add_credential(
                    attested.credential_id,
                    user_rowid,
                    attested.public_key_der,
                    auth_data.sign_count,
                )
            except UserExistsError as exc:
                raise FinishError("user already registered", 409) from exc

        return {
            "status": "registered",
            "username": username,
            "credentialId": b64url_encode(attested.credential_id),
        }

    def _extract_challenge_or_fail(self, client_data_raw: bytes) -> bytes:
        import json
        try:
            obj = json.loads(client_data_raw.decode("utf-8"))
            return b64url_decode(obj.get("challenge", ""))
        except Exception as exc:
            raise FinishError("invalid clientDataJSON") from exc

    # ---- login options ----

    def login_options(self, username: str) -> dict:
        with transaction(self.conn) as c:
            repo = Repo(c)
            user = repo.find_user_by_name(username)
            if user is None:
                raise FinishError("unknown user", 404)
            credentials = repo.list_credentials_for_user(user["rid"])
            if not credentials:
                raise FinishError("no credential registered", 404)
            challenge = secrets.token_bytes(32)
            repo.store_challenge(
                challenge_id=secrets.token_bytes(16),
                username=username,
                operation="login",
                challenge=challenge,
                ttl_seconds=self.settings.challenge_ttl_seconds,
                user_rowid=user["rid"],
                user_handle=user["id"],
            )
        return {
            "challenge": b64url_encode(challenge),
            "rpId": self.settings.rp_id,
            "timeout": 60000,
            "allowCredentials": [
                {"type": "public-key", "id": b64url_encode(row["credential_id"])}
                for row in credentials
            ],
            "userVerification": "required",
            "extensions": {},
        }

    # ---- login finish ----

    def login_finish(self, payload: dict) -> dict:
        username = self._require_username(payload)
        try:
            credential_id = b64url_decode(payload.get("credentialId", ""))
            client_data_raw = b64url_decode(payload.get("clientDataJSON", ""))
            auth_data_raw = b64url_decode(payload.get("authenticatorData", ""))
            signature = b64url_decode(payload.get("signature", ""))
        except WebAuthnError as exc:
            raise FinishError(str(exc)) from exc
        if not (credential_id and client_data_raw and auth_data_raw and signature):
            raise FinishError("credentialId, clientDataJSON, authenticatorData, signature required")
        challenge = self._extract_challenge_or_fail(client_data_raw)

        user_handle_raw = payload.get("userHandle")
        if not isinstance(user_handle_raw, str) or not user_handle_raw:
            raise FinishError("userHandle is required")
        uh = b64url_decode(user_handle_raw)

        with transaction(self.conn) as c:
            repo = Repo(c)
            user = repo.find_user_by_name(username)
            if user is None:
                raise FinishError("unknown user", 404)
            cred = repo.credential_belonging_to_user(username, credential_id)
            if cred is None:
                raise FinishError("credential not allowed for this user", 403)

            taken = repo.take_challenge(username, "login", challenge)
            if taken is None:
                raise FinishError("no valid pending login challenge", 400)
            if taken["user_handle"] is None or uh != taken["user_handle"]:
                raise FinishError("userHandle does not match challenged user")

            parse_client_data(
                client_data_raw, "webauthn.get", challenge, self.settings.origin
            )
            auth_data = parse_authenticator_data(auth_data_raw)
            check_rp_id_hash(auth_data, self.settings.rp_id)
            verify_auth_data_flags(auth_data, registration=False)
            verify_assertion_signature(
                cred["public_key"], auth_data_raw, client_data_raw, signature
            )
            check_sign_count(cred["sign_count"], auth_data.sign_count)

            # Counter update and challenge consumption commit atomically
            # (challenge was consumed in this same transaction).
            repo.bump_sign_count(credential_id, auth_data.sign_count)

            token = secrets.token_urlsafe(32)
            token_hash = hash_token(token)
            repo.create_session(
                token_hash, user["rid"], self.settings.token_ttl_seconds
            )
            repo.purge_expired()

        return {
            "status": "ok",
            "username": username,
            "token": token,
            "expiresIn": self.settings.token_ttl_seconds,
        }

    # ---- sessions ----

    def session_identity(self, token: str) -> dict:
        with transaction(self.conn) as c:
            row = Repo(c).session_user(hash_token(token))
        if row is None:
            raise FinishError("login required", 401)
        return {
            "username": row["username"],
            "userId": b64url_encode(row["user_id"]),
            "user_rowid": int(row["rid"]),
        }

    def whoami(self, token: str) -> dict:
        with transaction(self.conn) as c:
            row = Repo(c).session_user(hash_token(token))
        if row is None:
            raise FinishError("invalid or expired token", 401)
        return {"username": row["username"], "userId": b64url_encode(row["user_id"])}

    def logout(self, token: str) -> None:
        with transaction(self.conn) as c:
            repo = Repo(c)
            if repo.session_user(hash_token(token)) is None:
                raise FinishError("invalid or expired token", 401)
            repo.delete_session(hash_token(token))


def hash_token(token: str) -> bytes:
    # Only a digest of opaque tokens is stored; compare with constant-time hmac.compare_digest.
    return hashlib.sha256(token.encode("utf-8")).digest()
