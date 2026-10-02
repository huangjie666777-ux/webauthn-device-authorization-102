"""Minimal software authenticator producing real ES256/P-256 signatures.

Used by tests and the curl demo. Not part of the server.
"""

from __future__ import annotations

import hashlib
import json
import struct

from cbor2 import dumps as cbor_dumps
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.webauthn import b64url_encode


class SoftAuthenticator:
    def __init__(self, rp_id: str, sign_count_start: int = 0) -> None:
        self.rp_id = rp_id
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.aaguid = b"\x00" * 16
        self.sign_count = sign_count_start
        x = self.private_key.public_key().public_numbers().x.to_bytes(32, "big")
        self.credential_id = b"cred-" + x[:27]

    def _cose_public_key(self) -> bytes:
        nums = self.private_key.public_key().public_numbers()
        cose = {
            1: 2,
            3: -7,
            -1: 1,
            -2: nums.x.to_bytes(32, "big"),
            -3: nums.y.to_bytes(32, "big"),
        }
        return cbor_dumps(cose)

    def _flags(self, attestation: bool) -> int:
        return 0x01 | 0x04 | (0x40 if attestation else 0)

    def _auth_data(self, attestation: bool) -> bytes:
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        base = rp_hash + bytes([self._flags(attestation)]) + struct.pack(">I", self.sign_count)
        if attestation:
            base += (
                self.aaguid
                + struct.pack(">H", len(self.credential_id))
                + self.credential_id
                + self._cose_public_key()
            )
        return base

    def _client_data(self, ctype: str, challenge_b64: str, origin: str,
                     cross_origin: bool = False) -> bytes:
        obj = {"type": ctype, "challenge": challenge_b64, "origin": origin}
        if cross_origin:
            obj["crossOrigin"] = True
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()

    def _sign(self, auth_data: bytes, client_data: bytes) -> bytes:
        signed = auth_data + hashlib.sha256(client_data).digest()
        der = self.private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def register(self, options: dict, origin: str, *, cross_origin: bool = False) -> dict:
        client_data = self._client_data(
            "webauthn.create", options["challenge"], origin, cross_origin
        )
        auth_data = self._auth_data(attestation=True)
        att_obj = cbor_dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
        return {
            "username": options["user"]["name"],
            "userHandle": options["user"]["id"],
            "clientDataJSON": b64url_encode(client_data),
            "attestationObject": b64url_encode(att_obj),
        }

    def login(self, username: str, options: dict, user_handle_b64: str, origin: str,
              *, cross_origin: bool = False, bump: bool = True) -> dict:
        if bump:
            self.sign_count += 1
        client_data = self._client_data(
            "webauthn.get", options["challenge"], origin, cross_origin
        )
        auth_data = self._auth_data(attestation=False)
        signature = self._sign(auth_data, client_data)
        return {
            "username": username,
            "credentialId": b64url_encode(self.credential_id),
            "clientDataJSON": b64url_encode(client_data),
            "authenticatorData": b64url_encode(auth_data),
            "signature": b64url_encode(signature),
            "userHandle": user_handle_b64,
        }
