"""Standalone software authenticator used for the curl demo.

State (P-256 private key, credential ID, counter) is persisted in a JSON file
so the same credential can register and log in across process invocations.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import struct
import sys

from cbor2 import dumps as cbor_dumps
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


STATE_PATH = os.environ.get("AUTHENTICATOR_STATE", "demo/authenticator_state.json")


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class StoredAuthenticator:
    def __init__(self, rp_id: str) -> None:
        self.rp_id = rp_id
        self.state = self._load()

    def _load(self) -> dict:
        if os.path.exists(STATE_PATH):
            with open(STATE_PATH, encoding="utf-8") as fh:
                state = json.load(fh)
            if state.get("rp_id") != self.rp_id:
                raise SystemExit("authenticator state belongs to a different RP ID")
            return state
        key = ec.generate_private_key(ec.SECP256R1())
        x = key.public_key().public_numbers().x.to_bytes(32, "big")
        state = {
            "rp_id": self.rp_id,
            "private_pem": key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ).decode(),
            "credential_id": b64e(b"cred-" + x[:27]),
            "sign_count": 0,
        }
        self._save(state)
        return state

    def _save(self, state: dict | None = None) -> None:
        os.makedirs(os.path.dirname(STATE_PATH) or ".", exist_ok=True)
        with open(STATE_PATH, "w", encoding="utf-8") as fh:
            json.dump(state or self.state, fh, indent=2)

    @property
    def private_key(self) -> ec.EllipticCurvePrivateKey:
        return serialization.load_pem_private_key(
            self.state["private_pem"].encode(), password=None
        )

    @property
    def credential_id(self) -> bytes:
        return b64d(self.state["credential_id"])

    def _auth_data(self, attestation: bool) -> bytes:
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        count = self.state["sign_count"]
        flags = 0x01 | 0x04 | (0x40 if attestation else 0)  # UP | UV [| AT]
        data = rp_hash + bytes([flags]) + struct.pack(">I", count)
        if attestation:
            nums = self.private_key.public_key().public_numbers()
            cose = cbor_dumps({
                1: 2,
                3: -7,
                -1: 1,
                -2: nums.x.to_bytes(32, "big"),
                -3: nums.y.to_bytes(32, "big"),
            })
            data += b"\x00" * 16 + struct.pack(">H", len(self.credential_id))
            data += self.credential_id + cose
        return data

    def _client_data(self, ctype: str, challenge: str, origin: str) -> bytes:
        return json.dumps(
            {"type": ctype, "challenge": challenge, "origin": origin},
            separators=(",", ":"), sort_keys=True,
        ).encode()

    def _sign_raw(self, auth_data: bytes, client_data: bytes) -> bytes:
        signed = auth_data + hashlib.sha256(client_data).digest()
        der = self.private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def register(self, options_path: str, origin: str, out_path: str) -> None:
        options = json.load(open(options_path, encoding="utf-8"))
        client_data = self._client_data("webauthn.create", options["challenge"], origin)
        att_obj = cbor_dumps({
            "fmt": "none", "attStmt": {}, "authData": self._auth_data(True),
        })
        body = {
            "username": options["user"]["name"],
            "userHandle": options["user"]["id"],
            "clientDataJSON": b64e(client_data),
            "attestationObject": b64e(att_obj),
        }
        json.dump(body, open(out_path, "w", encoding="utf-8"), indent=2)
        print(f"registration body written to {out_path}")

    def login(self, options_path: str, origin: str, out_path: str) -> None:
        options = json.load(open(options_path, encoding="utf-8"))
        client_data = self._client_data("webauthn.get", options["challenge"], origin)
        auth_data = self._auth_data(False)
        signature = self._sign_raw(auth_data, client_data)
        body = {
            "username": os.environ["DEMO_USERNAME"],
            "credentialId": self.state["credential_id"],
            "clientDataJSON": b64e(client_data),
            "authenticatorData": b64e(auth_data),
            "signature": b64e(signature),
            "userHandle": options["__user_handle"],
        }
        json.dump(body, open(out_path, "w", encoding="utf-8"), indent=2)
        self.state["sign_count"] += 1
        self._save()
        print(f"assertion body written to {out_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Software authenticator for the demo")
    parser.add_argument("--rp-id", default=os.environ.get("WEBAUTHN_RP_ID", "localhost"))
    parser.add_argument("--origin", default=os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:8000"))
    sub = parser.add_subparsers(dest="cmd", required=True)
    reg = sub.add_parser("register")
    reg.add_argument("options")
    reg.add_argument("out")
    lg = sub.add_parser("login")
    lg.add_argument("options")
    lg.add_argument("out")
    args = parser.parse_args()
    auth = StoredAuthenticator(args.rp_id)
    if args.cmd == "register":
        auth.register(args.options, args.origin, args.out)
    else:
        auth.login(args.options, args.origin, args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
