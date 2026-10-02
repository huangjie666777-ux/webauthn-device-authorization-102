"""WebAuthn Level 2 primitives: options, parsing, attestation/assertion verification.

No third-party WebAuthn server library is used. Only: ES256 (ECDSA P-256 with
SHA-256), "none" attestation, no extensions, no cross-origin use.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass

import io

from cbor2 import CBORDecoder, loads as cbor_loads
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)

ES256 = -7
EC2_TYPE = 2
P256_CRV = 1


class WebAuthnError(Exception):
    """Any protocol-level verification failure."""


def b64url_decode(value: str) -> bytes:
    raw = value.encode("ascii")
    padding = b"=" * (-len(raw) % 4)
    try:
        return base64.urlsafe_b64decode(raw + padding)
    except Exception as exc:
        raise WebAuthnError("malformed base64url value") from exc


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@dataclass
class ClientData:
    type: str
    challenge: bytes
    origin: str
    cross_origin: bool
    top_level_origin: str | None
    raw: bytes


def parse_client_data(raw: bytes, expected_type: str, expected_challenge: bytes,
                      expected_origin: str) -> ClientData:
    """Parse the genuine clientDataJSON bytes and check its core fields."""
    try:
        obj = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WebAuthnError("clientDataJSON is not valid JSON") from exc
    if not isinstance(obj, dict):
        raise WebAuthnError("clientDataJSON must be a JSON object")

    ctype = obj.get("type")
    if ctype != expected_type:
        raise WebAuthnError(f"clientData type must be {expected_type!r}, got {ctype!r}")

    challenge = b64url_decode(obj.get("challenge", ""))
    if challenge != expected_challenge:
        raise WebAuthnError("clientData challenge mismatch")

    origin = obj.get("origin")
    if origin != expected_origin:
        raise WebAuthnError("clientData origin mismatch")

    # WebAuthn Level 2: cross-origin credentials are forbidden by this server.
    if obj.get("crossOrigin", False) is not False:
        raise WebAuthnError("cross-origin authentication is not allowed")

    return ClientData(
        type=ctype,
        challenge=challenge,
        origin=origin,
        cross_origin=bool(obj.get("crossOrigin", False)),
        top_level_origin=obj.get("topLevelOrigin"),
        raw=raw,
    )


@dataclass
class AuthenticatorData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    attested_credential_data: bytes | None
    extensions: bytes | None
    raw: bytes

    @property
    def up(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def uv(self) -> bool:
        return bool(self.flags & 0x04)

    @property
    def at(self) -> bool:
        return bool(self.flags & 0x40)

    @property
    def ed(self) -> bool:
        return bool(self.flags & 0x80)


def parse_authenticator_data(raw: bytes) -> AuthenticatorData:
    if len(raw) < 37:
        raise WebAuthnError("authenticatorData too short")
    rp_id_hash = raw[0:32]
    flags = raw[32]
    (sign_count,) = struct.unpack(">I", raw[33:37])
    offset = 37

    attested = None
    if flags & 0x40:  # AT
        if len(raw) < offset + 18:
            raise WebAuthnError("truncated attested credential data")
        aaguid = raw[offset:offset + 16]
        (id_len,) = struct.unpack(">H", raw[offset + 16:offset + 18])
        end = offset + 18 + id_len
        if len(raw) < end or id_len == 0:
            raise WebAuthnError("invalid credential ID length")
        credential_id = raw[offset + 18:end]
        try:
            decoder = CBORDecoder(io.BytesIO(raw[end:]))
            decoder.decode()
            consumed = decoder.fp.tell()
        except Exception as exc:
            raise WebAuthnError("invalid COSE public key CBOR") from exc
        attested = raw[offset:end + consumed]
        offset = end + consumed

    extensions = None
    if flags & 0x80:  # ED
        raise WebAuthnError("extensions are not supported")

    return AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=sign_count,
        attested_credential_data=attested,
        extensions=extensions,
        raw=raw,
    )


def verify_auth_data_flags(ad: AuthenticatorData, *, registration: bool) -> None:
    if not ad.up:
        raise WebAuthnError("user present (UP) flag must be set")
    if not ad.uv:
        raise WebAuthnError("user verified (UV) flag must be set")
    if registration and not ad.at:
        raise WebAuthnError("attested credential data (AT) flag must be set at registration")


def expected_rp_id_hash(rp_id: str) -> bytes:
    return hashlib.sha256(rp_id.encode("utf-8")).digest()


def check_rp_id_hash(ad: AuthenticatorData, rp_id: str) -> None:
    if ad.rp_id_hash != expected_rp_id_hash(rp_id):
        raise WebAuthnError("rpIdHash mismatch")


def cose_ec2_to_der(cose_key: dict) -> bytes:
    """Validate an ES256 / P-256 COSE_Key and return its DER SubjectPublicKeyInfo."""
    if cose_key.get(1) != EC2_TYPE:
        raise WebAuthnError("only EC2 COSE keys (kty 2) are supported")
    if cose_key.get(3) != ES256:
        raise WebAuthnError("only ES256 (alg -7) is supported")
    if cose_key.get(-1) != P256_CRV:
        raise WebAuthnError("only P-256 (crv 1) is supported")
    x = cose_key.get(-2)
    y = cose_key.get(-3)
    if not isinstance(x, bytes) or not isinstance(y, bytes):
        raise WebAuthnError("COSE key coordinates must be byte strings")
    if len(x) != 32 or len(y) != 32:
        raise WebAuthnError("P-256 coordinates must each be 32 bytes")
    numbers = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(x, "big"),
        y=int.from_bytes(y, "big"),
        curve=ec.SECP256R1(),
    )
    public_key = numbers.public_key()
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


@dataclass
class AttestedCredential:
    aaguid: bytes
    credential_id: bytes
    public_key_der: bytes


def parse_attested_credential(ad: AuthenticatorData) -> AttestedCredential:
    if ad.attested_credential_data is None:
        raise WebAuthnError("missing attested credential data")
    blob = ad.attested_credential_data
    aaguid = blob[0:16]
    (id_len,) = struct.unpack(">H", blob[16:18])
    credential_id = blob[18:18 + id_len]
    try:
        cose_key = cbor_loads(blob[18 + id_len:])
    except Exception as exc:
        raise WebAuthnError("invalid COSE public key") from exc
    if not isinstance(cose_key, dict):
        raise WebAuthnError("COSE public key must be a map")
    der = cose_ec2_to_der(cose_key)
    return AttestedCredential(aaguid=aaguid, credential_id=credential_id, public_key_der=der)


def verify_none_attestation(attestation_object_raw: bytes, auth_data: AuthenticatorData) -> None:
    try:
        att_obj = cbor_loads(attestation_object_raw)
    except Exception as exc:
        raise WebAuthnError("invalid attestation object CBOR") from exc
    if not isinstance(att_obj, dict):
        raise WebAuthnError("attestation object must be a CBOR map")
    if att_obj.get("fmt") != "none":
        raise WebAuthnError("only the 'none' attestation format is supported")
    stmt = att_obj.get("attStmt")
    if stmt != {}:
        raise WebAuthnError("'none' attestation statement must be an empty map")
    embedded_auth_data = att_obj.get("authData")
    if not isinstance(embedded_auth_data, bytes) or embedded_auth_data != auth_data.raw:
        raise WebAuthnError("attestation authData does not match")


def _load_es256_key(public_key_der: bytes) -> ec.EllipticCurvePublicKey:
    key = load_der_public_key(public_key_der)
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise WebAuthnError("stored public key is not EC")
    return key


def verify_assertion_signature(
    public_key_der: bytes,
    authenticator_data_raw: bytes,
    client_data_json_raw: bytes,
    signature: bytes,
) -> None:
    # Signature base = authenticatorData || SHA-256(clientDataJSON), using the exact
    # original bytes received. The JSON is never parsed, re-serialized or re-encoded.
    signed = authenticator_data_raw + hashlib.sha256(client_data_json_raw).digest()
    key = _load_es256_key(public_key_der)
    if len(signature) == 64:
        signature = encode_dss_signature(
            int.from_bytes(signature[:32], "big"),
            int.from_bytes(signature[32:], "big"),
        )
    try:
        key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise WebAuthnError("assertion signature verification failed") from exc


def check_sign_count(stored: int, reported: int) -> None:
    # Both zero is allowed (authenticators without per-credential counter).
    # Otherwise the new counter must be strictly greater than the stored one.
    if stored == 0 and reported == 0:
        return
    if reported <= stored:
        raise WebAuthnError(
            f"sign count must strictly increase (stored={stored}, reported={reported})"
        )
