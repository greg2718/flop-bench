from __future__ import annotations

import base64
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import atomic_write_text
from .exceptions import SafetyError

B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_MULTICODEC = b"\xed\x01"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = bytearray()
    while n:
        n, r = divmod(n, 58)
        out.append(B58[r])
    zeros = len(raw) - len(raw.lstrip(b"\0"))
    encoded = bytes(reversed(out)) if out else b""
    return (B58[:1] * zeros + encoded).decode("ascii")


def b58decode(text: str) -> bytes:
    n = 0
    for ch in text.encode("ascii"):
        try:
            value = B58.index(ch)
        except ValueError as exc:
            raise ValueError("Invalid base58 character") from exc
        n = n * 58 + value
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    zeros = len(text) - len(text.lstrip("1"))
    return b"\0" * zeros + raw


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def public_did(key: Ed25519PrivateKey) -> str:
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "did:key:z" + b58encode(ED25519_MULTICODEC + pub)


def is_valid_ed25519_did(did: str) -> bool:
    if not re.fullmatch(r"did:key:z[1-9A-HJ-NP-Za-km-z]+", did):
        return False
    try:
        decoded = b58decode(did.removeprefix("did:key:z"))
    except ValueError:
        return False
    return decoded.startswith(ED25519_MULTICODEC) and len(decoded) == 34


def create_ephemeral_test_identity(directory: Path) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    did = public_did(key)
    key_path = directory / "identity-test-only.pem"
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    key_path.chmod(0o600)
    meta = {
        "schema_version": "flop-bench.identity.v0.1",
        "created_at": datetime.now(UTC).isoformat(),
        "did": did,
        "purpose": "test-only",
        "persistent": False,
        "private_key_path": str(key_path),
    }
    atomic_write_text(
        directory / "identity-test-only.json",
        json.dumps(meta, indent=2, sort_keys=True),
    )
    return meta


def refuse_production_identity_creation() -> None:
    raise SafetyError(
        "Production identity creation is disabled until FLOP Bench v0.1 isolation "
        "verification is approved."
    )
