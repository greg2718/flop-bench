from __future__ import annotations

import base64
import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import atomic_write_text, canonical_json_bytes
from .config import (
    CANONICAL_ROOM,
    DEFAULT_PRODUCTION_STATE,
    MAILBOX,
    SCOUT_DID,
    BenchConfig,
    assert_isolated,
)
from .exceptions import IsolationError, SafetyError, ValidationError

B58 = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ED25519_MULTICODEC = b"\xed\x01"
IDENTITY_CONFIRMATION = "CREATE-FLOP-BENCH-IDENTITY"
MIN_PASSPHRASE_LENGTH = 16
IDENTITY_PEM = "identity.pem"
IDENTITY_JSON = "identity.json"


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


def passphrase_policy_description() -> str:
    return (
        f"Passphrase must be at least {MIN_PASSPHRASE_LENGTH} characters and include at "
        "least three of: lowercase, uppercase, digit, symbol."
    )


def validate_passphrase_strength(passphrase: str) -> None:
    if not passphrase:
        raise SafetyError("passphrase must not be empty")
    classes = [
        any(ch.islower() for ch in passphrase),
        any(ch.isupper() for ch in passphrase),
        any(ch.isdigit() for ch in passphrase),
        any(not ch.isalnum() for ch in passphrase),
    ]
    if len(passphrase) < MIN_PASSPHRASE_LENGTH or sum(classes) < 3:
        raise SafetyError(passphrase_policy_description())


def _resolve(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)


def _assert_production_state_gate(state_dir: Path, expected_state_dir: Path) -> Path:
    expanded = state_dir.expanduser()
    if expanded.is_symlink():
        raise IsolationError("state directory must not be a symlink")
    resolved = _resolve(state_dir)
    expected = _resolve(expected_state_dir)
    if resolved != expected:
        raise SafetyError("production identity state directory must resolve exactly to Bench state")
    assert_isolated(BenchConfig(state_dir=resolved))
    if resolved.is_symlink():
        raise IsolationError("state directory must not be a symlink")
    return resolved


def _assert_no_identity_exists(state_dir: Path) -> None:
    for name in (IDENTITY_PEM, IDENTITY_JSON):
        path = state_dir / name
        if path.exists() or path.is_symlink():
            raise SafetyError(f"{name} already exists; refusing to overwrite")


def _atomic_write_bytes_no_replace(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd: int | None = None
    try:
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if path.exists() or path.is_symlink():
            raise SafetyError(f"{path.name} already exists; refusing to overwrite")
        tmp.replace(path)
        path.chmod(mode)
    finally:
        if fd is not None:
            os.close(fd)
        if tmp.exists():
            tmp.unlink()


def _atomic_write_json_no_replace(path: Path, value: dict[str, Any], mode: int = 0o600) -> None:
    _atomic_write_bytes_no_replace(path, canonical_json_bytes(value) + b"\n", mode)


def _cleanup_identity_files(state_dir: Path) -> None:
    for name in (IDENTITY_PEM, IDENTITY_JSON):
        path = state_dir / name
        if path.exists() and not path.is_symlink():
            path.unlink()
    for tmp in state_dir.glob(".identity.*.tmp"):
        if tmp.exists() and not tmp.is_symlink():
            tmp.unlink()


def _identity_metadata(did: str, public_key: bytes) -> dict[str, Any]:
    if did == SCOUT_DID:
        raise IsolationError("Bench production identity must not use the known Scout DID")
    return {
        "schema_version": "flop-bench.identity.v0.1",
        "created_at": datetime.now(UTC).isoformat(),
        "did": did,
        "public_key_multibase": "z" + b58encode(ED25519_MULTICODEC + public_key),
        "key_type": "Ed25519",
        "purpose": "flop-bench-production",
        "persistent": True,
        "canonical_room": CANONICAL_ROOM,
        "mailbox": MAILBOX,
        "operator_group": {
            "common_control_disclosure": True,
            "operator_group_id": "local-flop-agent-family",
            "related_agents": ["FLOP Scout", "FLOP Bench", "FLOP Sentinel"],
            "note": "Scout, Bench, and Sentinel are related agents under common operator control.",
        },
    }


def create_production_identity(
    *,
    state_dir: Path,
    confirm: str,
    passphrase: str,
    passphrase_confirmation: str,
    expected_state_dir: Path = DEFAULT_PRODUCTION_STATE,
) -> dict[str, Any]:
    if confirm != IDENTITY_CONFIRMATION:
        raise SafetyError("explicit identity creation confirmation value is required")
    resolved_state = _assert_production_state_gate(state_dir, expected_state_dir)
    validate_passphrase_strength(passphrase)
    if passphrase != passphrase_confirmation:
        raise SafetyError("passphrase confirmation does not match")
    created_state_dir = not resolved_state.exists()
    resolved_state.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved_state.chmod(0o700)
    _assert_no_identity_exists(resolved_state)
    try:
        key = Ed25519PrivateKey.generate()
        public_key = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        did = public_did(key)
        metadata = _identity_metadata(did, public_key)
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode("utf-8")),
        )
        _atomic_write_bytes_no_replace(resolved_state / IDENTITY_PEM, pem)
        _atomic_write_json_no_replace(resolved_state / IDENTITY_JSON, metadata)
        verify_identity(
            state_dir=resolved_state,
            passphrase=passphrase,
            expected_state_dir=expected_state_dir,
        )
        return metadata
    except Exception:
        _cleanup_identity_files(resolved_state)
        if created_state_dir:
            try:
                resolved_state.rmdir()
            except OSError:
                pass
        raise


def _load_private_key(pem_path: Path, passphrase: str) -> Ed25519PrivateKey:
    pem_bytes = pem_path.read_bytes()
    if b"BEGIN ENCRYPTED PRIVATE KEY" not in pem_bytes:
        raise ValidationError("identity.pem must contain encrypted PKCS#8 private-key material")
    try:
        loaded = serialization.load_pem_private_key(pem_bytes, password=passphrase.encode("utf-8"))
    except (InvalidKey, TypeError, ValueError) as exc:
        raise SafetyError("identity passphrase did not decrypt identity.pem") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise ValidationError("identity.pem does not contain an Ed25519 private key")
    return loaded


def verify_identity(
    *,
    state_dir: Path,
    passphrase: str,
    expected_state_dir: Path = DEFAULT_PRODUCTION_STATE,
) -> dict[str, Any]:
    resolved_state = _assert_production_state_gate(state_dir, expected_state_dir)
    pem_path = resolved_state / IDENTITY_PEM
    json_path = resolved_state / IDENTITY_JSON
    if not pem_path.exists() or not json_path.exists():
        raise ValidationError("identity.pem and identity.json are required")
    if pem_path.is_symlink() or json_path.is_symlink():
        raise IsolationError("identity files must not be symlinks")
    if resolved_state.stat().st_mode & 0o777 != 0o700:
        raise SafetyError("state directory mode must be 0700")
    if pem_path.stat().st_mode & 0o777 != 0o600:
        raise SafetyError("identity.pem mode must be 0600")
    if json_path.stat().st_mode & 0o777 != 0o600:
        raise SafetyError("identity.json mode must be 0600")
    metadata = json.loads(json_path.read_text(encoding="utf-8"))
    key = _load_private_key(pem_path, passphrase)
    public_key = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    did = public_did(key)
    if metadata.get("did") == SCOUT_DID:
        raise IsolationError("identity.json contains the known Scout DID")
    expected_metadata = {
        "schema_version": "flop-bench.identity.v0.1",
        "did": did,
        "public_key_multibase": "z" + b58encode(ED25519_MULTICODEC + public_key),
        "key_type": "Ed25519",
        "purpose": "flop-bench-production",
        "persistent": True,
        "canonical_room": CANONICAL_ROOM,
        "mailbox": MAILBOX,
    }
    for key_name, expected_value in expected_metadata.items():
        if metadata.get(key_name) != expected_value:
            raise ValidationError(f"identity metadata mismatch: {key_name}")
    operator_group = metadata.get("operator_group")
    if (
        not isinstance(operator_group, dict)
        or operator_group.get("common_control_disclosure") is not True
    ):
        raise ValidationError("identity metadata missing common-control disclosure")
    if operator_group.get("related_agents") != ["FLOP Scout", "FLOP Bench", "FLOP Sentinel"]:
        raise ValidationError("identity metadata missing related agent disclosure")
    return {
        "ok": True,
        "did": did,
        "state_dir": str(resolved_state),
        "key_type": "Ed25519",
        "pem_encrypted": True,
    }


def read_interactive_new_passphrase() -> tuple[str, str]:
    if not sys.stdin.isatty():
        raise SafetyError("interactive terminal required for production identity creation")
    import getpass

    first = getpass.getpass("New FLOP Bench identity passphrase: ")
    second = getpass.getpass("Confirm FLOP Bench identity passphrase: ")
    return first, second


def read_interactive_existing_passphrase() -> str:
    if not sys.stdin.isatty():
        raise SafetyError("interactive terminal required for identity verification")
    import getpass

    return getpass.getpass("FLOP Bench identity passphrase: ")


def refuse_production_identity_creation() -> None:
    raise SafetyError("use create_production_identity with the reviewed provisioning gate")
