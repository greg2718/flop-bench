from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_json_bytes
from .config import BENCH_DID, CANONICAL_ROOM, MAILBOX, SCOUT_DID
from .exceptions import SafetyError, ValidationError
from .identity import ED25519_MULTICODEC, b58decode, b64u, is_valid_ed25519_did
from .redaction import redact

REQUEST_SCHEMA_VERSION = "flop-bench.request.v0.2"
RESPONSE_SCHEMA_VERSION = "flop-bench.response.v0.2"
MAX_CLOCK_SKEW = timedelta(minutes=5)
SUPPORTED_CAPABILITIES = frozenset({"file-check", "approved-local-command"})


def b64u_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode((text + padding).encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValidationError("invalid base64url signature") from exc


def public_key_from_did(did: str) -> Ed25519PublicKey:
    if not is_valid_ed25519_did(did):
        raise ValidationError("invalid Ed25519 did:key")
    decoded = b58decode(did.removeprefix("did:key:z"))
    if not decoded.startswith(ED25519_MULTICODEC) or len(decoded) != 34:
        raise ValidationError("invalid Ed25519 did:key multicodec")
    return Ed25519PublicKey.from_public_bytes(decoded[len(ED25519_MULTICODEC) :])


def unsigned_payload(envelope: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in envelope.items() if key != "signature"}


def signing_preimage(kind: str, payload: dict[str, Any]) -> bytes:
    return b"flop-bench-v0.2|" + kind.encode("ascii") + b"|" + canonical_json_bytes(payload)


def sign_envelope(kind: str, payload: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    envelope = dict(payload)
    envelope["signature"] = b64u(key.sign(signing_preimage(kind, payload)))
    return envelope


def verify_signed_envelope(kind: str, envelope: dict[str, Any], signer_did: str) -> None:
    signature = envelope.get("signature")
    if not isinstance(signature, str):
        raise ValidationError("signed envelope is missing signature")
    public_key = public_key_from_did(signer_did)
    try:
        public_key.verify(
            b64u_decode(signature),
            signing_preimage(kind, unsigned_payload(envelope)),
        )
    except InvalidSignature as exc:
        raise SafetyError("signed envelope signature verification failed") from exc


def parse_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include timezone")
    return parsed.astimezone(UTC)


def validate_timestamp_window(
    created_at: str,
    expires_at: str,
    *,
    now: datetime | None = None,
    max_skew: timedelta = MAX_CLOCK_SKEW,
) -> None:
    current = now.astimezone(UTC) if now is not None else datetime.now(UTC)
    created = parse_timestamp(created_at, "created_at")
    expires = parse_timestamp(expires_at, "expires_at")
    if created > current + max_skew:
        raise SafetyError("request timestamp is too far in the future")
    if expires <= current:
        raise SafetyError("request is expired")
    if expires <= created:
        raise ValidationError("expires_at must be after created_at")


def validate_nonce(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("nonce must be an integer")
    if value <= 0 or value > 9_999_999_999_999_999:
        raise ValidationError("nonce is outside the supported range")
    return int(value)


def validate_room_and_mailbox(room: str = CANONICAL_ROOM, mailbox: str = MAILBOX) -> None:
    if room != CANONICAL_ROOM:
        raise ValidationError("canonical Bench room mismatch")
    if mailbox != MAILBOX:
        raise ValidationError("Bench mailbox mismatch")


def protocol_error_from_response(status: int, body: str) -> dict[str, Any]:
    return {
        "status": status,
        "duplicate": status == 422 and "duplicate" in body.casefold(),
        "body": redact(body, 2048),
    }


def operator_group_for_subject(subject_did: str) -> dict[str, Any]:
    related = {
        "FLOP Scout": SCOUT_DID,
        "FLOP Bench": BENCH_DID,
        "FLOP Sentinel": None,
    }
    return {
        "common_control_disclosure": True,
        "operator_group_id": "local-flop-agent-family",
        "related_agents": related,
        "subject_in_operator_group": subject_did in {SCOUT_DID, BENCH_DID},
    }


def independent_evidence_for_subject(subject_did: str) -> bool:
    return subject_did not in {SCOUT_DID, BENCH_DID}
