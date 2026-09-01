from __future__ import annotations

import json
import urllib.parse
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from .activation import (
    REQUEST_TIMEOUT_SECONDS,
    TECHNOCORE_ORIGIN,
    USER_AGENT,
    ActivationTransport,
    quote,
)
from .canonical import canonical_json_bytes, sha256_bytes, sha256_file
from .config import DEFAULT_PRODUCTION_STATE
from .exceptions import SafetyError, ValidationError
from .protocol import b64u_decode, public_key_from_did, validate_nonce

UNKNOWN_LEGACY = "UNKNOWN_LEGACY"
VERIFICATION_STATES = frozenset(
    {
        "VERIFIED_OFFLINE",
        "INVALID_SIGNATURE",
        "SIGNATURE_PRESENT_UNVERIFIED",
        "LEGACY_SERVER_VERIFIED_NO_SIGNATURE",
        "UNSIGNED",
        "PROVENANCE_INCOMPLETE",
    }
)
CANONICAL_TECHNOCORE_PAYLOAD = "room|nonce|text"
MAX_RECORD_BYTES = 1_000_000
MAX_EXPORT_BYTES = 25_000_000
MANIFEST_COUNT_KEYS = {
    "record_count": "observed_record_count",
    "signed_records": "observed_signed_records",
    "verified_records": "verified_offline",
    "legacy_records_without_sig": "legacy_without_sig",
    "unsigned_records": "unsigned",
    "invalid_signatures": "invalid_signatures",
}


def technocore_signed_post_preimage(room: str, nonce: str | int, text: str) -> bytes:
    return f"{room}|{nonce}|{text}".encode()


def message_hash(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def canonical_payload_hash(room: str, nonce: str | int, text: str) -> str:
    return sha256_bytes(technocore_signed_post_preimage(room, nonce, text))


def evidence_id(room: str, generation: str, seq: int, text_hash: str) -> str:
    payload = {
        "room": room,
        "generation": generation,
        "seq": seq,
        "message_hash": text_hash,
    }
    digest = sha256_bytes(canonical_json_bytes(payload))
    return f"tc:{room}:{generation}:{seq}:{digest[:16]}"


def _field(record: dict[str, Any], *names: str) -> Any:
    for name in names:
        if name in record:
            return record[name]
    return None


def _record_from_json_bytes(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_RECORD_BYTES:
        raise SafetyError("Technocore record exceeds local safety limit")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("Technocore record is not valid UTF-8") from exc
    try:
        value = json.loads(decoded)
    except json.JSONDecodeError as exc:
        raise ValidationError("Technocore record is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValidationError("Technocore record must be a JSON object")
    return value


def _coerce_record(
    record: dict[str, Any],
    *,
    room_context: str | None = None,
    generation_context: str | None = None,
) -> dict[str, Any]:
    room = room_context or _field(record, "room")
    if not isinstance(room, str) or not room:
        raise ValidationError("Technocore record missing room")
    generation_raw = _field(record, "generation", "room_generation")
    if generation_context is not None:
        generation = generation_context
    else:
        generation = str(generation_raw) if generation_raw not in (None, "") else UNKNOWN_LEGACY
    seq_raw = _field(record, "seq", "sequence")
    if isinstance(seq_raw, bool) or not isinstance(seq_raw, int):
        raise ValidationError("Technocore record missing integer seq")
    from_value = _field(record, "from", "sender")
    raw_did = _field(record, "did")
    did_conflict = (
        isinstance(from_value, str)
        and isinstance(raw_did, str)
        and from_value.startswith("did:key:")
        and raw_did.startswith("did:key:")
        and from_value != raw_did
    )
    did = from_value if isinstance(from_value, str) else raw_did
    nonce = _field(record, "nonce")
    sig = _field(record, "sig", "signature")
    text = _field(record, "text")
    ts = _field(record, "ts", "timestamp", "server_timestamp")
    if not isinstance(text, str):
        raise ValidationError("Technocore record missing text")
    if sig is not None and not isinstance(sig, str):
        raise ValidationError("Technocore record sig must be a string")
    if (
        nonce is not None
        and sig is None
        and not (isinstance(did, str) and bool(_field(record, "signed", "verified")))
    ):
        raise ValidationError("Technocore record has nonce without signature")
    if sig is not None and nonce is None:
        raise ValidationError("Technocore record has signature without nonce")
    if sig is not None and not (isinstance(did, str) and did.startswith("did:key:")):
        raise ValidationError("Technocore signed record missing did:key from")
    return {
        "room": room,
        "generation": generation,
        "seq": int(seq_raw),
        "server_timestamp": ts if isinstance(ts, str) else None,
        "did": did if isinstance(did, str) else None,
        "did_conflict": did_conflict,
        "nonce": nonce,
        "sig": sig,
        "text": text,
    }


def verify_record_mapping(
    record: dict[str, Any],
    *,
    room: str | None = None,
    generation: str | None = None,
) -> dict[str, Any]:
    coerced = _coerce_record(record, room_context=room, generation_context=generation)
    room = str(coerced["room"])
    generation = str(coerced["generation"])
    seq = int(coerced["seq"])
    did = coerced["did"]
    nonce = coerced["nonce"]
    sig = coerced["sig"]
    text = str(coerced["text"])
    text_digest = message_hash(text)
    payload_digest = canonical_payload_hash(room, nonce, text) if nonce is not None else None
    sig_present = bool(sig)
    did_conflict = bool(coerced["did_conflict"])
    if did_conflict:
        verification_status = "PROVENANCE_INCOMPLETE"
    elif did and sig and nonce is not None:
        try:
            nonce_value = validate_nonce(nonce) if isinstance(nonce, int) else str(nonce)
            public_key_from_did(did).verify(
                b64u_decode(sig),
                technocore_signed_post_preimage(room, nonce_value, text),
            )
            verification_status = "VERIFIED_OFFLINE"
        except InvalidSignature:
            verification_status = "INVALID_SIGNATURE"
        except (SafetyError, ValidationError, ValueError):
            verification_status = "SIGNATURE_PRESENT_UNVERIFIED"
    elif sig:
        verification_status = "PROVENANCE_INCOMPLETE"
    elif did and bool(_field(record, "signed", "verified")):
        verification_status = "LEGACY_SERVER_VERIFIED_NO_SIGNATURE"
    elif did and str(did).startswith("did:key:") and nonce is not None:
        verification_status = "LEGACY_SERVER_VERIFIED_NO_SIGNATURE"
    elif did:
        verification_status = "UNSIGNED"
    else:
        verification_status = "PROVENANCE_INCOMPLETE"
    return {
        "room": room,
        "generation": generation,
        "seq": seq,
        "timestamp": coerced["server_timestamp"],
        "server_timestamp": coerced["server_timestamp"],
        "did": did,
        "nonce": nonce,
        "sig_present": sig_present,
        "provenance_conflict": did_conflict,
        "message_hash": text_digest,
        "canonical_payload_hash": payload_digest,
        "verification_status": verification_status,
        "evidence_id": evidence_id(room, generation, seq, text_digest),
        "untrusted_content": True,
        "network_action": False,
        "state_write": False,
    }


def verify_record_file(path: Path) -> dict[str, Any]:
    return verify_record_mapping(_record_from_json_bytes(path.read_bytes()))


def _load_manifest(manifest_path: Path) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValidationError("export manifest is not valid JSON") from exc
    if not isinstance(manifest, dict):
        raise ValidationError("export manifest must be a JSON object")
    return manifest


def _manifest_hash(manifest: dict[str, Any]) -> str | None:
    for key in ("export_sha256", "sha256", "source_export_hash", "hash"):
        value = manifest.get(key)
        if isinstance(value, str):
            return value.removeprefix("sha256:").lower()
    return None


def _manifest_count_mismatches(
    manifest: dict[str, Any], observed: dict[str, Any]
) -> dict[str, dict[str, int]]:
    mismatches = {}
    for manifest_key, observed_key in MANIFEST_COUNT_KEYS.items():
        manifest_value = manifest.get(manifest_key)
        if isinstance(manifest_value, bool) or not isinstance(manifest_value, int):
            continue
        observed_value = observed.get(observed_key)
        if isinstance(observed_value, bool) or not isinstance(observed_value, int):
            continue
        if manifest_value != observed_value:
            mismatches[manifest_key] = {
                "manifest": manifest_value,
                "observed": observed_value,
            }
    return mismatches


def verify_export_file(jsonl_path: Path, manifest_path: Path) -> dict[str, Any]:
    if jsonl_path.stat().st_size > MAX_EXPORT_BYTES:
        raise SafetyError("Technocore export exceeds local safety limit")
    manifest = _load_manifest(manifest_path)
    actual_hash = sha256_file(jsonl_path)
    expected_hash = _manifest_hash(manifest)
    if expected_hash and expected_hash != actual_hash:
        raise ValidationError(
            f"export SHA-256 mismatch: expected {expected_hash}, got {actual_hash}"
        )
    room_context = manifest.get("room")
    generation_context = manifest.get("generation")
    if room_context is not None and not isinstance(room_context, str):
        raise ValidationError("export manifest room must be a string")
    if generation_context is not None:
        generation_context = str(generation_context)
    raw = jsonl_path.read_bytes()
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise ValidationError("Technocore export is not valid UTF-8") from exc
    records = 0
    malformed = 0
    statuses: Counter[str] = Counter()
    locations: dict[tuple[str, str, int], str] = {}
    conflicts = 0
    rooms: set[str] = set()
    generations: set[str] = set()
    for line in lines:
        if not line:
            continue
        try:
            raw_record = json.loads(line)
            if not isinstance(raw_record, dict):
                raise ValidationError("record is not an object")
            verified = verify_record_mapping(
                raw_record,
                room=room_context,
                generation=generation_context,
            )
        except (json.JSONDecodeError, ValidationError, SafetyError):
            malformed += 1
            continue
        records += 1
        rooms.add(str(verified["room"]))
        generations.add(str(verified["generation"]))
        status = str(verified["verification_status"])
        statuses[status] += 1
        location = (str(verified["room"]), str(verified["generation"]), int(verified["seq"]))
        existing_hash = locations.get(location)
        if existing_hash is not None and existing_hash != verified["message_hash"]:
            conflicts += 1
        locations[location] = str(verified["message_hash"])
    signed = (
        statuses["VERIFIED_OFFLINE"]
        + statuses["INVALID_SIGNATURE"]
        + statuses["SIGNATURE_PRESENT_UNVERIFIED"]
    )
    observed = {
        "room": str(room_context)
        if room_context is not None
        else (next(iter(rooms)) if len(rooms) == 1 else None),
        "generation": generation_context
        if generation_context is not None
        else (next(iter(generations)) if len(generations) == 1 else None),
        "records": records,
        "observed_records": records,
        "observed_record_count": records,
        "signed": signed,
        "observed_signed_records": signed,
        "verified_offline": statuses["VERIFIED_OFFLINE"],
        "legacy_without_sig": statuses["LEGACY_SERVER_VERIFIED_NO_SIGNATURE"],
        "unsigned": statuses["UNSIGNED"],
        "invalid_signatures": statuses["INVALID_SIGNATURE"],
    }
    count_mismatches = _manifest_count_mismatches(manifest, observed)
    record_parsing = "PASS" if malformed == 0 and conflicts == 0 else "FAIL"
    signature_verification = "PASS" if statuses["INVALID_SIGNATURE"] == 0 else "FAIL"
    manifest_statistics = "MISMATCH" if count_mismatches else "PASS"
    if record_parsing == "FAIL" or signature_verification == "FAIL":
        result = "FAIL"
    elif count_mismatches:
        result = "MANIFEST_MISMATCH"
    else:
        result = "PASS"
    return observed | {
        "manifest_record_count": manifest.get("record_count"),
        "manifest_signed_records": manifest.get("signed_records"),
        "manifest_verified_records": manifest.get("verified_records"),
        "manifest_legacy_records_without_sig": manifest.get("legacy_records_without_sig"),
        "manifest_unsigned_records": manifest.get("unsigned_records"),
        "manifest_invalid_signatures": manifest.get("invalid_signatures"),
        "signature_present_unverified": statuses["SIGNATURE_PRESENT_UNVERIFIED"],
        "provenance_incomplete": statuses["PROVENANCE_INCOMPLETE"],
        "malformed": malformed,
        "conflicts": conflicts,
        "manifest_count_mismatches": count_mismatches,
        "raw_export_integrity": "PASS",
        "record_parsing": record_parsing,
        "signature_verification": signature_verification,
        "manifest_statistics": manifest_statistics,
        "export_sha256": actual_hash,
        "result": result,
        "network_action": False,
        "state_write": False,
        "raw_export_mutated": False,
    }


def provenance_doctor() -> dict[str, Any]:
    sample = {
        "room": "doctor-room",
        "generation": "doctor-generation",
        "seq": 1,
        "from": "did:key:z6Mkdoctor",
        "nonce": 1,
        "text": "doctor",
        "signed": True,
    }
    legacy_sample = {key: value for key, value in sample.items() if key != "generation"}
    sample_hash = message_hash(str(sample["text"]))
    return {
        "title": "FLOP Bench Provenance Doctor",
        "canonical_payload": CANONICAL_TECHNOCORE_PAYLOAD,
        "generation_aware": evidence_id("room", "generation-a", 1, sample_hash)
        != evidence_id("room", "generation-b", 1, sample_hash),
        "offline_verification": "available",
        "private_key_required": False,
        "verified_offline_requires": ["did", "nonce", "sig", "text"],
        "invalid_signature_can_be_verified": False,
        "legacy_evidence_support": verify_record_mapping(legacy_sample)["generation"]
        == UNKNOWN_LEGACY,
        "raw_export_preservation": True,
        "raw_export_directory": str(
            (DEFAULT_PRODUCTION_STATE / "evidence" / "exports").expanduser()
        ),
        "network_action": False,
        "state_write": False,
        "status": "OK",
    }


def export_room_destination(room: str, generation: str = "<generation>") -> Path:
    return DEFAULT_PRODUCTION_STATE / "evidence" / "exports" / room / f"generation-{generation}"


def export_room_endpoint(room: str) -> str:
    return f"{TECHNOCORE_ORIGIN}/r/{quote(room)}/export"


def export_room(
    room: str,
    *,
    yes: bool = False,
    transport: ActivationTransport | None = None,
    state_dir: Path = DEFAULT_PRODUCTION_STATE,
) -> dict[str, Any]:
    endpoint = export_room_endpoint(room)
    destination_root = state_dir.expanduser() / "evidence" / "exports" / room
    if not yes:
        return {
            "room": room,
            "action": "official Technocore room export",
            "endpoint": urllib.parse.urlparse(endpoint).path,
            "destination": str(destination_root / "generation-<generation>"),
            "dry_run": True,
            "network_action": False,
            "state_write": False,
            "status": "DRY_RUN_ONLY",
            "rerun_with": "--yes",
        }
    if transport is None:
        raise SafetyError("export-room --yes requires a Technocore transport")
    response = transport.request(
        "GET",
        endpoint,
        headers={"User-Agent": USER_AGENT, "Accept": "application/jsonl, application/x-ndjson"},
        timeout=REQUEST_TIMEOUT_SECONDS,
    )
    if response.status != 200:
        raise SafetyError(f"Technocore export failed: HTTP {response.status}")
    generation = response.headers.get("X-Room-Generation") or response.headers.get(
        "x-room-generation"
    )
    if not generation:
        raise ValidationError("Technocore export response missing X-Room-Generation")
    body = response.body
    if len(body) > MAX_EXPORT_BYTES:
        raise SafetyError("Technocore export exceeds local safety limit")
    retrieved_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    timestamp = retrieved_at.replace(":", "").replace("-", "")
    dest = destination_root / f"generation-{generation}"
    dest.mkdir(parents=True, exist_ok=True)
    jsonl_path = dest / f"{timestamp}.jsonl"
    manifest_path = dest / f"{timestamp}.manifest.json"
    jsonl_path.write_bytes(body)
    temp_manifest = dest / f"{timestamp}.tmp-manifest.json"
    temp_manifest.write_text(
        json.dumps({"export_sha256": sha256_bytes(body), "room": room, "generation": generation}),
        encoding="utf-8",
    )
    counts = verify_export_file(jsonl_path, temp_manifest)
    temp_manifest.unlink()
    manifest = {
        "room": room,
        "generation": generation,
        "retrieved_at": retrieved_at,
        "export_sha256": sha256_bytes(body),
        "byte_count": len(body),
        "record_count": counts["records"],
        "signed_records": counts["signed"],
        "verified_records": counts["verified_offline"],
        "legacy_records_without_sig": counts["legacy_without_sig"],
        "unsigned_records": counts["unsigned"],
        "invalid_signatures": counts["invalid_signatures"],
    }
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return {
        "room": room,
        "generation": generation,
        "endpoint": urllib.parse.urlparse(endpoint).path,
        "destination": str(jsonl_path),
        "manifest": str(manifest_path),
        "export_sha256": manifest["export_sha256"],
        "byte_count": len(body),
        "record_count": counts["records"],
        "dry_run": False,
        "network_action": True,
        "state_write": True,
        "status": "EXPORTED",
    }
