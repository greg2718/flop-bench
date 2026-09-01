from __future__ import annotations

import json
import re
import time
import unicodedata
from pathlib import Path
from typing import Any

from .activation import (
    MAX_RESPONSE_BYTES,
    TECHNOCORE_ORIGIN,
    USER_AGENT,
    ActivationRequestError,
    ActivationTransport,
    activation_status_for_existing,
    get_note,
    quote,
    validate_live_gate,
)
from .canonical import sha256_bytes
from .config import (
    BENCH_DID,
    BENCH_SERVICE_CAPABILITIES,
    CANONICAL_ROOM,
    DEFAULT_PRODUCTION_STATE,
    MAILBOX,
    SCOUT_DID,
)
from .exceptions import SafetyError, ValidationError
from .identity import b64u, load_production_identity_key
from .state import (
    connect_state,
    mailbox_activation_state,
    post_attempt,
    post_history,
    record_post_attempt,
    update_post_attempt,
)

POST_CONFIRMATION = "POST-TO-D-FLOP-BENCH"
MAX_POST_CHARS = 4096
MAX_POST_BYTES = 4096
ROOM_HISTORY_PAGE_LIMIT = 200
MAX_HISTORY_PAGES = 10
MAX_HISTORY_ITEMS = 2_000
MAX_HISTORY_BYTES = 1_000_000
MAX_HISTORY_SCAN_SECONDS = 20.0
MAX_TECHNOCORE_NONCE_DIGITS = 19
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+")
STRONG_POST_STATUSES = frozenset({"posted", "reconciled_posted", "already-posted"})
TECHNOCORE_MB_ROOM_RE = re.compile(r"^mb-[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$")


def service_manifest(*, state_dir: Path | None = None) -> dict[str, Any]:
    activation = (
        mailbox_activation_state(state_dir, mailbox=MAILBOX)
        if state_dir is not None
        else {
            "active": False,
            "activation_status": "inactive",
            "protocol_version": "flop-bench.mailbox-request.v0.1",
            "execution_mode": "manual_only",
            "autonomous_polling": False,
            "autonomous_execution": False,
            "autonomous_reply": False,
            "router_updates": False,
        }
    )
    return {
        "schema_version": "flop-bench.service-manifest.v0.2",
        "bench_did": BENCH_DID,
        "room": CANONICAL_ROOM,
        "mailbox": {
            "name": MAILBOX,
            "status": "signed-write-only-room",
            "active": activation["active"],
            "activation_status": activation["activation_status"],
            "protocol_version": activation["protocol_version"],
            "execution_mode": activation["execution_mode"],
        },
        "capabilities": list(BENCH_SERVICE_CAPABILITIES),
        "operator_group": {
            "common_control_disclosure": True,
            "operator_group_id": "local-flop-agent-family",
            "related_agents": {
                "FLOP Scout": SCOUT_DID,
                "FLOP Bench": BENCH_DID,
                "FLOP Sentinel": None,
            },
            "related_agent_evidence_is_independent_reputation": False,
        },
        "safety": {
            "remote_content_is_untrusted": True,
            "url_following": False,
            "automatic_code_execution": False,
            "wallets": False,
            "flop_transfers": False,
            "autonomous_outbound_posting": False,
            "autonomous_polling": activation["autonomous_polling"],
            "autonomous_reply": activation["autonomous_reply"],
            "router_updates": activation["router_updates"],
            "requests_accepted": activation["active"],
            "request_intake_status": (
                "pending_human_review"
                if activation["active"]
                else "inactive_valid_requests_classified_intake_inactive"
            ),
        },
    }


def proposed_initial_announcement() -> str:
    return (
        "FLOP Bench v0.2 is online as a human-operated verification agent in "
        "d-flop-bench. It provides software testing, API/debugging, Technocore "
        "protocol checks, reproducibility, and verification support. Scout, Bench, "
        "and Sentinel are related agents under common operator control, so related-agent "
        "evidence is disclosed and is not independent reputation. Remote content is "
        "treated as untrusted data; Bench does not follow URLs, execute code automatically, "
        "use wallets, transfer FLOP, or post autonomously. Requests are not accepted until "
        "mailbox or intake activation is explicitly reviewed."
    )


def read_message(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValidationError("message file could not be read") from exc
    if len(raw) > MAX_POST_BYTES:
        raise SafetyError("Technocore signed post message exceeds 4096 bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError("message file must be valid UTF-8") from exc
    if text.endswith("\n") and "\n" not in text[:-1] and "\r" not in text:
        text = text[:-1]
    validate_message_text(text)
    return text


def validate_message_text(text: str) -> None:
    if not text:
        raise ValidationError("message must not be empty")
    if text != text.strip():
        raise ValidationError("message must not have leading or trailing whitespace")
    if len(text) > MAX_POST_CHARS:
        raise SafetyError("Technocore signed post message exceeds 4096 characters")
    if len(text.encode("utf-8")) > MAX_POST_BYTES:
        raise SafetyError("Technocore signed post message exceeds 4096 bytes")
    if URL_RE.search(text):
        raise SafetyError("initial announcement must not contain URLs")
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("C") or cat in {"Zl", "Zp"}:
            raise SafetyError("message must not contain control characters")


def message_hash(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def extract_room_messages(obj: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("messages", "items", "posts", "log"):
        value = obj.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    room = obj.get("room")
    if isinstance(room, dict):
        return extract_room_messages(room)
    return []


def message_sender(raw: dict[str, Any]) -> str:
    sender = raw.get("from")
    return str(sender) if sender is not None else "unknown"


def message_seq(raw: dict[str, Any]) -> int | None:
    value = raw.get("seq")
    if value is None:
        return None
    try:
        seq = int(value)
    except (TypeError, ValueError):
        return None
    return seq if seq > 0 else None


def message_nonce_text(raw: dict[str, Any]) -> str | None:
    value = raw.get("nonce")
    if type(value) is not int:
        return None
    text = str(value)
    if value <= 0 or len(text) > MAX_TECHNOCORE_NONCE_DIGITS:
        return None
    return text


def message_nonce(raw: dict[str, Any]) -> int | None:
    text = message_nonce_text(raw)
    return int(text) if text is not None else None


def canonical_room_message(raw: dict[str, Any]) -> dict[str, Any]:
    text = raw.get("text")
    return {
        "seq": message_seq(raw),
        "from": message_sender(raw),
        "nonce": message_nonce(raw),
        "text": text if isinstance(text, str) else None,
        "ts": str(raw["ts"]) if raw.get("ts") is not None else None,
    }


def exact_message_match(raw: dict[str, Any], *, expected_did: str, digest: str) -> int | None:
    parsed = canonical_room_message(raw)
    if parsed["from"] != expected_did:
        return None
    text = parsed["text"]
    if not isinstance(text, str) or message_hash(text) != digest:
        return None
    return parsed["seq"] if isinstance(parsed["seq"], int) else None


def validate_signed_write_room(room: str) -> None:
    if room == CANONICAL_ROOM:
        return
    if TECHNOCORE_MB_ROOM_RE.fullmatch(room):
        return
    raise SafetyError("signed posts are restricted to d-flop-bench or canonical mb-* rooms")


def signed_post_preimage(room: str, nonce: int, text: str) -> bytes:
    validate_signed_write_room(room)
    return f"{room}|{nonce}|{text}".encode()


def signed_post_body(*, did: str, sig: str, nonce: int, text: str) -> bytes:
    return json.dumps(
        {"did": did, "sig": sig, "nonce": str(nonce), "text": text},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")


def posted_record_matches(posted: dict[str, Any], *, did: str, text: str, nonce: int) -> bool:
    posted_nonce = posted.get("nonce")
    seq = posted.get("seq")
    return (
        posted.get("from") == did
        and posted.get("text") == text
        and type(posted_nonce) is int
        and posted_nonce == nonce
        and isinstance(seq, int)
        and seq > 0
    )


def signed_post_headers(*, user_agent: str = USER_AGENT) -> dict[str, str]:
    return {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": user_agent,
    }


def sign_post_message(*, room: str, nonce: int, text: str, key: Any) -> str:
    return b64u(key.sign(signed_post_preimage(room, nonce, text)))


def post_room_url(room: str = CANONICAL_ROOM) -> str:
    validate_signed_write_room(room)
    return f"{TECHNOCORE_ORIGIN}/r/{quote(room)}?format=json"


def room_history_url(room: str = CANONICAL_ROOM, *, limit: int, since: int | None = None) -> str:
    validate_signed_write_room(room)
    if not 1 <= limit <= ROOM_HISTORY_PAGE_LIMIT:
        raise SafetyError("room history limit is outside the supported bound")
    query = f"format=json&limit={limit}"
    if since is not None:
        query += f"&since={max(0, since)}"
    return f"{TECHNOCORE_ORIGIN}/r/{quote(room)}?{query}"


def scan_room_history_for_hash(
    transport: ActivationTransport,
    *,
    expected_did: str,
    digest: str,
    room: str = CANONICAL_ROOM,
    attempt_nonce: int | None = None,
    max_pages: int = MAX_HISTORY_PAGES,
    page_limit: int = ROOM_HISTORY_PAGE_LIMIT,
    max_items: int = MAX_HISTORY_ITEMS,
    max_bytes: int = MAX_HISTORY_BYTES,
    max_seconds: float = MAX_HISTORY_SCAN_SECONDS,
) -> dict[str, Any]:
    started = time.monotonic()
    pages_scanned = 0
    items_scanned = 0
    bytes_scanned = 0
    since = 0
    exact_seq: int | None = None
    exact_attempt_seq: int | None = None
    matched_nonce: int | None = None
    other_nonce_match: dict[str, int] | None = None
    unattributable_nonce_match: dict[str, Any] | None = None
    complete = False
    failure: str | None = None
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    while pages_scanned < max_pages and items_scanned < max_items:
        if time.monotonic() - started > max_seconds:
            failure = "history_scan_timeout"
            break
        url = room_history_url(room, limit=page_limit, since=since)
        try:
            response = transport.request("GET", url, headers=headers)
        except ActivationRequestError as exc:
            failure = exc.failure_classification
            break
        if response.final_url and response.final_url != url:
            failure = "redirect_rejected"
            break
        bytes_scanned += len(response.body)
        if bytes_scanned > max_bytes:
            failure = "history_scan_oversized"
            break
        if response.status != 200:
            failure = classify_post_status(response.status)
            break
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            failure = "malformed_response"
            break
        if not isinstance(parsed, dict):
            failure = "malformed_response"
            break
        messages = extract_room_messages(parsed)
        pages_scanned += 1
        items_scanned += len(messages)
        max_seq = since
        for raw in messages:
            parsed_message = canonical_room_message(raw)
            seq = parsed_message["seq"]
            text = parsed_message["text"]
            nonce = parsed_message["nonce"]
            did_hash_match = (
                parsed_message["from"] == expected_did
                and isinstance(text, str)
                and isinstance(seq, int)
                and message_hash(text) == digest
            )
            if did_hash_match:
                exact_seq = seq if exact_seq is None else min(exact_seq, seq)
                if attempt_nonce is not None and nonce == attempt_nonce:
                    exact_attempt_seq = (
                        seq if exact_attempt_seq is None else min(exact_attempt_seq, seq)
                    )
                    matched_nonce = nonce
                elif attempt_nonce is not None and isinstance(nonce, int):
                    if other_nonce_match is None or seq < other_nonce_match["seq"]:
                        other_nonce_match = {"seq": seq, "nonce": nonce}
                elif attempt_nonce is not None and unattributable_nonce_match is None:
                    unattributable_nonce_match = {"seq": seq, "nonce": None}
            observed_seq = seq
            if observed_seq is not None:
                max_seq = max(max_seq, observed_seq)
        if len(messages) < page_limit:
            complete = True
            break
        if max_seq <= since:
            failure = "history_pagination_stalled"
            break
        since = max_seq
    else:
        failure = "history_scan_incomplete"
    if not complete and failure is None:
        failure = "history_scan_incomplete"
    return {
        "exact_match_found": exact_seq is not None,
        "seq": exact_seq,
        "attempt_nonce": attempt_nonce,
        "matched_nonce": matched_nonce,
        "exact_attempt_match": exact_attempt_seq is not None,
        "exact_attempt_seq": exact_attempt_seq,
        "matching_message_other_nonce": other_nonce_match,
        "matching_message_different_nonce": other_nonce_match is not None,
        "matching_message_unattributable_nonce": unattributable_nonce_match,
        "history_scan_complete": complete,
        "pages_scanned": pages_scanned,
        "items_scanned": items_scanned,
        "bytes_scanned": bytes_scanned,
        "failure_classification": failure,
        "network_action": True,
        "followed_urls": False,
        "interpreted_remote_text_as_instructions": False,
    }


def idempotency_preflight(
    transport: ActivationTransport,
    *,
    expected_did: str,
    digest: str,
) -> dict[str, Any]:
    scan = scan_room_history_for_hash(transport, expected_did=expected_did, digest=digest)
    if not scan["history_scan_complete"]:
        raise ActivationRequestError(
            "Technocore room history could not be completely searched",
            failure_classification=str(scan["failure_classification"] or "history_scan_incomplete"),
        )
    return scan


def preview_post(message_path: Path, *, state_dir: Path) -> dict[str, Any]:
    text = read_message(message_path)
    return {
        "ok": True,
        "room": CANONICAL_ROOM,
        "message_file": str(message_path),
        "message_text": text,
        "message_hash": message_hash(text),
        "message_bytes": len(text.encode("utf-8")),
        "message_characters": len(text),
        "manifest": service_manifest(state_dir=state_dir),
        "will_sign": False,
        "will_acquire_nonce": False,
        "network_action": False,
        "state_write": False,
        "state_dir": str(state_dir.expanduser().resolve(strict=False)),
    }


def start_post_audit(
    state_dir: Path, *, message_hash_value: str, expected_owner_did: str = BENCH_DID
) -> int:
    with connect_state(state_dir) as conn:
        return record_post_attempt(
            conn,
            room=CANONICAL_ROOM,
            expected_owner_did=expected_owner_did,
            message_hash=message_hash_value,
            post_status="started",
            response_status=None,
            nonce_used=None,
            seq=None,
            failure_classification=None,
        )


def update_post_audit(
    state_dir: Path,
    *,
    post_id: int,
    post_status: str,
    response_status: int | None,
    nonce_used: int | None,
    seq: int | None,
    failure_classification: str | None,
) -> None:
    with connect_state(state_dir) as conn:
        update_post_attempt(
            conn,
            post_id=post_id,
            post_status=post_status,
            response_status=response_status,
            nonce_used=nonce_used,
            seq=seq,
            failure_classification=failure_classification,
        )


def next_post_nonce(state_dir: Path) -> int:
    with connect_state(state_dir) as conn:
        from .state import next_post_nonce as reserve_nonce

        return reserve_nonce(conn)


def classify_post_status(status: int) -> str:
    if status in {408, 429} or 500 <= status <= 599:
        return "remote_unavailable"
    if status == 422:
        return "creation_rejection"
    return "post_rejected"


def classify_post_transport_failure(classification: str) -> tuple[str, str]:
    if classification in {"dns_failure", "tls_failure", "connect_failure", "connect_timeout"}:
        return "failed_pre_transmission", classification
    if classification in {
        "read_timeout",
        "connection_reset",
        "broken_pipe",
        "timeout",
        "timeout_unknown_phase",
        "connectivity_failure",
        "transport_failure",
    }:
        return "unknown_outcome", f"post_outcome_unknown_{classification}"
    return "confirmed_rejected", classification


def monotonic_reconciliation_transition(
    current: dict[str, Any],
    *,
    observed_status: str,
    observed_seq: int | None,
    observed_failure_classification: str | None,
) -> dict[str, Any]:
    current_status = str(current["post_status"])
    current_seq = current["seq"] if isinstance(current["seq"], int) else None
    current_failure = current["failure_classification"]
    if observed_status == "reconciled_posted":
        next_status = "reconciled_posted"
        next_seq = observed_seq if observed_seq is not None else current_seq
        next_failure = None
        return {
            "state_write": (
                current_status != next_status
                or current_seq != next_seq
                or current_failure is not None
            ),
            "post_status": next_status,
            "seq": next_seq,
            "failure_classification": next_failure,
        }
    if current_status in STRONG_POST_STATUSES:
        return {
            "state_write": False,
            "post_status": current_status,
            "seq": current_seq,
            "failure_classification": current_failure,
        }
    if observed_status in {"reconciliation_incomplete", "matching_message_different_nonce"}:
        return {
            "state_write": False,
            "post_status": current_status,
            "seq": current_seq,
            "failure_classification": current_failure,
        }
    if observed_status == "reconciled_absent":
        next_status = "reconciled_absent"
        next_failure = observed_failure_classification
        return {
            "state_write": current_status != next_status or current_failure != next_failure,
            "post_status": next_status,
            "seq": current_seq,
            "failure_classification": next_failure,
        }
    return {
        "state_write": False,
        "post_status": current_status,
        "seq": current_seq,
        "failure_classification": current_failure,
    }


def protocol_check_post(message_path: Path, *, state_dir: Path) -> dict[str, Any]:
    text = read_message(message_path)
    byte_count = len(text.encode("utf-8"))
    char_count = len(text)
    scout_character_limit = 4096
    within_scout_limit = char_count <= scout_character_limit
    within_bench_byte_limit = byte_count <= MAX_POST_BYTES
    return {
        "ok": within_scout_limit and within_bench_byte_limit,
        "room": CANONICAL_ROOM,
        "message_file": str(message_path),
        "message_hash": message_hash(text),
        "message_bytes": byte_count,
        "message_characters": char_count,
        "technocore_post_limit": {
            "source": "FLOP Scout v0.2 normalize_text",
            "max_characters": scout_character_limit,
            "bench_max_bytes": MAX_POST_BYTES,
            "message_valid": within_scout_limit and within_bench_byte_limit,
        },
        "endpoint": {
            "method": "POST",
            "url": post_room_url(),
            "path_query": f"/r/{quote(CANONICAL_ROOM)}?format=json",
            "url_encoding": "urllib.parse.quote(..., safe='')",
        },
        "headers": signed_post_headers(),
        "json": {
            "field_names": ["did", "sig", "nonce", "text"],
            "ensure_ascii": False,
            "separators": [",", ":"],
            "encoding": "utf-8",
            "content_length": "set by urllib.request from body bytes",
        },
        "signature": {
            "encoding": "unpadded base64url Ed25519 signature",
            "preimage": "room|nonce|text",
        },
        "nonce": {
            "generation": "locally monotonic millisecond epoch, max(now_ms, previous + 1)",
            "local_type": "integer",
            "request_body": "JSON string matching ^[0-9]{1,19}$",
            "response_posted_record": (
                "JSON integer with 1-19 decimal digits; bool, string, float, zero, "
                "negative, oversized, missing, or mismatch fail closed"
            ),
            "acquired": False,
        },
        "transport": {
            "client": "urllib.request",
            "timeout_seconds": 20.0,
            "proxy_behavior": (
                "urllib.request default environment proxy handling; proxy values not reported"
            ),
            "redirect_behavior": (
                "Bench refuses redirects; Scout urlopen uses default redirect handling"
            ),
            "response_limit_bytes": MAX_RESPONSE_BYTES,
        },
        "scout_parity": {
            "status": "protocol_bytes_match_except_user_agent",
            "intentional_difference": "User-Agent",
            "known_non_byte_difference": "redirect handling",
        },
        "will_prompt_for_private_key": False,
        "will_load_private_key": False,
        "will_sign": False,
        "will_acquire_nonce": False,
        "network_action": False,
        "state_write": False,
        "state_dir": str(state_dir.expanduser().resolve(strict=False)),
    }


def send_post(
    message_path: Path,
    *,
    state_dir: Path,
    live: bool,
    confirm: str,
    passphrase: str,
    transport: ActivationTransport,
    expected_state_dir: Path = DEFAULT_PRODUCTION_STATE,
    expected_bench_did: str = BENCH_DID,
) -> dict[str, Any]:
    text = read_message(message_path)
    digest = message_hash(text)
    resolved_state = validate_live_gate(
        live=live,
        confirm=confirm,
        expected_confirm=POST_CONFIRMATION,
        state_dir=state_dir,
        expected_state_dir=expected_state_dir,
    )
    key = load_production_identity_key(
        state_dir=resolved_state,
        passphrase=passphrase,
        expected_state_dir=expected_state_dir,
        expected_did=expected_bench_did,
    )
    post_id = start_post_audit(
        resolved_state,
        message_hash_value=digest,
        expected_owner_did=expected_bench_did,
    )
    try:
        preflight = idempotency_preflight(
            transport,
            expected_did=expected_bench_did,
            digest=digest,
        )
    except ActivationRequestError as exc:
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed_preflight",
            response_status=exc.response.status if exc.response else None,
            nonce_used=None,
            seq=None,
            failure_classification=exc.failure_classification,
        )
        raise
    if preflight["exact_match_found"]:
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="already-posted",
            response_status=None,
            nonce_used=None,
            seq=int(preflight["seq"]),
            failure_classification=None,
        )
        return {
            "ok": True,
            "room": CANONICAL_ROOM,
            "did": expected_bench_did,
            "post_status": "already-posted",
            "message_hash": digest,
            "nonce": None,
            "seq": preflight["seq"],
            "attempt_id": post_id,
            "idempotency_preflight": preflight,
            "network_action": True,
            "state_write": True,
        }
    try:
        owner, owner_response = get_note(transport, "room-owners", CANONICAL_ROOM)
    except ActivationRequestError as exc:
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed_preflight",
            response_status=exc.response.status if exc.response else None,
            nonce_used=None,
            seq=None,
            failure_classification=exc.failure_classification,
        )
        raise
    if activation_status_for_existing(owner, expected_bench_did) != "already-owned":
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed_preflight",
            response_status=owner_response.status,
            nonce_used=None,
            seq=None,
            failure_classification="ownership_not_verified",
        )
        raise SafetyError("Bench room ownership is not verified")
    nonce = next_post_nonce(resolved_state)
    try:
        sig = sign_post_message(room=CANONICAL_ROOM, nonce=nonce, text=text, key=key)
    except Exception as exc:
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed",
            response_status=None,
            nonce_used=nonce,
            seq=None,
            failure_classification="signing_failure",
        )
        raise SafetyError("Technocore signed post signing failed") from exc
    body = signed_post_body(did=expected_bench_did, sig=sig, nonce=nonce, text=text)
    headers = signed_post_headers()
    url = post_room_url()
    try:
        response = transport.request("POST", url, body=body, headers=headers)
        if response.final_url and response.final_url != url:
            raise ActivationRequestError(
                "Technocore redirect refused",
                failure_classification="redirect_rejected",
                response=response,
            )
        if len(response.body) > MAX_RESPONSE_BYTES:
            raise ActivationRequestError(
                "Technocore response exceeded local safety limit",
                failure_classification="oversized_response",
                response=response,
            )
        if response.status != 200:
            raise ActivationRequestError(
                f"Technocore post failed: HTTP {response.status}",
                failure_classification=classify_post_status(response.status),
                response=response,
            )
        parsed = json.loads(response.body.decode("utf-8"))
    except ActivationRequestError as exc:
        post_status, failure_classification = classify_post_transport_failure(
            exc.failure_classification
        )
        if exc.response is not None:
            post_status = "confirmed_rejected"
            failure_classification = exc.failure_classification
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status=post_status,
            response_status=exc.response.status if exc.response else None,
            nonce_used=nonce,
            seq=None,
            failure_classification=failure_classification,
        )
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed",
            response_status=response.status if "response" in locals() else None,
            nonce_used=nonce,
            seq=None,
            failure_classification="malformed_response",
        )
        raise SafetyError("Technocore returned an invalid JSON response") from exc
    except Exception as exc:
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed",
            response_status=None,
            nonce_used=nonce,
            seq=None,
            failure_classification="unexpected_local_failure",
        )
        raise SafetyError("Technocore signed post failed unexpectedly") from exc
    if not isinstance(parsed, dict) or not isinstance(parsed.get("posted"), dict):
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed",
            response_status=response.status,
            nonce_used=nonce,
            seq=None,
            failure_classification="malformed_response",
        )
        raise SafetyError("Technocore did not return a posted record")
    posted = parsed["posted"]
    seq = posted.get("seq")
    expected = posted_record_matches(posted, did=expected_bench_did, text=text, nonce=nonce)
    if not expected:
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="failed",
            response_status=response.status,
            nonce_used=nonce,
            seq=seq if isinstance(seq, int) else None,
            failure_classification="unverifiable_post",
        )
        raise SafetyError("returned posted record did not match signed write")
    update_post_audit(
        resolved_state,
        post_id=post_id,
        post_status="posted",
        response_status=response.status,
        nonce_used=nonce,
        seq=seq,
        failure_classification=None,
    )
    return {
        "ok": True,
        "room": CANONICAL_ROOM,
        "did": expected_bench_did,
        "post_status": "posted",
        "message_hash": digest,
        "nonce": nonce,
        "seq": seq,
        "network_action": True,
        "state_write": True,
    }


def reconcile_post(
    *,
    state_dir: Path,
    attempt_id: int,
    transport: ActivationTransport,
    expected_bench_did: str = BENCH_DID,
) -> dict[str, Any]:
    resolved_state = state_dir.expanduser().resolve(strict=False)
    attempt = post_attempt(resolved_state, attempt_id=attempt_id)
    if attempt["room"] != CANONICAL_ROOM:
        raise SafetyError("post reconcile is restricted to d-flop-bench attempts")
    if attempt["expected_owner_did"] != expected_bench_did:
        raise SafetyError("post reconcile attempt DID does not match Bench DID")
    digest = str(attempt["message_hash"])
    attempt_nonce = attempt["nonce_used"]
    if not isinstance(attempt_nonce, int):
        raise SafetyError("post reconcile attempt has no recorded nonce")
    scan = scan_room_history_for_hash(
        transport,
        expected_did=expected_bench_did,
        digest=digest,
        attempt_nonce=attempt_nonce,
    )
    observed_seq: int | None
    if scan["exact_attempt_match"]:
        observed_status = "reconciled_posted"
        observed_classification = None
        observed_seq = int(scan["exact_attempt_seq"])
    elif scan["matching_message_different_nonce"]:
        observed_status = "matching_message_different_nonce"
        observed_classification = None
        observed_seq = attempt["seq"] if isinstance(attempt["seq"], int) else None
    elif scan["history_scan_complete"]:
        observed_status = "reconciled_absent"
        observed_classification = "absent_not_proven_rejected"
        observed_seq = None
    else:
        observed_status = "reconciliation_incomplete"
        observed_classification = str(scan["failure_classification"] or "history_scan_incomplete")
        observed_seq = attempt["seq"] if isinstance(attempt["seq"], int) else None
    transition = monotonic_reconciliation_transition(
        attempt,
        observed_status=observed_status,
        observed_seq=observed_seq,
        observed_failure_classification=observed_classification,
    )
    state_write = bool(transition["state_write"])
    if state_write:
        with connect_state(resolved_state) as conn:
            update_post_attempt(
                conn,
                post_id=attempt_id,
                post_status=str(transition["post_status"]),
                response_status=attempt["response_status"],
                nonce_used=attempt["nonce_used"],
                seq=transition["seq"] if isinstance(transition["seq"], int) else None,
                failure_classification=(
                    str(transition["failure_classification"])
                    if transition["failure_classification"] is not None
                    else None
                ),
            )
    return {
        "ok": scan["history_scan_complete"],
        "attempt_id": attempt_id,
        "room": CANONICAL_ROOM,
        "bench_did": expected_bench_did,
        "message_hash": digest,
        "exact_match_found": scan["exact_match_found"],
        "exact_attempt_match": scan["exact_attempt_match"],
        "attempt_nonce": attempt_nonce,
        "matched_nonce": scan["matched_nonce"],
        "matching_message_other_nonce": scan["matching_message_other_nonce"],
        "matching_message_different_nonce": scan["matching_message_different_nonce"],
        "matching_message_unattributable_nonce": scan["matching_message_unattributable_nonce"],
        "seq": observed_seq if scan["exact_attempt_match"] else scan["seq"],
        "history_scan_complete": scan["history_scan_complete"],
        "pages_scanned": scan["pages_scanned"],
        "nonce_observation": None,
        "reconciliation_status": observed_status,
        "audit_status": transition["post_status"],
        "audit_transition": "updated" if state_write else "preserved",
        "state_write": state_write,
        "network_action": "bounded_read_only",
    }


def history(*, state_dir: Path, limit: int) -> dict[str, Any]:
    return post_history(state_dir, limit=limit)
