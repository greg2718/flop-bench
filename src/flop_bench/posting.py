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
    CANONICAL_ROOM,
    DEFAULT_PRODUCTION_STATE,
    MAILBOX,
    SCOUT_DID,
)
from .exceptions import SafetyError, ValidationError
from .identity import b64u, load_production_identity_key
from .state import (
    connect_state,
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
URL_RE = re.compile(r"(?i)\b(?:https?://|www\.)\S+")


def service_manifest() -> dict[str, Any]:
    return {
        "schema_version": "flop-bench.service-manifest.v0.2",
        "bench_did": BENCH_DID,
        "room": CANONICAL_ROOM,
        "mailbox": {
            "name": MAILBOX,
            "status": "protocol-unconfirmed",
            "active": False,
        },
        "capabilities": [
            "software.testing",
            "software.api",
            "software.debugging",
            "technocore.api",
            "technocore.signed_post",
            "technocore.protocol",
            "reproducibility",
            "verification",
        ],
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
            "requests_accepted": False,
            "request_intake_status": "disabled_until_mailbox_or_intake_activation",
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
    sender = raw.get("from") or raw.get("did") or raw.get("nick") or raw.get("nickname")
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


def exact_message_match(raw: dict[str, Any], *, expected_did: str, digest: str) -> int | None:
    if message_sender(raw) != expected_did:
        return None
    text = raw.get("text")
    if not isinstance(text, str) or message_hash(text) != digest:
        return None
    return message_seq(raw)


def signed_post_preimage(room: str, nonce: int, text: str) -> bytes:
    if room != CANONICAL_ROOM:
        raise SafetyError("signed posts are restricted to d-flop-bench")
    return f"{room}|{nonce}|{text}".encode()


def post_room_url(room: str = CANONICAL_ROOM) -> str:
    if room != CANONICAL_ROOM:
        raise SafetyError("signed posts are restricted to d-flop-bench")
    return f"{TECHNOCORE_ORIGIN}/r/{quote(room)}?format=json"


def room_history_url(room: str = CANONICAL_ROOM, *, limit: int, since: int | None = None) -> str:
    if room != CANONICAL_ROOM:
        raise SafetyError("room history is restricted to d-flop-bench")
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
    complete = False
    failure: str | None = None
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    while pages_scanned < max_pages and items_scanned < max_items:
        if time.monotonic() - started > max_seconds:
            failure = "history_scan_timeout"
            break
        url = room_history_url(limit=page_limit, since=since)
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
            seq = exact_message_match(raw, expected_did=expected_did, digest=digest)
            if seq is not None:
                exact_seq = seq if exact_seq is None else min(exact_seq, seq)
            observed_seq = message_seq(raw)
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
        "message_hash": message_hash(text),
        "message_bytes": len(text.encode("utf-8")),
        "message_characters": len(text),
        "manifest": service_manifest(),
        "proposed_initial_announcement": proposed_initial_announcement(),
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
        sig = b64u(key.sign(signed_post_preimage(CANONICAL_ROOM, nonce, text)))
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
    body = json.dumps(
        {"did": expected_bench_did, "sig": sig, "nonce": nonce, "text": text},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json; charset=utf-8",
        "User-Agent": USER_AGENT,
    }
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
        ambiguous = exc.response is None and exc.failure_classification in {
            "timeout",
            "connectivity_failure",
        }
        update_post_audit(
            resolved_state,
            post_id=post_id,
            post_status="unknown_outcome" if ambiguous else "confirmed_rejected",
            response_status=exc.response.status if exc.response else None,
            nonce_used=nonce,
            seq=None,
            failure_classification=(
                "timeout_after_transmission"
                if exc.failure_classification == "timeout" and ambiguous
                else (
                    "connectivity_failure_after_transmission"
                    if exc.failure_classification == "connectivity_failure" and ambiguous
                    else exc.failure_classification
                )
            ),
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
    expected = (
        posted.get("from") == expected_bench_did
        and posted.get("text") == text
        and str(posted.get("nonce")) == str(nonce)
        and isinstance(seq, int)
        and seq > 0
    )
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
    scan = scan_room_history_for_hash(transport, expected_did=expected_bench_did, digest=digest)
    if scan["exact_match_found"]:
        status = "reconciled_posted"
        classification = None
        seq = int(scan["seq"])
    elif scan["history_scan_complete"]:
        status = "reconciled_absent"
        classification = "absent_not_proven_rejected"
        seq = None
    else:
        status = "reconciliation_incomplete"
        classification = str(scan["failure_classification"] or "history_scan_incomplete")
        seq = attempt["seq"]
    with connect_state(resolved_state) as conn:
        update_post_attempt(
            conn,
            post_id=attempt_id,
            post_status=status,
            response_status=attempt["response_status"],
            nonce_used=attempt["nonce_used"],
            seq=seq,
            failure_classification=classification,
        )
    return {
        "ok": scan["history_scan_complete"],
        "attempt_id": attempt_id,
        "room": CANONICAL_ROOM,
        "bench_did": expected_bench_did,
        "message_hash": digest,
        "exact_match_found": scan["exact_match_found"],
        "seq": seq,
        "history_scan_complete": scan["history_scan_complete"],
        "pages_scanned": scan["pages_scanned"],
        "nonce_observation": None,
        "reconciliation_status": status,
        "state_write": True,
        "network_action": "bounded_read_only",
    }


def history(*, state_dir: Path, limit: int) -> dict[str, Any]:
    return post_history(state_dir, limit=limit)
