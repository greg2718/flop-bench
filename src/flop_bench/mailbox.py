from __future__ import annotations

import json
import re
import sqlite3
import time
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any

from .activation import (
    MAX_RESPONSE_BYTES,
    REQUEST_TIMEOUT_SECONDS,
    TECHNOCORE_ORIGIN,
    USER_AGENT,
    ActivationRequestError,
    ActivationTransport,
    backoff_for_429,
    quote,
)
from .canonical import sha256_bytes
from .config import BENCH_DID, BENCH_SERVICE_CAPABILITIES, MAILBOX, BenchConfig, assert_isolated
from .exceptions import SafetyError, ValidationError
from .identity import is_valid_ed25519_did
from .identity_note import did_profile_path, identity_note_value, note_hash
from .posting import extract_room_messages, message_nonce_text, message_seq
from .protocol import parse_timestamp, validate_timestamp_window
from .redaction import redact
from .state import (
    STATE_DB,
    connect_state,
    latest_did_note_observation,
    mailbox_activation_state,
    mailbox_cursor,
    mailbox_message_detail,
    mailbox_messages_history,
    migration_status,
    record_mailbox_activation,
    record_mailbox_deactivation,
    store_mailbox_poll,
)

MAILBOX_REQUEST_SCHEMA_VERSION = "flop-bench.mailbox-request.v0.1"
MAILBOX_ACTIVATE_CONFIRMATION = "ACTIVATE-MB-FLOP-BENCH"
MAILBOX_DEACTIVATE_CONFIRMATION = "DEACTIVATE-MB-FLOP-BENCH"
SUPERVISED_POLLING_ACTIVATION_KEY = f"{MAILBOX}:supervised-continuous-polling"
MAX_MAILBOX_PAGE_LIMIT = 200
MAX_MAILBOX_PAGES = 10
MAX_MAILBOX_ITEMS = 2_000
MAX_MAILBOX_BYTES = 1_000_000
MAX_MAILBOX_SECONDS = 20.0
MAX_TEXT_STORE_BYTES = 4096
MAX_JSON_TEXT_BYTES = 8192
MAX_STRING_BYTES = 2048
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
REQUEST_REQUIRED = {
    "schema_version",
    "request_id",
    "sender_did",
    "target_did",
    "requested_capability",
    "hypothesis",
    "test_spec",
    "created_at",
    "expires_at",
    "provenance",
}
REQUEST_OPTIONAL = {"reply_room", "operator_group"}


def mailbox_history_url(*, limit: int, since: int | None = None) -> str:
    if not 1 <= limit <= MAX_MAILBOX_PAGE_LIMIT:
        raise SafetyError("mailbox history limit is outside the supported bound")
    query = f"format=json&limit={limit}"
    if since is not None:
        query += f"&since={max(0, since)}"
    return f"{TECHNOCORE_ORIGIN}/r/{quote(MAILBOX)}?{query}"


def mailbox_message_hash(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def _safe_text(text: str) -> str:
    raw = text.encode("utf-8")
    if len(raw) <= MAX_TEXT_STORE_BYTES:
        return redact(text, MAX_TEXT_STORE_BYTES)
    return redact(raw[:MAX_TEXT_STORE_BYTES].decode("utf-8", errors="ignore"), MAX_TEXT_STORE_BYTES)


def _has_control(value: str) -> bool:
    return any(unicodedata.category(ch).startswith("C") for ch in value)


def _check_json_bounds(value: Any, *, depth: int = 0) -> None:
    if depth > 6:
        raise ValidationError("mailbox request nesting is too deep")
    if isinstance(value, str):
        if len(value.encode("utf-8")) > MAX_STRING_BYTES:
            raise ValidationError("mailbox request string field exceeds size limit")
        if _has_control(value):
            raise ValidationError("mailbox request contains control characters")
    elif isinstance(value, list):
        if len(value) > 50:
            raise ValidationError("mailbox request array exceeds size limit")
        for item in value:
            _check_json_bounds(item, depth=depth + 1)
    elif isinstance(value, dict):
        if len(value) > 50:
            raise ValidationError("mailbox request object exceeds size limit")
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ValidationError("mailbox request object keys must be nonempty strings")
            _check_json_bounds(key, depth=depth + 1)
            _check_json_bounds(item, depth=depth + 1)
    elif value is None or isinstance(value, bool | int | float):
        return
    else:
        raise ValidationError("mailbox request contains unsupported JSON value")


def parse_mailbox_envelope(
    text: str,
    *,
    remote_sender: str,
    expected_bench_did: str = BENCH_DID,
    now: datetime | None = None,
) -> dict[str, Any]:
    if "\n" in text or "\r" in text:
        raise ValidationError("mailbox request envelope must be single-line JSON")
    if len(text.encode("utf-8")) > MAX_JSON_TEXT_BYTES:
        raise ValidationError("mailbox request envelope exceeds size limit")
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValidationError("mailbox request envelope is malformed JSON") from exc
    if not isinstance(envelope, dict):
        raise ValidationError("mailbox request envelope must be a JSON object")
    unexpected = set(envelope) - REQUEST_REQUIRED - REQUEST_OPTIONAL
    missing = REQUEST_REQUIRED - set(envelope)
    if unexpected:
        fields = ", ".join(sorted(unexpected))
        raise ValidationError(f"unexpected mailbox request field(s): {fields}")
    if missing:
        raise ValidationError(f"missing mailbox request field(s): {', '.join(sorted(missing))}")
    _check_json_bounds(envelope)
    if envelope["schema_version"] != MAILBOX_REQUEST_SCHEMA_VERSION:
        raise ValidationError("unsupported mailbox request schema_version")
    for field in ("request_id", "sender_did", "target_did", "requested_capability", "hypothesis"):
        if not isinstance(envelope[field], str) or not envelope[field]:
            raise ValidationError(f"{field} must be a nonempty string")
    if not REQUEST_ID_RE.fullmatch(envelope["request_id"]):
        raise ValidationError("request_id is outside the supported format")
    if envelope["target_did"] != expected_bench_did:
        raise SafetyError("mailbox request target_did is not the Bench DID")
    if envelope["sender_did"] != remote_sender:
        raise SafetyError("mailbox request sender_did does not match Technocore from")
    if envelope["requested_capability"] not in BENCH_SERVICE_CAPABILITIES:
        raise SafetyError("unsupported requested capability")
    if not isinstance(envelope["test_spec"], dict):
        raise ValidationError("test_spec must be an object")
    if not isinstance(envelope["provenance"], dict):
        raise ValidationError("provenance must be an object")
    if "reply_room" in envelope and not isinstance(envelope["reply_room"], str | None):
        raise ValidationError("reply_room must be a string or null")
    if "operator_group" in envelope and not isinstance(envelope["operator_group"], dict | None):
        raise ValidationError("operator_group must be an object or null")
    validate_timestamp_window(envelope["created_at"], envelope["expires_at"], now=now)
    expires = parse_timestamp(envelope["expires_at"], "expires_at").isoformat()
    request_json = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return {
        "request_id": envelope["request_id"],
        "requested_capability": envelope["requested_capability"],
        "expires_at": expires,
        "provenance": envelope["provenance"],
        "request_json": request_json,
    }


def classify_authentication(raw: dict[str, Any], *, room: str = MAILBOX) -> tuple[str, str | None]:
    sender = raw.get("from")
    if not isinstance(sender, str) or not is_valid_ed25519_did(sender):
        return "malformed_or_unverifiable", None
    nonce = message_nonce_text(raw)
    text = raw.get("text")
    if nonce is None or not isinstance(text, str):
        return "malformed_or_unverifiable", sender
    sig = raw.get("sig") or raw.get("signature")
    if isinstance(sig, str):
        # Technocore history normally does not return original signatures. Without exact
        # signature provenance we keep this conservative and avoid false local-verification claims.
        return "server_verified_signed_lane", sender
    del room
    return "server_verified_signed_lane", sender


def classify_mailbox_message(raw: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
    seq = message_seq(raw)
    text = raw.get("text")
    if seq is None or not isinstance(text, str):
        raise ValidationError("mailbox message missing canonical seq or text")
    nonce_text = message_nonce_text(raw)
    auth, sender = classify_authentication(raw)
    classification = "malformed_or_unverifiable"
    review_status = "rejected"
    request_id = None
    requested_capability = None
    expires_at = None
    provenance_json = None
    request_json = None
    if auth == "server_verified_signed_lane" and sender is not None:
        try:
            envelope = parse_mailbox_envelope(text, remote_sender=sender, now=now)
        except FlopBenchMailboxReject as exc:
            classification = exc.classification
        except SafetyError as exc:
            classification = _safe_classification_from_error(exc)
        except ValidationError as exc:
            classification = _safe_classification_from_error(exc)
        else:
            classification = "valid_request"
            review_status = "pending_human_review"
            request_id = envelope["request_id"]
            requested_capability = envelope["requested_capability"]
            expires_at = envelope["expires_at"]
            provenance_json = json.dumps(
                envelope["provenance"],
                sort_keys=True,
                separators=(",", ":"),
            )
            request_json = envelope["request_json"]
    return {
        "message_id": f"{MAILBOX}:{seq}",
        "seq": seq,
        "sender_did": sender,
        "nonce_text": nonce_text,
        "message_hash": mailbox_message_hash(text),
        "untrusted_text": _safe_text(text),
        "remote_ts": str(raw["ts"]) if raw.get("ts") is not None else None,
        "authentication_level": auth,
        "request_id": request_id,
        "requested_capability": requested_capability,
        "classification": classification,
        "review_status": review_status,
        "expires_at": expires_at,
        "provenance_json": provenance_json,
        "request_json": request_json,
    }


def _inactive_mailbox_message(item: dict[str, Any]) -> dict[str, Any]:
    if item["classification"] == "valid_request":
        return {
            **item,
            "classification": "intake_inactive",
            "review_status": "rejected",
        }
    return item


class FlopBenchMailboxReject(SafetyError):
    def __init__(self, classification: str) -> None:
        super().__init__(classification)
        self.classification = classification


def _safe_classification_from_error(exc: Exception) -> str:
    text = str(exc).casefold()
    if "target_did" in text:
        return "target_mismatch"
    if "sender_did" in text:
        return "sender_mismatch"
    if "expired" in text:
        return "expired"
    if "future" in text:
        return "future_timestamp"
    if "unsupported requested capability" in text:
        return "unsupported_capability"
    if "unexpected" in text:
        return "unexpected_field"
    if "malformed json" in text:
        return "malformed_json"
    return "invalid_request"


def _did_note_advertisement_status(state_dir: Path) -> dict[str, Any]:
    namespace, key, _fingerprint = did_profile_path(BENCH_DID)
    expected_note_hash = note_hash(identity_note_value(BENCH_DID))
    latest_ad = latest_did_note_observation(state_dir, namespace=namespace, key=key)
    if latest_ad is None:
        advertised: bool | None = None
        advertisement_status = "unknown_not_reconciled"
    elif (
        latest_ad["status"] == "already-matching"
        and latest_ad["expected_hash"] == expected_note_hash
        and latest_ad["observed_hash"] == expected_note_hash
    ):
        advertised = True
        advertisement_status = "already-matching"
    elif latest_ad["status"] == "absent":
        advertised = False
        advertisement_status = "absent"
    elif latest_ad["status"] == "conflict":
        advertised = False
        advertisement_status = "conflict"
    else:
        advertised = None
        advertisement_status = "unknown_not_reconciled"
    return {
        "advertised": advertised,
        "advertisement_status": advertisement_status,
        "advertisement_expected_hash": expected_note_hash,
    }


def _require_reconciled_did_note_advertisement(state_dir: Path) -> dict[str, Any]:
    status = _did_note_advertisement_status(state_dir)
    if status["advertised"] is not True:
        raise SafetyError("mailbox activation requires reconciled DID-note mailbox advertisement")
    return status


def mailbox_activation_preview(*, state_dir: Path) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    activation = mailbox_activation_state(resolved, mailbox=MAILBOX)
    advertisement = _did_note_advertisement_status(resolved)
    status = migration_status(resolved)
    activation_blockers = []
    if not status["database_exists"]:
        activation_blockers.append("state_database_missing")
    if status["pending_migrations"]:
        activation_blockers.append("state_schema_migration_required")
    if advertisement["advertised"] is not True:
        activation_blockers.append("did_note_advertisement_not_reconciled")
    can_activate = not activation_blockers
    return {
        "ok": True,
        "mailbox": MAILBOX,
        "protocol_version": MAILBOX_REQUEST_SCHEMA_VERSION,
        "protocol": "signed-write-only-room",
        "creation_required": False,
        "state_dir": str(resolved),
        "current_activation": activation,
        "database_exists": status["database_exists"],
        "schema_migrations": status["schema_migrations"],
        "pending_migrations": status["pending_migrations"],
        "migration_required": bool(status["pending_migrations"]),
        "activation_blockers": activation_blockers,
        **advertisement,
        "activation_consequences": [
            "valid signed mailbox requests will enter pending_human_review",
            "approval remains approved_for_manual_execution only",
            "remote content remains untrusted data",
        ],
        "disabled_behaviors": {
            "state_creation": False,
            "migration": False,
            "network": False,
            "identity_loading": False,
            "signing": False,
            "mailbox_creation": False,
            "polling": False,
            "execution": False,
            "reply": False,
            "posting": False,
            "router_updates": False,
            "autonomous_scheduler": False,
        },
        "required_confirmation": MAILBOX_ACTIVATE_CONFIRMATION,
        "can_activate": can_activate,
        "state_write": False,
        "network_action": False,
        "will_sign": False,
        "will_post": False,
        "will_execute": False,
        "will_reply": False,
        "will_update_router": False,
    }


def mailbox_activate(*, state_dir: Path, confirm: str) -> dict[str, Any]:
    if confirm != MAILBOX_ACTIVATE_CONFIRMATION:
        raise SafetyError("mailbox activation requires exact confirmation")
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        raise SafetyError("mailbox activation requires existing Bench state database")
    if status["pending_migrations"]:
        raise SafetyError("mailbox activation requires migrated Bench state")
    advertisement = _require_reconciled_did_note_advertisement(resolved)
    with connect_state(resolved) as conn:
        activation = record_mailbox_activation(
            conn,
            mailbox=MAILBOX,
            protocol_version=MAILBOX_REQUEST_SCHEMA_VERSION,
        )
    return {
        "ok": True,
        **activation,
        **advertisement,
        "state_dir": str(resolved),
        "state_write": True,
        "network_action": False,
        "will_create_mailbox": False,
        "will_poll": False,
        "will_sign": False,
        "will_post": False,
        "will_execute": False,
        "will_reply": False,
        "will_update_router": False,
        "autonomous_scheduler": False,
    }


def mailbox_deactivate(*, state_dir: Path, confirm: str) -> dict[str, Any]:
    if confirm != MAILBOX_DEACTIVATE_CONFIRMATION:
        raise SafetyError("mailbox deactivation requires exact confirmation")
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    if not status["database_exists"]:
        raise SafetyError("mailbox deactivation requires existing Bench state database")
    if status["pending_migrations"]:
        raise SafetyError("mailbox deactivation requires migrated Bench state")
    with connect_state(resolved) as conn:
        activation = record_mailbox_deactivation(conn, mailbox=MAILBOX)
    return {
        "ok": True,
        **activation,
        "state_dir": str(resolved),
        "new_valid_request_classification": "intake_inactive",
        "existing_records_preserved": True,
        "state_write": True,
        "network_action": False,
        "will_create_mailbox": False,
        "will_poll": False,
        "will_sign": False,
        "will_post": False,
        "will_execute": False,
        "will_reply": False,
        "will_update_router": False,
        "autonomous_scheduler": False,
    }


def mailbox_status(*, state_dir: Path) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    resolved = state_dir.expanduser().resolve(strict=False)
    status = migration_status(resolved)
    cursor = 0
    pending = 0
    total = 0
    activation = mailbox_activation_state(resolved, mailbox=MAILBOX)
    supervised_polling = mailbox_activation_state(
        resolved, mailbox=SUPERVISED_POLLING_ACTIVATION_KEY
    )
    advertisement = _did_note_advertisement_status(resolved)
    if status["database_exists"]:
        uri = f"file:{(resolved / STATE_DB).as_posix()}?mode=ro"
        with sqlite3.connect(uri, uri=True) as conn:
            conn.row_factory = sqlite3.Row
            has_table = conn.execute(
                """
                SELECT 1 FROM sqlite_master
                WHERE type = 'table' AND name = 'mailbox_messages'
                """
            ).fetchone()
            if has_table is not None:
                row = conn.execute(
                    "SELECT value FROM metadata WHERE key = ?",
                    (f"mailbox:{MAILBOX}:cursor",),
                ).fetchone()
                try:
                    cursor = int(row["value"]) if row is not None else 0
                except (TypeError, ValueError):
                    cursor = 0
                total = int(conn.execute("SELECT COUNT(*) FROM mailbox_messages").fetchone()[0])
                pending = int(
                    conn.execute(
                        """
                        SELECT COUNT(*)
                        FROM mailbox_messages
                        WHERE review_status = 'pending_human_review'
                        """
                    ).fetchone()[0]
                )
    return {
        "ok": True,
        "mailbox": MAILBOX,
        "protocol": "signed-write-only-room",
        "creation_required": False,
        "activation": activation,
        "intake_active": activation["active"],
        "supervised_continuous_polling": supervised_polling["active"],
        "supervised_continuous_polling_activation": supervised_polling["activation_status"],
        "new_valid_request_classification": (
            "valid_request" if activation["active"] else "intake_inactive"
        ),
        **advertisement,
        "cursor": cursor,
        "messages": total,
        "pending_human_review": pending,
        "state_write": False,
        "network_action": False,
    }


def mailbox_messages(*, state_dir: Path, limit: int) -> dict[str, Any]:
    return mailbox_messages_history(state_dir, limit=limit)


def mailbox_inspect(*, state_dir: Path, message_id: str) -> dict[str, Any]:
    detail = mailbox_message_detail(state_dir, message_id=message_id)
    detail["network_action"] = False
    detail["state_write"] = False
    detail["remote_text_is_untrusted"] = True
    detail["urls_followed"] = False
    detail["executed"] = False
    return detail


def mailbox_poll_local(*, state_dir: Path) -> dict[str, Any]:
    status = mailbox_status(state_dir=state_dir)
    return {
        **status,
        "poll_status": "local_only",
        "network_action": False,
        "state_write": status["state_write"],
        "will_sign": False,
        "will_post": False,
        "will_acquire_nonce": False,
    }


def poll_mailbox(
    *,
    state_dir: Path,
    network: bool,
    transport: ActivationTransport,
    page_limit: int = MAX_MAILBOX_PAGE_LIMIT,
    max_pages: int = MAX_MAILBOX_PAGES,
    max_items: int = MAX_MAILBOX_ITEMS,
    max_bytes: int = MAX_MAILBOX_BYTES,
    max_seconds: float = MAX_MAILBOX_SECONDS,
    sleep_on_429: bool = True,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not network:
        return mailbox_poll_local(state_dir=state_dir)
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    started = time.monotonic()
    with connect_state(state_dir) as conn:
        cursor = mailbox_cursor(conn, room=MAILBOX)
        active = bool(mailbox_activation_state(state_dir, mailbox=MAILBOX)["active"])
    since = cursor
    pages = 0
    items = 0
    bytes_read = 0
    classified: list[dict[str, Any]] = []
    failure: str | None = None
    complete = False
    retries = 0
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    while pages < max_pages and items < max_items:
        if time.monotonic() - started > max_seconds:
            failure = "mailbox_poll_timeout"
            break
        url = mailbox_history_url(limit=page_limit, since=since)
        try:
            response = transport.request(
                "GET", url, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS
            )
        except ActivationRequestError as exc:
            failure = exc.failure_classification
            break
        if response.final_url and response.final_url != url:
            failure = "redirect_rejected"
            break
        bytes_read += len(response.body)
        if bytes_read > max_bytes or len(response.body) > MAX_RESPONSE_BYTES:
            failure = "oversized_response"
            break
        if response.status == 404:
            complete = True
            break
        if response.status == 429 and retries < 1:
            retries += 1
            backoff_for_429(response, sleep=sleep_on_429)
            continue
        if response.status != 200:
            failure = (
                "remote_unavailable"
                if response.status in {408, 429} or response.status >= 500
                else "http_status_error"
            )
            break
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            failure = "malformed_response"
            break
        if not isinstance(parsed, dict):
            failure = "malformed_response"
            break
        raw_messages = extract_room_messages(parsed)
        pages += 1
        items += len(raw_messages)
        max_seq = since
        expected_next = since + 1
        for raw in raw_messages:
            seq = message_seq(raw)
            if seq is None:
                failure = "malformed_response"
                break
            if seq != expected_next:
                failure = "sequence_gap"
                break
            expected_next += 1
            max_seq = max(max_seq, seq)
            try:
                item = classify_mailbox_message(raw, now=now)
                classified.append(item if active else _inactive_mailbox_message(item))
            except ValidationError:
                failure = "malformed_response"
                break
        if failure is not None:
            break
        if len(raw_messages) < page_limit:
            complete = True
            since = max_seq
            break
        if max_seq <= since:
            failure = "history_pagination_stalled"
            break
        since = max_seq
    else:
        failure = "history_scan_incomplete"
    if complete:
        with connect_state(state_dir) as conn:
            stored = store_mailbox_poll(conn, room=MAILBOX, messages=classified, new_cursor=since)
    else:
        stored = {"inserted": 0, "duplicates": 0, "duplicate_request_ids": 0, "cursor": cursor}
    return {
        "ok": complete,
        "poll_status": "complete" if complete else "incomplete",
        "failure_classification": failure,
        "mailbox": MAILBOX,
        "cursor_before": cursor,
        "cursor_after": stored["cursor"],
        "history_scan_complete": complete,
        "pages_scanned": pages,
        "items_scanned": items,
        "bytes_scanned": bytes_read,
        "messages_classified": len(classified) if complete else 0,
        "inserted": stored["inserted"],
        "duplicates": stored["duplicates"],
        "duplicate_request_ids": stored["duplicate_request_ids"],
        "state_write": complete,
        "network_action": "bounded_read_only",
        "will_sign": False,
        "will_post": False,
        "will_acquire_nonce": False,
        "followed_urls": False,
        "executed_remote_content": False,
    }


def request_queue(*, state_dir: Path) -> dict[str, Any]:
    history = mailbox_messages_history(state_dir, limit=100)
    return {
        **history,
        "requests": [
            item for item in history["messages"] if item["review_status"] == "pending_human_review"
        ],
    }


def request_show(*, state_dir: Path, request_id: str) -> dict[str, Any]:
    history = mailbox_messages_history(state_dir, limit=100)
    for item in history["messages"]:
        if item["request_id"] == request_id:
            return {
                "ok": True,
                "request": item,
                "network_action": False,
                "state_write": False,
                "will_execute": False,
            }
    raise SafetyError("request not found")


def _set_review_status(
    *,
    state_dir: Path,
    request_id: str,
    status: str,
    reason: str | None = None,
) -> dict[str, Any]:
    del reason
    with connect_state(state_dir) as conn:
        cur = conn.execute(
            """
            UPDATE mailbox_messages
            SET review_status = ?
            WHERE request_id = ? AND review_status = 'pending_human_review'
            """,
            (status, request_id),
        )
        conn.commit()
        if cur.rowcount != 1:
            raise SafetyError("request not pending human review")
    return {
        "ok": True,
        "request_id": request_id,
        "review_status": status,
        "network_action": False,
        "state_write": True,
        "will_execute": False,
        "will_sign": False,
        "will_post": False,
        "will_reply": False,
        "will_update_router": False,
    }


def request_approve(*, state_dir: Path, request_id: str, confirm: str) -> dict[str, Any]:
    if confirm != "APPROVE-BENCH-REQUEST":
        raise SafetyError("request approval requires exact confirmation")
    return _set_review_status(
        state_dir=state_dir,
        request_id=request_id,
        status="approved_for_manual_execution",
    )


def request_reject(*, state_dir: Path, request_id: str, reason: str) -> dict[str, Any]:
    if not reason.strip():
        raise ValidationError("rejection reason must be nonempty")
    return _set_review_status(
        state_dir=state_dir,
        request_id=request_id,
        status="rejected",
        reason=reason,
    )
