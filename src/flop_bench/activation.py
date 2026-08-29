from __future__ import annotations

import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .canonical import sha256_bytes
from .config import (
    BENCH_DID,
    CANONICAL_ROOM,
    DEFAULT_PRODUCTION_STATE,
    MAILBOX,
    BenchConfig,
    assert_isolated,
)
from .exceptions import SafetyError
from .identity import b64u, is_valid_ed25519_did, load_production_identity_key
from .ledger import append_record
from .redaction import redact
from .state import connect_state, record_service_activation

TECHNOCORE_ORIGIN = "https://technocore.chat"
USER_AGENT = "flop-bench/0.2-phase-b"
MAX_RESPONSE_BYTES = 1_000_000
REQUEST_TIMEOUT_SECONDS = 20.0
MAX_RETRY_AFTER_SECONDS = 30.0
MAX_ACTIVATION_ATTEMPTS = 3
CREATE_ROOM_CONFIRMATION = "CREATE-D-FLOP-BENCH"
CREATE_MAILBOX_CONFIRMATION = "CREATE-MB-FLOP-BENCH"


@dataclass(frozen=True)
class TransportResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    final_url: str | None = None


class ActivationTransport(Protocol):
    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> TransportResponse: ...


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class UrlLibActivationTransport:
    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(NoRedirectHandler)

    def request(
        self,
        method: str,
        url: str,
        *,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = REQUEST_TIMEOUT_SECONDS,
    ) -> TransportResponse:
        validate_origin(url)
        req = urllib.request.Request(  # noqa: S310 - validate_origin allowlists Technocore.
            url,
            data=body,
            method=method,
            headers=headers or {},
        )
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = resp.read(MAX_RESPONSE_BYTES + 1)
                final_url = resp.geturl()
                status = int(resp.status)
                response_headers = dict(resp.headers.items())
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_RESPONSE_BYTES + 1)
            final_url = exc.geturl()
            status = int(exc.code)
            response_headers = dict(exc.headers.items())
        except (TimeoutError, urllib.error.URLError) as exc:
            raise SafetyError("Technocore request timed out or failed before verification") from exc
        if final_url and final_url != url:
            raise SafetyError("Technocore redirect refused")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SafetyError("Technocore response exceeded local safety limit")
        return TransportResponse(
            status=status,
            body=raw,
            headers=response_headers,
            final_url=final_url,
        )


def validate_origin(url: str, *, origin: str = TECHNOCORE_ORIGIN) -> None:
    parsed = urllib.parse.urlparse(url)
    allowed = urllib.parse.urlparse(origin)
    if parsed.scheme != "https":
        raise SafetyError("Technocore live transport requires HTTPS")
    if parsed.scheme != allowed.scheme or parsed.netloc != allowed.netloc:
        raise SafetyError("Technocore origin is not allowlisted")


def quote(value: str) -> str:
    return urllib.parse.quote(value, safe="")


def service_note_url(namespace: str, key: str) -> str:
    return f"{TECHNOCORE_ORIGIN}/kv/{quote(namespace)}/{quote(key)}"


def signed_note_url(
    namespace: str,
    key: str,
    signer_did: str,
    sig: str,
    nonce: int,
    value: str,
) -> str:
    return (
        f"{service_note_url(namespace, key)}/set-signed/"
        f"{quote(signer_did)}/{quote(sig)}/{nonce}/{quote(value)}?if_absent=1"
    )


def signed_note_preimage(namespace: str, key: str, nonce: int, value: str) -> bytes:
    return f"{namespace}|{key}|{nonce}|{value}".encode()


def room_owner_claim_preimage(room: str, nonce: int, did: str) -> bytes:
    return signed_note_preimage("room-owners", room, nonce, did)


def validate_live_gate(
    *,
    live: bool,
    confirm: str,
    expected_confirm: str,
    state_dir: Path,
    expected_state_dir: Path,
) -> Path:
    if not live:
        raise SafetyError("live Technocore operation requires explicit --live")
    if confirm != expected_confirm:
        raise SafetyError("live Technocore operation requires the exact confirmation string")
    resolved = state_dir.expanduser().resolve(strict=False)
    if resolved != expected_state_dir.expanduser().resolve(strict=False):
        raise SafetyError("live Technocore state directory must resolve exactly to Bench state")
    assert_isolated(BenchConfig(state_dir=resolved, subject_did=BENCH_DID))
    return resolved


def parse_owner_note(raw: bytes | None) -> str | None:
    if raw is None:
        return None
    text = raw.decode("utf-8", errors="replace")
    candidates = {
        item for item in text.split() if item.startswith("did:key:") and is_valid_ed25519_did(item)
    }
    if len(candidates) == 1:
        return next(iter(candidates))
    if not candidates:
        return None
    raise SafetyError("ownership response contained multiple valid DIDs")


def response_hash(response: TransportResponse) -> str:
    return sha256_bytes(response.body[:4096])


def request_text(
    transport: ActivationTransport,
    method: str,
    url: str,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> TransportResponse:
    response = transport.request(
        method,
        url,
        headers={"User-Agent": USER_AGENT},
        timeout=timeout,
    )
    if response.final_url and response.final_url != url:
        raise SafetyError("Technocore redirect refused")
    if len(response.body) > MAX_RESPONSE_BYTES:
        raise SafetyError("Technocore response exceeded local safety limit")
    return response


def get_note(
    transport: ActivationTransport,
    namespace: str,
    key: str,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> tuple[str | None, TransportResponse]:
    response = request_text(transport, "GET", service_note_url(namespace, key), timeout=timeout)
    if response.status == 404:
        return None, response
    if response.status != 200:
        raise SafetyError(f"Technocore status check failed: HTTP {response.status}")
    return parse_owner_note(response.body), response


def get_nonce(
    transport: ActivationTransport,
    room: str,
    *,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> tuple[int, TransportResponse]:
    response = request_text(transport, "GET", service_note_url("room-nonce", room), timeout=timeout)
    if response.status == 404:
        return 0, response
    if response.status != 200:
        raise SafetyError(f"Technocore nonce check failed: HTTP {response.status}")
    digits = "".join(ch for ch in response.body.decode("utf-8", errors="replace") if ch.isdigit())
    return (int(digits) if digits else 0), response


def backoff_for_429(response: TransportResponse, *, sleep: bool) -> float:
    retry_after = response.headers.get("Retry-After") or response.headers.get("retry-after") or "1"
    try:
        seconds = float(retry_after)
    except ValueError:
        seconds = 1.0
    seconds = max(0.0, min(seconds, MAX_RETRY_AFTER_SECONDS))
    if sleep and seconds:
        time.sleep(seconds)
    return seconds


def activation_status_for_existing(observed_owner: str | None, expected_owner: str) -> str:
    if observed_owner is None:
        return "unclaimed"
    if observed_owner == expected_owner:
        return "already-owned"
    return "name-conflict"


def record_activation_audit(
    state_dir: Path,
    *,
    service_type: str,
    service_name: str,
    expected_owner_did: str,
    observed_owner_did: str | None,
    activation_status: str,
    response_status: int | None,
    nonce_used: int | None,
    response_body_hash: str | None,
    failure_classification: str | None,
) -> None:
    with connect_state(state_dir) as conn:
        record_service_activation(
            conn,
            service_type=service_type,
            service_name=service_name,
            expected_owner_did=expected_owner_did,
            observed_owner_did=observed_owner_did,
            activation_status=activation_status,
            response_status=response_status,
            nonce_used=nonce_used,
            response_hash=response_body_hash,
            failure_classification=failure_classification,
        )
    append_record(
        state_dir,
        {
            "schema_version": "flop-bench.activation-audit.v0.2",
            "service_type": service_type,
            "service_name": service_name,
            "expected_owner_did": expected_owner_did,
            "observed_owner_did": observed_owner_did,
            "activation_status": activation_status,
            "response_status": response_status,
            "nonce_used": nonce_used,
            "response_hash": response_body_hash,
            "failure_classification": failure_classification,
        },
    )


def classify_write_failure(status: int) -> str:
    if status == 409:
        return "name-conflict"
    if status == 422:
        return "duplicate-or-invalid"
    if status == 429:
        return "rate-limited"
    if 500 <= status <= 599:
        return "server-error"
    return "write-failed"


def create_service(
    *,
    service_type: str,
    service_name: str,
    namespace: str,
    live: bool,
    confirm: str,
    expected_confirm: str,
    state_dir: Path,
    passphrase: str,
    transport: ActivationTransport,
    expected_state_dir: Path = DEFAULT_PRODUCTION_STATE,
    expected_bench_did: str = BENCH_DID,
    sleep_on_429: bool = True,
    max_attempts: int = MAX_ACTIVATION_ATTEMPTS,
) -> dict[str, Any]:
    resolved_state = validate_live_gate(
        live=live,
        confirm=confirm,
        expected_confirm=expected_confirm,
        state_dir=state_dir,
        expected_state_dir=expected_state_dir,
    )
    key = load_production_identity_key(
        state_dir=resolved_state,
        passphrase=passphrase,
        expected_state_dir=expected_state_dir,
        expected_did=expected_bench_did,
    )
    observed, read_response = get_note(transport, namespace, service_name)
    existing = activation_status_for_existing(observed, expected_bench_did)
    if existing == "already-owned":
        record_activation_audit(
            resolved_state,
            service_type=service_type,
            service_name=service_name,
            expected_owner_did=expected_bench_did,
            observed_owner_did=observed,
            activation_status=existing,
            response_status=read_response.status,
            nonce_used=None,
            response_body_hash=response_hash(read_response),
            failure_classification=None,
        )
        return {"ok": True, "status": existing, "service": service_name, "owner": observed}
    if existing == "name-conflict":
        record_activation_audit(
            resolved_state,
            service_type=service_type,
            service_name=service_name,
            expected_owner_did=expected_bench_did,
            observed_owner_did=observed,
            activation_status=existing,
            response_status=read_response.status,
            nonce_used=None,
            response_body_hash=response_hash(read_response),
            failure_classification="foreign-owner",
        )
        raise SafetyError(f"{service_name} is already owned by another DID")
    nonce_base, _nonce_response = get_nonce(transport, service_name)
    last_response: TransportResponse | None = None
    for attempt in range(max_attempts):
        nonce = nonce_base + 1 + attempt
        preimage = signed_note_preimage(namespace, service_name, nonce, expected_bench_did)
        sig = b64u(key.sign(preimage))
        url = signed_note_url(
            namespace,
            service_name,
            expected_bench_did,
            sig,
            nonce,
            expected_bench_did,
        )
        response = request_text(transport, "GET", url)
        last_response = response
        if response.status in {200, 201, 204}:
            verified, verify_response = get_note(transport, namespace, service_name)
            if verified != expected_bench_did:
                record_activation_audit(
                    resolved_state,
                    service_type=service_type,
                    service_name=service_name,
                    expected_owner_did=expected_bench_did,
                    observed_owner_did=verified,
                    activation_status="unverifiable",
                    response_status=verify_response.status,
                    nonce_used=nonce,
                    response_body_hash=response_hash(verify_response),
                    failure_classification="ownership-verification-failed",
                )
                raise SafetyError("created service ownership could not be verified")
            record_activation_audit(
                resolved_state,
                service_type=service_type,
                service_name=service_name,
                expected_owner_did=expected_bench_did,
                observed_owner_did=verified,
                activation_status="created",
                response_status=response.status,
                nonce_used=nonce,
                response_body_hash=response_hash(response),
                failure_classification=None,
            )
            return {"ok": True, "status": "created", "service": service_name, "owner": verified}
        if response.status == 429 and attempt < max_attempts - 1:
            backoff_for_429(response, sleep=sleep_on_429)
            nonce_base, _ = get_nonce(transport, service_name)
            continue
        if response.status in {409, 422} and attempt < max_attempts - 1:
            nonce_base, _ = get_nonce(transport, service_name)
            continue
        failure = classify_write_failure(response.status)
        record_activation_audit(
            resolved_state,
            service_type=service_type,
            service_name=service_name,
            expected_owner_did=expected_bench_did,
            observed_owner_did=observed,
            activation_status="failed",
            response_status=response.status,
            nonce_used=nonce,
            response_body_hash=response_hash(response),
            failure_classification=failure,
        )
        body = response.body.decode("utf-8", errors="replace")
        raise SafetyError(f"Technocore activation failed: {failure}: {redact(body, 512)}")
    status = last_response.status if last_response else None
    raise SafetyError(f"Technocore activation failed after bounded retries: {status}")


def create_room(
    *,
    live: bool,
    confirm: str,
    state_dir: Path,
    passphrase: str,
    transport: ActivationTransport,
    expected_state_dir: Path = DEFAULT_PRODUCTION_STATE,
    expected_bench_did: str = BENCH_DID,
    sleep_on_429: bool = True,
) -> dict[str, Any]:
    return create_service(
        service_type="room",
        service_name=CANONICAL_ROOM,
        namespace="room-owners",
        live=live,
        confirm=confirm,
        expected_confirm=CREATE_ROOM_CONFIRMATION,
        state_dir=state_dir,
        passphrase=passphrase,
        transport=transport,
        expected_state_dir=expected_state_dir,
        expected_bench_did=expected_bench_did,
        sleep_on_429=sleep_on_429,
    )


def create_mailbox(
    *,
    live: bool,
    confirm: str,
    state_dir: Path,
    transport: ActivationTransport | None = None,
    expected_state_dir: Path = DEFAULT_PRODUCTION_STATE,
    expected_bench_did: str = BENCH_DID,
    sleep_on_429: bool = True,
) -> dict[str, Any]:
    del live, confirm, state_dir, transport, expected_state_dir, expected_bench_did, sleep_on_429
    raise SafetyError("PROTOCOL_UNCONFIRMED: live mailbox creation protocol has not been verified")


def technocore_status(
    *,
    state_dir: Path,
    transport: ActivationTransport,
) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir, subject_did=BENCH_DID))
    room_owner, room_response = get_note(transport, "room-owners", CANONICAL_ROOM)
    return {
        "ok": True,
        "network_action": True,
        "room": {
            "name": CANONICAL_ROOM,
            "owner": room_owner,
            "status": activation_status_for_existing(room_owner, BENCH_DID),
            "response_status": room_response.status,
        },
        "mailbox": {
            "name": MAILBOX,
            "owner": None,
            "status": "unknown",
            "protocol_status": "unconfirmed",
            "response_status": None,
        },
    }
