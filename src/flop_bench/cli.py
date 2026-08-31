from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .activation import (
    CREATE_MAILBOX_CONFIRMATION,
    CREATE_ROOM_CONFIRMATION,
    UrlLibActivationTransport,
    create_mailbox,
    create_room,
    technocore_status,
)
from .config import BenchConfig, assert_isolated, isolation_boundaries
from .engine import router_export, verify_spec
from .exceptions import FlopBenchError, IsolationError, LedgerError, SafetyError, ValidationError
from .identity import (
    IDENTITY_CONFIRMATION,
    create_production_identity,
    read_interactive_existing_passphrase,
    read_interactive_new_passphrase,
    verify_identity,
)
from .identity_note import (
    DID_NOTE_CONFIRMATION,
    identity_note_status,
    preview_identity_note,
    publish_identity_note,
)
from .ledger import verify_ledger
from .mailbox import (
    mailbox_inspect,
    mailbox_messages,
    mailbox_status,
    poll_mailbox,
    request_approve,
    request_queue,
    request_reject,
    request_show,
)
from .posting import POST_CONFIRMATION, preview_post, protocol_check_post, reconcile_post, send_post
from .posting import history as post_history
from .schemas import validate_test_spec
from .service import (
    dry_run_sign_payload,
    inspect_request,
    plan_init,
    prepare_signed_response,
    service_doctor,
    verify_request,
)
from .state import activation_history, connect_state_with_migrations


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def doctor(state_dir: Path) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir))
    conn, migrations_applied = connect_state_with_migrations(state_dir)
    with conn:
        migrations = [row[0] for row in conn.execute("SELECT version FROM schema_migrations")]
    return {
        "ok": True,
        "state_dir": str(state_dir.expanduser().resolve(strict=False)),
        "schema_migrations": migrations,
        "permission_issues": [],
        "state_write": True,
        "migrations_applied": migrations_applied,
        "network_action": False,
    }


def isolation_report(config: BenchConfig) -> dict[str, Any]:
    checks = isolation_boundaries(config)
    return {"ok": all(bool(check["ok"]) for check in checks), "checks": checks}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="flop-bench")
    sub = parser.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("doctor")
    d.add_argument("--state-dir", required=True, type=Path)
    iso = sub.add_parser("isolation-check")
    iso.add_argument("--state-dir", required=True, type=Path)
    vs = sub.add_parser("validate-spec")
    vs.add_argument("spec", type=Path)
    ver = sub.add_parser("verify")
    ver.add_argument("spec", type=Path)
    ver.add_argument("--state-dir", required=True, type=Path)
    ver.add_argument("--allow-local-exec", action="store_true")
    service = sub.add_parser("service")
    service_sub = service.add_subparsers(dest="service_cmd", required=True)
    service_doctor_cmd = service_sub.add_parser("doctor")
    service_doctor_cmd.add_argument("--state-dir", required=True, type=Path)
    service_doctor_cmd.add_argument("--read-only", action="store_true")
    request = sub.add_parser("request")
    request_sub = request.add_subparsers(dest="request_cmd", required=True)
    request_verify = request_sub.add_parser("verify")
    request_verify.add_argument("request", type=Path)
    request_verify.add_argument("--state-dir", required=True, type=Path)
    request_inspect = request_sub.add_parser("inspect")
    request_inspect.add_argument("request", type=Path)
    request_inspect.add_argument("--state-dir", required=True, type=Path)
    request_queue_cmd = request_sub.add_parser("queue")
    request_queue_cmd.add_argument("--state-dir", required=True, type=Path)
    request_show_cmd = request_sub.add_parser("show")
    request_show_cmd.add_argument("request_id")
    request_show_cmd.add_argument("--state-dir", required=True, type=Path)
    request_approve_cmd = request_sub.add_parser("approve")
    request_approve_cmd.add_argument("request_id")
    request_approve_cmd.add_argument("--state-dir", required=True, type=Path)
    request_approve_cmd.add_argument("--confirm", required=True)
    request_reject_cmd = request_sub.add_parser("reject")
    request_reject_cmd.add_argument("request_id")
    request_reject_cmd.add_argument("--state-dir", required=True, type=Path)
    request_reject_cmd.add_argument("--reason", required=True)
    response = sub.add_parser("response")
    response_sub = response.add_subparsers(dest="response_cmd", required=True)
    response_prepare = response_sub.add_parser("prepare")
    response_prepare.add_argument("evidence", type=Path)
    response_prepare.add_argument("--state-dir", required=True, type=Path)
    technocore = sub.add_parser("technocore")
    technocore_sub = technocore.add_subparsers(dest="technocore_cmd", required=True)
    plan = technocore_sub.add_parser("plan-init")
    plan.add_argument("--state-dir", required=True, type=Path)
    dry_run = technocore_sub.add_parser("dry-run-sign")
    dry_run.add_argument("payload", type=Path)
    dry_run.add_argument("--state-dir", required=True, type=Path)
    create_room_cmd = technocore_sub.add_parser("create-room")
    create_room_cmd.add_argument("--state-dir", required=True, type=Path)
    create_room_cmd.add_argument("--live", action="store_true")
    create_room_cmd.add_argument("--confirm", required=True, choices=[CREATE_ROOM_CONFIRMATION])
    create_mailbox_cmd = technocore_sub.add_parser("create-mailbox")
    create_mailbox_cmd.add_argument("--state-dir", required=True, type=Path)
    create_mailbox_cmd.add_argument("--live", action="store_true")
    create_mailbox_cmd.add_argument(
        "--confirm", required=True, choices=[CREATE_MAILBOX_CONFIRMATION]
    )
    status_cmd = technocore_sub.add_parser("status")
    status_cmd.add_argument("--state-dir", required=True, type=Path)
    activation_history_cmd = technocore_sub.add_parser("activation-history")
    activation_history_cmd.add_argument("--state-dir", required=True, type=Path)
    activation_history_cmd.add_argument("--limit", required=True, type=int)
    ledger = sub.add_parser("ledger")
    ledger_sub = ledger.add_subparsers(dest="ledger_cmd", required=True)
    ledger_verify = ledger_sub.add_parser("verify")
    ledger_verify.add_argument("--state-dir", required=True, type=Path)
    rexp = sub.add_parser("router-export")
    rexp.add_argument("evidence", type=Path)
    identity = sub.add_parser("identity")
    identity_sub = identity.add_subparsers(dest="identity_cmd", required=True)
    create_identity = identity_sub.add_parser("create-production")
    create_identity.add_argument("--state-dir", required=True, type=Path)
    create_identity.add_argument("--confirm", required=True, choices=[IDENTITY_CONFIRMATION])
    verify_identity_cmd = identity_sub.add_parser("verify")
    verify_identity_cmd.add_argument("--state-dir", required=True, type=Path)
    post = sub.add_parser("post")
    post_sub = post.add_subparsers(dest="post_cmd", required=True)
    post_preview = post_sub.add_parser("preview")
    post_preview.add_argument("message", type=Path)
    post_preview.add_argument("--state-dir", required=True, type=Path)
    post_protocol_check = post_sub.add_parser("protocol-check")
    post_protocol_check.add_argument("message", type=Path)
    post_protocol_check.add_argument("--state-dir", required=True, type=Path)
    post_send = post_sub.add_parser("send")
    post_send.add_argument("message", type=Path)
    post_send.add_argument("--state-dir", required=True, type=Path)
    post_send.add_argument("--live", action="store_true")
    post_send.add_argument("--confirm", required=True, choices=[POST_CONFIRMATION])
    post_history_cmd = post_sub.add_parser("history")
    post_history_cmd.add_argument("--state-dir", required=True, type=Path)
    post_history_cmd.add_argument("--limit", required=True, type=int)
    post_reconcile = post_sub.add_parser("reconcile")
    post_reconcile.add_argument("--state-dir", required=True, type=Path)
    post_reconcile.add_argument("--attempt-id", required=True, type=int)
    mailbox = sub.add_parser("mailbox")
    mailbox_sub = mailbox.add_subparsers(dest="mailbox_cmd", required=True)
    mailbox_status_cmd = mailbox_sub.add_parser("status")
    mailbox_status_cmd.add_argument("--state-dir", required=True, type=Path)
    mailbox_poll_cmd = mailbox_sub.add_parser("poll")
    mailbox_poll_cmd.add_argument("--state-dir", required=True, type=Path)
    mailbox_poll_cmd.add_argument("--network", action="store_true")
    mailbox_messages_cmd = mailbox_sub.add_parser("messages")
    mailbox_messages_cmd.add_argument("--state-dir", required=True, type=Path)
    mailbox_messages_cmd.add_argument("--limit", required=True, type=int)
    mailbox_inspect_cmd = mailbox_sub.add_parser("inspect")
    mailbox_inspect_cmd.add_argument("--state-dir", required=True, type=Path)
    mailbox_inspect_cmd.add_argument("--message-id", required=True)
    identity_note = sub.add_parser("identity-note")
    identity_note_sub = identity_note.add_subparsers(dest="identity_note_cmd", required=True)
    identity_note_preview = identity_note_sub.add_parser("preview")
    identity_note_preview.add_argument("--state-dir", required=True, type=Path)
    identity_note_status_cmd = identity_note_sub.add_parser("status")
    identity_note_status_cmd.add_argument("--state-dir", required=True, type=Path)
    identity_note_publish = identity_note_sub.add_parser("publish")
    identity_note_publish.add_argument("--state-dir", required=True, type=Path)
    identity_note_publish.add_argument("--live", action="store_true")
    identity_note_publish.add_argument("--confirm", required=True, choices=[DID_NOTE_CONFIRMATION])
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "doctor":
            _print_json(doctor(args.state_dir))
        elif args.cmd == "isolation-check":
            config = BenchConfig(state_dir=args.state_dir)
            report = isolation_report(config)
            _print_json(report)
            if not report["ok"]:
                return 4
        elif args.cmd == "validate-spec":
            spec = json.loads(args.spec.read_text(encoding="utf-8"))
            validate_test_spec(spec)
            _print_json({"ok": True, "spec": str(args.spec)})
        elif args.cmd == "verify":
            _print_json(
                verify_spec(
                    args.spec,
                    state_dir=args.state_dir,
                    allow_local_exec=args.allow_local_exec,
                )
            )
        elif args.cmd == "service" and args.service_cmd == "doctor":
            _print_json(service_doctor(state_dir=args.state_dir, read_only=args.read_only))
        elif args.cmd == "request" and args.request_cmd == "verify":
            _print_json(verify_request(args.request, state_dir=args.state_dir))
        elif args.cmd == "request" and args.request_cmd == "inspect":
            _print_json(inspect_request(args.request, state_dir=args.state_dir))
        elif args.cmd == "request" and args.request_cmd == "queue":
            _print_json(request_queue(state_dir=args.state_dir))
        elif args.cmd == "request" and args.request_cmd == "show":
            _print_json(request_show(state_dir=args.state_dir, request_id=args.request_id))
        elif args.cmd == "request" and args.request_cmd == "approve":
            _print_json(
                request_approve(
                    state_dir=args.state_dir,
                    request_id=args.request_id,
                    confirm=args.confirm,
                )
            )
        elif args.cmd == "request" and args.request_cmd == "reject":
            _print_json(
                request_reject(
                    state_dir=args.state_dir,
                    request_id=args.request_id,
                    reason=args.reason,
                )
            )
        elif args.cmd == "response" and args.response_cmd == "prepare":
            passphrase = read_interactive_existing_passphrase()
            _print_json(
                prepare_signed_response(
                    args.evidence,
                    state_dir=args.state_dir,
                    passphrase=passphrase,
                )
            )
        elif args.cmd == "technocore" and args.technocore_cmd == "plan-init":
            _print_json(plan_init(state_dir=args.state_dir))
        elif args.cmd == "technocore" and args.technocore_cmd == "dry-run-sign":
            passphrase = read_interactive_existing_passphrase()
            _print_json(
                dry_run_sign_payload(
                    args.payload,
                    state_dir=args.state_dir,
                    passphrase=passphrase,
                )
            )
        elif args.cmd == "technocore" and args.technocore_cmd == "create-room":
            passphrase = read_interactive_existing_passphrase()
            _print_json(
                create_room(
                    live=args.live,
                    confirm=args.confirm,
                    state_dir=args.state_dir,
                    passphrase=passphrase,
                    transport=UrlLibActivationTransport(),
                )
            )
        elif args.cmd == "technocore" and args.technocore_cmd == "create-mailbox":
            _print_json(
                create_mailbox(
                    live=args.live,
                    confirm=args.confirm,
                    state_dir=args.state_dir,
                )
            )
        elif args.cmd == "technocore" and args.technocore_cmd == "status":
            _print_json(
                technocore_status(
                    state_dir=args.state_dir,
                    transport=UrlLibActivationTransport(),
                )
            )
        elif args.cmd == "technocore" and args.technocore_cmd == "activation-history":
            _print_json(activation_history(args.state_dir, limit=args.limit))
        elif args.cmd == "ledger" and args.ledger_cmd == "verify":
            _print_json(verify_ledger(args.state_dir))
        elif args.cmd == "router-export":
            evidence = json.loads(args.evidence.read_text(encoding="utf-8"))
            _print_json(router_export(evidence))
        elif args.cmd == "identity" and args.identity_cmd == "create-production":
            passphrase, confirmation = read_interactive_new_passphrase()
            _print_json(
                create_production_identity(
                    state_dir=args.state_dir,
                    confirm=args.confirm,
                    passphrase=passphrase,
                    passphrase_confirmation=confirmation,
                )
            )
        elif args.cmd == "identity" and args.identity_cmd == "verify":
            passphrase = read_interactive_existing_passphrase()
            _print_json(verify_identity(state_dir=args.state_dir, passphrase=passphrase))
        elif args.cmd == "post" and args.post_cmd == "preview":
            _print_json(preview_post(args.message, state_dir=args.state_dir))
        elif args.cmd == "post" and args.post_cmd == "protocol-check":
            _print_json(protocol_check_post(args.message, state_dir=args.state_dir))
        elif args.cmd == "post" and args.post_cmd == "send":
            passphrase = read_interactive_existing_passphrase()
            _print_json(
                send_post(
                    args.message,
                    state_dir=args.state_dir,
                    live=args.live,
                    confirm=args.confirm,
                    passphrase=passphrase,
                    transport=UrlLibActivationTransport(),
                )
            )
        elif args.cmd == "post" and args.post_cmd == "history":
            _print_json(post_history(state_dir=args.state_dir, limit=args.limit))
        elif args.cmd == "post" and args.post_cmd == "reconcile":
            _print_json(
                reconcile_post(
                    state_dir=args.state_dir,
                    attempt_id=args.attempt_id,
                    transport=UrlLibActivationTransport(),
                )
            )
        elif args.cmd == "mailbox" and args.mailbox_cmd == "status":
            _print_json(mailbox_status(state_dir=args.state_dir))
        elif args.cmd == "mailbox" and args.mailbox_cmd == "poll":
            _print_json(
                poll_mailbox(
                    state_dir=args.state_dir,
                    network=args.network,
                    transport=UrlLibActivationTransport(),
                )
            )
        elif args.cmd == "mailbox" and args.mailbox_cmd == "messages":
            _print_json(mailbox_messages(state_dir=args.state_dir, limit=args.limit))
        elif args.cmd == "mailbox" and args.mailbox_cmd == "inspect":
            _print_json(mailbox_inspect(state_dir=args.state_dir, message_id=args.message_id))
        elif args.cmd == "identity-note" and args.identity_note_cmd == "preview":
            _print_json(preview_identity_note(state_dir=args.state_dir))
        elif args.cmd == "identity-note" and args.identity_note_cmd == "status":
            _print_json(
                identity_note_status(
                    state_dir=args.state_dir,
                    transport=UrlLibActivationTransport(),
                )
            )
        elif args.cmd == "identity-note" and args.identity_note_cmd == "publish":
            _print_json(
                publish_identity_note(
                    state_dir=args.state_dir,
                    live=args.live,
                    confirm=args.confirm,
                    transport=UrlLibActivationTransport(),
                )
            )
        else:
            raise FlopBenchError("unknown command")
    except LedgerError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 3
    except (SafetyError, IsolationError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 4
    except FlopBenchError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0


def main() -> None:
    raise SystemExit(run())


if __name__ == "__main__":
    main()
