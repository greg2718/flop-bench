from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

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
from .ledger import verify_ledger
from .schemas import validate_test_spec
from .state import connect_state


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def doctor(state_dir: Path) -> dict[str, Any]:
    assert_isolated(BenchConfig(state_dir=state_dir))
    with connect_state(state_dir) as conn:
        migrations = [row[0] for row in conn.execute("SELECT version FROM schema_migrations")]
    return {"ok": True, "state_dir": str(state_dir), "schema_migrations": migrations}


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
