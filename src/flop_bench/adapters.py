from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from .canonical import sha256_file
from .exceptions import SafetyError, ValidationError
from .redaction import redact

MAX_CAPTURE = 8192
ALLOWLIST_ENV = ("PATH", "LANG", "LC_ALL", "TZ")
NETWORK_COMMANDS = {
    "curl",
    "ftp",
    "nc",
    "netcat",
    "nmap",
    "openssl",
    "ping",
    "rsync",
    "scp",
    "sftp",
    "ssh",
    "telnet",
    "wget",
}
DYNAMIC_CODE_TOKENS = ("eval(", "exec(", "__import__(", "importlib.")


def reject_url_like(value: Any) -> None:
    text = json.dumps(value, sort_keys=True)
    if "http://" in text or "https://" in text or "www." in text:
        raise SafetyError("automatic URL fetching or URL-directed actions are disabled in v0.1")


def reject_local_command_safety_hazards(step: dict[str, Any], argv: list[str]) -> None:
    reject_url_like(step)
    if "allow_local_exec" in step:
        raise SafetyError("test specifications cannot authorize local command execution")
    executable = Path(argv[0]).name if argv else ""
    module = " ".join([executable, *argv[1:3]]) if len(argv) >= 3 else executable
    if executable in NETWORK_COMMANDS or module in {
        "python -m http.server",
        "python3 -m http.server",
    }:
        raise SafetyError(f"network-capable command is disabled in v0.1: {executable}")
    joined = "\n".join(argv)
    if any(token in joined for token in DYNAMIC_CODE_TOKENS):
        raise SafetyError("eval, exec, and dynamic imports requested by specs are disabled")
    env = step.get("env", {})
    if not isinstance(env, dict):
        raise SafetyError("local command env must be an object when provided")
    blocked_env = sorted(set(str(key) for key in env) - set(ALLOWLIST_ENV))
    if blocked_env:
        raise SafetyError(f"local command env key(s) are not allowlisted: {', '.join(blocked_env)}")


def json_path_value(obj: Any, dotted_path: str) -> Any:
    current = obj
    for part in dotted_path.split("."):
        if isinstance(current, dict):
            current = current[part]
        elif isinstance(current, list):
            current = current[int(part)]
        else:
            raise KeyError(dotted_path)
    return current


def run_passive_step(step: dict[str, Any]) -> dict[str, Any]:
    reject_url_like(step)
    adapter = step.get("adapter")
    path = Path(str(step.get("path", ""))).expanduser()
    if adapter == "file_exists":
        exists = path.exists()
        return {"adapter": adapter, "path": str(path), "exists": exists, "pass": exists}
    if adapter == "file_sha256":
        expected = step.get("sha256")
        actual = sha256_file(path) if path.exists() else None
        return {
            "adapter": adapter,
            "path": str(path),
            "sha256": actual,
            "pass": actual == expected,
        }
    if adapter == "text_contains":
        needle = str(step.get("text", ""))
        content = path.read_text(encoding="utf-8") if path.exists() else ""
        return {
            "adapter": adapter,
            "path": str(path),
            "contains": needle in content,
            "pass": needle in content,
        }
    if adapter == "json_path_equals":
        obj = json.loads(path.read_text(encoding="utf-8"))
        actual = json_path_value(obj, str(step["json_path"]))
        return {
            "adapter": adapter,
            "path": str(path),
            "actual": actual,
            "expected": step.get("equals"),
            "pass": actual == step.get("equals"),
        }
    if adapter == "json_schema":
        obj = json.loads(path.read_text(encoding="utf-8"))
        schema = json.loads(Path(str(step["schema_path"])).read_text(encoding="utf-8"))
        errors = sorted(
            Draft202012Validator(schema).iter_errors(obj),
            key=lambda err: err.path,
        )
        return {
            "adapter": adapter,
            "path": str(path),
            "errors": [err.message for err in errors],
            "pass": not errors,
        }
    raise ValidationError(f"unknown passive adapter: {adapter}")


def run_local_command_step(step: dict[str, Any], *, allow_local_exec: bool) -> dict[str, Any]:
    if not allow_local_exec:
        raise SafetyError("local command execution requires CLI flag --allow-local-exec")
    argv = step.get("argv")
    if not isinstance(argv, list) or not all(isinstance(item, str) for item in argv):
        raise SafetyError("local command argv must be a JSON array of strings")
    if not argv or not argv[0]:
        raise SafetyError("local command argv must include an executable")
    reject_local_command_safety_hazards(step, argv)
    if "cwd" not in step:
        raise SafetyError("local command requires an explicit working directory")
    cwd = Path(str(step["cwd"])).expanduser().resolve(strict=False)
    if not cwd.is_dir():
        raise SafetyError("local command requires an explicit existing working directory")
    timeout = float(step.get("timeout_seconds", 10))
    if timeout <= 0:
        raise SafetyError("local command timeout must be greater than zero")
    env = {key: os.environ[key] for key in ALLOWLIST_ENV if key in os.environ}
    env.update({str(k): str(v) for k, v in step.get("env", {}).items()})
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 - explicitly human-gated argv execution.
            argv,
            cwd=cwd,
            env=env,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        duration = time.monotonic() - started
        stdout = redact(completed.stdout, MAX_CAPTURE)
        stderr = redact(completed.stderr, MAX_CAPTURE)
        expected = step.get("expect_exit_code", 0)
        passed = completed.returncode == expected and "[truncated]" not in stdout + stderr
        return {
            "adapter": "local_command",
            "argv": argv,
            "cwd": str(cwd),
            "exit_code": completed.returncode,
            "duration_seconds": round(duration, 6),
            "stdout": stdout,
            "stderr": stderr,
            "pass": passed,
            "provenance": {"local_execution": True, "network_sandboxed": False},
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "adapter": "local_command",
            "argv": argv,
            "cwd": str(cwd),
            "timeout_seconds": timeout,
            "duration_seconds": round(time.monotonic() - started, 6),
            "stdout": redact(
                (exc.stdout or "") if isinstance(exc.stdout, str) else "", MAX_CAPTURE
            ),
            "stderr": redact(
                (exc.stderr or "") if isinstance(exc.stderr, str) else "", MAX_CAPTURE
            ),
            "timed_out": True,
            "pass": False,
            "provenance": {"local_execution": True, "network_sandboxed": False},
        }
