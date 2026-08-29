from __future__ import annotations

from typing import Any

from .exceptions import SafetyError


class DisabledTechnocoreTransport:
    """Fail-closed v0.2 Phase A transport placeholder."""

    def _fail(self, operation: str) -> None:
        raise SafetyError(f"Technocore {operation} is disabled in FLOP Bench v0.2 Phase A")

    def send(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("send")

    def post(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("post")

    def join(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("join")

    def fetch(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("fetch")

    def transfer(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("transfer")

    def create_room(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("create-room")

    def create_mailbox(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("create-mailbox")

    def fetch_url(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("fetch-URL")

    def wallet(self, *_args: Any, **_kwargs: Any) -> None:
        self._fail("wallet")
