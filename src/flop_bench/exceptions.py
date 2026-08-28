class FlopBenchError(Exception):
    """Base error for CLI-safe failures."""


class SafetyError(FlopBenchError):
    """Raised when a requested action violates v0.1 safety policy."""


class IsolationError(FlopBenchError):
    """Raised when Bench configuration overlaps Scout state or identity."""


class ValidationError(FlopBenchError):
    """Raised when a spec or evidence document is invalid."""


class LedgerError(FlopBenchError):
    """Raised when ledger verification fails."""
