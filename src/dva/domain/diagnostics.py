"""Structured diagnostics emitted by discovery, adapters, and the pipeline."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from dva.domain.paths import require_relative_path

_CODE = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")


class DiagnosticLevel(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """A machine-readable observation about the scan.

    ``code`` is a stable identifier (for example ``discovery.depth_limit``);
    ``message`` is human-readable and must not contain absolute paths.
    """

    code: str
    level: DiagnosticLevel
    message: str
    path: str | None = None

    def __post_init__(self) -> None:
        if not _CODE.match(self.code):
            raise ValueError(f"invalid diagnostic code: {self.code!r}")
        if not self.message.strip():
            raise ValueError("diagnostic message must not be empty")
        if self.path is not None:
            require_relative_path(self.path)
