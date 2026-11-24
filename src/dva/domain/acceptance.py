"""Accepted risks: findings a team has reviewed and decided to live with.

An acceptance names an advisory (by its id or any alias, such as a CVE id),
optionally the package it applies to, a reason, and optionally the last day
it holds. Accepting a finding never hides it: reports keep listing it, marked
as accepted, and only the exit code stops counting it. Once the date has
passed, the finding counts again.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

#: The longest reason DVA keeps.
MAX_REASON_LENGTH = 500


def _require_label(field: str, value: str) -> None:
    if not value or value != value.strip() or any(char.isspace() for char in value):
        raise ValueError(f"{field} must be a single word without spaces: {value!r}")
    if any(not char.isprintable() for char in value):
        raise ValueError(f"{field} can't contain control characters")


@dataclass(frozen=True, slots=True)
class Acceptance:
    advisory: str
    reason: str
    package: str | None = None
    until: date | None = None

    def __post_init__(self) -> None:
        _require_label("the advisory id", self.advisory)
        if self.package is not None:
            _require_label("the package name", self.package)
        reason = self.reason.strip()
        if not reason:
            raise ValueError("an acceptance needs a reason")
        if len(reason) > MAX_REASON_LENGTH:
            raise ValueError(f"the reason can be at most {MAX_REASON_LENGTH} characters")
        if any(not char.isprintable() for char in reason):
            raise ValueError("the reason can't contain control characters")
        object.__setattr__(self, "reason", reason)

    def expired(self, today: date) -> bool:
        return self.until is not None and today > self.until

    def names(self, ids: set[str]) -> bool:
        """Whether this acceptance is about one of these advisory ids (any case)."""
        return self.advisory.casefold() in {i.casefold() for i in ids}
