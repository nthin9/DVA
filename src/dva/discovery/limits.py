"""Resource limits applied to every scan."""

from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True, slots=True)
class ScanLimits:
    """Upper bounds on how much of a project DVA will read.

    ``max_depth`` is the number of directory levels below the project root
    that are searched (files directly in the root are at depth 0).
    ``max_entries`` bounds the total number of directory entries examined.
    """

    max_depth: int = 16
    max_entries: int = 100_000
    max_manifests: int = 1_000
    max_file_bytes: int = 32 * 1024 * 1024

    def __post_init__(self) -> None:
        for field in fields(self):
            value = getattr(self, field.name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise ValueError(f"{field.name} must be a positive integer, got {value!r}")
