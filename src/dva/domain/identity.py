"""Normalized package identity."""

from __future__ import annotations

from dataclasses import dataclass


def _require_text(field: str, value: str) -> None:
    if not value or not value.strip() or value != value.strip():
        raise ValueError(f"{field} must be non-empty without surrounding whitespace: {value!r}")


@dataclass(frozen=True, slots=True)
class PackageIdentity:
    """Identity of a package within an ecosystem.

    ``ecosystem`` is the adapter-defined ecosystem identifier (for example
    ``pypi`` or ``npm``). ``name`` and ``namespace`` keep the ecosystem's own
    spelling; any normalization is the adapter's responsibility. ``purl`` is
    supplied by the adapter when the ecosystem has a registered Package URL type.
    """

    ecosystem: str
    name: str
    namespace: str | None = None
    purl: str | None = None

    def __post_init__(self) -> None:
        _require_text("ecosystem", self.ecosystem)
        _require_text("name", self.name)
        if self.namespace is not None:
            _require_text("namespace", self.namespace)
        if self.purl is not None and not self.purl.startswith("pkg:"):
            raise ValueError(f"purl must start with 'pkg:': {self.purl!r}")
