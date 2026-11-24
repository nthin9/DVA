"""Contracts for vulnerability sources and the local advisory cache.

A source answers two questions: which advisories exist for these packages
(identified by ecosystem and name only, never by project details), and what
does one advisory record say. The cache keeps both answers with the time
they were retrieved, so a scan can run offline and say how old its data is.
Records are kept as the source's raw text and parsed again when read, so the
cache never has to trust its own contents.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from dva.domain.advisory import Advisory


class ProviderError(Exception):
    """A vulnerability source could not be reached or answered badly.

    Messages are safe to show: they never contain credentials or local paths.
    """


@dataclass(frozen=True, slots=True, order=True)
class PackageKey:
    """A package as a vulnerability source knows it.

    ``ecosystem`` is DVA's identifier (``pypi``, ``npm``); ``name`` is the
    full name the ecosystem uses, scope included (``@babel/core``).
    """

    ecosystem: str
    name: str


@dataclass(frozen=True, slots=True)
class AdvisoryStamp:
    """An advisory id and when the source last modified the record."""

    id: str
    modified: datetime


class AdvisorySource(Protocol):
    @property
    def provider_id(self) -> str: ...

    def supports(self, ecosystem: str) -> bool: ...

    def list_advisories(
        self, packages: Sequence[PackageKey]
    ) -> Mapping[PackageKey, tuple[AdvisoryStamp, ...]]:
        """Every advisory for each package, whatever the version. Raises ProviderError."""
        ...

    def fetch_record(self, advisory_id: str) -> str:
        """The raw record text for one advisory. Raises ProviderError."""
        ...

    def parse_record(self, raw: str) -> Advisory:
        """Parse raw record text. Raises ValueError if the record can't be used."""
        ...


@dataclass(frozen=True, slots=True)
class CachedIndex:
    stamps: tuple[AdvisoryStamp, ...]
    retrieved_at: datetime


@dataclass(frozen=True, slots=True)
class CachedRecord:
    raw: str
    modified: datetime
    retrieved_at: datetime


class AdvisoryCache(Protocol):
    def get_index(self, provider: str, key: PackageKey) -> CachedIndex | None: ...

    def put_index(
        self,
        provider: str,
        key: PackageKey,
        stamps: Sequence[AdvisoryStamp],
        retrieved_at: datetime,
    ) -> None: ...

    def get_record(self, provider: str, advisory_id: str) -> CachedRecord | None: ...

    def put_record(
        self,
        provider: str,
        advisory_id: str,
        modified: datetime,
        raw: str,
        retrieved_at: datetime,
    ) -> None: ...
