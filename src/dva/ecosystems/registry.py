"""Explicit, in-process registry of ecosystem adapters.

There is no dynamic plugin loading: built-in adapters are listed in
``_BUILTIN_ADAPTERS`` and callers may register additional adapter objects
programmatically. Conflicts are rejected rather than resolved by precedence.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

from dva.contracts.ecosystem import EcosystemAdapter, FileFormat
from dva.ecosystems.python import PythonAdapter

_ADAPTER_ID = re.compile(r"^[a-z0-9]+(?:[._-][a-z0-9]+)*$")

#: Adapters shipped with DVA.
_BUILTIN_ADAPTERS: tuple[EcosystemAdapter, ...] = (PythonAdapter(),)


class RegistrationError(ValueError):
    """An adapter could not be registered because it is invalid or conflicts."""


class AdapterRegistry:
    def __init__(self, adapters: Iterable[EcosystemAdapter] = ()) -> None:
        self._adapters: dict[str, EcosystemAdapter] = {}
        self._pattern_owner: dict[str, str] = {}
        for adapter in adapters:
            self.register(adapter)

    def register(self, adapter: EcosystemAdapter) -> None:
        adapter_id = adapter.adapter_id
        if not _ADAPTER_ID.match(adapter_id):
            raise RegistrationError(f"invalid adapter id: {adapter_id!r}")
        if adapter_id in self._adapters:
            raise RegistrationError(f"adapter id already registered: {adapter_id!r}")
        if not adapter.display_name or not adapter.ecosystem:
            raise RegistrationError(f"adapter {adapter_id!r} needs a display name and ecosystem")
        formats = adapter.formats
        if not formats:
            raise RegistrationError(f"adapter {adapter_id!r} declares no file formats")
        patterns = [file_format.pattern for file_format in formats]
        if len(set(patterns)) != len(patterns):
            raise RegistrationError(f"adapter {adapter_id!r} declares a pattern twice")
        for pattern in patterns:
            owner = self._pattern_owner.get(pattern)
            if owner is not None:
                raise RegistrationError(
                    f"pattern {pattern!r} of adapter {adapter_id!r} is already claimed by {owner!r}"
                )
        self._adapters[adapter_id] = adapter
        for pattern in patterns:
            self._pattern_owner[pattern] = adapter_id

    @property
    def adapters(self) -> tuple[EcosystemAdapter, ...]:
        """Registered adapters in registration order."""
        return tuple(self._adapters.values())

    def get(self, adapter_id: str) -> EcosystemAdapter | None:
        return self._adapters.get(adapter_id)

    def match(self, filename: str) -> tuple[tuple[EcosystemAdapter, FileFormat], ...]:
        """Every (adapter, format) whose pattern matches ``filename``, in registration order."""
        return tuple(
            (adapter, file_format)
            for adapter in self._adapters.values()
            for file_format in adapter.formats
            if file_format.matches(filename)
        )


def default_registry() -> AdapterRegistry:
    """A fresh registry containing DVA's built-in adapters."""
    return AdapterRegistry(_BUILTIN_ADAPTERS)
