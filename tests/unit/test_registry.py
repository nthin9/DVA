from __future__ import annotations

import pytest

from dva.ecosystems.registry import AdapterRegistry, RegistrationError, default_registry
from tests.support.example_adapter import EXAMPLE_DEPS, ExampleAdapter, RaisingAdapter


def test_registers_and_matches_adapters_in_order() -> None:
    example, raising = ExampleAdapter(), RaisingAdapter()
    registry = AdapterRegistry([example, raising])
    assert registry.adapters == (example, raising)
    assert registry.get("example") is example
    assert registry.get("missing") is None
    assert registry.match("example-deps.txt") == ((example, EXAMPLE_DEPS),)
    assert registry.match("unrelated.txt") == ()


def test_rejects_duplicate_adapter_id() -> None:
    registry = AdapterRegistry([ExampleAdapter()])
    with pytest.raises(RegistrationError, match="already registered"):
        registry.register(ExampleAdapter())


def test_rejects_pattern_claimed_by_another_adapter() -> None:
    registry = AdapterRegistry([ExampleAdapter()])
    with pytest.raises(RegistrationError, match="already claimed"):
        registry.register(ExampleAdapter("other", patterns=("example-deps.txt",)))
    assert registry.get("other") is None


def test_rejects_duplicate_pattern_within_one_adapter() -> None:
    with pytest.raises(RegistrationError, match="twice"):
        AdapterRegistry([ExampleAdapter("dup", patterns=("a.txt", "a.txt"))])


@pytest.mark.parametrize("adapter_id", ["", "Upper", "has space", "-leading"])
def test_rejects_invalid_adapter_ids(adapter_id: str) -> None:
    with pytest.raises(RegistrationError, match="invalid adapter id"):
        AdapterRegistry([ExampleAdapter(adapter_id)])


def test_rejects_adapter_without_formats() -> None:
    adapter = ExampleAdapter("empty")
    adapter.formats = ()
    with pytest.raises(RegistrationError, match="no file formats"):
        AdapterRegistry([adapter])


def test_default_registry_is_a_fresh_instance() -> None:
    first = default_registry()
    first.register(ExampleAdapter())
    assert default_registry().get("example") is None
