from __future__ import annotations

import json

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.manifest import ParseStatus
from dva.ecosystems.npm.adapter import PACKAGE_JSON, NpmAdapter
from tests.support.readers import MemoryReader


def parse(text: str | bytes | dict[str, object]) -> AdapterResult:
    if isinstance(text, dict):
        text = json.dumps(text)
    content = text.encode("utf-8") if isinstance(text, str) else text
    context = ParseContext("package.json", content, PACKAGE_JSON, MemoryReader())
    return NpmAdapter().parse(context)


def codes(result: AdapterResult) -> set[str]:
    return {d.code for d in result.diagnostics}


def names(result: AdapterResult) -> list[tuple[str, tuple[str, ...]]]:
    return sorted((r.identity.name, r.groups) for r in result.requirements)


def test_optional_dependencies_replace_regular_ones() -> None:
    result = parse({"dependencies": {"a": "1", "b": "1"}, "optionalDependencies": {"a": "2"}})
    assert result.status is ParseStatus.PARSED
    assert names(result) == [("a", ("optional",)), ("b", ())]
    assert [r.constraint for r in result.requirements if r.identity.name == "a"] == ["2"]


def test_dev_and_regular_entries_are_both_kept() -> None:
    result = parse({"dependencies": {"a": "1"}, "devDependencies": {"a": "1"}})
    assert names(result) == [("a", ()), ("a", ("dev",))]


def test_bundled_dependencies_are_labelled() -> None:
    result = parse({"dependencies": {"a": "1", "b": "1"}, "bundleDependencies": ["a"]})
    assert names(result) == [("a", ("bundled",)), ("b", ())]
    legacy = parse({"dependencies": {"a": "1"}, "bundledDependencies": ["a"]})
    assert names(legacy) == [("a", ("bundled",))]


def test_invalid_names_specs_and_fields_are_reported() -> None:
    result = parse(
        {
            "dependencies": {"../evil": "1", "ok": 5, "alias": "npm:../x@1", "fine": "^1"},
            "devDependencies": ["not", "an", "object"],
            "bundleDependencies": "nope",
        }
    )
    assert result.status is ParseStatus.PARTIAL
    assert names(result) == [("fine", ())]
    assert {
        "npm.package_json.invalid_name",
        "npm.package_json.invalid_spec",
        "npm.package_json.invalid_field",
    } <= codes(result)


def test_duplicate_keys_are_reported() -> None:
    result = parse('{"dependencies": {"a": "1", "a": "2"}}')
    assert result.status is ParseStatus.PARTIAL
    assert "npm.duplicate_keys" in codes(result)
    assert [r.constraint for r in result.requirements] == ["2"]


def test_overrides_are_noted() -> None:
    result = parse({"dependencies": {"a": "1"}, "overrides": {"a": "2"}})
    assert result.status is ParseStatus.PARSED
    assert "npm.package_json.overrides" in codes(result)


def test_no_dependencies_is_fine() -> None:
    result = parse({"name": "x", "scripts": {"postinstall": "rm -rf /"}})
    assert result.status is ParseStatus.PARSED
    assert not result.requirements


def test_bad_json_and_non_objects_fail() -> None:
    for text in ("{", "[]", '"string"', b"\xff\xfe"):
        result = parse(text)
        assert result.status is ParseStatus.FAILED
    assert parse("[" * 100_000 + "]" * 100_000).status is ParseStatus.FAILED
