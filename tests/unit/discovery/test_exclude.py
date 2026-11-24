from __future__ import annotations

from pathlib import Path

import pytest

from dva.application.analyze import analyze_project
from dva.discovery.exclude import ExcludeRules, normalize_pattern
from dva.ecosystems.registry import default_registry


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("tests/fixtures", "tests/fixtures"),
        ("./tests/fixtures/", "tests/fixtures"),
        (r"tests\fixtures", "tests/fixtures"),
        ("*/fixtures", "*/fixtures"),
    ],
)
def test_patterns_are_normalized(raw: str, expected: str) -> None:
    assert normalize_pattern(raw) == expected


@pytest.mark.parametrize("bad", ["", "/abs", "C:/x", "../outside", "a/../../b", "."])
def test_patterns_outside_the_project_are_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        normalize_pattern(bad)


def test_matching() -> None:
    rules = ExcludeRules(["tests/fixtures", "*/examples", "legacy/package.json"])
    assert rules.matches("tests/fixtures")
    assert rules.matches("Tests/Fixtures/npm/package.json")
    assert rules.matches("a/b/examples")
    assert rules.matches("legacy/package.json")
    assert not rules.matches("tests/fixtures-2")
    assert not rules.matches("tests")
    assert not rules.matches("legacy/package-lock.json")
    assert not ExcludeRules()


def test_scan_skips_excluded_paths_and_records_them(tmp_path: Path) -> None:
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "requirements.txt").write_text("idna==3.10\n", encoding="utf-8")
    (tmp_path / "tests" / "fixtures").mkdir(parents=True)
    (tmp_path / "tests" / "fixtures" / "requirements.txt").write_text("x==1\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("y==1\n", encoding="utf-8")
    scan = analyze_project(
        tmp_path, default_registry(), exclude=["tests/fixtures", "./requirements.txt"]
    )
    assert [m.path for m in scan.manifests] == ["app/requirements.txt"]
    assert scan.excluded == ("tests/fixtures", "requirements.txt")
    # Excluding on purpose doesn't make the analysis incomplete.
    assert scan.completion.value == "complete"
