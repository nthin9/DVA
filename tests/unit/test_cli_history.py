"""The project, rescan, history and compare commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dva import cli
from dva.cli import EXIT_AFFECTED, EXIT_CLEAN, EXIT_ERROR, EXIT_INCOMPLETE, main
from dva.intelligence.osv.source import OsvSource
from tests.support.osv_fake import FakeOsvTransport


@pytest.fixture
def fake_osv(monkeypatch: pytest.MonkeyPatch) -> FakeOsvTransport:
    """Route the CLI's OSV lookups to the fake server; no network in unit tests."""
    transport = FakeOsvTransport()
    monkeypatch.setattr(cli, "UrllibTransport", lambda: transport)
    monkeypatch.setattr(cli, "OsvSource", lambda t: OsvSource(t))
    return transport


@pytest.fixture
def data(tmp_path: Path) -> list[str]:
    return ["--data-dir", str(tmp_path / "data")]


def app(tmp_path: Path, lodash: str = "4.17.20", name: str = "app") -> Path:
    root = tmp_path / name
    root.mkdir(exist_ok=True)
    write(root, lodash)
    return root


def write(root: Path, lodash: str) -> None:
    manifest = {"dependencies": {"lodash": lodash}}
    (root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_add_list_and_remove(
    tmp_path: Path, data: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    assert main(["project", "add", str(root), *data]) == EXIT_CLEAN
    assert "Registered 'app'" in capsys.readouterr().out
    assert main(["project", "list", *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "app" in out and str(root.resolve()) in out and "none yet" in out

    assert main(["project", "remove", "app", *data]) == EXIT_ERROR
    assert "--yes" in capsys.readouterr().err
    assert main(["project", "remove", "APP", "--yes", *data]) == EXIT_CLEAN
    assert root.exists() and (root / "package.json").exists()
    main(["project", "list", *data])
    assert "No projects are registered" in capsys.readouterr().out


def test_add_refuses_duplicates_bad_names_and_missing_folders(
    tmp_path: Path, data: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    assert main(["project", "add", str(root), *data]) == EXIT_CLEAN
    assert main(["project", "add", str(root), "--name", "other", *data]) == EXIT_ERROR
    assert main(["project", "add", str(tmp_path / "nope"), *data]) == EXIT_ERROR
    assert main(["project", "add", str(root), "--name", "42", *data]) == EXIT_ERROR
    err = capsys.readouterr().err
    assert "already registered" in err and "doesn't exist" in err and "only digits" in err


def test_unknown_project_is_an_error(
    tmp_path: Path, data: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    for command in (["rescan", "x"], ["history", "x"], ["compare", "x"]):
        assert main([*command, *data]) == EXIT_ERROR
    assert capsys.readouterr().err.count("no project is registered as 'x'") == 3


def test_rescan_saves_history_and_compare_shows_changes(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    main(["project", "add", str(root), *data])
    assert main(["rescan", "app", *data]) == EXIT_AFFECTED
    out = capsys.readouterr().out
    assert "GHSA-35jh-r3h4-6jhm" in out and "Saved as scan #1" in out
    assert "Changes since" not in out

    write(root, "4.17.21")
    assert main(["rescan", "app", *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "Changes since scan #1: packages 0 added, 0 removed, 1 changed" in out
    assert "1 no longer reported" in out

    assert main(["history", "app", *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert out.index("#2") < out.index("#1")
    assert "1 affected (1 advisory)" in out

    assert main(["compare", "app", *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "~ lodash (npm): 4.17.20 -> 4.17.21" in out
    assert "lodash 4.17.20: GHSA-35jh-r3h4-6jhm (the project now has a different version)" in out
    assert "not proof that a problem was fixed" in out
    assert "fixed in" not in out

    # Reversed, the advisory is new again, which compare signals with exit code 1.
    assert main(["compare", "app", "2", "1", *data]) == EXIT_AFFECTED
    assert "New advisory findings (1)" in capsys.readouterr().out


def test_a_finding_the_newer_scan_could_not_check_is_not_called_resolved(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    main(["project", "add", str(root), *data])
    main(["rescan", "app", "--quiet", *data])
    main(["rescan", "app", "--no-vulnerabilities", "--quiet", *data])
    capsys.readouterr()
    assert main(["compare", "app", *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "could not be checked in the newer scan (1)" in out
    assert "No longer reported" not in out


def test_history_exports_the_saved_report_exactly(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    original = tmp_path / "original.json"
    main(["project", "add", str(root), *data])
    main(["rescan", "app", "--json", str(original), "--quiet", *data])
    exported = tmp_path / "exported.json"
    assert main(["history", "app", "--show", "1", "--json", str(exported), *data]) == 0
    assert exported.read_bytes() == original.read_bytes()
    assert str(root.resolve()) not in exported.read_text(encoding="utf-8")
    capsys.readouterr()
    assert main(["history", "app", "--show", "1", *data]) == EXIT_CLEAN
    assert json.loads(capsys.readouterr().out)["schema_version"] == "dva.report/1"
    assert main(["history", "app", "--show", "7", *data]) == EXIT_ERROR


def test_compare_needs_two_scans(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    main(["project", "add", str(root), *data])
    assert main(["compare", "app", *data]) == EXIT_ERROR
    main(["rescan", "app", "--quiet", *data])
    assert main(["compare", "app", *data]) == EXIT_ERROR
    assert "at least two saved scans" in capsys.readouterr().err


def test_rescan_of_a_moved_folder_is_an_error_and_keeps_history(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    main(["project", "add", str(root), *data])
    main(["rescan", "app", "--quiet", *data])
    root.rename(tmp_path / "moved")
    assert main(["rescan", "app", *data]) == EXIT_ERROR
    assert "may have been moved or deleted" in capsys.readouterr().err
    main(["history", "app", *data])
    assert "#1" in capsys.readouterr().out


def test_rescan_all_returns_the_most_serious_outcome(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["rescan", "--all", *data]) == EXIT_ERROR  # Nothing registered yet.
    main(["project", "add", str(app(tmp_path, "4.17.21", "clean")), *data])
    assert main(["rescan", "--all", "--quiet", *data]) == EXIT_CLEAN
    main(["project", "add", str(app(tmp_path, "4.17.20", "vulnerable")), *data])
    assert main(["rescan", "--all", *data]) == EXIT_AFFECTED
    out = capsys.readouterr().out
    assert "=== clean ===" in out and "=== vulnerable ===" in out


def test_rescan_offline_without_cache_is_incomplete(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport
) -> None:
    main(["project", "add", str(app(tmp_path)), *data])
    assert main(["rescan", "app", "--offline", "--quiet", *data]) == EXIT_INCOMPLETE
    assert fake_osv.requests == []


@pytest.mark.parametrize(
    "argv",
    [
        ["rescan"],
        ["rescan", "app", "--all"],
        ["rescan", "--all", "--json", "x.json"],
        ["history", "app", "--json", "x.json"],
        ["history", "app", "--limit", "0"],
        ["project"],
    ],
)
def test_invalid_arguments(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_names_from_scanned_files_are_cleaned_in_comparisons(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    main(["project", "add", str(root), *data])
    main(["rescan", "app", "--quiet", *data])
    manifest = {"dependencies": {"evil\x1b[31mname": "1.0.0"}}
    (root / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    main(["rescan", "app", "--quiet", *data])
    capsys.readouterr()
    main(["compare", "app", *data])
    out = capsys.readouterr().out
    assert "\x1b" not in out
