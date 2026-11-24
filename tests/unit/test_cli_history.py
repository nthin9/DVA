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
        ["history", "app", "--html", "x.html"],
        ["history", "app", "--show", "1", "--prune", "2"],
        ["history", "app", "--prune", "0"],
        ["cache"],
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


def test_cache_info_and_clear(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    main(["project", "add", str(root), *data])
    main(["rescan", "app", "--quiet", *data])
    capsys.readouterr()
    assert main(["cache", "info", *data]) == EXIT_CLEAN
    assert "1 package lookup(s), 1 advisory record(s)" in capsys.readouterr().out
    assert main(["cache", "clear", *data]) == EXIT_ERROR
    assert main(["cache", "clear", "--yes", *data]) == EXIT_CLEAN
    main(["cache", "info", *data])
    assert "0 package lookup(s), 0 advisory record(s)" in capsys.readouterr().out
    # Saved scans survive, and an offline rescan now has nothing to use.
    main(["history", "app", *data])
    assert "#1" in capsys.readouterr().out
    assert main(["rescan", "app", "--offline", "--quiet", *data]) == EXIT_INCOMPLETE


def test_private_registry_flag_reaches_the_check(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport
) -> None:
    root = tmp_path / "corp"
    root.mkdir()
    (root / "requirements.txt").write_text(
        "--index-url https://pkgs.corp.example/simple\ncorp-secret==1.0\n", encoding="utf-8"
    )
    main(["scan", str(root), "--quiet", *data])
    assert "corp-secret" not in json.dumps(fake_osv.requests)
    main(["scan", str(root), "--quiet", "--include-private-registries", *data])
    assert "corp-secret" in json.dumps(fake_osv.requests)


def test_history_rebuilds_the_html_report_of_a_saved_scan(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    from dva.domain.deserialization import loads_scan
    from dva.reporting.html import render_html

    root = app(tmp_path)
    original = tmp_path / "original.json"
    main(["project", "add", str(root), *data])
    main(["rescan", "app", "--json", str(original), "--quiet", *data])
    write(root, "4.17.21")
    main(["rescan", "app", "--quiet", *data])
    page = tmp_path / "old.html"
    assert main(["history", "app", "--show", "1", "--html", str(page), *data]) == EXIT_CLEAN
    expected = render_html(loads_scan(original.read_text(encoding="utf-8")))
    assert page.read_text(encoding="utf-8") == expected
    assert "GHSA-35jh-r3h4-6jhm" in expected


def test_prune_keeps_the_newest_scans(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["project", "add", str(app(tmp_path)), *data])
    for _ in range(3):
        main(["rescan", "app", "--quiet", *data])
    capsys.readouterr()
    assert main(["history", "app", "--prune", "1", *data]) == EXIT_ERROR
    assert "delete 2 of 'app'" in capsys.readouterr().err
    assert main(["history", "app", "--prune", "1", "--yes", *data]) == EXIT_CLEAN
    main(["history", "app", *data])
    out = capsys.readouterr().out
    assert "#3" in out and "#2" not in out and "#1" not in out
    # Nothing to delete is fine without --yes.
    assert main(["history", "app", "--prune", "5", *data]) == EXIT_CLEAN


def test_search_finds_packages_across_projects(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    main(["project", "add", str(app(tmp_path, "4.17.20", "one")), *data])
    main(["project", "add", str(app(tmp_path, "4.17.21", "two")), *data])
    py = tmp_path / "py"
    py.mkdir()
    (py / "requirements.txt").write_text("Typing_Extensions==4.12.2\n", encoding="utf-8")
    main(["project", "add", str(py), *data])
    main(["project", "add", str(app(tmp_path, "4.17.20", "never")), *data])
    for name in ("one", "two", "py"):
        main(["rescan", name, "--quiet", *data])
    capsys.readouterr()

    assert main(["search", "lodash", *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "one: lodash (npm) 4.17.20 (affected: GHSA-35jh-r3h4-6jhm)" in out
    assert "two: lodash (npm) 4.17.21 (no matching advisory)" in out
    assert "never" not in out
    main(["search", "typing.extensions", *data])
    assert "py: typing-extensions (pypi) 4.12.2" in capsys.readouterr().out
    main(["search", "nothing-like-this", *data])
    assert "No registered project's latest scan includes" in capsys.readouterr().out


def test_a_saved_report_printed_to_the_screen_has_no_control_characters(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    # Regression: advisory text with a C1 control (CSI) or a bidi override was
    # printed raw, since JSON only escapes C0 controls.
    hostile = "evil\u009b31m\u202etext"
    fake_osv.record("GHSA-35jh-r3h4-6jhm")["summary"] = hostile
    main(["project", "add", str(app(tmp_path)), *data])
    main(["rescan", "app", "--quiet", *data])
    capsys.readouterr()
    assert main(["history", "app", "--show", "1", *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "\u009b" not in out and "\u202e" not in out
    advisories = json.loads(out)["vulnerabilities"]["advisories"]
    assert advisories[0]["summary"] == hostile


def test_a_damaged_saved_report_is_not_exported(
    tmp_path: Path, data: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    import sqlite3

    main(["project", "add", str(app(tmp_path)), *data])
    main(["rescan", "app", "--no-vulnerabilities", "--quiet", *data])
    db = sqlite3.connect(tmp_path / "data" / "dva.sqlite")
    db.execute('UPDATE scans SET report = \'{"schema_version": "dva.report/1"}\'')
    db.commit()
    db.close()
    out = tmp_path / "x.json"
    assert main(["history", "app", "--show", "1", "--json", str(out), *data]) == EXIT_ERROR
    assert not out.exists()
    assert "damaged" in capsys.readouterr().err


def test_a_locked_database_is_a_clear_error(
    tmp_path: Path,
    data: list[str],
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sqlite3

    from dva.storage import database

    main(["project", "add", str(app(tmp_path)), *data])
    monkeypatch.setattr(database, "BUSY_TIMEOUT_SECONDS", 0.05)
    other = sqlite3.connect(tmp_path / "data" / "dva.sqlite", isolation_level=None)
    other.execute("BEGIN EXCLUSIVE")
    try:
        assert main(["project", "add", str(app(tmp_path, name="b")), *data]) == EXIT_ERROR
        assert "in use by another DVA command" in capsys.readouterr().err
    finally:
        other.close()


def test_json_dash_prints_only_the_report(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    assert main(["scan", str(root), "--json", "-", *data]) == EXIT_AFFECTED
    out = capsys.readouterr().out
    assert json.loads(out)["schema_version"] == "dva.report/1"
    assert not (Path.cwd() / "-").exists()
    main(["project", "add", str(root), *data])
    capsys.readouterr()
    main(["rescan", "app", "--json", "-", *data])
    captured = capsys.readouterr()
    assert json.loads(captured.out)["project_name"] == "app"
    assert "Saved as scan #1" in captured.err


def test_exclusions_on_scan_and_saved_with_a_project(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    (root / "vendor").mkdir()
    write(root / "vendor", "4.17.20")
    write(root, "4.17.21")
    report = tmp_path / "r.json"
    assert main(["scan", str(root), "--exclude", "vendor", "--json", str(report), *data]) == 0
    assert "Excluded on request: vendor" in capsys.readouterr().out
    assert json.loads(report.read_text(encoding="utf-8"))["excluded"] == ["vendor"]
    assert main(["scan", str(root), "--exclude", "../x", *data]) == EXIT_ERROR

    assert main(["project", "add", str(root), "--exclude", "vendor/", *data]) == EXIT_CLEAN
    assert "Rescans skip: vendor" in capsys.readouterr().out
    assert main(["rescan", "app", "--quiet", *data]) == EXIT_CLEAN  # vendor's 4.17.20 skipped
    main(["project", "exclude", "app", "--clear", *data])
    assert "skip nothing" in capsys.readouterr().out
    assert main(["rescan", "app", "--quiet", *data]) == EXIT_AFFECTED
    main(["project", "exclude", "app", "vendor", "*/tmp", *data])
    main(["project", "list", *data])
    assert "skips: vendor, */tmp" in capsys.readouterr().out
    # A one-off --exclude on rescan adds to the saved ones.
    main(["project", "exclude", "app", "--clear", *data])
    assert main(["rescan", "app", "--exclude", "vendor", "--quiet", *data]) == EXIT_CLEAN
    assert main(["project", "exclude", "app", "/abs", *data]) == EXIT_ERROR


def test_brief_and_colour_options(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    assert main(["scan", str(root), "--brief", *data]) == EXIT_AFFECTED
    out = capsys.readouterr().out
    assert "lodash 4.17.20: 1 advisory (1 high)" in out and "\x1b" not in out
    main(["scan", str(root), "--color", "always", *data])
    assert "\x1b[" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        main(["scan", str(root), "--brief", "--quiet"])


def test_accepted_risks_from_a_file_and_a_project(
    tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = app(tmp_path)
    accept = tmp_path / "accept.toml"
    accept.write_text(
        '[[accept]]\nadvisory = "CVE-2021-23337"\nreason = "template input is trusted"\n',
        encoding="utf-8",
    )
    # The file is only used when passed; a file in the scanned folder is never read.
    (root / "accept.toml").write_text(accept.read_text(encoding="utf-8"), encoding="utf-8")
    assert main(["scan", str(root), "--quiet", *data]) == EXIT_AFFECTED
    assert main(["scan", str(root), "--accept-file", str(accept), *data]) == EXIT_CLEAN
    out = capsys.readouterr().out
    assert "accepted risk: template input is trusted" in out
    assert main(["scan", str(root), "--accept-file", str(tmp_path / "nope.toml"), *data]) == 4

    main(["project", "add", str(root), *data])
    assert main(["project", "accept", "app", "GHSA-35jh-r3h4-6jhm", *data]) == EXIT_ERROR
    assert "--reason" in capsys.readouterr().err
    assert (
        main(
            [
                "project",
                "accept",
                "app",
                "GHSA-35jh-r3h4-6jhm",
                "--reason",
                "ok",
                "--until",
                "2999-01-01",
                *data,
            ]
        )
        == EXIT_CLEAN
    )
    main(["project", "accept", "app", "--list", *data])
    assert "GHSA-35jh-r3h4-6jhm, until 2999-01-01: ok" in capsys.readouterr().out
    assert main(["rescan", "app", "--quiet", *data]) == EXIT_CLEAN
    main(["project", "accept", "app", "ghsa-35jh-r3h4-6jhm", "--remove", *data])
    assert "Removed 1" in capsys.readouterr().out
    assert main(["rescan", "app", "--quiet", *data]) == EXIT_AFFECTED
    assert main(["project", "accept", "app", "X", "--reason", "r", "--until", "soon", *data]) == 4


def test_fail_on_option(tmp_path: Path, data: list[str], fake_osv: FakeOsvTransport) -> None:
    root = app(tmp_path)  # lodash 4.17.20: one HIGH advisory.
    assert main(["scan", str(root), "--quiet", "--fail-on", "high", *data]) == EXIT_AFFECTED
    assert main(["scan", str(root), "--quiet", "--fail-on", "critical", *data]) == EXIT_CLEAN
    main(["project", "add", str(root), *data])
    assert main(["rescan", "app", "--quiet", "--fail-on", "critical", *data]) == EXIT_CLEAN
    with pytest.raises(SystemExit):
        main(["scan", str(root), "--fail-on", "severe"])
