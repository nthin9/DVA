from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from dva import __version__, cli
from dva.cli import EXIT_AFFECTED, EXIT_CLEAN, EXIT_ERROR, EXIT_INCOMPLETE, main
from dva.intelligence.osv.source import OsvSource
from tests.support.osv_fake import FakeOsvTransport

FIXTURES = Path(__file__).parents[1] / "fixtures"


@pytest.fixture
def fake_osv(monkeypatch: pytest.MonkeyPatch) -> FakeOsvTransport:
    """Route the CLI's OSV lookups to the fake server; no network in unit tests."""
    transport = FakeOsvTransport()
    monkeypatch.setattr(cli, "UrllibTransport", lambda: transport)
    monkeypatch.setattr(cli, "OsvSource", lambda t: OsvSource(t))
    return transport


def project(tmp_path: Path, fixture: str) -> Path:
    root = tmp_path / "project"
    shutil.copytree(FIXTURES / fixture, root)
    return root


def test_version_flag_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"dva {__version__}"


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "usage: dva" in out and "scan" in out


def test_unknown_argument_is_rejected() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--no-such-option"])
    assert exc.value.code == 2


def test_offline_and_no_vulnerabilities_are_exclusive() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["scan", ".", "--offline", "--no-vulnerabilities"])
    assert exc.value.code == 2


def test_scan_with_affected_packages_writes_all_reports(
    tmp_path: Path, fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = project(tmp_path, "npm/basic_project")
    json_path, html_path = tmp_path / "out" / "r.json", tmp_path / "r.html"
    json_path.parent.mkdir()
    code = main(
        [
            "scan",
            str(root),
            "--data-dir",
            str(tmp_path / "data"),
            "--json",
            str(json_path),
            "--html",
            str(html_path),
        ]
    )
    assert code == EXIT_AFFECTED
    out = capsys.readouterr().out
    assert "lodash 3.10.1" in out and "GHSA-35jh-r3h4-6jhm" in out and "fixed in: 4.17.21" in out
    assert "not proof that a package is safe" in out
    report = json.loads(json_path.read_text(encoding="utf-8"))
    assert report["schema_version"] == "dva.report/1"
    assert report["overview"]["outcomes"]["affected"] == 1
    assert "<html" in html_path.read_text(encoding="utf-8")
    assert (tmp_path / "data" / "dva.sqlite").exists()
    assert not (root / "POSTINSTALL_WAS_EXECUTED").exists()


def test_offline_scan_uses_what_an_earlier_scan_cached(
    tmp_path: Path, fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = project(tmp_path, "npm/basic_project")
    data = ["--data-dir", str(tmp_path / "data")]
    main(["scan", str(root), *data, "--quiet"])
    fake_osv.requests.clear()
    assert main(["scan", str(root), *data, "--offline"]) == EXIT_AFFECTED
    assert fake_osv.requests == []
    assert "cached data" in capsys.readouterr().out


def test_offline_without_cache_is_incomplete_not_clean(
    tmp_path: Path, fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = project(tmp_path, "python/basic_project")
    code = main(["scan", str(root), "--data-dir", str(tmp_path / "data"), "--offline"])
    assert code == EXIT_INCOMPLETE
    assert "lookup failed" in capsys.readouterr().out


def test_a_clean_complete_scan_exits_zero(
    tmp_path: Path, fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("idna==3.10\n", encoding="utf-8")
    assert main(["scan", str(root), "--data-dir", str(tmp_path / "data")]) == EXIT_CLEAN
    assert "no package matched a known advisory" in capsys.readouterr().out


def test_no_vulnerabilities_skips_the_lookup(
    tmp_path: Path, fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = project(tmp_path, "python/basic_project")
    code = main(["scan", str(root), "--no-vulnerabilities", "--data-dir", str(tmp_path / "d")])
    assert code == EXIT_INCOMPLETE  # the fixture has a partly read file
    assert fake_osv.requests == []
    assert not (tmp_path / "d").exists()
    assert "Vulnerabilities: not checked" in capsys.readouterr().out


def test_missing_folder_is_an_error(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", str(tmp_path / "nope"), "--no-vulnerabilities"]) == EXIT_ERROR
    assert "is not a folder" in capsys.readouterr().err


def test_unwritable_report_path_is_an_error(
    tmp_path: Path, fake_osv: FakeOsvTransport, capsys: pytest.CaptureFixture[str]
) -> None:
    root = project(tmp_path, "python/basic_project")
    target = tmp_path / "missing-dir" / "r.json"
    code = main(["scan", str(root), "--no-vulnerabilities", "--json", str(target)])
    assert code == EXIT_ERROR
    assert "couldn't write" in capsys.readouterr().err


def test_module_invocation_reports_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "dva", "--version"],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"dva {__version__}"
