from __future__ import annotations

import subprocess
import sys

import pytest

from dva import __version__
from dva.cli import main


def test_version_flag_prints_version_and_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"dva {__version__}"


def test_no_arguments_prints_help_stating_pre_alpha(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    out = capsys.readouterr().out
    assert "usage: dva" in out
    # argparse wraps help text to terminal width; compare with whitespace normalized.
    assert "no scanning functionality is implemented yet" in " ".join(out.split())


def test_unknown_argument_is_rejected() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--no-such-option"])
    assert exc.value.code == 2


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
