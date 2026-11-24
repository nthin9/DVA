"""Guards on what DVA's published files may contain."""

from __future__ import annotations

import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).parents[2] / "pyproject.toml"


def test_source_archive_uses_an_explicit_allowlist() -> None:
    config = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    sdist = config["tool"]["hatch"]["build"]["targets"]["sdist"]
    included = sdist["only-include"]
    assert "src" in included and "README.md" in included
    # Only these top-level entries may ever be published.
    allowed = {"src", "tests", "docs", "README.md", "LICENSE", "pyproject.toml", "uv.lock"}
    assert set(included) <= allowed
