from __future__ import annotations

import pytest

from dva.domain.paths import require_relative_path


@pytest.mark.parametrize("value", ["package.json", "a/b/requirements.txt", "dir.with.dots/x"])
def test_accepts_normalized_relative_paths(value: str) -> None:
    assert require_relative_path(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        ".",
        "..",
        "../x",
        "/etc/passwd",
        "C:/Users/x",
        "c:relative",
        "a\\b",
        "a/./b",
        "a//b",
        "a/../b",
        "a/",
        "a\x00b",
    ],
)
def test_rejects_absolute_escaping_or_unnormalized_paths(value: str) -> None:
    with pytest.raises(ValueError):
        require_relative_path(value)
