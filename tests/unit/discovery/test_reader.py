from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from dva.contracts.files import FileAccessDeniedError, FileAccessError, FileTooLargeError
from dva.discovery.reader import BoundedFileReader


@pytest.fixture
def project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "sub").mkdir(parents=True)
    (root / "sub" / "file.txt").write_bytes(b"hello")
    (tmp_path / "secret.txt").write_bytes(b"outside")
    return root


def test_reads_file_inside_root(project: Path) -> None:
    assert BoundedFileReader(project, 100).read("sub/file.txt") == b"hello"


@pytest.mark.parametrize(
    "path",
    ["../secret.txt", "sub/../../secret.txt", "/etc/passwd", "C:/Windows/win.ini", "sub\\file.txt"],
)
def test_rejects_paths_escaping_or_not_normalized(project: Path, path: str) -> None:
    with pytest.raises(FileAccessDeniedError):
        BoundedFileReader(project, 100).read(path)


def test_rejects_colon_alternate_data_stream_syntax(project: Path) -> None:
    with pytest.raises(FileAccessDeniedError, match="':'"):
        BoundedFileReader(project, 100).read("sub/file.txt:stream")


def test_rejects_directories(project: Path) -> None:
    with pytest.raises(FileAccessDeniedError, match="regular file"):
        BoundedFileReader(project, 100).read("sub")


def test_missing_file_is_an_access_error(project: Path) -> None:
    with pytest.raises(FileAccessError, match="not found"):
        BoundedFileReader(project, 100).read("sub/nope.txt")


def test_enforces_size_limit(project: Path) -> None:
    with pytest.raises(FileTooLargeError):
        BoundedFileReader(project, 4).read("sub/file.txt")
    assert BoundedFileReader(project, 5).read("sub/file.txt") == b"hello"


def test_error_messages_do_not_contain_absolute_paths(project: Path) -> None:
    reader = BoundedFileReader(project, 100)
    for bad in ("sub/nope.txt", "../secret.txt", "sub"):
        with pytest.raises(FileAccessError) as exc:
            reader.read(bad)
        assert str(project) not in str(exc.value)
        assert str(project.parent) not in str(exc.value)


@pytest.mark.parametrize("directory", [False, True])
def test_refuses_symlinks(project: Path, directory: bool) -> None:
    target = project.parent / ("secret.txt" if not directory else "")
    link = project / ("link.txt" if not directory else "linkdir")
    try:
        os.symlink(target, link, target_is_directory=directory)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"cannot create symlinks here: {exc}")
    path = "link.txt" if not directory else "linkdir/secret.txt"
    with pytest.raises(FileAccessDeniedError, match="link"):
        BoundedFileReader(project, 100).read(path)


@pytest.mark.skipif(sys.platform != "win32", reason="junctions are Windows-only")
def test_refuses_windows_junctions(project: Path) -> None:
    if sys.platform == "win32":  # narrows the platform for type checkers
        import _winapi

        _winapi.CreateJunction(str(project.parent), str(project / "junction"))
        with pytest.raises(FileAccessDeniedError, match="link"):
            BoundedFileReader(project, 100).read("junction/secret.txt")
