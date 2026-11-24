"""Where DVA keeps its local data: never inside the scanned project."""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from pathlib import Path

DATABASE_NAME = "dva.sqlite"


def default_data_dir(environ: Mapping[str, str] | None = None) -> Path:
    """The per-user data folder for this platform.

    ``DVA_DATA_DIR`` overrides it. Otherwise: ``%LOCALAPPDATA%\\DVA`` on
    Windows, ``~/Library/Application Support/DVA`` on macOS, and
    ``$XDG_DATA_HOME/dva`` (default ``~/.local/share/dva``) elsewhere.
    """
    env = os.environ if environ is None else environ
    override = env.get("DVA_DATA_DIR")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = env.get("LOCALAPPDATA")
        return Path(base) / "DVA" if base else Path.home() / "AppData" / "Local" / "DVA"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "DVA"
    base = env.get("XDG_DATA_HOME")
    return (Path(base) if base else Path.home() / ".local" / "share") / "dva"


def default_database_path(environ: Mapping[str, str] | None = None) -> Path:
    return default_data_dir(environ) / DATABASE_NAME
