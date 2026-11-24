"""Command-line entry point.

Presentation only: the CLI must not contain analysis logic. No scanning
commands exist yet; they are added once the application layer exists.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from dva import __version__

_DESCRIPTION = (
    "DVA (Dependency Vulnerability Analysis). "
    "Pre-alpha: no scanning functionality is implemented yet."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dva", description=_DESCRIPTION)
    parser.add_argument("--version", action="version", version=f"dva {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
