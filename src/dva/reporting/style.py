"""Optional colour for the terminal summary.

Colour codes are only ever added around text that has already been through
``clean_text``, and only by this module, so text from a scanned file or an
advisory can never choose or break out of an escape sequence. Colour is off
unless the CLI turns it on.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import TextIO

_RESET = "\x1b[0m"
_CODES = {
    "bold": "1",
    "dim": "2",
    "red": "31",
    "green": "32",
    "yellow": "33",
    "magenta": "35",
}


class Style:
    """Wraps already-cleaned text in colour codes, or does nothing when disabled."""

    def __init__(self, enabled: bool = False) -> None:
        self.enabled = enabled

    def __call__(self, text: str, *names: str) -> str:
        if not self.enabled or not names or not text:
            return text
        codes = ";".join(_CODES[name] for name in names)
        return f"\x1b[{codes}m{text}{_RESET}"


PLAIN = Style(False)

#: Colour for each database severity label, most severe first.
SEVERITY_COLOURS = {
    "critical": ("red", "bold"),
    "high": ("red",),
    "moderate": ("yellow",),
    "low": ("dim",),
}


def colour_wanted(
    choice: str, stream: TextIO | None = None, environ: Mapping[str, str] | None = None
) -> bool:
    """Whether to colour output: ``always``, ``never``, or ``auto`` (a terminal,
    no ``NO_COLOR``, and a terminal type that supports it)."""
    if choice == "always":
        _enable_windows_terminal()  # Best effort; the user asked for colour regardless.
        return True
    if choice == "never":
        return False
    env = os.environ if environ is None else environ
    stream = sys.stdout if stream is None else stream
    if env.get("NO_COLOR") or env.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    if isatty is None or not isatty():
        return False
    return sys.platform != "win32" or _enable_windows_terminal()


def _enable_windows_terminal() -> bool:
    """Turn on escape-code handling in the Windows console; False if it can't be."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # Standard output.
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError):
        return False
