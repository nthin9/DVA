"""Loading untrusted TOML files for the Python parsers."""

from __future__ import annotations

import tomllib
from typing import Any

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.text import decode_utf8, preview


def failure(context: ParseContext, code: str, message: str) -> AdapterResult:
    return AdapterResult(
        status=ParseStatus.FAILED,
        diagnostics=(Diagnostic(code, DiagnosticLevel.ERROR, message, context.path),),
    )


def load_toml(context: ParseContext, code: str) -> dict[str, Any] | AdapterResult:
    """The parsed document, or a failed result explaining why it couldn't be read."""
    text = decode_utf8(context.content)
    if text is None:
        return failure(context, "python.decode_error", "the file is not valid UTF-8 text")
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        return failure(context, code, f"not valid TOML: {preview(str(error))}")
    except RecursionError:
        return failure(context, code, "the TOML is nested too deeply")
