"""Loading untrusted JSON files for the npm parsers."""

from __future__ import annotations

import json
from typing import Any

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.text import decode_utf8


def failure(context: ParseContext, code: str, message: str) -> AdapterResult:
    return AdapterResult(
        status=ParseStatus.FAILED,
        diagnostics=(Diagnostic(code, DiagnosticLevel.ERROR, message, context.path),),
    )


def load_json_object(
    context: ParseContext, code: str
) -> tuple[dict[str, Any], int] | AdapterResult:
    """The top-level object and how many duplicate keys it contained, or a failed result.

    JSON allows a key to appear twice in one object; npm keeps the last value.
    DVA does the same but counts the duplicates, because a file that says two
    different things about one dependency should not be read silently.
    """
    text = decode_utf8(context.content)
    if text is None:
        return failure(context, "npm.decode_error", "the file is not valid UTF-8 text")
    duplicates = 0

    def build(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        nonlocal duplicates
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                duplicates += 1
            result[key] = value
        return result

    try:
        document = json.loads(text, object_pairs_hook=build)
    except json.JSONDecodeError as error:
        return failure(context, code, f"not valid JSON (line {error.lineno}, column {error.colno})")
    except RecursionError:
        return failure(context, code, "the JSON is nested too deeply")
    if not isinstance(document, dict):
        return failure(context, code, "the top level is not a JSON object")
    return document, duplicates
