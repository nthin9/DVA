"""Small helpers shared by ecosystem adapters for handling untrusted text."""

from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

_BOM = "﻿"
_PREVIEW_LIMIT = 80
_USERINFO = re.compile(r"(?<=://)[^/@\s]+@")


def decode_utf8(content: bytes) -> str | None:
    """Decode UTF-8 text, dropping a leading byte-order mark. ``None`` if not UTF-8."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return text.removeprefix(_BOM)


def redact_url(value: str) -> str:
    """Remove credentials (``user:token@``) from any URL inside ``value``.

    Dependency URLs sometimes embed access tokens. They must never reach a
    report, a diagnostic, or a vulnerability provider.
    """
    if "://" not in value:
        return value
    try:
        parts = urlsplit(value)
    except ValueError:
        return _USERINFO.sub("***@", value)
    if parts.scheme and "@" in parts.netloc:
        host = parts.netloc.rsplit("@", 1)[1]
        return urlunsplit(parts._replace(netloc=f"***@{host}"))
    return _USERINFO.sub("***@", value)


def preview(value: str) -> str:
    """A short, credential-free, single-line excerpt of untrusted text for messages."""
    flat = " ".join(redact_url(value).split())
    if len(flat) > _PREVIEW_LIMIT:
        return flat[: _PREVIEW_LIMIT - 3] + "..."
    return flat
