"""Reading OSV records (https://ossf.github.io/osv-schema/) into advisories.

Records come from the network and are treated as untrusted. The parts that
decide whether a version is affected (``affected``, its ranges and events)
are checked strictly: if any of them is malformed, the whole record is
rejected, because silently dropping a range could hide a real vulnerability.
Display-only parts (references, severity entries) that are malformed are
skipped instead.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from dva.domain.advisory import (
    Advisory,
    AffectedPackage,
    AffectedRange,
    EventKind,
    RangeEvent,
    Reference,
    Severity,
)

#: OSV ecosystem names for the ecosystems DVA supports, mapped to DVA's identifiers.
OSV_ECOSYSTEMS = {"PyPI": "pypi", "npm": "npm"}
#: The reverse mapping, for building queries.
DVA_TO_OSV = {dva: osv for osv, dva in OSV_ECOSYSTEMS.items()}

_ID = re.compile(r"^[A-Za-z0-9:_.-]{1,128}$")
_TIMESTAMP = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$"
)
_EVENT_KINDS = {kind.value: kind for kind in EventKind}


class InvalidRecordError(ValueError):
    """An OSV record that can't be used safely. The message is safe to show."""


def parse_record(value: object) -> Advisory:
    """Build an :class:`Advisory` from a decoded OSV record."""
    if not isinstance(value, dict):
        raise InvalidRecordError("record is not a JSON object")
    record_id = value.get("id")
    if not isinstance(record_id, str) or not _ID.match(record_id):
        raise InvalidRecordError("record has no valid id")

    def fail(message: str) -> InvalidRecordError:
        return InvalidRecordError(f"{record_id}: {message}")

    modified = _timestamp(value.get("modified"))
    if modified is None:
        raise fail("modified is missing or not an RFC 3339 timestamp")
    affected = value.get("affected", [])
    if not isinstance(affected, list):
        raise fail("affected is not an array")

    try:
        return Advisory(
            id=record_id,
            modified=modified,
            published=_optional_timestamp(value, "published", fail),
            withdrawn=_optional_timestamp(value, "withdrawn", fail),
            aliases=_ids(value.get("aliases")),
            related=_ids(value.get("related")),
            summary=_text(value.get("summary")),
            details=_text(value.get("details")),
            severities=_severities(value.get("severity")),
            database_severity=_database_severity(value.get("database_specific")),
            references=_references(value.get("references")),
            affected=tuple(_affected(entry, fail) for entry in affected),
            schema_version=_text(value.get("schema_version")),
        )
    except ValueError as error:
        if isinstance(error, InvalidRecordError):
            raise
        raise fail("contains an invalid value") from None


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    match = _TIMESTAMP.match(value)
    if match is None:
        return None
    year, month, day, hour, minute, second, fraction, zone = match.groups()
    micro = int((fraction or "0")[:6].ljust(6, "0"))
    if zone in ("Z", "z"):
        tz = UTC
    else:
        sign = 1 if zone[0] == "+" else -1
        tz = timezone(sign * timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6])))
    try:
        stamp = datetime(
            int(year), int(month), int(day), int(hour), int(minute), int(second), micro, tz
        )
    except ValueError:
        return None
    return stamp.astimezone(UTC)


def _optional_timestamp(value: dict[str, Any], key: str, fail: Any) -> datetime | None:
    if value.get(key) is None:
        return None
    stamp = _timestamp(value[key])
    if stamp is None:
        raise fail(f"{key} is not an RFC 3339 timestamp")
    return stamp


def _text(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(dict.fromkeys(v for v in value if isinstance(v, str) and _ID.match(v)))


def _severities(value: object) -> tuple[Severity, ...]:
    if not isinstance(value, list):
        return ()
    found = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        kind, score, source = entry.get("type"), entry.get("score"), entry.get("source")
        if isinstance(kind, str) and kind and isinstance(score, str) and score.strip():
            found.append(Severity(kind, score.strip(), source if isinstance(source, str) else None))
    return tuple(found)


def _database_severity(value: object) -> str | None:
    if isinstance(value, dict):
        return _text(value.get("severity"))
    return None


def _references(value: object) -> tuple[Reference, ...]:
    if not isinstance(value, list):
        return ()
    found = []
    for entry in value:
        if not isinstance(entry, dict):
            continue
        kind, url = entry.get("type"), entry.get("url")
        if isinstance(kind, str) and kind and isinstance(url, str) and _is_web_url(url):
            found.append(Reference(kind, url))
    return tuple(found)


def _is_web_url(url: str) -> bool:
    """Only http(s) links are kept, so a report never renders ``javascript:`` or similar."""
    return url.startswith(("https://", "http://")) and not any(c.isspace() for c in url)


def _affected(entry: object, fail: Any) -> AffectedPackage:
    if not isinstance(entry, dict):
        raise fail("an affected entry is not an object")
    package = entry.get("package")
    if not isinstance(package, dict):
        raise fail("an affected entry has no package")
    ecosystem, name = package.get("ecosystem"), package.get("name")
    if not isinstance(ecosystem, str) or not ecosystem or not isinstance(name, str) or not name:
        raise fail("an affected package has no ecosystem or name")
    purl = package.get("purl")

    ranges = entry.get("ranges", [])
    versions = entry.get("versions", [])
    if not isinstance(ranges, list) or not isinstance(versions, list):
        raise fail(f"ranges or versions of {name!r} are not arrays")
    if not all(isinstance(v, str) and v for v in versions):
        raise fail(f"versions of {name!r} contain a non-string")

    return AffectedPackage(
        ecosystem=OSV_ECOSYSTEMS.get(ecosystem, ecosystem),
        name=name,
        purl=purl if isinstance(purl, str) and purl.startswith("pkg:") else None,
        ranges=tuple(_range(item, name, fail) for item in ranges),
        versions=tuple(versions),
    )


def _range(item: object, name: str, fail: Any) -> AffectedRange:
    if not isinstance(item, dict):
        raise fail(f"a range of {name!r} is not an object")
    kind, events, repo = item.get("type"), item.get("events"), item.get("repo")
    if not isinstance(kind, str) or not kind or not isinstance(events, list) or not events:
        raise fail(f"a range of {name!r} has no type or events")
    parsed = []
    for event in events:
        if not isinstance(event, dict) or len(event) != 1:
            raise fail(f"a range event of {name!r} must have exactly one key")
        ((key, version),) = event.items()
        if key not in _EVENT_KINDS or not isinstance(version, str) or not version.strip():
            raise fail(f"a range event of {name!r} is not understood")
        parsed.append(RangeEvent(_EVENT_KINDS[key], version.strip()))
    if not any(e.kind is EventKind.INTRODUCED for e in parsed):
        raise fail(f"a range of {name!r} has no introduced event")
    return AffectedRange(kind, tuple(parsed), repo if isinstance(repo, str) else None)
