"""Deciding whether one package version is affected by one advisory.

The rules follow the OSV format's definition of affected ranges:

* A version is affected if the advisory lists it explicitly in ``versions``,
  or if it falls inside any of the affected ranges.
* Within a range, events are sorted by version and read in order.
  ``introduced`` starts an affected stretch (``"0"`` means "from the very
  first version"), ``fixed`` ends it at that version (the fixed version is
  not affected), and ``last_affected`` ends it after that version (that
  version is still affected). If the range has ``limit`` events, the version
  must also be below one of them.
* ``GIT`` ranges describe commits, not versions. They are only consulted
  when nothing else in the entry describes versions, and then the answer is
  "unknown", because DVA doesn't know which commit an installed version is.

Whenever a version string can't be read under the ecosystem's rules, the
answer is "unknown", never "not affected".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from dva.domain.advisory import Advisory, AffectedPackage, AffectedRange, EventKind
from dva.matching.schemes import SEMVER, UnparsableVersionError, VersionScheme, scheme_for

_EVALUATED_TYPES = {"ECOSYSTEM", "SEMVER"}


class MatchStatus(StrEnum):
    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    #: The advisory names this package, but DVA can't decide for this version.
    UNKNOWN = "unknown"
    #: The database withdrew the advisory.
    WITHDRAWN = "withdrawn"
    #: The advisory is about other packages only.
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class MatchResult:
    status: MatchStatus
    #: How the match was made: "versions" (listed explicitly) or "range".
    matched_by: tuple[str, ...] = ()
    #: Fixed versions above the checked version, exactly as the advisory gives them.
    fixed_versions: tuple[str, ...] = ()
    #: ``last_affected`` bounds that cover the checked version, when no fix is given.
    last_affected: tuple[str, ...] = ()
    reasons: tuple[str, ...] = field(default=())


def match(advisory: Advisory, ecosystem: str, name: str, version: str) -> MatchResult:
    """Whether ``name`` at ``version`` in DVA ecosystem ``ecosystem`` is affected."""
    scheme = scheme_for(ecosystem)
    if scheme is None:
        return MatchResult(MatchStatus.UNKNOWN, reasons=(f"no version rules for {ecosystem}",))
    entries = [
        entry
        for entry in advisory.affected
        if entry.ecosystem == ecosystem and scheme.same_package(entry.name, name)
    ]
    if not entries:
        return MatchResult(MatchStatus.NOT_APPLICABLE)
    if advisory.withdrawn is not None:
        return MatchResult(MatchStatus.WITHDRAWN)

    results = [_match_entry(entry, scheme, version) for entry in entries]
    affected = [r for r in results if r.status is MatchStatus.AFFECTED]
    if affected:
        return MatchResult(
            MatchStatus.AFFECTED,
            matched_by=_union(r.matched_by for r in affected),
            fixed_versions=_union(r.fixed_versions for r in affected),
            last_affected=_union(r.last_affected for r in affected),
        )
    unknown = [r for r in results if r.status is MatchStatus.UNKNOWN]
    if unknown:
        return MatchResult(MatchStatus.UNKNOWN, reasons=_union(r.reasons for r in unknown))
    return MatchResult(MatchStatus.NOT_AFFECTED)


def _union(groups: Any) -> tuple[str, ...]:
    seen: dict[str, None] = {}
    for group in groups:
        for item in group:
            seen[item] = None
    return tuple(seen)


def _match_entry(entry: AffectedPackage, scheme: VersionScheme, version: str) -> MatchResult:
    reasons: list[str] = []
    try:
        key = scheme.key(version)
    except UnparsableVersionError:
        return MatchResult(
            MatchStatus.UNKNOWN, reasons=(f"version {version!r} doesn't follow {scheme.name}",)
        )

    if _listed(entry.versions, version, key, scheme):
        result_by = ["versions"]
    else:
        result_by = []

    fixed: list[str] = []
    last: list[str] = []
    version_ranges = [r for r in entry.ranges if r.type in _EVALUATED_TYPES]
    for affected_range in version_ranges:
        range_scheme = SEMVER if affected_range.type == "SEMVER" else scheme
        outcome = _evaluate(affected_range, version, range_scheme)
        if outcome is None:
            reasons.append(f"a {affected_range.type} range has versions DVA can't read")
        elif outcome:
            result_by.append("range")
            fixed.extend(_bounds(affected_range, EventKind.FIXED, version, range_scheme))
            last.extend(_bounds(affected_range, EventKind.LAST_AFFECTED, version, range_scheme))

    others = [r for r in entry.ranges if r.type not in _EVALUATED_TYPES]
    if others and not version_ranges and not entry.versions:
        kinds = ", ".join(sorted({r.type for r in others}))
        reasons.append(f"only {kinds} ranges are given, which don't map to versions")

    if result_by:
        return MatchResult(
            MatchStatus.AFFECTED,
            matched_by=tuple(dict.fromkeys(result_by)),
            fixed_versions=tuple(dict.fromkeys(fixed)),
            last_affected=tuple(dict.fromkeys(last)),
        )
    if reasons:
        return MatchResult(MatchStatus.UNKNOWN, reasons=tuple(reasons))
    return MatchResult(MatchStatus.NOT_AFFECTED)


def _listed(versions: tuple[str, ...], version: str, key: Any, scheme: VersionScheme) -> bool:
    for listed in versions:
        if listed == version:
            return True
        try:
            if scheme.key(listed) == key:
                return True
        except UnparsableVersionError:
            continue
    return False


def _evaluate(affected_range: AffectedRange, version: str, scheme: VersionScheme) -> bool | None:
    """True/False for in/out of the range, ``None`` if the range can't be read."""
    try:
        key = scheme.key(version)
        limits = [
            scheme.key(e.version)
            for e in affected_range.events
            if e.kind is EventKind.LIMIT and e.version != "*"
        ]
        # (rank, version key, position): introduced "0" (rank 0) sorts before
        # every real version (rank 1); ties keep the advisory's order.
        events: list[tuple[tuple[Any, ...], EventKind, Any]] = []
        for index, event in enumerate(affected_range.events):
            if event.kind is EventKind.LIMIT:
                continue
            if event.kind is EventKind.INTRODUCED and event.version == "0":
                events.append(((0, index), event.kind, None))
            else:
                event_key = scheme.key(event.version)
                events.append(((1, event_key, index), event.kind, event_key))
        events.sort(key=lambda item: item[0])
    except UnparsableVersionError:
        return None
    if limits and not any(key < limit for limit in limits):
        return False

    affected = False
    for _, kind, event_key in events:
        if kind is EventKind.INTRODUCED and (event_key is None or key >= event_key):
            affected = True
        elif kind is EventKind.FIXED and key >= event_key:
            affected = False
        elif kind is EventKind.LAST_AFFECTED and key > event_key:
            affected = False
    return affected


def _bounds(
    affected_range: AffectedRange, kind: EventKind, version: str, scheme: VersionScheme
) -> list[str]:
    """Event versions of ``kind`` at or above ``version``, as written in the advisory."""
    key = scheme.key(version)
    found = []
    for event in affected_range.events:
        if event.kind is not kind:
            continue
        try:
            bound = scheme.key(event.version)
        except UnparsableVersionError:
            continue
        if (kind is EventKind.FIXED and bound > key) or (
            kind is EventKind.LAST_AFFECTED and bound >= key
        ):
            found.append(event.version)
    return found
