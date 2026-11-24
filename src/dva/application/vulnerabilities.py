"""The vulnerability-check use case: look up a scan's packages and match versions.

1. Collect every package version the scan knows exactly: lockfile packages
   from a registry, and requirements pinned to one version. Everything else
   is recorded as not checked, with the reason, unless the same package is
   already checked through a lockfile.
2. Ask the source which advisories exist for each package (by ecosystem and
   name only). If it can't be reached, or ``offline`` is set, use the cache.
3. Fetch the full records that are new or changed since they were cached.
4. Match each version against its package's advisories locally.

Nothing here knows about a particular ecosystem or provider: version rules
come from the matching layer, and the source and cache are passed in.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime

from dva.contracts.intelligence import (
    AdvisoryCache,
    AdvisorySource,
    AdvisoryStamp,
    PackageKey,
    ProviderError,
)
from dva.domain.advisory import Advisory
from dva.domain.dependency import SourceKind
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.identity import PackageIdentity
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import (
    CheckStatus,
    DataSource,
    Finding,
    Location,
    PackageCheck,
    VulnerabilityReport,
)
from dva.matching.match import MatchStatus, match
from dva.matching.schemes import scheme_for

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Target:
    identity: PackageIdentity
    key: PackageKey
    version: str
    locations: list[Location] = field(default_factory=list)


@dataclass
class _Unchecked:
    """One package that wasn't looked up, with every place and reason found.

    Each entry in ``items`` is (reason, key, location). ``key`` is set when a
    lockfile elsewhere could cover the gap (a range next to a pinned lockfile
    entry); it is ``None`` for packages that can never be looked up.
    """

    identity: PackageIdentity
    items: list[tuple[str, PackageKey | None, Location]] = field(default_factory=list)


@dataclass
class _Lookup:
    """What is known about one package's advisories after the lookup step."""

    stamps: tuple[AdvisoryStamp, ...] | None = None
    retrieved_at: datetime | None = None
    from_cache: bool = False
    failure: str | None = None


def check_vulnerabilities(
    scan: ScanResult,
    source: AdvisorySource,
    cache: AdvisoryCache,
    *,
    offline: bool = False,
    clock: Clock = _utc_now,
) -> ScanResult:
    """Return ``scan`` with a :class:`VulnerabilityReport` attached."""
    checked_at = clock()
    diagnostics: list[Diagnostic] = []
    targets, unchecked = _collect(scan, source)

    keys = sorted({target.key for target in targets.values()})
    lookups = _lookup(keys, source, cache, offline, checked_at, diagnostics)
    advisories, failed_records = _records(lookups, source, cache, offline, checked_at, diagnostics)

    checks = [
        _check(target, lookups[target.key], advisories, failed_records)
        for target in targets.values()
    ]
    checked_names = {target.key for target in targets.values()}
    for entry in unchecked.values():
        # Drop gaps that an exact version elsewhere in the scan already covers.
        remaining = [i for i in entry.items if i[1] is None or i[1] not in checked_names]
        if not remaining:
            continue
        checks.append(
            PackageCheck(
                entry.identity,
                None,
                CheckStatus.NOT_CHECKED,
                tuple(dict.fromkeys(location for _, _, location in remaining)),
                reasons=tuple(dict.fromkeys(reason for reason, _, _ in remaining)),
            )
        )

    used = {f.advisory_id for check in checks for f in check.findings}
    report = VulnerabilityReport(
        provider=source.provider_id,
        checked_at=checked_at,
        data_source=_data_source(lookups),
        checks=tuple(checks),
        advisories=tuple(advisories[advisory_id] for advisory_id in sorted(used)),
        oldest_data_at=min(
            (lookup.retrieved_at for lookup in lookups.values() if lookup.retrieved_at),
            default=None,
        ),
        diagnostics=tuple(diagnostics),
    )
    return replace(scan, vulnerabilities=report)


def _source_name(kind: SourceKind) -> str:
    return {
        SourceKind.GIT: "a git repository",
        SourceKind.URL: "a URL",
        SourceKind.PATH: "a local path",
        SourceKind.WORKSPACE: "the project's own workspace",
        SourceKind.UNKNOWN: "an unknown source",
    }.get(kind, "somewhere other than a registry")


def _full_name(identity: PackageIdentity) -> str:
    return f"{identity.namespace}/{identity.name}" if identity.namespace else identity.name


def _collect(
    scan: ScanResult, source: AdvisorySource
) -> tuple[dict[tuple[PackageKey, str], _Target], dict[tuple[str, str], _Unchecked]]:
    targets: dict[tuple[PackageKey, str], _Target] = {}
    unchecked: dict[tuple[str, str], _Unchecked] = {}

    def skip(
        identity: PackageIdentity, key: PackageKey | None, reason: str, where: Location
    ) -> None:
        entry = unchecked.setdefault(
            (identity.ecosystem, _full_name(identity)), _Unchecked(identity)
        )
        entry.items.append((reason, key, where))

    def target(identity: PackageIdentity, key: PackageKey, version: str, where: Location) -> None:
        entry = targets.setdefault((key, version), _Target(identity, key, version))
        entry.locations.append(where)

    for manifest in scan.manifests:
        for package in manifest.packages:
            where = Location(manifest.path, node_id=package.node_id)
            key = PackageKey(package.identity.ecosystem, _full_name(package.identity))
            if not source.supports(key.ecosystem) or scheme_for(key.ecosystem) is None:
                skip(package.identity, key, "no vulnerability data for this ecosystem", where)
            elif package.source is not SourceKind.REGISTRY:
                skip(
                    package.identity,
                    None,
                    f"installed from {_source_name(package.source)}, not a registry release",
                    where,
                )
            else:
                target(package.identity, key, package.version, where)

        for requirement in manifest.requirements:
            identity = requirement.identity
            where = Location(manifest.path, line=requirement.line)
            key = PackageKey(identity.ecosystem, _full_name(identity))
            scheme = scheme_for(key.ecosystem)
            if not source.supports(key.ecosystem) or scheme is None:
                skip(identity, key, "no vulnerability data for this ecosystem", where)
            elif requirement.source is not SourceKind.REGISTRY:
                skip(identity, None, f"comes from {_source_name(requirement.source)}", where)
            elif requirement.constraint is None:
                skip(identity, key, "declares no version", where)
            else:
                version = scheme.exact_version(requirement.constraint)
                if version is None:
                    skip(identity, key, "declares a version range, not one exact version", where)
                else:
                    target(identity, key, version, where)
    return targets, unchecked


def _lookup(
    keys: list[PackageKey],
    source: AdvisorySource,
    cache: AdvisoryCache,
    offline: bool,
    now: datetime,
    diagnostics: list[Diagnostic],
) -> dict[PackageKey, _Lookup]:
    lookups = {key: _Lookup() for key in keys}
    if not keys:
        return lookups
    failure = "offline: no live lookup was made" if offline else None
    if not offline:
        try:
            listed = source.list_advisories(keys)
        except ProviderError as error:
            failure = f"lookup failed: {error}"
            diagnostics.append(
                Diagnostic(
                    "vulnerabilities.provider_unavailable",
                    DiagnosticLevel.WARNING,
                    f"{source.provider_id} could not be queried ({error}); using cached data",
                )
            )
        else:
            for key in keys:
                stamps = tuple(listed.get(key, ()))
                cache.put_index(source.provider_id, key, stamps, now)
                lookups[key] = _Lookup(stamps, now)
            return lookups

    for key in keys:
        cached = cache.get_index(source.provider_id, key)
        if cached is None:
            reason = failure or "no data"
            lookups[key] = _Lookup(failure=f"{reason}, and nothing is cached for this package")
        else:
            lookups[key] = _Lookup(cached.stamps, cached.retrieved_at, from_cache=True)
    return lookups


def _records(
    lookups: dict[PackageKey, _Lookup],
    source: AdvisorySource,
    cache: AdvisoryCache,
    offline: bool,
    now: datetime,
    diagnostics: list[Diagnostic],
) -> tuple[dict[str, Advisory], dict[str, str]]:
    wanted: dict[str, AdvisoryStamp] = {}
    for lookup in lookups.values():
        for stamp in lookup.stamps or ():
            current = wanted.get(stamp.id)
            if current is None or stamp.modified > current.modified:
                wanted[stamp.id] = stamp

    live = not offline and not any(lookup.from_cache for lookup in lookups.values())
    advisories: dict[str, Advisory] = {}
    failed: dict[str, str] = {}
    stale = 0
    for advisory_id, stamp in sorted(wanted.items()):
        cached = cache.get_record(source.provider_id, advisory_id)
        raw = cached.raw if cached is not None else None
        if live and (cached is None or cached.modified < stamp.modified):
            try:
                raw = source.fetch_record(advisory_id)
            except ProviderError as error:
                if raw is None:
                    failed[advisory_id] = (
                        f"the record for {advisory_id} could not be fetched ({error})"
                    )
                    continue
                stale += 1  # keep using the older cached copy
            else:
                cache.put_record(source.provider_id, advisory_id, stamp.modified, raw, now)
        if raw is None:
            failed[advisory_id] = f"the record for {advisory_id} is not cached"
            continue
        try:
            advisories[advisory_id] = source.parse_record(raw)
        except ValueError:
            failed[advisory_id] = f"the record for {advisory_id} is malformed"
            diagnostics.append(
                Diagnostic(
                    "vulnerabilities.invalid_record",
                    DiagnosticLevel.WARNING,
                    f"advisory {advisory_id} from {source.provider_id} could not be used",
                )
            )
    if stale:
        diagnostics.append(
            Diagnostic(
                "vulnerabilities.stale_records",
                DiagnosticLevel.WARNING,
                f"{stale} updated advisory record(s) could not be fetched; older cached copies "
                "were used",
            )
        )
    return advisories, failed


def _check(
    target: _Target,
    lookup: _Lookup,
    advisories: dict[str, Advisory],
    failed_records: dict[str, str],
) -> PackageCheck:
    locations = tuple(target.locations)
    if lookup.stamps is None:
        return PackageCheck(
            target.identity,
            target.version,
            CheckStatus.LOOKUP_FAILED,
            locations,
            reasons=(lookup.failure or "lookup failed",),
        )
    findings: list[Finding] = []
    reasons: list[str] = []
    for stamp in lookup.stamps:
        if stamp.id in failed_records:
            reasons.append(failed_records[stamp.id])
            continue
        result = match(advisories[stamp.id], target.key.ecosystem, target.key.name, target.version)
        if result.status is MatchStatus.AFFECTED:
            findings.append(
                Finding(stamp.id, result.matched_by, result.fixed_versions, result.last_affected)
            )
        elif result.status is MatchStatus.UNKNOWN:
            reasons.extend(f"{stamp.id}: {reason}" for reason in result.reasons)

    if findings:
        status = CheckStatus.AFFECTED
    elif reasons:
        status = CheckStatus.UNKNOWN
    else:
        status = CheckStatus.NO_MATCHING_ADVISORY
    return PackageCheck(
        target.identity,
        target.version,
        status,
        locations,
        findings=tuple(findings),
        reasons=tuple(reasons),
        data_retrieved_at=lookup.retrieved_at,
    )


def _data_source(lookups: dict[PackageKey, _Lookup]) -> DataSource:
    kinds = {lookup.from_cache for lookup in lookups.values() if lookup.stamps is not None}
    if not kinds:
        return DataSource.NONE
    if kinds == {True}:
        return DataSource.CACHE
    if kinds == {False}:
        return DataSource.LIVE
    return DataSource.MIXED
