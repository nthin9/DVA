from __future__ import annotations

import base64
import hashlib
import json
import re
from datetime import UTC, datetime
from importlib.resources import files

from dva.domain.advisory import Advisory, Reference, Severity
from dva.domain.dependency import DependencyEdge, ResolvedPackage, SourceKind
from dva.domain.identity import PackageIdentity
from dva.domain.manifest import ManifestAnalysis, ManifestKind, ParseStatus
from dva.domain.scan import ScanResult
from dva.domain.vulnerability import (
    CheckStatus,
    DataSource,
    Finding,
    Location,
    PackageCheck,
    VulnerabilityReport,
)
from dva.reporting.html import render_html
from dva.reporting.json_report import render_json
from dva.reporting.overview import clean_text
from dva.reporting.text import render_text

T0 = datetime(2026, 3, 1, tzinfo=UTC)
EVIL = "</script><script>alert(1)</script>\x1b[31m‮{{APP}}"
ASSETS = files("dva.reporting").joinpath("assets")


def hostile_scan() -> ScanResult:
    identity = PackageIdentity("npm", EVIL)
    package = ResolvedPackage("node_modules/x", identity, "1.0.0", source=SourceKind.REGISTRY)
    lock = ManifestAnalysis(
        "package-lock.json",
        "npm",
        "npm",
        ManifestKind.LOCKFILE,
        "package-lock",
        ParseStatus.PARSED,
        packages=(package,),
        edges=(DependencyEdge(None, "node_modules/x"),),
    )
    advisory = Advisory(
        "GHSA-test",
        T0,
        summary=EVIL,
        details=EVIL,
        severities=(Severity("CVSS_V3", "CVSS:3.1/AV:N"),),
        database_severity="HIGH",
        references=(Reference("WEB", "https://example.com/a"),),
    )
    check = PackageCheck(
        identity,
        "1.0.0",
        CheckStatus.AFFECTED,
        (Location("package-lock.json", "node_modules/x"),),
        findings=(Finding("GHSA-test", ("range",), ("1.0.1",)),),
        data_retrieved_at=T0,
    )
    report = VulnerabilityReport("osv", T0, DataSource.LIVE, (check,), (advisory,), T0)
    return ScanResult("0.0.1", "demo", T0, T0, manifests=(lock,), vulnerabilities=report)


def test_terminal_text_has_no_control_characters() -> None:
    text = render_text(hostile_scan())
    assert "\x1b" not in text and "‮" not in text
    assert "fixed in: 1.0.1" in text
    assert "HIGH (rated by the database)" in text
    assert "not proof that a package is safe" in text


def test_clean_text() -> None:
    assert clean_text("a\x1b[0mb​c\nd") == "a?[0mb?c d"
    assert clean_text("café 中") == "café 中"


def test_json_report_has_overview_and_format_version() -> None:
    data = json.loads(render_json(hostile_scan()))
    assert data["schema_version"] == "dva.report/1"
    assert data["overview"]["outcomes"]["affected"] == 1
    assert data["overview"]["direct_dependencies"] == 1


def inline_scripts(page: str) -> list[str]:
    return re.findall(r"<script>(.*?)</script>", page, flags=re.S)


def test_html_data_cannot_break_out_of_its_script_element() -> None:
    page = render_html(hostile_scan())
    data_block = re.search(
        r'<script type="application/json" id="dva-data">(.*?)</script>', page, re.S
    )
    assert data_block is not None
    assert "<" not in data_block.group(1) and ">" not in data_block.group(1)
    assert json.loads(data_block.group(1))["vulnerabilities"]["advisories"][0]["summary"] == EVIL
    # Exactly the template's three script elements, and the placeholder text in the
    # data was not expanded.
    assert page.count("<script") == 3
    assert "{{APP}}" in data_block.group(1)


def test_html_csp_allows_exactly_the_inline_scripts() -> None:
    page = render_html(hostile_scan())
    policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', page)
    assert policy is not None
    csp = policy.group(1)
    assert "default-src 'none'" in csp and "unsafe-eval" not in csp
    assert "script-src" in csp and "'unsafe-inline'" not in csp.split("script-src")[1].split(";")[0]
    for script in inline_scripts(page):
        digest = base64.b64encode(hashlib.sha256(script.encode()).digest()).decode()
        assert f"'sha256-{digest}'" in csp


def test_page_script_never_parses_text_as_html() -> None:
    script = ASSETS.joinpath("report.js").read_text(encoding="utf-8")
    for dangerous in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert dangerous not in script


def test_vendored_library_matches_its_recorded_hash() -> None:
    library = ASSETS.joinpath("cytoscape.min.js").read_bytes()
    notes = ASSETS.joinpath("VENDORED.md").read_text(encoding="utf-8")
    recorded = re.search(r"SHA-256 of `cytoscape.min.js`: `([0-9a-f]{64})`", notes)
    assert recorded is not None
    assert hashlib.sha256(library).hexdigest() == recorded.group(1)
    assert (
        ASSETS.joinpath("LICENSE-cytoscape.txt").read_text(encoding="utf-8").startswith("Copyright")
    )


def test_reports_without_vulnerability_data() -> None:
    plain = ScanResult("0.0.1", "demo", T0, T0, manifests=hostile_scan().manifests)
    assert '"vulnerability_status": "not_queried"' in render_html(plain)
    assert "Vulnerabilities: not checked" in render_text(plain)


def test_graph_uses_the_lockfile_and_skips_a_manifest_next_to_it() -> None:
    from dva.domain.dependency import DeclaredRequirement
    from dva.reporting.html import graph_data

    lock = hostile_scan().manifests[0]
    beside = ManifestAnalysis(
        "package.json",
        "npm",
        "npm",
        ManifestKind.MANIFEST,
        "package-json",
        ParseStatus.PARSED,
        requirements=(DeclaredRequirement(PackageIdentity("npm", "a"), constraint="^1"),),
    )
    alone = ManifestAnalysis(
        "tools/package.json",
        "npm",
        "npm",
        ManifestKind.MANIFEST,
        "package-json",
        ParseStatus.PARSED,
        requirements=(DeclaredRequirement(PackageIdentity("npm", "b"), constraint="^2"),),
    )
    graph = graph_data(ScanResult("0.0.1", "demo", T0, T0, manifests=(lock, beside, alone)))
    nodes = graph["nodes"]
    assert isinstance(nodes, list)
    roots = [n["label"] for n in nodes if isinstance(n, dict) and n["kind"] == "root"]
    assert roots == ["package-lock.json", "tools/package.json"]
    labels = {n["label"] for n in nodes if isinstance(n, dict)}
    assert "b ^2" in labels and "a ^1" not in labels


def test_copies_of_one_vulnerability_are_grouped_under_the_richest_record() -> None:
    from dva.reporting.overview import group_findings

    ghsa = Advisory(
        "GHSA-1", T0, aliases=("CVE-1", "PYSEC-1"), summary="s", database_severity="HIGH"
    )
    pysec = Advisory("PYSEC-1", T0, aliases=("CVE-1", "GHSA-1"))
    other = Advisory("GHSA-2", T0, aliases=("CVE-2",))
    advisories = {a.id: a for a in (ghsa, pysec, other)}
    findings = tuple(Finding(i, ("range",)) for i in ("PYSEC-1", "GHSA-2", "GHSA-1"))
    groups = group_findings(findings, advisories)
    assert [[f.advisory_id for f in g] for g in groups] == [["GHSA-1", "PYSEC-1"], ["GHSA-2"]]


def test_package_level_severity_is_shown_in_every_format() -> None:
    from dataclasses import replace

    scan = hostile_scan()
    assert scan.vulnerabilities is not None
    check = scan.vulnerabilities.checks[0]
    finding = replace(check.findings[0], severities=(Severity("CVSS_V4", "CVSS:4.0/AV:N"),))
    report = replace(scan.vulnerabilities, checks=(replace(check, findings=(finding,)),))
    scan = replace(scan, vulnerabilities=report)
    assert "CVSS_V4 CVSS:4.0/AV:N (for this package)" in render_text(scan)
    data = json.loads(render_json(scan))
    (found,) = data["vulnerabilities"]["checks"][0]["findings"]
    assert found["severities"] == [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N", "source": None}]
    assert "(for this package)" in (ASSETS / "report.js").read_text(encoding="utf-8")
