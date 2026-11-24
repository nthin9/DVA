"""The JSON report: the full scan result plus an overview of counts."""

from __future__ import annotations

import json

from dva.domain.scan import ScanResult
from dva.domain.serialization import scan_to_dict
from dva.reporting.overview import JsonValue, Overview, introduced_by


def render_json(scan: ScanResult) -> str:
    data = scan_to_dict(scan)
    data["overview"] = Overview.of(scan).to_json()
    add_introduced_by(scan, data)
    return json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2) + "\n"


def add_introduced_by(scan: ScanResult, data: dict[str, JsonValue]) -> None:
    """Give each check in ``data`` the chain of packages that pulls it in,
    for every lockfile location: an empty list means a direct dependency."""
    report = data.get("vulnerabilities")
    if not isinstance(report, dict):
        return
    checks = report.get("checks")
    if not isinstance(checks, list):
        return
    paths = introduced_by(scan)
    for check in checks:
        locations = check.get("locations") if isinstance(check, dict) else None
        if not isinstance(check, dict) or not isinstance(locations, list):
            continue
        chains: list[JsonValue] = []
        for location in locations:
            if isinstance(location, dict):
                key = (str(location.get("path")), str(location.get("node_id") or ""))
                if key in paths:
                    chain: list[JsonValue] = [name for name in paths[key]]
                    if chain not in chains:
                        chains.append(chain)
        check["introduced_by"] = chains
