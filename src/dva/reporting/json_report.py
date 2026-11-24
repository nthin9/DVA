"""The JSON report: the full scan result plus an overview of counts."""

from __future__ import annotations

import json

from dva.domain.scan import ScanResult
from dva.domain.serialization import scan_to_dict
from dva.reporting.overview import Overview


def render_json(scan: ScanResult) -> str:
    data = scan_to_dict(scan)
    data["overview"] = Overview.of(scan).to_json()
    return json.dumps(data, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
