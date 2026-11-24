"""The standalone HTML report: dependency graph, findings and files in one page.

The page works offline: its stylesheet, its script and the graph library
(Cytoscape.js, vendored in ``assets/``) are all inside the file. Scan data
is embedded as JSON in a ``<script type="application/json">`` element, with
``<``, ``>`` and ``&`` escaped so no value can close the element, and the
page script only ever puts text into the page with ``textContent``. A
Content Security Policy allows exactly the page's own inline scripts (by
hash), no network access and no plugins.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
import posixpath
import re
from importlib.resources import files

from dva.domain.manifest import ManifestKind
from dva.domain.scan import ScanResult
from dva.domain.serialization import JsonValue, scan_to_dict
from dva.domain.vulnerability import CheckStatus
from dva.reporting.overview import Overview

_PLACEHOLDER = re.compile(r"\{\{([A-Z]+)\}\}")

#: Above this many nodes the graph is left out; the tables still show everything.
MAX_GRAPH_NODES = 3000


def _asset(name: str) -> str:
    return files("dva.reporting").joinpath("assets", name).read_text(encoding="utf-8")


def _script_hash(source: str) -> str:
    digest = hashlib.sha256(source.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _embed_json(value: object) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=True)
    return text.replace("&", "\\u0026").replace("<", "\\u003c").replace(">", "\\u003e")


def graph_data(scan: ScanResult) -> dict[str, JsonValue]:
    """Nodes and edges for the graph: one tree per dependency file.

    Lockfiles contribute their resolved packages and links. A manifest with
    no lockfile in the same folder contributes its declared requirements, so a
    project without a lockfile still gets a (one-level) picture; when there is
    a lockfile, the manifest would only repeat it, so it is left out.
    """
    status_of: dict[tuple[str, str | None], str] = {}
    if scan.vulnerabilities is not None:
        for check in scan.vulnerabilities.checks:
            for location in check.locations:
                status_of[(location.path, location.node_id)] = check.status.value
                if location.line is not None:
                    status_of[(location.path, f"line:{location.line}")] = check.status.value

    locked_folders = {
        posixpath.dirname(m.path)
        for m in scan.manifests
        if m.kind is ManifestKind.LOCKFILE and m.packages
    }
    nodes: list[JsonValue] = []
    edges: list[JsonValue] = []
    for manifest in sorted(scan.manifests, key=lambda m: m.path):
        root = f"{manifest.path}::"
        if manifest.kind is ManifestKind.LOCKFILE and manifest.packages:
            nodes.append({"id": root, "label": manifest.path, "kind": "root", "status": "root"})
            for package in manifest.packages:
                name = package.identity.name
                if package.identity.namespace:
                    name = f"{package.identity.namespace}/{name}"
                nodes.append(
                    {
                        "id": f"{root}{package.node_id}",
                        "label": f"{name} {package.version}",
                        "kind": "package",
                        "status": status_of.get((manifest.path, package.node_id), "none"),
                        "file": manifest.path,
                    }
                )
            for edge in manifest.edges:
                parent = root if edge.parent_id is None else f"{root}{edge.parent_id}"
                edges.append({"source": parent, "target": f"{root}{edge.child_id}"})
        elif (
            manifest.kind is ManifestKind.MANIFEST
            and manifest.requirements
            and posixpath.dirname(manifest.path) not in locked_folders
        ):
            nodes.append({"id": root, "label": manifest.path, "kind": "root", "status": "root"})
            for index, requirement in enumerate(manifest.requirements):
                name = requirement.identity.name
                if requirement.identity.namespace:
                    name = f"{requirement.identity.namespace}/{name}"
                node_id = f"{root}req:{index}"
                status = "none"
                if requirement.line is not None:
                    status = status_of.get((manifest.path, f"line:{requirement.line}"), "none")
                label = f"{name} {requirement.constraint}" if requirement.constraint else name
                nodes.append(
                    {
                        "id": node_id,
                        "label": label,
                        "kind": "requirement",
                        "status": status,
                        "file": manifest.path,
                    }
                )
                edges.append({"source": root, "target": node_id})
    if len(nodes) > MAX_GRAPH_NODES:
        return {"nodes": [], "edges": [], "omitted": len(nodes)}
    return {"nodes": nodes, "edges": edges, "omitted": 0}


def render_html(scan: ScanResult) -> str:
    data = scan_to_dict(scan)
    data["overview"] = Overview.of(scan).to_json()
    data["graph"] = graph_data(scan)
    data["statuses"] = [status.value for status in CheckStatus]

    library = _asset("cytoscape.min.js")
    app = _asset("report.js")
    style = _asset("report.css")
    policy = "; ".join(
        [
            "default-src 'none'",
            f"script-src {_script_hash(library)} {_script_hash(app)}",
            # Cytoscape sets element styles from script; no style can load anything.
            "style-src 'unsafe-inline'",
            "img-src data:",
            "base-uri 'none'",
            "form-action 'none'",
        ]
    )
    if '"' in policy or "<" in policy:
        raise ValueError("content security policy must not contain quotes or markup")
    title = html.escape(f"DVA report: {scan.project_name}")
    values = {
        # Built by DVA alone (hashes and keywords), so it never contains a quote.
        "CSP": policy,
        "TITLE": title,
        "STYLE": style,
        "DATA": _embed_json(data),
        "LIBRARY": library,
        "APP": app,
    }
    # One pass, so text inserted for one placeholder is never scanned for another.
    return _PLACEHOLDER.sub(lambda m: values[m.group(1)], _asset("report.html"))
