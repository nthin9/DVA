"""Scanning a local npm project end to end with the built-in adapters (offline)."""

from __future__ import annotations

import shutil
from pathlib import Path

from dva.application.analyze import analyze_project
from dva.domain.dependency import SourceKind
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.domain.scan import CompletionState
from dva.domain.serialization import dumps_scan
from dva.ecosystems.registry import default_registry

FIXTURE = Path(__file__).parents[1] / "fixtures" / "npm" / "basic_project"


def scan(tmp_path: Path) -> tuple[dict[str, ManifestAnalysis], str]:
    root = tmp_path / "project"
    shutil.copytree(FIXTURE, root)
    result = analyze_project(root, default_registry())
    assert result.completion is CompletionState.PARTIAL
    assert not (root / "POSTINSTALL_WAS_EXECUTED").exists()
    return {m.path: m for m in result.manifests}, dumps_scan(result)


def test_every_npm_file_is_accounted_for_and_node_modules_is_skipped(tmp_path: Path) -> None:
    manifests, _ = scan(tmp_path)
    assert {path: m.status for path, m in manifests.items()} == {
        "package.json": ParseStatus.PARSED,
        "package-lock.json": ParseStatus.PARSED,
        "packages/shared-ui/package.json": ParseStatus.PARSED,
        "yarn.lock": ParseStatus.UNSUPPORTED,
    }


def test_package_json_requirements(tmp_path: Path) -> None:
    manifests, _ = scan(tmp_path)
    found = {
        (r.identity.namespace, r.identity.name, r.constraint, r.groups, r.source, r.alias)
        for r in manifests["package.json"].requirements
    }
    assert found == {
        (None, "express", "^4.21.0", (), SourceKind.REGISTRY, None),
        ("@babel", "core", "~7.26.0", (), SourceKind.REGISTRY, None),
        (None, "lodash", "^3.10.1", (), SourceKind.REGISTRY, "lodash-legacy"),
        (
            None,
            "internal-tool",
            "git+https://***@example.com/org/internal-tool.git#v1.2.0",
            (),
            SourceKind.GIT,
            None,
        ),
        (None, "shared-ui", "workspace:*", (), SourceKind.WORKSPACE, None),
        (None, "typescript", "5.7.2", ("dev",), SourceKind.REGISTRY, None),
        (None, "fsevents", "^2.3.3", ("optional",), SourceKind.REGISTRY, None),
        (None, "react", ">=18", ("optional", "peer"), SourceKind.REGISTRY, None),
    }
    assert "npm.package_json.workspaces" in {d.code for d in manifests["package.json"].diagnostics}


def test_lockfile_graph(tmp_path: Path) -> None:
    manifests, _ = scan(tmp_path)
    lock = manifests["package-lock.json"]
    assert lock.format_version == "3"
    packages = {p.node_id: p for p in lock.packages}
    assert "node_modules/shared-ui" not in packages
    assert "packages/shared-ui" not in packages

    babel = packages["node_modules/@babel/core"]
    assert (babel.identity.namespace, babel.identity.name) == ("@babel", "core")
    assert babel.identity.purl == "pkg:npm/%40babel/core"
    assert packages["node_modules/lodash-legacy"].identity.name == "lodash"
    assert packages["node_modules/internal-tool"].source is SourceKind.GIT
    assert packages["node_modules/internal-tool"].identity.purl is None
    assert packages["node_modules/typescript"].groups == ("dev",)
    assert packages["node_modules/fsevents"].groups == ("optional",)

    # Two versions of debug and of ms, each its own node.
    assert packages["node_modules/debug"].version == "4.3.7"
    assert packages["node_modules/express/node_modules/debug"].version == "2.6.9"

    edges = {(e.parent_id, e.child_id): e for e in lock.edges}
    direct = {child for parent, child in edges if parent is None}
    assert direct == {
        "node_modules/@babel/core",
        "node_modules/express",
        "node_modules/internal-tool",
        "node_modules/lodash-legacy",
        "node_modules/typescript",
        "node_modules/fsevents",
        "node_modules/debug",  # via the shared-ui workspace member
    }
    assert edges[(None, "node_modules/typescript")].groups == ("dev",)
    # Node's lookup: express finds its own nested copies first.
    assert ("node_modules/express", "node_modules/express/node_modules/debug") in edges
    assert ("node_modules/express", "node_modules/express/node_modules/ms") in edges
    # The nested debug finds the nested ms next to it, not the top-level one.
    assert (
        "node_modules/express/node_modules/debug",
        "node_modules/express/node_modules/ms",
    ) in edges
    # The top-level debug finds the top-level ms.
    assert ("node_modules/debug", "node_modules/ms") in edges
    # The optional peer react isn't installed; that's noted, not an error.
    assert "npm.package_lock.optional_missing" in {d.code for d in lock.diagnostics}


def test_credentials_and_hashes_stay_out_of_the_results(tmp_path: Path) -> None:
    _, output = scan(tmp_path)
    assert "s3cret" not in output
    assert "sha512" not in output
    assert "registry.npmjs.org" not in output
