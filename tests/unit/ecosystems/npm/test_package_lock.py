from __future__ import annotations

import json

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import SourceKind
from dva.domain.manifest import ManifestAnalysis, ParseStatus
from dva.ecosystems.npm.adapter import PACKAGE_LOCK, SHRINKWRAP, NpmAdapter
from tests.support.readers import MemoryReader

REGISTRY = "https://registry.npmjs.org/{0}/-/{0}-{1}.tgz"


def entry(name: str, version: str, **extra: object) -> dict[str, object]:
    return {"version": version, "resolved": REGISTRY.format(name, version), **extra}


def lock(packages: dict[str, object], version: int = 3) -> str:
    return json.dumps({"lockfileVersion": version, "packages": packages})


def parse(text: str) -> AdapterResult:
    context = ParseContext("package-lock.json", text.encode("utf-8"), PACKAGE_LOCK, MemoryReader())
    result = NpmAdapter().parse(context)
    ManifestAnalysis(
        path="package-lock.json",
        adapter_id="npm",
        ecosystem="npm",
        kind=PACKAGE_LOCK.kind,
        format_name=PACKAGE_LOCK.format_name,
        status=result.status,
        packages=result.packages,
        edges=result.edges,
        diagnostics=result.diagnostics,
    )
    return result


def codes(result: AdapterResult) -> set[str]:
    return {d.code for d in result.diagnostics}


def edge_set(result: AdapterResult) -> set[tuple[str | None, str]]:
    return {(e.parent_id, e.child_id) for e in result.edges}


def test_version_1_is_unsupported_and_missing_versions_fail() -> None:
    v1 = parse(json.dumps({"lockfileVersion": 1, "dependencies": {}}))
    assert v1.status is ParseStatus.UNSUPPORTED
    assert v1.format_version == "1"
    assert parse(json.dumps({"packages": {}})).status is ParseStatus.FAILED
    assert parse(json.dumps({"lockfileVersion": 3})).status is ParseStatus.FAILED
    assert parse(json.dumps({"lockfileVersion": True, "packages": {}})).status is ParseStatus.FAILED


def test_version_2_reads_the_packages_section() -> None:
    text = lock({"": {"dependencies": {"a": "^1"}}, "node_modules/a": entry("a", "1.0.0")}, 2)
    result = parse(text)
    assert result.status is ParseStatus.PARSED
    assert result.format_version == "2"
    assert edge_set(result) == {(None, "node_modules/a")}
    assert result.edges[0].constraint == "^1"


def test_lookup_walks_up_through_nested_node_modules() -> None:
    text = lock(
        {
            "": {"dependencies": {"a": "1"}},
            "node_modules/a": entry("a", "1.0.0", dependencies={"b": "1", "c": "1"}),
            "node_modules/a/node_modules/b": entry("b", "1.0.0", dependencies={"c": "2"}),
            "node_modules/a/node_modules/b/node_modules/c": entry("c", "2.0.0"),
            "node_modules/c": entry("c", "1.0.0"),
        }
    )
    result = parse(text)
    assert edge_set(result) == {
        (None, "node_modules/a"),
        ("node_modules/a", "node_modules/a/node_modules/b"),
        ("node_modules/a", "node_modules/c"),
        ("node_modules/a/node_modules/b", "node_modules/a/node_modules/b/node_modules/c"),
    }


def test_scoped_packages_resolve() -> None:
    text = lock(
        {
            "": {"dependencies": {"@s/a": "1"}},
            "node_modules/@s/a": entry("@s/a", "1.0.0", dependencies={"b": "1"}),
            "node_modules/b": entry("b", "1.0.0"),
        }
    )
    result = parse(text)
    assert edge_set(result) == {
        (None, "node_modules/@s/a"),
        ("node_modules/@s/a", "node_modules/b"),
    }


def test_links_to_non_workspace_folders_are_followed() -> None:
    text = lock(
        {
            "": {"dependencies": {"vendored": "file:vendor/v"}},
            "node_modules/vendored": {"resolved": "vendor/v", "link": True},
            "vendor/v": {"version": "1.0.0", "dependencies": {"x": "1"}},
            "node_modules/x": entry("x", "1.0.0"),
        }
    )
    result = parse(text)
    # vendor/v sits outside node_modules, so it is treated as part of the project.
    assert edge_set(result) == {(None, "node_modules/x")}


def test_missing_dependencies_are_reported_unless_optional() -> None:
    text = lock(
        {
            "": {
                "dependencies": {"gone": "1"},
                "optionalDependencies": {"maybe": "1"},
                "peerDependencies": {"peer-opt": "1", "peer-req": "1"},
                "peerDependenciesMeta": {"peer-opt": {"optional": True}},
            },
            "node_modules/dangling": {"resolved": "nowhere", "link": True},
        }
    )
    result = parse(text)
    assert result.status is ParseStatus.PARTIAL
    unresolved = [d.message for d in result.diagnostics if d.code.endswith("unresolved_dependency")]
    assert len(unresolved) == 2
    assert "npm.package_lock.optional_missing" in codes(result)


def test_only_the_projects_dev_dependencies_count() -> None:
    text = lock(
        {
            "": {"devDependencies": {"a": "1"}},
            "node_modules/a": entry("a", "1.0.0", dev=True, devDependencies={"nope": "1"}),
        }
    )
    result = parse(text)
    assert result.status is ParseStatus.PARSED
    assert [(e.parent_id, e.groups) for e in result.edges] == [(None, ("dev",))]


def test_flags_and_sources() -> None:
    text = lock(
        {
            "": {},
            "node_modules/d": entry("d", "1.0.0", devOptional=True),
            "node_modules/p": entry("p", "1.0.0", peer=True),
            "node_modules/g": {"version": "1.0.0", "resolved": "git+ssh://git@x.com/g.git#abc"},
            "node_modules/f": {"version": "1.0.0", "resolved": "file:../f.tgz"},
            "node_modules/u": {"version": "1.0.0", "resolved": "https://cdn.example.com/u.tgz"},
            "node_modules/b": {"version": "1.0.0", "inBundle": True},
            "node_modules/x": entry("x", "1.0.0", extraneous=True),
        }
    )
    result = parse(text)
    packages = {p.node_id: p for p in result.packages}
    assert packages["node_modules/d"].groups == ("dev", "optional")
    assert packages["node_modules/p"].groups == ("peer",)
    assert packages["node_modules/g"].source is SourceKind.GIT
    assert packages["node_modules/f"].source is SourceKind.PATH
    assert packages["node_modules/u"].source is SourceKind.URL
    assert packages["node_modules/b"].source is SourceKind.UNKNOWN
    assert packages["node_modules/x"].source is SourceKind.REGISTRY
    assert packages["node_modules/g"].identity.purl is None
    assert packages["node_modules/x"].identity.purl == "pkg:npm/x"
    assert "npm.package_lock.extraneous" in codes(result)


def test_malformed_entries() -> None:
    text = lock(
        {
            "": {"dependencies": "nope"},
            "node_modules/a": "not an object",
            "node_modules/b": {"resolved": "x"},
            "node_modules/.bad": entry(".bad", "1.0.0"),
            "node_modules/ok": entry("ok", "1.0.0", dependencies={"../evil": "1"}),
        }
    )
    result = parse(text)
    assert result.status is ParseStatus.PARTIAL
    assert [p.node_id for p in result.packages] == ["node_modules/ok"]
    assert {
        "npm.package_lock.invalid_entry",
        "npm.package_lock.invalid_field",
        "npm.package_lock.missing_version",
    } <= codes(result)


def test_no_project_entry_and_duplicate_keys() -> None:
    result = parse(
        '{"lockfileVersion": 3, "packages": {"node_modules/a": {"version": "1"},'
        ' "node_modules/a": {"version": "2"}}}'
    )
    assert result.status is ParseStatus.PARTIAL
    assert {"npm.package_lock.no_project", "npm.duplicate_keys"} <= codes(result)
    assert [p.version for p in result.packages] == ["2"]


def test_credentials_in_ranges_are_redacted() -> None:
    text = lock(
        {
            "": {"dependencies": {"g": "git+https://user:tok@x.com/g.git"}},
            "node_modules/g": {"version": "1.0.0", "resolved": "git+https://x.com/g.git#abc"},
        }
    )
    result = parse(text)
    assert result.edges[0].constraint == "git+https://***@x.com/g.git"


def test_shrinkwrap_uses_the_same_parser() -> None:
    text = lock({"": {"dependencies": {"a": "1"}}, "node_modules/a": entry("a", "1.0.0")})
    context = ParseContext("npm-shrinkwrap.json", text.encode(), SHRINKWRAP, MemoryReader())
    assert NpmAdapter().parse(context).status is ParseStatus.PARSED
