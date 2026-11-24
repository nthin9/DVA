from __future__ import annotations

import pytest

from dva.domain.dependency import SourceKind
from dva.ecosystems.npm.names import identity, is_valid_name
from dva.ecosystems.npm.spec import InvalidSpecError, classify


@pytest.mark.parametrize(
    ("spec", "source", "constraint"),
    [
        ("^1.2.3", SourceKind.REGISTRY, "^1.2.3"),
        (">=1 <2 || 3.x", SourceKind.REGISTRY, ">=1 <2 || 3.x"),
        ("latest", SourceKind.REGISTRY, "latest"),
        ("", SourceKind.REGISTRY, None),
        (
            "git+ssh://git@github.com/a/b.git#v1",
            SourceKind.GIT,
            "git+ssh://***@github.com/a/b.git#v1",
        ),
        ("github:user/repo", SourceKind.GIT, "github:user/repo"),
        ("user/repo#main", SourceKind.GIT, "user/repo#main"),
        ("https://example.com/pkg.tgz", SourceKind.URL, "https://example.com/pkg.tgz"),
        ("file:../local", SourceKind.PATH, "file:../local"),
        ("link:../linked", SourceKind.PATH, "link:../linked"),
        ("./vendored", SourceKind.PATH, "./vendored"),
        ("C:\\pkgs\\x", SourceKind.PATH, "C:\\pkgs\\x"),
        ("workspace:^", SourceKind.WORKSPACE, "workspace:^"),
    ],
)
def test_classify(spec: str, source: SourceKind, constraint: str | None) -> None:
    result = classify(spec)
    assert (result.source, result.constraint, result.target_name) == (source, constraint, None)


@pytest.mark.parametrize(
    ("spec", "name", "constraint"),
    [
        ("npm:lodash@^4", "lodash", "^4"),
        ("npm:@scope/pkg@1.0.0", "@scope/pkg", "1.0.0"),
        ("npm:lodash", "lodash", None),
        ("npm:@scope/pkg", "@scope/pkg", None),
    ],
)
def test_aliases(spec: str, name: str, constraint: str | None) -> None:
    result = classify(spec)
    assert (result.source, result.target_name, result.constraint) == (
        SourceKind.REGISTRY,
        name,
        constraint,
    )


@pytest.mark.parametrize("spec", ["npm:", "npm:@scope", "npm:../evil@1", "npm:a b@1"])
def test_bad_aliases(spec: str) -> None:
    with pytest.raises(InvalidSpecError):
        classify(spec)


@pytest.mark.parametrize(
    ("name", "valid"),
    [
        ("lodash", True),
        ("@babel/core", True),
        ("JSONStream", True),
        ("", False),
        (".hidden", False),
        ("_private", False),
        ("@scope", False),
        ("@scope/", False),
        ("a/b", False),
        ("../x", False),
        ("has space", False),
        ("x" * 215, False),
    ],
)
def test_name_validation(name: str, valid: bool) -> None:
    assert is_valid_name(name) is valid


def test_identity_splits_scope_and_encodes_purl() -> None:
    scoped = identity("@babel/core")
    assert (scoped.ecosystem, scoped.namespace, scoped.name) == ("npm", "@babel", "core")
    assert scoped.purl == "pkg:npm/%40babel/core"
    plain = identity("lodash", from_registry=False)
    assert (plain.namespace, plain.purl) == (None, None)
