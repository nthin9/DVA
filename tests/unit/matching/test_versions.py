from __future__ import annotations

import pytest

from dva.matching.schemes import NPM, PYPI, UnparsableVersionError, scheme_for
from dva.matching.semver import InvalidSemVerError, SemVer

# The precedence example from section 11 of the SemVer 2.0.0 specification,
# plus numeric ordering that plain text comparison would get wrong.
SEMVER_ORDER = [
    "1.0.0-alpha",
    "1.0.0-alpha.1",
    "1.0.0-alpha.beta",
    "1.0.0-beta",
    "1.0.0-beta.2",
    "1.0.0-beta.11",
    "1.0.0-rc.1",
    "1.0.0",
    "1.0.1",
    "1.9.0",
    "1.10.0",
    "2.0.0",
]


def test_semver_precedence_follows_the_specification() -> None:
    keys = [SemVer.parse(v) for v in SEMVER_ORDER]
    assert keys == sorted(keys)
    assert len(set(keys)) == len(keys)


def test_semver_ignores_build_metadata_and_a_leading_v() -> None:
    assert SemVer.parse("1.0.0+build.1") == SemVer.parse("1.0.0+build.2") == SemVer.parse("1.0.0")
    assert SemVer.parse("v1.2.3") == SemVer.parse("1.2.3")


@pytest.mark.parametrize(
    "text", ["1.2", "1.2.3.4", "01.2.3", "1.2.3-01", "1.2.3-", "latest", "", "1.2.3 "]
)
def test_invalid_semver(text: str) -> None:
    with pytest.raises(InvalidSemVerError):
        SemVer.parse(text)


@pytest.mark.parametrize(
    ("lower", "higher"),
    [
        ("1.9", "1.10"),
        ("2.0rc1", "2.0"),
        ("2.0", "2.0.post1"),
        ("2.0.dev1", "2.0a1"),
        ("9.9", "1!0.1"),  # an epoch outranks every version without one
        ("2.31.0", "2.31.0.1"),
    ],
)
def test_pep440_ordering(lower: str, higher: str) -> None:
    assert PYPI.key(lower) < PYPI.key(higher)


def test_pep440_normalizes_equal_spellings() -> None:
    assert PYPI.key("2.0") == PYPI.key("2.0.0") == PYPI.key("v2.0")
    assert PYPI.key("1.0RC1") == PYPI.key("1.0rc1")


def test_unparsable_versions_raise_one_error_type() -> None:
    with pytest.raises(UnparsableVersionError):
        PYPI.key("not a version")
    with pytest.raises(UnparsableVersionError):
        NPM.key("1.2")


def test_package_name_rules() -> None:
    assert PYPI.same_package("Django_REST.framework", "django-rest-framework")
    assert not NPM.same_package("Lodash", "lodash")
    assert NPM.same_package("@babel/core", "@babel/core")


def test_scheme_lookup() -> None:
    assert scheme_for("pypi") is PYPI
    assert scheme_for("npm") is NPM
    assert scheme_for("cargo") is None
