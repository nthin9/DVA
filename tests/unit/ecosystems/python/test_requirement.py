from __future__ import annotations

import pytest

from dva.domain.dependency import SourceKind
from dva.ecosystems.python.requirement import RequirementSyntaxError, parse_requirement


def test_name_is_normalized_and_purl_set() -> None:
    requirement = parse_requirement("Foo_Bar.baz>=1.0")
    assert requirement.identity.ecosystem == "pypi"
    assert requirement.identity.name == "foo-bar-baz"
    assert requirement.identity.purl == "pkg:pypi/foo-bar-baz"


def test_constraint_and_markers_are_kept_as_written() -> None:
    requirement = parse_requirement('requests >=2.31, <3 ; python_version<"3.13"')
    assert requirement.constraint == ">=2.31, <3"
    assert requirement.markers == 'python_version<"3.13"'
    assert requirement.source is SourceKind.REGISTRY


def test_parenthesized_constraint_and_extras() -> None:
    requirement = parse_requirement("requests[socks,Security] (>=2)")
    assert requirement.constraint == ">=2"
    assert requirement.extras == ("security", "socks")


def test_bare_name_has_no_constraint() -> None:
    requirement = parse_requirement("django")
    assert requirement.constraint is None
    assert requirement.markers is None


@pytest.mark.parametrize(
    ("text", "source"),
    [
        ("pkg @ git+https://example.com/pkg.git@v1", SourceKind.GIT),
        ("pkg @ https://example.com/pkg-1.0.tar.gz", SourceKind.URL),
        ("pkg @ file:///home/someone/pkg", SourceKind.PATH),
    ],
)
def test_url_requirements_record_their_source(text: str, source: SourceKind) -> None:
    requirement = parse_requirement(text)
    assert requirement.source is source
    assert requirement.identity.purl is None


def test_url_marker_is_separated() -> None:
    requirement = parse_requirement('pkg @ https://example.com/p.whl ; os_name == "nt"')
    assert requirement.constraint == "https://example.com/p.whl"
    assert requirement.markers == 'os_name == "nt"'


def test_credentials_in_urls_are_redacted() -> None:
    requirement = parse_requirement("pkg @ git+https://user:s3cret@example.com/pkg.git")
    assert requirement.constraint == "git+https://***@example.com/pkg.git"
    assert "s3cret" not in repr(requirement)


def test_requirement_on_the_project_itself_is_a_workspace_dependency() -> None:
    requirement = parse_requirement("My_Project[test]", project_name="my-project")
    assert requirement.source is SourceKind.WORKSPACE
    assert requirement.extras == ("test",)


@pytest.mark.parametrize("text", ["", "==1.0", "foo ==", "foo[bar", "foo; python_version <"])
def test_invalid_specifiers_raise(text: str) -> None:
    with pytest.raises(RequirementSyntaxError):
        parse_requirement(text)


def test_error_message_does_not_leak_secrets_or_long_text() -> None:
    with pytest.raises(RequirementSyntaxError) as error:
        parse_requirement("pkg @@ https://user:token@example.com/" + "x" * 500)
    assert "token" not in str(error.value)
    assert len(str(error.value)) < 200
