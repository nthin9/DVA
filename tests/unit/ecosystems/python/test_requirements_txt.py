from __future__ import annotations

from collections.abc import Mapping

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.domain.dependency import SourceKind
from dva.domain.manifest import ParseStatus
from dva.ecosystems.python.adapter import REQUIREMENTS_TXT, PythonAdapter
from dva.ecosystems.python.requirements_txt import MAX_INCLUDE_DEPTH
from tests.support.readers import MemoryReader


def parse(
    text: str | bytes,
    files: Mapping[str, bytes | str] | None = None,
    path: str = "requirements.txt",
) -> tuple[AdapterResult, MemoryReader]:
    reader = MemoryReader(files)
    content = text.encode("utf-8") if isinstance(text, str) else text
    result = PythonAdapter().parse(ParseContext(path, content, REQUIREMENTS_TXT, reader))
    return result, reader


def names(result: AdapterResult) -> list[str]:
    return [r.identity.name for r in result.requirements]


def codes(result: AdapterResult) -> set[str]:
    return {d.code for d in result.diagnostics}


def test_plain_file_with_comments_and_blank_lines() -> None:
    result, _ = parse("# top\n\nDjango==5.0  # pinned\nrequests>=2\n   \n")
    assert result.status is ParseStatus.PARSED
    assert names(result) == ["django", "requests"]
    assert [r.line for r in result.requirements] == [3, 4]
    assert result.requirements[0].constraint == "==5.0"
    assert not result.diagnostics


def test_hash_comment_without_space_is_part_of_url() -> None:
    result, _ = parse("pkg @ https://example.com/p.whl#sha256=abc\n")
    assert result.requirements[0].constraint == "https://example.com/p.whl#sha256=abc"


def test_line_continuations_are_joined_and_keep_first_line_number() -> None:
    result, _ = parse("a\nrequests \\\n  >=2 \\\n  ,<3\n")
    assert names(result) == ["a", "requests"]
    assert result.requirements[1].line == 2
    assert result.requirements[1].constraint == ">=2   ,<3"


def test_hashes_are_accepted_silently() -> None:
    result, _ = parse("pkg==1.0 --hash=sha256:aa --hash=sha256:bb\n")
    assert result.status is ParseStatus.PARSED
    assert result.requirements[0].constraint == "==1.0"


def test_other_per_requirement_options_are_noted() -> None:
    result, _ = parse("pkg==1.0 --config-settings=x=y\n")
    assert result.status is ParseStatus.PARSED
    assert "python.requirements.option_ignored" in codes(result)


def test_installer_options_are_ignored_without_echoing_values() -> None:
    result, _ = parse("--index-url https://user:token@private.example/simple\n-i https://x\npkg\n")
    assert result.status is ParseStatus.PARSED
    assert names(result) == ["pkg"]
    assert all("token" not in d.message for d in result.diagnostics)


def test_markers_and_extras() -> None:
    result, _ = parse('pkg[a]>=1; sys_platform == "win32"\n')
    requirement = result.requirements[0]
    assert requirement.extras == ("a",)
    assert requirement.markers == 'sys_platform == "win32"'


def test_editable_and_unnamed_requirements_make_the_result_partial() -> None:
    result, _ = parse("-e .\n./local/pkg\nhttps://example.com/pkg.whl\npkg-1.0.whl\nok\n")
    assert result.status is ParseStatus.PARTIAL
    assert names(result) == ["ok"]
    assert "python.requirements.editable" in codes(result)
    unnamed = [d for d in result.diagnostics if d.code == "python.requirements.unnamed"]
    assert len(unnamed) == 3


def test_invalid_line_is_reported_and_others_kept() -> None:
    result, _ = parse("good\nbad ==\nalso-good\n")
    assert result.status is ParseStatus.PARTIAL
    assert names(result) == ["good", "also-good"]
    invalid = [d for d in result.diagnostics if d.code == "python.requirements.invalid_line"]
    assert invalid and invalid[0].message.startswith("line 2:")


def test_environment_variables_are_not_expanded() -> None:
    result, _ = parse("pkg @ https://${TOKEN}@example.com/pkg.whl\n")
    assert result.status is ParseStatus.PARTIAL
    assert "python.requirements.env_var" in codes(result)


def test_unknown_option_is_a_warning() -> None:
    result, _ = parse("--frobnicate\n")
    assert result.status is ParseStatus.PARTIAL
    assert "python.requirements.unknown_option" in codes(result)


def test_constraints_files_pin_ranged_requirements() -> None:
    files = {
        "constraints.txt": "pkg==1.4\nother==2\nranged>=1\n-r more.txt\n",
        "more.txt": "late==3\n",
    }
    result, reader = parse("-c constraints.txt\npkg>=1\npinned==2.0\nlate\nnot-pinned\n", files)
    assert result.status is ParseStatus.PARSED
    assert reader.requested == ["constraints.txt", "more.txt"]
    # Constraints add no requirements of their own.
    assert names(result) == ["pkg", "pinned", "late", "not-pinned"]
    pins = {r.identity.name: r.constrained_to for r in result.requirements}
    assert pins == {"pkg": "1.4", "pinned": None, "late": "3", "not-pinned": None}
    assert "python.requirements.constraints_file" in codes(result)


def test_a_constraint_the_requirement_does_not_allow_is_reported() -> None:
    result, _ = parse("-c c.txt\npkg<1\n", {"c.txt": "pkg==2\n"})
    assert result.requirements[0].constrained_to is None
    assert result.status is ParseStatus.PARTIAL
    assert "python.requirements.constraint_conflict" in codes(result)


def test_two_different_pins_for_one_package_are_not_used() -> None:
    result, _ = parse("-c a.txt\n-c b.txt\npkg\n", {"a.txt": "pkg==1\n", "b.txt": "pkg==2\n"})
    assert result.requirements[0].constrained_to is None
    assert "python.requirements.constraint_conflict" in codes(result)


def test_a_private_index_marks_requirements_as_another_registry() -> None:
    result, _ = parse("--index-url https://user:pw@pkgs.example.com/simple\npkg==1\n")
    (requirement,) = result.requirements
    assert requirement.source is SourceKind.OTHER_REGISTRY
    assert requirement.identity.purl is None
    assert "python.requirements.other_index" in codes(result)
    assert "pw" not in " ".join(d.message for d in result.diagnostics)
    public, _ = parse("-i https://pypi.org/simple\npkg==1\n")
    assert public.requirements[0].source is SourceKind.REGISTRY


def test_includes_are_followed_relative_to_the_including_file() -> None:
    files = {"reqs/base.txt": "django==5.0\n", "reqs/extra/more.txt": "-r ../base.txt\n"}
    result, reader = parse("-r base.txt\n-r extra/more.txt\npkg\n", files, "reqs/requirements.txt")
    assert reader.requested == ["reqs/base.txt", "reqs/extra/more.txt"]
    assert names(result) == ["django", "pkg"]
    # An included requirement keeps the file and line it is written in.
    assert (result.requirements[0].origin, result.requirements[0].line) == ("reqs/base.txt", 1)
    assert (result.requirements[1].origin, result.requirements[1].line) == (None, 3)
    assert "python.requirements.include_repeated" in codes(result)
    included = [d.path for d in result.diagnostics if d.code == "python.requirements.included"]
    assert included == ["reqs/base.txt", "reqs/extra/more.txt"]


def test_include_option_spellings() -> None:
    files = {"a.txt": "a\n", "b.txt": "b\n", "c.txt": "c\n"}
    result, _ = parse("-ra.txt\n--requirement=b.txt\n--requirement c.txt\n", files)
    assert names(result) == ["a", "b", "c"]


def test_include_cycle_is_reported() -> None:
    result, _ = parse("-r requirements.txt\n-r other.txt\n", {"other.txt": "-r requirements.txt\n"})
    assert result.status is ParseStatus.PARTIAL
    assert "python.requirements.include_cycle" in codes(result)


def test_includes_outside_the_project_are_never_read() -> None:
    text = r"""-r ../outside.txt
-r /etc/passwd
-r 'C:\Windows\win.ini'
-r '..\up.txt'
"""
    result, reader = parse(text, path="requirements.txt")
    assert reader.requested == []
    outside = [
        d for d in result.diagnostics if d.code == "python.requirements.include_outside_root"
    ]
    assert len(outside) == 4


def test_url_includes_are_never_downloaded() -> None:
    result, reader = parse("-r https://example.com/reqs.txt\n")
    assert reader.requested == []
    assert "python.requirements.include_url" in codes(result)


def test_unreadable_and_undecodable_includes_are_reported() -> None:
    result, _ = parse("-r missing.txt\n-r binary.txt\n", {"binary.txt": b"\xff\xfe"})
    assert result.status is ParseStatus.PARTIAL
    unreadable = [
        d for d in result.diagnostics if d.code == "python.requirements.include_unreadable"
    ]
    assert len(unreadable) == 2


def test_include_depth_is_bounded() -> None:
    depth = MAX_INCLUDE_DEPTH + 3
    files: dict[str, bytes | str] = {
        f"r{i}.txt": f"-r r{i + 1}.txt\npkg{i}\n" for i in range(depth)
    }
    result, reader = parse("-r r0.txt\n", files)
    assert result.status is ParseStatus.PARTIAL
    assert "python.requirements.include_limit" in codes(result)
    assert len(reader.requested) == MAX_INCLUDE_DEPTH


def test_bom_is_ignored_and_non_utf8_fails() -> None:
    result, _ = parse(b"\xef\xbb\xbfpkg\n")
    assert names(result) == ["pkg"]
    failed, _ = parse(b"pkg\xff\n")
    assert failed.status is ParseStatus.FAILED
    assert "python.decode_error" in codes(failed)


def test_crlf_line_endings() -> None:
    result, _ = parse("a==1\r\nb==2\r\n")
    assert names(result) == ["a", "b"]
    assert result.requirements[1].constraint == "==2"


def test_include_with_nul_byte_is_refused_before_reading() -> None:
    result, reader = parse("-r a\x00b.txt\n")
    assert reader.requested == []
    assert "python.requirements.include_outside_root" in codes(result)
