"""pip requirements files (``requirements.txt`` and friends).

Follows the syntax pip documents for requirements files: one requirement per
line, ``#`` comments, ``\\`` line continuations, and option lines. Nothing in
the file is executed and environment variables are never expanded.

Files included with ``-r`` are read through the project-confined reader, so a
reference outside the project root is refused. Their requirements are merged
into the including file's result, the way pip would install them, without a
line number (the line belongs to the other file); an info diagnostic records
each included file.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Iterator
from dataclasses import dataclass, field

from dva.contracts.ecosystem import AdapterResult, ParseContext
from dva.contracts.files import FileAccessError, ProjectFileReader
from dva.domain.dependency import DeclaredRequirement
from dva.domain.diagnostics import Diagnostic, DiagnosticLevel
from dva.domain.manifest import ParseStatus
from dva.ecosystems.python.requirement import RequirementSyntaxError, parse_requirement
from dva.ecosystems.text import decode_utf8, preview

MAX_INCLUDE_DEPTH = 8
MAX_INCLUDED_FILES = 64

_COMMENT = re.compile(r"(^|\s+)#.*$")
_ENV_VAR = re.compile(r"\$\{[A-Z0-9_]+\}")
_DRIVE = re.compile(r"^[A-Za-z]:")
_ARCHIVE_SUFFIXES = (".whl", ".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".tar")

_INCLUDE = {"-r", "--requirement"}
_CONSTRAINT = {"-c", "--constraint"}
_EDITABLE = {"-e", "--editable"}
#: Options that change how pip finds or builds packages, not what is required.
_INSTALLER_OPTIONS = {
    "-i",
    "--index-url",
    "--extra-index-url",
    "--no-index",
    "-f",
    "--find-links",
    "--pre",
    "--prefer-binary",
    "--require-hashes",
    "--only-binary",
    "--no-binary",
    "--trusted-host",
    "--use-feature",
    "--config-settings",
}
_TAKES_VALUE = (
    _INCLUDE
    | _CONSTRAINT
    | _EDITABLE
    | {
        "-i",
        "--index-url",
        "--extra-index-url",
        "-f",
        "--find-links",
        "--only-binary",
        "--no-binary",
        "--trusted-host",
        "--use-feature",
        "--config-settings",
    }
)
_SHORT_WITH_VALUE = {"-r", "-c", "-e", "-i", "-f"}
#: Per-requirement options that do not change which package is required.
_HARMLESS_REQUIREMENT_OPTIONS = {"--hash"}


@dataclass
class _State:
    reader: ProjectFileReader
    requirements: list[DeclaredRequirement] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    visited: set[str] = field(default_factory=set)
    incomplete: bool = False

    def note(self, code: str, path: str, message: str) -> None:
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.INFO, message, path))

    def warn(self, code: str, path: str, message: str) -> None:
        self.incomplete = True
        self.diagnostics.append(Diagnostic(code, DiagnosticLevel.WARNING, message, path))


def parse_requirements_file(context: ParseContext) -> AdapterResult:
    text = decode_utf8(context.content)
    if text is None:
        return AdapterResult(
            status=ParseStatus.FAILED,
            diagnostics=(
                Diagnostic(
                    "python.decode_error",
                    DiagnosticLevel.ERROR,
                    "the file is not valid UTF-8 text",
                    context.path,
                ),
            ),
        )
    state = _State(reader=context.reader, visited={context.path})
    _parse_text(state, context.path, text, depth=0, stack=(context.path,))
    return AdapterResult(
        status=ParseStatus.PARTIAL if state.incomplete else ParseStatus.PARSED,
        requirements=tuple(state.requirements),
        diagnostics=tuple(state.diagnostics),
    )


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """Join continuation lines and drop comments, as pip does. Yields (line number, text)."""
    pending: list[str] = []
    first = 0
    for number, raw in enumerate(text.splitlines(), start=1):
        if raw.endswith("\\") and not _COMMENT.match(raw):
            if not pending:
                first = number
            pending.append(raw[:-1])
            continue
        if pending:
            pending.append(" " + raw if _COMMENT.match(raw) else raw)
            joined, start = "".join(pending), first
            pending = []
        else:
            joined, start = raw, number
        stripped = _COMMENT.sub("", joined).strip()
        if stripped:
            yield start, stripped
    if pending:
        stripped = _COMMENT.sub("", "".join(pending)).strip()
        if stripped:
            yield first, stripped


def _parse_text(state: _State, path: str, text: str, *, depth: int, stack: tuple[str, ...]) -> None:
    included = depth > 0
    for number, line in _logical_lines(text):
        where = f"line {number}"
        if _ENV_VAR.search(line):
            state.warn(
                "python.requirements.env_var",
                path,
                f"{where}: uses an environment variable, which DVA does not expand",
            )
        if line.startswith("-"):
            _handle_option(state, path, where, line, depth=depth, stack=stack)
            continue
        requirement_text, options = _split_options(line)
        if _looks_like_location(requirement_text):
            state.warn(
                "python.requirements.unnamed",
                path,
                f"{where}: installs from a path or URL without naming the package; not analyzed",
            )
            continue
        try:
            requirement = parse_requirement(requirement_text, line=None if included else number)
        except RequirementSyntaxError as error:
            state.warn("python.requirements.invalid_line", path, f"{where}: {error}")
            continue
        state.requirements.append(requirement)
        for option in options:
            if option.split("=", 1)[0] not in _HARMLESS_REQUIREMENT_OPTIONS:
                state.note(
                    "python.requirements.option_ignored",
                    path,
                    f"{where}: per-requirement option {preview(option.split('=', 1)[0])!r} "
                    "is not analyzed",
                )


def _split_options(line: str) -> tuple[str, list[str]]:
    """Split ``line`` into the requirement and trailing ``--option`` tokens, like pip."""
    tokens = line.split(" ")
    for index, token in enumerate(tokens):
        if token.startswith("-"):
            options = [t for t in tokens[index:] if t.startswith("-")]
            return " ".join(tokens[:index]), options
    return line, []


def _looks_like_location(text: str) -> bool:
    lowered = text.lower()
    if text.startswith((".", "/", "\\", "~")) or _DRIVE.match(text):
        return True
    if "://" in text and "@" not in text.split("://", 1)[0]:
        return True
    return lowered.endswith(_ARCHIVE_SUFFIXES)


def _handle_option(
    state: _State, path: str, where: str, line: str, *, depth: int, stack: tuple[str, ...]
) -> None:
    try:
        tokens = shlex.split(line, posix=True)
    except ValueError:
        state.warn("python.requirements.invalid_line", path, f"{where}: unbalanced quotes")
        return
    if not tokens:
        return
    name, value = _option_name_and_value(tokens)

    if name in _INCLUDE:
        if value is None:
            state.warn("python.requirements.invalid_line", path, f"{where}: -r needs a file")
        else:
            _include(state, path, where, value, depth=depth, stack=stack)
    elif name in _CONSTRAINT:
        state.note(
            "python.requirements.constraints_file",
            path,
            f"{where}: constraints files limit versions but add no requirements; not analyzed",
        )
    elif name in _EDITABLE:
        state.warn(
            "python.requirements.editable",
            path,
            f"{where}: editable installs come from a local path or repository; not analyzed",
        )
    elif name in _INSTALLER_OPTIONS:
        state.note(
            "python.requirements.option_ignored",
            path,
            f"{where}: installer option {name!r} does not declare a dependency; ignored",
        )
    else:
        state.warn(
            "python.requirements.unknown_option",
            path,
            f"{where}: unrecognized option {preview(name)!r}",
        )


def _option_name_and_value(tokens: list[str]) -> tuple[str, str | None]:
    first = tokens[0]
    if first.startswith("--") and "=" in first:
        name, value = first.split("=", 1)
        return name, value
    if not first.startswith("--") and len(first) > 2 and first[:2] in _SHORT_WITH_VALUE:
        return first[:2], first[2:]
    if first in _TAKES_VALUE:
        return first, tokens[1] if len(tokens) > 1 else None
    return first, None


def _include(
    state: _State, path: str, where: str, reference: str, *, depth: int, stack: tuple[str, ...]
) -> None:
    if "://" in reference:
        state.warn(
            "python.requirements.include_url",
            path,
            f"{where}: includes a file from a URL; DVA never downloads it",
        )
        return
    target = _resolve(path, reference)
    if target is None:
        state.warn(
            "python.requirements.include_outside_root",
            path,
            f"{where}: includes a file outside the project; not read",
        )
        return
    if target in stack:
        state.warn("python.requirements.include_cycle", path, f"{where}: include cycle")
        return
    if target in state.visited:
        state.note(
            "python.requirements.include_repeated",
            path,
            f"{where}: {target} was already included",
        )
        return
    if depth + 1 > MAX_INCLUDE_DEPTH or len(state.visited) >= MAX_INCLUDED_FILES:
        state.warn(
            "python.requirements.include_limit",
            path,
            f"{where}: too many nested or included files; stopped following includes",
        )
        return
    state.visited.add(target)
    try:
        content = state.reader.read(target)
    except FileAccessError as error:
        state.warn("python.requirements.include_unreadable", path, f"{where}: {error}")
        return
    text = decode_utf8(content)
    if text is None:
        state.warn(
            "python.requirements.include_unreadable",
            path,
            f"{where}: included file is not valid UTF-8 text",
        )
        return
    state.note("python.requirements.included", target, f"included from {path}")
    _parse_text(state, target, text, depth=depth + 1, stack=(*stack, target))


def _resolve(current: str, reference: str) -> str | None:
    """Project-relative path for ``reference`` seen in ``current``, or ``None`` if it escapes."""
    reference = reference.replace("\\", "/")
    if not reference or reference.startswith("/") or ":" in reference or "\x00" in reference:
        return None
    joined = posixpath.normpath(posixpath.join(posixpath.dirname(current), reference))
    if joined == ".." or joined.startswith("../") or joined == ".":
        return None
    return joined
