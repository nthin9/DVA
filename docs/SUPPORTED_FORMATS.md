# Supported formats

This page lists every dependency file DVA looks for, and how well it
understands each one. A file that DVA recognises but can't read is still
listed in the scan results as unsupported, so it never disappears silently.

## Python

### Read

**`requirements*.txt`** (for example `requirements.txt`, `requirements-dev.txt`)

DVA follows the syntax pip documents for requirements files.

- Requirement lines in the standard format: name, extras, version range and
  platform conditions, such as `requests[socks]>=2.31; python_version >= "3.10"`.
- Comments, blank lines, `\` line continuations, and Windows or Unix line
  endings.
- `-r other.txt` / `--requirement other.txt`. The included file is read
  relative to the including one, and its requirements are added to the
  including file's results, the way pip would install them. Included files
  have to be inside the project: references outside it, to a URL, in a loop,
  or nested more than 8 deep are reported and not followed.
- `--hash` options are accepted. Requirements that name a URL
  (`name @ https://...`) are kept, marked with where they come from.

Reported as not analyzed, which marks the file as partially read:

- editable installs (`-e`), and lines that point at a path, archive or URL
  without naming the package;
- environment variables such as `${TOKEN}`, which DVA never expands;
- options it doesn't recognise.

Noted but harmless: constraints files (`-c`), which limit versions but don't
add requirements, and installer options such as `--index-url`. Their values
are not copied into the results, because they can contain credentials.

**`pyproject.toml`**

- `[project] dependencies` and `[project.optional-dependencies]`, following
  the standard project metadata format (PEP 621). Optional dependencies are
  labelled with their extra, for example `optional:socks`.
- `[dependency-groups]` (PEP 735), including `include-group`. A requirement
  is labelled with every group that ends up installing it, so a test
  dependency included by a `dev` group carries both `group:test` and
  `group:dev`.
- A requirement on the project itself, such as `myproject[socks]`, is marked
  as a workspace dependency rather than a package from PyPI.

Reported as not analyzed:

- dependencies listed in `dynamic`, which only the build backend can work
  out, and DVA doesn't run it;
- tool-specific tables: Poetry's `[tool.poetry]` dependencies and groups,
  PDM's `dev-dependencies`, and uv's older `dev-dependencies`.

A `pyproject.toml` that only configures tools, with no dependency tables, is
read successfully and simply has no requirements.

### Recognised, not read yet

| File | Status |
|---|---|
| `uv.lock` | Planned next |
| `poetry.lock` | Planned next |
| `Pipfile`, `Pipfile.lock` | Not supported |
| `pylock.toml`, `pylock.*.toml` | Not supported |
| `setup.py` | Never read: it's a program, and reading its dependencies would mean running it |
| `setup.cfg` | Not supported |

### Names and versions

Package names are normalized the way PyPI does it (lowercase, with runs of
`-`, `_` and `.` turned into a single `-`), and each package gets a
`pkg:pypi/...` Package URL. Version ranges and conditions are kept exactly as
written in the file.

## npm

Planned next: `package.json`, and `package-lock.json` / `npm-shrinkwrap.json`
lockfile versions 2 and 3.
