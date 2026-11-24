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
  including file's results, the way pip would install them. Each keeps the
  path and line number of the file it is written in. Included files have to
  be inside the project: references outside it, to a URL, in a loop, or
  nested more than 8 deep are reported and not followed.
- `-c constraints.txt` / `--constraint constraints.txt`, read with the same
  rules. A constraints file adds no requirements, but when it pins a package
  to one exact version (`name==1.2.3`) and the requirement only gives a range,
  that version is what pip installs, so it is the version DVA checks. A pin
  the requirement doesn't allow, or two different pins for one package, is
  reported and not used.
- `--index-url` / `-i`. If it points anywhere other than PyPI, the file's
  requirements are marked as coming from another registry (see
  [below](#packages-from-other-registries)).
- `--hash` options are accepted. Requirements that name a URL
  (`name @ https://...`) are kept, marked with where they come from.

Reported as not analyzed, which marks the file as partially read:

- editable installs (`-e`), and lines that point at a path, archive or URL
  without naming the package;
- environment variables such as `${TOKEN}`, which DVA never expands;
- options it doesn't recognise.

Noted but harmless: other installer options, such as `--extra-index-url`.
Option values are never copied into the results, because they can contain
credentials.

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
- Poetry's `[tool.poetry.dependencies]`, `[tool.poetry.group.<name>.dependencies]`
  (labelled `group:<name>`) and the older `[tool.poetry.dev-dependencies]`
  (labelled `group:dev`). Poetry's own version syntax is translated to the
  standard form: `^1.2.3` becomes `>=1.2.3,<2.0.0`, `~1.2.3` becomes
  `>=1.2.3,<1.3.0`, and a bare `1.2.3` means exactly that version. A `python`
  condition becomes a `python_version` marker. Optional dependencies are
  labelled with the extras that install them. Dependencies from git, a path
  or a URL are marked as such, with credentials removed. A constraint with
  alternatives (`1.0 || 2.0`) has no standard form, so it is kept without a
  version and reported. With Poetry 2, `[tool.poetry.dependencies]` only adds
  details to packages already listed in `[project]`, so those aren't counted
  twice.

Reported as not analyzed:

- dependencies listed in `dynamic`, which only the build backend can work
  out, and DVA doesn't run it;
- other tool-specific tables: PDM's `dev-dependencies`, and uv's older
  `dev-dependencies`.

A `pyproject.toml` that only configures tools, with no dependency tables, is
read successfully and simply has no requirements.

**`uv.lock`** (lockfile version 1)

- Every locked package with its exact version and where it comes from
  (PyPI or another registry, git, a URL, a local path, or the workspace).
- The full dependency graph. The project's own entry isn't listed as a
  package; its dependencies become the direct dependencies, so you can see
  which packages you asked for and which arrived through them. If the
  project's entry can't be found, that is reported.
- Workspaces: when the root isn't a project itself, the members listed in
  `[manifest]` are treated as the project.
- Platform conditions on each link (`sys_platform == 'win32'`), and the group
  each direct dependency comes from (`optional:<extra>`, `group:<name>`).
  Each package is labelled with the groups that pull it in; a package needed
  by the main dependencies has no label, because it is always installed.
- When the same package is locked at more than one version, each link is
  matched to the right one using the version and source uv records. Links
  that can't be matched are reported.

Other lockfile versions are reported as unsupported. Registry URLs and file
hashes are not copied into the results.

**`poetry.lock`** (lock-version 2.0 and 2.1)

- Every locked package with its exact version and source, and the links
  between packages, including each link's version range and conditions.
- Optional dependencies are labelled with the extra that installs them.
- Lock-version 2.1 records which dependency groups a package belongs to
  (`main`, `dev` and so on); these are kept as `group:<name>` labels.
- When a package is locked more than once, the right one is picked by
  checking the link's version range using Python's version rules (PEP 440).
  If that still leaves more than one, the link is reported, not guessed.

A `poetry.lock` doesn't record which packages the project asked for directly,
so the graph from this file alone has no direct dependencies; the results say
so. Lock-version 2.1's per-package conditions (`markers`) are kept on each
package; when they differ per group they are combined with `or`. Older
lock-versions (1.x) are reported as unsupported.

### Recognised, not read

| File | Status |
|---|---|
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

npm covers JavaScript and TypeScript projects alike; they share one package
ecosystem.

### Read

**`package.json`**

- `dependencies`, `devDependencies` (labelled `dev`), `optionalDependencies`
  (`optional`) and `peerDependencies` (`peer`, plus `optional` when
  `peerDependenciesMeta` marks the peer optional). Packages listed in
  `bundleDependencies` are also labelled `bundled`.
- As npm does, an entry in `optionalDependencies` replaces one of the same
  name in `dependencies`.
- Every version spec is kept as written and tagged with where it installs
  from: version ranges and tags (`^1.2.0`, `latest`) from the registry;
  aliases (`npm:lodash@^4`) are recorded as the real package, with the name
  they're installed under kept as the alias; git repositories (`git+https://`,
  `github:user/repo`, `user/repo`); tarball URLs; local paths (`file:`,
  `link:`); and the `workspace:` protocol. Passwords and tokens in URLs are
  removed.
- `workspaces`, `overrides` and `resolutions` are noted. Each workspace
  member has its own `package.json`, which is scanned separately.

Reported as problems: invalid package names, specs that aren't strings, and
keys that appear twice in the same object (npm uses the last one, and so does
DVA, but the file is marked as partially read).

**`package-lock.json`** and **`npm-shrinkwrap.json`** (lockfile versions 2 and 3)

- Every installed package from the `packages` section, keyed by the folder
  it's installed in. The same package at two versions is two separate
  entries.
- Exact versions, where each package comes from (registry, git, URL or local
  path), and npm's `dev`, `optional` and `peer` flags as labels.
- The full dependency graph. Links are worked out the way Node.js finds a
  module: from the depending package's folder, look in its `node_modules`,
  then in each parent folder's, up to the project root. Linked folders are
  followed.
- The project itself and its workspace members aren't listed as packages.
  Their dependencies are the project's direct dependencies. Only the
  project's own `devDependencies` count, as with npm.
- A dependency that isn't in the lockfile is reported. Missing optional
  dependencies and optional peers are only noted, since leaving them out is
  normal.

Version 1 lockfiles, from npm 6 and older, use a different layout and are
reported as unsupported. Registry URLs and integrity hashes are not copied
into the results.

### Recognised, not read

| File | Status |
|---|---|
| `yarn.lock` | Not supported |
| `pnpm-lock.yaml` | Not supported |
| `bun.lock`, `bun.lockb` | Not supported |

Folders named `node_modules` are never scanned: they hold installed copies of
packages, and the lockfile already describes them.

## Packages from other registries

Most packages come from the ecosystem's public registry: PyPI, or the npm
registry (`registry.npmjs.org`, also served as `registry.yarnpkg.com`). DVA
marks packages from anywhere else, such as a company's private registry or a
mirror, with the source `other_registry`. It recognises them in:

- `package-lock.json` and `npm-shrinkwrap.json`: a tarball from another host;
- `uv.lock`: a `registry` source that isn't PyPI;
- `poetry.lock`: a `legacy` source whose URL isn't PyPI;
- `pyproject.toml`: a Poetry dependency that names a `[[tool.poetry.source]]`
  that isn't PyPI, and every package when the project's primary Poetry source
  isn't PyPI (which makes Poetry stop using PyPI);
- requirements files: a `--index-url` that isn't PyPI.

The names of such packages may be private, so by default they are not looked
up in OSV and are listed as not checked, with that reason.
`--include-private-registries` looks them up as well. Only the package's name
and ecosystem are sent, as for any other package. Not detected yet: indexes
configured outside these files (in `pip.conf`, `.npmrc`, or the PDM and uv
settings in `pyproject.toml`), and `--extra-index-url`, which mixes PyPI with another index.
