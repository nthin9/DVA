# Limitations

What DVA doesn't do yet, or can't do by design, gathered in one place.
Where a release is planned to change something, it is named; the
[Roadmap](ROADMAP.md) has the details. Items without a release are limits by
design.

## What a scan can and can't tell you

- A scan reports what it found, what it couldn't check, and how old its data
  is. It never says a project is safe. "No matching advisory" means OSV had
  nothing matching that version when it was asked.
- Vulnerability databases are never complete, and new advisories can take time
  to appear.
- A package version inside an affected range doesn't mean the vulnerable code
  is actually used by your project. DVA doesn't analyse code.
- "Upgrade to" suggestions only consider the advisories OSV returned at scan
  time and the fixed versions they name. DVA doesn't check that the version
  works with the rest of your dependencies, because it doesn't resolve them.
- "Pulled in by" needs a lockfile. Without one, DVA only knows where a
  package was declared.
- DVA reads dependency files without running anything, so it can miss
  dependencies that are only decided at install time or depend on the
  environment. See the [Threat model](THREAT_MODEL.md#known-limits).

## Ecosystems and files

- Only Python and npm projects are supported. Java (Maven and Gradle)
  comes in v1.1; the next ecosystem is chosen after that.
- Recognised but not read: `Pipfile.lock`, `pylock.toml`, `yarn.lock`,
  `pnpm-lock.yaml` and `bun.lock` (all read from v0.3), plus `Pipfile`,
  `setup.cfg`, `bun.lockb` and npm lockfiles older than version 2, which stay
  unread. `setup.py` is never read, because it is a program. These files are
  listed in the results as unsupported. See
  [Supported formats](SUPPORTED_FORMATS.md).
- A requirement that only gives a version range is listed as not checked,
  unless a lockfile or a pip constraints file pins it to one version.
- Packages installed from git, a URL or a local path aren't looked up.
- Packages from a private registry or a mirror aren't looked up unless you
  pass `--include-private-registries`. Registries configured outside the
  dependency files (`pip.conf`, `.npmrc`, PDM and uv settings) and
  `--extra-index-url` aren't detected yet, so those packages are treated as
  coming from the public registry; v0.2 reads these settings. See
  [Supported formats](SUPPORTED_FORMATS.md#packages-from-other-registries).
- Optional dependencies and platform conditions are kept as the files record
  them; DVA doesn't yet work out which ones apply to a given Python version
  or operating system (v0.2). Monorepo results aren't grouped per workspace
  member yet (v0.2).

## Vulnerability data

- OSV is the only source. Every online scan asks it for the current advisory
  list. Offline scans only know what earlier online scans cached; downloading
  OSV's full data for offline use comes in v0.4.
- Cached advisory data is used offline and when OSV can't be reached, and its
  age is always shown, but it never expires on its own. v0.1 adds a warning
  for old data and `--max-age`. `dva cache clear` deletes it.

## History and reports

- Comparisons are between two scans of one project. `dva search` is the only
  query across projects, and it looks at each project's latest scan only.
  A dashboard across projects is part of the v3.0 desktop application.
- `dva compare` doesn't show findings that became accepted risks between two
  scans yet (v0.1).
- History is never pruned automatically; use `dva history NAME --prune`.
- An HTML report rebuilt from history uses the current version of DVA's
  report page, so it may look different from the one produced at the time.
- The local database isn't encrypted. It holds your project folders' paths,
  package names and scan results, and stays in your user data folder.

## Platforms and installation

- Windows is the main target and Linux is tested in CI. macOS isn't tested
  yet; it is added to CI for v1.0.
- DVA needs Python 3.12 or newer and is installed with `uv` or `pipx`.
  Releases before v1.0 are published on GitHub only; whether v1.0 goes to
  PyPI is decided at that release. A standalone Windows installer that
  doesn't need Python arrives with the v2.0 desktop front end.
