# Limitations

What DVA doesn't do yet, or can't do by design, gathered in one place. Each
item is described in more detail in the page it links to.

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

- Only Python and npm projects are supported. Maven, Gradle and other
  ecosystems are planned (see the [Roadmap](ROADMAP.md)).
- Recognised but not read: `Pipfile`, `Pipfile.lock`, `pylock.toml`,
  `setup.cfg`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` and npm lockfiles
  older than version 2. `setup.py` is never read, because it is a program.
  These files are listed in the results as unsupported. See
  [Supported formats](SUPPORTED_FORMATS.md).
- A requirement that only gives a version range is listed as not checked,
  unless a lockfile or a pip constraints file pins it to one version.
- Packages installed from git, a URL or a local path aren't looked up.
- Packages from a private registry or a mirror aren't looked up unless you
  pass `--include-private-registries`. Registries configured outside the
  dependency files (`pip.conf`, `.npmrc`, PDM and uv settings) and
  `--extra-index-url` aren't detected, so those packages are treated as coming
  from the public registry. See
  [Supported formats](SUPPORTED_FORMATS.md#packages-from-other-registries).
- Monorepos, optional dependencies and platform conditions are kept as the
  files record them; DVA doesn't work out which ones apply to your machine.

## Vulnerability data

- OSV is the only source. Every online scan asks it for the current advisory
  list; there is no bulk download for fully offline use yet.
- Cached advisory data is used offline and when OSV can't be reached, and its
  age is always shown, but the cache never expires on its own. `dva cache
  clear` deletes it.

## History and reports

- Comparisons are between two scans of one project. `dva search` is the only
  query across projects, and it looks at each project's latest scan only.
- History is never pruned automatically; use `dva history NAME --prune`.
- An HTML report rebuilt from history uses the current version of DVA's
  report page, so it may look different from the one produced at the time.
- The local database isn't encrypted. It holds your project folders' paths,
  package names and scan results, and stays in your user data folder.

## Platforms and installation

- Windows is the main target; Linux is tested in CI; macOS should work but
  isn't tested.
- DVA needs Python 3.12 or newer and is installed with `uv` or `pipx`. It
  isn't on PyPI yet, and there is no standalone installer: a desktop app with
  its own installer is planned after the first release.
