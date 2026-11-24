# Architecture

DVA is a single Python package. It isn't split into services, because it's a
local tool with one user at a time and a split would add moving parts without
buying anything. The code is still divided into layers with clear jobs, so the
CLI, a possible future desktop app, and the tests all drive the same engine.

```text
   CLI (now)            Desktop app (maybe, later)
       |                          |
       +------------+-------------+
                    |
           Application layer
   scan, register, rescan, compare, refresh
                    |
             Core domain model
   packages, dependencies, scans, diagnostics
                    |
     +--------------+---------------+
     |              |               |
 Ecosystem      Vulnerability     Storage
 adapters       sources           (SQLite)
 (Python, npm)  (OSV)
     |              |               |
     +--------------+---------------+
                    |
                 Output
       terminal, JSON, HTML graph
```

## Code layout

The folders marked "built" exist today. The others are planned and get added
when the work that needs them starts:

```text
src/dva/
  cli.py          command-line interface, presentation only        (built)
  domain/         the data model: packages, dependencies, scans,   (built)
                  diagnostics, and stable JSON serialization
  application/    use cases such as "analyze this project"         (built)
  contracts/      the interfaces adapters implement                (built)
  discovery/      finding and safely reading project files         (built)
  ecosystems/     the adapter registry and one adapter per         (built)
                  ecosystem: python/ (built), npm/ to come
  intelligence/   vulnerability sources; osv/ is the first
  matching/       checking whether a version falls in an affected range
  storage/        SQLite persistence
  reporting/      JSON report and the HTML graph
```

The engine runs end to end today. The Python adapter reads `requirements.txt`
files and `pyproject.toml`; the files it recognises but can't read yet, such
as lockfiles, are listed in the results as unsupported. The exact list is in
[Supported formats](SUPPORTED_FORMATS.md). The tests also use a small made-up
format to show that any adapter works with the engine.

## How a scan works

1. Check the project folder and set limits on how much DVA will read.
2. Walk the folder looking for dependency files. Folders like `node_modules`,
   `.git` and virtual environments are skipped, and so are symlinks.
3. Hand each file to the adapter that knows its format.
4. The adapter parses the file and returns packages, versions and dependency
   relationships, plus notes about anything it couldn't handle.
5. Look up the exact resolved versions in the vulnerability source.
6. Check each advisory's affected ranges against the package versions.
7. Save the scan and the cached advisory data.
8. Produce the terminal summary, the JSON report and the HTML graph from the
   same result.

A manifest such as `package.json` only lists your direct dependencies, so DVA
only shows a full dependency tree when a lockfile provides one. It doesn't
guess the rest.

## Ecosystem adapters

Each ecosystem has its own adapter. An adapter declares which file names it
handles (for example `package.json` or `requirements*.txt`), which versions of
those formats it supports, and which formats it recognises but can't parse yet.
That last part matters: if DVA finds a `poetry.lock` it can't read, it says so
instead of quietly ignoring it.

Adapters only parse. They are given the file contents and return data. They
don't open files on their own, run package managers, or execute anything from
the project. If an adapter needs to follow a reference to another file (as
`requirements.txt` can with `-r other.txt`), it asks the core for that file,
and the core refuses paths that point outside the project.

Adapters are listed explicitly in a registry inside DVA. There's no plugin
system that loads code from elsewhere. The registry refuses two adapters with
the same ID or the same file pattern, and if a file still matches more than
one adapter, discovery skips it and says why instead of picking one.

When an adapter fails, the damage stays with that one file. If it crashes or
returns data that doesn't hold together (say, a dependency pointing at a
package that isn't in the file), that file is marked as failed with a note
and the rest of the scan carries on. The note gives only the error type,
because an error message could repeat file contents or local paths.

## Limits

Every scan has limits, all adjustable: how many folder levels deep to look
(16 by default), how many folder entries to examine (100,000), how many
dependency files to accept (1,000), and the largest file to read (32 MiB).
Hitting any of them is recorded in the result, and the scan is marked partial.

## Data model

The model keeps a few distinctions that are easy to lose:

- **What was declared versus what was installed.** `requests>=2.0` in a
  manifest and `requests 2.31.0` in a lockfile are stored as different things.
- **Direct versus transitive.** A dependency you listed yourself is kept
  separate from one that arrived through another package, and the chain between
  them is kept when the lockfile records it.
- **Same name, different versions.** A project can contain the same package at
  more than one version, so graph nodes aren't identified by name alone.
- **Where each piece of data came from.** Every result records which file it
  was read from and how well that file was understood.
- **Where a dependency is installed from.** Each requirement and package says
  whether it comes from a package registry, a git repository, a URL, a local
  path, or the project's own workspace. Only registry packages have release
  versions that a vulnerability database can be asked about.
- **The details that change what gets installed.** Requirements keep any
  extras they ask for (`requests[socks]`), any alias they're installed under,
  and their platform conditions. A dependency link between two packages can
  carry its own conditions and groups, because some lockfiles record them per
  link rather than per package.

Packages also get a [Package URL](https://github.com/package-url/purl-spec)
(PURL) where the ecosystem has one, while the original name and version are
kept as written.

Every scan ends with a clear overall state: complete, partial, failed, or no
supported files found. "Complete" is only used when every file was fully
understood and nothing was skipped.

## Versions and vulnerability matching

Version numbers are never compared as plain text, since that would put `1.10`
before `1.9`. Each ecosystem has its own version rules (Python's PEP 440 and
npm's semver differ in several ways), so matching is written and tested per
ecosystem. When DVA meets a version or range format it doesn't understand, it
reports the result as unknown instead of guessing.

Not every advisory has a CVE number, so CVE is stored as one of an advisory's
aliases when it's present. Severity is shown together with the scoring system
it came from, and is left empty when the advisory doesn't give one.

## OSV

OSV is the first vulnerability source. Its batch API returns only advisory IDs
for a list of package versions, so DVA then fetches the full records it needs
and caches them locally with the time they were retrieved.

If OSV can't be reached, DVA uses the cached data and says how old it is. A
failed lookup is never reported as "no vulnerabilities".

API reference: <https://github.com/google/osv.dev/blob/master/docs/api/post-v1-querybatch.md>

## Storage

Registered projects, scan history and cached advisories go in a SQLite file in
the user's application data folder, not inside the scanned project. Each scan
is stored as a snapshot that isn't changed afterwards, so earlier scans can be
compared with new ones. Whether to use plain `sqlite3` with numbered migration
scripts or SQLAlchemy with Alembic will be decided when storage is built.

## Reports and the dependency graph

Reports are built from the finished scan result and do no analysis of their
own. The HTML graph will use an existing graph library (Cytoscape.js is the
current candidate) bundled into the file, so it opens offline without loading
anything from the internet. Package names and advisory text come from outside
sources, so they are escaped before being put into HTML and are passed to the
page as data, never as code.

## A desktop app later

A GUI isn't part of the first release. If one is built, it will call the same
application layer as the CLI, and the choice of UI toolkit will be made then.
