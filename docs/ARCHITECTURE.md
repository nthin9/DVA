# Architecture

DVA is a single Python package. It isn't split into services, because it's a
local tool with one user at a time and a split would add moving parts without
buying anything. The code is still divided into layers with clear jobs, so the
CLI, the planned desktop app, and the tests all drive the same engine.

```text
   CLI (now)            Desktop app (planned)
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
                  ecosystem: python/ and npm/
  intelligence/   vulnerability sources; osv/ is the first, plus a (built)
                  small HTTPS client
  matching/       checking whether a version falls in an affected  (built)
                  range, with each ecosystem's version rules
  storage/        SQLite persistence: the advisory cache, projects (built)
                  and saved scans
  reporting/      terminal summary, JSON report and HTML report   (built)
```

The engine runs end to end today. The Python adapter reads `requirements.txt`
files, `pyproject.toml`, `uv.lock` and `poetry.lock`, and the npm adapter reads
`package.json`, `package-lock.json` and `npm-shrinkwrap.json`. Files they
recognise but can't read, such as `Pipfile.lock` or `yarn.lock`, are listed in
the results as unsupported. The exact list is in
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

Python versions follow PEP 440, using the `packaging` library. npm versions
follow Semantic Versioning 2.0.0, which DVA implements itself in a few dozen
lines: only exact versions need comparing, because DVA checks the versions a
project actually installs, not the ranges it asks for.

Whether a version is affected follows the OSV format's rules. It is affected
if the advisory lists it explicitly, or if it falls inside an affected range.
A range is read as a sorted list of events: `introduced` starts an affected
stretch (`0` means from the first version), `fixed` ends it at that version,
and `last_affected` ends it just after. Ranges given as git commits can't be
mapped to an installed version, so on their own they give an "unknown"
answer. One range that clearly matches is enough for a positive result. If no
range matches but one of them couldn't be read, the answer is "unknown"
rather than "not affected".

Not every advisory has a CVE number, so CVE is stored as one of an advisory's
aliases when it's present. Severity is shown together with the scoring system
it came from, and is left empty when the advisory doesn't give one. A
database's own rating label (such as GitHub's "moderate") is kept separately
from scored severities, because it isn't a standard scale. Fixed versions are
only shown when the advisory gives them.

Advisories from the network are checked before use. A record whose affected
ranges are malformed is rejected as a whole, because quietly dropping one
range could hide a real vulnerability. Problems in display-only parts, such as
a reference link that isn't an `http(s)` URL, only drop that part.

## OSV

OSV is the first vulnerability source. DVA asks its batch API which advisories
exist for each package, by ecosystem and name only, without a version. The
answer lists advisory IDs with the time each record was last changed. DVA
then downloads only the records that are new or have changed since it cached
them, and checks each installed version against them locally. Asking by name
sends OSV less about the project, and it means the cache holds every advisory
for a package, so any version of it can be checked offline later.

The versions checked are the exact ones a lockfile records, plus requirements
pinned to a single version (`requests==2.31.0`). A requirement that only gives
a range (`requests>=2`) can't be checked honestly and is listed as not
checked, unless a lockfile in the same project pins that package anyway, or
a pip constraints file pins it to one version. Packages from git, URLs or
local paths aren't looked up and are listed with the reason. Neither are
packages from a registry other than the ecosystem's public one, unless the
user allows it, because their names may be private.

When an advisory gives a severity score for one affected package rather than
for the whole advisory, that score is kept on the finding for that package
and shown as applying to it.

Every package gets one of five outcomes: affected, no matching advisory,
unknown (advisories exist but DVA couldn't decide for this version), not
checked (with the reason), or lookup failed. "No matching advisory" means OSV
had nothing matching that version when it was asked; it isn't a claim that
the package is safe.

If OSV can't be reached, or DVA is told to work offline, it uses the cached
data and records how old it is. If an updated record can't be downloaded, the
older cached copy is used and the result says so. A failed lookup is never
reported as "no vulnerabilities": a package with no cached data at all is
marked as a failed lookup. `dva cache info` shows how much is cached and how
old it is, and `dva cache clear` deletes it; saved scans are kept.

API reference: <https://github.com/google/osv.dev/blob/master/docs/api/post-v1-querybatch.md>

## Storage

Registered projects, scan history and cached advisories go in a SQLite file in
the user's application data folder, not inside the scanned project. Each scan
is stored as a snapshot that isn't changed afterwards, so earlier scans can be
compared with new ones.

The database uses Python's built-in `sqlite3` module and plain SQL. Its schema
is built by numbered migration scripts in `storage/migrations/`, each applied
once inside a transaction and recorded in the database. A database written by
a newer version of DVA is refused rather than opened. The folder is
`%LOCALAPPDATA%\DVA` on Windows, `~/Library/Application Support/DVA` on macOS,
and `~/.local/share/dva` elsewhere; setting `DVA_DATA_DIR` overrides it.

The cache keeps advisory records as the raw text OSV returned and checks them
again every time they're read, so a damaged or edited cache file can't slip
bad data into a scan.

Registered projects keep a name and the absolute folder path. A saved scan
keeps its full JSON report and, in separate tables, the package versions it
found, the status of each and the advisories that affected them. Those rows
are what two scans are compared on, so a comparison is a few SQL reads rather
than parsing two reports. Scans are only ever added; removing a project
deletes its scans with it, and pruning deletes a project's oldest scans whole.
A saved JSON report can be read back into a scan result
(`domain/deserialization.py`), which validates every value, so an old scan's
HTML report can be rebuilt. Rows read back are turned into domain objects,
which validate them, so a damaged or edited database gives an error rather
than a wrong comparison.

The application layer talks to this through a small history interface in
`contracts/`, so a future desktop app can use the same code. Comparing two
scans is a pure function of their saved data in `application/history.py`.
It never treats a finding that the newer scan couldn't check as resolved.
How comparisons are worded for users is described in
[Projects and scan history](HISTORY.md).

## Reports and the dependency graph

Reports are built from the finished scan result and do no analysis of their
own. All three formats use the same counts, so they always agree.

Databases often publish the same vulnerability under their own IDs (a GitHub
`GHSA-` advisory and a PyPI `PYSEC-` one) and list each other as aliases. The
terminal summary and the HTML report show such copies once, under the most
informative record, with the others listed as "also published as". The JSON
report keeps every record.

- The **terminal summary** lists affected packages with their advisories,
  then everything that couldn't be checked, and ends with the overall result
  and a reminder that "no matching advisory" isn't proof of safety. Text that
  came from a scanned file or an advisory has control characters removed, so
  it can't send escape codes to the terminal or hide text with
  right-to-left overrides.
- The **JSON report** is the full scan result in a versioned format,
  described in [Report format](REPORT_FORMAT.md).
- The **HTML report** is one file with its stylesheet, script and data inside,
  so it opens offline. It shows summary cards, an interactive dependency
  graph (one tree per lockfile; a manifest gets its own one-level tree only
  when there's no lockfile next to it), each affected package with its
  advisories, the packages that couldn't be checked, and the files found.

The graph uses [Cytoscape.js](https://js.cytoscape.org/) (MIT License),
vendored in `src/dva/reporting/assets/` together with its license and a note
of where it came from: the exact npm release, checked against the registry's
integrity value. A test checks the file's hash, so it can't change unnoticed.

Package names and advisory text come from outside sources, so the page never
treats them as HTML. The scan data is embedded as JSON with `<`, `>` and `&`
escaped, so nothing in it can close its script element, and the page script
only ever inserts text with `textContent`. Links are only created for
`http(s)` URLs. A Content Security Policy allows exactly the page's own two
inline scripts (by their SHA-256 hashes) and no network requests at all.

## A desktop app later

A GUI isn't part of the first release, but it is the next major step after it
(see the [Roadmap](ROADMAP.md)): a standalone desktop application that
becomes the main way to use DVA, with the CLI kept for scripts and CI. It
will call the same application layer as the CLI, so scanning, matching,
history and comparison aren't written twice. The UI toolkit and the way it is
packaged will be chosen when that work starts.
