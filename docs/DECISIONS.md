# Design decisions

This page records the main choices behind DVA and the reasoning for them. A
decision can be revisited when the situation changes, and if one is replaced,
the new decision is added here.

## 1. Never run code from the scanned project

DVA works out dependencies only by reading files: manifests and lockfiles. It
doesn't call `pip`, `npm` or a build tool, even though doing so would often
produce a more complete dependency tree.

Package managers can run code from the project or its dependencies (install
scripts, build backends, lifecycle hooks), and one of DVA's uses is looking at
projects you don't fully trust yet. The cost is that some projects will only
get a partial dependency graph, so DVA labels those results as partial.

## 2. Everything runs locally

There is no server, account or cloud database. The only network traffic is
vulnerability lookups, which send a package name, ecosystem and version.

This keeps your project information on your machine and means there's nothing
to host. It also means DVA has to cope with being offline, which is why
advisories are cached and their age is always shown.

## 3. One Python package, split into layers

DVA is a single Python application with separate layers for the data model,
the use cases, ecosystem adapters, vulnerability sources, storage and output.
Python has good libraries for every format DVA needs to read, and a single
package is easy to install and test. The layering lets the CLI and a possible
desktop app share the same engine.

## 4. OSV as the first vulnerability source

OSV covers both Python and npm, is free to use, and has a documented batch
API. Starting with one source avoids having to merge and de-duplicate
advisories from several databases. The code that talks to OSV is kept separate
from the rest of the engine, so another source can be added later if it brings
better data.

## 5. SQLite for local data

Projects, scan history and the advisory cache are stored in a single SQLite
file. It needs no server, ships with Python, and is more than enough for one
user. Syncing between machines isn't planned.

DVA talks to it with the standard library's `sqlite3` module and plain SQL,
not an ORM such as SQLAlchemy. The database has only a few tables, there is
one user and one database engine, and keeping the queries visible as plain SQL
makes them easy to review. Schema changes are small numbered SQL scripts that
DVA applies itself, which needs no migration tool and no extra dependency. If
DVA ever needed a server database, this would be worth revisiting.

## 6. As few runtime dependencies as possible

DVA started out with only the standard library: `argparse` for the CLI,
`dataclasses` for the data model, `json` and `tomllib` for reading and writing
data. Each dependency is something to install, update and trust, which matters
for a security tool. A library gets added only when there's a concrete need.

The first one is [`packaging`](https://packaging.pypa.io/), maintained by the
Python Packaging Authority. It is the reference implementation of the
standards for Python requirement strings and version numbers, has no
dependencies of its own, and is what pip itself uses. Writing our own parser
for those grammars would be easy to get subtly wrong, and the same library
will be needed for comparing Python versions against advisories.

For development, the project uses uv with a lockfile, Ruff for linting and
formatting, mypy in strict mode, and pytest. CI runs on Windows and Ubuntu with
Python 3.12 and 3.15.

## 7. Immutable data model built from dataclasses

Packages, dependencies and scan results are frozen dataclasses. A scan result
is a snapshot that shouldn't change once it's made, and making the objects
immutable enforces that. Input from outside, such as file contents and API
responses, is checked when it is turned into these objects, so the rest of the
code can rely on them being valid.

## 8. The engine reads files; adapters only parse

Ecosystem adapters don't open files themselves. The engine finds the
dependency files, reads them with a size limit, and passes the contents to
the adapter. When an adapter needs another file (for example an included
requirements file), it asks the engine, which refuses anything outside the
project folder, symlinks, Windows junctions, and oversized files.

With this split, the protections against path tricks are written and tested
once, instead of being repeated in every adapter, where one mistake would be
enough to break them. It also keeps adapters simple to test: give them bytes,
check what comes back.

## 9. A standalone HTML graph instead of a desktop app

The first release draws the dependency graph as a single HTML file with its
JavaScript bundled inside. It opens in any browser, works offline, and avoids
building a GUI before the engine is finished.

## 10. Apache License 2.0

DVA uses the Apache 2.0 license, a permissive license with an explicit patent
grant. Any third-party code bundled with DVA, such as a graph library, has to
use a compatible license, and its notice is included.

## 11. Look up packages by name and match versions locally

DVA asks OSV which advisories exist for a package by ecosystem and name, and
then decides on its own machine whether the installed version is affected.
It could instead send each version and let OSV decide, but that tells the
service more about the project, and the answer couldn't be reused for other
versions or offline. Matching locally needs correct version rules for each
ecosystem, which DVA has to have anyway, and the tests check them at the
edges of real advisories' ranges.

The HTTP client is the standard library's `urllib`, with timeouts, HTTPS only,
no redirects, a response-size limit and a few retries, so no extra dependency
is needed for the handful of requests a scan makes.
