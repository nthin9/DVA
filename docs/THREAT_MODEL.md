# Threat model

DVA reads files from projects that may have been written by someone else, and
it uses data from an external vulnerability service. Both are treated as
untrusted. This document lists what DVA protects, where the trust boundaries
are, and how each risk is handled.

## What needs protecting

- The source code and dependency files of the project being scanned.
- The list of projects you've registered and where they live on disk.
- Your scan history and the local advisory cache.
- The reports and HTML graphs DVA produces.
- Credentials on your machine, such as Git or GitHub tokens. DVA has no reason
  to read these, and it doesn't.

## Trust boundaries

1. **Scanned project files.** These might be malformed by accident or crafted
   on purpose to break the parser.
2. **Responses from OSV.** They come over the network and are checked before
   use.
3. **Generated reports.** They contain text from package metadata and
   advisories, which could include markup or script.
4. **The local database.** It holds information about your projects, so it
   stays on your machine.

## Risks and how they're handled

| Risk | How DVA handles it |
|---|---|
| A crafted dependency file crashes the parser or uses up memory | Limits on file size, folder depth and the number of files; malformed input is reported as a problem with that file and the scan carries on |
| A file reference or symlink points outside the project | Paths are resolved and checked against the project folder; symlinks are not followed |
| Scanning runs code from the project | DVA never runs install scripts, build steps or package managers. Files that can only be understood by running them, such as `setup.py`, are reported as unsupported |
| Credentials in dependency files leak into results | Tokens and passwords in URLs are removed before anything is stored, environment variables in requirements files are never expanded, and option values such as private index URLs are not copied into messages |
| XML or YAML parsing is abused (external entities, unsafe tags) | Safe parser settings only, if and when those formats are added |
| A tampered or broken response from OSV | HTTPS only, timeouts, response size limits, and validation of the response before use |
| A network failure is read as "nothing found" | Failed lookups are reported as failed, and cached results are shown with their age |
| A version is matched against the wrong range | Version rules specific to each ecosystem, with tests at the edges of affected ranges |
| Script injection through the HTML report | Data is embedded as escaped JSON, the page only inserts text (never HTML), links are limited to http(s), the graph library is vendored and hash-checked, and a Content Security Policy allows only the page's own scripts by hash and no network access |
| Escape codes in the terminal | Control and invisible formatting characters in package names and advisory text are replaced before printing; JSON printed to the screen has every non-ASCII character escaped |
| Private information leaks out | No telemetry; reports leave out absolute paths by default; only the ecosystem and package name are sent to OSV. A registered project's folder path is kept only in the local database and never written into a report |
| A damaged or edited database changes what a comparison says | Saved rows and saved reports are validated when read; anything invalid is an error, not a result. Saved scans are never modified by DVA |
| Deleted data stays readable in the database file | Deleted rows are overwritten (SQLite's `secure_delete`), so clearing the cache, pruning history or removing a project doesn't leave the data behind |
| A published archive contains local files | The source archive uses an explicit allowlist, and CI checks the built wheel and archive for local or secret files before anything could be published |
| DVA's own dependencies are compromised | Few dependencies, locked versions, and review of any dependency change |

## What gets sent over the network

When DVA looks up a package it sends OSV only the ecosystem and the package
name, for example `PyPI` and `requests`. It doesn't send the version, source
code, dependency files, file paths, or anything else from the project.
Packages installed from git, a URL or a local path aren't looked up at all,
so the names of private internal packages don't leave the machine that way.
Packages from a registry other than the public one (a company registry or a
mirror) aren't looked up either, unless you pass
`--include-private-registries`. DVA can only tell where a package comes from
when the dependency files record it; see
[Supported formats](SUPPORTED_FORMATS.md#packages-from-other-registries).

Requests go only to `https://api.osv.dev`, with a timeout, a cap on the
response size, and no redirects followed. At most eight run at the same time,
and each one backs off and retries a few times if OSV says it is busy. The User-Agent names DVA and its
version, nothing about the user.

## Known limits

- Vulnerability databases are never complete, and new advisories can take time
  to appear.
- Reading dependency files without running anything can miss dependencies that
  are only decided at install time or depend on the environment.
- A package version falling inside an affected range doesn't mean the
  vulnerable code is actually used by your project.
- Cached advisory data gets out of date. DVA shows how old it is, but can't
  make it current while offline.
- If a future version lets package managers help resolve dependencies, that
  brings back the risk of running project code. It would need its own design
  and security review before being added.
