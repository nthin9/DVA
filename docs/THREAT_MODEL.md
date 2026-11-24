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
| Scanning runs code from the project | DVA never runs install scripts, build steps or package managers |
| XML or YAML parsing is abused (external entities, unsafe tags) | Safe parser settings only, if and when those formats are added |
| A tampered or broken response from OSV | HTTPS only, timeouts, response size limits, and validation of the response before use |
| A network failure is read as "nothing found" | Failed lookups are reported as failed, and cached results are shown with their age |
| A version is matched against the wrong range | Version rules specific to each ecosystem, with tests at the edges of affected ranges |
| Script injection through the HTML report | Outside text is escaped, data is passed as JSON, scripts are bundled locally, and a restrictive Content Security Policy is applied |
| Private information leaks out | No telemetry; reports leave out absolute paths by default; only package name, ecosystem and version are sent to OSV |
| DVA's own dependencies are compromised | Few dependencies, locked versions, and review of any dependency change |

## What gets sent over the network

When DVA looks up a package it sends OSV the ecosystem, the package name (or
PURL) and the version. It doesn't send source code, dependency files, file
paths, or anything else from the project.

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
