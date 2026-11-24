# JSON report format

`dva scan --json FILE` writes the full result of a scan as JSON. This page
describes version `dva.report/1` of that format. A change that removes or
renames a field, or changes what one means, gets a new version; new fields
may be added within a version.

The output is deterministic: keys are sorted and lists come in a fixed order,
so the same scan always produces the same file. Times are UTC, written as
`2026-03-01T12:00:00.000000Z`. Paths are relative to the scanned folder and
use `/`; absolute paths never appear.

## Top level

| Field | Meaning |
|---|---|
| `schema_version` | `"dva.report/1"` |
| `tool_version` | The DVA version that produced the report |
| `project_name` | The scanned folder's name (not its full path) |
| `started_at`, `finished_at` | When the dependency analysis ran |
| `completion` | How completely the dependency files were understood: `complete`, `partial`, `failed` or `no_supported_files` |
| `vulnerability_status` | `not_queried`, `complete`, `partial` or `failed` (see below) |
| `manifests` | One entry per dependency file found |
| `diagnostics` | Problems found while looking for files (limits reached, skipped entries) |
| `excluded` | Paths and patterns the scan was asked to skip (`--exclude`), so readers know the coverage was limited on purpose; empty when nothing was excluded |
| `vulnerabilities` | The vulnerability check, or `null` if it wasn't run |
| `overview` | Counts that summarize everything above |

`completion` is only `complete` when every file found was fully read and
nothing was skipped. `vulnerability_status` is `complete` only when every
package with an exact version was checked without problems.

## Dependency files (`manifests[]`)

| Field | Meaning |
|---|---|
| `path` | The file, relative to the scanned folder |
| `adapter_id`, `ecosystem` | Which part of DVA read it (`python`, `npm`) and the package ecosystem (`pypi`, `npm`) |
| `kind` | `manifest` (what the project asks for) or `lockfile` (what was installed) |
| `format_name`, `format_version` | The file format, and its version when the file states one |
| `status` | `parsed`, `partial`, `unsupported`, `failed` or `skipped` |
| `requirements` | Declared dependencies (manifests) |
| `packages` | Installed packages at exact versions (lockfiles) |
| `edges` | Links between packages (lockfiles) |
| `diagnostics` | What couldn't be read, and why |

A **requirement** has `identity`, `constraint` (the version range as written,
or `null`), `markers` (platform conditions as written), `extras`, `groups`
(such as `dev`, `optional:<extra>`, `group:<name>`), `alias` (the name it is
installed under, if different), `source` (`registry`, `other_registry`,
`git`, `url`, `path`, `workspace` or `unknown`), `line` (when known),
`origin` (the file the requirement is written in, when it was pulled in from
another file such as one included with `-r`; `line` then refers to that file,
otherwise `null`) and `constrained_to` (an exact version a constraints file
pins it to, or `null`).

`registry` means the ecosystem's public registry (PyPI, the npm registry);
`other_registry` means any other package index, such as a private one.

A **package** has `node_id` (unique within its file), `identity`, `version`
(exactly as recorded), `groups`, `source` and `markers` (conditions for
installing the package at all, when the lockfile records them per package,
otherwise `null`).

An **edge** has `parent_id` (`null` when the project depends on the package
directly), `child_id`, `direct`, `constraint`, `markers` and `groups`.

An **identity** has `ecosystem`, `namespace` (an npm scope such as `@babel`,
or `null`), `name` (normalized the way the ecosystem does it) and `purl` (a
Package URL, only for packages from the public registry).

A **diagnostic** has `code` (a stable identifier such as
`python.requirements.editable`), `level` (`info`, `warning` or `error`),
`message` and `path`.

## Vulnerability check (`vulnerabilities`)

| Field | Meaning |
|---|---|
| `provider` | The advisory source, currently `osv` |
| `checked_at` | When the check ran |
| `data_source` | `live`, `cache`, `mixed` or `none` |
| `oldest_data_at` | The oldest retrieval time of the advisory data used |
| `checks` | One entry per package version (or per unversioned declaration) |
| `advisories` | The full text of every advisory behind a finding |
| `diagnostics` | Problems with the lookup, such as the source being unreachable |

Each **check** has `identity`, `version` (`null` when no exact version is
known), `status`, `locations` (each a `path` plus a `node_id` or `line`),
`findings`, `reasons` and `data_retrieved_at`. `status` is one of:

- `affected`: at least one advisory matches this version. `findings` lists them.
- `no_matching_advisory`: the source returned no advisory matching this
  version when asked. This is not proof that the package is safe.
- `unknown`: advisories exist for the package, but DVA couldn't decide for
  this version. `reasons` says why.
- `not_checked`: the package wasn't looked up, for example because only a
  version range is known, or it comes from git. `reasons` says why.
- `lookup_failed`: the lookup failed and nothing usable was cached.

For an affected package, `upgrade_to` is the lowest version that the
advisories themselves name as fixed and that none of the advisories the
source listed for the package affect, checked with the ecosystem's own
version rules. When there is no such version, `upgrade_to` is `null` and
`upgrade_note` says why (for example, an advisory names no fixed version).
Both are `null` for packages that aren't affected. DVA doesn't check whether
the suggested version fits the rest of the dependency tree.

`introduced_by` (in the report written by DVA, not part of the scan data it
reads back) lists, for each lockfile location, the shortest chain of package
names from a direct dependency down to this package. An empty chain means
the package is itself a direct dependency.

A **finding** has `advisory_id`, `matched_by` (`range`, `versions` or both),
`fixed_versions`, `last_affected` and `severities`. The fixed and last
affected versions are copied from the advisory and are empty when the
advisory doesn't give them; DVA never guesses a fix. `severities` lists the
scores the advisory gives for this particular package (OSV allows a score per
affected package instead of one for the whole advisory), in the same shape as
an advisory's `severities`. It is usually empty. `accepted` is `null`, or the
accepted risk that covers this finding: `advisory` (the id or alias it was
accepted under), `package` (or `null` for any package), `reason` and `until`
(the last day it holds, or `null`). An accepted finding is still a finding,
and the check is still `affected`.

An **advisory** has `id`, `aliases` (CVE identifiers among them, when there
are any), `related`, `summary`, `details`, `severities` (each with `type`
such as `CVSS_V3`, `score` as published, and `source`), `database_severity`
(the database's own label, such as `HIGH`), `references` (only `http(s)`
links), `affected` (each package with its ranges, versions and any
`severities` given for that package alone), `published`, `modified`, `withdrawn` and
`schema_version`. DVA doesn't compute or change severity scores.

## Overview (`overview`)

| Field | Meaning |
|---|---|
| `files_by_status`, `files_by_kind` | How many dependency files had each status and kind |
| `declared_requirements` | Requirements across all manifests |
| `resolved_packages` | Packages across all lockfiles |
| `direct_dependencies` | Packages the project depends on directly, according to its lockfiles |
| `outcomes` | How many checks had each status |
| `advisories` | How many distinct advisories matched |
| `accepted_findings` | How many findings are covered by an accepted risk |
