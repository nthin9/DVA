# Projects and scan history

`dva scan` checks a folder once and keeps nothing except cached advisory
data. To follow a project over time, register it and rescan it whenever you
like. Each rescan is saved as a snapshot in DVA's local database, and any two
snapshots can be compared.

```powershell
dva project add C:\code\myapp            # register it; the name defaults to "myapp"
dva project add C:\code\api --name api   # or choose a name
dva project list                         # registered projects and their last scan
dva rescan myapp                         # scan again, save it, show what changed
dva rescan --all                         # rescan every registered project
dva history myapp                        # saved scans, newest first
dva history myapp --show 3 --json scan3.json   # export a saved scan's JSON report
dva compare myapp                        # the latest scan against the one before
dva compare myapp 3                      # scan 3 against the latest
dva compare myapp 3 5                    # scan 3 against scan 5
dva project remove myapp --yes           # unregister it and delete its saved scans
```

`rescan` takes the same options as `scan` (`--offline`, `--no-vulnerabilities`,
`--json`, `--html`, `--quiet`, `--data-dir`) and reads the project in exactly
the same way: nothing in it is run, installed or changed. Project names are
matched without regard to case.

## What a comparison shows

- Dependency files that appeared or disappeared.
- Packages that were added or removed, and packages whose versions changed.
  The versions are listed as each scan found them.
- **New advisory findings**: an advisory affecting a package version that the
  older scan checked (or didn't have) and didn't report.
- **Reported now, but not checked in the older scan**: findings for versions
  the older scan had but couldn't check, for example because it ran offline
  without cached data or without a vulnerability check.
- **No longer reported**, with the reason when DVA can tell: the package was
  removed, the project now has a different version, or the source no longer
  matched the advisory to that version.
- **Reported before, but could not be checked in the newer scan**: these are
  kept apart on purpose. A finding that disappeared because the newer lookup
  failed hasn't gone away.
- Versions the older scan checked that the newer one couldn't.

An advisory that is no longer reported is not proof that a problem was fixed.
It only means the newer scan didn't report it.

## Exit codes

`rescan` uses the same exit codes as `scan` (see the README). With `--all`
it returns the most serious result across all projects, in the order 4, 1,
3, 0. `compare` returns 1 when the newer scan reports a finding the older one
didn't, and 0 otherwise. Every command returns 4 on an error, such as an
unknown project or a registered folder that has been moved.

## What is stored

Everything lives in the same local database as the advisory cache (see
[Architecture](ARCHITECTURE.md#storage)). For each project DVA keeps its name
and the absolute path of its folder. For each scan it keeps the full JSON
report, exactly as `--json` would have written it, plus the list of package
versions, statuses and findings used for comparisons. Saved scans are never
changed. Removing a project deletes its saved scans but never touches the
project's folder.

The folder path is stored only in the local database. It is shown by
`dva project list` and in error messages, but it is not written into JSON or
HTML reports.

## Current limits

- `history --show` exports the saved JSON report only. Rebuilding the HTML
  report of an old scan isn't supported yet; run `dva rescan --html` for a
  current one.
- Comparisons are between two scans of one project. There are no queries
  across projects yet.
- History is never pruned automatically. Each saved scan takes roughly the
  size of its JSON report.
