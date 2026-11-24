# OSV fixture records

Real records downloaded unchanged from `https://api.osv.dev/v1/vulns/<id>` on
2026-11-24. They are used to test record parsing and version matching against
the data the live service actually returns:

- `GHSA-j8r2-6x86-q33q`: requests, a version range with a lower bound, plus an
  explicit versions list and a CVSS score.
- `PYSEC-2023-74`: the same issue from the PyPI advisory database, with a GIT
  commit range next to the version range and no severity.
- `GHSA-9wx4-h78v-vm56`: requests, affected from the first version onward.
- `GHSA-35jh-r3h4-6jhm`: lodash and related npm packages with SEMVER ranges,
  `last_affected` instead of a fix, and one package from another ecosystem.

The records are not refreshed automatically, so the expected results in the
tests stay stable even when OSV updates them.
