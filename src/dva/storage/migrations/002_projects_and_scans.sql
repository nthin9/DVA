-- Registered projects and their saved scans.
--
-- projects: local folders registered for repeated scans. root_key is the
--   folder path in the form used to tell whether two paths are the same
--   folder (case-folded on Windows).
-- scans: one row per saved scan, with its full JSON report. Rows are only
--   ever added, never changed.
-- scan_manifests, scan_packages, scan_findings: what each scan found, in the
--   form two scans are compared in. An empty namespace or version means none.
-- scan_records: each scan's summary with its counts, as history lists it.
-- Timestamps are UTC, stored as ISO 8601 text.

CREATE TABLE projects (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    root       TEXT NOT NULL,
    root_key   TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL
);

CREATE TABLE scans (
    id                   INTEGER PRIMARY KEY,
    project_id           INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    tool_version         TEXT NOT NULL,
    started_at           TEXT NOT NULL,
    finished_at          TEXT NOT NULL,
    completion           TEXT NOT NULL,
    vulnerability_status TEXT NOT NULL,
    data_source          TEXT,
    oldest_data_at       TEXT,
    report_format        TEXT NOT NULL,
    report               TEXT NOT NULL
);

CREATE INDEX scans_by_project ON scans (project_id, id);

CREATE TABLE scan_manifests (
    scan_id INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    path    TEXT NOT NULL,
    PRIMARY KEY (scan_id, path)
);

CREATE TABLE scan_packages (
    scan_id   INTEGER NOT NULL REFERENCES scans (id) ON DELETE CASCADE,
    ecosystem TEXT NOT NULL,
    namespace TEXT NOT NULL,
    name      TEXT NOT NULL,
    version   TEXT NOT NULL,
    status    TEXT NOT NULL,
    PRIMARY KEY (scan_id, ecosystem, namespace, name, version)
);

CREATE TABLE scan_findings (
    scan_id     INTEGER NOT NULL,
    ecosystem   TEXT NOT NULL,
    namespace   TEXT NOT NULL,
    name        TEXT NOT NULL,
    version     TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    PRIMARY KEY (scan_id, ecosystem, namespace, name, version, advisory_id),
    FOREIGN KEY (scan_id, ecosystem, namespace, name, version)
        REFERENCES scan_packages (scan_id, ecosystem, namespace, name, version)
        ON DELETE CASCADE
);

CREATE VIEW scan_records AS
SELECT
    s.id, s.project_id, s.tool_version, s.started_at, s.finished_at, s.completion,
    s.vulnerability_status, s.data_source, s.oldest_data_at,
    (SELECT COUNT(*) FROM scan_packages p WHERE p.scan_id = s.id) AS packages,
    (SELECT COUNT(*) FROM scan_packages p
        WHERE p.scan_id = s.id AND p.status = 'affected') AS affected,
    (SELECT COUNT(DISTINCT f.advisory_id) FROM scan_findings f
        WHERE f.scan_id = s.id) AS advisories
FROM scans s;
