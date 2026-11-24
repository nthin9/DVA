-- Risks a team accepted for a registered project. Each names an advisory
-- (its id or an alias), optionally a package ('' for any), a reason, and
-- optionally the last day it holds (ISO date, or NULL for no end).

CREATE TABLE project_acceptances (
    project_id INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    advisory   TEXT NOT NULL,
    package    TEXT NOT NULL,
    reason     TEXT NOT NULL,
    until      TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (project_id, advisory, package)
);
