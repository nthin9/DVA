-- Paths and patterns to skip when a registered project is rescanned.
-- Each is project-relative (for example tests/fixtures) or a glob pattern.

CREATE TABLE project_excludes (
    project_id INTEGER NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    pattern    TEXT NOT NULL,
    PRIMARY KEY (project_id, pattern)
);
