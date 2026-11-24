-- Cached advisory data from vulnerability sources.
--
-- package_lookups: when a source was last asked about a package.
-- package_advisories: which advisories it listed for the package then.
-- advisories: each advisory's raw record text, as the source returned it.
-- Timestamps are UTC, stored as ISO 8601 text.

CREATE TABLE package_lookups (
    provider     TEXT NOT NULL,
    ecosystem    TEXT NOT NULL,
    name         TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    PRIMARY KEY (provider, ecosystem, name)
);

CREATE TABLE package_advisories (
    provider    TEXT NOT NULL,
    ecosystem   TEXT NOT NULL,
    name        TEXT NOT NULL,
    advisory_id TEXT NOT NULL,
    modified    TEXT NOT NULL,
    PRIMARY KEY (provider, ecosystem, name, advisory_id),
    FOREIGN KEY (provider, ecosystem, name)
        REFERENCES package_lookups (provider, ecosystem, name) ON DELETE CASCADE
);

CREATE TABLE advisories (
    provider     TEXT NOT NULL,
    advisory_id  TEXT NOT NULL,
    modified     TEXT NOT NULL,
    record       TEXT NOT NULL,
    retrieved_at TEXT NOT NULL,
    PRIMARY KEY (provider, advisory_id)
);
