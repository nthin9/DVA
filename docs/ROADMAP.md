# Roadmap

This is the order the work is planned in. Plans change as the project
develops, so treat it as a guide, not a schedule.

## Done

**Project setup.** The repository, Python packaging, test and lint tooling,
and CI on Windows and Linux.

**The core engine.** The data model for packages, dependencies, dependency
files and scans; the interface ecosystem adapters implement and the registry
they're listed in; safe discovery of dependency files with limits on depth,
file count and file size; and stable JSON output, so the same scan always
produces the same result. Tests show that a new adapter can be plugged in
without changing the engine.

**Python and npm support.** Parsers for Python's `requirements.txt` files,
`pyproject.toml`, `uv.lock` and `poetry.lock`, and for npm's `package.json`,
`package-lock.json` and `npm-shrinkwrap.json`, including direct and transitive
dependencies. Each format has its own test files, including malformed and
deliberately hostile ones. The details are in
[Supported formats](SUPPORTED_FORMATS.md).

**Vulnerability lookups.** The data model for advisories and findings,
designed against real OSV records; looking packages up in OSV by name;
caching advisories in SQLite and working offline from the cache; and matching
installed versions against affected ranges using each ecosystem's own version
rules.

## Next

**Projects and history.** Registering projects, keeping a history of scans in
SQLite, rescanning, and comparing two scans.

**Output.** A readable terminal summary, a versioned JSON report, and the
interactive HTML dependency graph.

**First release.** Windows packaging, install instructions, a security review,
and documentation of what's supported and what isn't.

## Later

- Maven and Gradle, which also covers Java libraries published by vendors such
  as Oracle.
- More ecosystems based on demand: Rust (Cargo), Go modules, NuGet, C/C++
  package managers such as Conan and vcpkg, and LuaRocks.
- Downloading vulnerability data in bulk for fully offline use.
- More lockfiles for the ecosystems already supported: Yarn, pnpm and Bun for
  JavaScript, and `Pipfile.lock` and `pylock.toml` for Python.
- Better handling of monorepos and optional or platform-specific dependencies.
- A desktop app, a standalone Windows installer, and possibly a VS Code
  extension.

Some things aren't planned: changing project files automatically, cloud sync,
and AI-written vulnerability summaries.
