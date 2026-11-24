# Roadmap

This is the order the work is planned in. Plans change as the project
develops, so treat it as a guide, not a schedule.

## Done

**Project setup.** The repository, Python packaging, test and lint tooling,
and CI on Windows and Linux.

## Now: the core engine

- The data model for packages, dependencies, dependency files and scans.
- The interface that ecosystem adapters implement, and the registry they are
  listed in.
- Safe discovery of dependency files in a project folder, with limits on depth,
  file count and file size.
- Stable JSON output of scan results, so the same scan always produces the
  same output.

This stage is finished when tests show that a new adapter can be added without
changing the engine itself.

## Next

**Python and npm support.** Parsers for specific Python and npm dependency
files and lockfiles, including direct and transitive dependencies. Each format
gets its own test files, including malformed and deliberately hostile ones.

**Vulnerability lookups.** Querying OSV, fetching and caching advisories,
working offline from the cache, and matching versions against affected ranges
using each ecosystem's own version rules.

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
- Better handling of monorepos and optional or platform-specific dependencies.
- A desktop app, a standalone Windows installer, and possibly a VS Code
  extension.

Some things aren't planned: changing project files automatically, cloud sync,
and AI-written vulnerability summaries.
