"""Check the built wheel and source archive before they could be published.

Run after ``uv build``: ``python .github/scripts/check_dist.py dist``. Fails if
an archive is missing files DVA needs at run time, or contains anything that
must never be published (local agent material, databases, caches, secrets).
"""

from __future__ import annotations

import sys
import tarfile
import zipfile
from pathlib import Path

#: Files the installed package can't work without.
REQUIRED_IN_WHEEL = (
    "dva/cli.py",
    "dva/storage/migrations/001_advisory_cache.sql",
    "dva/storage/migrations/002_projects_and_scans.sql",
    "dva/reporting/assets/report.html",
    "dva/reporting/assets/report.js",
    "dva/reporting/assets/report.css",
    "dva/reporting/assets/cytoscape.min.js",
    "dva/reporting/assets/LICENSE-cytoscape.txt",
)

#: Path fragments that must never appear in a published archive.
FORBIDDEN = (".claude", ".git/", ".venv", "__pycache__", ".sqlite", ".env", ".pytest_cache")


def check(names: list[str], label: str) -> list[str]:
    problems = [f"{label}: must not contain {name}" for name in names if _forbidden(name)]
    return problems


def _forbidden(name: str) -> bool:
    return any(fragment in name for fragment in FORBIDDEN)


def main(folder: str) -> int:
    dist = Path(folder)
    wheels, sdists = sorted(dist.glob("*.whl")), sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        print(f"expected one wheel and one source archive in {dist}")
        return 1
    with zipfile.ZipFile(wheels[0]) as wheel:
        wheel_names = wheel.namelist()
    with tarfile.open(sdists[0]) as sdist:
        sdist_names = sdist.getnames()
    problems = check(wheel_names, "wheel") + check(sdist_names, "source archive")
    problems += [f"wheel: missing {name}" for name in REQUIRED_IN_WHEEL if name not in wheel_names]
    if not any(name.endswith("/licenses/LICENSE") for name in wheel_names):
        problems.append("wheel: missing the license file")
    for problem in problems:
        print(problem)
    print(f"checked {len(wheel_names)} wheel and {len(sdist_names)} source archive entries")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "dist"))
