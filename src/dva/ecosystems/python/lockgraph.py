"""Assembling a resolved dependency graph from a Python lockfile.

Shared by the lockfile parsers. Edges that differ only in their group labels
are merged, so a dependency reached through several groups appears once with
all of them. Each package's ``groups`` lists the groups that pull it in from
the project's direct dependencies; a package needed by the main (ungrouped)
dependencies has no groups, because it is always installed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from dva.domain.dependency import DependencyEdge, ResolvedPackage

_MAIN = ""


@dataclass
class LockGraph:
    packages: dict[str, ResolvedPackage] = field(default_factory=dict)
    _edges: dict[tuple[str | None, str, str | None, str | None], set[str]] = field(
        default_factory=dict
    )

    def add_edge(
        self,
        parent_id: str | None,
        child_id: str,
        *,
        constraint: str | None = None,
        markers: str | None = None,
        groups: tuple[str, ...] = (),
    ) -> None:
        if parent_id == child_id:
            return
        key = (parent_id, child_id, constraint, markers)
        self._edges.setdefault(key, set()).update(groups)

    def edges(self) -> tuple[DependencyEdge, ...]:
        return tuple(
            DependencyEdge(
                parent_id,
                child_id,
                constraint=constraint,
                markers=markers,
                groups=tuple(sorted(groups)),
            )
            for (parent_id, child_id, constraint, markers), groups in self._edges.items()
        )

    def packages_with_groups(self) -> tuple[tuple[ResolvedPackage, ...], tuple[str, ...]]:
        """Packages with ``groups`` set from reachability, plus the unreachable node ids.

        When the graph has no direct edges, packages are returned unchanged and
        nothing is reported as unreachable (there is nothing to measure from).
        """
        children: dict[str, list[str]] = {}
        reached: dict[str, set[str]] = {node: set() for node in self.packages}
        pending: list[tuple[str, str]] = []
        for (parent_id, child_id, _, _), groups in self._edges.items():
            if parent_id is None:
                for label in groups or {_MAIN}:
                    pending.append((child_id, label))
            else:
                children.setdefault(parent_id, []).append(child_id)
        if not pending:
            return tuple(self.packages.values()), ()

        while pending:
            node, label = pending.pop()
            if label in reached[node]:
                continue
            reached[node].add(label)
            for child in children.get(node, ()):
                pending.append((child, label))

        result = []
        unreachable = []
        for node, package in self.packages.items():
            labels = reached[node]
            if not labels:
                unreachable.append(node)
            package_groups = () if _MAIN in labels else tuple(sorted(labels))
            result.append(
                ResolvedPackage(
                    package.node_id,
                    package.identity,
                    package.version,
                    groups=package_groups,
                    source=package.source,
                )
            )
        return tuple(result), tuple(unreachable)
