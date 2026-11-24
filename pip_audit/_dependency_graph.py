"""
Dependency graph support for tracing vulnerable packages back to the
top-level packages that introduced them.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, TypeAlias, cast

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from pip_audit._service import Dependency, ResolvedDependency, SkippedDependency

DependencyLike: TypeAlias = Dependency | str

_EXTRA_MARKER_VALUE_RE = re.compile(r"""extra\s*(?:==|in)\s*['"]([^'"]+)['"]""")


def dependency_key(dependency: DependencyLike) -> str:
    """Return the canonical lookup key for a dependency or package name."""

    if isinstance(dependency, str):
        return canonicalize_name(dependency)
    return dependency.canonical_name


def format_dependency(dependency: Dependency) -> str:
    """Format a dependency as a compact `name==version` string."""

    if dependency.is_skipped():
        return dependency.name
    dependency = cast(ResolvedDependency, dependency)
    return f"{dependency.name}=={dependency.version}"


def format_dependency_path(path: Iterable[Dependency]) -> str:
    """Format a dependency path as `root==1.0 -> child==2.0`."""

    return " -> ".join(format_dependency(dep) for dep in path)


@dataclass(frozen=True)
class PackageDependency:
    """
    A package record used to construct a `DependencyGraph`.

    `requires` contains PEP 508 requirement strings, as found in a package's
    `Requires-Dist` metadata. `requested` marks packages that were explicitly
    requested by the project or requirements file being audited.
    """

    name: str
    version: Version | str | None = None
    requires: tuple[str, ...] = ()
    requested: bool = False


def _to_dependency(package: PackageDependency) -> Dependency:
    if package.version is None:
        return SkippedDependency(name=package.name, skip_reason="no version specified")

    try:
        version = package.version
        if not isinstance(version, Version):
            version = Version(str(version))
    except InvalidVersion:
        return SkippedDependency(name=package.name, skip_reason="invalid version")

    return ResolvedDependency(name=package.name, version=version)


def _marker_applies(requirement: Requirement) -> bool:
    """
    Return whether a requirement's environment marker applies.

    Extras are not known when reconstructing a graph from installed metadata.
    If a requirement is gated on an extra, treat it as applicable: the target
    package is already known to be present in the resolved environment.
    """

    if requirement.marker is None:
        return True

    marker = str(requirement.marker)
    extras = {"", *_EXTRA_MARKER_VALUE_RE.findall(marker)}

    def applies_for(extra: str) -> bool:
        """Evaluate the marker for a candidate extra value."""

        try:
            return requirement.marker is not None and requirement.marker.evaluate({"extra": extra})
        except Exception:
            return False

    return any(applies_for(extra) for extra in extras)


class DependencyGraph:
    """
    A directed graph of resolved Python dependencies.

    Edges point from a package to the packages it directly requires. Roots are
    either explicitly marked (for example, packages requested by a project) or
    inferred as packages with no incoming edges.

    The graph is cycle-tolerant: path discovery never revisits a package within
    a single chain.
    """

    def __init__(self) -> None:
        """Create an empty dependency graph."""

        self._nodes: dict[str, Dependency] = {}
        self._parents: dict[str, set[str]] = defaultdict(set)
        self._children: dict[str, set[str]] = defaultdict(set)
        self._explicit_roots: set[str] = set()

    def __len__(self) -> int:
        """Return the number of packages in the graph."""

        return len(self._nodes)

    def __contains__(self, dependency: object) -> bool:
        """Return whether a dependency is present in the graph."""

        if isinstance(dependency, (Dependency, str)):
            return dependency_key(dependency) in self._nodes
        return False

    @property
    def nodes(self) -> tuple[Dependency, ...]:
        """Return all graph nodes in canonical-name order."""

        return tuple(self._nodes[key] for key in sorted(self._nodes))

    @property
    def dependencies(self) -> tuple[Dependency, ...]:
        """Alias for `nodes`."""

        return self.nodes

    @property
    def roots(self) -> tuple[Dependency, ...]:
        """
        Return the graph's roots.

        If no roots were explicitly marked, packages with no parents are
        treated as roots.
        """

        if self._explicit_roots:
            keys = self._explicit_roots
        else:
            keys = {key for key in self._nodes if not self._parents[key]}
        return tuple(self._nodes[key] for key in sorted(keys) if key in self._nodes)

    def add_node(self, dependency: Dependency, *, root: bool = False) -> Dependency:
        """Add a dependency node, returning the node stored in the graph."""

        key = dependency.canonical_name
        previous = self._nodes.get(key)

        # Prefer a resolved dependency if duplicate metadata supplies both a
        # resolved and an unresolved node for the same canonical name.
        if previous is None or (previous.is_skipped() and not dependency.is_skipped()):
            self._nodes[key] = dependency

        if root:
            self._explicit_roots.add(key)

        self._parents[key]
        self._children[key]
        return self._nodes[key]

    def add_edge(self, parent: Dependency, child: Dependency) -> None:
        """Add a direct dependency edge from `parent` to `child`."""

        parent_node = self.add_node(parent)
        child_node = self.add_node(child)

        parent_key = parent_node.canonical_name
        child_key = child_node.canonical_name
        if parent_key == child_key:
            return

        self._children[parent_key].add(child_key)
        self._parents[child_key].add(parent_key)

    def get(self, dependency: DependencyLike) -> Dependency | None:
        """Return a node by dependency or canonical package name."""

        return self._nodes.get(dependency_key(dependency))

    def parents(self, dependency: DependencyLike) -> tuple[Dependency, ...]:
        """Return the direct parents of a dependency."""

        key = dependency_key(dependency)
        return tuple(self._nodes[parent] for parent in sorted(self._parents[key]))

    def children(self, dependency: DependencyLike) -> tuple[Dependency, ...]:
        """Return the direct children of a dependency."""

        key = dependency_key(dependency)
        return tuple(self._nodes[child] for child in sorted(self._children[key]))

    def paths_to(
        self,
        dependency: DependencyLike,
        *,
        max_depth: int = 64,
        max_paths: int = 100,
    ) -> list[list[Dependency]]:
        """
        Return all root-to-`dependency` paths.

        Paths are deterministic: shorter paths come first, followed by
        lexicographic ordering. At most `max_paths` paths and `max_depth` nodes
        are returned. An unknown package has no paths.
        """

        target = dependency_key(dependency)
        if target not in self._nodes or max_depth < 1 or max_paths < 1:
            return []

        roots = [root.canonical_name for root in self.roots]
        paths: list[tuple[str, ...]] = []

        def visit(current: str, path: tuple[str, ...], seen: set[str]) -> None:
            """Collect paths from `current` to the target package."""

            if len(path) > max_depth or len(paths) >= max_paths:
                return
            if current == target:
                paths.append(path)
                return

            for child in sorted(self._children[current]):
                if child in seen:
                    continue
                visit(child, path + (child,), seen | {child})

        for root in roots:
            visit(root, (root,), {root})

        unique_paths = sorted(
            set(paths),
            key=lambda path: (len(path), path),
        )
        return [[self._nodes[key] for key in path] for path in unique_paths[:max_paths]]

    def introduction_points(self, dependency: DependencyLike) -> list[Dependency]:
        """
        Return the roots that introduce `dependency`.

        These are the first nodes of each root-to-dependency path, de-duplicated
        in deterministic order.
        """

        points: dict[str, Dependency] = {}
        for path in self.paths_to(dependency):
            root = path[0]
            points.setdefault(root.canonical_name, root)
        return list(points.values())

    @classmethod
    def from_packages(cls, packages: Iterable[PackageDependency]) -> DependencyGraph:
        """Build a graph from package metadata records."""

        return dependency_graph_from_packages(packages)

    @classmethod
    def from_install_report(cls, report: Mapping[str, Any]) -> DependencyGraph:
        """Build a graph from a `pip install --dry-run --report` payload."""

        return dependency_graph_from_install_report(report)

    @classmethod
    def from_distributions(cls, distributions: Iterable[Any]) -> DependencyGraph:
        """Build a graph from `importlib.metadata.Distribution` objects."""

        return dependency_graph_from_distributions(distributions)

    @classmethod
    def from_pylock_packages(cls, packages: Sequence[Mapping[str, Any]]) -> DependencyGraph:
        """Build a graph from PEP 751 package records."""

        return dependency_graph_from_pylock_packages(packages)


def dependency_graph_from_packages(packages: Iterable[PackageDependency]) -> DependencyGraph:
    """
    Build a `DependencyGraph` from package metadata records.

    Requirements that do not correspond to another package in `packages` are
    ignored, since they are not part of the resolved environment.
    """

    graph = DependencyGraph()
    records = list(packages)

    for package in records:
        graph.add_node(_to_dependency(package), root=package.requested)

    for package in records:
        parent = graph.get(package.name)
        if parent is None:
            continue

        for requirement_string in package.requires:
            try:
                requirement = Requirement(requirement_string)
            except InvalidRequirement:
                continue

            child = graph.get(requirement.name)
            if child is None or not _marker_applies(requirement):
                continue
            graph.add_edge(parent, child)

    return graph


def dependency_graph_from_install_report(report: Mapping[str, Any]) -> DependencyGraph:
    """
    Build a `DependencyGraph` from a `pip install --dry-run --report` payload.
    """

    packages = []
    for entry in report.get("install") or []:
        metadata = entry.get("metadata", {})
        name = metadata.get("name")
        if not name:
            continue

        packages.append(
            PackageDependency(
                name=name,
                version=metadata.get("version"),
                requires=tuple(metadata.get("requires_dist") or ()),
                requested=bool(entry.get("requested", entry.get("is_direct", False))),
            )
        )

    return dependency_graph_from_packages(packages)


def dependency_graph_from_distributions(distributions: Iterable[Any]) -> DependencyGraph:
    """
    Build a `DependencyGraph` from `importlib.metadata.Distribution` objects.
    """

    packages = []
    for distribution in distributions:
        metadata = distribution.metadata
        name = metadata.get("Name")
        if not name:
            continue

        packages.append(
            PackageDependency(
                name=name,
                version=distribution.version,
                requires=tuple(distribution.requires or ()),
            )
        )

    return dependency_graph_from_packages(packages)


def dependency_graph_from_pylock_packages(
    packages: Sequence[Mapping[str, Any]],
) -> DependencyGraph:
    """Build a `DependencyGraph` from PEP 751 package records."""

    records = []
    for package in packages:
        name = package.get("name")
        if not name:
            continue

        requires = []
        for dependency in package.get("dependencies", ()):
            if isinstance(dependency, str):
                requires.append(dependency)
            elif isinstance(dependency, Mapping) and dependency.get("name"):
                requires.append(str(dependency["name"]))

        records.append(
            PackageDependency(
                name=str(name),
                version=package.get("version"),
                requires=tuple(requires),
            )
        )

    return dependency_graph_from_packages(records)


def dependency_chains_for_result(
    result: Mapping[Dependency, Sequence[Any]],
    graph: DependencyGraph | None,
) -> dict[Dependency | str, Sequence[Sequence[Dependency]]]:
    """
    Build package-to-chains data for a set of audit results.

    Packages with no vulnerabilities are omitted. Sources without a graph fall
    back to treating each vulnerable package as its own direct chain.
    """

    chains: dict[Dependency | str, Sequence[Sequence[Dependency]]] = {}
    for dependency, vulns in result.items():
        if dependency.is_skipped() or not vulns:
            continue

        if graph is not None and dependency in graph:
            paths = graph.paths_to(dependency)
        else:
            paths = [[dependency]]

        if paths:
            chains[dependency.canonical_name] = paths

    return chains
