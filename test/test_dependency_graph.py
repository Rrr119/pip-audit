from __future__ import annotations

import pytest
from packaging.version import Version

from pip_audit._dependency_graph import (
    DependencyGraph,
    PackageDependency,
    dependency_chains_for_result,
    dependency_graph_from_install_report,
    dependency_graph_from_packages,
    format_dependency_path,
)
from pip_audit._service import ResolvedDependency


def _dep(name: str, version: str = "1.0") -> ResolvedDependency:
    return ResolvedDependency(name=name, version=Version(version))


def _graph(edges: list[tuple[str, str]], *, roots: list[str] = ()) -> DependencyGraph:
    graph = DependencyGraph()
    for name in roots:
        graph.add_node(_dep(name), root=True)
    for parent, child in edges:
        graph.add_edge(_dep(parent), _dep(child))
    return graph


def test_paths_to_simple_chain():
    graph = _graph([("app", "middle"), ("middle", "vulnerable")], roots=["app"])

    paths = graph.paths_to("vulnerable")

    assert [[dep.canonical_name for dep in path] for path in paths] == [
        ["app", "middle", "vulnerable"]
    ]
    assert [dep.canonical_name for dep in graph.introduction_points("vulnerable")] == ["app"]
    assert format_dependency_path(paths[0]) == "app==1.0 -> middle==1.0 -> vulnerable==1.0"


def test_paths_to_diamond_is_aggregated_by_package():
    graph = _graph(
        [
            ("app", "left"),
            ("app", "right"),
            ("left", "vulnerable"),
            ("right", "vulnerable"),
        ],
        roots=["app"],
    )

    paths = graph.paths_to("vulnerable")

    assert [[dep.canonical_name for dep in path] for path in paths] == [
        ["app", "left", "vulnerable"],
        ["app", "right", "vulnerable"],
    ]
    assert [dep.canonical_name for dep in graph.introduction_points("vulnerable")] == ["app"]


def test_paths_to_multiple_roots():
    graph = _graph(
        [("first", "shared"), ("second", "shared"), ("shared", "vulnerable")],
        roots=["first", "second"],
    )

    paths = graph.paths_to("vulnerable")

    assert [path[0].canonical_name for path in paths] == ["first", "second"]
    assert [dep.canonical_name for dep in graph.introduction_points("vulnerable")] == [
        "first",
        "second",
    ]


def test_paths_to_handles_cycles():
    graph = _graph([("app", "cycle-a"), ("cycle-a", "cycle-b"), ("cycle-b", "cycle-a")])

    assert graph.paths_to("cycle-b") == [[_dep("app"), _dep("cycle-a"), _dep("cycle-b")]]
    assert graph.paths_to("unknown") == []


def test_paths_to_uses_inferred_roots():
    graph = _graph([("top", "middle"), ("middle", "leaf")])

    assert [[dep.canonical_name for dep in path] for path in graph.paths_to("leaf")] == [
        ["top", "middle", "leaf"]
    ]
    assert [dep.canonical_name for dep in graph.roots] == ["top"]


def test_path_limit_and_depth_limit():
    graph = _graph([("root", "a"), ("a", "b"), ("b", "leaf")])

    assert graph.paths_to("leaf", max_depth=2) == []
    assert len(graph.paths_to("leaf", max_depth=4)) == 1
    assert graph.paths_to("leaf", max_paths=0) == []


def test_canonical_names_and_duplicate_nodes():
    graph = DependencyGraph()
    graph.add_node(_dep("My_Package"), root=True)
    graph.add_edge(_dep("my-package"), _dep("Dependency.Name"))

    assert [dep.canonical_name for dep in graph.nodes] == ["dependency-name", "my-package"]
    assert [[dep.canonical_name for dep in path] for path in graph.paths_to("dependency_name")] == [
        ["my-package", "dependency-name"]
    ]


def test_dependency_graph_from_packages_ignores_unresolved_requirements():
    graph = dependency_graph_from_packages(
        [
            PackageDependency(
                name="app",
                version="1.0",
                requires=("present>=1", "missing>=1", "bad requirement !"),
                requested=True,
            ),
            PackageDependency(name="present", version="2.0"),
        ]
    )

    assert [[dep.canonical_name for dep in path] for path in graph.paths_to("present")] == [
        ["app", "present"]
    ]


def test_dependency_graph_ignores_extra_requirement_with_false_marker():
    graph = dependency_graph_from_packages(
        [
            PackageDependency(
                name="app",
                version="1.0",
                requires=('optional; extra == "extra" and python_version < "2"',),
                requested=True,
            ),
            PackageDependency(name="optional", version="1.0"),
        ]
    )

    assert graph.paths_to("optional") == []


def test_dependency_graph_from_install_report():
    report = {
        "install": [
            {
                "requested": True,
                "metadata": {
                    "name": "Flask",
                    "version": "3.0.0",
                    "requires_dist": ["Werkzeug>=3.0", "Jinja2>=3.1.2"],
                },
            },
            {
                "requested": False,
                "metadata": {
                    "name": "Werkzeug",
                    "version": "3.1.9",
                    "requires_dist": ["MarkupSafe>=2.1.1"],
                },
            },
            {
                "requested": False,
                "metadata": {"name": "MarkupSafe", "version": "3.0.3"},
            },
            {
                "requested": False,
                "metadata": {"name": "Jinja2", "version": "3.1.6"},
            },
        ]
    }

    graph = dependency_graph_from_install_report(report)

    assert [[dep.canonical_name for dep in path] for path in graph.paths_to("markupsafe")] == [
        ["flask", "werkzeug", "markupsafe"]
    ]


def test_dependency_chains_for_result_aggregates_by_package():
    app = _dep("app")
    vulnerable = _dep("vulnerable")
    graph = DependencyGraph()
    graph.add_edge(app, vulnerable)

    chains = dependency_chains_for_result(
        {app: [], vulnerable: [object()]},
        graph,
    )

    assert list(chains) == ["vulnerable"]
    assert [[dep.canonical_name for dep in path] for path in chains["vulnerable"]] == [
        ["app", "vulnerable"]
    ]


# Each project exercises a different shape that a real dependency tree can take:
# direct, transitive, deep, diamond, multiple roots, cycles, shared subtrees,
# optional dependencies, casing differences, and multiple vulnerable packages.
_PROJECTS = [
    {
        "name": "project-01-direct",
        "packages": [
            PackageDependency("app", "1.0", requires=("vulnerable",), requested=True),
            PackageDependency("vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"app"},
        "path_count": 1,
    },
    {
        "name": "project-02-transitive",
        "packages": [
            PackageDependency("app", "1.0", requires=("middle",), requested=True),
            PackageDependency("middle", "1.0", requires=("vulnerable",)),
            PackageDependency("vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"app"},
        "path_count": 1,
    },
    {
        "name": "project-03-deep",
        "packages": [
            PackageDependency("app", "1.0", requires=("one",), requested=True),
            PackageDependency("one", "1.0", requires=("two",)),
            PackageDependency("two", "1.0", requires=("three",)),
            PackageDependency("three", "1.0", requires=("vulnerable",)),
            PackageDependency("vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"app"},
        "path_count": 1,
    },
    {
        "name": "project-04-diamond",
        "packages": [
            PackageDependency("app", "1.0", requires=("left", "right"), requested=True),
            PackageDependency("left", "1.0", requires=("shared",)),
            PackageDependency("right", "1.0", requires=("shared",)),
            PackageDependency("shared", "1.0", requires=("vulnerable",)),
            PackageDependency("vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"app"},
        "path_count": 2,
    },
    {
        "name": "project-05-multiple-roots",
        "packages": [
            PackageDependency("api", "1.0", requires=("shared",), requested=True),
            PackageDependency("worker", "1.0", requires=("shared",), requested=True),
            PackageDependency("shared", "1.0", requires=("vulnerable",)),
            PackageDependency("vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"api", "worker"},
        "path_count": 2,
    },
    {
        "name": "project-06-cycle-detour",
        "packages": [
            PackageDependency("app", "1.0", requires=("a",), requested=True),
            PackageDependency("a", "1.0", requires=("b",)),
            PackageDependency("b", "1.0", requires=("a", "vulnerable")),
            PackageDependency("vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"app"},
        "path_count": 1,
    },
    {
        "name": "project-07-shared-subtree",
        "packages": [
            PackageDependency("app", "1.0", requires=("web", "jobs"), requested=True),
            PackageDependency("web", "1.0", requires=("common",)),
            PackageDependency("jobs", "1.0", requires=("common",)),
            PackageDependency("common", "1.0", requires=("codec",)),
            PackageDependency("codec", "0.1"),
        ],
        "vulnerable": "codec",
        "roots": {"app"},
        "path_count": 2,
    },
    {
        "name": "project-08-optional-extra",
        "packages": [
            PackageDependency(
                "app",
                "1.0",
                requires=("core", 'optional; extra == "extra"'),
                requested=True,
            ),
            PackageDependency("core", "1.0"),
            PackageDependency("optional", "0.1", requires=("vulnerable",)),
            PackageDependency("vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"app"},
        "path_count": 1,
    },
    {
        "name": "project-09-canonical-casing",
        "packages": [
            PackageDependency("My_App", "1.0", requires=("Some_Library",), requested=True),
            PackageDependency("some-library", "1.0", requires=("Vulnerable_Pkg",)),
            PackageDependency("vulnerable-pkg", "0.1"),
        ],
        "vulnerable": "vulnerable-pkg",
        "roots": {"my-app"},
        "path_count": 1,
    },
    {
        "name": "project-10-multiple-vulnerable-packages",
        "packages": [
            PackageDependency("app", "1.0", requires=("branch-a", "branch-b"), requested=True),
            PackageDependency("branch-a", "1.0", requires=("vulnerable",)),
            PackageDependency("branch-b", "1.0", requires=("also-vulnerable",)),
            PackageDependency("vulnerable", "0.1"),
            PackageDependency("also-vulnerable", "0.1"),
        ],
        "vulnerable": "vulnerable",
        "roots": {"app"},
        "path_count": 1,
    },
]


@pytest.mark.parametrize("project", _PROJECTS, ids=[project["name"] for project in _PROJECTS])
def test_ten_projects_trace_chains_to_introduction_point(project):
    graph = dependency_graph_from_packages(project["packages"])

    paths = graph.paths_to(project["vulnerable"])

    assert len(paths) == project["path_count"]
    assert {path[0].canonical_name for path in paths} == project["roots"]
    for path in paths:
        assert path[-1].canonical_name == project["vulnerable"]
        assert all(child in graph.children(parent) for parent, child in zip(path, path[1:]))
