"""
Interfaces for formatting vulnerability results into a string representation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import TypeAlias

import pip_audit._fix as fix
import pip_audit._service as service
from pip_audit._dependency_graph import format_dependency_path

DependencyChains: TypeAlias = Mapping[
    service.Dependency | str,
    Sequence[Sequence[service.Dependency]],
]


def dependency_chains_for(
    dependency_chains: DependencyChains | None,
    dependency: service.Dependency,
) -> list[list[service.Dependency]]:
    """Look up dependency chains for a dependency."""

    if not dependency_chains:
        return []

    chains = dependency_chains.get(dependency)
    if chains is None:
        chains = dependency_chains.get(dependency.canonical_name)
    if chains is None:
        return []

    return [list(chain) for chain in chains]


def format_dependency_chains(
    dependency_chains: DependencyChains | None,
    dependency: service.Dependency,
) -> str:
    """Format all dependency chains for a dependency on a single line."""

    return "; ".join(
        format_dependency_path(chain)
        for chain in dependency_chains_for(dependency_chains, dependency)
    )


def vuln_id_url(vuln_id: str) -> str:
    """Return the OSV URL for a vulnerability ID."""
    return f"https://osv.dev/vulnerability/{vuln_id}"


def pypi_url(name: str) -> str:
    """Return the PyPI URL for a package."""
    return f"https://pypi.org/project/{name}/"


class VulnerabilityFormat(ABC):
    """
    Represents an abstract string representation for vulnerability results.
    """

    @property
    @abstractmethod
    def is_manifest(self) -> bool:  # pragma: no cover
        """
        Is this format a "manifest" format, i.e. one that prints a summary
        of all results?

        Manifest formats are always rendered emitted unconditionally, even
        if the audit results contain nothing out of the ordinary
        (no vulnerabilities, skips, or fixes).
        """
        raise NotImplementedError

    @abstractmethod
    def format(
        self,
        result: dict[service.Dependency, list[service.VulnerabilityResult]],
        fixes: list[fix.FixVersion],
        dependency_chains: DependencyChains | None = None,
    ) -> str:  # pragma: no cover
        """
        Convert a mapping of dependencies to vulnerabilities into a string.

        `dependency_chains`, when provided, maps packages to root-to-package
        dependency paths for display.
        """
        raise NotImplementedError
