"""Ecosystem boundaries: adapters provide packages, edges and metadata detectors."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from dam.domain import Finding
from dam.graph import DependencyGraph
from dam.security import Limits


@dataclass
class Project:
    name: str
    ecosystem: str
    graph: DependencyGraph
    root_metadata: dict[str, Any]
    root_known: bool
    warnings: list[str]
    requirements: list[dict[str, Any]]
    directory: Path


class EcosystemAdapter(Protocol):
    def load(
        self, lockfile: Path, manifest: Path | None, include_dev: bool, limits: Limits
    ) -> Project: ...

    def detect_metadata(self, project: Project) -> list[Finding]: ...
