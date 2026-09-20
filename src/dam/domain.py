"""Ecosystem-independent evidence and exposure vocabulary."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

ROOT = "@root"


class Capability(str, Enum):
    INSTALL_EXECUTION = "install_execution"
    NATIVE_CODE = "native_code"
    NETWORK_ACCESS = "network_access"
    SUBPROCESS_EXECUTION = "subprocess_execution"
    FILESYSTEM_ACCESS = "filesystem_access"
    DYNAMIC_CODE_LOADING = "dynamic_code_loading"
    ENVIRONMENT_ACCESS = "environment_access"
    PRIVILEGE_RELATED_OPERATIONS = "privilege_related_operations"
    INTERNET_FACING_REACH = "internet_facing_reach"


class Status(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    HEURISTIC = "heuristic"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Evidence:
    kind: str
    source: str
    location: str
    observation: str
    rationale: str
    status: Status = Status.OBSERVED


@dataclass
class Finding:
    package: str
    capability: Capability
    status: Status
    confidence: Confidence
    evidence: list[Evidence]
    context: dict[str, Any] = field(default_factory=dict)
    recommendation: str = "Review whether this capability is necessary for the application."


@dataclass
class Package:
    name: str
    version: str
    package_type: str
    development: bool
    metadata: dict[str, Any]


@dataclass(frozen=True, order=True)
class Edge:
    parent: str
    child: str
    requirement: str
    constraint: str
    resolution: str = "exact"
    scope: str = "runtime"


@dataclass(frozen=True)
class AttackNode:
    id: str
    kind: str
    label: str


@dataclass(frozen=True)
class AttackEdge:
    source: str
    target: str
    evidence: tuple[Evidence, ...]
    status: Status


@dataclass(frozen=True)
class AttackPath:
    """Reserved for evidence-backed application reachability; v0.1 emits none."""

    nodes: tuple[AttackNode, ...]
    edges: tuple[AttackEdge, ...]
    capability: Capability
