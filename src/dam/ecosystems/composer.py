"""Composer semantics: only root require-dev/scripts apply to installation."""

import re
from pathlib import Path
from typing import Any

from dam.domain import ROOT, Capability, Confidence, Edge, Evidence, Finding, Package, Status
from dam.ecosystems import Project
from dam.errors import AnalysisError
from dam.graph import DependencyGraph
from dam.security import DEFAULT_LIMITS, Limits, load_json

NAME = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?/[a-z0-9](?:[a-z0-9_.-]*[a-z0-9])?$")
EVENTS = {
    "pre-install-cmd",
    "post-install-cmd",
    "pre-update-cmd",
    "post-update-cmd",
    "pre-autoload-dump",
    "post-autoload-dump",
    "post-root-package-install",
    "post-create-project-cmd",
    "pre-operations-exec",
    "pre-package-install",
    "post-package-install",
    "pre-package-update",
    "post-package-update",
    "pre-package-uninstall",
    "post-package-uninstall",
    "pre-file-download",
    "post-file-download",
}


def mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AnalysisError(f"{label} must be an object")
    return value


def requirements(metadata: dict[str, Any], key: str) -> dict[str, str]:
    raw = mapping(metadata.get(key, {}), key)
    if any(not isinstance(v, str) for v in raw.values()):
        raise AnalysisError(f"{key} constraints must be strings")
    return raw


def platform(name: str) -> bool:
    return name in {
        "php",
        "php-64bit",
        "php-ipv6",
        "php-zts",
        "php-debug",
        "composer",
        "composer-plugin-api",
        "composer-runtime-api",
    } or name.startswith(("ext-", "lib-"))


def plugin_matches(name: str, pattern: str) -> bool:
    """Composer's case-insensitive * glob; no shell ?/[] or regex backtracking."""
    name, pattern = name.lower(), pattern.lower()
    parts = pattern.split("*")
    if len(parts) == 1:
        return name == pattern
    prefix, suffix = parts[0], parts[-1]
    if (
        not name.startswith(prefix)
        or not name.endswith(suffix)
        or len(prefix) + len(suffix) > len(name)
    ):
        return False
    start, end = len(prefix), len(name) - len(suffix)
    for part in parts[1:-1]:
        index = name.find(part, start, end)
        if index < 0:
            return False
        start = index + len(part)
    return True


class ComposerAdapter:
    def load(
        self,
        lockfile: Path,
        manifest: Path | None = None,
        include_dev: bool = True,
        limits: Limits = DEFAULT_LIMITS,
    ) -> Project:
        lock = load_json(lockfile, limits)
        if "packages" not in lock:
            raise AnalysisError("composer.lock must contain a packages array")
        if manifest is None:
            candidate = lockfile.parent / "composer.json"
            if candidate.exists() or candidate.is_symlink():
                manifest = candidate
        root = load_json(manifest, limits) if manifest is not None else {}
        warnings: list[str] = []
        if manifest is None:
            warnings.append("No composer.json: direct dependencies and root paths are unknown.")
        packages: dict[str, Package] = {}
        all_names: set[str] = set()
        for section, dev in [("packages", False), ("packages-dev", True)]:
            records = lock.get(section, [])
            if not isinstance(records, list):
                raise AnalysisError(f"{section} must be an array")
            for record in records:
                raw = mapping(record, "package")
                name, version = raw.get("name"), raw.get("version")
                if not isinstance(name, str) or not NAME.fullmatch(name):
                    raise AnalysisError("Invalid Composer package name")
                if not isinstance(version, str) or not version:
                    raise AnalysisError(f"Missing or invalid version for {name}")
                if name in all_names:
                    raise AnalysisError(f"Duplicate package: {name}")
                all_names.add(name)
                if len(all_names) > limits.packages:
                    raise AnalysisError("Package count limit exceeded")
                for key in ["require", "require-dev", "provide", "replace"]:
                    requirements(raw, key)
                for key in ["autoload", "autoload-dev", "scripts", "extra"]:
                    mapping(raw.get(key, {}), key)
                package_type = raw.get("type", "library")
                if not isinstance(package_type, str):
                    raise AnalysisError(f"Invalid package type: {name}")
                if include_dev or not dev:
                    packages[name] = Package(name, version, package_type, dev, raw)
        providers: dict[str, list[tuple[str, str]]] = {}
        for name, package in packages.items():
            for kind in ["provide", "replace"]:
                for virtual in requirements(package.metadata, kind):
                    providers.setdefault(virtual, []).append((name, kind))
        root_provides = {**requirements(root, "provide"), **requirements(root, "replace")}
        edges: list[Edge] = []
        references: list[dict[str, Any]] = []
        pending = [(ROOT, root, "require", "runtime")]
        if include_dev:
            pending.append((ROOT, root, "require-dev", "development"))
        pending.extend(
            (name, package.metadata, "require", "runtime") for name, package in packages.items()
        )
        for parent, metadata, key, scope in pending:
            for requested, constraint in sorted(requirements(metadata, key).items()):
                if len(references) >= limits.edges:
                    raise AnalysisError("Requirement count limit exceeded")
                resolution = "exact"
                candidates: list[tuple[str, str]] = []
                if platform(requested):
                    resolution = "platform"
                elif requested in root_provides:
                    resolution = "root-provided"
                elif requested in packages:
                    candidates = [(requested, "exact")]
                elif requested in providers:
                    candidates = sorted(providers[requested])
                    resolution = "candidate-provider"
                else:
                    resolution = "unresolved"
                    warnings.append(
                        f"Unresolved requirement: {parent} -> {requested} ({constraint})"
                    )
                references.append(
                    {
                        "parent": parent,
                        "requirement": requested,
                        "constraint": constraint,
                        "resolution": resolution,
                        "scope": scope,
                    }
                )
                for child, kind in candidates:
                    if len(edges) >= limits.edges:
                        raise AnalysisError("Edge count limit exceeded")
                    edges.append(
                        Edge(
                            parent,
                            child,
                            requested,
                            constraint,
                            "exact" if kind == "exact" else f"candidate-{kind}",
                            scope,
                        )
                    )
        if any(edge.resolution != "exact" for edge in edges):
            warnings.append(
                "Virtual/replaced requirements use candidate provider edges; Composer "
                "version constraints and the solver's selected provider are not verified."
            )
        graph = DependencyGraph(packages, edges)
        name = root.get("name", lockfile.parent.name or "project")
        if not isinstance(name, str):
            raise AnalysisError("Project name must be a string")
        return Project(
            name,
            "composer",
            graph,
            root,
            manifest is not None,
            sorted(set(warnings)),
            references,
            lockfile.parent,
        )

    def detect_metadata(self, project: Project) -> list[Finding]:
        findings: list[Finding] = []
        scripts = mapping(project.root_metadata.get("scripts", {}), "root scripts")
        evidence = []
        for event in sorted(EVENTS & scripts.keys()):
            commands = scripts[event]
            if not isinstance(commands, (str, list)) or (
                isinstance(commands, list) and any(not isinstance(c, str) for c in commands)
            ):
                raise AnalysisError(f"Invalid script commands: {event}")
            if commands:
                evidence.append(
                    Evidence(
                        "composer_root_script",
                        "composer.json",
                        f"scripts.{event}",
                        f"Lifecycle hook declared: {commands!r}",
                        "Root lifecycle hooks can execute during Composer operations; "
                        "execution was not observed and --no-scripts can disable them.",
                    )
                )
        if evidence:
            findings.append(
                Finding(
                    ROOT,
                    Capability.INSTALL_EXECUTION,
                    Status.INFERRED,
                    Confidence.HIGH,
                    evidence,
                    {"execution": "conditional", "mechanism": "root_scripts"},
                )
            )
        config = mapping(project.root_metadata.get("config", {}), "config")
        allowed = config.get("allow-plugins", {})
        if not isinstance(allowed, (dict, bool)) or (
            isinstance(allowed, dict) and any(not isinstance(v, bool) for v in allowed.values())
        ):
            raise AnalysisError("config.allow-plugins must be a boolean or map of booleans")
        for name, package in sorted(project.graph.packages.items()):
            if package.package_type != "composer-plugin":
                continue
            permission = "unknown" if not project.root_known else "not-listed"
            if isinstance(allowed, bool):
                permission = "allowed" if allowed else "blocked"
            else:
                for pattern, enabled in allowed.items():
                    if plugin_matches(name, pattern):
                        permission = "allowed" if enabled else "blocked"
                        break
            findings.append(
                Finding(
                    name,
                    Capability.INSTALL_EXECUTION,
                    Status.INFERRED,
                    Confidence.HIGH,
                    [
                        Evidence(
                            "composer_plugin",
                            "composer.lock",
                            f"{name}.type",
                            "type = composer-plugin",
                            "Composer plugins can execute on Composer events; "
                            "activation depends on policy and command flags.",
                        )
                    ],
                    {"plugin_permission": permission, "execution": "conditional"},
                )
            )
        return findings
