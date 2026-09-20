"""Public orchestration API; adapters and detectors can be supplied by callers."""

from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dam import __version__
from dam.domain import ROOT, Capability, Finding
from dam.ecosystems import EcosystemAdapter
from dam.ecosystems.composer import ComposerAdapter
from dam.inspection import ContentDetector, LocalInspector, NativeCodeDetector
from dam.security import DEFAULT_LIMITS, Limits


def priority(finding: Finding) -> tuple[int, str]:
    """Review ordering only. No severity, objective risk or fabricated exposure score."""
    if finding.capability == Capability.INSTALL_EXECUTION:
        if finding.context.get("plugin_permission") == "blocked":
            return 2, "Execution mechanism declared, but root plugin policy blocks activation."
        return (
            0,
            "Installation/update execution mechanism warrants review before dependency operations.",
        )
    if finding.confidence.value == "high":
        return 1, "Multiple native artifact indicators corroborate the capability."
    return (
        2,
        "Limited native evidence; confirm whether it is used or only example/test content.",
    )


def scan(
    lockfile: str | Path,
    *,
    manifest: str | Path | None = None,
    include_dev: bool = True,
    inspect_content: bool = False,
    vendor_dir: str | Path | None = None,
    limits: Limits = DEFAULT_LIMITS,
    adapter: EcosystemAdapter | None = None,
    detectors: Sequence[ContentDetector] | None = None,
) -> dict[str, Any]:
    """Analyze metadata and optionally a conventional local vendor tree, without execution."""
    adapter = adapter or ComposerAdapter()
    project = adapter.load(
        Path(lockfile), Path(manifest) if manifest else None, include_dev, limits
    )
    graph = project.graph
    findings = adapter.detect_metadata(project)
    inspector = LocalInspector(limits)
    content_detectors = detectors if detectors is not None else [NativeCodeDetector()]
    coverage: dict[str, Any] = {}
    content_root = Path(vendor_dir) if vendor_dir is not None else project.directory / "vendor"
    if vendor_dir is not None:
        inspect_content = True
    for name in sorted(graph.packages):
        if inspect_content:
            # Adapter package identifiers are data, never trusted filesystem paths.
            parts = name.split("/")
            if len(parts) != 2 or any(part in {"", ".", ".."} for part in parts) or "\\" in name:
                raise ValueError("Package content lookup requires safe vendor/package identifiers")
            inspection = inspector.inspect(content_root / name)
            coverage[name] = {
                "state": inspection.state,
                "files_seen": inspection.files_seen,
                "warnings": inspection.warnings,
            }
            for detector in content_detectors:
                findings.extend(detector.detect(name, inspection))
        else:
            coverage[name] = {"state": "not_requested", "files_seen": 0, "warnings": []}
    direct = graph.children[ROOT]
    packages = []
    for name, package in sorted(graph.packages.items()):
        packages.append(
            {
                **asdict(package),
                "direct": (name in direct) if project.root_known else None,
                "depth": graph.depths.get(name),
                "content_inspection": coverage[name],
            }
        )
    output_findings = []
    for finding in sorted(findings, key=lambda f: (priority(f)[0], f.package, f.capability.value)):
        rank, reason = priority(finding)
        output_findings.append(
            {
                **asdict(finding),
                "depth": graph.depths.get(finding.package),
                "direct": (finding.package in direct) if project.root_known else None,
                "shortest_dependency_path": graph.shortest_path(finding.package),
                "exposure": {"application_reachability": "unknown"},
                "review_priority": {"order": rank + 1, "reason": reason},
            }
        )
    states = [c["state"] for c in coverage.values()]
    if not inspect_content:
        project.warnings.append(
            "Package contents were not inspected; native capability coverage is unknown."
        )
    elif any(state != "complete" for state in states):
        project.warnings.append(
            "Some package content is unavailable or partially inspected; "
            "see per-package coverage and warnings."
        )
    return {
        "schema_version": "1.0.0",
        "project": project.name,
        "ecosystem": project.ecosystem,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "package_statistics": {
            "total": len(packages),
            "direct": len(direct) if project.root_known else None,
            "transitive": (len(packages) - len(direct)) if project.root_known else None,
            "development": sum(p.development for p in graph.packages.values()),
            "unreachable_from_root": sum(p not in graph.depths for p in graph.packages),
        },
        "dependency_graph": {
            "root": ROOT,
            "root_known": project.root_known,
            "nodes": packages,
            "edges": [asdict(e) for e in graph.edges],
            "requirements": project.requirements,
        },
        "findings": output_findings,
        "capabilities": [capability.value for capability in Capability],
        "evidence": [asdict(e) for f in findings for e in f.evidence],
        "attack_paths": [],
        "analysis_metadata": {
            "tool_version": __version__,
            "include_dev": include_dev,
            "content_inspection_requested": inspect_content,
            "content_coverage": {state: states.count(state) for state in sorted(set(states))},
            "reachability": "not_analyzed",
            "network_used": False,
            "package_code_executed": False,
            "limits": asdict(limits),
            "warnings": sorted(set(project.warnings)),
            "detectors": [
                "composer_metadata",
                *([type(d).__name__ for d in content_detectors] if inspect_content else []),
            ],
        },
    }
