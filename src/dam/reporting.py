"""Text rendering escapes all terminal controls from hostile metadata."""

import json
import unicodedata
from typing import Any


def safe_text(value: object) -> str:
    return "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C") else char
        for char in str(value)
    )


def text_report(report: dict[str, Any]) -> str:
    stats = report["package_statistics"]

    def known(value: object) -> str:
        return "unknown" if value is None else str(value)

    lines = [
        "Dependency Attack Surface Mapper",
        "Capability over vulnerability.",
        "",
        f"Project: {safe_text(report['project'])}  |  Ecosystem: {report['ecosystem']}",
        f"Packages: {stats['total']}  |  Direct: {known(stats['direct'])}  |  "
        f"Transitive: {known(stats['transitive'])}  |  Development: {stats['development']}",
        "",
        "CAPABILITY MAP",
    ]
    for finding in report["findings"]:
        lines.extend(
            [
                "",
                f"{safe_text(finding['package'])}  /  {finding['capability']}",
                f"  Status: {finding['status']}  |  Confidence: {finding['confidence']}  |  "
                f"Depth: {known(finding['depth'])}",
                f"  Review order {finding['review_priority']['order']}: "
                f"{finding['review_priority']['reason']}",
            ]
        )
        if finding["shortest_dependency_path"]:
            lines.append(
                "  Introduced through: "
                + " -> ".join(safe_text(p) for p in finding["shortest_dependency_path"])
            )
        else:
            lines.append("  Introduced through: unknown")
        for evidence in finding["evidence"][:8]:
            lines.extend(
                [
                    f"  - {safe_text(evidence['source'])}:{safe_text(evidence['location'])}",
                    f"    {safe_text(evidence['observation'])}",
                    f"    {safe_text(evidence['rationale'])}",
                ]
            )
        if len(finding["evidence"]) > 8:
            lines.append("  Additional evidence available in JSON output.")
        lines.append("  Context: " + safe_text(json.dumps(finding["context"], sort_keys=True)))
    if not report["findings"]:
        lines.append("No capability indicators detected within the analyzed coverage.")
    lines.extend(
        [
            "",
            "Application reachability: unknown (not analyzed).",
            "Capabilities are not vulnerabilities or evidence of maliciousness.",
        ]
    )
    for warning in report["analysis_metadata"]["warnings"]:
        lines.append(f"Note: {safe_text(warning)}")
    return "\n".join(lines) + "\n"
