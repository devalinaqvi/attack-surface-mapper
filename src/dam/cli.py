"""Small CLI boundary. Findings never change the exit code; errors return 2."""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from dam import __version__
from dam.analysis import scan
from dam.ecosystems.composer import ComposerAdapter
from dam.errors import AnalysisError
from dam.reporting import safe_text, text_report
from dam.security import Limits


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(
        prog="dam", description="Map dependency capabilities with evidence."
    )
    result.add_argument("--version", action="version", version=f"dam {__version__}")
    commands = result.add_subparsers(dest="command", required=True)
    for command in ["scan", "graph", "explain"]:
        sub = commands.add_parser(command)
        if command == "explain":
            sub.add_argument("package", help="Composer vendor/package name")
        sub.add_argument("lockfile", nargs="?", type=Path, default=Path("composer.lock"))
        sub.add_argument(
            "--manifest", type=Path, help="Root composer.json (auto-detected beside lockfile)"
        )
        sub.add_argument(
            "--no-dev", action="store_true", help="Exclude packages-dev and root require-dev"
        )
        sub.add_argument("--format", choices=["text", "json"], default="text")
        if command == "scan":
            sub.add_argument(
                "--inspect", action="store_true", help="Statically inspect local vendor files"
            )
            sub.add_argument(
                "--vendor-dir", type=Path, help="Explicit vendor directory; enables inspection"
            )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "scan":
            report = scan(
                args.lockfile,
                manifest=args.manifest,
                include_dev=not args.no_dev,
                inspect_content=args.inspect,
                vendor_dir=args.vendor_dir,
            )
            sys.stdout.write(
                json.dumps(report, indent=2, ensure_ascii=True) + "\n"
                if args.format == "json"
                else text_report(report)
            )
        else:
            project = ComposerAdapter().load(
                args.lockfile, args.manifest, not args.no_dev, Limits()
            )
            graph = project.graph
            if args.command == "graph":
                from dataclasses import asdict

                output = {
                    "root_known": project.root_known,
                    "packages": sorted(graph.packages),
                    "edges": [asdict(edge) for edge in graph.edges],
                    "requirements": project.requirements,
                    "warnings": project.warnings,
                }
                if args.format == "json":
                    print(json.dumps(output, indent=2))
                else:
                    print(f"Dependency graph: {safe_text(project.name)}")
                    for edge in graph.edges:
                        print(
                            safe_text(
                                f"{edge.parent} -> {edge.child} "
                                f"[{edge.requirement}; {edge.resolution}; {edge.scope}]"
                            )
                        )
                    for name in sorted(set(graph.packages) - graph.depths.keys()):
                        print(safe_text(f"{name} [no known root path]"))
                    for warning in project.warnings:
                        print("Note: " + safe_text(warning))
            else:
                if args.package not in graph.packages:
                    raise AnalysisError(f"Package not found: {args.package}")
                paths, truncated = graph.paths(args.package)
                output = {
                    "package": args.package,
                    "depth": graph.depths.get(args.package),
                    "shortest_path": graph.shortest_path(args.package),
                    "paths": paths,
                    "paths_truncated": truncated,
                    "parents": sorted(graph.parents[args.package]),
                    "ancestors": sorted(graph.ancestors(args.package)),
                    "descendants": sorted(graph.descendants(args.package)),
                    "warnings": project.warnings,
                }
                if args.format == "json":
                    print(json.dumps(output, indent=2))
                else:
                    print(safe_text(f"{args.package} | Depth: {output['depth']}"))
                    for path in paths:
                        print(" -> ".join(safe_text(p) for p in path))
                    if not paths:
                        print("No known root path.")
                    if truncated:
                        print("Paths truncated; the graph command preserves all dependency edges.")
                    for warning in project.warnings:
                        print("Note: " + safe_text(warning))
        return 0
    except (AnalysisError, OSError, ValueError) as exc:
        print(f"dam: {safe_text(exc)}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("dam: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
