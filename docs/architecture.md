# Architecture and decisions

```text
CLI -> analysis.scan -> EcosystemAdapter -> Project + DependencyGraph
                    -> metadata findings
                    -> LocalInspector -> ContentDetector -> findings
                    -> review ordering -> text/JSON report
```

`domain.py` defines packages, directed edges, evidence, confidence, capability vocabulary, and future evidence-backed attack nodes/edges. `graph.py` owns iterative, cycle-safe traversal. `ecosystems/composer.py` alone interprets Composer package records and lifecycle semantics. `security.py` bounds/parses JSON and pins filesystem descriptors. `inspection.py` inventories local artifacts, then applies native evidence aggregation. `analysis.py` coordinates those independent parts. The CLI only selects inputs and renders output.

The core accepts an adapter protocol and detector protocol without network, package-manager execution, persistence, or AI dependencies. The current local-content lookup assumes vendor/package layout and refuses unsafe identifiers; another ecosystem should supply its own content locator before using that inspection mode. Lock-only graph analysis remains independent of that convention.

## Dependency graph

All selected locked packages remain nodes, including disconnected packages. `@root` is a synthetic application node, not a counted dependency. Edges preserve requested name, constraint, scope, and resolution kind. Root require/require-dev and package require form installation edges; package require-dev does not. Platform requirements and unresolved requirements are separately retained. Virtual and replaced requirements expand to bounded candidate-provider edges; constraints are preserved but not evaluated. Root provide/replace is represented as a root-provided requirement.

Construction/traversal is O(V+E), apart from deterministic sorting and bounded provider expansion. Ancestor/descendant traversal and shortest paths handle cycles without recursion. Full edge storage preserves multiple parents; exponential simple path enumeration has count/work budgets and reports truncation. Reports use one shortest path per finding; `explain` exposes alternatives. An edge does not establish function calls, execution, or internet reachability.

## Evidence and priorities

Facts are observations such as a metadata declaration or file/header presence. Capability status describes interpretation separately from the evidence's own observed status. High confidence means strong evidence for the modeled capability, not high likelihood of compromise. Native build configuration plus native sources is stronger than one header filename. All artifact findings retain caveats about fixtures and unused code.

Review order 1 covers install mechanisms eligible for review before Composer operations. Order 2 covers corroborated native artifacts. Order 3 covers blocked plugins or weaker artifact evidence. These are transparent workflow ordering rules, not security severity or a risk score. Unknown runtime exposure is never promoted into an exposure claim.

## Security boundary

Bounded UTF-8 JSON rejects duplicate keys, nonstandard constants, wrong shapes, invalid package names, and excessive nesting. File paths are walked from a root descriptor using `O_NOFOLLOW`; local traversal uses pinned directory descriptors to resist symlink substitution. Only regular files/directories are accepted. Directory enumeration, depth, metadata size, total entries, evidence, and content reads have limits. No subprocess/network APIs are used by analysis. Files and directories can still change concurrently: reports are best-effort snapshots, not attestations. Source/version matching and filesystem snapshots are future work.

Local filenames are observed; arbitrary PHP or build script contents are not parsed in v0.1. Binary candidates contribute a four-byte magic observation at most. Sensitive files such as `.env` are not opened. Text rendering escapes Unicode controls, ANSI escapes, and embedded newlines in metadata.

## Extension path

New detectors return `Finding` objects; they should carry source locations and a justified confidence/status. New adapters return packages/edges and their own metadata findings. Application reachability must populate `AttackPath` nodes and edges from actual analysis with evidence; the v1 report intentionally forbids nonempty attack paths until that contract is versioned. Policy and diff engines should consume the report/API, separate from capability detection. Version plus retained source/dist metadata supports future provenance and comparison, but v0.1 does not claim integrity verification.

Fetching/archive inspection is deliberately absent. Before implementation, require bounded fetching, URL policy, limits on compressed/uncompressed bytes and entry counts, rejection of links/devices/absolute and traversal paths, temporary-directory cleanup, and malicious-archive tests. Avoid extraction entirely if stream inspection suffices.
