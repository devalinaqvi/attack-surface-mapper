# Contributing

Use Python 3.10+ on Linux/macOS. Create a virtual environment and run `python -m pip install -e '.[dev]'`. Run `make check` before proposing changes. `make build` verifies wheel/sdist packaging. CI covers Python 3.10–3.13 on Linux.

Keep adapters ecosystem-specific and domain models/reporting reusable. For a detector, provide structured evidence, rationale, confidence, false-positive cases, and tests. Do not equate capability with maliciousness. Changes to report semantics must update the schema and compatibility documentation. Never execute analyzed code or run a package manager against fixtures. Do not add downloads, archive extraction, or application reachability without the security controls described in SECURITY.md.

Use synthetic fixtures. Local dogfooding should read only explicitly selected lockfiles/manifests, keep proprietary metadata out of commits, and never modify or install dependencies in the inspected projects. Tests should assert evidence and uncertainty, including malformed or adversarial input. Keep errors actionable and partial coverage visible.

Use descriptive commits and preserve configured Git identities. For Codex-assisted commits, use the trailer `Co-authored-by: Codex <noreply@openai.com>` once, separated from the body by a blank line. This address was verified against the installed Codex application. Do not invent other bot accounts or co-author addresses. GitHub attribution depends on its account/email mapping; a trailer alone does not guarantee a contributor-sidebar entry. Submit focused changes with validation results and relevant limitations.

Contributions are submitted under Apache License 2.0. Read [public-release privacy guidance](docs/publication.md) before adding fixtures, reports, or release artifacts.
