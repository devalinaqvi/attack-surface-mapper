# Dependency Attack Surface Mapper

[![Built with OpenAI Codex](https://img.shields.io/badge/built%20with-OpenAI%20Codex-412991?logo=openai&logoColor=white)](https://openai.com/codex/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

**Capability over vulnerability.** A Python CLI and library that maps what Composer dependencies may be able to do, why they were flagged, and how they entered an application.

A vulnerability scanner connects packages to known CVEs. DAM connects dependencies to **capabilities, evidence, confidence, and dependency paths**. Capability is neither vulnerability nor maliciousness. V0.1 does not calculate a risk score or claim that dependency relationships prove application reachability.

## Quick start

Requires Python 3.10+ on Linux or macOS (POSIX descriptor-based file protection). No runtime dependencies. Windows users should use WSL with the project in the Linux filesystem. Open a terminal in the repository directory containing `pyproject.toml`:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
dam scan fixtures/demo/composer.lock --inspect
mkdir -p reports
dam scan /path/to/application/composer.lock --format json > reports/report.json
dam explain example/native fixtures/demo/composer.lock
dam graph fixtures/demo/composer.lock --format json
```

Metadata analysis is offline. Native artifact inspection is explicitly enabled with `--inspect` (conventional adjacent `vendor/`) or `--vendor-dir /path/to/vendor`. No package is downloaded, installed, extracted, imported, compiled, or executed. Missing local content is reported as unavailable, never as proof that a package lacks capabilities. Custom Composer installer paths and `config.vendor-dir` are not automatically followed; explicitly choose a trusted vendor root.

## What v0.1 finds

| Mechanism | Evidence and interpretation |
| --- | --- |
| Root install/update/autoload lifecycle scripts | Observed hook declarations; inferred execution capability, not observed execution |
| Composer plugins | Observed `composer-plugin` type; inferred capability with root `allow-plugins` context |
| Native source/build artifacts | Filenames, build configurations, and bounded binary magic inspection; aggregated confidence |
| Dependency provenance | All locked package nodes and require edges, root runtime/dev requirements, platform references, candidate virtual providers |

Composer executes **root scripts only**. Scripts declared by dependencies are retained as metadata but are not installation findings. `autoload.files`, `bin`, or `ext-*` requirements alone are not treated as install execution or native code inside a dependency. Plugins remain capability-bearing even when blocked; the report records that policy and lowers their review order. Global Composer plugin configuration is not read. Command flags and actual runtime execution cannot be established by static analysis.

[Composer scripts](https://getcomposer.org/doc/articles/scripts.md), [plugin permissions](https://getcomposer.org/doc/06-config.md#allow-plugins), and [package schema](https://getcomposer.org/doc/04-schema.md) inform these semantics.

## Example

The synthetic, non-executed fixture includes two root dependencies, a plugin, and native build artifacts:

```text
Project: example/laravel-app  |  Ecosystem: composer
Packages: 5  |  Direct: 2  |  Transitive: 3  |  Development: 1

example/native  /  native_code
  Status: inferred  |  Confidence: high  |  Depth: 2
  Introduced through: @root -> example/framework -> example/native
  - package_content:config.m4
  - package_content:ext/example.c
```

`dam explain` also preserves the alternative introductions through `example/bridge` and the development dependency. Full edges are always available in JSON. Root depth is 0; direct packages have depth 1. Explanation paths are bounded to 20 paths/10,000 expansion steps and explicitly indicate truncation.

## CLI and automation

- `dam scan [composer.lock] [--manifest composer.json] [--no-dev] [--inspect] [--vendor-dir PATH] [--format text|json]`
- `dam graph [composer.lock] [--manifest composer.json] [--no-dev] [--format text|json]`
- `dam explain vendor/package [composer.lock] [--manifest composer.json] [--no-dev] [--format text|json]`

Exit **0** means analysis completed (including partial coverage, explained in the report); **2** means input/usage/analysis failure; **130** means interruption. Findings do not fail CI. No policy enforcement is implemented yet. Redirect stdout for reports; errors go to stderr. Text output escapes terminal controls. JSON output encodes untrusted strings; consumers must also escape them when rendering.

Report schema: [`schemas/report-1.0.0.schema.json`](schemas/report-1.0.0.schema.json). `schema_version` describes the report contract separately from the tool version. Findings carry structured evidence, observation versus inference, confidence, review-order reasons, dependency context, and unknown application exposure. Ordering is deterministic; `generated_at` is the only intentional run-to-run difference on unchanged inputs.

## Python API

```python
from pathlib import Path
from dam.analysis import scan
from dam.ecosystems.composer import ComposerAdapter

report = scan("/path/to/composer.lock", inspect_content=True)
project = ComposerAdapter().load(Path("composer.lock"))
path = project.graph.shortest_path("vendor/package")
parents = project.graph.parents["vendor/package"]
```

The engine accepts an `EcosystemAdapter` and optional content detectors. See [architecture](docs/architecture.md) for extension boundaries and [security](SECURITY.md) for the threat model.

## Limits and honest uncertainty

- A lockfile alone does not identify direct dependencies. Without an adjacent/explicit manifest, direct/transitive counts and root paths are unknown. Unreachable nodes remain in the report.
- `provide`/`replace` edges are **candidates**, not a reimplementation of Composer's version solver. All candidates remain visible with a warning. Paths over them are potential introductions, not proven resolved paths. Manifest/lock consistency and installed content/version integrity are not verified.
- Only root `require-dev` affects installation. A dependency's `require-dev` is retained but not traversed. `--no-dev` excludes the lockfile's development section.
- Native detection uses artifact names and binary headers, not a full language parser. Fixtures, examples, unused sources, and mislabeled files can produce findings. Extension structure and source/build aggregation increase confidence but never establish execution.
- Network, subprocess, filesystem, FFI/API usage, privileges, and Laravel/application reachability are reserved capability types, not implemented detectors. `attack_paths` is empty. No CVE database, AI, or security-risk score is used.
- Content inspection rejects symlinks and special files, prunes nested `vendor`, `node_modules`, and VCS directories, and inspects only artifact names and binary headers. Its `complete` state means completion within this documented detector scope, not exhaustive source analysis. Package paths outside a conventional vendor tree require future adapter support.
- Defaults: 32 MiB per JSON document, 20,000 packages, 200,000 requirements/edges, 50,000 directory entries per scan, depth 40, 200 evidence entries per package. Global content bytes are bounded; current binary reads consume only four bytes per candidate. Budgets are configurable through `Limits` in the Python API. An incomplete scan is always reported.
- Archives and network fetching are unsupported. Archive traversal/extraction tests are intentionally deferred until that feature exists. See the security policy for mandatory controls before adding it.

## Development

Activate the virtual environment, then install the development tools:

```sh
python -m pip install -e '.[dev]'
make check             # tests + coverage, lint, format, strict types
make build             # wheel and sdist
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [roadmap](docs/roadmap.md), and [CHANGELOG.md](CHANGELOG.md). Synthetic fixture files are safe static examples, not installable dependencies. Local dogfooding uses only manifests and lockfiles; no unrelated project is modified.

## Documentation

- [Documentation index](docs/README.md)
- [Installation, real-project scans, and troubleshooting](docs/usage.md)
- [GitHub Actions, free-plan usage, and billing errors](docs/ci.md)
- [Report privacy and public-release review](docs/publication.md)
- [Architecture and extension points](docs/architecture.md)
- [Validation record](docs/validation.md)
- [Roadmap](docs/roadmap.md)

## Privacy

Reports can contain private package names, repository URLs, source references, and script commands copied from the input. DAM does not redact those values. Keep real scan reports private and review them before sharing. `reports/` is ignored by Git; the committed demo is synthetic. No GitHub account, API key, paid service, or Composer installation is required to run DAM locally.

## License and attribution

Licensed under [Apache License 2.0](LICENSE); see [NOTICE](NOTICE). Created by Ali Naqvi with assistance from OpenAI Codex, which wrote much of the initial implementation, tests, and documentation under review. Codex-assisted commits use the verified attribution trailer `Co-authored-by: Codex <noreply@openai.com>`. This records assistance and does not imply endorsement by OpenAI. See [AUTHORS.md](AUTHORS.md).
