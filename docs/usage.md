# Install and run

## Requirements

Python 3.10 or newer on Linux/macOS; use WSL on Windows. No PHP, Composer executable, GitHub account, API keys, or subscription is required. Network access is needed to obtain Python packaging/development tools during installation; the analyzer itself runs offline. An existing `composer.lock` is the scan input. An adjacent `composer.json` gives direct dependencies and root script/plugin context.

## Installation

Clone the repository once it is available, or download and unpack its source. In the directory containing `pyproject.toml`:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
dam --version
dam --help
```

On distributions without venv support, install the distribution's Python venv package first. Activate `.venv` in each new terminal. Alternatively invoke `.venv/bin/dam` directly from the project directory. Use `python -m dam` within the activated environment if the console command is unavailable.

For development, use `python -m pip install -e '.[dev]'` instead. The editable install tracks source changes. After updating a non-editable checkout, run `python -m pip install --upgrade .` again.

## Try the synthetic demo

```sh
dam scan fixtures/demo/composer.lock --inspect
dam explain example/native fixtures/demo/composer.lock
dam graph fixtures/demo/composer.lock --format json
```

Expect five packages, two direct dependencies, three transitive dependencies, and findings for root lifecycle scripts, a blocked Composer plugin, and native build/source artifacts. Missing vendor content for the other fixture packages is intentional and reported as unavailable.

## Scan your application

Replace `/path/to/application` with your application's directory. DAM reads it; it does not install or change anything there.

```sh
dam scan /path/to/application/composer.lock
dam scan /path/to/application/composer.lock --no-dev
dam scan /path/to/application/composer.lock --inspect
dam scan /path/to/application/composer.lock --vendor-dir /path/to/existing/vendor
```

`--inspect` uses the adjacent conventional `vendor/` directory. An explicit `--vendor-dir` also enables inspection. DAM does not follow Composer custom installer paths automatically, download missing packages, or run Composer scripts. Content may not match the locked version; this release does not verify that integrity.

For a manifest in another location:

```sh
dam scan /path/to/composer.lock --manifest /path/to/composer.json
```

Choose the matching root manifest. Without one, direct/transitive classification and root paths are unknown. `--no-dev` excludes locked development packages and root development requirements.

## Save and interpret reports

From this tool's repository, `reports/` is ignored by Git:

```sh
mkdir -p reports
dam scan /path/to/application/composer.lock --format json > reports/report.json
dam scan /path/to/application/composer.lock > reports/report.txt
```

Reports retain input metadata, which can contain private URLs, package names, and script arguments. Keep real reports private. Git ignore rules do not redact reports and do not protect output directories in other repositories.

- `evidence.status: observed` describes a declaration, filename, or header read from the input.
- A finding's `inferred` or `heuristic` status describes what that observation suggests.
- Confidence is evidence strength, not vulnerability severity or likelihood of compromise.
- Review order is explained in each finding; it is not a risk score.
- `content_inspection.state` distinguishes complete, partial, unavailable, and not requested.
- Application reachability is unknown and attack paths are empty in v0.1.
- Exit 0 means completed analysis, possibly with partial coverage. Exit 2 means an input/usage failure. Exit 130 means interrupted execution. Findings do not fail CI.

Run `dam explain vendor/package /path/to/composer.lock` to inspect introduction paths. Graph edges marked `candidate-provide`/`candidate-replace` express possible virtual-package providers; the Composer version solver is not reimplemented.

## Troubleshooting

| Symptom | Resolution |
| --- | --- |
| `dam: command not found` | Activate `.venv`, install the project, or use `.venv/bin/dam`. |
| Input cannot be safely read | Check path/permissions and use real file paths; symlink path components are rejected. |
| Direct dependencies are unknown | Place the matching `composer.json` next to the lockfile or pass `--manifest`. |
| No native findings | Check whether inspection was requested and content coverage is complete; absence of findings is not proof of no native capability. |
| Partial inspection | Read per-package warnings in JSON for skipped links, special files, or resource limits. |
| No internet/network findings | Those detectors and Laravel reachability are future work, not v0.1 features. |
| GitHub job never starts | See [CI account/billing troubleshooting](ci.md); run local checks meanwhile. |

## Validate and build locally

```sh
. .venv/bin/activate
python -m pip install -e '.[dev]'
make check
make build
```

`make check` runs tests with coverage, Ruff lint/format checks, and strict mypy. `make build` produces a wheel and source distribution under `dist/`. On systems without `make`, run `python -m pytest --cov=dam`, `python -m ruff check .`, `python -m ruff format --check .`, `python -m mypy src`, and `python -m build`.
