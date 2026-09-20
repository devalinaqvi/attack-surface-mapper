# Validation record

Local dogfooding on 2026-09-20 used four existing Composer/Laravel lockfiles plus their adjacent root manifests. Package contents and unrelated files were not read; nothing was installed or executed. Private project metadata is not copied into fixtures or committed reports.

| Input | Packages | Direct | Transitive | Development | No known root path |
| --- | ---: | ---: | ---: | ---: | ---: |
| Local project A | 136 | 13 | 123 | 48 | 0 |
| Local project B | 115 | 11 | 104 | 36 | 0 |
| Local project C | 110 | 9 | 101 | 33 | 0 |
| Local project D | 115 | 10 | 105 | 38 | 0 |

Each report identified root lifecycle declarations, preserved candidate virtual/replaced package edges with explicit warnings, and reported native content coverage as unknown. These are smoke checks, not a correctness proof of Composer's solver or the inspected applications.

The automated suite covers synthetic graphs, cycle/depth behavior, multiple introduction paths, Composer lifecycle semantics, plugin policy, artifact evidence aggregation, stable output/schema validation, CLI exit behavior, malformed/duplicate/oversized JSON, special files, symlink escapes, resource limits, and no-execution/no-network behavior. It runs on Python 3.10 locally; CI is configured for additional versions.

Release checks completed locally: **71 tests passed**, **95.69% combined statement/branch coverage**, Ruff lint/format checks passed, and strict mypy passed for all 12 source modules. Both sdist and wheel built successfully. An isolated, offline installation of the wheel ran the demo CLI and validated its report against the schema shipped in the wheel. A review of source/documentation found no common private-key/token credential patterns; this is not a proof that arbitrary future inputs contain no secrets.
