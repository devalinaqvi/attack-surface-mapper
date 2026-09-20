# Security policy

V0.1 analyzes untrusted metadata and static local files. It never executes analyzed code, invokes Composer, imports package code, fetches packages, or extracts archives. Supported environments are POSIX Python 3.10+. Treat this initial release as an analysis aid, not an integrity attestation or a guarantee that dependencies are safe.

## Reporting issues

For a parsing escape, unintended execution/read, resource-limit bypass, or report injection, use the repository host's private vulnerability reporting facility if enabled. If private reporting is unavailable, open a minimal issue requesting a private contact without publishing the exploit or sensitive input. Do not submit credentials, real secrets, or proprietary package contents. Include tool/Python/OS versions and a sanitized reproducer when a private channel is established. No monitored security email address is claimed by this repository.

## Boundaries

Symlinks/special files are rejected, including in parent paths. Traversal uses pinned descriptors and bounded enumeration. Metadata parsing and content inspection have independent budgets. Invalid metadata fails with exit 2; skipped/unavailable content remains explicitly visible in report coverage. Root scripts, binaries, plugins, and build files are data only. Terminal control characters are escaped in text output. JSON consumers must render data safely.

V0.1 performs no archive extraction. Future archive support must reject path traversal, absolute paths, symlinks/hardlinks and special entries, enforce download and decompression limits, isolate temporary storage, clean up after errors, and include adversarial tests before release.

Limits bound individual inputs and traversal; they are not an operating-system resource sandbox. Extremely constrained deployment environments should additionally impose process memory/CPU limits. Analysis is a best-effort snapshot of a potentially changing filesystem. No reachability, package-content provenance, or version-constraint proof is claimed.
