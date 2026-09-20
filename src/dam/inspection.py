"""Bounded local inspection using pinned descriptors; no archive extraction or execution."""

import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from dam.domain import Capability, Confidence, Evidence, Finding, Status
from dam.errors import AnalysisError
from dam.security import DEFAULT_LIMITS, Limits, safe_open

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".rs"}
HEADER_SUFFIXES = {".h", ".hpp", ".hxx"}
BINARY_SUFFIXES = {".so", ".dll", ".dylib", ".a", ".lib", ".o", ".exe"}
BUILD_NAMES = {"config.m4", "config.w32", "binding.gyp", "CMakeLists.txt", "Cargo.toml"}
# Secret/config files and arbitrary source text are never opened by this detector.
PRUNED = {".git", ".svn", "node_modules", ".env", "vendor"}


@dataclass
class Inspection:
    state: str = "complete"
    files_seen: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class Budget:
    files: int = 0
    bytes: int = 0


class ContentDetector(Protocol):
    def detect(self, package: str, inspection: Inspection) -> list[Finding]: ...


class LocalInspector:
    def __init__(self, limits: Limits = DEFAULT_LIMITS) -> None:
        self.limits = limits
        self.budget = Budget()

    def inspect(self, path: Path) -> Inspection:
        result = Inspection()
        try:
            with safe_open(path, directory=True) as fd:
                self._walk(fd, "", 0, result)
        except FileNotFoundError:
            result.state = "unavailable"
        except (OSError, AnalysisError) as exc:
            result.state = "partial"
            result.warnings.append(f"Inspection stopped: {exc}")
        return result

    def _walk(self, fd: int, prefix: str, depth: int, result: Inspection) -> None:
        if depth > self.limits.directory_depth:
            raise AnalysisError("Directory depth limit exceeded")
        # Bound directory enumeration itself, before sorting or allocating all entries.
        entries = []
        with os.scandir(fd) as iterator:
            for entry in iterator:
                self.budget.files += 1
                if self.budget.files > self.limits.files:
                    raise AnalysisError("Global file count limit exceeded")
                entries.append(entry.name)
        for name in sorted(entries):
            relative = f"{prefix}/{name}" if prefix else name
            mode = os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                result.state = "partial"
                if len(result.warnings) < self.limits.evidence_per_package:
                    result.warnings.append(f"Skipped symlink or special file: {relative}")
                continue
            if stat.S_ISDIR(mode):
                if name in PRUNED:
                    continue
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    self._walk(child, relative, depth + 1, result)
                finally:
                    os.close(child)
                continue
            result.files_seen += 1
            suffix = Path(name).suffix.lower()
            kind, rationale = "", ""
            if name in BUILD_NAMES:
                kind = "native_build_configuration"
                rationale = "A build configuration filename indicates potential native compilation."
            elif suffix in SOURCE_SUFFIXES:
                kind = "native_source"
                rationale = (
                    "A native-language source filename is present; it may be a fixture or example."
                )
            elif suffix in HEADER_SUFFIXES:
                kind = "native_header"
                rationale = "A header filename is a weak native-code indicator on its own."
            elif suffix in BINARY_SUFFIXES:
                kind = "native_binary_filename"
                rationale = (
                    "A binary-like filename alone does not establish that the file is executable."
                )
            if not kind:
                continue
            if len(result.evidence) >= self.limits.evidence_per_package:
                raise AnalysisError("Evidence limit exceeded")
            result.evidence.append(
                Evidence(kind, "package_content", relative, f"File present: {relative}", rationale)
            )
            if suffix in BINARY_SUFFIXES:
                self._binary(fd, name, relative, result)

    def _binary(self, parent: int, name: str, relative: str, result: Inspection) -> None:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise AnalysisError("File changed to a special file during inspection")
            # Only the magic header is needed; never load a binary into memory or execute it.
            if self.limits.file_bytes < 4:
                raise AnalysisError("Per-file header byte limit exceeded")
            header = os.read(fd, 4)
            self.budget.bytes += len(header)
            if self.budget.bytes > self.limits.content_bytes:
                raise AnalysisError("Global content byte limit exceeded")
            if header.startswith(
                (
                    b"\x7fELF",
                    b"MZ",
                    b"\xfe\xed\xfa",
                    b"\xcf\xfa\xed\xfe",
                    b"\xce\xfa\xed\xfe",
                    b"\xca\xfe\xba\xbe",
                )
            ):
                if len(result.evidence) >= self.limits.evidence_per_package:
                    raise AnalysisError("Evidence limit exceeded")
                result.evidence.append(
                    Evidence(
                        "native_binary_header",
                        "package_content",
                        relative,
                        f"Native binary magic: {header.hex()}",
                        "A recognized executable/object format header was read; "
                        "validity and execution are not established.",
                    )
                )
        finally:
            os.close(fd)


class NativeCodeDetector:
    def detect(self, package: str, inspection: Inspection) -> list[Finding]:
        if not inspection.evidence:
            return []
        kinds = {e.kind for e in inspection.evidence}
        strong = "native_source" in kinds and "native_build_configuration" in kinds
        confidence = (
            Confidence.HIGH
            if strong
            else (
                Confidence.MEDIUM
                if kinds & {"native_source", "native_build_configuration", "native_binary_header"}
                else Confidence.LOW
            )
        )
        return [
            Finding(
                package,
                Capability.NATIVE_CODE,
                Status.INFERRED if confidence != Confidence.LOW else Status.HEURISTIC,
                confidence,
                inspection.evidence,
                {
                    "content_coverage": inspection.state,
                    "execution": "not_observed",
                    "build_verified": False,
                },
            )
        ]
