"""Bounded input handling. All paths are read without following symlinks (POSIX)."""

import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dam.errors import AnalysisError


@dataclass(frozen=True)
class Limits:
    metadata_bytes: int = 32 * 1024 * 1024
    packages: int = 20000
    edges: int = 200000
    files: int = 50000
    file_bytes: int = 2 * 1024 * 1024
    content_bytes: int = 128 * 1024 * 1024
    directory_depth: int = 40
    evidence_per_package: int = 200


DEFAULT_LIMITS = Limits()


@contextmanager
def safe_open(path: Path, directory: bool = False) -> Iterator[int]:
    """Open each component relative to a pinned descriptor; reject links and special files."""
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(absolute.parts[1:]):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(absolute.parts) - 2 or directory:
                flags |= os.O_DIRECTORY
            next_fd = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        mode = os.fstat(fd).st_mode
        if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
            raise AnalysisError(f"Not a regular {'directory' if directory else 'file'}: {path}")
        yield fd
    finally:
        os.close(fd)


def read_fd(fd: int, limit: int) -> bytes:
    if os.fstat(fd).st_size > limit:
        raise AnalysisError(f"File exceeds {limit} byte limit")
    chunks: list[bytes] = []
    remaining = limit + 1
    while remaining:
        chunk = os.read(fd, min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    result = b"".join(chunks)
    if len(result) > limit:
        raise AnalysisError(f"File exceeds {limit} byte limit")
    return result


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AnalysisError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise AnalysisError(f"Invalid JSON constant: {value}")


def parse_json(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            data.decode("utf-8"), object_pairs_hook=_unique, parse_constant=_constant
        )
        if not isinstance(value, dict):
            raise AnalysisError(f"{label}: expected a JSON object")
        pending: list[tuple[Any, int]] = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 64:
                raise AnalysisError(f"{label}: JSON nesting exceeds 64 levels")
            if isinstance(item, dict):
                pending.extend(
                    (child, depth + 1) for child in item.values() if isinstance(child, (dict, list))
                )
            elif isinstance(item, list):
                pending.extend(
                    (child, depth + 1) for child in item if isinstance(child, (dict, list))
                )
        return value
    except (ValueError, RecursionError) as exc:
        raise AnalysisError(f"{label}: invalid or excessively nested JSON") from exc


def load_json(path: Path, limits: Limits) -> dict[str, Any]:
    try:
        with safe_open(path) as fd:
            return parse_json(read_fd(fd, limits.metadata_bytes), str(path))
    except OSError as exc:
        raise AnalysisError(f"Cannot safely read {path}: {exc.strerror}") from exc
