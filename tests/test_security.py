import os
from pathlib import Path
from unittest.mock import patch

import pytest

from dam.analysis import scan
from dam.errors import AnalysisError
from dam.inspection import LocalInspector
from dam.reporting import safe_text
from dam.security import Limits, load_json, parse_json, read_fd, safe_open


def test_static_only_no_execution(tmp_path, project):
    marker = tmp_path / "executed"
    lock = project(
        [
            {
                "name": "a/b",
                "version": "1",
                "type": "composer-plugin",
                "scripts": {"post-install-cmd": f"touch {marker}"},
            }
        ],
        {"scripts": {"post-install-cmd": f"touch {marker}"}},
    )
    content = tmp_path / "vendor/a/b"
    content.mkdir(parents=True)
    script = content / "payload.exe"
    script.write_text(f"#!/bin/sh\ntouch {marker}\n")
    script.chmod(0o755)
    (content / "config.m4").write_text(f"syscmd(touch {marker})")
    with (
        patch("subprocess.Popen", side_effect=AssertionError("Must not spawn processes")),
        patch("os.system", side_effect=AssertionError("Must not execute shell")),
        patch("socket.socket", side_effect=AssertionError("Must not access network")),
    ):
        report = scan(lock, inspect_content=True)
    assert report["findings"] and not marker.exists()


def test_symlink_package_and_parent(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.c").write_text("not allowed")
    link = tmp_path / "link"
    link.symlink_to(outside, target_is_directory=True)
    for path in [link, link / "nested"]:
        result = LocalInspector().inspect(path)
        assert result.state == "partial" and not result.evidence


def test_symlink_files_special_and_secret(tmp_path):
    outside = tmp_path / "outside.c"
    outside.write_text("not allowed")
    package = tmp_path / "package"
    package.mkdir()
    (package / "escape.c").symlink_to(outside)
    os.mkfifo(package / "pipe.so")
    (package / ".env").write_text("SECRET=must-not-read")
    (package / "plain.php").write_text("<?php system('anything');")
    result = LocalInspector().inspect(package)
    assert result.state == "partial" and not result.evidence
    assert len(result.warnings) == 2


def test_metadata_symlink_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.write_text('{"packages":[]}')
    link = tmp_path / "composer.lock"
    link.symlink_to(actual)
    with pytest.raises(AnalysisError):
        scan(link)


def test_fifo_metadata_rejected_without_blocking(tmp_path):
    path = tmp_path / "composer.lock"
    os.mkfifo(path)
    with pytest.raises(AnalysisError):
        scan(path)


def test_content_limits(tmp_path):
    (tmp_path / "one.c").write_text("")
    (tmp_path / "two.c").write_text("")
    for limits in [Limits(files=1), Limits(evidence_per_package=1)]:
        assert LocalInspector(limits).inspect(tmp_path).state == "partial"
    (tmp_path / "deep/more").mkdir(parents=True)
    assert LocalInspector(Limits(directory_depth=0)).inspect(tmp_path).state == "partial"


def test_global_budget(tmp_path):
    for name in ["one", "two"]:
        (tmp_path / name).mkdir()
        (tmp_path / name / "native.c").write_text("")
    inspector = LocalInspector(Limits(files=1))
    assert inspector.inspect(tmp_path / "one").state == "complete"
    assert inspector.inspect(tmp_path / "two").state == "partial"


def test_read_limit_invalid_encoding(tmp_path):
    path = tmp_path / "large"
    path.write_bytes(b"0123456789")
    with safe_open(path) as fd, pytest.raises(AnalysisError):
        read_fd(fd, 2)
    with pytest.raises(AnalysisError):
        parse_json(b"\xff", "invalid")
    assert load_json(Path(__file__).parents[1] / "fixtures/demo/composer.lock", Limits())[
        "packages"
    ]


def test_terminal_escapes():
    assert safe_text("hello\x1b[31m\n\u202eevil") == "hello\\u001b[31m\\u000a\\u202eevil"


def test_deep_but_parseable_json_rejected():
    with pytest.raises(AnalysisError, match="nesting"):
        parse_json(b'{"nested":' + b"[" * 70 + b"0" + b"]" * 70 + b"}", "nested")


def test_binary_read_budgets(tmp_path):
    (tmp_path / "native.so").write_bytes(b"\x7fELF")
    for limits in [Limits(file_bytes=1), Limits(content_bytes=1), Limits(evidence_per_package=1)]:
        result = LocalInspector(limits).inspect(tmp_path)
        assert result.state == "partial" and result.warnings
