import pytest

from dam.analysis import scan
from dam.domain import Confidence, Status
from dam.inspection import LocalInspector, NativeCodeDetector


def test_root_scripts_only(project):
    lock = project(
        [{"name": "a/b", "version": "1", "scripts": {"post-install-cmd": "evil"}}],
        {"require": {"a/b": "*"}, "scripts": {"post-install-cmd": "@custom", "custom": "evil"}},
    )
    findings = scan(lock)["findings"]
    assert len(findings) == 1 and findings[0]["package"] == "@root"
    assert findings[0]["status"] == "inferred"
    assert findings[0]["evidence"][0]["status"] == "observed"


@pytest.mark.parametrize(
    "policy,permission",
    [
        (True, "allowed"),
        (False, "blocked"),
        ({"a/*": True}, "allowed"),
        ({"a/b": False, "*": True}, "blocked"),
        ({}, "not-listed"),
    ],
)
def test_plugin_permissions(project, policy, permission):
    lock = project(
        [{"name": "a/b", "version": "1", "type": "composer-plugin"}],
        {"require": {"a/b": "*"}, "config": {"allow-plugins": policy}},
    )
    finding = scan(lock)["findings"][0]
    assert finding["context"]["plugin_permission"] == permission
    assert finding["exposure"]["application_reachability"] == "unknown"


def test_plugin_without_manifest(project):
    report = scan(project([{"name": "a/b", "version": "1", "type": "composer-plugin"}]))
    assert report["findings"][0]["context"]["plugin_permission"] == "unknown"


@pytest.mark.parametrize(
    "files,confidence,status",
    [
        ({"only.h": ""}, Confidence.LOW, Status.HEURISTIC),
        ({"test.c": ""}, Confidence.MEDIUM, Status.INFERRED),
        ({"config.m4": "", "ext/test.c": ""}, Confidence.HIGH, Status.INFERRED),
        ({"thing.dll": "text"}, Confidence.LOW, Status.HEURISTIC),
        ({"thing.so": b"\x7fELF"}, Confidence.MEDIUM, Status.INFERRED),
        ({"Cargo.toml": "", "src/lib.rs": ""}, Confidence.HIGH, Status.INFERRED),
    ],
)
def test_native_evidence(tmp_path, files, confidence, status):
    for name, value in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value.encode() if isinstance(value, str) else value)
    finding = NativeCodeDetector().detect("a/b", LocalInspector().inspect(tmp_path))[0]
    assert finding.confidence == confidence and finding.status == status
    assert all(
        e.source == "package_content" and e.location and e.rationale for e in finding.evidence
    )


def test_content_opt_in_and_missing(demo):
    report = scan(demo)
    assert not any(f["capability"] == "native_code" for f in report["findings"])
    assert report["analysis_metadata"]["content_coverage"] == {"not_requested": 5}
    report = scan(demo, inspect_content=True)
    native = next(f for f in report["findings"] if f["capability"] == "native_code")
    assert native["confidence"] == "high"
    assert report["analysis_metadata"]["content_coverage"] == {"complete": 1, "unavailable": 4}


@pytest.mark.parametrize(
    "event", ["post-package-install", "pre-package-update", "pre-file-download"]
)
def test_package_lifecycle_root_scripts(project, event):
    finding = scan(project(root={"scripts": {event: "Handler::run"}}))["findings"][0]
    assert finding["evidence"][0]["location"] == f"scripts.{event}"


@pytest.mark.parametrize(
    "pattern,expected",
    [
        ("A/B", True),
        ("a/*", True),
        ("*a*b*", True),
        ("*z*b", False),
        ("a/?", False),
        ("a/[b]", False),
        ("a/b*a/b", False),
        ("x*", False),
    ],
)
def test_composer_glob_semantics(pattern, expected):
    from dam.ecosystems.composer import plugin_matches

    assert plugin_matches("a/b", pattern) is expected
