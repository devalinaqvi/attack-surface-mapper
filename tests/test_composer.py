import json

import pytest

from dam.analysis import scan
from dam.domain import ROOT
from dam.ecosystems.composer import ComposerAdapter
from dam.errors import AnalysisError
from dam.security import Limits


def pkg(name, **extra):
    return {"name": name, "version": "dev-main#odd+version", **extra}


def test_demo_graph(demo):
    project = ComposerAdapter().load(demo)
    graph = project.graph
    assert graph.shortest_path("example/native") == [ROOT, "example/framework", "example/native"]
    assert graph.parents["example/native"] == {"example/framework", "example/bridge"}
    paths, truncated = graph.paths("example/native")
    assert len(paths) == 3 and not truncated
    assert graph.ancestors("example/native") == {
        "example/framework",
        "example/bridge",
        "example/dev-tools",
    }
    assert "example/plugin" in graph.descendants("example/framework")
    assert graph.packages["example/native"].metadata["license"] == ["MIT"]


def test_lock_only_unknown(project):
    report = scan(project([pkg("a/b")]))
    assert report["package_statistics"]["direct"] is None
    assert report["dependency_graph"]["nodes"][0]["depth"] is None
    assert report["analysis_metadata"]["warnings"]


def test_dev_semantics(project):
    lock = project(
        [pkg("a/b", **{"require-dev": {"not/installed": "*"}})],
        {"require": {"a/b": "*"}, "require-dev": {"dev/tool": "*"}},
        [pkg("dev/tool")],
    )
    report = scan(lock, include_dev=False)
    assert report["package_statistics"]["total"] == 1
    assert not report["dependency_graph"]["nodes"][0]["development"]
    assert len(report["dependency_graph"]["edges"]) == 1
    assert not any("Unresolved" in w for w in report["analysis_metadata"]["warnings"])


def test_virtual_replace_platform_unresolved(project):
    lock = project(
        [
            pkg("a/b", require={"virtual/api": "^1", "php": "^8.2", "missing/x": "*"}),
            pkg("x/one", provide={"virtual/api": "1.0"}),
            pkg("x/two", replace={"virtual/api": "self.version"}),
        ],
        {"require": {"a/b": "*"}},
    )
    p = ComposerAdapter().load(lock)
    assert p.graph.children["a/b"] == {"x/one", "x/two"}
    assert {e.resolution for e in p.graph.edges} == {
        "exact",
        "candidate-provide",
        "candidate-replace",
    }
    assert {r["resolution"] for r in p.requirements} == {
        "exact",
        "platform",
        "unresolved",
        "candidate-provider",
    }


def test_root_replace(project):
    p = ComposerAdapter().load(
        project(
            [pkg("a/b", require={"x/y": "*"})], {"require": {"a/b": "*"}, "replace": {"x/y": "*"}}
        )
    )
    assert p.requirements[-1]["resolution"] == "root-provided"


@pytest.mark.parametrize(
    "packages,root",
    [
        ([pkg("a/b"), pkg("a/b")], {}),
        ([pkg("../../escape")], {}),
        ([{"name": "a/b"}], {}),
        ([pkg("a/b", require=[])], {}),
        ([pkg("a/b", require={"a/c": 12})], {}),
        ([pkg("a/b", type={})], {}),
        ([pkg("a/b", scripts=[])], {}),
        ([], {"name": []}),
        ([], {"scripts": {"post-install-cmd": [12]}}),
        ([], {"config": {"allow-plugins": {"a/b": "yes"}}}),
    ],
)
def test_reject_invalid_shapes(project, packages, root):
    with pytest.raises(AnalysisError):
        scan(project(packages, root))


@pytest.mark.parametrize(
    "raw",
    [
        "{}",
        '{"packages":{}}',
        '{"packages":[null]}',
        '{"packages":[],"packages":[]}',
        '{"packages":NaN}',
        "[1]",
        "{",
        '{"x":' + "[" * 1100 + "0" + "]" * 1100 + "}",
    ],
)
def test_malformed_json(tmp_path, raw):
    lock = tmp_path / "composer.lock"
    lock.write_text(raw)
    with pytest.raises(AnalysisError):
        scan(lock)


def test_budgets(project):
    lock = project([pkg("a/b"), pkg("c/d")], {"require": {"a/b": "*", "c/d": "*"}})
    for limits in [Limits(metadata_bytes=10), Limits(packages=1), Limits(edges=1)]:
        with pytest.raises(AnalysisError):
            scan(lock, limits=limits)


def test_all_metadata_retained(project):
    item = pkg(
        "a/b",
        source={"type": "git", "reference": "abc"},
        dist={"type": "zip"},
        autoload={"files": ["bootstrap.php"]},
        **{"autoload-dev": {"files": []}},
    )
    report = scan(project([item]))
    assert report["dependency_graph"]["nodes"][0]["metadata"] == item
    assert not report["findings"]  # autoload.files is not an install hook


def test_deterministic(demo):
    one, two = scan(demo, inspect_content=True), scan(demo, inspect_content=True)
    one.pop("generated_at")
    two.pop("generated_at")
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)
