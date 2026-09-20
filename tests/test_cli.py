import json

from dam.cli import main


def test_scan_text(demo, capsys):
    assert main(["scan", str(demo), "--inspect"]) == 0
    output = capsys.readouterr().out
    assert "native_code" in output and "Introduced through" in output
    assert "Application reachability: unknown" in output


def test_scan_json(demo, capsys):
    assert main(["scan", str(demo), "--format", "json", "--no-dev"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "1.0.0"
    assert report["package_statistics"]["development"] == 0


def test_explain_graph(demo, capsys):
    assert main(["explain", "example/native", str(demo), "--format", "json"]) == 0
    assert len(json.loads(capsys.readouterr().out)["paths"]) == 3
    assert main(["graph", str(demo)]) == 0
    assert "example/framework -> example/bridge" in capsys.readouterr().out
    assert main(["graph", str(demo), "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["edges"]
    assert main(["explain", "example/native", str(demo)]) == 0
    assert "example/native" in capsys.readouterr().out


def test_errors(tmp_path, demo, capsys):
    assert main(["scan", str(tmp_path / "missing")]) == 2
    assert "Cannot safely read" in capsys.readouterr().err
    assert main(["explain", "missing/pkg", str(demo)]) == 2
    assert "Package not found" in capsys.readouterr().err


def test_empty_scan(project, capsys):
    assert main(["scan", str(project())]) == 0
    assert "No capability indicators" in capsys.readouterr().out
