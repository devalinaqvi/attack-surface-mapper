from dam.domain import ROOT, Edge, Package
from dam.graph import DependencyGraph


def graph(names, edges):
    return DependencyGraph(
        {n: Package(n, "1", "library", False, {}) for n in names},
        [Edge(a, b, b, "*") for a, b in edges],
    )


def test_cycles_and_disconnected():
    g = graph(["a", "b", "c"], [(ROOT, "a"), ("a", "b"), ("b", "a")])
    assert g.ancestors("a") == {"b"}
    assert g.descendants("a") == {"b"}
    assert g.shortest_path("c") is None
    assert g.paths("c") == ([], False)
    assert g.paths("b") == ([[ROOT, "a", "b"]], False)


def test_deep_iterative_traversal():
    names = [str(i) for i in range(1600)]
    g = graph(names, [(ROOT, "0"), *zip(names, names[1:], strict=False)])
    assert g.depths["1599"] == 1600
    assert len(g.shortest_path("1599")) == 1601
    assert len(g.ancestors("1599")) == 1599
    assert len(g.paths("1599")[0][0]) == 1601


def test_path_bounds():
    g = graph(["a", "b", "c"], [(ROOT, "a"), (ROOT, "b"), ("a", "c"), ("b", "c")])
    paths, truncated = g.paths("c", limit=1)
    assert len(paths) == 1 and truncated
    assert g.paths("c", budget=1)[1]
