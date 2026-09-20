"""Cycle-safe dependency graph. No dependency edge implies runtime reachability."""

from collections import deque
from collections.abc import Iterable

from dam.domain import ROOT, Edge, Package


class DependencyGraph:
    def __init__(self, packages: dict[str, Package], edges: Iterable[Edge]) -> None:
        self.packages = packages
        self.edges = sorted(set(edges))
        self.children: dict[str, set[str]] = {name: set() for name in [ROOT, *packages]}
        self.parents: dict[str, set[str]] = {name: set() for name in [ROOT, *packages]}
        for edge in self.edges:
            self.children[edge.parent].add(edge.child)
            self.parents[edge.child].add(edge.parent)
        self.depths = self._depths()

    def _depths(self) -> dict[str, int]:
        depths = {ROOT: 0}
        queue = deque([ROOT])
        while queue:
            parent = queue.popleft()
            for child in sorted(self.children[parent]):
                if child not in depths:
                    depths[child] = depths[parent] + 1
                    queue.append(child)
        return depths

    def _traverse(self, name: str, adjacency: dict[str, set[str]]) -> set[str]:
        seen = {name}
        queue = deque([name])
        while queue:
            for item in adjacency[queue.popleft()]:
                if item not in seen:
                    seen.add(item)
                    queue.append(item)
        return seen - {name, ROOT}

    def ancestors(self, name: str) -> set[str]:
        return self._traverse(name, self.parents)

    def descendants(self, name: str) -> set[str]:
        return self._traverse(name, self.children)

    def shortest_path(self, name: str) -> list[str] | None:
        if name not in self.depths:
            return None
        path = [name]
        while path[-1] != ROOT:
            current = path[-1]
            path.append(
                min(
                    p
                    for p in self.parents[current]
                    if self.depths.get(p) == self.depths[current] - 1
                )
            )
        return list(reversed(path))

    def paths(
        self, name: str, limit: int = 20, budget: int = 10000
    ) -> tuple[list[list[str]], bool]:
        """Enumerate simple root paths, bounded even for cyclic/exponential graphs."""
        if name not in self.depths:
            return [], False
        paths: list[list[str]] = []
        stack = [[name]]
        steps = 0
        while stack and len(paths) < limit and steps < budget:
            path = stack.pop()
            steps += 1
            if path[-1] == ROOT:
                paths.append(list(reversed(path)))
                continue
            for parent in sorted(self.parents[path[-1]], reverse=True):
                if parent not in path:
                    stack.append([*path, parent])
                    if len(stack) >= budget:
                        return paths, True
        return paths, bool(stack)
