import json
from pathlib import Path

import pytest


@pytest.fixture
def project(tmp_path):
    def write(packages=None, root=None, dev=None):
        lock = tmp_path / "composer.lock"
        lock.write_text(json.dumps({"packages": packages or [], "packages-dev": dev or []}))
        if root is not None:
            (tmp_path / "composer.json").write_text(json.dumps(root))
        return lock

    return write


@pytest.fixture
def demo():
    return Path(__file__).resolve().parents[1] / "fixtures/demo/composer.lock"
