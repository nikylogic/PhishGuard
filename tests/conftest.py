import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from phishguard import create_app  # noqa: E402
from phishguard.db import connect  # noqa: E402


@pytest.fixture
def app(tmp_path):
    return create_app({"INSTANCE_DIR": str(tmp_path / "instance"), "TESTING": True})


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def con(app):
    c = connect(app.config["DATABASE"])
    yield c
    c.close()
