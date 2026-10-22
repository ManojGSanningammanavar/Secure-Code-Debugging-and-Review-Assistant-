import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_TMP = tempfile.mkdtemp(prefix="sentinel-test-")
os.environ["SENTINEL_VAR_DIR"] = _TMP
os.environ["OLLAMA_URL"] = ""
os.environ["SENTINEL_SECRET_KEY"] = "test-secret"

# reuse already-trained models (python -m app.ml.train) to keep tests fast; otherwise they train on startup
_models = ROOT / "var" / "models"
if _models.exists():
    shutil.copytree(_models, Path(_TMP) / "models")


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        yield c


def _login(client, user, pw):
    r = client.post("/api/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


@pytest.fixture(scope="session")
def reviewer(client):
    return _login(client, "reviewer", "review123")


@pytest.fixture(scope="session")
def dev(client):
    return _login(client, "dev", "dev123")


@pytest.fixture(scope="session")
def intern(client):
    return _login(client, "intern", "intern123")


@pytest.fixture(scope="session")
def repo_id(client, reviewer):
    return next(r["id"] for r in client.get("/api/repos", headers=reviewer).json() if r["name"] == "brake-ecu")
