"""Central configuration. Values come from environment variables or a local .env file."""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines) so no extra dependency is needed."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv(BASE_DIR / ".env")

VAR_DIR = Path(os.getenv("SENTINEL_VAR_DIR", str(BASE_DIR / "var")))
DATA_DIR = BASE_DIR / "data"
GUIDELINES_DIR = DATA_DIR / "guidelines"
SAMPLE_REPOS_DIR = DATA_DIR / "sample_repos"
FRONTEND_DIR = BASE_DIR / "frontend"

DB_PATH = VAR_DIR / "sentinel.db"
MODEL_DIR = VAR_DIR / "models"
INDEX_DIR = VAR_DIR / "index"
OUTBOX_DIR = VAR_DIR / "workflow_outbox"

SECRET_KEY = os.getenv("SENTINEL_SECRET_KEY", "dev-only-secret-change-me")
TOKEN_TTL_SECONDS = int(os.getenv("SENTINEL_TOKEN_TTL", "28800"))

# Local LLM (optional). Leave OLLAMA_URL empty to use the built-in grounded answer engine.
OLLAMA_URL = os.getenv("OLLAMA_URL", "").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "90"))

# Embeddings: "lsa" (built in, no download) or "sentence-transformers" (e.g. BAAI/bge-small-en-v1.5)
EMBEDDING_BACKEND = os.getenv("EMBEDDING_BACKEND", "lsa")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "BAAI/bge-small-en-v1.5")

MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", "2000000"))
ALLOWED_EXTENSIONS = {".c", ".h", ".log", ".txt"}
SEED_DEMO_DATA = os.getenv("SEED_DEMO_DATA", "true").lower() == "true"


def ensure_dirs() -> None:
    for d in (VAR_DIR, MODEL_DIR, INDEX_DIR, OUTBOX_DIR):
        d.mkdir(parents=True, exist_ok=True)
