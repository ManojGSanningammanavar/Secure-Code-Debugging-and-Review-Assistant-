"""SQLite storage for users, repositories, files, findings, reviews and audit data."""
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin','reviewer','developer')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS repo_access (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path_prefix TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (user_id, repo_id, path_prefix)
);
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    content TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    loc INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    UNIQUE (repo_id, path)
);
CREATE TABLE IF NOT EXISTS build_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS analysis_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_id INTEGER NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    started_by TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    summary_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS functions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL,
    file_path TEXT NOT NULL,
    name TEXT NOT NULL,
    signature TEXT NOT NULL,
    start_line INTEGER NOT NULL,
    end_line INTEGER NOT NULL,
    metrics_json TEXT NOT NULL,
    calls_json TEXT NOT NULL,
    anomaly REAL NOT NULL DEFAULT 0,
    ml_label TEXT,
    ml_conf REAL DEFAULT 0,
    summary TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    repo_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    file_path TEXT NOT NULL,
    function TEXT,
    line INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    misra_ref TEXT DEFAULT '',
    cwe TEXT DEFAULT '',
    guideline TEXT DEFAULT '',
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    evidence TEXT NOT NULL,
    suggested_fix TEXT NOT NULL,
    rule_conf REAL NOT NULL,
    ml_conf REAL NOT NULL,
    triage_score REAL NOT NULL,
    confidence REAL NOT NULL,
    sources TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    reviewer TEXT,
    review_comment TEXT,
    reviewed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo_id, run_id);
CREATE TABLE IF NOT EXISTS dispositions (
    fingerprint TEXT PRIMARY KEY,
    repo_id INTEGER NOT NULL,
    status TEXT NOT NULL,
    reviewer TEXT NOT NULL,
    comment TEXT,
    features_json TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS qa_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    repo_id INTEGER NOT NULL,
    question TEXT NOT NULL,
    answer TEXT NOT NULL,
    citations_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT DEFAULT '',
    detail TEXT DEFAULT ''
);
"""


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    config.DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(config.DB_PATH), check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def get_conn():
    conn = connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(SCHEMA)


def rows(conn, sql: str, params=()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def row(conn, sql: str, params=()):
    r = conn.execute(sql, params).fetchone()
    return dict(r) if r else None


def audit(conn, username: str, action: str, target: str = "", detail: str = "") -> None:
    conn.execute(
        "INSERT INTO audit_log (ts, username, action, target, detail) VALUES (?,?,?,?,?)",
        (now_iso(), username, action, target, detail[:2000]),
    )
