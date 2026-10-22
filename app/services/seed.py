"""Demo seed: users with different roles/permissions, two repositories, a build log and a first analysis."""
import hashlib

from .. import config
from ..database import audit, get_conn, now_iso, row
from ..security import hash_password
from .pipeline import analyze_repository

USERS = [
    ("admin", "Asha Admin", "admin", "admin123"),
    ("reviewer", "Rahul Reviewer", "reviewer", "review123"),
    ("dev", "Divya Developer", "developer", "dev123"),
    ("intern", "Ishan Intern", "developer", "intern123"),
]
REPOS = [
    ("brake-ecu", "Brake ECU application software (pressure control, wheel speed, CAN, UDS diagnostics)"),
    ("infotainment-gw", "Infotainment gateway (restricted: not visible to brake team developers)"),
]
# (username, repo, path prefix)  '' = whole repository
GRANTS = [
    ("reviewer", "brake-ecu", ""), ("reviewer", "infotainment-gw", ""),
    ("dev", "brake-ecu", ""),
    ("intern", "brake-ecu", "src/com"), ("intern", "brake-ecu", "include"),
]


def upsert_file(conn, repo_id: int, path: str, content: str) -> None:
    sha = hashlib.sha256(content.encode()).hexdigest()
    loc = sum(1 for ln in content.splitlines() if ln.strip())
    conn.execute(
        """INSERT INTO files (repo_id, path, content, sha256, loc, updated_at) VALUES (?,?,?,?,?,?)
           ON CONFLICT(repo_id, path) DO UPDATE SET content=excluded.content, sha256=excluded.sha256,
           loc=excluded.loc, updated_at=excluded.updated_at""",
        (repo_id, path, content, sha, loc, now_iso()))


def seed_if_empty() -> bool:
    with get_conn() as conn:
        if row(conn, "SELECT id FROM users LIMIT 1"):
            return False
        for username, name, role, pw in USERS:
            conn.execute("INSERT INTO users (username, full_name, role, password_hash, created_at) VALUES (?,?,?,?,?)",
                         (username, name, role, hash_password(pw), now_iso()))
        for name, desc in REPOS:
            conn.execute("INSERT INTO repositories (name, description, created_at) VALUES (?,?,?)", (name, desc, now_iso()))
        for username, repo, prefix in GRANTS:
            u = row(conn, "SELECT id FROM users WHERE username=?", (username,))
            r = row(conn, "SELECT id FROM repositories WHERE name=?", (repo,))
            conn.execute("INSERT INTO repo_access (user_id, repo_id, path_prefix) VALUES (?,?,?)", (u["id"], r["id"], prefix))
        audit(conn, "system", "seed", "", "demo users and repositories created")

        if not config.SEED_DEMO_DATA:
            return True
        for name, _ in REPOS:
            repo = row(conn, "SELECT id FROM repositories WHERE name=?", (name,))
            root = config.SAMPLE_REPOS_DIR / name
            for p in sorted(root.rglob("*")):
                rel = p.relative_to(root).as_posix()
                if p.is_file() and p.suffix in (".c", ".h"):
                    upsert_file(conn, repo["id"], rel, p.read_text(encoding="utf-8"))
                elif p.is_file() and p.suffix == ".log":
                    conn.execute("INSERT INTO build_logs (repo_id, name, content, created_at) VALUES (?,?,?,?)",
                                 (repo["id"], p.name, p.read_text(encoding="utf-8"), now_iso()))
            analyze_repository(conn, repo["id"], "system")
    return True
