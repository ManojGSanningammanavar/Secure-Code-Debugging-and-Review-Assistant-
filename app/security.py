"""Authentication, role checks and repository/path-level authorization."""
import base64
import hashlib
import hmac
import json
import os
import posixpath
import time

from fastapi import Depends, Header, HTTPException, status

from . import config
from .database import get_conn, row, rows

ROLES = ("admin", "reviewer", "developer")


# ---------------------------------------------------------------- passwords
def hash_password(password: str, salt: bytes | None = None, iterations: int = 120_000) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt_hex, digest_hex = stored.split("$")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iterations))
        return hmac.compare_digest(digest.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------- tokens
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def create_token(username: str, role: str, ttl: int | None = None) -> str:
    payload = {"sub": username, "role": role, "exp": int(time.time()) + (ttl or config.TOKEN_TTL_SECONDS)}
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(config.SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def decode_token(token: str) -> dict:
    try:
        body, sig = token.split(".")
    except ValueError as exc:
        raise ValueError("malformed token") from exc
    expected = _b64(hmac.new(config.SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise ValueError("bad signature")
    payload = json.loads(_unb64(body))
    if payload.get("exp", 0) < time.time():
        raise ValueError("token expired")
    return payload


# ---------------------------------------------------------------- dependencies
def get_current_user(authorization: str = Header(default="")) -> dict:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing bearer token")
    try:
        payload = decode_token(authorization.split(" ", 1)[1].strip())
    except ValueError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"Invalid token: {exc}") from exc
    with get_conn() as conn:
        user = row(conn, "SELECT id, username, full_name, role FROM users WHERE username=?", (payload["sub"],))
    if not user:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown user")
    return user


def require_roles(*allowed: str):
    def checker(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in allowed:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"Requires role: {', '.join(allowed)}")
        return user

    return checker


# ---------------------------------------------------------------- authorization
def safe_relpath(path: str) -> str:
    """Normalise a repository-relative path and refuse traversal or absolute paths."""
    p = (path or "").replace("\\", "/").strip()
    if not p or p.startswith("/") or ":" in p.split("/")[0]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid path")
    norm = posixpath.normpath(p)
    if norm.startswith("..") or "/../" in f"/{norm}/":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Path traversal is not allowed")
    return norm


def repo_prefixes(conn, user: dict, repo_id: int) -> list[str] | None:
    """Return the path prefixes the user may read in a repo ([''] = whole repo, None = no access)."""
    if user["role"] == "admin":
        return [""]
    grants = rows(conn, "SELECT path_prefix FROM repo_access WHERE user_id=? AND repo_id=?", (user["id"], repo_id))
    if not grants:
        return None
    return [g["path_prefix"] for g in grants]


def path_allowed(prefixes: list[str] | None, path: str) -> bool:
    if prefixes is None:
        return False
    return any(pref == "" or path == pref.rstrip("/") or path.startswith(pref.rstrip("/") + "/") for pref in prefixes)


def ensure_repo_access(conn, user: dict, repo_id: int) -> list[str]:
    if not row(conn, "SELECT id FROM repositories WHERE id=?", (repo_id,)):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Repository not found")
    prefixes = repo_prefixes(conn, user, repo_id)
    if prefixes is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "You do not have access to this repository")
    return prefixes
