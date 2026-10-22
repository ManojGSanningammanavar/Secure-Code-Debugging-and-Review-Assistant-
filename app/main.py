"""ECU Sentinel API (FastAPI) + static single-page UI."""
import json
import time
from collections import defaultdict
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from . import config
from .analysis.rules import RULES, SEVERITY_ORDER
from .database import audit, get_conn, init_db, now_iso, row, rows
from .ml.dataset import triage_features
from .ml.models import get_registry
from .rag import llm, retriever
from .schemas import FileWrite, LoginRequest, LogRequest, QuestionRequest, RepoCreate, ReviewRequest
from .security import (create_token, ensure_repo_access, get_current_user, path_allowed, repo_prefixes, require_roles,
                       safe_relpath, verify_password)
from .services import assistant, logs, reports
from .services.pipeline import analyze_repository, confidence, latest_run_id
from .services.seed import seed_if_empty, upsert_file

SEV_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


@asynccontextmanager
async def lifespan(_app: FastAPI):
    config.ensure_dirs()
    init_db()
    get_registry()  # loads models; trains them on first start (~10-20 s)
    seed_if_empty()
    yield


app = FastAPI(title="ECU Sentinel", version="1.0.0", description="Secure Code Debugging & Review Assistant", lifespan=lifespan)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                                   "connect-src 'self'; frame-ancestors 'none'")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


# ------------------------------------------------------------------ auth
_failed: dict = defaultdict(list)


@app.post("/api/auth/login")
def login(body: LoginRequest):
    now = time.time()
    _failed[body.username] = [t for t in _failed[body.username] if now - t < 60]
    if len(_failed[body.username]) >= 5:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many failed attempts. Try again in a minute.")
    with get_conn() as conn:
        user = row(conn, "SELECT * FROM users WHERE username=?", (body.username,))
        if not user or not verify_password(body.password, user["password_hash"]):
            _failed[body.username].append(now)
            audit(conn, body.username, "auth.failed")
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid username or password")
        audit(conn, user["username"], "auth.login")
    return {"token": create_token(user["username"], user["role"]),
            "user": {k: user[k] for k in ("id", "username", "full_name", "role")}}


@app.get("/api/auth/me")
def me(user: dict = Depends(get_current_user)):
    return user


@app.get("/api/health")
def health():
    return {"status": "ok", "llm": "ollama" if llm.available() else "grounded-engine (offline)",
            "embeddings": config.EMBEDDING_BACKEND, "models": list(get_registry().metrics().keys())}


# ------------------------------------------------------------------ repositories & files
def _repo_summary(conn, repo: dict, prefixes) -> dict:
    run_id = latest_run_id(conn, repo["id"])
    files = [f for f in rows(conn, "SELECT path FROM files WHERE repo_id=?", (repo["id"],)) if path_allowed(prefixes, f["path"])]
    fnd = [f for f in rows(conn, "SELECT file_path, severity, status FROM findings WHERE run_id=?", (run_id,))
           if path_allowed(prefixes, f["file_path"])] if run_id else []
    run = row(conn, "SELECT id, started_at, started_by FROM analysis_runs WHERE id=?", (run_id,)) if run_id else None
    return {**repo, "files": len(files), "open_findings": sum(1 for f in fnd if f["status"] == "open"),
            "critical_high": sum(1 for f in fnd if f["severity"] in ("critical", "high") and f["status"] in ("open", "accepted")),
            "scope": "full" if prefixes == [""] else ", ".join(prefixes),
            "last_run": {"id": run["id"], "at": run["started_at"], "by": run["started_by"]} if run else None}


@app.get("/api/repos")
def list_repos(user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        out = []
        for repo in rows(conn, "SELECT * FROM repositories ORDER BY name"):
            prefixes = repo_prefixes(conn, user, repo["id"])
            if prefixes is not None:
                out.append(_repo_summary(conn, repo, prefixes))
        return out


@app.post("/api/repos", status_code=201)
def create_repo(body: RepoCreate, user: dict = Depends(require_roles("admin"))):
    with get_conn() as conn:
        if row(conn, "SELECT id FROM repositories WHERE name=?", (body.name,)):
            raise HTTPException(409, "Repository already exists")
        cur = conn.execute("INSERT INTO repositories (name, description, created_at) VALUES (?,?,?)", (body.name, body.description, now_iso()))
        audit(conn, user["username"], "repo.create", body.name)
        return {"id": cur.lastrowid, "name": body.name}


@app.get("/api/repos/{repo_id}/files")
def list_files(repo_id: int, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        run_id = latest_run_id(conn, repo_id)
        fnd = rows(conn, "SELECT file_path, severity, confidence FROM findings WHERE run_id=? AND status IN ('open','accepted')", (run_id,)) if run_id else []
        out = []
        for f in rows(conn, "SELECT path, loc, updated_at FROM files WHERE repo_id=? ORDER BY path", (repo_id,)):
            if not path_allowed(prefixes, f["path"]):
                continue
            mine = [x for x in fnd if x["file_path"] == f["path"]]
            risk = sum(SEV_WEIGHT[x["severity"]] * x["confidence"] for x in mine)
            out.append({**f, "findings": len(mine), "risk": round(risk, 2),
                        "max_severity": max((x["severity"] for x in mine), key=lambda s: SEVERITY_ORDER[s], default=None)})
        return out


@app.get("/api/repos/{repo_id}/file")
def get_file(repo_id: int, path: str = Query(...), user: dict = Depends(get_current_user)):
    path = safe_relpath(path)
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        if not path_allowed(prefixes, path):
            audit(conn, user["username"], "access.denied", f"repo:{repo_id}:{path}")
            raise HTTPException(403, "You are not authorised to read this path")
        f = row(conn, "SELECT path, content, loc, updated_at FROM files WHERE repo_id=? AND path=?", (repo_id, path))
        if not f:
            raise HTTPException(404, "File not found")
        run_id = latest_run_id(conn, repo_id)
        fns = rows(conn, "SELECT * FROM functions WHERE run_id=? AND file_path=? ORDER BY start_line", (run_id, path)) if run_id else []
        for fn in fns:
            fn["metrics"] = json.loads(fn.pop("metrics_json"))
            fn["calls"] = json.loads(fn.pop("calls_json"))
        fnd = rows(conn, "SELECT id, line, severity, title, rule_id, status, confidence FROM findings WHERE run_id=? AND file_path=? ORDER BY line",
                   (run_id, path)) if run_id else []
        audit(conn, user["username"], "file.read", f"repo:{repo_id}:{path}")
        return {**f, "functions": fns, "findings": fnd}


@app.post("/api/repos/{repo_id}/files")
def write_file(repo_id: int, body: FileWrite, user: dict = Depends(get_current_user)):
    path = safe_relpath(body.path)
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        if not path_allowed(prefixes, path):
            raise HTTPException(403, "You are not authorised to write this path")
        upsert_file(conn, repo_id, path, body.content)
        retriever.invalidate(repo_id)
        audit(conn, user["username"], "file.write", f"repo:{repo_id}:{path}")
    return {"path": path, "saved": True}


@app.post("/api/repos/{repo_id}/upload")
async def upload(repo_id: int, files: list[UploadFile] = File(...), folder: str = Form(default="src"),
                 user: dict = Depends(get_current_user)):
    saved, logs_saved, skipped = [], [], []
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        for up in files:
            name = (up.filename or "").replace("\\", "/").split("/")[-1]
            ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
            data = await up.read()
            if ext not in config.ALLOWED_EXTENSIONS or len(data) > config.MAX_UPLOAD_BYTES:
                skipped.append(name)
                continue
            text = data.decode("utf-8", errors="replace")
            if ext in (".log", ".txt"):
                conn.execute("INSERT INTO build_logs (repo_id, name, content, created_at) VALUES (?,?,?,?)", (repo_id, name, text, now_iso()))
                logs_saved.append(name)
                continue
            target_dir = "include" if ext == ".h" and folder == "src" else folder.strip("/")
            path = safe_relpath(f"{target_dir}/{name}" if target_dir else name)
            if not path_allowed(prefixes, path):
                skipped.append(name)
                continue
            upsert_file(conn, repo_id, path, text)
            saved.append(path)
        retriever.invalidate(repo_id)
        audit(conn, user["username"], "file.upload", f"repo:{repo_id}", f"saved={saved} logs={logs_saved} skipped={skipped}")
    return {"saved": saved, "logs": logs_saved, "skipped": skipped}


@app.post("/api/repos/{repo_id}/analyze")
def analyze(repo_id: int, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        if prefixes != [""]:
            raise HTTPException(403, "Full-repository analysis requires access to the whole repository")
        t0 = time.time()
        result = analyze_repository(conn, repo_id, user["username"])
        result["duration_ms"] = int((time.time() - t0) * 1000)
        return result


@app.get("/api/repos/{repo_id}/runs")
def runs(repo_id: int, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        ensure_repo_access(conn, user, repo_id)
        out = rows(conn, "SELECT id, started_by, started_at, finished_at, status, summary_json FROM analysis_runs WHERE repo_id=? ORDER BY id DESC LIMIT 20", (repo_id,))
        for r in out:
            r["summary"] = json.loads(r.pop("summary_json") or "{}")
        return out


# ------------------------------------------------------------------ findings & review workflow
def _finding_out(f: dict) -> dict:
    f["sources"] = json.loads(f["sources"]) if isinstance(f["sources"], str) else f["sources"]
    return f


@app.get("/api/findings")
def list_findings(repo_id: int, severity: str = "", status_: str = Query("", alias="status"), category: str = "", q: str = "",
                  user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        run_id = latest_run_id(conn, repo_id)
        if not run_id:
            return []
        items = [f for f in rows(conn, "SELECT * FROM findings WHERE run_id=?", (run_id,)) if path_allowed(prefixes, f["file_path"])]
    if severity:
        items = [f for f in items if f["severity"] in severity.split(",")]
    if status_:
        items = [f for f in items if f["status"] in status_.split(",")]
    if category:
        items = [f for f in items if f["category"] in category.split(",")]
    if q:
        ql = q.lower()
        items = [f for f in items if ql in f"{f['title']} {f['message']} {f['file_path']} {f['function']} {f['rule_id']} {f['misra_ref']} {f['cwe']}".lower()]
    items.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], -f["confidence"]))
    return [_finding_out(f) for f in items]


def _get_finding(conn, user, finding_id: int) -> dict:
    f = row(conn, "SELECT * FROM findings WHERE id=?", (finding_id,))
    if not f:
        raise HTTPException(404, "Finding not found")
    prefixes = ensure_repo_access(conn, user, f["repo_id"])
    if not path_allowed(prefixes, f["file_path"]):
        raise HTTPException(403, "You are not authorised to view this finding")
    return f


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        f = _get_finding(conn, user, finding_id)
        file = row(conn, "SELECT content FROM files WHERE repo_id=? AND path=?", (f["repo_id"], f["file_path"]))
        lines = file["content"].splitlines() if file else []
        lo, hi = max(1, f["line"] - 6), min(len(lines), f["line"] + 6)
        f["context"] = [{"n": i, "text": lines[i - 1]} for i in range(lo, hi + 1)]
        f["rule"] = RULES.get(f["rule_id"], {})
        return _finding_out(f)


@app.get("/api/findings/{finding_id}/explain")
def explain(finding_id: int, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        f = _get_finding(conn, user, finding_id)
        return assistant.explain_finding(conn, f)


def _features_for(conn, f: dict) -> dict:
    fn = row(conn, "SELECT anomaly FROM functions WHERE run_id=? AND file_path=? AND name=?", (f["run_id"], f["file_path"], f["function"] or ""))
    sources = json.loads(f["sources"]) if isinstance(f["sources"], str) else f["sources"]
    return triage_features(f["category"], f["severity"], f["rule_conf"], f["ml_conf"], int("compiler_log" in sources),
                           fn["anomaly"] if fn else 0.0, int("test" in f["file_path"]))


@app.post("/api/findings/{finding_id}/review")
def review(finding_id: int, body: ReviewRequest, user: dict = Depends(get_current_user)):
    if body.status in ("accepted", "rejected", "open") and user["role"] not in ("reviewer", "admin"):
        raise HTTPException(403, "Only reviewers can accept, reject or reopen findings")
    if body.status == "rejected" and not body.comment.strip():
        raise HTTPException(422, "A reason is required when rejecting a finding")
    with get_conn() as conn:
        f = _get_finding(conn, user, finding_id)
        ts = now_iso()
        conn.execute("UPDATE findings SET status=?, reviewer=?, review_comment=?, reviewed_at=? WHERE fingerprint=? AND repo_id=?",
                     (body.status, user["username"], body.comment, ts, f["fingerprint"], f["repo_id"]))
        conn.execute("""INSERT INTO dispositions (fingerprint, repo_id, status, reviewer, comment, features_json, updated_at)
                        VALUES (?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET status=excluded.status,
                        reviewer=excluded.reviewer, comment=excluded.comment, updated_at=excluded.updated_at""",
                     (f["fingerprint"], f["repo_id"], body.status, user["username"], body.comment, json.dumps(_features_for(conn, f)), ts))
        audit(conn, user["username"], f"finding.{body.status}", f"finding:{finding_id}", body.comment)
        return {"id": finding_id, "status": body.status, "reviewer": user["username"], "reviewed_at": ts}


# ------------------------------------------------------------------ logs, Q&A
@app.post("/api/logs/analyze")
def analyze_log(body: LogRequest, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, body.repo_id)
        return logs.analyze_log(conn, body.repo_id, body.name, body.content, user["username"], prefixes)


@app.get("/api/repos/{repo_id}/logs")
def list_logs(repo_id: int, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        if prefixes != [""]:
            return []  # raw logs may reference files outside the user's paths
        return rows(conn, "SELECT id, name, created_at, content FROM build_logs WHERE repo_id=? ORDER BY id DESC LIMIT 10", (repo_id,))


@app.post("/api/qa")
def ask(body: QuestionRequest, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, body.repo_id)
        return assistant.answer_question(conn, user, body.repo_id, body.question, prefixes)


# ------------------------------------------------------------------ dashboard
@app.get("/api/dashboard")
def dashboard(repo_id: int, user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        run_id = latest_run_id(conn, repo_id)
        items = [_finding_out(f) for f in rows(conn, "SELECT * FROM findings WHERE run_id=?", (run_id,))
                 if path_allowed(prefixes, f["file_path"])] if run_id else []
        fns = [f for f in rows(conn, "SELECT file_path, name, anomaly, metrics_json, ml_label, ml_conf FROM functions WHERE run_id=?", (run_id,))
               if path_allowed(prefixes, f["file_path"])] if run_id else []
        history = rows(conn, "SELECT id, started_at, summary_json FROM analysis_runs WHERE repo_id=? AND status='completed' ORDER BY id DESC LIMIT 10", (repo_id,))
    active = [f for f in items if f["status"] != "rejected"]
    reviewed = [f for f in items if f["status"] in ("accepted", "rejected", "fixed")]
    accepted = sum(1 for f in reviewed if f["status"] in ("accepted", "fixed"))
    file_risk = {}
    for f in active:
        if f["status"] in ("open", "accepted"):
            e = file_risk.setdefault(f["file_path"], {"path": f["file_path"], "score": 0.0, "findings": 0})
            e["score"] += SEV_WEIGHT[f["severity"]] * f["confidence"]
            e["findings"] += 1
    hotspots = sorted(({"file": f["file_path"], "function": f["name"], "anomaly": f["anomaly"],
                        "cyclomatic": json.loads(f["metrics_json"])["cyclomatic"], "ml_label": f["ml_label"]} for f in fns),
                      key=lambda x: -x["anomaly"])[:5]
    trend = []
    for h in reversed(history):
        s = json.loads(h["summary_json"] or "{}")
        bs = s.get("by_severity", {})
        trend.append({"run": h["id"], "at": h["started_at"], "total": s.get("total", 0), "high": bs.get("high", 0) + bs.get("critical", 0)})
    by_category = {}
    for f in active:
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
    return {
        "kpis": {
            "open": sum(1 for f in items if f["status"] == "open"),
            "critical_high": sum(1 for f in active if f["severity"] in ("critical", "high") and f["status"] in ("open", "accepted")),
            "accepted": accepted, "rejected": sum(1 for f in reviewed if f["status"] == "rejected"),
            "precision": round(accepted / len(reviewed), 3) if reviewed else None,
            "avg_confidence": round(sum(f["confidence"] for f in active) / len(active), 3) if active else 0,
            "files": len({f["file_path"] for f in fns}), "functions": len(fns),
            "ml_corroborated": sum(1 for f in active if "defect_model" in f["sources"]),
            "log_corroborated": sum(1 for f in active if "compiler_log" in f["sources"]),
        },
        "by_severity": {s: sum(1 for f in active if f["severity"] == s) for s in ("critical", "high", "medium", "low")},
        "by_category": by_category,
        "by_status": {s: sum(1 for f in items if f["status"] == s) for s in ("open", "accepted", "rejected", "fixed", "disputed")},
        "file_risk": sorted(({**v, "score": round(v["score"], 2)} for v in file_risk.values()), key=lambda x: -x["score"]),
        "hotspots": hotspots,
        "trend": trend,
        "top": sorted((f for f in active if f["status"] == "open"), key=lambda f: (-SEVERITY_ORDER[f["severity"]], -f["confidence"]))[:6],
    }


# ------------------------------------------------------------------ models
@app.get("/api/models")
def models(user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        labels = row(conn, "SELECT COUNT(*) AS n FROM dispositions WHERE status IN ('accepted','rejected','fixed')")["n"]
    return {"metrics": get_registry().metrics(), "reviewer_labels_available": labels,
            "llm": {"configured": bool(config.OLLAMA_URL), "available": llm.available(), "model": config.OLLAMA_MODEL},
            "embeddings": config.EMBEDDING_BACKEND}


@app.post("/api/models/retrain")
def retrain(user: dict = Depends(require_roles("reviewer", "admin"))):
    reg = get_registry()
    with get_conn() as conn:
        disp = rows(conn, "SELECT status, features_json FROM dispositions WHERE status IN ('accepted','rejected','fixed')")
        extra = ([json.loads(d["features_json"]) for d in disp], [0 if d["status"] == "rejected" else 1 for d in disp])
        metrics = reg.train_triage(extra)
        reg.save()
        rescored = 0  # re-score the latest run of every repository with the updated model
        for repo in rows(conn, "SELECT id FROM repositories"):
            run_id = latest_run_id(conn, repo["id"])
            items = rows(conn, "SELECT * FROM findings WHERE run_id=?", (run_id,)) if run_id else []
            if not items:
                continue
            feats = [_features_for(conn, f) for f in items]
            for f, feat, tri in zip(items, feats, reg.triage.predict(feats)):
                conf = confidence(f["rule_conf"], f["ml_conf"], tri, bool(feat["corroborated"]), f["rule_id"], feat["anomaly"])
                conn.execute("UPDATE findings SET triage_score=?, confidence=? WHERE id=?", (round(tri, 3), conf, f["id"]))
                rescored += 1
        audit(conn, user["username"], "model.retrain", "triage_model", f"{len(disp)} reviewer labels, {rescored} findings re-scored")
    return {"metrics": metrics, "reviewer_labels": len(disp), "rescored": rescored}


# ------------------------------------------------------------------ reports & audit
@app.get("/api/reports/{repo_id}")
def report(repo_id: int, fmt: str = Query("json", pattern="^(json|md|sarif)$"), scope: str = Query("approved", pattern="^(approved|all)$"),
           user: dict = Depends(get_current_user)):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        body, media, filename = reports.render(conn, repo_id, fmt, scope, prefixes)
        audit(conn, user["username"], "report.export", f"repo:{repo_id}", f"{fmt}/{scope}")
    return Response(content=body, media_type=media, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@app.post("/api/reports/{repo_id}/push")
def push(repo_id: int, user: dict = Depends(require_roles("reviewer", "admin"))):
    with get_conn() as conn:
        prefixes = ensure_repo_access(conn, user, repo_id)
        return reports.push_to_workflow(conn, repo_id, user["username"], prefixes)


@app.get("/api/audit")
def audit_log(limit: int = Query(200, le=1000), user: dict = Depends(require_roles("admin", "reviewer"))):
    with get_conn() as conn:
        return rows(conn, "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))


@app.get("/api/users")
def users(user: dict = Depends(require_roles("admin"))):
    with get_conn() as conn:
        out = rows(conn, "SELECT id, username, full_name, role, created_at FROM users ORDER BY id")
        for u in out:
            u["grants"] = rows(conn, """SELECT r.name AS repo, a.path_prefix FROM repo_access a JOIN repositories r ON r.id=a.repo_id
                                       WHERE a.user_id=?""", (u["id"],))
        return out


@app.exception_handler(Exception)
async def unhandled(_request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"detail": f"Internal error: {type(exc).__name__}"})


app.mount("/", StaticFiles(directory=str(config.FRONTEND_DIR), html=True), name="ui")
