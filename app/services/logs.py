"""Build-log analysis: parse warnings, classify with ML, cluster into root-cause groups, link to findings."""
from collections import Counter
from pathlib import PurePosixPath

from ..analysis.log_parser import parse_log
from ..database import audit, now_iso, rows
from ..ml.models import get_registry
from ..security import path_allowed
from .pipeline import latest_run_id

LABELS = {"null_pointer": "Null pointer", "buffer_overflow": "Buffer / bounds", "uninitialized": "Uninitialised data",
          "integer_overflow": "Integer conversion / overflow", "resource_leak": "Resource leak", "div_by_zero": "Division by zero",
          "concurrency": "Concurrency", "style": "Style / hygiene", "build_config": "Build configuration"}
PRIORITY = {"build_config": 0, "buffer_overflow": 1, "null_pointer": 1, "uninitialized": 1, "div_by_zero": 1,
            "resource_leak": 2, "integer_overflow": 2, "concurrency": 2, "style": 3}


def analyze_log(conn, repo_id: int, name: str, content: str, username: str, prefixes: list[str]) -> dict:
    reg = get_registry()
    warnings = parse_log(content)
    repo_files = [r["path"] for r in rows(conn, "SELECT path FROM files WHERE repo_id=?", (repo_id,))]
    run_id = latest_run_id(conn, repo_id)
    findings = rows(conn, "SELECT id, file_path, line, title, severity FROM findings WHERE run_id=?", (run_id,)) if run_id else []

    visible = []
    for w in warnings:
        match = next((f for f in repo_files if f == w["file"] or (w["file"] and f.endswith("/" + PurePosixPath(w["file"]).name))), None)
        if match and not path_allowed(prefixes, match):
            continue  # do not reveal content outside the user's authorised paths
        visible.append((w, match))
    msgs = [w["message"] for w, _ in visible]
    preds = reg.logs.predict(msgs)
    clusters = reg.logs.cluster(msgs, [p["label"] for p in preds])

    out = []
    for (w, match), p, c in zip(visible, preds, clusters):
        linked = [f for f in findings if match and f["file_path"] == match and abs(f["line"] - w["line"]) <= 2]
        out.append({**w, "file": match or w["file"], "in_repo": bool(match), "category": p["label"],
                    "category_label": LABELS.get(p["label"], p["label"]), "confidence": round(p["confidence"], 3),
                    "cluster": c, "linked_findings": [{"id": f["id"], "title": f["title"], "severity": f["severity"]} for f in linked]})

    groups = {}
    for w in out:
        groups.setdefault(w["cluster"], []).append(w)
    cards = []
    for cid, items in groups.items():
        cat = Counter(i["category"] for i in items).most_common(1)[0][0]
        prio = PRIORITY.get(cat, 3)
        if any(i["level"] == "error" for i in items):
            prio = min(prio, 1)
        cards.append({
            "cluster": cid, "size": len(items), "category": cat, "category_label": LABELS.get(cat, cat),
            "representative": items[0]["message"], "files": sorted({i["file"] for i in items if i["file"]}),
            "levels": dict(Counter(i["level"] for i in items)), "priority": prio,
            "linked_findings": sum(len(i["linked_findings"]) for i in items),
        })
    cards.sort(key=lambda c: (c["priority"], -c["size"]))

    conn.execute("INSERT INTO build_logs (repo_id, name, content, created_at) VALUES (?,?,?,?)", (repo_id, name, content, now_iso()))
    audit(conn, username, "log.analyze", f"repo:{repo_id}", f"{name}: {len(out)} warnings, {len(cards)} clusters")
    return {
        "warnings": out, "clusters": cards,
        "stats": {"total": len(out), "errors": sum(1 for w in out if w["level"] == "error"),
                  "warnings": sum(1 for w in out if w["level"] == "warning"), "clusters": len(cards),
                  "linked": sum(1 for w in out if w["linked_findings"])},
    }
