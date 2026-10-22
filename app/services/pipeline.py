"""Analysis pipeline: parse -> rules -> ML models -> evidence fusion -> triage -> persist -> index."""
import hashlib
import json
import re
from pathlib import PurePosixPath

from ..analysis.c_parser import parse_c, summarize_function
from ..analysis.log_parser import parse_log
from ..analysis.rules import SEVERITY_ORDER, RawFinding, run_rules
from ..database import audit, now_iso, row, rows
from ..ml.dataset import DEFECT_CLASSES, triage_features
from ..ml.models import get_registry
from ..rag import retriever

CODE_EXT = (".c", ".h")
LOG_TO_FINDING = {"buffer_overflow": "buffer_overflow", "null_pointer": "null_pointer", "uninitialized": "uninitialized",
                  "integer_overflow": "integer_overflow", "resource_leak": "resource_leak", "div_by_zero": "div_by_zero",
                  "concurrency": "concurrency", "style": "control_flow", "build_config": "api_usage"}


def latest_run_id(conn, repo_id: int):
    r = row(conn, "SELECT MAX(id) AS id FROM analysis_runs WHERE repo_id=? AND status='completed'", (repo_id,))
    return r["id"] if r else None


def load_parsed(conn, repo_id: int):
    files = rows(conn, "SELECT path, content FROM files WHERE repo_id=? ORDER BY path", (repo_id,))
    return [parse_c(f["path"], f["content"]) for f in files if f["path"].endswith(CODE_EXT)]


def fingerprint(repo_id, f: RawFinding) -> str:
    """Stable identity of a finding (independent of line number) so reviewer decisions survive re-analysis."""
    evidence = re.sub(r"\s+", " ", f.evidence).strip()
    return hashlib.sha1(f"{repo_id}|{f.file_path}|{f.function}|{f.rule_id}|{evidence}".encode()).hexdigest()[:20]


def confidence(rule_conf: float, ml_conf: float, triage: float, corroborated: bool, rule_id: str, anomaly: float) -> float:
    if rule_conf > 0:
        c = 0.5 * rule_conf + 0.2 * ml_conf + 0.3 * triage + (0.08 if corroborated else 0.0)
    elif rule_id == "SC-ML-DEF":
        c = 0.85 * (0.55 * ml_conf + 0.45 * triage)
    else:
        c = 0.6 * anomaly + 0.4 * triage
    return round(min(c, 0.99), 3)


def _log_warnings(conn, repo_id: int) -> list[dict]:
    log = row(conn, "SELECT content FROM build_logs WHERE repo_id=? ORDER BY id DESC LIMIT 1", (repo_id,))
    if not log:
        return []
    warnings = parse_log(log["content"])
    if warnings:
        preds = get_registry().logs.predict([w["message"] for w in warnings])
        for w, p in zip(warnings, preds):
            w["category"] = LOG_TO_FINDING.get(p["label"], p["label"])
    return warnings


def _corroborated(f: RawFinding, warnings: list[dict]) -> bool:
    for w in warnings:
        if not w["file"] or w["line"] <= 0:
            continue
        same_file = w["file"] == f.file_path or PurePosixPath(w["file"]).name == PurePosixPath(f.file_path).name
        related = w.get("category") == f.category or (f.category == "security" and "format" in w.get("flag", "")) \
            or (f.category == "control_flow" and w.get("category") == "control_flow") \
            or (f.category == "api_usage" and w.get("category") in ("api_usage", "control_flow"))
        if same_file and abs(w["line"] - f.line) <= 2 and related:
            return True
    return False


def analyze_repository(conn, repo_id: int, username: str) -> dict:
    reg = get_registry()
    cur = conn.execute("INSERT INTO analysis_runs (repo_id, started_by, started_at, status) VALUES (?,?,?,?)",
                       (repo_id, username, now_iso(), "running"))
    run_id = cur.lastrowid
    parsed = load_parsed(conn, repo_id)

    # 1) deterministic rule engine
    findings = run_rules(parsed)

    # 2) prompt-injection detector over repository comments
    comments = [(pf, ln, txt) for pf in parsed for ln, txt in pf.comments if len(txt) >= 15]
    quarantined = 0
    for (pf, ln, txt), score in zip(comments, reg.injection.score([" ".join(c[2].split()) for c in comments])):
        if score >= 0.7:
            quarantined += 1
            fn = pf.function_at(ln) or pf.function_at(ln + 6)
            findings.append(RawFinding(
                rule_id="SC-SEC-03", file_path=pf.path, line=ln, function=fn.name if fn else None,
                message=f"Comment reads like an instruction to an AI tool (injection score {score:.2f}). It was quarantined from AI context.",
                evidence=" ".join(txt.split())[:200], rule_conf=round(score, 3), sources=["injection_model"]))

    # 3) defect classifier + complexity anomaly per function
    fn_list = [(pf, fn) for pf in parsed for fn in pf.functions]
    fn_code = ["\n".join(pf.source.splitlines()[fn.start_line - 1:fn.end_line]) for pf, fn in fn_list]
    preds = reg.defect.predict(fn_code)
    anomalies = reg.anomaly.score([fn.metrics for _, fn in fn_list])
    fn_meta = {(pf.path, fn.name): {"pred": p, "anomaly": a, "fn": fn} for (pf, fn), p, a in zip(fn_list, preds, anomalies)}

    rule_cats = {}
    for f in findings:
        rule_cats.setdefault((f.file_path, f.function), set()).add(f.category)
    for key, meta in fn_meta.items():
        pred, fn = meta["pred"], meta["fn"]
        if pred["label"] != "clean" and pred["confidence"] >= 0.6 and pred["label"] not in rule_cats.get(key, set()):
            findings.append(RawFinding(
                rule_id="SC-ML-DEF", file_path=key[0], line=fn.start_line, function=fn.name,
                title=f"ML-suspected {pred['label'].replace('_', ' ')}",
                message=f"The defect model predicts `{pred['label']}` for `{fn.name}` (p={pred['confidence']:.2f}) although no rule fired. Needs reviewer confirmation.",
                evidence=fn.signature, rule_conf=0.0, sources=["defect_model"]))
        if meta["anomaly"] >= 0.6 and fn.metrics["cyclomatic"] >= 10:
            findings.append(RawFinding(
                rule_id="SC-ML-CPLX", file_path=key[0], line=fn.start_line, function=fn.name,
                message=f"`{fn.name}` is a complexity outlier (anomaly {meta['anomaly']:.2f}, cyclomatic {fn.metrics['cyclomatic']}, nesting {fn.metrics['nesting']}).",
                evidence=fn.signature, rule_conf=0.0, sources=["anomaly_model"]))

    # 4) evidence fusion + triage model
    warnings = _log_warnings(conn, repo_id)
    feats, extras = [], []
    for f in findings:
        meta = fn_meta.get((f.file_path, f.function))
        pred = meta["pred"] if meta else None
        if f.rule_id == "SC-ML-DEF" and pred:
            ml_conf = pred["confidence"]
        elif pred and f.category in DEFECT_CLASSES:
            ml_conf = pred["probs"].get(f.category, 0.0)
        else:
            ml_conf = 0.0
        corr = _corroborated(f, warnings)
        anomaly = meta["anomaly"] if meta else 0.0
        test_code = 1 if re.search(r"(^|/)(test|tests|mock)", f.file_path) else 0
        feats.append(triage_features(f.category, f.severity, f.rule_conf, ml_conf, int(corr), anomaly, test_code))
        extras.append((ml_conf, corr, anomaly))
    triage = reg.triage.predict(feats)

    prior = {r["fingerprint"]: r for r in rows(conn, "SELECT * FROM dispositions WHERE repo_id=?", (repo_id,))}
    stats = {"total": 0, "by_severity": {}, "by_category": {}, "suppressed": 0}
    seen = set()
    for f, tri, (ml_conf, corr, anomaly) in zip(findings, triage, extras):
        fp = fingerprint(repo_id, f)
        if fp in seen:
            continue
        seen.add(fp)
        sources = list(f.sources)
        if ml_conf >= 0.5 and "defect_model" not in sources:
            sources.append("defect_model")
        if corr:
            sources.append("compiler_log")
        sources.append("triage_model")
        status, reviewer, comment, reviewed_at = "open", None, None, None
        if fp in prior:
            p = prior[fp]
            status, reviewer, comment, reviewed_at = p["status"], p["reviewer"], p["comment"], p["updated_at"]
            if status == "rejected":
                stats["suppressed"] += 1
        conn.execute(
            """INSERT INTO findings (run_id, repo_id, fingerprint, file_path, function, line, rule_id, misra_ref, cwe, guideline,
               category, severity, title, message, evidence, suggested_fix, rule_conf, ml_conf, triage_score, confidence, sources,
               status, reviewer, review_comment, reviewed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run_id, repo_id, fp, f.file_path, f.function, f.line, f.rule_id, f.misra_ref, f.cwe, f.guideline, f.category,
             f.severity, f.title, f.message, f.evidence, f.suggested_fix, round(f.rule_conf, 3), round(ml_conf, 3),
             round(tri, 3), confidence(f.rule_conf, ml_conf, tri, corr, f.rule_id, anomaly), json.dumps(sources),
             status, reviewer, comment, reviewed_at))
        stats["total"] += 1
        stats["by_severity"][f.severity] = stats["by_severity"].get(f.severity, 0) + 1
        stats["by_category"][f.category] = stats["by_category"].get(f.category, 0) + 1

    # 5) persist function summaries
    by_fn = {}
    for f in findings:
        by_fn.setdefault((f.file_path, f.function), []).append(f)
    for key, meta in fn_meta.items():
        fn = meta["fn"]
        conn.execute(
            """INSERT INTO functions (run_id, repo_id, file_path, name, signature, start_line, end_line, metrics_json, calls_json,
               anomaly, ml_label, ml_conf, summary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (run_id, repo_id, key[0], fn.name, fn.signature, fn.start_line, fn.end_line, json.dumps(fn.metrics),
             json.dumps(fn.calls), meta["anomaly"], meta["pred"]["label"], round(meta["pred"]["confidence"], 3),
             summarize_function(fn, by_fn.get(key))))

    # 6) refresh retrieval index
    retriever.build_index(repo_id, parsed)

    summary = {**stats, "files": len(parsed), "functions": len(fn_list), "quarantined_comments": quarantined,
               "log_warnings": len(warnings), "max_severity": max((SEVERITY_ORDER[f.severity] for f in findings), default=0)}
    conn.execute("UPDATE analysis_runs SET status='completed', finished_at=?, summary_json=? WHERE id=?",
                 (now_iso(), json.dumps(summary), run_id))
    audit(conn, username, "analysis.run", f"repo:{repo_id}", f"run {run_id}: {stats['total']} findings")
    return {"run_id": run_id, **summary}
