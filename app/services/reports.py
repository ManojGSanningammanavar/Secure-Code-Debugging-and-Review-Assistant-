"""Structured review reports: JSON, Markdown and SARIF 2.1.0, plus workflow outbox export."""
import json
from datetime import datetime, timezone

from .. import config
from ..analysis.rules import RULES, SEVERITY_ORDER
from ..database import audit, row, rows
from ..security import path_allowed
from .pipeline import latest_run_id

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def collect(conn, repo_id: int, scope: str, prefixes: list[str]) -> tuple[dict, list[dict]]:
    repo = row(conn, "SELECT * FROM repositories WHERE id=?", (repo_id,))
    run_id = latest_run_id(conn, repo_id)
    if not run_id:
        return repo, []
    sql = "SELECT * FROM findings WHERE run_id=?"
    if scope == "approved":
        sql += " AND status='accepted'"
    items = [f for f in rows(conn, sql, (run_id,)) if path_allowed(prefixes, f["file_path"])]
    items.sort(key=lambda f: (-SEVERITY_ORDER[f["severity"]], -f["confidence"]))
    for f in items:
        f["sources"] = json.loads(f["sources"])
    return repo, items


def to_json(repo, items, scope) -> str:
    keys = ("id", "file_path", "function", "line", "rule_id", "misra_ref", "cwe", "guideline", "category", "severity", "title",
            "message", "evidence", "suggested_fix", "confidence", "triage_score", "sources", "status", "reviewer", "review_comment")
    return json.dumps({"tool": "ECU Sentinel", "generated_at": datetime.now(timezone.utc).isoformat(), "repository": repo["name"],
                       "scope": scope, "count": len(items), "findings": [{k: f[k] for k in keys} for f in items]}, indent=2)


def to_markdown(repo, items, scope) -> str:
    out = [f"# Code Review Report — {repo['name']}", "",
           f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M UTC} by ECU Sentinel · scope: **{scope}** · {len(items)} finding(s)", "",
           "| # | Severity | Rule | Location | Title | Confidence | Status |", "|---|---|---|---|---|---|---|"]
    for i, f in enumerate(items, 1):
        out.append(f"| {i} | {f['severity']} | {f['rule_id']} {f['misra_ref']} {f['cwe']} | `{f['file_path']}:{f['line']}` "
                   f"({f['function'] or '-'}) | {f['title']} | {f['confidence']:.0%} | {f['status']} |")
    out.append("")
    for i, f in enumerate(items, 1):
        out += [f"## {i}. {f['title']}", f"- **Location:** `{f['file_path']}:{f['line']}` in `{f['function'] or 'file scope'}`",
                f"- **Rule:** {f['rule_id']} · {f['misra_ref'] or '—'} · {f['cwe'] or '—'} · guideline {f['guideline']}",
                f"- **Evidence:** `{f['evidence']}`", f"- **Finding:** {f['message']}", f"- **Suggested fix:** {f['suggested_fix']}",
                f"- **Evidence sources:** {', '.join(f['sources'])}",
                f"- **Status:** {f['status']}" + (f" by {f['reviewer']} — {f['review_comment']}" if f["reviewer"] else ""), ""]
    out.append("> AI-assisted findings. Approved items were confirmed by an authorised reviewer.")
    return "\n".join(out)


def to_sarif(repo, items) -> str:
    used = sorted({f["rule_id"] for f in items})
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ECU Sentinel", "version": "1.0.0", "rules": [
                {"id": r, "name": RULES[r]["title"], "shortDescription": {"text": RULES[r]["title"]},
                 "help": {"text": RULES[r]["fix"]},
                 "properties": {"misra": RULES[r]["misra"], "cwe": RULES[r]["cwe"], "category": RULES[r]["category"]}} for r in used]}},
            "results": [{
                "ruleId": f["rule_id"], "level": SARIF_LEVEL[f["severity"]], "message": {"text": f["message"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file_path"]}, "region": {"startLine": f["line"]}}}],
                "partialFingerprints": {"ecuSentinel/v1": f["fingerprint"]},
                "properties": {"confidence": f["confidence"], "status": f["status"], "severity": f["severity"]},
            } for f in items],
        }],
    }, indent=2)


def render(conn, repo_id: int, fmt: str, scope: str, prefixes: list[str]) -> tuple[str, str, str]:
    repo, items = collect(conn, repo_id, scope, prefixes)
    if fmt == "md":
        return to_markdown(repo, items, scope), "text/markdown", f"{repo['name']}-review.md"
    if fmt == "sarif":
        return to_sarif(repo, items), "application/sarif+json", f"{repo['name']}-review.sarif"
    return to_json(repo, items, scope), "application/json", f"{repo['name']}-review.json"


def push_to_workflow(conn, repo_id: int, username: str, prefixes: list[str]) -> dict:
    """Write approved findings to the workflow outbox (integration point for Jira/Polarion/internal tracker)."""
    repo, items = collect(conn, repo_id, "approved", prefixes)
    config.OUTBOX_DIR.mkdir(parents=True, exist_ok=True)
    name = f"{repo['name']}-{datetime.now(timezone.utc):%Y%m%dT%H%M%S%f}.json"
    (config.OUTBOX_DIR / name).write_text(to_json(repo, items, "approved"), encoding="utf-8")
    audit(conn, username, "workflow.push", f"repo:{repo_id}", f"{len(items)} approved findings -> {name}")
    return {"file": name, "count": len(items)}
