"""Repository-aware Q&A and finding explanations (RAG with citations, injection-safe)."""
import json
import re

from ..database import audit, now_iso, rows
from ..ml.models import get_registry
from ..rag import llm, retriever
from ..security import path_allowed
from .pipeline import latest_run_id, load_parsed


def _index(conn, repo_id: int):
    idx = retriever.load_index(repo_id)
    if idx is None:
        idx = retriever.build_index(repo_id, load_parsed(conn, repo_id))
    return idx


def _first_sentences(text: str, n: int = 2) -> str:
    body = "\n".join(line for line in text.splitlines() if not line.startswith("#")).strip()
    parts = re.split(r"(?<=[.!?])\s+", " ".join(body.split()))
    return " ".join(parts[:n])


def _quarantine(blocks: list[dict]) -> tuple[list[dict], int]:
    """Drop code chunks whose comments look like prompt injection (they are data, never instructions)."""
    reg = get_registry()
    safe, dropped = [], 0
    for b in blocks:
        if b["kind"] == "code":
            comments = re.findall(r"/\*.*?\*/|//[^\n]*", b["text"], re.S)
            texts = [" ".join(c.strip("/* \n").replace("*", " ").split()) for c in comments]
            if texts and any(s >= 0.7 for s in reg.injection.score(texts)):
                dropped += 1
                continue
        safe.append(b)
    return safe, dropped


def _compose(question: str, blocks: list[dict], fn_rows: dict, fn_findings: dict) -> str:
    """Deterministic grounded answer used when no local LLM is configured."""
    if not blocks:
        return "I could not find grounded material in the code you can access or in the internal guidelines for that question."
    lines = []
    named = [b for b in blocks if b["kind"] == "code" and b.get("function")
             and re.search(rf"\b{re.escape(b['function'])}\b", question, re.I)]
    focus = named[:2] or blocks[:1]
    for b in focus:
        n = blocks.index(b) + 1
        if b["kind"] == "guideline":
            lines.append(f"**{b['title']}** — {_first_sentences(b['text'], 4)} [{n}]")
            continue
        info = fn_rows.get((b["path"], b.get("function")))
        if info:
            lines.append(f"**{b['function']}()** in `{b['path']}` (lines {b['start_line']}–{b['end_line']}): {info['summary']} [{n}]")
        else:
            lines.append(f"`{b['path']}` (lines {b['start_line']}–{b['end_line']}) is the most relevant code. [{n}]")
        fnd = fn_findings.get((b["path"], b.get("function")), [])
        if fnd:
            items = "; ".join(f"{f['title']} (line {f['line']}, {f['severity']})" for f in fnd[:4])
            lines.append(f"Open review findings here: {items}. [{n}]")
    others = [b for b in blocks if b not in focus]
    if others:
        lines.append("\n**Related sources**")
    for b in others[:4]:
        n = blocks.index(b) + 1
        if b["kind"] == "guideline":
            lines.append(f"- **{b['title']}**: {_first_sentences(b['text'], 2)} [{n}]")
        elif b.get("function"):
            info = fn_rows.get((b["path"], b["function"]))
            desc = info["summary"].split(". ")[0] + "." if info else ""
            lines.append(f"- `{b['function']}()` in `{b['path']}`: {desc} [{n}]")
        else:
            lines.append(f"- Module `{b['path']}` header and declarations. [{n}]")
    lines.append("\n_Grounded answer built from retrieved repository code and internal guidelines. Validate before acting._")
    return "\n".join(lines)


def answer_question(conn, user: dict, repo_id: int, question: str, prefixes: list[str]) -> dict:
    reg = get_registry()
    inj = reg.injection.score([question])[0]
    if inj >= 0.85:
        audit(conn, user["username"], "qa.blocked", f"repo:{repo_id}", f"injection score {inj:.2f}")
        return {"answer": "This request looks like an attempt to override the assistant's instructions, so it was not executed. "
                          "Ask a question about the code or guidelines instead.",
                "citations": [], "used_llm": False, "injection_score": round(inj, 3), "quarantined": 0, "blocked": True}

    idx = _index(conn, repo_id)

    def allow(d):
        return d["kind"] != "code" or path_allowed(prefixes, d["path"])

    hits = idx.search(question, k=8, allow=allow)
    # exact function-name mentions always ground on that function first
    for d in idx.docs:
        if d["kind"] == "code" and d.get("function") and allow(d) and re.search(rf"\b{re.escape(d['function'])}\b", question, re.I):
            hits = [h for h in hits if h["id"] != d["id"]]
            hits.insert(0, dict(d, score=999))
    blocks, dropped = _quarantine(hits[:6])

    run_id = latest_run_id(conn, repo_id)
    fn_rows, fn_findings = {}, {}
    if run_id:
        for r in rows(conn, "SELECT file_path, name, summary FROM functions WHERE run_id=?", (run_id,)):
            fn_rows[(r["file_path"], r["name"])] = r
        for f in rows(conn, "SELECT file_path, function, title, line, severity FROM findings WHERE run_id=? AND status!='rejected'", (run_id,)):
            fn_findings.setdefault((f["file_path"], f["function"]), []).append(f)

    answer = llm.generate(question, blocks) if blocks else None
    used_llm = answer is not None
    if not used_llm:
        answer = _compose(question, blocks, fn_rows, fn_findings)

    citations = [{"n": i + 1, "kind": b["kind"], "title": b["title"], "path": b["path"],
                  "start_line": b.get("start_line", 0), "end_line": b.get("end_line", 0),
                  "snippet": b["text"][:600]} for i, b in enumerate(blocks)]
    conn.execute("INSERT INTO qa_history (username, repo_id, question, answer, citations_json, created_at) VALUES (?,?,?,?,?,?)",
                 (user["username"], repo_id, question, answer, json.dumps(citations), now_iso()))
    audit(conn, user["username"], "qa.ask", f"repo:{repo_id}", question[:200])
    return {"answer": answer, "citations": citations, "used_llm": used_llm, "injection_score": round(inj, 3),
            "quarantined": dropped, "blocked": False}


def explain_finding(conn, finding: dict) -> dict:
    idx = _index(conn, finding["repo_id"])
    query = f"{finding['guideline']} {finding['title']} {finding['misra_ref']} {finding['cwe']} {finding['category'].replace('_', ' ')}"
    guides = idx.search(query, k=3, kinds={"guideline"})
    exact = [d for d in idx.docs if d["kind"] == "guideline" and d.get("guideline_id") == finding["guideline"]]
    if exact:
        guides = [dict(exact[0], score=999)] + [g for g in guides if g["id"] != exact[0]["id"]][:2]
    question = (f"Explain why this is a problem and how to fix it safely: {finding['title']} in function "
                f"{finding['function']} at line {finding['line']}: `{finding['evidence']}`")
    code_block = {"kind": "code", "title": f"{finding['file_path']} line {finding['line']}", "path": finding["file_path"],
                  "start_line": finding["line"], "end_line": finding["line"], "text": finding["evidence"]}
    answer = llm.generate(question, guides + [code_block])
    used_llm = answer is not None
    if answer is None:
        g = guides[0] if guides else None
        refs = ", ".join(x for x in (finding["misra_ref"] and f"MISRA C:2012 {finding['misra_ref']}", finding["cwe"]) if x)
        answer = (f"**Why it matters.** {finding['message']} "
                  + (f"{_first_sentences(g['text'], 3)} [1]" if g else "")
                  + f"\n\n**Recommended fix.** {finding['suggested_fix']}"
                  + (f"\n\n**References.** {refs}; internal guideline {finding['guideline']}." if refs else "")
                  + "\n\n_Suggested fix must be compiled, tested and approved by a reviewer before merge._")
    return {"explanation": answer, "used_llm": used_llm,
            "guidelines": [{"n": i + 1, "title": g["title"], "path": g["path"], "snippet": g["text"][:900]} for i, g in enumerate(guides)]}
