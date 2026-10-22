# Architecture

```
Browser SPA (vanilla JS, no CDN)  ──JSON──►  FastAPI (app/main.py)
                                               │  auth (PBKDF2 + HMAC token), RBAC + path ACL, audit
                                               ▼
        ┌───────────── Analysis pipeline (services/pipeline.py) ─────────────┐
        │ C parser → rule engine (31 rules, MISRA/CWE refs, repo-aware)       │
        │ → defect classifier (TF-IDF+LR) per function                         │
        │ → complexity anomaly (Isolation Forest)                              │
        │ → injection detector on comments (quarantine)                        │
        │ → build-log parse + log classifier → corroboration ±2 lines          │
        │ → triage model (Gradient Boosting) → fused confidence                │
        │ → fingerprint + reviewer dispositions → SQLite                       │
        │ → hybrid RAG index (BM25 + LSA/BGE, rank fusion) per repo            │
        └─────────────────────────────────────────────────────────────────────┘
Q&A: question → injection screen → hybrid retrieve (ACL-filtered) → quarantine injected chunks
     → local LLM (Ollama, controlled prompt) or grounded composer → cited answer
```

## Confidence fusion
- Rule findings: `0.5·rule + 0.2·defect_model + 0.3·triage + 0.08 if log corroborated`
- ML-only findings: `0.85·(0.55·ml + 0.45·triage)` (always labelled as hypotheses)
- Complexity hotspots: `0.6·anomaly + 0.4·triage`

## Feedback loop
Reviewer decisions are stored per fingerprint (file + function + rule + evidence, independent of line number).
On re-analysis the decision is re-applied; **Retrain triage** adds them (weighted ×5) to the training set and re-scores findings.

## Roadmap (assessment-sized)
| Phase | Deliverables | Time |
|---|---|---|
| 1. Secure core | FastAPI, SQLite schema, auth, RBAC + path ACL, audit, seed repo | Day 1 |
| 2. Analysis engine | C parser, 31 rules, log parser, tests | Day 2 |
| 3. ML layer | 5 models + synthetic corpora, fusion, triage feedback loop | Day 3 |
| 4. RAG assistant | guidelines, hybrid index, Q&A + explain, injection defence, optional Ollama | Day 4 |
| 5. UI & workflow | dashboard, findings drawer, explorer, logs, chat, reports/SARIF | Day 5–6 |
| 6. Polish | Docker, docs, demo script | Day 7 |

## Production next steps (not built)
libclang/cppcheck integration, Postgres, SSO/LDAP, Git webhooks for merge-request review, real historical findings instead of synthetic corpora, model registry.
