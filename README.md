# ECU Sentinel — Secure Code Debugging & Review Assistant

On-premises, AI-assisted code review for automotive embedded C (Tata Case Study 4).
ECU Sentinel fuses a **MISRA/secure-coding rule engine (31 rules)**, **five local ML models**, **compiler/static-analysis
logs** and **grounded RAG** into one explainable confidence score per finding. Reviewers stay in control, and no source
code ever leaves the machine.

## Highlights
- **Evidence fusion:** every finding shows *why* it is trusted (rule + defect model + triage model + log corroboration).
- **Five ML models:** defect classifier, triage model that learns from reviewers, log classifier with root-cause clustering, prompt-injection detector, complexity-anomaly model (Isolation Forest).
- **Repository-aware rules:** e.g. it knows `Brake_GetState()` can return NULL and flags callers that don't check.
- **Grounded Q&A with citations** over authorised code plus internal guidelines; works offline, optional local LLM (Ollama).
- **Security by design:** path-level RBAC, prompt-injection quarantine, audit trail, CSP headers, no external calls.
- **Workflow:** accept/reject/fix with reasons; rejections persist across re-analysis; reports in Markdown, JSON and SARIF 2.1; push approved findings to the workflow outbox.

## Quick start
Requirements: Python 3.10+ (tested on 3.12).

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # Windows: copy .env.example .env
python -m app.ml.train             # trains all 5 models (~10 s); also auto-runs on first start
uvicorn app.main:app --reload      # open http://127.0.0.1:8000
```
Or run `scripts/run.sh` (Linux/macOS) / `scripts/run.ps1` (Windows).

Demo logins: `reviewer/review123`, `admin/admin123`, `dev/dev123`, `intern/intern123` (intern sees only `src/com` and `include`).

## Tests
```bash
python -m pytest      # 39 tests: parser/rules, ML models, API, RBAC, RAG, workflow
```

## Docker
```bash
docker compose up --build                 # app only, http://localhost:8000
docker compose --profile llm up --build   # plus local Ollama
docker compose exec ollama ollama pull qwen2.5-coder:7b
# then set OLLAMA_URL=http://ollama:11434 in .env and restart
```

## Optional upgrades
- **Local LLM:** set `OLLAMA_URL` / `OLLAMA_MODEL`. Without it, the built-in grounded engine answers from retrieved sources.
- **Transformer embeddings:** `pip install -r requirements-optional.txt` and set `EMBEDDING_BACKEND=sentence-transformers`.

## Reset the demo
`scripts/reset_demo.sh` (or delete `var/sentinel.db*`), then restart.

See `docs/ARCHITECTURE.md`, `docs/UI_DESIGN.md` and `docs/DEMO_SCRIPT.md`.
