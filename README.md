# AutoArch AI — Complete Hiring-Assessment Prototype

AutoArch AI is a local-first AUTOSAR High-Level Design (HLD) intelligence workbench. It turns engineering design documents into searchable evidence, a component inventory, candidate dependency map, revision comparison, change-impact report, and verification checklist.

## What is implemented
- React + Vite responsive dashboard with Overview, Architecture Map, HLD Assistant, and Revision Compare.
- FastAPI backend for PDF/TXT/Markdown/DOCX ingestion, with a 20 MB upload limit.
- SQLite-backed document metadata and extracted text so uploaded documents remain available after an API restart.
- Document deletion endpoint and dedicated evidence search endpoint.
- Engineering review screen with evidence-linked presence checks for safety, cybersecurity, diagnostics, communication contracts, persistence/recovery and watchdog/liveness concerns.
- Physical page-aware PDF text extraction using PyMuPDF.
- Heuristic architecture extraction for common AUTOSAR and automotive terms, interfaces, signals, components and candidate relationships.
- Search retrieval using local TF-IDF when scikit-learn is installed; a deterministic keyword fallback otherwise.
- Optional grounded synthesis through an OpenAI-compatible `/chat/completions` endpoint. Model use is optional; no API key is needed for the baseline application.
- Revision comparison for passages, components, interfaces and candidate dependencies.
- Downstream impact traversal and suggested verification checks.
- JSON findings and CSV inventory export.
- Local uploaded files, request validation, upload-size limits, useful error messages.
- Backend regression tests and synthetic demo documents.

## Important limits
This is a hiring-assessment prototype, not a certified AUTOSAR parser, an ISO 26262 / ISO/SAE 21434 compliance tool, or an architecture approval system. Extraction and dependency relationships are inferred from text and must be checked by qualified engineers. AI answers are constrained to retrieved text but still require citation and engineering review. OCR for scanned PDFs, authentication, role-based access, OCR for scanned PDFs, formal AUTOSAR parsing, vector-database retrieval, and production deployment hardening are not included. SQLite persistence is local and single-instance oriented; it is not a multi-user production data layer. Do not upload confidential company data to an unapproved environment.

## Requirements
- Python 3.10+
- Node.js 18+
- npm

## Run locally

### Backend (Terminal 1)
```bash
cd autoarch-ai-complete/backend
python -m venv .venv
# Windows PowerShell:
.venv\\Scripts\\Activate.ps1
# macOS/Linux:
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### Frontend (Terminal 2)
```bash
cd autoarch-ai-complete/frontend
npm install
npm run dev
```
Open http://localhost:5173. API docs: http://localhost:8000/docs.

## Demo without an LLM
Click **Try interactive demo** in the UI. It uploads a synthetic, fictional automotive HLD example. Ask:
- Which components communicate with the gateway?
- What interfaces are mentioned?
- What should engineers verify?
- Summarize the architecture.

Without an LLM endpoint, the assistant returns ranked source passages and clearly labels the answer as extractive retrieval.

## Optional LLM-backed synthesis
The backend supports an OpenAI-compatible chat completion endpoint. Set environment variables before starting Uvicorn:

Windows PowerShell:
```powershell
$env:AUTOARCH_LLM_BASE_URL="http://localhost:11434/v1"
$env:AUTOARCH_LLM_MODEL="qwen2.5:7b"
$env:AUTOARCH_LLM_API_KEY=""
uvicorn app.main:app --reload --port 8000
```

macOS/Linux:
```bash
export AUTOARCH_LLM_BASE_URL="http://localhost:11434/v1"
export AUTOARCH_LLM_MODEL="qwen2.5:7b"
export AUTOARCH_LLM_API_KEY=""
uvicorn app.main:app --reload --port 8000
```
The example assumes a local server that actually exposes `/v1/chat/completions` and has the chosen model available. Other compatible providers can be used. If the endpoint is unreachable, the app safely falls back to extractive mode. Keep API keys out of source control.

## Tests
From `backend` with the virtual environment active:
```bash
pytest -q
```

## Suggested 3-minute demo
1. Open the application and click **Try interactive demo**.
2. Review the inventory and candidate dependency graph.
3. Ask a question and point to the source-page evidence.
4. Upload `sample-data/sample_hld_v2.txt` from the project folder through the UI.
5. Select the original document as baseline in Revision Compare.
6. Show added/removed components, downstream impact candidates, and suggested verification checks.
7. Export the inventory CSV or findings JSON.

## Palette
- Background: #0B1220
- Sidebar: #0E1727
- Surface: #111D2E
- Raised surface: #17253A
- Primary blue: #66A6FF
- Teal accent: #65D6D0
- Success: #4ED1A1
- Warning: #F3BD67
- Error: #FF7B86
- Main text: #E8EEF8
- Muted text: #899AB3

## Architecture
`frontend/` contains the user interface. `backend/app/main.py` provides ingestion, retrieval, extraction, comparison, impact analysis, and export APIs. `sample-data/` includes fictional example HLD revisions. `backend/tests/` contains regression tests.


## Advanced review and API endpoints
- `GET /api/documents/{id}/review` returns evidence-linked heuristic review signals.
- `POST /api/documents/{id}/search` runs evidence retrieval without generating an answer.
- `DELETE /api/documents/{id}` removes the document from the local index and deletes its uploaded file.
- `GET /health` reports retrieval and optional model configuration.

The review checks are a triage aid only. They do not establish ISO 26262, ISO/SAE 21434, AUTOSAR, or OEM compliance.

## Verification status
Backend tests cover health, upload and evidence retrieval, revision comparison, unsupported uploads, engineering review, search, and deletion. Run `pytest -q` in the backend directory. The frontend dependency install/build must be run in an environment with npm registry access (`npm install && npm run build`); the frontend was not build-verified in the packaging environment.


## Optional ML retrieval (semantic search + reranking)

The default install stays lightweight and uses TF-IDF/keyword retrieval. To enable local
embedding-based semantic search, install the optional ML dependencies from `backend/`:

```bash
pip install -r requirements-ml.txt
```

Then set these environment variables before starting the backend:

```bash
AUTOARCH_ENABLE_SEMANTIC=true
AUTOARCH_EMBEDDING_MODEL=sentence-transformers/all-MiniLM-L6-v2
AUTOARCH_ENABLE_RERANKER=false
AUTOARCH_RERANKER_MODEL=cross-encoder/ms-marco-MiniLM-L-6-v2
```

Restart the backend. The first enabled run may download model weights and therefore
requires network access; later runs can use the local cache. For optional neural
reranking, set `AUTOARCH_ENABLE_RERANKER=true`. This loads a cross-encoder and adds
latency and memory use. If model loading fails, retrieval safely falls back to TF-IDF
or keyword search. `/health` reports whether the model is enabled/loaded.

These models improve retrieval ranking but do not prove engineering correctness.
Review cited evidence and validate safety/security findings with qualified engineers.


## ML-assisted architecture topic insights

`GET /api/documents/{id}/ml-insights` ranks topics such as functional safety, cybersecurity,
diagnostics, communication contracts, persistence/recovery, timing, traceability, and resource
constraints. When semantic retrieval is enabled, the endpoint uses the configured sentence
transformer to compare passage embeddings with topic descriptions. Otherwise it uses a transparent
keyword-overlap fallback. Results include evidence passages and ranking scores.

The semantic retriever now caches document chunk embeddings in memory to reduce repeat-query
latency. The cache is bounded by `AUTOARCH_EMBEDDING_CACHE_LIMIT` (default 256 entries). Cache
entries are process-local and recomputed after restart. Similarity values are not calibrated
probabilities and must not be interpreted as compliance scores.
