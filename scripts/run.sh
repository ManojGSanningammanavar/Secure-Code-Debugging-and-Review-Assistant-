#!/usr/bin/env bash
# One-command local start (Linux/macOS): creates venv, installs deps, trains models, runs server.
set -euo pipefail
cd "$(dirname "$0")/.."
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
[ -f .env ] || cp .env.example .env
[ -f var/models/defect_classifier.joblib ] || python -m app.ml.train
exec uvicorn app.main:app --host 127.0.0.1 --port "${PORT:-8000}"
