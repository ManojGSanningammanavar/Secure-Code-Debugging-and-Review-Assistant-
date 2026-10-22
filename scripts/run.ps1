# One-command local start (Windows PowerShell)
Set-Location (Join-Path $PSScriptRoot "..")
if (-not (Test-Path ".venv")) { python -m venv .venv }
.\.venv\Scripts\Activate.ps1
pip install -q -r requirements.txt
if (-not (Test-Path ".env")) { Copy-Item ".env.example" ".env" }
if (-not (Test-Path "var/models/defect_classifier.joblib")) { python -m app.ml.train }
uvicorn app.main:app --host 127.0.0.1 --port 8000
