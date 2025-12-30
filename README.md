# PQC Scanner — Phase 3 (Enterprise bundle)

This bundle includes:

- Phase 1 (TLS + cert posture + PQC relevance)
- Phase 2/3 Step 1: **OCSP validation** (live responder query when possible)
- Optional Phase 1B: lightweight Python code crypto/TLS hints scanner

## Run (Windows / Linux / macOS)

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt

# from the same folder that contains app.py + index.html
uvicorn app:app --reload --port 8000
```

Open: http://127.0.0.1:8000

## API

- `POST /scan` (sync) body:
  - `{"targets":["example.com","example.com:8443"]}`
- `POST /scans` (async) body:
  - `{"targets":[{"host":"example.com","port":443}]}`
- `GET /scans/{id}`
- `GET /scans/{id}/migration-plan`

## Optional API key

Set `PQC_SCANNER_API_KEY` and pass `x-api-key` header.

## Smoke tests

```bash
python tests_smoke.py
```
