from fastapi.middleware.cors import CORSMiddleware

from typing import List

from fastapi import FastAPI
from pydantic import BaseModel

from scanner import run_scan  # import from scanner.py


class ScanRequest(BaseModel):
    targets: List[str]


app = FastAPI(
    title="PQC Scanner API",
    description="Simple API to scan TLS endpoints for certificate details and basic PQC-relevant risk.",
    version="0.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # for development; later we restrict this
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/scan")
def scan_endpoints(request: ScanRequest):
    """
    Scan a list of endpoints and return certificate info + basic risk.
    """
    results = run_scan(request.targets)
    return {
        "count": len(results),
        "results": results,
    }
