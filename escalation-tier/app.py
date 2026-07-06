"""Deep-scan escalation service (Tier-3a) — paper Section IX.

Runs ON-PREMISE at/near the origin. The edge firewall forwards a request with
`x-firewall-escalate: 1` when its deterministic layer is not confident; the origin
calls this service to get an ML verdict on the (already tenant-authenticated,
edge-redacted) payload. Sensitive data never leaves the trust boundary — this
service is self-hosted, satisfying the isolation/PCI thesis (Sections IV, VI-F).

Trust: the caller (origin) authenticates over the private B2 channel with a shared
secret (X-Edge-Auth). The tenant id is the value already cryptographically bound and
verified at the edge (Section IV); it is trusted here and used only for per-tenant
logging/metrics, never to select model behavior.

Robustness: strict input validation (empty / oversized / non-string bodies are
rejected with 4xx, never crash the worker), a readiness gate so requests fail 503
until the model is loaded, and a catch-all handler that returns a generic 500
without leaking internals.
"""
from __future__ import annotations
import hmac
import logging
import os

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, ValidationError

from classifier import InjectionClassifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("deepscan")

SHARED_SECRET = os.environ.get("DEEPSCAN_SHARED_SECRET", "")
BLOCK_THRESHOLD = float(os.environ.get("BLOCK_THRESHOLD", "0.5"))
MAX_TEXT_CHARS = int(os.environ.get("MAX_TEXT_CHARS", "100000"))  # 512-token model; guard anyway

app = FastAPI(title="LLM Firewall Deep-Scan Tier", version="1.0.0")
_clf: InjectionClassifier | None = None
_ready = False


class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=MAX_TEXT_CHARS,
                      description="The (edge-redacted) payload to deep-scan.")
    tenant_id: str = Field(..., min_length=1, max_length=128,
                           description="Authenticated tenant id (bound at edge).")


class ScanResponse(BaseModel):
    verdict: str          # "malicious" | "benign"
    action: str           # "block" | "allow"
    score: float          # P(malicious)
    model: str
    latency_ms: float
    tenant_id: str


@app.on_event("startup")
def _startup() -> None:
    # Load the model once at startup. If it fails (e.g. missing gated access), keep
    # the process up but not ready, so /health reports 503 instead of crash-looping.
    global _clf, _ready
    if not SHARED_SECRET:
        log.warning("DEEPSCAN_SHARED_SECRET is empty — all requests will 401.")
    try:
        _clf = InjectionClassifier()
        _ready = True
        log.info("model loaded: %s", _clf.model_id)
    except Exception:  # noqa: BLE001
        log.exception("model failed to load; service will report not-ready (503)")


@app.exception_handler(Exception)
async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
    # Never leak internals/stack traces to the caller.
    log.exception("unhandled error: %s", type(exc).__name__)
    return JSONResponse(status_code=500, content={"error": "internal_error"})


@app.get("/health")
def health() -> JSONResponse:
    if not _ready or _clf is None:
        return JSONResponse(status_code=503, content={"status": "not_ready"})
    return JSONResponse(status_code=200, content={"status": "ok", "model": _clf.model_id})


@app.post("/v1/deep-scan", response_model=ScanResponse)
def deep_scan(req: ScanRequest, x_edge_auth: str = Header(default="")) -> ScanResponse:
    # Constant-time B2 shared-secret comparison (avoid timing oracle).
    if not SHARED_SECRET or not hmac.compare_digest(x_edge_auth, SHARED_SECRET):
        raise HTTPException(status_code=401, detail="unauthorized")
    if not _ready or _clf is None:
        raise HTTPException(status_code=503, detail="model_not_ready")
    try:
        result = _clf.classify(req.text)
    except Exception as e:  # noqa: BLE001 — a single bad payload must not 500 the worker
        log.exception("classify failed for tenant=%s", req.tenant_id)
        raise HTTPException(status_code=422, detail="unprocessable_payload") from e
    # The classifier applies its own calibrated threshold (the trained-head threshold
    # in composed mode, 0.5 native), so the verdict is authoritative for the action.
    action = "block" if result["verdict"] == "malicious" else "allow"
    return ScanResponse(
        verdict=result["verdict"], action=action, score=result["score"],
        model=result["model"], latency_ms=result["latency_ms"], tenant_id=req.tenant_id,
    )
