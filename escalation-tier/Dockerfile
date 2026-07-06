# On-prem deep-scan tier — CPU-optimized Debian image.
# The Tier-3a model (Prompt Guard 2 86M, an mDeBERTa encoder) runs efficiently on
# CPU/RAM; no GPU needed. We install the CPU-only torch wheel to keep the image
# small (no CUDA libraries) — ideal for the 64GB Debian origin server.
FROM python:3.11-slim-bookworm

# --- CPU inference tuning ----------------------------------------------------
# Thread counts are set at RUN time to match the host; defaults here are safe.
# Override per host, e.g. -e OMP_NUM_THREADS=8 (leave headroom for other origin work).
ENV OMP_NUM_THREADS=4 \
    MKL_NUM_THREADS=4 \
    TOKENIZERS_PARALLELISM=false \
    HF_HOME=/models \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ARG MODEL_ID=meta-llama/Llama-Prompt-Guard-2-86M
ENV MODEL_ID=${MODEL_ID}

WORKDIR /app

# curl for the container HEALTHCHECK; build tools not needed for prebuilt wheels.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# CPU-only torch first (from the PyTorch CPU index), then the rest.
COPY requirements.txt .
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch \
    && pip install -r requirements.txt

COPY classifier.py app.py ./

# Gated models (Prompt Guard 2) are downloaded at RUNTIME using an HF token passed
# as an environment secret (-e HF_TOKEN=... or a Docker/K8s secret). The token is
# NEVER baked into an image layer. For air-gapped hosts, pre-populate /models on a
# connected machine and mount it read-only at runtime instead.

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=120s --retries=3 \
    CMD curl -fsS http://localhost:8080/health || exit 1

# One worker: the model is the bottleneck and holds ~350MB resident; scale by
# running more replicas behind a load balancer rather than more workers per replica.
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
