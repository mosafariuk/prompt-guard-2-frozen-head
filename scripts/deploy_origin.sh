#!/usr/bin/env bash
# Deploy the Tier-3a deep-scan service to the on-prem Debian origin server.
#
# Design notes:
#   - Secrets (HF_TOKEN, DEEPSCAN_SHARED_SECRET) come from the ENVIRONMENT, never
#     from this file or a committed .env. Export them before running.
#   - The container is bound to 127.0.0.1 only: the origin process calls it over
#     loopback / the private network. It is NEVER exposed to the public internet
#     (the whole point of the on-prem isolation thesis, Sections IV / VI-F).
#   - Log rotation is enabled so the security/access log cannot exhaust the disk.
#   - The HF model cache is a named volume so restarts don't re-download the model.
#
# Usage:
#   export HF_TOKEN=hf_...              # must have gated access to the model
#   export DEEPSCAN_SHARED_SECRET=...   # same secret the origin uses as X-Edge-Auth
#   scripts/deploy_origin.sh
set -euo pipefail

IMAGE="${IMAGE:-deepscan:latest}"
MODEL_ID="${MODEL_ID:-meta-llama/Llama-Prompt-Guard-2-86M}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
PORT="${PORT:-8080}"
CONTAINER="${CONTAINER:-deepscan}"
MEM_LIMIT="${MEM_LIMIT:-4g}"        # 86M model + runtime fits comfortably; cap anyway
CPUS="${CPUS:-4}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --- Preconditions -----------------------------------------------------------
command -v docker >/dev/null || { echo "docker not found on PATH" >&2; exit 1; }
: "${DEEPSCAN_SHARED_SECRET:?export DEEPSCAN_SHARED_SECRET before deploying}"
if [ -z "${HF_TOKEN:-}" ]; then
  echo "WARN: HF_TOKEN not set. Gated models (Prompt Guard 2) will fail to download." >&2
  echo "      Set it, or pre-populate the model cache volume for an air-gapped host." >&2
fi

echo "==> Building ${IMAGE} (MODEL_ID=${MODEL_ID}) ..."
docker build --build-arg "MODEL_ID=${MODEL_ID}" -t "${IMAGE}" "${HERE}/escalation-tier"

echo "==> Replacing any existing container ..."
docker rm -f "${CONTAINER}" 2>/dev/null || true

echo "==> Starting ${CONTAINER} bound to ${BIND_ADDR}:${PORT} (loopback only) ..."
docker run -d \
  --name "${CONTAINER}" \
  --restart unless-stopped \
  --memory "${MEM_LIMIT}" --cpus "${CPUS}" \
  --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges \
  -p "${BIND_ADDR}:${PORT}:8080" \
  -e "MODEL_ID=${MODEL_ID}" \
  -e "DEEPSCAN_SHARED_SECRET=${DEEPSCAN_SHARED_SECRET}" \
  ${HF_TOKEN:+-e "HF_TOKEN=${HF_TOKEN}"} \
  -e "OMP_NUM_THREADS=${CPUS}" \
  -v deepscan-models:/models \
  --log-driver json-file --log-opt max-size=50m --log-opt max-file=5 \
  "${IMAGE}"

echo "==> Waiting for readiness (model load can take ~1-2 min on first run) ..."
for i in $(seq 1 60); do
  if curl -fsS "http://${BIND_ADDR}:${PORT}/health" >/dev/null 2>&1; then
    echo "==> READY: $(curl -s http://${BIND_ADDR}:${PORT}/health)"
    exit 0
  fi
  sleep 5
done
echo "ERROR: service did not become ready in time. Recent logs:" >&2
docker logs --tail 40 "${CONTAINER}" >&2
exit 1
