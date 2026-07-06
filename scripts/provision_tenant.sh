#!/usr/bin/env bash
# Mint a per-tenant HMAC key into the edge firewall's TENANT_KEYS KV namespace (§IV).
#
# The printed SECRET is what the tenant's webhook producer uses to sign requests
# (HMAC-SHA256 over  tid.kid.timestamp.nonce.sha256(body) ). Run this YOURSELF so
# real tenant secrets never leave your terminal.
#
# Usage:
#   export CLOUDFLARE_API_TOKEN=...            # Workers KV:Edit scope
#   export CLOUDFLARE_ACCOUNT_ID=fe52d4758c6e5acc286bc9769c9ed0bd
#   scripts/provision_tenant.sh <tenant_id> [kid]
set -euo pipefail

TENANT="${1:?usage: provision_tenant.sh <tenant_id> [kid]}"
KID="${2:-1}"
KV_ID="${TENANT_KEYS_KV_ID:-93417b6f8f18444da03ede11fa6a4c38}"
FW_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/edge-firewall"

# tenant_id must match the worker's validation regex: ^[A-Za-z0-9-]{1,64}$
if ! [[ "$TENANT" =~ ^[A-Za-z0-9-]{1,64}$ ]]; then
  echo "tenant_id must match ^[A-Za-z0-9-]{1,64}$" >&2; exit 1
fi
: "${CLOUDFLARE_API_TOKEN:?export CLOUDFLARE_API_TOKEN}"
: "${CLOUDFLARE_ACCOUNT_ID:?export CLOUDFLARE_ACCOUNT_ID}"

SECRET="$(openssl rand -base64 32)"

( cd "$FW_DIR" && npx wrangler kv key put --namespace-id="$KV_ID" "${TENANT}:${KID}" "$SECRET" >/dev/null )

echo "provisioned tenant='${TENANT}' kid='${KID}'"
echo "  KV key : ${TENANT}:${KID}"
echo "  SECRET : ${SECRET}"
echo
echo "Give SECRET to the tenant's webhook producer. It signs each request:"
echo "  message = tid.kid.unix_ts.nonce.sha256hex(body)"
echo "  v1      = HMAC_SHA256(base64decode(SECRET), message)  (hex)"
echo "  header  : X-Webhook-Signature: tid=${TENANT},kid=${KID},t=<ts>,n=<nonce>,v1=<v1>"
echo
echo "Rotate by re-running with a new kid and updating the producer; the old kid keeps"
echo "working until you delete it:  wrangler kv key delete --namespace-id=${KV_ID} '${TENANT}:${KID}'"
