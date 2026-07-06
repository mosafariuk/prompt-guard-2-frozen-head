# Edge-side durable infrastructure: KV namespaces, Queue, Hyperdrive, and the
# firewall Worker script + bindings (paper Sections III-VI).
#
# NOTE ON TF vs wrangler: Terraform does not bundle TypeScript. The Worker script
# resources below reference a PRE-BUILT bundle (see the `wrangler deploy --dry-run
# --outdir dist` build step in terraform/README.md). In many shops the Workers are
# deployed by `wrangler deploy` (which bundles + wires consumers) while TF owns the
# stateful infra (KV/Queue/Hyperdrive/RDS). Both paths are documented; the split
# is a deliberate, honest boundary, not an oversight.

# --- KV: per-tenant HMAC keys (Section IV) -----------------------------------
resource "cloudflare_workers_kv_namespace" "tenant_keys" {
  account_id = var.cloudflare_account_id
  title      = "edge-firewall-tenant-keys"
}

# --- KV: replay nonce cache (Section IV-E) -----------------------------------
resource "cloudflare_workers_kv_namespace" "nonce_cache" {
  account_id = var.cloudflare_account_id
  title      = "edge-firewall-nonce-cache"
}

# --- Queue: decouples logging from the request path (Section VI-B) -----------
resource "cloudflare_queue" "threat_log" {
  account_id = var.cloudflare_account_id
  name       = "threat-log"
}

resource "cloudflare_queue" "threat_log_dlq" {
  account_id = var.cloudflare_account_id
  name       = "threat-log-dlq"
}

# --- Hyperdrive: pooled/accelerated Postgres connection for the consumer ------
resource "cloudflare_hyperdrive_config" "threatlog" {
  account_id = var.cloudflare_account_id
  name       = "threatlog-hyperdrive"
  # v4 SDKv2 schema uses nested BLOCKS (no `=`). Verify block vs attribute syntax
  # against the pinned provider (4.52.0) with `terraform validate` before apply.
  origin {
    host     = aws_db_instance.threatlog.address
    port     = aws_db_instance.threatlog.port
    database = var.db_name
    user     = postgresql_role.firewall_writer_login.name
    password = random_password.writer.result
    scheme   = "postgres"
  }
  caching {
    disabled = true # threat-log writes must not be served from a read cache
  }
}

# --- Edge firewall Worker script (Section III-E) -----------------------------
# References the built bundle. Bindings mirror wrangler.toml exactly.
resource "cloudflare_workers_script" "edge_firewall" {
  account_id         = var.cloudflare_account_id
  name               = "edge-llm-firewall"
  content            = file("${path.module}/../edge-firewall/dist/index.js")
  module             = true
  compatibility_date = "2026-06-01"

  kv_namespace_binding {
    name         = "TENANT_KEYS"
    namespace_id = cloudflare_workers_kv_namespace.tenant_keys.id
  }
  kv_namespace_binding {
    name         = "NONCE_CACHE"
    namespace_id = cloudflare_workers_kv_namespace.nonce_cache.id
  }
  queue_binding {
    binding = "THREAT_LOG_QUEUE"
    queue   = cloudflare_queue.threat_log.name
  }
  plain_text_binding {
    name = "ORIGIN_URL"
    text = var.origin_url
  }
  plain_text_binding {
    name = "MAX_BODY_BYTES"
    text = tostring(var.max_body_bytes)
  }
  plain_text_binding {
    name = "REPLAY_TOLERANCE_SECONDS"
    text = tostring(var.replay_tolerance_seconds)
  }
  plain_text_binding {
    name = "SCORE_THRESHOLD"
    text = "1.0"
  }
  secret_text_binding {
    name = "ORIGIN_SHARED_SECRET"
    text = var.origin_shared_secret
  }
}

# The consumer Worker (db/consumer) is deployed via `wrangler deploy` because it
# bundles postgres.js and subscribes to the queue as a consumer (a build/runtime
# concern TF does not model). It consumes cloudflare_queue.threat_log and uses
# cloudflare_hyperdrive_config.threatlog (ids surfaced in outputs.tf).
