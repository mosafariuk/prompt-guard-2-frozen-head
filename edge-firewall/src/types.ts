// Shared types and the environment binding contract (mirrors wrangler.toml).

export interface Env {
  // KV: per-tenant HMAC keys, key = `${tenantId}:${kid}` -> base64 secret.
  TENANT_KEYS: KVNamespace;
  // KV: replay nonce cache, key = nonce -> "1", TTL = 2*Delta (Section IV-E).
  NONCE_CACHE: KVNamespace;
  // Queue: threat-log events, drained off-path by the consumer (Section VI-B).
  // Optional: absent on Workers Free (Queues need the paid plan); logging is then skipped.
  THREAT_LOG_QUEUE?: Queue<ThreatLogEvent>;

  // Origin escalation tier (Tier-3a) — the on-prem deep-scan service (Section IX).
  DEEPSCAN_URL: string;        // e.g. https://ai-firewall.aioapex.com/v1/deep-scan
  DEEPSCAN_SECRET: string;     // X-Edge-Auth shared secret (B2), secret binding

  MAX_BODY_BYTES: string;
  REPLAY_TOLERANCE_SECONDS: string;
  SCORE_THRESHOLD: string;
}

// Verdict of the screening pipeline (Section V).
export type Decision = "forward" | "reject" | "escalate";

export interface ScreenResult {
  decision: Decision;
  // Names of blocking signatures that fired (Section V-B). Capped for logging.
  blockingSignatures: string[];
  // Soft feature score (Section V-C).
  score: number;
  // Individual feature contributions, for auditability (Section V-A reason 3).
  features: Record<string, number>;
  // Shannon entropy of the (sanitized) payload (Section V-C).
  entropy: number;
}

// Authenticated signature envelope extracted from request headers (Section IV-B).
export interface SignatureEnvelope {
  tenantId: string;
  kid: string; // key-id, authenticated inside the signed message
  timestamp: number; // Unix seconds
  nonce: string;
  signatureHex: string; // hex-encoded HMAC-SHA256 tag
}

// One row of the append-only threat log (Section VI). Written as JSONB.
export interface ThreatLogEvent {
  eventId: string; // idempotency key = nonce (Section VI-B)
  tenantId: string;
  createdAt: string; // ISO-8601; also the RANGE partition key (Section VI-E)
  decision: Decision;
  authResult: "ok" | "bad_signature" | "replay" | "stale" | "unknown_tenant";
  blockingSignatures: string[];
  score: number;
  features: Record<string, number>;
  entropy: number;
  // REDACTED payload only (Section VI-F). Raw CHD/PII never reaches this field.
  redactedPayload: string;
  sourceIp: string | null;
  userAgent: string | null;
}
