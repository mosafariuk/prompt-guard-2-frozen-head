// Non-blocking threat logging (paper Section VI-B).
//
// The Worker only ENQUEUES (one fast subrequest); a separate queue consumer
// batches inserts into PostgreSQL. This keeps durability and retries OFF the
// request path. Called exclusively via ctx.waitUntil(...) so it runs AFTER the
// Response is returned (Section VI-B): logging adds zero wall-clock to the client.

import type { Env, ThreatLogEvent, ScreenResult, SignatureEnvelope } from "./types.js";
import type { AuthResult } from "./hmac.js";
import { redactForLog } from "./sanitize.js";

export function buildEvent(
  rawBody: string,
  authResult: AuthResult,
  envelope: SignatureEnvelope | null,
  screen: ScreenResult | null,
  request: Request,
  nowIso: string,
): ThreatLogEvent {
  return {
    // Idempotency key = nonce, so at-least-once queue delivery dedupes on insert
    // via ON CONFLICT DO NOTHING (Section VI-B). Fallback id if no envelope.
    eventId: envelope?.nonce ?? crypto.randomUUID(),
    tenantId: envelope?.tenantId ?? "unknown",
    createdAt: nowIso, // also the RANGE partition key (Section VI-E)
    decision: screen?.decision ?? "reject",
    authResult: (authResult === "malformed" ? "bad_signature" : authResult) as ThreatLogEvent["authResult"],
    blockingSignatures: screen?.blockingSignatures ?? [],
    score: screen?.score ?? 0,
    features: screen?.features ?? {},
    entropy: screen?.entropy ?? 0,
    // REDACTION happens here, at the edge, before the queue (Section VI-F):
    // raw PAN/PII never leaves the isolate toward the log tier.
    redactedPayload: redactForLog(rawBody),
    sourceIp: request.headers.get("cf-connecting-ip"),
    userAgent: request.headers.get("user-agent"),
  };
}

// Enqueue is a single subrequest; failures must not surface to the client.
// The queue is optional (absent on Workers Free); logging is skipped if unbound.
export async function enqueueThreatLog(env: Env, event: ThreatLogEvent): Promise<void> {
  if (!env.THREAT_LOG_QUEUE) return; // no queue bound (free plan) -> skip logging
  try {
    await env.THREAT_LOG_QUEUE.send(event);
  } catch {
    // Best-effort: a queue send failure is swallowed (the client already has its
    // response). Queue depth / send errors are monitored out-of-band.
  }
}
