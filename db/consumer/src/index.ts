// Threat-log queue consumer (paper Section VI-B).
//
// Drains batches of ThreatLogEvent and inserts them into the partitioned JSONB
// table. Runs OFF the request path, so the ~ms-scale DB write never affects the
// webhook's client-perceived latency. At-least-once delivery is deduped by the
// (created_at, event_id) primary key via ON CONFLICT DO NOTHING (Section VI-B).

import postgres from "postgres";

// Mirror of the edge firewall's ThreatLogEvent (src/types.ts). Kept local so the
// consumer has no build dependency on the firewall package.
interface ThreatLogEvent {
  eventId: string;
  tenantId: string;
  createdAt: string; // ISO-8601 -> timestamptz
  decision: "forward" | "reject" | "escalate";
  authResult: "ok" | "bad_signature" | "replay" | "stale" | "unknown_tenant";
  blockingSignatures: string[];
  score: number;
  entropy: number;
  features: Record<string, number>;
  redactedPayload: string;
  sourceIp: string | null;
  userAgent: string | null;
}

interface Env {
  HYPERDRIVE: Hyperdrive;
}

export default {
  async queue(batch: MessageBatch<ThreatLogEvent>, env: Env, ctx: ExecutionContext): Promise<void> {
    // One short-lived pooled connection per batch (Hyperdrive pools underneath).
    const sql = postgres(env.HYPERDRIVE.connectionString, {
      max: 5,
      fetch_types: false, // skip type introspection round-trips (cold-start latency)
      idle_timeout: 20,
    });

    try {
      // Single transaction per batch: amortizes WAL flush + commit across all
      // rows (Section VI-D group-commit rationale). For extreme throughput this
      // could be swapped for COPY; per-row INSERT is used here for clarity and
      // for the ON CONFLICT dedup semantics.
      await sql.begin(async (tx) => {
        for (const msg of batch.messages) {
          const e = msg.body;
          await tx`
            INSERT INTO threat_log (
              event_id, tenant_id, created_at, decision, auth_result,
              score, entropy, blocking_signatures, features,
              redacted_payload, source_ip, user_agent
            ) VALUES (
              ${e.eventId}, ${e.tenantId}, ${e.createdAt}::timestamptz,
              ${e.decision}, ${e.authResult}, ${e.score}, ${e.entropy},
              ${tx.json(e.blockingSignatures)}, ${tx.json(e.features)},
              ${e.redactedPayload}, ${e.sourceIp}, ${e.userAgent}
            )
            ON CONFLICT (created_at, event_id) DO NOTHING
          `;
        }
      });
      // Whole batch committed: acknowledge all.
      batch.ackAll();
    } catch (err) {
      // Any failure: retry the whole batch. Dedup makes retries safe (idempotent).
      // After max_retries the batch lands in the DLQ (wrangler.toml).
      console.error("threat-log insert failed; retrying batch", err);
      batch.retryAll();
    } finally {
      // Close the connection after the response is settled (off-path).
      ctx.waitUntil(sql.end({ timeout: 5 }));
    }
  },
} satisfies ExportedHandler<Env, ThreatLogEvent>;
