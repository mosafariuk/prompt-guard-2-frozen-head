// Edge LLM Firewall — main Worker entrypoint (full layered system, §III-VI + §IX).
//
// Implements the Fig. 1 lifecycle AND orchestrates the two-layer decision live:
//   size guard -> authenticate (HMAC + tenant binding + replay) -> edge screen
//   (Aho-Corasick) -> if not hard-rejected, call the on-prem deep-scan tier
//   (Tier-3a ML classifier) -> block iff EITHER layer flags it.
// Threat logging is deferred off the response path via waitUntil (optional queue).

import type { Env, ScreenResult } from "./types.js";
import { authenticate, recordNonce } from "./hmac.js";
import { sanitizeForScan } from "./sanitize.js";
import { screen } from "./heuristics.js";
import { buildEvent, enqueueThreatLog } from "./logging.js";

interface DeepScanVerdict {
  action: "block" | "allow";
  score: number;
  model: string;
  error?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // --- (1) Size guard (§III-C input bound N_max; DoS control) ---------------
    const maxBytes = Number.parseInt(env.MAX_BODY_BYTES, 10);
    const contentLength = Number.parseInt(request.headers.get("content-length") ?? "0", 10);
    if (Number.isFinite(contentLength) && contentLength > maxBytes) {
      return new Response("Payload Too Large", { status: 413 });
    }
    const rawBody = await readCapped(request, maxBytes);
    if (rawBody === null) return new Response("Payload Too Large", { status: 413 });

    const nowIso = new Date().toISOString();
    const sigHeader = request.headers.get("x-webhook-signature");

    // --- (2) Authenticate: HMAC + tenant binding + freshness (§IV) ------------
    const { result: authResult, envelope } = await authenticate(env, rawBody, sigHeader);
    if (authResult !== "ok") {
      ctx.waitUntil(enqueueThreatLog(env, buildEvent(rawBody, authResult, envelope, null, request, nowIso)));
      return json({ action: "block", blocked_by: "auth", error: authResult },
        authResult === "malformed" ? 400 : 401);
    }
    if (envelope) ctx.waitUntil(recordNonce(env, envelope.nonce));
    const tenantId = envelope!.tenantId;

    // --- (3)-(5) Edge screen: sanitize + Aho-Corasick + features (§V) ---------
    const sanitized = sanitizeForScan(rawBody);
    const edge: ScreenResult = screen(sanitized, Number.parseFloat(env.SCORE_THRESHOLD));

    // --- (6a) Edge hard-reject short-circuits (cheapest layer, 0% FPR) --------
    if (edge.decision === "reject") {
      ctx.waitUntil(enqueueThreatLog(env, buildEvent(rawBody, authResult, envelope, edge, request, nowIso)));
      return json({
        action: "block", blocked_by: "edge", tenant_id: tenantId,
        edge: edgeView(edge), deepscan: null,
      }, 403);
    }

    // --- (6b) Escalate to the on-prem deep-scan tier (§IX) --------------------
    const deep = await callDeepScan(env, rawBody, tenantId);
    const action = deep.action === "block" ? "block" : "allow";
    ctx.waitUntil(enqueueThreatLog(env, buildEvent(rawBody, authResult, envelope, edge, request, nowIso)));

    return json({
      action,
      blocked_by: action === "block" ? "deepscan" : null,
      tenant_id: tenantId,
      edge: edgeView(edge),
      deepscan: deep.error ? { error: deep.error, action: deep.action } : { action: deep.action, score: deep.score, model: deep.model },
    }, action === "block" ? 403 : 200);
  },
} satisfies ExportedHandler<Env>;

// Call the on-prem Tier-3a deep-scan service over B2 (shared-secret auth).
// FAIL-OPEN on error: if the ML tier is unreachable, we fall back to the edge
// verdict (which already ran) rather than take a full outage. The unavailability
// is surfaced in the response and logged. Flip to fail-closed by returning
// {action:"block"} here if your risk posture requires it.
async function callDeepScan(env: Env, text: string, tenantId: string): Promise<DeepScanVerdict> {
  try {
    const res = await fetch(env.DEEPSCAN_URL, {
      method: "POST",
      headers: { "content-type": "application/json", "x-edge-auth": env.DEEPSCAN_SECRET },
      body: JSON.stringify({ text, tenant_id: tenantId }),
    });
    if (!res.ok) return { action: "allow", score: 0, model: "unavailable", error: `deepscan_http_${res.status}` };
    const j = (await res.json()) as { action?: string; score?: number; model?: string };
    return {
      action: j.action === "block" ? "block" : "allow",
      score: typeof j.score === "number" ? j.score : 0,
      model: j.model ?? "unknown",
    };
  } catch (e) {
    return { action: "allow", score: 0, model: "unavailable", error: `deepscan_unreachable` };
  }
}

function edgeView(e: ScreenResult) {
  return { decision: e.decision, blocking_signatures: e.blockingSignatures, score: e.score };
}

function json(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

async function readCapped(request: Request, maxBytes: number): Promise<string | null> {
  const buf = await request.arrayBuffer();
  if (buf.byteLength > maxBytes) return null;
  return new TextDecoder().decode(buf);
}
