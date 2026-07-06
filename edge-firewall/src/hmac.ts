// HMAC-SHA256 tenant-bound authentication + replay defense.
// Paper Section IV (IV-B scheme, IV-C tenant binding, IV-E replay).
//
// Signature header (Stripe-style, extended with tenant binding):
//   X-Webhook-Signature: tid=<tenantId>,kid=<keyId>,t=<unixSeconds>,n=<nonce>,v1=<hexHMAC>
//
// The SIGNED MESSAGE binds tenant id and key id INSIDE the MAC input (Section IV-F),
// so tenant attribution is as hard as forging HMAC (Theorem 1):
//   m = tid "." kid "." t "." n "." sha256hex(body)
// Fields use "." as delimiter; tid (UUID), kid/t (numeric), n (base64url) and the
// hex digest contain no ".", so the encoding is injective (no ambiguity attack).

import type { Env, SignatureEnvelope } from "./types.js";

export type AuthResult = "ok" | "bad_signature" | "replay" | "stale" | "unknown_tenant" | "malformed";

const enc = new TextEncoder();

function hex(buf: ArrayBuffer): string {
  const b = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i]!.toString(16).padStart(2, "0");
  return s;
}

function hexToBytes(h: string): Uint8Array | null {
  if (h.length % 2 !== 0) return null;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(h.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

async function sha256Hex(data: string): Promise<string> {
  return hex(await crypto.subtle.digest("SHA-256", enc.encode(data)));
}

// Parse the signature header into its fields. Returns null on any malformation.
export function parseEnvelope(header: string | null): SignatureEnvelope | null {
  if (!header) return null;
  const parts = new Map<string, string>();
  for (const kv of header.split(",")) {
    const idx = kv.indexOf("=");
    if (idx <= 0) return null;
    parts.set(kv.slice(0, idx).trim(), kv.slice(idx + 1).trim());
  }
  const tid = parts.get("tid");
  const kid = parts.get("kid");
  const t = parts.get("t");
  const n = parts.get("n");
  const v1 = parts.get("v1");
  if (!tid || !kid || !t || !n || !v1) return null;
  const timestamp = Number.parseInt(t, 10);
  if (!Number.isFinite(timestamp)) return null;
  // Defensive input validation: bound field shapes before any crypto work.
  if (!/^[A-Za-z0-9-]{1,64}$/.test(tid)) return null;
  if (!/^[0-9]{1,10}$/.test(kid)) return null;
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(n)) return null;
  if (!/^[0-9a-f]{64}$/.test(v1)) return null;
  return { tenantId: tid, kid, timestamp, nonce: n, signatureHex: v1 };
}

// Full authentication: signature validity + freshness + replay (Section IV).
// Returns the result; the caller records the nonce (Section IV-E) on "ok".
export async function authenticate(
  env: Env,
  rawBody: string,
  header: string | null,
): Promise<{ result: AuthResult; envelope: SignatureEnvelope | null }> {
  const envelope = parseEnvelope(header);
  if (!envelope) return { result: "malformed", envelope: null };

  // (a) Freshness first (Section IV-E): reject stale timestamps BEFORE crypto,
  // cheaply shedding replayed/old traffic. Tolerance window Delta.
  const delta = Number.parseInt(env.REPLAY_TOLERANCE_SECONDS, 10);
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - envelope.timestamp) > delta) {
    return { result: "stale", envelope };
  }

  // (b) Fetch the per-tenant key by (tenantId, kid). I/O, not CPU (Section III-B).
  const keyB64 = await env.TENANT_KEYS.get(`${envelope.tenantId}:${envelope.kid}`);
  if (!keyB64) return { result: "unknown_tenant", envelope };

  // (c) Reconstruct the canonical signed message and verify the tag.
  const hbody = await sha256Hex(rawBody);
  const message = `${envelope.tenantId}.${envelope.kid}.${envelope.timestamp}.${envelope.nonce}.${hbody}`;
  const rawKey = Uint8Array.from(atob(keyB64), (c) => c.charCodeAt(0));
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const sigBytes = hexToBytes(envelope.signatureHex);
  if (!sigBytes) return { result: "malformed", envelope };
  // crypto.subtle.verify is constant-time (no timing side channel, Section IV-B).
  const valid = await crypto.subtle.verify("HMAC", cryptoKey, sigBytes, enc.encode(message));
  if (!valid) return { result: "bad_signature", envelope };

  // (d) Replay check: nonce must be unseen within the window (Section IV-E).
  const seen = await env.NONCE_CACHE.get(envelope.nonce);
  if (seen) return { result: "replay", envelope };

  return { result: "ok", envelope };
}

// Record the nonce for TTL = 2*Delta (Section IV-E). Called via waitUntil so the
// KV write is off the response path; the residual (a race within the window) is
// exactly the "nonce-store loss" term bounded in the paper's replay analysis.
export async function recordNonce(env: Env, nonce: string): Promise<void> {
  const delta = Number.parseInt(env.REPLAY_TOLERANCE_SECONDS, 10);
  await env.NONCE_CACHE.put(nonce, "1", { expirationTtl: Math.max(60, 2 * delta) });
}
