// Screening pipeline: Layer 1 (Aho-Corasick) + Layer 2 (linear features).
// Paper Sections V-B, V-C, V-F.
//
// MODULE-SCOPE CONSTRUCTION (Section III-A): the automaton is built ONCE when the
// isolate loads and reused for every request. Its O(m) build cost is therefore
// amortized to zero on the request path; only the O(n) search + O(n) feature
// passes run per request, giving the C_req <= kappa * N_max bound of Section V-F.

import { AhoCorasick } from "./ahocorasick.js";
import { SIGNATURES, ROLE_TOKEN_IDS } from "./signatures.js";
import type { ScreenResult, Decision } from "./types.js";

// Built once per isolate. This line is the amortized O(m) construction.
const AUTOMATON = new AhoCorasick(SIGNATURES);

// Shannon entropy over the character distribution, one O(n) accumulation pass
// (Section V-C). High entropy flags encoded/obfuscated payloads; used only to
// ESCALATE, never to block alone (Section V-D).
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<number, number>();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    counts.set(c, (counts.get(c) ?? 0) + 1);
  }
  let h = 0;
  const n = s.length;
  for (const count of counts.values()) {
    const p = count / n;
    h -= p * Math.log2(p);
  }
  return h;
}

// Combine the layers into a single decision. `threshold` is theta (Section V-C).
export function screen(sanitized: string, threshold: number): ScreenResult {
  // --- Layer 1: single-pass Aho-Corasick over all signatures (Section V-B) ---
  const { matches, blockingHit } = AUTOMATON.search(sanitized, /*stopOnBlocking*/ true);

  const blockingSignatures: string[] = [];
  const features: Record<string, number> = {};
  let softScore = 0;
  let roleTokenHits = 0;

  for (const m of matches) {
    const pat = AUTOMATON.patternAt(m.patternIndex);
    if (pat.blocking) {
      blockingSignatures.push(pat.id);
    } else {
      softScore += pat.weight;
      features[pat.id] = (features[pat.id] ?? 0) + pat.weight;
      if (ROLE_TOKEN_IDS.has(pat.id)) roleTokenHits++;
    }
  }

  // --- Layer 2: linear structural + entropy features (Section V-C) -----------
  // Role/delimiter-token density, normalized by length (per-KB rate).
  const density = sanitized.length > 0 ? (roleTokenHits * 1000) / sanitized.length : 0;
  const densityFeature = density > 2 ? Math.min(density / 4, 1.0) : 0; // capped
  features["_role_token_density"] = densityFeature;
  softScore += densityFeature;

  const entropy = shannonEntropy(sanitized);
  features["_entropy"] = entropy;

  // --- Decision (Section V-C threshold rule) ---------------------------------
  let decision: Decision;
  if (blockingHit) {
    decision = "reject"; // a hard signature => immediate block
  } else if (softScore >= threshold) {
    decision = "reject"; // aggregated soft evidence crosses theta
  } else if (softScore >= threshold * 0.5 || entropy > 5.5) {
    // Mid-band or anomalously high entropy: not confident enough to block,
    // route to the origin model tier for a deep scan (Section V-D / IX).
    decision = "escalate";
  } else {
    decision = "forward";
  }

  return { decision, blockingSignatures, score: softScore, features, entropy };
}
