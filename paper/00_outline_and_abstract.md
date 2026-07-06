# Multi-Layered Defensive Architecture and Webhook Securitization for LLM Deployment in Multi-Tenant Enterprise Systems

**Target venue:** IEEE (conference or TDSC/TIFS-style journal). Format: IEEEtran, two-column.
**Status:** Outline + Abstract for approval. Full text follows on sign-off.
**Evidence base:** `paper/refs/verified-facts.md` (deep-research verification, 2026-07-04).

---

## Abstract (draft, ~230 words)

Large Language Models (LLMs) exposed through webhook interfaces in multi-tenant enterprise
platforms — payment orchestration, ticketing, workflow automation — inherit a hostile attack
surface in which a single unauthenticated or adversarial request can trigger prompt injection,
cross-tenant context leakage, or spoofed event delivery. Conventional application-layer
guardrails, invoked only after the request reaches origin, both add round-trip latency and
concentrate risk at the trust boundary they are meant to protect. This paper presents a
multi-layered defensive architecture that relocates the first line of defense to the network
edge. We deploy a reverse-proxying firewall on a V8-isolate edge runtime (Cloudflare Workers)
that (i) authenticates every webhook via HMAC-SHA256 signatures that cryptographically bind a
tenant identifier into the signed message, providing existentially-unforgeable (EUF-CMA) tenant
context integrity and timestamp-windowed replay resistance; (ii) screens payloads with
deterministic, single-pass NLP heuristics — Aho-Corasick multi-pattern matching in O(n+z),
plus entropy and structural scoring — that execute in a sub-millisecond CPU budget, orders of
magnitude below the runtime's per-invocation ceiling; and (iii) records every interception
event to a partitioned PostgreSQL JSONB store on a non-blocking, out-of-band write path so that
threat logging never gates the request. We formalize the threat model with STRIDE, derive the
latency budget analytically, and evaluate detection efficacy against an open-source
prompt-injection corpus, reporting p50/p90/p99 latency and false-positive/false-negative rates.
We correct a widely-repeated misconception about edge CPU limits and quantify the resulting
engineering headroom.

> **Reviewer-facing note (remove before submission):** The abstract deliberately states the CPU
> cost as "sub-millisecond ... orders of magnitude below the runtime's per-invocation ceiling"
> rather than the brief's "50 ms limit," which our verification found to be a **legacy 2024
> artifact**. See §III and the correction ledger.

---

## Structural Outline (IEEE, 10–12 pages, two-column)

### I. Introduction
- I-A. Motivation: LLMs as webhook consumers in multi-tenant SaaS (payment-gateway running example).
- I-B. Problem: post-origin guardrails add latency + concentrate trust; injection and cross-tenant leakage are underserved at the edge.
- I-C. Contributions (enumerated, 5): edge-relocated defense; tenant-bound HMAC context integrity with proof sketch; sub-ms deterministic heuristic layer with complexity analysis; non-blocking JSONB threat-logging data path; empirical latency + detection evaluation.
- I-D. **Premise correction as a contribution:** explicitly document the CPU-budget vs wall-clock-SLO distinction and the deprecated-50 ms correction; frame headroom as a design margin.

### II. Threat Model and Taxonomy
- II-A. System & trust model: tenants, webhook producers, edge, origin LLM, shared model context.
- II-B. **STRIDE decomposition** mapped to the webhook→LLM pipeline (table: threat → asset → surface → mitigation layer).
  - Spoofing → forged webhooks → HMAC auth (§IV).
  - Tampering → payload/instruction mutation → signature + sanitization.
  - Repudiation → threat logging (§VI).
  - Information disclosure → **cross-tenant context leakage** → tenant-ID binding (§IV) + isolation.
  - DoS → CPU/subrequest exhaustion → edge budget (§III).
  - Elevation → prompt injection / jailbreak → heuristic layer (§V).
- II-C. **Prompt-injection taxonomy** (OWASP LLM01:2025): direct, indirect (incl. stored as subcategory), with a jailbreak-category sub-table. [verified]
- II-D. **Cross-tenant data leakage** formalized: shared-context and shared-key failure modes; adversary capabilities (Dolev-Yao network attacker + malicious tenant).

### III. Edge Interception Layer: V8 Isolate Architecture
- III-A. V8 isolate execution model: isolates vs containers, cold-start/reuse, why per-request compute must be bounded.
- III-B. **Resource envelope (date-stamped table):** 128 MB/isolate memory; CPU 10 ms (free) / 30 s default → 5 min max (paid); subrequests 50+1,000 (free) / 10,000 (paid, since 2026-02-11). [all verified]
- III-C. **The correction:** the 50 ms figure is the deprecated Bundled-model 2024 artifact; CPU excludes I/O wait; wall-clock unlimited for HTTP triggers. Consequences for firewall design.
- III-D. Reverse-proxy dataflow: request → verify → screen → forward/reject → async-log. Diagram.

### IV. Cryptographic Tenant Isolation
- IV-A. Formal MAC preliminaries: MAC syntax, EUF-CMA game, HMAC as a PRF (RFC 2104, FIPS 198-1, Bellare-Canetti-Krawczyk). [primary-sourced; re-verify]
- IV-B. **Tenant-context-binding theorem (with proof):** define signed message m = tenantID ‖ timestamp ‖ nonce ‖ body; show that an adversary forging a valid (m′, tag) for a *different* tenantID reduces to an EUF-CMA forgery on HMAC. State assumptions and the reduction explicitly.
- IV-C. Replay resistance: timestamp tolerance window + nonce cache; bound on replay probability; interaction with edge KV for nonce storage (subrequest cost).
- IV-D. Key management: per-tenant keys, rotation strategy (overlapping key epochs, `kid` selector), compromise containment; comparison to Stripe/GitHub timestamped signing schemes.

### V. Lightweight NLP Heuristics for Webhook Screening
- V-A. Design goal: high recall on known injection patterns within sub-ms CPU; layered escalation.
- V-B. **Layer 1 — Aho-Corasick signature scan:** construction O(m), matching O(n+z), single pass over all signatures; contrast with per-pattern regex/KMP. [verified] Signature families from OWASP + jailbreak corpus.
- V-C. **Layer 2 — structural/entropy scoring:** delimiter-injection, role-token, and Shannon-entropy features; O(n) pass. [complexity to be sourced]
- V-D. Accuracy ceiling of deterministic filters vs ML: report lexical-filter ROC-AUC band and the embedding-classifier comparison, positioning heuristics as high-precision *first* stage, not sole defense. [ML result MEDIUM confidence, single preprint]
- V-E. Input sanitization & canonicalization (Unicode, encoding smuggling) before scanning.
- V-F. Aggregate CPU-budget accounting: worst-case cycles → sub-ms claim with headroom vs §III envelope.

### VI. Asynchronous Threat Logging & Data Architecture
- VI-A. Requirement: zero blocking on the request path; durable, queryable attack record.
- VI-B. **Decoupling mechanism:** `waitUntil()` / queue hand-off so the DB write runs after the response is returned; back-pressure and delivery-guarantee discussion.
- VI-C. **PostgreSQL JSONB rationale** [EVIDENTIARY GAP — pending second verification pass]: JSONB binary vs JSON text; TOAST (~2 KB threshold) for oversized payloads; WAL and insert throughput; GIN index write cost tradeoff.
- VI-D. **Partitioning:** native declarative range partitioning by date for time-series threat logs; retention/detach. [pending sourcing]
- VI-E. `postgresql.conf` tuning for high-velocity inserts (synchronous_commit, wal_*, checkpoint_*, shared_buffers). [pending sourcing]

### VII. Empirical Evaluation
- VII-A. Methodology: testbed topology, load generator (k6/autocannon), payload corpus provenance & labeling. [dataset provenance to be re-sourced — the "deepset" claim was refuted]
- VII-B. **Latency:** analytical budget derivation + measured p50/p90/p99; separate CPU-time and added-wall-clock-latency reporting; state the SLO precisely.
- VII-C. **Detection efficacy:** confusion matrix, FPR/FNR, mitigation rate over the corpus; report CIs. Frame ">99%" as an evaluated claim on a specified corpus, not a universal guarantee.
- VII-D. Threats to validity: corpus bias, adaptive-adversary limits, single-region measurement.

### VIII. Related Work
Edge/WAF security; LLM guardrails & prompt-injection defenses (StruQ/SecAlign brittleness); webhook signing; multi-tenant isolation.

### IX. Limitations and Future Work
Adaptive/obfuscated injections; heuristic maintenance; ML-layer integration under CPU budget; cross-region.

### X. Conclusion

### Appendices
- A. STRIDE→mitigation full mapping table.
- B. HMAC tenant-binding proof, full.
- C. Signature corpus & reproducibility artifacts.

---

## Two open items that gate peer-review readiness (need your call)

1. **PostgreSQL pillar (§VI) is unsourced.** I recommend a second focused deep-research pass on
   PostgreSQL official docs (TOAST/WAL/JSONB/partitioning/tuning) before writing §VI, so the
   internals are cited, not asserted.
2. **The 200-payload dataset provenance was refuted.** We need to pin a real, citable corpus.
   I recommend I verify `deepset/prompt-injections` directly and, if it doesn't cleanly yield
   ~200 labeled payloads, document a composed corpus with explicit provenance.
