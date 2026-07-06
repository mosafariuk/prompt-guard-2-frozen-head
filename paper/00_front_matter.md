# Multi-Layered Defensive Architecture and Webhook Securitization for LLM Deployment in Multi-Tenant Enterprise Systems

**Authors:** [Author list] — *corresponding:* mo@selected.org
**Target:** IEEE (TDSC / TIFS / S&P track). Format: IEEEtran, two-column.
**Draft compiled:** 2026-07-04.

> **Provenance note.** Every factual claim is traced to a primary source in the
> evidence ledger (`paper/refs/verified-facts.md`), assembled over three
> adversarial deep-research verification passes. Each section retains a *Citation
> keys* / *Evidence status* block recording what is CONFIRMED, MEASURED, or scoped;
> these provenance blocks would be stripped for camera-ready and are kept here to
> make the draft auditable. Result numbers are either MEASURED by the `benchmarks/`
> suite (detection, §VII Table III) or marked as placeholders pending deployment
> (latency, §VII-C).

## Abstract

Large Language Models (LLMs) exposed through webhook interfaces in multi-tenant
enterprise platforms — payment orchestration, ticketing, workflow automation —
inherit a hostile attack surface in which a single unauthenticated or adversarial
request can trigger prompt injection, cross-tenant data leakage, or spoofed event
delivery. Conventional application-layer guardrails, invoked only after the request
reaches origin, both add round-trip latency and concentrate risk at the trust
boundary they are meant to protect. This paper presents a multi-layered defensive
architecture that relocates the first line of defense to the network edge. We deploy
a reverse-proxying firewall on a V8-isolate edge runtime (Cloudflare Workers) that
(i) authenticates every webhook via HMAC-SHA256 signatures that cryptographically
bind a tenant identifier into the signed message, providing existentially-unforgeable
(EUF-CMA) tenant-context integrity with a multi-user bound independent of tenant
count and key-rotation multiplicity, plus timestamp-windowed replay resistance;
(ii) screens payloads with deterministic, single-pass NLP heuristics — Aho–Corasick
multi-pattern matching in $O(n+z)$, plus entropy and structural scoring — that execute
in a sub-millisecond CPU budget, orders of magnitude below the runtime's per-invocation
ceiling; and (iii) records every interception event to a partitioned PostgreSQL JSONB
store on a non-blocking, out-of-band write path so that threat logging never gates the
primary webhook execution path. We formalize the threat model with STRIDE extended by
cross-boundary coupling, derive the latency budget analytically, and evaluate detection
efficacy against open-source prompt-injection corpora. The deterministic edge layer is a
high-precision first filter (0.00 % FPR, 2.28 % recall on deepset); its recall gap is closed
by a self-hosted origin tier, to which the edge **fails open** for availability. Our central
empirical finding concerns that tier: Meta Prompt Guard 2's 22.8 % out-of-distribution recall
is a *decision-head artifact*, not an encoder limitation — a linear head on its frozen
embeddings reaches **99.9 % OOD recall at 0.7 % false-positive rate (AUC $\approx$ 0.999)** under
a pre-registered, leakage-controlled protocol on fresh disjoint data, and is deployed as the
production classifier. We treat the evaluation *discipline* as a first-class contribution:
pre-registered success criteria, cosine-$\ge$0.95 cross-split deduplication, refusal of
unverifiable-license data, and two NULL verdicts held on 99.7 %+ recall before the strict
false-positive ceiling was met. We further correct a widely-repeated misconception about edge
CPU limits and quantify the resulting engineering headroom.

**Index Terms** — LLM security, prompt injection, multi-tenant isolation, edge
computing, HMAC, webhook authentication, PostgreSQL, JSONB, threat modeling, STRIDE.
