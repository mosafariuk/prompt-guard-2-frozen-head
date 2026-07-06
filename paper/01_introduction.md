# I. Introduction

## I-A. Motivation

Enterprise SaaS platforms increasingly place Large Language Models (LLMs) on the *receiving*
end of webhooks. A payment-orchestration provider routes `charge.disputed` events into an LLM
that drafts a merchant response; a ticketing platform feeds inbound `issue.created` payloads to
an LLM triage agent; a workflow-automation vendor lets tenants wire arbitrary third-party events
into model-backed actions. In each case the LLM is a *shared, multi-tenant* compute resource
invoked by *externally originated, attacker-influenceable* HTTP requests. This composition is
qualitatively more dangerous than an interactive chatbot: the input is machine-delivered rather
than human-typed, it arrives at machine rates, and a single event may carry both tenant A's
trusted configuration and tenant B's adversarial content into the same model context.

Throughout this paper we use a **payment-gateway** as the running example because it exhibits the
full hazard profile — high request velocity, strong tenant-isolation requirements, regulatory
exposure, and a webhook interface that is, by construction, reachable by parties the platform
does not fully trust.

## I-B. Problem Statement

The prevailing defensive posture places LLM guardrails at the *application origin*: the request
traverses the public network, terminates at the platform's backend, and only there is it
inspected — for prompt injection, for signature validity, for tenant scope. This arrangement has
two structural defects.

1. **Latency and cost are paid before rejection.** A malicious webhook consumes a full network
   round trip and origin compute before it is discarded. Under a flood, the origin absorbs the
   full load of traffic it will ultimately reject.
2. **The trust boundary and the inspection point coincide.** The component that must be protected
   is also the component performing the protection. A parser bug or an injection that survives the
   guardrail executes in the same trust domain as tenant data.

A defense that inspects and authenticates requests *before* they reach the origin — at the
network edge, in a sandboxed runtime that shares no state with tenant data — addresses both. The
engineering question this paper answers is whether such an edge defense can be made
**cryptographically sound** (it must authenticate tenants, not merely filter text),
**computationally cheap enough** to run inside a constrained edge runtime, and **observable**
(every interception durably logged) without any of these properties gating the request path.

## I-C. A Premise We Must Correct Up Front

A recurring claim in edge-security folklore — and in the original specification of this work — is
that a "standard Cloudflare Worker enforces a 50 ms CPU limit," and that fitting a firewall
inside that window is the central engineering challenge. **This is incorrect as of 2026.** Our
verification against primary Cloudflare documentation establishes that the 50 ms figure is a
*legacy artifact*: it was auto-applied to the deprecated "Bundled" usage model during the
migration to Standard pricing on 2024-03-01 [C-pricing]. The current envelope (§III) is 10 ms of
CPU per invocation on the Free plan, and on paid plans a default of **30 seconds**, configurable
to **5 minutes** [C-limits, C-changelog-2025]. Moreover, CPU time meters *active computation
only*; time spent awaiting network, KV, or database I/O is excluded [C-limits].

Two consequences follow, and we treat them as first-class contributions rather than footnotes.
First, the design target for our deterministic screening layer is **sub-millisecond CPU**, which
sits three to four orders of magnitude below even the Free-plan ceiling — the engineering story
is *headroom*, not survival. Second, the "<50 ms" budget that genuinely matters is a **wall-clock,
end-to-end latency SLO**, a distinct quantity from the CPU-time limit. Conflating the two — as the
folklore does — produces both an overstated challenge and an unfalsifiable evaluation. We keep
them separate throughout, and §III and §VII report them independently.

## I-D. Contributions

This paper makes the following contributions.

1. **An edge-relocated, multi-layered defensive architecture** for LLM webhook ingestion in
   multi-tenant systems, in which authentication, screening, and logging execute in a V8-isolate
   edge runtime ahead of the origin (§III).
2. **A tenant-context-binding construction and its security argument.** We bind a tenant
   identifier into an HMAC-SHA256-signed message and prove, by reduction to HMAC's existential
   unforgeability under chosen-message attack (EUF-CMA), that an attacker cannot present a
   validly-signed webhook attributed to a tenant it does not control (§IV).
3. **A deterministic screening layer with explicit complexity bounds.** Aho-Corasick
   multi-pattern matching in O(n+z) over all injection signatures in a single pass, plus O(n)
   structural and entropy scoring, with a worst-case CPU-budget accounting that establishes the
   sub-millisecond claim against the measured §III envelope (§V).
4. **A non-blocking threat-logging data path.** Interception events are written out-of-band to a
   partitioned PostgreSQL JSONB store after the response is returned, so that durable logging
   never appears on the request's critical path (§VI).
5. **An empirical evaluation** reporting p50/p90/p99 latency (CPU and wall-clock reported
   separately) and detection efficacy — false-positive and false-negative rates — against a
   documented open-source prompt-injection corpus, together with the analytical latency budget
   that the measurements test (§VII).

As a cross-cutting contribution, we **date-stamp and correct the edge resource model** (I-C, §III),
replacing a widely-repeated but obsolete constraint with the current, primary-sourced envelope.

## I-E. Paper Organization

Section II formalizes the threat model with STRIDE and fixes the prompt-injection and
cross-tenant-leakage taxonomy. Section III characterizes the V8-isolate execution envelope.
Section IV develops the cryptographic tenant-isolation construction and its proof. Section V
specifies the heuristic screening layer and its complexity. Section VI details the asynchronous
JSONB logging architecture. Section VII presents the evaluation methodology and results.
Sections VIII–X cover related work, limitations, and conclusions.

---

### Citation keys used above (resolved in the References section)
- **[C-pricing]** Cloudflare, "Workers Pricing," developers.cloudflare.com/workers/platform/pricing (accessed 2026-07-04).
- **[C-limits]** Cloudflare, "Workers Limits," developers.cloudflare.com/workers/platform/limits (accessed 2026-07-04).
- **[C-changelog-2025]** Cloudflare, "Higher CPU limits," changelog 2025-03-25.

> Evidence status: every factual claim in §I is drawn from the verified-facts ledger
> (`paper/refs/verified-facts.md`), Part 1 — all CONFIRMED at high confidence (3-0 votes).
