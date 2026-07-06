# II. Threat Model and Taxonomy

We first fix the system and adversary model (§II-A), then decompose the attack surface with STRIDE,
applied with explicit cross-boundary coupling to account for the code/data confusion intrinsic to
LLMs (§II-B). We then pin the prompt-injection taxonomy to the OWASP LLM Top 10 (§II-C) and
formalize cross-tenant leakage (§II-D).

## II-A. System and Trust Model

**Principals.** Let $\mathcal{T} = \{t_1, \dots, t_N\}$ be the set of tenants provisioned on the
platform. Each tenant $t_i$ is associated with (i) a set of *webhook producers* — external
services (payment networks, ticketing backends) authorized by $t_i$ to emit events — and (ii) a
per-tenant secret $k_i$ used to authenticate those events (§IV). The platform operates an **edge
firewall** $F$ (a V8 isolate, §III) and an **origin** $O$ that hosts the shared LLM inference
service $\mathcal{M}$. A webhook is an HTTP request $r$ carrying a payload $p$ and metadata,
delivered to $F$, which either forwards a sanitized request to $O$ or rejects it.

**Trust boundaries.** Three boundaries matter. **B1**, the public network between producers and
$F$ (untrusted). **B2**, between $F$ and $O$ (mutually authenticated, private). **B3**, *inside*
$\mathcal{M}$, between the model's system/instruction context and the tenant-supplied content —
the boundary that prompt injection attacks. Classical architectures collapse B1's enforcement
into $O$; we relocate it to $F$, which shares no persistent state with tenant data.

**Assets.** (A1) Per-tenant secrets $k_i$. (A2) Tenant data resident in or reachable from
$\mathcal{M}$'s context. (A3) The integrity of the instruction channel at B3. (A4) Availability
and cost bounds of $\mathcal{M}$. (A5) The non-repudiable record of security events.

**Adversary model.** We assume a **Dolev–Yao network attacker** on B1 who can observe, drop,
replay, reorder, and inject arbitrary messages, but cannot break cryptographic primitives. We
additionally assume a **malicious-but-authenticated tenant** $t_a$: a legitimate principal holding
a valid $k_a$ who attempts to influence another tenant $t_b$'s model interactions (the
cross-tenant adversary). We do *not* assume a compromised $O$ or a broken HMAC/SHA-256; those are
the trust roots. This dual adversary — external forger plus insider tenant — is what distinguishes
multi-tenant LLM webhook security from single-tenant chatbot hardening.

## II-B. STRIDE Decomposition with Cross-Boundary Coupling

STRIDE classifies threats against *data flows*, and its six categories were defined for systems in
which the control plane (code) and data plane (data) are physically distinct channels. An LLM
violates this premise: instructions and data share one natural-language channel, so **Tampering
with the data an LLM reads becomes Elevation of Privilege the instant the model acts on it.** This
is not a new taxonomy; it is an *extended application* of STRIDE in which we retain the six
canonical categories as the primary classification and additionally annotate the **coupling
chains** ($T\!\rightarrow\!E$, $T\!\rightarrow\!I$) — a single event traversing two categories
across a trust boundary — that a flat per-category classification would obscure. Table I gives the
decomposition over the webhook→LLM pipeline.

**TABLE I. STRIDE decomposition of the multi-tenant webhook→LLM pipeline.**

| # | STRIDE | Threat (webhook→LLM) | Asset | Trust bdy | Coupling | Mitigating layer |
|---|---|---|---|---|---|---|
| 1 | **S**poofing | Forged/unsigned webhook impersonating a producer or tenant | A1 | B1 | — | HMAC tenant binding (§IV) |
| 2 | **T**ampering | Payload mutation in transit | A3 | B1 | — | Signature over canonical payload (§IV) |
| 3 | **T**ampering→**E** | Indirect injection: adversarial instructions embedded in retrieved/relayed content | A3 | B1,B3 | $T\!\rightarrow\!E$ | Heuristic screening (§V) + isolation |
| 4 | **T**ampering→**I** | Cross-tenant context poisoning: $t_a$ mutates shared state later read into $t_b$'s context | A2,A3 | B3 | $T\!\rightarrow\!I$ | Tenant binding (§IV) + per-tenant context |
| 5 | **R**epudiation | Attack occurs with no durable attribution | A5 | B1 | — | Async threat log (§VI) |
| 6 | **I**nfo. disclosure | System-prompt/context extraction; cross-tenant leakage | A2 | B3 | — | Screening (§V) + isolation |
| 7 | **D**oS | Token flood / CPU / subrequest exhaustion; "denial-of-wallet" cost amplification | A4 | B1 | — | Edge rejection within CPU budget (§III,§V) |
| 8 | **E**levation | Direct injection/jailbreak executes with the agent's tool/data privileges | A2,A3 | B3 | — | Screening (§V) + least-privilege tools |

**The lateral (multi-tenancy) axis.** Orthogonal to STRIDE, each threat has a *same-tenant* and a
*cross-tenant* manifestation. Same-tenant injection (a tenant attacking its own model surface) is
comparatively benign and well-studied; the platform's obligation is the **cross-tenant** cases —
rows 4 and 6 — where one tenant's input compromises another's confidentiality or integrity. We
therefore treat the effective threat space as $\text{STRIDE} \times \{\text{same},
\text{cross}\}$ and prioritize the cross-tenant quadrant. This is the precise sense in which our
contribution is *multi-tenant* security rather than generic LLM hardening.

**Why the coupling annotation matters for defense placement.** Because $T\!\rightarrow\!E$ (row 3)
originates as *Tampering on B1* but detonates as *Elevation at B3*, it can be intercepted at
*either* boundary. Origin-only defenses can act only at B3, after the model has already ingested
the payload. Relocating screening to $F$ lets us break the chain at B1 — before the data ever
reaches the channel where it can become an instruction. This is the architectural justification,
in threat-model terms, for the edge relocation argued informally in §I-B.

## II-C. Prompt-Injection Taxonomy (OWASP LLM01:2025)

We adopt the taxonomy of OWASP's *Top 10 for LLM Applications*, entry **LLM01: Prompt Injection**,
as the authoritative reference [OWASP-LLM01], corroborated in the literature [arXiv-2410.21146].
Prompt injection partitions into:

- **Direct injection.** The attacker supplies malicious instructions through inputs the model
  processes in real time, aiming to override the intended system instructions (e.g., "ignore
  previous instructions and …"). In the webhook setting, the payload body is the injection vector.
- **Indirect injection.** Adversarial instructions are embedded in *externally retrieved or
  relayed* content — a document, a web page, an upstream event field — that the model consumes as
  data but interprets as instruction. This is the vector for row 3 of Table I and the more insidious
  because the injecting party need not be the requesting party.
  - **Stored injection** is a subcategory of indirect in which the payload is persisted (e.g., in a
    record or knowledge base) and executes on a *later*, possibly different-tenant, retrieval —
    the mechanism underlying cross-tenant context poisoning (row 4).

We further sub-classify injection *techniques* (jailbreak families) as an implementation concern
of the screening layer — instruction-override, role-play/persona ("DAN"-style), system-prompt
extraction, delimiter/tag spoofing, and control-token injection — and enumerate their signatures
in §V and Appendix C. This taxonomy is *verified*: the direct/indirect (with stored as an indirect
subcategory) partition and its OWASP grounding were confirmed at high confidence.

## II-D. Formalizing Cross-Tenant Data Leakage

Let $c_b$ denote the model context assembled for a request on behalf of tenant $t_b$: it comprises
a platform system prompt $s$, tenant-scoped data $d_b$, and the request payload $p$. **Cross-tenant
leakage** is any execution in which information derived from $d_{a}$ ($a \neq b$) becomes
observable in the response to $t_b$, or vice versa. Two failure modes generate it.

1. **Shared-context leakage.** If context assembly places $d_a$ and $d_b$ in the same $c$ (e.g., a
   shared conversation buffer, a mis-scoped retrieval, a global cache), an extraction injection
   (row 6) in $p$ can exfiltrate $d_a$. Formally, isolation requires that for every request on
   behalf of $t_b$, $c_b \cap d_a = \emptyset$ for all $a \neq b$ — a property the *architecture*,
   not the model, must guarantee.
2. **Shared-key attribution failure.** If a single secret $k$ authenticates all tenants, a valid
   signature proves only that *some* authorized party sent the event, not *which* tenant. An
   attacker (or a confused-deputy producer) can then present content that the origin attributes to
   the wrong tenant, causing $p$ authored under $t_a$'s authority to execute in $c_b$. Preventing
   this is exactly the tenant-*binding* property we construct and prove in §IV: the signature must
   authenticate not just *authenticity* but *tenant identity*.

These two modes motivate the two independent controls the architecture provides — per-tenant
context isolation at the origin (assumed, and out of scope for the edge firewall) and per-tenant
cryptographic binding at the edge (§IV, our contribution). The threat model thus reduces the
cross-tenant obligation to a property we can state and prove cryptographically, which §IV does.

---

### Citation keys
- **[OWASP-LLM01]** OWASP, "LLM01:2025 Prompt Injection," Top 10 for LLM Applications, genai.owasp.org/llmrisk/llm01-prompt-injection.
- **[arXiv-2410.21146]** "*(indirect/stored injection taxonomy)*," arXiv:2410.21146.

> Evidence status: §II-C taxonomy is CONFIRMED (verified-facts Part 5, 3-0). The STRIDE
> decomposition and cross-tenant formalization in §II-A/B/D are original analytical framing built
> on the verified taxonomy; they assert no unverified external facts.
