# V. Lightweight NLP Heuristics for Webhook Screening

Having authenticated the webhook (§IV), the firewall screens its content for injection signatures
before forwarding. This section defends the *architectural* choice of a deterministic screening
layer over an LLM-based guardrail at this position (§V-A), specifies the Aho–Corasick signature
scanner (§V-B) and the linear feature passes (§V-C), gives input sanitization (§V-E), accounts the
total per-request cost against the §III budget (§V-F), and states honestly the accuracy ceiling of
heuristics relative to ML classifiers (§V-D).

## V-A. Why Deterministic Screening at the Edge, Not an LLM Guardrail

A natural objection is: *why not run an LLM guardrail (e.g., Llama Guard, a fine-tuned DeBERTa
injection classifier) at the edge instead of hand-maintained signatures?* The answer is not that
guardrails are less accurate — for many inputs they are more accurate (§V-D) — but that a
model-based guardrail is **structurally incompatible with this architectural layer**, for four
independent reasons rooted in §III.

1. **Compute placement.** Transformer inference is not a sub-millisecond, 128 MB-isolate workload.
   Llama Guard (≈7–8 B parameters) requires GPU-class accelerators and gigabytes of weights; even a
   small encoder-only classifier (DeBERTa-base, ≈184 M params) exceeds the isolate's 128 MB memory
   ceiling (§III-B) once weights, activations, and the runtime are counted, and its matrix-multiply
   inference is orders of magnitude beyond a $\kappa N_{\max}$ linear scan. The edge isolate is the
   *wrong hardware* for tensor math.
2. **The guardrail becomes a network hop, not local compute.** Deploying the model behind an
   inference API turns screening into a *subrequest* — adding a full RTT (tens to hundreds of ms of
   wall-clock, per the layered-detector measurements: model deep-scan adds ≈300–800 ms [Layered])
   to *every* webhook, including the benign majority. This inverts the design goal of §I-B: the
   cheap perimeter check now costs more than the origin call it is meant to gate. A deterministic
   scan keeps screening as *local CPU* (I/O-free), preserving the wall-clock SLO.
3. **Determinism and auditability.** A signature match is explainable and reproducible: the threat
   log (§VI) records *which* signature fired. A model score is neither, complicating the
   non-repudiation obligation (Table I, row 5) and incident forensics.
4. **Attack surface.** An LLM guardrail is itself susceptible to prompt injection — the very
   threat it screens for [arXiv-2601.07185 finds SFT defenses learn brittle surface heuristics].
   A finite-state automaton has no instruction-following semantics to subvert.

The correct architecture is therefore **layered**: a deterministic, high-precision, sub-millisecond
scan at the edge (this section) that rejects known-signature attacks cheaply and, for the residual
uncertain traffic, *optionally* escalates to a model-based deep scan at the origin — where GPU
compute and higher latency budgets exist. This paper's contribution is the edge layer; the escalation
tier is discussed as future work (§IX). The edge layer's role is not to be the last word on
subtle semantic attacks but to eliminate the high-volume, signature-expressible ones within the CPU
envelope, so that the expensive tiers see less traffic.

## V-B. Layer 1: Aho–Corasick Multi-Signature Scan

**Problem.** Given a signature set $S=\{s_1,\dots,s_p\}$ (injection phrases, jailbreak markers,
control tokens; Appendix C), determine which $s_j$ occur in the sanitized payload $x$ of length $n$.

**Why not per-pattern matching.** Running a separate matcher per signature costs
$O\!\big(\sum_j (n+|s_j|)\big)=O(pn+m)$ where $m=\sum_j|s_j|$ — linear in the *number* of
signatures $p$. With $p$ in the hundreds to thousands, the $pn$ term dominates and scales poorly.
A single regular expression alternation `(s_1|...|s_p)` compiled to an NFA risks catastrophic
backtracking on adversarial input (a ReDoS vector), which is itself a DoS surface (Table I, row 7).

**Aho–Corasick.** The Aho–Corasick automaton is a trie of all signatures augmented with failure
(suffix) links, forming a deterministic finite automaton that matches **all** signatures in a
**single pass** over $x$, regardless of $p$ [Springer-AC]:

- **Construction:** $O(m)$ time and space in the total signature length $m$ — built **once at
  module top level** (§III-A) and amortized to zero on the request path.
- **Search:** $O(n+z)$, where $n=|x|$ and $z$ is the number of matches reported; each input byte
  triggers a constant number of automaton transitions (goto/failure), with **no backtracking**.

Contrasted with KMP — a *single*-pattern algorithm at $O(n+|s_j|)$ per pattern, hence $O(pn+m)$
for $p$ patterns — Aho–Corasick removes the dependence on $p$ from the search cost entirely
[Springer-AC]. This is the property that makes hundreds of signatures affordable in one scan.

**Match cap (bounding $z$).** Since $z\le n$ in the worst case (e.g., many overlapping short
signatures), we cap reported matches at a constant $z_{\max}$ and early-exit on the first
*blocking*-class signature, so the effective per-request search cost is $O(n+\min(z,z_{\max}))=
O(n)$. Early exit is safe for a *reject* decision (one confirmed malicious signature suffices) and
the cap only limits *enumeration* for logging, not detection.

## V-C. Layer 2: Linear Structural and Entropy Features

Signatures catch *known* phrasings; a small set of $O(n)$ structural features catches *structural*
injection independent of exact wording. Each is a single linear pass, contributing to the constant
$k\le 4$ of §III-C:

- **Delimiter/role-token density.** Count occurrences of instruction-boundary and role markers
  (`### instruction`, `<|system|>`, `assistant:`, fenced-block openers) normalized by length; a
  spike signals delimiter-spoofing / tag-injection. $O(n)$, computed as a by-product of the
  Aho–Corasick pass over a token sub-dictionary.
- **Imperative-override heuristic.** Presence of override collocations ("ignore/disregard …
  previous/above … instructions/prompt") captured as multi-word signatures in Layer 1; scored as a
  weighted feature rather than an immediate block to limit false positives on benign text that
  quotes such phrases.
- **Shannon entropy.** $\hat{H}(x)=-\sum_{c} \hat p(c)\log_2 \hat p(c)$ over the byte/character
  distribution, one pass to accumulate counts, $O(n)$. Anomalously high entropy flags encoded or
  obfuscated payloads (base64/hex smuggling) that evade literal signatures; anomalously low entropy
  with high delimiter density flags templated injection. Entropy is a *weak* feature used only to
  *escalate* (route to the origin deep-scan tier), never to block alone (§V-D).

The layer emits a score vector; a linear threshold rule combines Layer 1 blocking hits (hard
reject), weighted Layer 1/2 features (soft score), and an escalate/forward/reject decision. All
features are $O(n)$ and share the input scan, so Layer 2 adds a small constant multiple of $n$, not
a new asymptotic term.

## V-D. Accuracy Ceiling: Heuristics vs. ML Classifiers (Honest Positioning)

We do **not** claim deterministic heuristics match ML classifiers on subtle or novel injections.
The evidence base is explicit about the ceiling, and we report it rather than obscure it:

- Lexical/deterministic filters achieve moderate standalone discrimination — reported ROC-AUC in
  the ≈0.65 band for Aho–Corasick / regex-denylist style detectors on injection corpora
  [arXiv-2601.07185] *(from source; to be re-verified at claim level, see caveat)*.
- Embedding-based ML classifiers can do better: a Random Forest over `text-embedding-3-small`
  features reached AUC 0.764 / P 0.867 / R 0.870, outperforming encoder-only baselines (DeBERTa
  variants at AUC ≈0.50–0.59) [arXiv-2410.22284] — though this rests on a single preprint with an
  author-curated set and modest absolute AUC (medium confidence, verified-facts Part 2).
- Fine-tuned guardrails achieve high attack-rejection but can learn brittle surface correlations
  with large OOD degradation [arXiv-2601.07185] (medium confidence, single source).

The design implication is precisely the layering of §V-A: the edge heuristics are positioned as a
**high-precision first filter** (favoring low false-positive rate at a chosen operating point, so
benign traffic is not wrongly blocked) that cheaply removes signature-expressible attacks, with the
*recall gap* on novel/semantic attacks delegated to an optional origin-side model tier. §VII
measures the edge layer's own FPR/FNR at its operating point; we make no claim that the edge layer
alone achieves the full-system detection rate, only that it does so for the signature-expressible
class it targets, within the CPU budget.

## V-E. Input Sanitization and Canonicalization

Signatures match a *canonical* representation; an attacker who can vary encoding while preserving
meaning evades a naive scan. Before Layer 1, the firewall (Fig. 1, step 3) applies, in one or two
linear passes: (a) **Unicode normalization** (NFKC) to fold compatibility/homoglyph variants; (b)
**decoding of transport encodings** actually in scope (percent-encoding, HTML entities) where the
downstream will decode them, to prevent encode-smuggling past the scanner; (c) **whitespace and
zero-width-character collapse** (zero-width joiners/spaces are a known signature-splitting trick);
and (d) **case folding** for case-insensitive signatures. Sanitization is bounded by $O(n)$ and
its output length is $\le c\cdot n$ for a small constant, preserving the $N_{\max}$ bound. Crucially,
sanitization is applied to the copy that is *scanned*; the *forwarded* payload is the original (the
signature over which was already verified in §IV), so normalization cannot alter authenticated
content — it only informs the block/forward decision.

## V-F. Per-Request Cost Accounting Against the §III Budget

Collecting the layers, the per-request CPU cost is
$$C_{\text{req}} \le \underbrace{c_{\text{san}}n}_{\text{§V-E}} +
\underbrace{c_{\text{ac}}(n+z_{\max})}_{\text{§V-B, capped}} +
\underbrace{k\,c_{\text{lin}}n}_{\text{§V-C},\ k\le4} +
\underbrace{c_{\text{hmac}}n}_{\text{§IV}} = \kappa\,n \le \kappa N_{\max},$$
exactly the form of §III-C: a constant $\kappa$ times a bounded input, with the one-time $O(m)$
automaton construction excluded (module scope). There is no super-linear term, no backtracking, and
no per-request allocation proportional to $p$ (the signature count lives in the shared, once-built
automaton counted against the 128 MB isolate memory, not per request). The absolute
sub-millisecond claim is thus reduced to a single measured quantity $\kappa/\rho$ (§III-C),
evaluated at $N_{\max}=128$ KiB against the 10 ms Free-plan ceiling in §VII. The structural
guarantee — bounded, strictly linear, backtrack-free, construction-amortized — holds regardless of
the measured constant, which is the claim §III promised this section would substantiate.

---

### Citation keys
- **[Springer-AC]** "*(Aho–Corasick multi-pattern matching for signature detection)*," Springer, doi:10.1007/978-3-031-96093-2_15.
- **[arXiv-2601.07185]** "Defenses Against Prompt Attacks Learn Surface Heuristics," arXiv:2601.07185.
- **[arXiv-2410.22284]** Ayub & Majumdar, "*(embedding-based prompt-injection classification)*," CAMLIS 2024, arXiv:2410.22284.
- **[Layered]** "*(layered prompt-injection detector; <1 ms Layers 1–2, 300–800 ms model layer)*," dev.to (secondary; used only for the model-tier latency order-of-magnitude).

> Evidence status: Aho–Corasick complexity (V-B) is CONFIRMED (verified-facts Part 2, 3-0). The
> heuristic-vs-ML figures (V-D) are MEDIUM confidence / single-source and are presented as such,
> with the lexical-filter AUC flagged for claim-level re-verification. V-A's LLM-guardrail
> incompatibility argument rests on the CONFIRMED §III envelope (128 MB, sub-ms CPU) plus the
> model-tier latency order-of-magnitude from [Layered] (secondary — used only qualitatively).
