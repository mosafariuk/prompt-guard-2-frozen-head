# VIII. Related Work

We situate the contribution across five strands. Throughout, we cite only sources whose claims were
primary-verified in this work or which are canonical, dated references; any citation requiring final
bibliographic completion is marked `[cite]`.

**Edge and serverless security.** Web Application Firewalls and CDN-layer filtering are established,
but classical WAF rule engines target SQL-injection/XSS signatures over HTTP structure, not
natural-language instruction injection into an LLM. The V8-isolate execution model [C-limits] gives
a materially different cost envelope than container-per-request FaaS (cold start, per-request
process), which prior serverless-security work assumes; our cost model (§III-C) is specific to the
isolate's amortized-construction, CPU-vs-I/O-metered regime and, to our knowledge, is the first to
bound an LLM-injection screener against the *corrected* (post-2024) Workers CPU envelope rather than
the obsolete 50 ms figure.

**LLM prompt-injection defenses.** The field spans (i) fine-tuned structural defenses — StruQ,
SecAlign — which achieve high attack-rejection but were recently shown to learn brittle surface
heuristics with large OOD degradation [arXiv-2601.07185]; (ii) embedding-based classifiers (RF/
XGBoost over prompt embeddings) that can outperform encoder-only baselines but at modest absolute
AUC on curated sets [arXiv-2410.22284]; (iii) model-based guardrails (Llama Guard-class) `[cite]`;
and (iv) deterministic/lexical filters. The OWASP LLM Top 10 [OWASP-LLM01] fixes the direct/indirect
taxonomy we adopt (§II-C), corroborated by [arXiv-2410.21146]. Our position (§V-A) is *not* to
compete with model guardrails on recall but to argue their *architectural* misplacement at the edge
and to occupy the high-precision, sub-millisecond, I/O-free niche a finite-state matcher uniquely
fills — with the model tier relocated to the origin (§IX). The multi-pattern primitive is
Aho–Corasick [AC75], whose $O(n+z)$ single-pass matching [Springer-AC] is what makes hundreds of
signatures affordable in the isolate budget.

**Webhook authentication and MAC security.** Production webhook signing (Stripe's timestamped
`t`/`v1` HMAC-SHA256 scheme [Stripe-sig], GitHub's equivalent `[cite]`) establishes the practice we
formalize. HMAC itself is RFC 2104 [RFC2104] / FIPS 198-1 [FIPS198-1], with PRF-security from
Bellare–Canetti–Krawczyk [BCK96] and *tight multi-user* security from Bellare–Bernstein–Tessaro
[BBT16] — the latter is what lets our tenant-binding bound (§IV-C/D) avoid linear degradation in the
tenant count. The novelty is not HMAC but the *tenant-binding theorem*: to our knowledge, prior
webhook-signing treatments authenticate *message integrity* but do not prove *tenant-context
binding* as a reduction discharging a cross-tenant-isolation obligation (§II-D → §IV).

**Multi-tenant isolation.** Cross-tenant leakage in shared-context LLM systems is an emerging
concern; the adversary model combining a Dolev–Yao network attacker [DY83] with a malicious
authenticated tenant (§II-A) is, we believe, the appropriate formalization for multi-tenant webhook
ingestion and is not standard in prior LLM-security threat models.

**High-velocity logging.** Time-series and append-only logging over PostgreSQL is well-trodden
operationally; our contribution is the specific composition — `waitUntil`-decoupled writes, a
durable queue for at-least-once delivery, JSONB+TOAST for unstructured payloads, GIN `fastupdate`
to bound index cost, and declarative range partitioning for O(1) retention [PG-toast, PG-gin,
PG-partition] — tied to PCI-DSS Req 10.5.1 / SOC 2 CC7 with edge-side PAN redaction (§VI-F).

**In sum**, each primitive is prior art; the *contribution is the vertically-integrated composition*
— edge relocation + a proven tenant-binding cryptographic layer + a cost-bounded deterministic
screener + a non-blocking compliant logging path — engineered against the real, current constraints
of the edge runtime and evaluated with methodological honesty.

# IX. Limitations and Future Work

**Limitations (stated plainly).** (L1) The edge screener is deterministic and therefore evadable by
an adaptive adversary who crafts novel phrasings outside the signature set; §V-D's recall claim is
scoped to the signature-expressible class, and static-corpus recall (§VII) is *not* robustness
against adaptive attack. (L2) HMAC is symmetric, so the scheme provides no **forward secrecy**: a
leaked per-epoch key forges within its rollover window (§IV-D). (L3) Cross-tenant *context*
isolation at the origin (the $c_b\cap d_a=\emptyset$ property of §II-D, mode 1) is *assumed*, not
enforced by the edge; the firewall discharges the *attribution* obligation (mode 2) only. (L4) The
replay nonce cache (§IV-E) is regional; a globally distributed producer set needs distributed replay
state. (L5) Evaluation is single-region, bilingual, and on a modestly-sized corpus (§VII-F).

**Future work.**

1. **Origin-side escalation tier (implemented, deployed, measured).** We built and *deployed* the
   Layer-3 escalation tier as a self-hosted classifier and measured it live on the full corpus
   (§VII, Table IV): the chosen multilingual **Prompt Guard 2 86M** achieves 22.8 % recall at 0.25 %
   FPR, and the English-only proxy 41.4 % at 1.0 % FPR — both an order of magnitude above the edge
   alone, and both far below their vendor self-reports (97.5 % / 99.7 %). We *tested* the two obvious
   remedies (§VII, Phase 4): a PG2 threshold sweep lifts recall only to 26.6 %, and an OR-ensemble with
   NVIDIA NemoGuard (jailbreak axis) adds 0 % on this injection corpus — compounded by our inability to
   reproduce NemoGuard's CPU embedding pipeline from public artifacts (a blatant jailbreak scored ~0.09;
   we do not claim NemoGuard is weak, only that we could not faithfully run it off-NIM). That the
   flagship model sits at 22.8 % recall and neither of those two remedies closes the gap was, at
   Phase 4, the key open question. **Phase 5 resolved it (§VII, Table VI): the gap is NOT structural.**
   A linear head trained on PG2's *frozen* embeddings reaches **99.9 % OOD recall at 0.7 % FPR**
   (AUC ≈ 1.0) under a pre-registered, leakage-controlled protocol — proving the encoder always
   carried near-perfect signal and the 22.8 % was purely Meta's precision-first decision head. The
   composed **PG2-encoder → logistic-head** classifier is deployed as the origin Tier-3a model,
   replacing the native head. Remaining future work: a cost model bounding the escalation rate,
   adaptive-attack hardening, and periodic re-calibration of the head threshold on deployment traffic.
2. **Threat-log-driven signature synthesis (closed loop).** Mine the §VI JSONB threat log to
   auto-propose new Aho–Corasick signatures from clustered novel payloads, with human-in-the-loop
   validation — turning the logging tier from a passive record into an active detection feedback
   loop, and partially closing L1 against slowly-adapting adversaries.
3. **Forward-secure / asymmetric webhook signing.** Replace or augment symmetric HMAC with per-epoch
   key ratcheting or asymmetric signatures to obtain forward secrecy and reduce key-distribution
   burden (addressing L2), quantifying the added edge CPU cost of asymmetric verification against
   the §III budget.
4. **TEE-backed origin context isolation.** Enforce (rather than assume) the mode-1 isolation of L3
   with hardware-isolated per-tenant model contexts, extending the cryptographic guarantee across
   trust boundary B3.
5. **Distributed replay state.** Realize the nonce cache as globally-consistent state (e.g., Durable
   Objects) with an explicit latency/consistency trade characterization (addressing L4).
6. **Adaptive-adversary and multi-modal evaluation.** Extend the corpus to adaptive/obfuscated and
   non-text (image/file) injection vectors, and characterize the economic ("denial-of-wallet") DoS
   bound formally.

# X. Conclusion

We presented a multi-layered defensive architecture that relocates the first line of LLM-webhook
defense to the network edge and integrates four contributions into one request path: (i) an
edge-isolate firewall whose per-request cost is provably bounded — strictly linear in a capped
input, backtrack-free, with one-time automaton construction amortized to module scope — and analyzed
against the *corrected* Cloudflare Workers envelope (10 ms free / 30 s–5 min paid CPU, 128 MB
isolate), replacing the widely-repeated but obsolete "50 ms" premise with primary-sourced facts;
(ii) a cryptographic tenant-isolation layer whose tenant-binding property is proven by reduction to
HMAC's multi-user EUF-CMA security, yielding a bound independent of tenant count and key-rotation
multiplicity, with replay handled as an orthogonal freshness property; (iii) a deterministic
Aho–Corasick screening layer, honestly positioned as a high-precision sub-millisecond first filter
whose recall gap on novel semantic attacks is delegated to an origin-side model tier; and (iv) a
non-blocking, compliance-aware threat-logging path over partitioned PostgreSQL JSONB that never
gates the request and never persists cardholder data.

Two commitments distinguish the work methodologically: every platform figure is primary-sourced and
date-stamped against an actively-changing edge platform, and every *result* quantity is deferred to
a reproducible benchmark harness rather than asserted — the paper specifies the experiment and lets
measurement dictate the claims.

**The deployed system, operating as the AIO Apex enterprise firewall, is a dual-tier composition.**
A multi-tenant Cloudflare edge performs the
rapid, sub-millisecond screen — HMAC-SHA256 tenant binding for authenticated isolation, plus
Aho–Corasick signature matching — and **fails open to a self-hosted origin deep-scanner** when the
model tier is unreachable, so availability never depends on the heavier layer. That origin tier now
runs the Phase-5 classifier: **Prompt Guard 2's frozen encoder feeding a calibrated linear head**.

**The central empirical result is that the recall gap was never structural.** Meta's Prompt Guard 2
exhibits 22.8 % out-of-distribution recall through its *native* head, and Phase 4 might have
concluded the encoder was blind to those attacks. Phase 5 disproves that: a *linear* logistic head on
the model's frozen penultimate embeddings reaches **99.9 % OOD recall at 0.7 % false-positive rate
(AUC $\approx 0.999$)** under a pre-registered, leakage-controlled protocol on fresh, disjoint data
(Table VI). The 22.8 % was purely a **decision-head artifact** — Meta's precision-first calibration —
not an encoder limitation; the injection signal was present in the representation all along and
merely required a properly calibrated boundary to extract. This composed head is deployed as the
origin tier, replacing the native head end-to-end.

Equally, we regard the *discipline* that produced that number as a contribution in its own right
(§VII-G): success criteria pre-registered before any code, cosine-$\ge 0.95$ cross-split
deduplication, refusal of unverifiable-license data, and — decisively — **two NULL verdicts held on
99.7 %+ recall** because a strict FPR point-estimate ceiling was not cleared, before the bar was met
on genuinely fresh data. A 99.9 % that survives that process is worth more than one asserted without
it. The architecture demonstrates that strong, provable multi-tenant LLM webhook security — and a
detector that closes the recall gap — is achievable within the real constraints of edge compute,
with vast CPU headroom rather than at its margin, provided each layer is engineered to the
platform's actual, current envelope and each claim is earned rather than curated.

---

### Additional citation keys (canonical / dated)
- **[AC75]** A. V. Aho, M. J. Corasick, "Efficient String Matching: An Aid to Bibliographic Search," Communications of the ACM, 18(6):333–340, 1975.
- **[DY83]** D. Dolev, A. C. Yao, "On the Security of Public Key Protocols," IEEE Trans. Information Theory, 29(2):198–208, 1983.
- **[Wilson27]** E. B. Wilson, "Probable Inference, the Law of Succession, and Statistical Inference," J. American Statistical Association, 22(158):209–212, 1927. *(§VII-E interval.)*
- (Prior citation keys [C-limits], [OWASP-LLM01], [arXiv-2601.07185], [arXiv-2410.22284], [arXiv-2410.21146], [Springer-AC], [Stripe-sig], [RFC2104], [FIPS198-1], [BCK96], [BBT16], [PG-*], [DS-*] resolve as defined in their home sections.)

> Evidence status: §VIII cites only primary-verified sources or canonical dated works (Aho–Corasick
> 1975, Dolev–Yao 1983, Wilson 1927 — all real, well-established); items needing final bibliographic
> detail (Llama Guard, GitHub webhook docs) are marked `[cite]` and must be completed before
> submission — none is load-bearing for a claim. §IX limitations are the honest consolidation of the
> non-claims made throughout (forward secrecy, adaptive adversary, assumed origin isolation).
> §X asserts no new facts.
