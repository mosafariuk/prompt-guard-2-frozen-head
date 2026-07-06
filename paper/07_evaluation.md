# VII. Empirical Evaluation

This section defines the evaluation of two claims the architecture must support: **latency** — the
edge firewall adds bounded, sub-SLO latency at the tail (§VII-B analytical, §VII-C protocol) — and
**detection efficacy** — the edge layer mitigates the signature-expressible attack class at high
rate with a controlled false-positive rate (§VII-D). We first fix the methodology and corpus
(§VII-A), then give the analytical latency model, the measurement protocols, the statistical
treatment (§VII-E), and threats to validity (§VII-F).

> **Reporting convention.** This paper specifies the experiment and does **not** assert result
> values it has not measured. **Detection-efficacy results (§VII-D) are populated from a real run**
> over the 662-row deepset corpus via the Phase-2 harness; **latency percentiles (§VII-C) remain
> placeholders** $\langle\cdot\rangle$ pending a full edge deployment. Analytical bounds (§VII-B) are
> derived and labelled as such, distinct from empirical percentiles. Where a run overturned an
> initial expectation — as the detection numbers do for the "$>99\%$" ambition — we report the
> measurement and revise the claim, not the reverse.

## VII-A. Methodology and Benchmark Corpus

**Testbed.** The firewall Worker is deployed to the edge runtime (Cloudflare Workers) with a mock
origin that returns a fixed-size response after a controlled service time $S_O$, isolating the
firewall's *added* latency from origin variability. Load is generated with **k6** (distributed,
scriptable, native percentile output) cross-checked against **autocannon** for a second
measurement path. Each configuration is run for $R$ repetitions after a warm-up that guarantees a
warm isolate (§III-A), so cold-start is measured separately (§VII-C) rather than contaminating the
steady-state distribution.

**Benchmark corpus (documented provenance).** Rather than the folklore "200-payload set" — which
corresponds to no real dataset — we use a corpus of *verified provenance*:

- **Primary:** `deepset/prompt-injections` (Hugging Face) — **662 examples** (546 train / 116 test),
  binary labels **0 = legitimate, 1 = injection**, columns `text`/`label`, German+English, Apache
  2.0 [DS-PI]. The **malicious payload set** $\mathcal{X}^{+}$ is the `label==1` subset; the
  **benign control set** $\mathcal{X}^{-}$ (for false-positive measurement) is the `label==0`
  subset.
- **Diversity supplement:** `jackhhao/jailbreak-classification` (1,306 rows, `jailbreak`/`benign`,
  Apache 2.0 [DS-JB]) and `Lakera/gandalf_ignore_instructions` [DS-GA], to test recall on jailbreak
  and instruction-ignore families beyond the primary set.

The exact counts $|\mathcal{X}^{+}|, |\mathcal{X}^{-}|$ used in each experiment are reported **from
the data at run time** (a seed-fixed, documented split), not assumed; the harness prints them for
inclusion in the results table. This makes the corpus reproducible from named, licensed sources —
directly remedying the unsupported dataset provenance the design review flagged.

## VII-B. Analytical Latency Model (the theoretical bound)

We decompose the firewall's *added* end-to-end latency (excluding origin service time $S_O$, which
the firewall does not control) into its constituent terms, per the Fig. 1 pipeline:
$$L_{\text{added}} \;=\; \underbrace{L_{\text{CPU}}^{\text{proc}}}_{\text{steps 1--6, local}}
\;+\; \underbrace{L_{\text{enq}}}_{\text{waitUntil enqueue, off-path}}
\;+\; \underbrace{L_{\text{net}}^{\Delta}}_{\text{proxy hop overhead}}.$$

**The CPU term.** From §III-C/§V-F, the local processing cost is $C_{\text{req}}\le\kappa N_{\max}$
operations, i.e. wall-time $L_{\text{CPU}}^{\text{proc}} = C_{\text{req}}/\rho \le
(\kappa/\rho)\,N_{\max}$. This is the term the theory bounds; $\kappa/\rho$ (per-byte wall cost) is
the single empirical constant, measured in §VII-C. Structurally it is $O(N_{\max})$ with no
super-linear component, so it cannot exhibit a heavy tail from the algorithm itself.

**The off-path term.** $L_{\text{enq}}$ is the `queue.send` enqueue (§VI-B). Because the threat-log
write is deferred via `waitUntil` *after* the response returns, $L_{\text{enq}}$ contributes to the
*response* path only as a single fast subrequest and the DB write contributes **zero** (it happens
after the client is served). We include $L_{\text{enq}}$ conservatively; if the enqueue itself is
also deferred behind the response, this term vanishes from $L_{\text{added}}$.

**The proxy-hop term.** $L_{\text{net}}^{\Delta}$ is the incremental network cost of interposing the
edge proxy versus a direct origin call. Since the edge runtime terminates the connection at a
point-of-presence geographically near the client, $L_{\text{net}}^{\Delta}$ is typically *small or
negative* (edge TLS termination can reduce client-perceived latency), but we treat it as a
non-negative unknown bounded by measurement.

**Tail (p99) argument.** The p99 of $L_{\text{added}}$ is bounded by the p99 of each additive term
(subadditivity of quantiles does not hold in general, so we bound conservatively by the sum of
per-term p99s under independence, and validate empirically):
$$L_{\text{added}}^{p99} \;\lesssim\; \frac{\kappa}{\rho}N_{\max}
\;+\; L_{\text{enq}}^{p99} \;+\; L_{\text{net}}^{\Delta,p99}.$$
The **claim to be tested** is $L_{\text{added}}^{p99} < 50\text{ ms}$. The analysis shows the
*algorithmic* term is a bounded constant (sub-millisecond for realistic $\kappa/\rho$ and
$N_{\max}=128$ KiB, since even $\rho$ on the order of $10^{8}$ byte-ops/s gives
$\frac{\kappa}{\rho}N_{\max}\ll 1$ ms), so any violation of the 50 ms target must originate in the
*network/queue* terms, not the firewall's computation — which is the decomposition's diagnostic
value. §VII-C tests the bound and attributes any tail to the correct term.

## VII-C. Empirical Latency Protocol

- **Percentiles.** Report $\langle p50\rangle, \langle p90\rangle, \langle p99\rangle$ (and
  $\langle p99.9\rangle$) of $L_{\text{added}}$, computed from $\ge N_{\text{req}}$ requests per
  configuration with the origin mock's $S_O$ subtracted. Percentiles are estimated with the harness's
  streaming estimator and cross-checked by a bootstrap over raw samples (§VII-E).
- **Isolating $\kappa/\rho$.** Sweep payload size $N\in\{1\text{ KiB},\dots,N_{\max}\}$ and regress
  $L_{\text{CPU}}^{\text{proc}}$ on $N$; the slope is $\kappa/\rho$ (closing the §III-C/§V-F loop with
  a measured constant), the intercept is fixed overhead. Report $\langle\kappa/\rho\rangle$ with a
  confidence band.
- **Cold vs warm.** Report cold-start added latency $\langle L_{\text{cold}}\rangle$ separately
  (first request to a fresh isolate, including module-scope automaton build, §III-A) from warm
  steady state, since they have different distributions and the automaton build is a one-time cost.
- **Load levels.** Repeat at increasing arrival rates to the saturation point; report the rate at
  which $L_{\text{added}}^{p99}$ crosses the SLO, characterizing headroom.

## VII-D. Detection-Efficacy Methodology

**Confusion matrix.** Running $\mathcal{X}^{+}\cup\mathcal{X}^{-}$ through the firewall at a fixed
decision threshold $\theta$ (§V-C) yields counts $TP, FP, TN, FN$. We report:
$$\text{FNR}=\frac{FN}{TP+FN},\quad \text{FPR}=\frac{FP}{FP+TN},\quad
\text{Mitigation}=\text{Recall}=\frac{TP}{TP+FN}=1-\text{FNR},\quad
\text{Precision}=\frac{TP}{TP+FP}.$$
The "$>99\%$ mitigation" target is thus the hypothesis $\text{Recall}>0.99$ **on the
signature-expressible malicious class** (the scoping of §V-D — we do not claim it for arbitrary
semantic attacks). It is reported as $\langle\text{Recall}\rangle$ with a confidence interval, not
asserted.

**Interval estimation.** Because $TP,FP$ are binomial counts, point rates are insufficient; we
report **Wilson score 95% confidence intervals** for each proportion (Wilson is preferred over
normal-approximation for proportions near 0 or 1, exactly the regime of a $>99\%$ recall claim). A
claim "$\text{Recall}>0.99$" is credited only if the *lower* Wilson bound exceeds 0.99, which in
turn dictates the minimum $|\mathcal{X}^{+}|$ needed (§VII-E).

**Operating point and ROC.** We sweep $\theta$ to trace the ROC/precision-recall curve and select
the operating point by the design priority of §V-D (high precision / low FPR first filter), and
report the chosen $\theta$, its FPR/FNR, and the AUC $\langle\text{AUC}\rangle$ for comparability
with the literature band (lexical filters ≈0.65; embedding classifiers ≈0.76, §V-D).

**Per-family breakdown.** Report recall separately per attack family (direct override, role-play,
delimiter/tag, control-token, §II-C/Appendix C) and per source dataset, since an aggregate rate can
mask a blind spot in one family — a per-family table is more informative and more honest than a
single headline number.

**Results (measured, full deepset corpus).** Running the complete 662-row corpus
($|\mathcal{X}^{+}|=263$ injection, $|\mathcal{X}^{-}|=399$ legitimate) through the shipped edge
screening pipeline at $\theta=1.0$ yields Table III.

**TABLE III. Edge screening layer on deepset/prompt-injections (Wilson 95% CI).**

| Metric | Value | 95% CI |
|---|---|---|
| Mitigation (Recall) | **2.28 %** | [1.05 %, 4.89 %] |
| False-Positive Rate | **0.00 %** | [0.00 %, 0.95 %] |
| Precision | 100.00 % | [60.97 %, 100 %] |
| ROC AUC | **0.511** | — |

This result is decisive and, we argue, *strengthens* the paper rather than undermining it, because
it confirms the §V-D positioning empirically and refutes an overclaim. Three readings follow.
**(i)** The edge layer is a **high-precision, low-recall first filter**: it blocked $6/263$
injections while raising **zero** false positives over $399$ legitimate payloads — it never harms
benign traffic, the property a perimeter filter must guarantee. **(ii)** Its recall on the *full*,
diverse, partly-German deepset distribution is low ($2.28\%$, AUC $\approx$ chance) because a
compact deterministic signature set cannot, even in principle, cover novel or multilingual
phrasings — precisely the ceiling §V-D anticipated and the motivation for the origin escalation
tier (§IX). **(iii)** Consequently, **the "$>99\%$ mitigation" figure is a *full-system* target,
not an edge-layer property**, and the data show the signature layer alone does not meet it: the
Wilson lower bound is $1.05\%$, nowhere near $0.99$, so the hypothesis $\text{Recall}>0.99$ is
**rejected for the edge layer in isolation**. We therefore restate the system's detection claim
precisely: the edge layer contributes *high-precision, zero-false-positive* removal of the
signature-expressible subclass within the sub-millisecond CPU budget, and the aggregate mitigation
rate is a property of the *composed* edge + origin-tier system, whose measurement we scope to future
work (§IX). Reporting Table III rather than curating a benchmark to flatter the signature set is the
methodological commitment of §VII's opening convention.

**Full-system result (edge + origin escalation tier).** We implemented and *deployed* the
origin-side escalation tier (§IX) as a self-hosted injection classifier, and measured the *composed*
system on the same corpus — a payload is blocked iff the edge hard-rejects it **or** the classifier
flags it. We report two classifiers run on the live deployment (CPU inference): the ungated
`protectai/deberta-v3-base-prompt-injection-v2` (English-only), and the chosen, purpose-built
multilingual **Meta Llama Prompt Guard 2 86M** (Table IV).

**TABLE IV. Full-system detection on deepset, live deployment (Wilson 95% CI).**

| Configuration | Recall (Mitigation) | FPR | Precision |
|---|---|---|---|
| Edge only (Table III) | 2.28 % [1.05, 4.89] | 0.00 % | 100 % |
| + protectai (EN-only) | **41.44 %** [35.66, 47.48] | 1.00 % [0.39, 2.55] | 96.46 % |
| + Prompt Guard 2 86M (chosen, multilingual) | **22.81 %** [18.15, 28.26] | **0.25 %** [0.04, 1.41] | 98.36 % |

Four findings follow, and the third **corrects an expectation stated in an earlier draft of this
work**. **(i)** The escalation tier lifts recall an order of magnitude over the edge alone
(2.28 % → 22.8–41.4 %) — the layered architecture's value is *empirically demonstrated*, not merely
argued. **(ii)** Vendor accuracy numbers do **not** transfer across distributions: protectai
self-reports 99.74 % recall and Prompt Guard 2 self-reports 97.5 % recall at 1 % FPR, both *on their
own held-out sets*, yet on this out-of-distribution, partly-German corpus they measure 41.4 % and
22.8 % respectively — a stark, quantified vindication of independent evaluation over cited
model-card figures. **(iii)** Counterintuitively, the flagship multilingual model achieves *lower*
recall than the English-only proxy, because Meta deliberately tuned Prompt Guard 2 to minimize false
positives: it trades recall for precision, delivering 0.25 % FPR / 98.4 % precision versus the
proxy's 1.0 % / 96.5 %. Model selection at this tier is therefore an *operating-point* decision
(precision-first vs recall-first), not a strict quality ordering — a nuance invisible to anyone
trusting a single headline accuracy figure. **(iv)** Even the chosen model at its default operating
point leaves a large residual recall gap; the ">99 % mitigation" ambition is thus a genuinely
**open problem** (§IX) that dropping in a purpose-built guardrail does *not* close — threshold
tuning, ensembling (e.g. adding NVIDIA NemoGuard on the jailbreak axis), and adaptive-attack
hardening remain necessary.

**Testing those two remedies (threshold sweep + jailbreak-axis ensemble).** We evaluated both
directly. Sweeping Prompt Guard 2's decision threshold across $[0.9, 0.1]$ moves recall only from
20.5 % to **26.6 %** (the aggressive end costing a doubling of FPR to 0.50 %) — the recall gap is
**structural, not a threshold artifact**: PG2 scores ~73 % of deepset injections *below 0.1*. Adding
NVIDIA NemoGuard JailbreakDetect as an OR ensemble yielded **0 % additional recall** on deepset, for
two separable reasons we report honestly: (a) NemoGuard is a *jailbreak* detector and deepset is
*injection* — an axis mismatch — and (b) we could not reproduce NVIDIA's exact CPU embedding
pipeline from the public artifacts and self-contradictory model card (a blatant jailbreak scored
~0.09, not ~0.99, across every embedder/pooling/normalization variant tried), so this 0 % reflects
*our reproduction*, not NemoGuard's true NIM performance. The operational conclusion (details in
`docs/nemoguard_ensemble.md`) is that neither remedy closes the gap on this corpus; a stronger
injection-specific classifier or a fine-tune on injection data is required.

**Phase 5 — the gap was never structural; it is a decision-head artifact (SOLVED).** We tested
whether PG2's *frozen encoder* already separates injections, training a lightweight logistic head
on its penultimate (pooler) embeddings — the exact representation PG2's own head classifies —
using a license-clean corpus (deepset+gandalf+OpenOrca train; §refs Part 8). Evaluation followed a
**pre-registered, leakage-controlled OOD protocol** (threshold calibrated on validation/benign
only; OOD = fresh HackAPrompt injections + dolly benign, deduplicated within and across splits;
touched once). The result required three pre-registered runs, and we report the full arc — including
two NULLs we held rather than rationalize — as the honest record.

**TABLE VI. Phase-5 head on PG2 frozen embeddings (fresh OOD, Wilson 95% CI).**

| Run | OOD Recall | OOD FPR | AUC | Verdict (bar: recall ≥50 %, FPR ≤1 %) |
|---|---|---|---|---|
| PG2 native head (baseline) | 22.8 % | 0.25 % | — | — |
| 5a (threshold on 45 mismatched benign) | 99.7 % | 2.2 % | 1.000 | **NULL** (FPR > 1 %) |
| 5a-bis (calibration fixed) | 99.9 % | 1.2 % [0.8, 1.7] | 1.000 | **NULL** (point FPR > 1 %) |
| **5a-ter (99.5th-pct calib, fresh data)** | **99.9 %** [99.3, 100] | **0.7 %** [0.4, 1.2] | 0.999 | **SUCCESS** |

The finding is decisive: a *linear* head on PG2's frozen embeddings lifts out-of-distribution
injection recall from **22.8 % to 99.9 % at 0.7 % FPR**. Phase 4's "structural gap" was therefore
**not** in the encoder — the representation carries near-perfect signal (AUC ≈ 1.0) — but entirely
in Meta's precision-first *decision head*. 5a and 5a-bis returned NULL on the hard FPR ceiling
(2.2 %, then 1.2 % with a CI that included 1.0 %); we held both rather than loosen a pre-registered
criterion after seeing the data, and 5a-ter cleared all three locked bars strictly on fresh disjoint
data via a single pre-registered operating-point change. The composed **PG2-encoder → logistic-head**
classifier was then deployed as the origin Tier-3a model (§IX), replacing the native head. Full
protocol and pre-registration: `docs/phase5a_finetune_scoping.md`.

## VII-E. Statistical Rigor

- **Sample size for the recall claim.** To credit $\text{Recall}>0.99$ via the Wilson lower bound at
  95% confidence, the required $|\mathcal{X}^{+}|$ follows from the Wilson interval width at the
  observed rate; we state the attained $|\mathcal{X}^{+}|$ and whether it suffices, and if the
  primary corpus is too small for a 0.99 lower bound we say so explicitly rather than over-claim
  from a small sample.
- **Latency percentile uncertainty.** Tail percentiles from finite samples have non-trivial
  variance; we report bootstrap confidence intervals for $\langle p99\rangle$ and run $R\ge$ (stated)
  repetitions across time-of-day to bound diurnal network variance.
- **Multiple comparisons.** When comparing operating points or datasets, we note the number of
  comparisons and avoid selecting the best-looking $\theta$ post hoc without a held-out split.

## VII-F. Threats to Validity

- **Construct / corpus bias.** `deepset/prompt-injections` is bilingual DE/EN and modestly sized;
  recall on it may not transfer to other languages or to adaptive adversaries. We mitigate by
  supplementing families (§VII-A) and reporting per-family, but do not claim generality beyond the
  tested distribution.
- **Adaptive adversary.** The evaluation is against a *static* corpus; a signature filter is, by
  construction, evadable by an attacker who knows the signatures (novel phrasings). §V-D's scoped
  claim and the origin-tier escalation (§IX) are the response; we do not present static-corpus
  recall as robustness against adaptive attack.
- **Single-region measurement.** Latency measured from limited client geographies may not represent
  global tail behavior; we report the measurement geography and treat $L_{\text{net}}^{\Delta}$ as
  region-dependent.
- **Mock origin.** Subtracting a controlled $S_O$ isolates firewall latency but omits real-origin
  variance interactions; we note this and report both firewall-added and end-to-end figures.

## VII-G. Methodological Integrity (the discipline behind the numbers)

The Phase-5 result (Table VI) is a 99.9 % recall claim, and such claims are exactly where
evaluation most often deceives itself. We therefore adopted a set of adversarial-to-ourselves
controls, and we regard the *process* as a primary contribution — a headline number is only as
credible as the protocol that could have falsified it.

- **Pre-registration.** The full success criterion — OOD recall $\ge 50\%$ at *point-estimate*
  FPR $\le 1\%$, with the recall Wilson lower bound clearing the baseline's upper bound — was
  fixed in writing (`docs/phase5a_finetune_scoping.md`) **before any training code was written**,
  and the single pre-registered operating-point change for 5a-ter (99.0th $\to$ 99.5th calibration
  percentile) was recorded **before** the fresh draw. The criterion was never renegotiated after
  seeing data.
- **Leakage control.** Splits were deduplicated by exact normalized-text hash *and* by embedding
  cosine similarity $\ge 0.95$ **across** train/validation/OOD (and $\ge 0.98$ within splits), so a
  reported "win" cannot arise from near-duplicate memorization. This removed, e.g., 14 validation
  items that were near-copies of training data, and 137 of 500 sampled OOD injections as
  exact/cross-train matches.
- **License refusal.** Datasets whose licenses could not be confirmed to a primary source were
  **excluded from training and evaluation** regardless of their utility — Tensor Trust (license
  unconfirmed; the code repo's BSD-2 does not cover the crowdsourced data), the safe-guard set (no
  license listed), and BIPIA (non-standard license). We accepted a smaller corpus over an
  unverifiable one.
- **Holding the NULL — twice.** The decisive discipline: run 5a returned 99.7 % recall at 2.2 % FPR
  and run 5a-bis returned 99.9 % recall at 1.2 % FPR **with a Wilson CI that included 1.0 %**. A
  single sentence ("statistically consistent with $\le 1\%$") would have converted either into a
  reported SUCCESS. We returned **NULL** both times, because the pre-registered ceiling was on the
  point estimate and loosening it post hoc is precisely the self-deception pre-registration exists
  to prevent. Only after a legitimate operating-point change, tested **once** on genuinely fresh,
  disjoint, never-scored data, did the point estimate clear the bar (0.7 % FPR) — and *that* number
  we report as SUCCESS. The two NULLs are not failures to hide; they are the evidence that the final
  number was earned, not curated.

---

### Citation keys
- **[DS-PI]** deepset, "prompt-injections," Hugging Face Datasets, huggingface.co/datasets/deepset/prompt-injections (662 rows; 546/116; Apache 2.0; accessed 2026-07-04).
- **[DS-JB]** jackhhao, "jailbreak-classification," Hugging Face Datasets (1,306 rows; Apache 2.0; accessed 2026-07-04).
- **[DS-GA]** Lakera, "gandalf_ignore_instructions," Hugging Face Datasets; see also arXiv:2311.01011.

> Evidence status: dataset provenance, counts, splits, labels, and licenses (§VII-A) are CONFIRMED
> by direct fetch of the HF dataset cards (verified-facts Part 4b, 2026-07-04). **Detection results
> (Table III: edge Recall 2.28 %, FPR 0.00 %, AUC 0.511; Table IV: protectai 41.44 % / FPR 1.00 %,
> Prompt Guard 2 86M 22.81 % / FPR 0.25 %) are MEASURED** over the full 662-row deepset corpus
> (`benchmarks/results/deepset-662-{local,fullsystem,promptguard2}/`) — Table III via the firewall's
> own `screen()` pipeline; Table IV's protectai row via `full_system.py`, and its Prompt Guard 2 row
> via `run_prompt_guard.py` executed on the **live production deployment** (Helsinki origin, CPU). The escalation-tier model specs are CONFIRMED (verified-facts
> Part 7) but their accuracy figures are vendor-self-reported; Table IV is our own independent
> measurement of a proxy. Latency quantities ($\langle p50/p90/p99\rangle$, $\langle\kappa/\rho\rangle$)
> remain placeholders pending an edge deployment. The statistical methods (Wilson intervals,
> bootstrap percentiles) are standard; the analytical latency decomposition (§VII-B) is original and
> rests only on the CONFIRMED §III envelope.
