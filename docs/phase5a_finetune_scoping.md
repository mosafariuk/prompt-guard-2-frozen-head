# Phase 5a — Head-Only Injection Classifier: Scoping & Pre-Registration

**Status:** scoping COMPLETE, decisions LOCKED (confirmed with stakeholder before any
training code). Success criteria and split are **pre-registered** — fixed BEFORE any
training script is written, so the experiment cannot be rationalized into a flattering
result after the fact.

**Locked decisions:** SUCCESS = OOD recall ≥ 50% @ FPR ≤ 1% (Wilson lower bound clears
baseline). Primary OOD ship-gate = **HackAPrompt** (direct injection, MIT); BIPIA
(indirect) is secondary/reported-only. Train on the **license-confirmed core**
(deepset + gandalf, + a clean benign slice); safe-guard/BIPIA added only if their licenses
verify; Tensor Trust excluded (license unconfirmed).

## 1. Hypothesis and experiment

**Hypothesis:** the frozen embedding space of an existing encoder already contains the
signal needed to separate deepset-style injections from benign text — PG2's 22.8%
recall is a *classifier-head* limitation (it was tuned precision-first), not an
*embedding* limitation.

**Experiment (CPU-only, no GPU):**
1. Freeze an encoder; embed every train/val/test example **once**; cache embeddings.
2. Train a lightweight head (logistic regression / small MLP / gradient-boosted trees)
   on cached train embeddings. Seconds of CPU.
3. Select the operating threshold on **validation** only.
4. Report the frozen threshold's performance on the **OOD test set** (never seen in
   training or threshold selection). That OOD number is THE result.

**Encoders to compare** (which embedding space has the signal):
- Prompt Guard 2 86M penultimate embeddings (the model we're trying to beat).
- `snowflake-arctic-embed-m` (general-purpose, already on the box).
- One strong general text embedder if a self-hostable one is verified.

## 2. Datasets (VERIFIED — refs/verified-facts.md Part 8)

Selection rule enforced: **train only on license-confirmed permissive datasets.** Two
candidates are held out of training on license grounds (honesty over corpus size):
Tensor Trust (license unconfirmed → excluded) and safe-guard/BIPIA (licenses to verify
before inclusion).

| Role | Dataset(s) | License | Injection type / why |
|------|-----------|---------|----------------------|
| **Train — injection** | deepset(train, label=1) + Lakera gandalf(train, 777) [+ safe-guard label=1 *iff license verified*] | Apache-2.0 / MIT | direct injection, mixed sources (curated + game + synthetic) |
| **Train — benign** | deepset(train, label=0) + a license-clean general-instruction benign slice (source pinned at build, documented) | Apache-2.0 / permissive | benign controls for FPR |
| **Validation (in-distribution)** | deepset(test split, 116) | Apache-2.0 | threshold + head hyperparameters ONLY |
| **OOD Test — PRIMARY (ship gate)** | **HackAPrompt** (dedup sample) + held-out benign from a DIFFERENT source than train benign | MIT | direct injection, crowdsourced — matches our webhook use case, unseen source |
| **OOD Test — SECONDARY (reported, not gating)** | **BIPIA** (indirect) *iff license verified* | verify | hardest generalization (indirect ≠ our direct target); reported for completeness |

**Benign for OOD FPR:** HackAPrompt is attacks-only, so OOD benign is drawn from a
license-clean source **distinct from the training benign** (so FPR is also OOD). Source
pinned + documented at corpus-build time.

**License resolution (checked 2026-07-05):** safe-guard HF card lists **NO license** →
**EXCLUDED from training**. BIPIA GitHub reports **`NOASSERTION`/"Other"** (custom Microsoft
license, not a recognized open license) → secondary-OOD **ON HOLD** pending a manual read of
its LICENSE file. Tensor Trust excluded (license unconfirmed). **Net: the Phase-5a corpus is
the license-confirmed core only — train deepset+gandalf(+clean benign), validation
deepset(test), OOD ship-gate HackAPrompt.** No unverified-license data enters the experiment.

## 3. The honesty split (leakage-proof, OOD-real)

- **Train / Validation:** a combination of injection datasets that share a generation
  methodology, split by example (with **exact + near-duplicate dedup** via embedding
  cosine ≥ 0.98 removal) into train/val. Validation is for head hyperparameters and
  threshold selection ONLY.
- **OOD Test:** a **whole dataset held out**, chosen to be *structurally distinct* from
  the training sources (different origin/methodology — e.g., game-sourced vs
  crowdsourced vs synthetic, or direct vs indirect injection). A model that only
  memorizes the training distribution will fail here. This is the number we report and
  the only one that speaks to production generalization.
- **No cross-split leakage:** dedup ALSO runs across train↔test (drop any test item with
  cosine ≥ 0.95 to any train item), so a "win" cannot come from near-copies.
- **Benign controls** are drawn per split from the same-provenance benign pools; FPR is
  measured on benign held out identically.

## 4. Pre-registered success criteria (FIXED before training)

Baseline to beat: **PG2 edge-composed recall 22.8% @ 0.25% FPR** (deepset, §VII Table IV).

| Outcome | Definition (on the OOD test set, Wilson 95% CI) |
|---------|--------------------------------------------------|
| **SUCCESS** | OOD Recall **≥ 50%** with **FPR ≤ 1%**, *and* the recall Wilson **lower bound** exceeds the PG2 baseline's upper bound (i.e. a statistically real >2× lift). |
| **PARTIAL** | OOD Recall in [30%, 50%) at FPR ≤ 1% — the embedding has *some* extra signal but frozen features are not enough; motivates a full fine-tune (Phase 5b, GPU). |
| **NULL** | OOD Recall not statistically above the 22.8% baseline — frozen embeddings lack the signal; a head cannot fix it. Report as such; do NOT tune on the test set to manufacture a pass. |

Secondary constraints (all pre-registered):
- **FPR ceiling is hard:** any operating point with OOD FPR > 1% is disqualified,
  regardless of recall (the edge's precision-first posture must be preserved).
- **No test-set peeking:** the OOD test set is touched exactly once, at the end, at the
  validation-selected threshold. If we run it more than once we disclose every run.
- **Report the in-distribution number too**, side by side, to quantify the
  train→OOD generalization gap (the "vendor trap" made explicit for our own model).

## 5. Deployment gate (Phase 5a → production)

Ship the tuned head as a swappable Tier-3a model (the service is already model-agnostic
via `MODEL_ID`/wrapper) **only** on a SUCCESS outcome AND after re-measuring FPR on the
live deployment. A PARTIAL or NULL result is reported honestly and does not ship — same
discipline as the Phase-4 NemoGuard gate.

## 5b. Phase 5a-ter — PRE-REGISTERED before the run (2026-07-05)

5a returned NULL (OOD FPR 2.2% > 1%). 5a-bis (calibration fix) returned NULL (FPR 1.2%
[0.8,1.7] > 1% point estimate) with 99.9% recall / AUC 1.000. Both held strictly.

**5a-ter — the ONLY change (fixed before the fresh draw):** calibrate the threshold at
the **99.5th percentile** of the calibration benign (target ~0.5% FPR on calib), giving
headroom so the OOD-benign FPR clears the 1% ceiling with margin. **Everything else is
unchanged**, including the success bar: OOD recall ≥ 50% @ **point-estimate FPR ≤ 1%**,
Wilson lower > 28.3%. We are NOT loosening the FPR criterion (that stays point-estimate);
we are choosing a stricter *operating point*, which is a legitimate model decision.

**Fresh data (leakage-proof):** exclude every text used/scored in 5a AND 5a-bis (the
latter reproduced deterministically from its seed), then draw fresh disjoint HackAPrompt
injections + dolly benign (calib + test) with a new seed (20260707). OOD touched once.
If this returns NULL, it is reported as NULL — this is the final attempt on this approach.

## 6. Compute

All of Phase 5a runs on the CPU Debian origin (frozen-embedding + light head). A GPU is
provisioned ONLY if we escalate to Phase 5b (full encoder fine-tune), and only after 5a
shows PARTIAL promise. No GPU spend on a hypothesis a CPU experiment can falsify.
