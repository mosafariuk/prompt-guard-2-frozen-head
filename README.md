# Prompt Guard 2, Frozen: Closing the Injection-Recall Gap

**Multi-Layered Defensive Architecture & Webhook Securitization for LLM Deployment in
Multi-Tenant Enterprise Systems** — the IEEE-standard paper **and** the production
codebase it describes, operating as the **AIO Apex** enterprise firewall.

> ### Headline result: **22.8% → 99.9% out-of-distribution injection recall, at 0.7% FPR**
>
> Meta's Prompt Guard 2 catches only **22.8%** of out-of-distribution prompt injections
> through its native head. We show that gap is a **decision-head artifact, not an encoder
> blind spot**: a *linear* logistic head on the model's **frozen** embeddings reaches
> **99.9% recall at 0.7% FPR (AUC ≈ 0.999)** — the injection signal was in the
> representation all along. The composed classifier is deployed as the origin deep-scan tier.

## The result, and how it was earned

The number is trustworthy *because of the process that produced it* — a pre-registered,
leakage-controlled protocol on fresh, disjoint data, in which we **held a NULL verdict
twice** rather than rationalize a pass.

| Run | OOD Recall | OOD FPR | AUC | Verdict (bar: recall ≥ 50%, point-estimate FPR ≤ 1%) |
|---|---|---|---|---|
| PG2 native head (baseline) | 22.8% | 0.25% | — | — |
| Phase 5a (threshold miscalibrated) | 99.7% | 2.2% | 1.000 | **NULL** — FPR > 1% |
| Phase 5a-bis (calibration fixed) | 99.9% | 1.2% [0.8, 1.7] | 1.000 | **NULL** — point FPR > 1% |
| **Phase 5a-ter (99.5th-pct calib, fresh data)** | **99.9%** [99.3, 100] | **0.7%** [0.4, 1.2] | 0.999 | **✅ SUCCESS** |

At 5a-bis — 99.9% recall with a CI that *included* 1.0% — one sentence would have made it a
"SUCCESS." We returned NULL, changed exactly one pre-registered operating-point knob
(99.0 → 99.5th calibration percentile), drew genuinely fresh data, and touched it once. It
cleared with margin. Full pre-registration: [`docs/phase5a_finetune_scoping.md`](docs/phase5a_finetune_scoping.md).

**Methodological integrity** (paper §VII-G): success criteria fixed *before any training
code*; exact-hash **and** cosine-≥ 0.95 cross-split deduplication; refusal of
unverifiable-license datasets (Tensor Trust, safe-guard, BIPIA excluded); deterministic
seeds (`20260705/06/07`) reproducing the exact splits.

## The dual-tier architecture

A rapid edge screen fails open to a heavier origin classifier, so availability never
depends on the model tier:

```
webhook ─▶  Cloudflare edge (V8 isolate)                    ─▶  self-hosted origin
            • HMAC-SHA256 tenant binding (EUF-CMA, §IV)          • PG2 frozen encoder
            • Aho–Corasick screen, O(n+z), sub-ms (§V)           •   → logistic head
            • async PostgreSQL JSONB threat log (§VI)            •   → calibrated threshold
            └─ high-precision first filter ───────┐             └─ 99.9% recall @ 0.7% FPR
                                    fail-open ─────┴──────────────▶  (deep-scan, §IX)
```

Validated live end-to-end (Cloudflare edge → self-hosted origin): subtle paraphrased
injections that evade the edge signatures are caught by the composed head
(`403 block by:deepscan`, score ≈ 0.99), benign traffic passes (`200 allow`).

## Repo layout

```
paper/                 # IEEE paper §I–X + Appendices A–C + refs
├── manuscript.md      # assembled single-file manuscript
├── ieee/main.pdf      # compiled two-column IEEEtran PDF (build.sh + fixup.py)
└── refs/verified-facts.md   # evidence ledger (every claim → primary source)
benchmarks/            # Phase-5 pipeline + detection/ROC + latency harnesses
├── build_corpus.py            # fetch + leakage-controlled dedup
├── extract_pg2_embeddings.py  # frozen PG2 pooler embeddings
├── train_head.py, phase5a_bis.py, phase5a_ter.py   # head training + single-touch OOD eval
├── finalize_head.py           # production head → head.npz (numpy weights + threshold)
└── results/phase5a/           # committed run outputs (the table above)
edge-firewall/         # Cloudflare Worker: HMAC + Aho–Corasick + logging (§III–VI)
escalation-tier/       # FastAPI deep-scan service: PG2 encoder → logreg head (§IX)
db/                    # partitioned JSONB threat log + tuning + queue consumer (§VI)
terraform/             # KV/Queue/Hyperdrive/RDS IaC
scripts/               # tenant provisioning + origin deploy + E2E test
docs/                  # Phase-5 pre-registration + ensemble post-mortems
```

## The four findings that shaped the work

1. **The "50 ms Worker CPU limit" premise is obsolete** (§I-C) — a legacy 2024
   Bundled-model artifact; the real envelope is 10 ms (free) / 30 s–5 min (paid), CPU
   excluding I/O wait. Corrected and turned into a contribution.
2. **A proven tenant-binding property** (§IV) — binding the tenant id inside an
   HMAC-SHA256 message makes cross-tenant attribution as hard as forging HMAC, with a
   multi-user bound independent of tenant count and key rotation (full game-hopping proof,
   Appendix B).
3. **The edge signature layer is a precision filter, not a > 99% mitigator** (§VII,
   Table III) — measured on the 662-row deepset corpus: **Recall 2.28%, FPR 0.00%**. The
   ">99% mitigation" figure is a full-system target, not an edge-layer property.
4. **The recall gap was never structural** (§VII, Table VI) — the headline result above.
   The edge delegates its recall gap to the origin tier, which closes it.

## Reproduce

```bash
# Phase-5 classifier (needs HF access to meta-llama/Llama-Prompt-Guard-2-86M)
cd benchmarks
python build_corpus.py            # fetch + dedup license-clean corpora
python extract_pg2_embeddings.py  # frozen PG2 embeddings
python phase5a_ter.py             # pre-registered, single-touch OOD eval → the table above
python finalize_head.py           # production head → corpus5a/head.npz

# Edge firewall unit tests + type check
cd ../edge-firewall && npm install && npm test && npx tsc --noEmit

# Compile the paper (needs: brew install pandoc tectonic)
bash paper/ieee/build.sh          # → paper/ieee/main.pdf (two-column IEEEtran)
```

## Status

| Component | Status |
|---|---|
| **Phase-5 classifier** | ✅ **SUCCESS** (99.9% @ 0.7% FPR, fresh disjoint OOD); deployed as origin Tier-3a; live E2E verified |
| `edge-firewall/` | ✅ unit tests pass; `tsc` clean; deployed on Cloudflare + custom domain |
| `escalation-tier/` | ✅ composed PG2-encoder → logreg head serving on a hardened CPU container |
| `benchmarks/` detection + ROC | ✅ run on the real 662-row deepset corpus (results committed) |
| `paper/ieee/main.pdf` | ✅ compiled two-column IEEEtran (23 pp) via `build.sh` |
| `db/migrations/*.sql` | ⚠️ authored to primary-sourced spec; **not executed** in the authoring env |
| `terraform/` | ⚠️ authored to v4 schema; **not `terraform validate`d** (CLI absent) |

## Paper & citation

The full manuscript is in [`paper/manuscript.md`](paper/manuscript.md); the compiled
two-column PDF is [`paper/ieee/main.pdf`](paper/ieee/main.pdf). Every factual claim traces
to a primary source in [`paper/refs/verified-facts.md`](paper/refs/verified-facts.md); every
result number is either measured by `benchmarks/` or explicitly marked pending.

Repository: <https://github.com/mosafariuk/prompt-guard-2-frozen-head>
