# Benchmark Suite (paper Section VII)

Latency + detection harnesses that emit the exact tables the paper's Section VII
placeholders expect.

```
benchmarks/
├── corpus/
│   ├── fetch_corpus.mjs      # pull deepset/prompt-injections (662 rows, Apache 2.0)
│   └── sample_payloads.json  # tiny offline sample for CI
├── lib/stats.mjs             # Wilson intervals, percentiles, trapezoidal AUC
├── roc.mjs                   # offline ROC/AUC over the REAL screen() code
├── detection.mjs             # confusion matrix + Wilson CIs (+per-family)
├── latency.k6.js             # k6: warm/cold p50/p90/p99, <50ms p99 SLO gate
├── report.mjs                # aggregate results/ -> Section VII placeholder table
└── results/                  # generated; deepset-662-local/ holds the real run
```

## Run

```bash
npm install
npm run corpus          # fetch the real 662-row deepset corpus
npm run detection       # local-screening mode; set WORKER_URL for end-to-end
npm run roc             # offline ROC/AUC over the screening code
# latency needs a deployed worker + the bench tenant key in KV:
WORKER_URL=https://<your-worker> BENCH_TENANT_KEY=<base64> npm run latency
npm run report          # print the Section VII placeholder table
```

## Headline result (real deepset run, local screening) — READ THIS

The shipped 24-signature edge layer, measured over the full 662-row deepset
corpus:

| Metric | Value (Wilson 95% CI) |
|--------|-----------------------|
| Mitigation (Recall) | **2.28%** [1.05%, 4.89%] |
| FPR | **0.00%** [0.00%, 0.95%] |
| Precision | 100.00% |
| AUC | **0.5114** |

**Interpretation (this is the honest, paper-consistent reading):** the
deterministic edge layer is a **high-precision (0% FPR), low-recall FIRST
FILTER** — exactly as Section V-D states in advance. It cheaply and safely removes
the signature-expressible attack subclass **without ever blocking legitimate
traffic**, and delegates the large recall gap on diverse/novel/multilingual
injections to the origin model tier (Section IX). The original ">99% mitigation"
figure is a **full-system** target that requires the escalation tier; it is **not**
an edge-signature-layer claim, and the data proves the layer alone does not reach
it. Reporting this rather than gaming the signature set is the integrity contract
of Section VII.

> The earlier 100% / AUC=1.0 on `sample_payloads.json` was circular (that sample
> was authored from our own signatures) — kept only as an offline harness smoke
> test, never as an evaluation result.

## Modes

- `detection.mjs` runs **end-to-end** (HMAC-signs and POSTs to `WORKER_URL`) or, with
  no `WORKER_URL`, **local-screening** (imports the firewall's `screen()`). Detection
  rates are identical in both (the screening logic is the same); only latency needs
  a live deployment, which is why `latency.k6.js` is separate.
- `latency.k6.js` encodes the `<50 ms` p99 SLO as a k6 threshold, so a breach fails
  the run, and separates cold-start isolates from warm steady state (Section VII-C).
