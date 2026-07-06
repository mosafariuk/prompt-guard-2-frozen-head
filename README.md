# Multi-Layered Defensive Architecture & Webhook Securitization for LLM Deployment in Multi-Tenant Enterprise Systems

Companion repository: an IEEE-standard paper **and** the production-ready codebase
it describes. Every factual claim in the paper traces to a primary source in
`paper/refs/verified-facts.md`; every result number is either measured by the
`benchmarks/` suite or explicitly marked as pending.

## Layout

```
paper/                     # IEEE paper, Sections I-X + Appendices A-C + refs
├── manuscript.md          # ASSEMBLED single-file manuscript (front matter → refs)
├── 00_front_matter.md, 01_introduction.md … 09_appendices.md, 10_references.md
├── ieee/main.tex          # IEEEtran wrapper (+ README: pandoc build path)
└── refs/verified-facts.md # the evidence ledger (3 deep-research passes)
edge-firewall/             # Cloudflare Worker: HMAC + Aho-Corasick + logging (§III-VI)
db/                        # partitioned JSONB threat log + tuning + queue consumer (§VI)
terraform/                 # KV/Queue/Hyperdrive/RDS + param group (IaC, pinned)
benchmarks/                # k6 latency + detection/ROC + full-system + Prompt Guard 2 harness
escalation-tier/           # on-prem ML deep-scan FastAPI service (Prompt Guard 2) (§IX)
scripts/                   # deploy_origin.sh -> containerized deploy to the Debian origin
```

**v3 (escalation tier, on-prem):** `escalation-tier/` FastAPI service + CPU Debian
`Dockerfile`, `scripts/deploy_origin.sh` (loopback-bound, hardened container),
`benchmarks/latency_escalation.k6.js`, and `benchmarks/run_prompt_guard.py` (the
independent multilingual benchmark — **ready but pending HF gated-access approval for
Prompt Guard 2**; runs the moment the account is authorized). Service validated live:
health, malicious/benign classification, 401/422 handling all confirmed on CPU.

## The three findings that shaped the work

1. **The "50 ms Worker CPU limit" premise is obsolete** (§I-C). It is a legacy
   2024 Bundled-model artifact; the real envelope is 10 ms (free) / 30 s–5 min
   (paid), and CPU excludes I/O wait. Corrected and turned into a contribution.
2. **A proven tenant-binding property** (§IV): binding the tenant id into an
   HMAC-SHA256 message makes cross-tenant attribution as hard as forging HMAC,
   with a multi-user bound independent of tenant count and key rotation.
3. **The edge signature layer is a precision filter, not a >99% mitigator**
   (§VII, Table III). Measured on the real 662-row deepset corpus: **Recall
   2.28 %, FPR 0.00 %, AUC 0.511**. This confirms the §V-D scoping and refutes
   the original ">99%" ambition for the edge layer in isolation.
4. **The escalation tier lifts recall ~18× — and vendor accuracy doesn't transfer**
   (§VII, Table IV). Full-system (edge + ONNX proxy classifier) measured **Recall
   41.4 %, FPR 1.0 %** — an 18× lift proving the layered design, while the proxy's
   *independently-measured* 41.4 % vs its *self-reported* 99.7 % shows model-card
   numbers do not survive out-of-distribution data.

## Verification status (what was actually run vs. authored-to-spec)

| Component | Status |
|---|---|
| `edge-firewall/` | ✅ **13/13 unit tests pass**; ✅ `tsc` clean vs `@cloudflare/workers-types` |
| `benchmarks/` detection + ROC | ✅ **run on the real 662-row deepset corpus** (results committed) |
| `benchmarks/full_system.py` + `escalation-tier/` | ✅ **run on real corpus via ONNX proxy** — 18× recall lift measured (Table IV); production torch service authored |
| `db/consumer/` | ✅ `tsc` clean (caught+fixed a real generic bug) |
| `db/migrations/*.sql` | ⚠️ authored to primary-sourced spec; **not executed** (Docker down + macOS `shmall` blocked a local cluster). One-liner validation in `db/README.md` |
| `terraform/` | ⚠️ authored to v4 schema; **not `terraform validate`d** (CLI absent). Fixed one HCL typo + one block-syntax risk by inspection |

## Reproduce the measured results

```bash
cd benchmarks && npm install
npm run corpus      # fetch deepset/prompt-injections (662 rows, Apache 2.0)
npm run detection   # confusion matrix + Wilson CIs (local screening)
npm run roc         # ROC/AUC over the real screen() code
npm run report      # Section VII placeholder table
```

## Outstanding (not yet done)

- **PDF build:** run the `pandoc` + `pdflatex` path in `paper/ieee/README.md`
  (no LaTeX toolchain in the authoring env).
- Latency benchmark requires a live edge deployment (`benchmarks/latency.k6.js`).
- Origin-side model escalation tier (§IX) — the path to a full-system recall figure.
- `terraform validate` + a container run of the SQL migrations (both blocked only
  by the authoring environment, not by the artifacts).

## Done

- Paper §I–X + **Appendices A (STRIDE), B (full HMAC game-hopping proof), C (corpus)**.
- **`paper/manuscript.md`** — assembled single-file manuscript; IEEEtran wrapper in `paper/ieee/`.
