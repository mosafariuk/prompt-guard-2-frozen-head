# Verified Facts Ledger — Source of Truth for the Paper

> Generated from a deep-research verification pass (16 primary/secondary sources, 74 extracted
> claims, top-25 adversarially verified 3-vote). Every numeric claim in the paper MUST trace
> to a row here. Date-stamp all Cloudflare figures: the platform is changing quarterly.
> Verification date: 2026-07-04.

## Part 1 — Cloudflare Workers / V8 Isolate (CONFIRMED, high confidence)

| Fact | Value | Source |
|---|---|---|
| **Free plan CPU time** | **10 ms** per invocation | developers.cloudflare.com/workers/platform/limits |
| **Paid (Standard) CPU time — default** | **30 seconds** | changelog 2025-03-25 higher-cpu-limits |
| **Paid CPU time — max (configurable)** | **5 min = 300,000 ms** via `[limits] cpu_ms` in wrangler | changelog 2025-03-25; pricing |
| **The "50 ms" figure** | ❌ LEGACY. Auto-applied to deprecated "Bundled" model during the **2024-03-01** migration to Standard pricing. NOT the current standard. | pricing docs |
| **CPU vs wall-clock** | CPU time counts active compute only; time waiting on `fetch`/KV/DB I/O is EXCLUDED. Wall-clock has no charge/limit for **HTTP-triggered** Workers. | limits; pricing |
| **Wall-clock caveat** | Non-HTTP triggers (Cron, Queue Consumers, DO Alarms) DO carry a 15-min duration cap. | limits |
| **Per-isolate memory** | **128 MB** (JS heap + Wasm), per-isolate not per-invocation; one isolate serves many concurrent requests. | limits |
| **Subrequests — paid** | **10,000/invocation default** (up to 10M), raised **2026-02-11** from the old universal 1,000 cap. | changelog 2026-02-11 |
| **Subrequests — free** | **50 external + 1,000** to Cloudflare services per invocation (unchanged). | limits |
| **Durable Objects CPU** | 30 s default per request (resets per HTTP req/WS message), configurable to 5 min. | durable-objects/platform/limits |
| **Workflows CPU** | 10 ms free / 30 s default → 5 min paid, per step. | workflows/reference/limits |

**Framing correction for the paper:** The original brief conflates two distinct budgets.
- **CPU-time budget** — the firewall's heuristics must stay well under the plan's CPU ceiling. Design target: **sub-1 ms CPU** per request for the deterministic layers. This is trivially inside even the 10 ms free-plan ceiling — so the paper's real contribution is *headroom*, not *survival*.
- **Wall-clock latency SLO** — the "<50 ms added latency at p99" claim is a *wall-clock* end-to-end target (network + compute), NOT a CPU limit. Keep these separate or a reviewer will reject the conflation. Reframe the thesis around: "sub-1 ms CPU cost, <X ms added wall-clock latency at p99."

## Part 2 — Edge NLP Heuristics (PARTIAL: only Aho-Corasick primary-verified)

| Fact | Value | Source | Status |
|---|---|---|---|
| **Aho-Corasick build** | O(m), m = total pattern length | Springer 978-3-031-96093-2_15 | ✓ 3-0 |
| **Aho-Corasick search** | O(n + z), n = text len, z = matches; single pass ∀ patterns | same | ✓ 3-0 |
| **vs KMP** | KMP is single-pattern (~O(n+k·m) for k patterns); AC beats it for multi-signature | same | ✓ 3-0 |
| Lexical filter ROC-AUC | AC ~0.66, regex denylist ~0.65, entropy ~0.54 (search snippet, arXiv 2601.07185) | arXiv 2601.07185 | ⚠ from search snippet, not vote-verified |
| Deterministic detectors runtime | <0.1 ms/prompt claim | arXiv 2601.07185 | ⚠ not vote-verified |
| SFT defenses (StruQ/SecAlign) learn brittle surface heuristics; up to 40% OOD drop | — | arXiv 2601.07185 | ✓ 2-0 (single source, MEDIUM) |
| Embedding RF/XGBoost > encoder-only: RF on text-embedding-3-small AUC 0.764, P 0.867, R 0.870 | vs deberta ~0.50 | arXiv 2410.22284 | ✓ 3-0 but single preprint (MEDIUM) |
| **NOT verified**: regex/trie-DFA/n-gram/Shannon-entropy Big-O and accuracy | — | — | ✗ needs sourcing |

## Part 3 — HMAC-SHA256 (fetched, NOT in top-25 vote; treat as primary-sourced-but-reverify)

Sources were fetched and quotes extracted, but these did not make the top-25 verified set.
Cite directly from primaries; re-verify quotes before submission.

| Fact | Source (fetched) |
|---|---|
| HMAC(K,m) = H((K⊕opad) ‖ H((K⊕ipad) ‖ m)); ipad=0x36, opad=0x5C ×B | RFC 2104 (datatracker.ietf.org/doc/html/rfc2104) |
| FIPS 198-1 is the NIST standard for HMAC | nvlpubs.nist.gov/nistpubs/fips/nist.fips.198-1.pdf |
| Formal MAC/EUF-CMA & PRF security treatment | Bellare CSE107 slides (cseweb.ucsd.edu/~mihir/cse107/slides/s-mac.pdf) |
| Stripe: HMAC-SHA256, signing secret as key, `t.v1` scheme, timestamp `t` + tolerance window (replay defense) | docs.stripe.com/webhooks/signature |

**Gap flagged by synthesis:** No vote-verified claim exists for EUF-CMA proof, tenant-ID
binding, key rotation, or replay/nonce specifics. I will write these from the primary sources
above (RFC 2104, FIPS 198-1, Bellare) and mark them for a targeted re-verification pass.

## Part 4 — PostgreSQL JSONB (CONFIRMED — 2nd pass, 25/25 claims 3-0 vs official docs)

All from postgresql.org/docs, verbatim quotes, unanimous adversarial votes. High confidence.

| Fact | Value / detail | Source |
|---|---|---|
| **TOAST trigger** | Row value wider than `TOAST_TUPLE_THRESHOLD` (**normally 2 kB**) | storage-toast.html |
| **TOAST target** | Compress/move out-of-line until row < `TOAST_TUPLE_TARGET` (also ~2 kB, per-table adjustable via `ALTER TABLE … SET (toast_tuple_target=…)`) | storage-toast.html |
| ⚠ precision | "2 kB" is nominal; internal constant is **2032 bytes**, not 2048. Say "~2 kB", never exact 2048. | storage-toast.html |
| **4 TOAST strategies** | PLAIN (none), EXTENDED (compress+out-of-line, default), EXTERNAL (out-of-line only, faster substring on text/bytea), MAIN (compress only, out-of-line last resort) | storage-toast.html |
| **JSONB vs JSON** | json = exact text copy, reparsed each op, preserves whitespace/key-order/dup-keys; **jsonb = decomposed binary, slightly slower input (conversion), significantly faster to process (no reparse), no whitespace/order, last dup-key wins, supports indexing** | datatype-json.html |
| **synchronous_commit** | default `on`; `off` = no commit wait, risks losing recent commits (max delay 3× `wal_writer_delay`) but **NO db inconsistency** | runtime-config-wal.html |
| **full_page_writes** | default `on`; logs full page content to WAL on first modify after checkpoint = torn-page protection | runtime-config-wal.html |
| **commit_delay / commit_siblings** | group commit: delay WAL flush so more txns flush together; default delay 0, siblings 5 | runtime-config-wal.html |
| **checkpoint** | begins every `checkpoint_timeout` (default **5 min**) or when `max_wal_size` (default **1 GB**) about to be exceeded | wal-configuration.html |
| **checkpoint_completion_target** | spreads checkpoint I/O; default **0.9**, recommended max 0.9 | wal-configuration.html |
| **GIN insert cost** | one heap row → many index inserts (one per extracted key) → slow high-velocity inserts | gin.html |
| **GIN fastupdate** | new tuples buffered in unsorted pending list; flushed on vacuum/autoanalyze, `gin_clean_pending_list()`, or when list > `gin_pending_list_limit`; per-index storage param | gin.html, sql-createindex.html |
| **Declarative partitioning** | native, **PG 10+** (not inheritance/UNION ALL); auto row routing; RANGE bounds inclusive-lower/exclusive-upper; ideal `PARTITION BY RANGE (logdate)` | ddl-partitioning.html (10/11/16/current) |
| **Retention** | `ATTACH`/`DETACH PARTITION`, `DROP TABLE` on a partition = far faster than bulk DELETE, avoids VACUUM overhead | ddl-partitioning.html (11/16) |
| **Unique/PK constraint** | must include ALL partition-key columns; partition key can't be expression/function | ddl-partitioning.html (current/11) |

**NOT surviving synthesis (in scope, treat as unverified until sourced):** `jsonb_path_ops` vs
`jsonb_ops` operator-class tradeoff, `wal_compression`, `wal_buffers`, `shared_buffers` sizing
direction, `wal_level` values, unlogged-tables behavior. I'll source these directly from the
config docs when writing §VI rather than assert them.

## Part 4b — Benchmark corpus (RESOLVED via direct WebFetch, 2026-07-04)

| Dataset | Total rows | Split | Label schema | Columns | Lang | License |
|---|---|---|---|---|---|---|
| **deepset/prompt-injections** | **662** | 546 train / 116 test | binary **0=legit, 1=injection** | `text`, `label` | DE+EN | Apache 2.0 |
| **jackhhao/jailbreak-classification** | 1,306 | 1,044 / 262 | `jailbreak` / `benign` | `prompt`, `type` | EN | Apache 2.0 (no paper) |

Other candidates (from 2nd-pass source list, not directly fetched): JailbreakBench/JBB-Behaviors
(HF, has arXiv paper — citable), Lakera/gandalf_ignore_instructions (arXiv:2311.01011).

**KEY CORRECTION:** No single open dataset equals the brief's "~200 payloads." deepset is **662**
total. The refuted 1st-pass claim ("deepset = 546 = the 200 set") is superseded by these verified
counts.

**DECISION for §VII (composed benchmark):** Use **deepset/prompt-injections** as the primary
labeled corpus (real provenance, Apache 2.0, binary labels). The **malicious set** = the
`label==1` rows; the **benign controls** (for FPR) = the `label==0` rows. If a fixed ~200-payload
evaluation subset is wanted, define it as a *documented, seed-fixed sample* and report the EXACT
counts FROM THE DATA at run time. Supplement diversity with jailbreak-classification + gandalf.

**HARD RULE:** §VII presents METHODOLOGY + analytical framework only. All measured numbers — p50/
p90/p99 latency, the empirical constant ρ, FPR/FNR, the mitigation % — MUST come from actually
running the Phase-2 k6/autocannon + detection harness. Do NOT fabricate result values in the paper;
use clearly-marked placeholders (e.g., ⟨p99⟩) that the benchmark run fills. Consistent with the
ρ-deferral promised in §III and §V-F.

## Part 5 — Prompt Injection Taxonomy (CONFIRMED)

| Fact | Source | Status |
|---|---|---|
| Direct vs indirect injection; stored = subcategory of indirect | OWASP LLM01:2025; arXiv 2410.21146 | ✓ 3-0 |
| OWASP Top 10 for LLM Apps, LLM01 Prompt Injection is authoritative taxonomy | genai.owasp.org/llmrisk/llm01-prompt-injection | ✓ |
| **REFUTED**: the "deepset/prompt-injections = 546 prompts, the ~200-payload benchmark" provenance | arXiv 2410.21146 | ❌ 1-2 — do NOT cite this provenance |

**Gap:** The "~200 malicious payload open-source dataset" in the brief is currently
**unsupported**. We need a defensible, citable benchmark (verified provenance + label schema)
before claiming ">99% mitigation over 200 payloads." Candidates to verify: `deepset/prompt-injections`
(HF), `jailbreak_llms`, Lakera Gandalf, or a composed corpus we document ourselves.

## Part 6 — Compliance (CONFIRMED — 3rd pass, vs primary PCI SSC v4.0.1 + AICPA TSC)

| Control | Verbatim / detail | Standard |
|---|---|---|
| **Req 10** title | "Log and Monitor All Access to System Components and Cardholder Data" | PCI-DSS v4.0.1 |
| **10.2** | Audit logs support anomaly detection + forensics (10.2.1.3 = log access to audit logs) | PCI-DSS v4.0.1 |
| **10.3.1 / 10.3.2** | Read access limited to job-need; logs protected from modification (immutability) | PCI-DSS v4.0.1 |
| **10.4** | Log review; NEW automated-mechanism requirement (best practice until 2025-03-31) | PCI-DSS v4.0.1 |
| **10.5.1** | "Retain audit log history for at least 12 months, with at least the most recent three months immediately available for analysis" (exact text, p.251) | PCI-DSS v4.0.1 |
| **3.3** | No storage of sensitive authentication data (track/CVV/PIN) after authorization | PCI-DSS v4.0.1 |
| **3.4.1** | PAN masked on display to max BIN + last four | PCI-DSS v4.0.1 |
| **3.5.1** | Stored PAN rendered unreadable: one-way hash / truncation / index tokens / strong crypto | PCI-DSS v4.0.1 |
| **SOC 2** | 5 categories (Security, Availability, Processing Integrity, Confidentiality, Privacy); Security = Common Criteria, mandatory | AICPA 2017 TSC (rev. 2022) |
| **CC7.1–7.4** | 7.1 vuln detection, 7.2 anomaly monitoring (incl. logging), 7.3 event evaluation, 7.4 incident response | AICPA TSC |

Primary source: PCI SSC PCI-DSS v4.0.1 PDF (June 2024); AICPA/ASEC 2017 TSC. All 3-0.

## Part 7 — Self-hostable guardrail models (CONFIRMED — 4th pass, vs official model cards)

**Purpose-built INJECTION/JAILBREAK classifiers (self-hostable):**

| Model | Params | Arch | Labels | License | Self-reported acc | Notes |
|---|---|---|---|---|---|---|
| **Llama Prompt Guard 2 86M** | 86M | mDeBERTa-base (encoder) | benign/malicious | Llama 4 Community (<700M MAU) | AUC .998, Recall@1%FPR 97.5% (EN); **92.4 ms latency** | **MULTILINGUAL** (EN/FR/DE/HI/IT/PT/ES/TH), 512-tok |
| Llama Prompt Guard 2 22M | 22M | DeBERTa-xsmall | benign/malicious | Llama 4 Community | AUC .995 / 88.7% | tiny/fast |
| protectai deberta-v3-base-prompt-injection-v2 | ~184M | DeBERTa-v3 (encoder) | benign/injection | **Apache-2.0** | Acc 95.25, P 91.59, R 99.74, F1 95.49 (20k held-out) | **EN-only; no jailbreak detection** |
| deepset deberta-v3-base-injection | ~184M | DeBERTa-v3 | injection/legit | **MIT** | — | |
| **NVIDIA NemoGuard JailbreakDetect** | RF over snowflake-arctic-embed-m-long (137M, 768-d, Apache-2.0) | RF on embeddings | bool + prob | NVIDIA Open Model | F1 0.9601, FPR 0.0042, FNR 0.0435 (JailbreakHub) | ships as on-prem **NIM Docker** container, REST `/v1/security/.../nemoguard-jailbreak-detect`, air-gap path |

**Llama Guard family (3-1B, 3-8B, 4-12B):** decoder/generative, MLCommons hazard taxonomy
(S1–S14). These are **content/SAFETY moderation, NOT prompt-injection detectors** — Meta
explicitly redirects injection use-cases to Prompt Guard. Usable only as an optional *policy/output*
rail, a different axis from injection detection. Llama Community License (<700M MAU).

**CRITICAL caveats:**
- **ALL accuracy numbers are VENDOR SELF-REPORTED** from model cards; NO independent third-party
  evals survived verification. Benchmarks differ per model (Prompt Guard 2 own set; ProtectAI 20k;
  NemoGuard JailbreakHub) → **not directly comparable**. The paper/design must label them as such.
- **Quantization/serving VRAM-latency was NOT covered** (open question) — do NOT assert specific
  VRAM/quant numbers without a follow-up pass; treat as deployment-dependent.
- Time-sensitivity: Prompt Guard 2 + Llama Guard 4 shipped with Llama 4 (Apr 2025); NIM tags drift.

**Design implication:** Prompt Guard 2 86M is the primary Tier-3a (multilingual matches our DE+EN
deepset corpus; ProtectAI is EN-only + no jailbreak). NemoGuard covers the jailbreak axis on-prem.
Both self-hostable. Llama Guard is out-of-scope for injection.

## Part 8 — Prompt-injection datasets (CONFIRMED — 5th pass, vs HF cards/arXiv/licenses)

| Dataset | Count (verified?) | License | Citable | Type / source | Benign? |
|---|---|---|---|---|---|
| **deepset/prompt-injections** | 662 (546/116) — **machine-confirmed** | **Apache-2.0** ✓ | — | direct, curated, DE+EN | yes (399) |
| **Lakera/gandalf_ignore_instructions** | 1,000 (777/111/112) — **machine-confirmed** | **MIT** ✓ | arXiv:2501.07927 | direct, game-sourced "ignore instructions" | **NO** (attacks only) |
| **HackAPrompt** (hackaprompt/hackaprompt-dataset) | 600K+ raw submissions (dedup count UNKNOWN) | **MIT** ✓ | arXiv:2311.16119 (EMNLP'23) | direct, competition-crowdsourced | attacks (need benign elsewhere) |
| **Microsoft BIPIA** | 626,250 tr / 86,250 te (paper self-report) | ⚠ **verify** (microsoft/BIPIA) | arXiv:2312.14197 (KDD'25) | **INDIRECT** (embedded in external content) | has both |
| **xTRam1/safe-guard-prompt-injection** | ~10K (exact counts **REFUTED**) | ⚠ **unverified** | community, no paper | synthetic GPT-3.5, categorical tree | yes (seed) |
| **Tensor Trust** | 126K+ attacks / 46K defenses (paper) | ❌ **license UNCONFIRMED** (CC BY 4.0 refuted) | arXiv:2311.01011 | direct, game (extraction vs hijack) | defenses≠benign |

**Corrections logged:** Gandalf paper is **2501.07927** (not 2311.01011); Tensor Trust is **2311.01011**.

**Training-eligible (license-confirmed permissive):** deepset (Apache-2.0), gandalf (MIT),
HackAPrompt (MIT). **Hold before training:** safe-guard (license unverified), BIPIA (verify
microsoft license), Tensor Trust (**license unconfirmed → exclude** until confirmed).

**OOD-test decision:** primary OOD = **HackAPrompt** (direct injection = our webhook use case,
MIT-clean, crowdsourced source structurally distinct from curated deepset/game gandalf). Secondary
OOD (reported, not ship-gating) = **BIPIA** (indirect — the *hardest* generalization; failing it is
expected, not disqualifying). Rationale: an indirect-only OOD (BIPIA) as the sole gate would be
mis-scoped — our target is direct injection in webhook bodies.

## Standing rules for the paper
1. Every Cloudflare number gets a `(as of YYYY-MM-DD)` stamp.
2. Separate CPU-time budget from wall-clock latency SLO — never conflate.
3. Parts 3 & 4 claims are provisional until the second verification pass closes the gaps.
4. Do not assert a specific 200-payload dataset provenance until re-sourced.
