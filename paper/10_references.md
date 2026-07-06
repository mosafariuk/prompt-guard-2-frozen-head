# References

Consolidated bibliography. Keys are the mnemonic `\cite` labels used inline
throughout the sections; a camera-ready build would renumber these [1]…[n] via
BibTeX. Grouped by type for readability; **P** = primary/verified, **C** =
canonical dated work, **S** = secondary (used only qualitatively).

## Platform documentation (P — Cloudflare, accessed 2026-07-04)
- **[C-limits]** Cloudflare, "Workers — Limits," developers.cloudflare.com/workers/platform/limits.
- **[C-pricing]** Cloudflare, "Workers — Pricing," developers.cloudflare.com/workers/platform/pricing.
- **[C-changelog-2025]** Cloudflare, "Higher CPU limits for Workers," changelog, 2025-03-25.
- **[C-changelog-2026]** Cloudflare, "Increased subrequest limits," changelog, 2026-02-11.
- **[C-do-limits]** Cloudflare, "Durable Objects — Limits," developers.cloudflare.com/durable-objects/platform/limits.
- **[C-wf-limits]** Cloudflare, "Workflows — Limits," developers.cloudflare.com/workflows/reference/limits.

## Cryptography (P/C)
- **[RFC2104]** H. Krawczyk, M. Bellare, R. Canetti, "HMAC: Keyed-Hashing for Message Authentication," RFC 2104, IETF, Feb. 1997.
- **[FIPS198-1]** NIST, "The Keyed-Hash Message Authentication Code (HMAC)," FIPS PUB 198-1, 2008.
- **[BCK96]** M. Bellare, R. Canetti, H. Krawczyk, "Keying Hash Functions for Message Authentication," CRYPTO 1996. (See also M. Bellare, "New Proofs for NMAC and HMAC," CRYPTO 2006.)
- **[BBT16]** M. Bellare, D. J. Bernstein, S. Tessaro, "Hash-Function Based PRFs: AMAC and Its Multi-User Security," EUROCRYPT 2016.
- **[Stripe-sig]** Stripe, "Verify webhook signatures," docs.stripe.com/webhooks/signature (accessed 2026-07-04).

## LLM security & prompt injection (P)
- **[OWASP-LLM01]** OWASP, "LLM01:2025 Prompt Injection," Top 10 for LLM Applications, genai.owasp.org/llmrisk/llm01-prompt-injection.
- **[arXiv-2601.07185]** "Defenses Against Prompt Attacks Learn Surface Heuristics," arXiv:2601.07185, 2026.
- **[arXiv-2410.22284]** M. A. Ayub, S. Majumdar, "Embedding-based classifiers for prompt-injection detection," CAMLIS 2024, arXiv:2410.22284.
- **[arXiv-2410.21146]** "(direct/indirect/stored prompt-injection taxonomy)," arXiv:2410.21146, 2024.

## Algorithms & statistics (C)
- **[AC75]** A. V. Aho, M. J. Corasick, "Efficient String Matching: An Aid to Bibliographic Search," Comm. ACM, 18(6):333–340, 1975.
- **[Springer-AC]** "(Aho–Corasick multi-pattern matching for signature detection)," Springer, doi:10.1007/978-3-031-96093-2_15.
- **[DY83]** D. Dolev, A. C. Yao, "On the Security of Public Key Protocols," IEEE Trans. Inf. Theory, 29(2):198–208, 1983.
- **[Wilson27]** E. B. Wilson, "Probable Inference, the Law of Succession, and Statistical Inference," J. Amer. Stat. Assoc., 22(158):209–212, 1927.

## Database (P — PostgreSQL official docs)
- **[PG-json]** "JSON Types," postgresql.org/docs/current/datatype-json.html.
- **[PG-toast]** "Database Physical Storage — TOAST," postgresql.org/docs/current/storage-toast.html.
- **[PG-wal-conf]** "Write Ahead Log — runtime config," postgresql.org/docs/current/runtime-config-wal.html.
- **[PG-wal-config]** "WAL Configuration," postgresql.org/docs/current/wal-configuration.html.
- **[PG-gin]** "GIN Indexes," postgresql.org/docs/current/gin.html.
- **[PG-partition]** "Table Partitioning," postgresql.org/docs/current/ddl-partitioning.html.

## Compliance (P)
- **[PCI-DSS]** PCI Security Standards Council, "PCI-DSS v4.0.1," June 2024. Req 10.2/10.3.1/10.3.2/10.5.1; Req 3.3/3.4.1/3.5.1.
- **[AICPA-TSC]** AICPA, "Trust Services Criteria" (2017, rev. 2022), Common Criteria CC7.1–CC7.4.

## Datasets (P — accessed 2026-07-04)
- **[DS-PI]** deepset, "prompt-injections," Hugging Face Datasets (662 rows; 546/116; Apache 2.0).
- **[DS-JB]** jackhhao, "jailbreak-classification," Hugging Face Datasets (1,306 rows; Apache 2.0).
- **[DS-GA]** Lakera, "gandalf_ignore_instructions," Hugging Face Datasets; see also arXiv:2311.01011.

## Secondary (S — qualitative use only)
- **[Layered]** "(layered prompt-injection detector; <1 ms Layers 1–2, 300–800 ms model layer)," dev.to. Used only for the model-tier latency order-of-magnitude (§V-A/§V-D).

## To complete before camera-ready
- **[cite]** Llama Guard (Meta) — model-guardrail reference (§V-A, §VIII).
- **[cite]** GitHub webhook signing docs — timestamped HMAC scheme (§VIII).
