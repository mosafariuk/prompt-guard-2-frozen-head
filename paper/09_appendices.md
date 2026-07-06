# Appendix A. Full STRIDE → Mitigation Mapping

Table A.1 expands the abbreviated Table I (§II-B) into the complete decomposition,
adding the cross-boundary coupling, a qualitative likelihood/impact for the
payment-gateway running example, the mitigating control with its paper section,
and the residual risk that survives the control. "L/I" is Likelihood/Impact on a
{Low, Med, High} scale. Boundaries: **B1** public network, **B2** edge↔origin,
**B3** the model's instruction/data boundary (§II-A).

**TABLE A.1. Complete STRIDE decomposition of the webhook→LLM pipeline.**

| # | STRIDE | Threat | Asset | Bdy | Coupling | L/I | Mitigating control (§) | Residual risk |
|---|--------|--------|-------|-----|----------|-----|------------------------|---------------|
| 1 | Spoofing | Forged/unsigned webhook impersonating a producer or tenant | A1 | B1 | — | H/H | HMAC-SHA256 verify + tenant binding (§IV-C) | Key compromise within a rollover window (§IV-D) |
| 2 | Tampering | Payload mutated in transit | A3 | B1 | — | M/H | Signature over canonical `H_body` (§IV-B) | None if HMAC unbroken |
| 3 | Tampering→Elev. | Indirect injection: adversarial instructions in relayed content | A3 | B1,B3 | T→E | H/H | Aho–Corasick + feature screening (§V) | Novel/semantic phrasings (measured FNR 97.7 %, §VII); delegated to origin tier (§IX) |
| 4 | Tampering→Info | Cross-tenant context poisoning: $t_a$ mutates shared state read into $t_b$'s context | A2,A3 | B3 | T→I | L/H | Tenant binding (§IV) + assumed per-tenant context isolation (§II-D mode 1) | Origin-side isolation is *assumed*, not enforced by the edge (L3, §IX) |
| 5 | Repudiation | Attack occurs with no durable attribution | A5 | B1 | — | M/M | Async append-only threat log (§VI); PCI 10.2/10.3 | Log-store availability over the write window (§VI-B) |
| 6 | Info. disclosure | System-prompt / context extraction; cross-tenant leakage | A2 | B3 | — | M/H | Extraction signatures (§V-B) + isolation | Obfuscated extraction below signature threshold |
| 7 | DoS | Token flood / CPU / subrequest exhaustion; "denial-of-wallet" | A4 | B1 | — | H/M | Size guard + sub-ms rejection before inspection (§III-C, §V) | Distributed volumetric floods (upstream CDN scope) |
| 8 | Elev. of priv. | Direct injection / jailbreak executes with the agent's tool/data privileges | A2,A3 | B3 | — | H/H | Screening (§V) + least-privilege origin tools | Same recall gap as row 3 |

**Reading the residual-risk column.** Rows 3 and 8 carry the recall gap the paper
measures empirically (§VII, Table III): the edge layer's deterministic screening is
high-precision but low-recall, so the *residual* for these rows is explicitly
transferred to the origin escalation tier (§IX), not claimed as closed. Row 4's
residual — that mode-1 context isolation is assumed — is the paper's principal
scoping boundary (L3). This column is what makes the threat model *actionable*: it
states, per threat, exactly what is and is not discharged.

---

# Appendix B. Proof of the Tenant-Binding Theorem

We give the full game-hopping proof of Theorem 1 (§IV-C), the Injectivity Lemma it
depends on, and the extensions to key rotation (Theorem 2) and replay.

## B.1 Preliminaries recalled

Let $H=\mathsf{HMAC\text{-}SHA256}$ with tag length $n=256$. For a set of tenants
$\mathcal{T}$, keys $k_i \leftarrow_\$ \{0,1\}^n$ are drawn independently. The signed
message is the injective encoding
$$m = \langle \mathsf{tid} \rangle \,\|\, \langle \kappa \rangle \,\|\, \langle t \rangle
\,\|\, \langle \eta \rangle \,\|\, \langle H_{\text{body}} \rangle,$$
where $\langle\cdot\rangle$ denotes a length-prefixed (self-delimiting) field
encoding. Write $\mathsf{tid}(m)$ for the tenant-id field recovered from $m$. The
signing function is $\mathsf{Mac}_{k}(m)=H_k(m)$ and verification checks
$H_k(m)\stackrel{?}{=}\tau$ in constant time.

**Assumptions.** (i) Multi-user PRF security of HMAC: for $u$ instances,
$\mathbf{Adv}^{\text{mu-prf}}_{H,u}(\mathcal{B})$ is negligible and, by [BBT16],
carries no factor linear in $u$. (ii) The field encoding is injective (Lemma B.1).

## B.2 The multi-user tenant-binding game $\mathbf{G}_0$

1. Sample $k_i\leftarrow_\$\{0,1\}^n$ for all $t_i\in\mathcal{T}$.
2. $\mathcal{A}$ chooses a corrupt set $\mathcal{C}\subsetneq\mathcal{T}$ and receives
   $\{k_i: t_i\in\mathcal{C}\}$. Let $\mathcal{U}=\mathcal{T}\setminus\mathcal{C}$,
   $u=|\mathcal{U}|$.
3. $\mathcal{A}$ has oracles, for every $t_j\in\mathcal{U}$:
   $\mathsf{Sign}_j(m)=H_{k_j}(m)$ (queries recorded in $\mathcal{Q}_j$) and
   $\mathsf{Ver}_j(m,\tau)=[\,H_{k_j}(m)=\tau\,]$.
4. $\mathcal{A}$ outputs $(b,m^\*,\tau^\*)$ with $t_b\in\mathcal{U}$ and
   $\mathsf{tid}(m^\*)=\mathsf{tid}_b$.
5. **Win** ($\mathbf{G}_0=1$) iff $H_{k_b}(m^\*)=\tau^\*$ and $m^\*\notin\mathcal{Q}_b$.

By definition $\mathbf{Adv}^{\text{bind}}(\mathcal{A})=\Pr[\mathbf{G}_0=1]$. Let $Q_v$
be the total number of verification queries $\mathcal{A}$ makes.

## B.3 Lemma B.1 (Injectivity / namespace separation)

*If the field encoding $\langle\cdot\rangle\|\cdots$ is injective and $\mathsf{tid}$
occupies a self-delimiting field, then (a) distinct field-tuples yield distinct $m$,
and (b) any $m^\*$ with $\mathsf{tid}(m^\*)=\mathsf{tid}_b$ that is not in
$\mathcal{Q}_b$ is a fresh input to $H_{k_b}$ — independent of every query made to any
$\mathsf{Sign}_j$, $j\neq b$.*

*Proof.* (a) is immediate from injectivity of a concatenation of self-delimiting
fields. For (b): the only oracle evaluating $H_{k_b}$ is $\mathsf{Sign}_b$ (and
$\mathsf{Ver}_b$, which reveals only a bit). Queries to $\mathsf{Sign}_j$, $j\neq b$,
evaluate $H_{k_j}$ under an independent key $k_j$ and thus reveal nothing about
$H_{k_b}(m^\*)$. Since $m^\*\notin\mathcal{Q}_b$, the value $H_{k_b}(m^\*)$ was never
returned to $\mathcal{A}$. $\square$

The lemma is the crux of *binding*: because $\mathsf{tid}_b$ is inside $m$, owning
every other tenant's key (hence every $H_{k_j}$, $j\neq b$) yields no information about
the tag $\mathcal{A}$ must produce for $t_b$.

## B.4 Proof of Theorem 1

We bound $\Pr[\mathbf{G}_0=1]$ by a two-game hop.

**Game $\mathbf{G}_1$.** Identical to $\mathbf{G}_0$, except each uncorrupted tenant's
$H_{k_j}$ ($j\in\mathcal{U}$) is replaced by an independent truly random function
$R_j:\{0,1\}^\*\to\{0,1\}^n$; both $\mathsf{Sign}_j$ and $\mathsf{Ver}_j$ use $R_j$.

*Claim 1.* $\big|\Pr[\mathbf{G}_1=1]-\Pr[\mathbf{G}_0=1]\big|\le
\mathbf{Adv}^{\text{mu-prf}}_{H,u}(\mathcal{B})$.

*Proof.* Construct a mu-PRF distinguisher $\mathcal{B}$ against $u$ instances.
$\mathcal{B}$ samples the corrupt keys itself, answers corrupt-key reveals directly,
and routes every $\mathsf{Sign}_j/\mathsf{Ver}_j$ call ($j\in\mathcal{U}$) to its
$j$-th oracle. If the oracles are the real $H_{k_j}$, $\mathcal{B}$ simulates
$\mathbf{G}_0$ exactly; if they are random functions, it simulates $\mathbf{G}_1$.
$\mathcal{B}$ outputs $1$ iff $\mathcal{A}$ wins. The distinguishing advantage is the
game gap, and by [BBT16] it is $\le\mathbf{Adv}^{\text{mu-prf}}_{H,u}$ with no
$u$-factor. $\square$

*Claim 2.* $\Pr[\mathbf{G}_1=1]\le Q_v\,2^{-n}$.

*Proof.* In $\mathbf{G}_1$, verification of a candidate $(b,m^\*,\tau^\*)$ succeeds iff
$\tau^\*=R_b(m^\*)$. By Lemma B.1(b), $m^\*$ (fresh, $\mathsf{tid}=\mathsf{tid}_b$,
$\notin\mathcal{Q}_b$) is a point at which $R_b$ has never been evaluated in
$\mathcal{A}$'s view, so $R_b(m^\*)$ is uniform on $\{0,1\}^n$ and independent of
everything $\mathcal{A}$ has seen (including all $R_{j\neq b}$ outputs and all corrupt
keys). Any single verification query therefore succeeds with probability exactly
$2^{-n}$. A union bound over the $\le Q_v$ verification queries gives
$\Pr[\mathbf{G}_1=1]\le Q_v\,2^{-n}$. $\square$

Combining, $\mathbf{Adv}^{\text{bind}}(\mathcal{A})=\Pr[\mathbf{G}_0=1]\le
\mathbf{Adv}^{\text{mu-prf}}_{H,u}(\mathcal{B})+Q_v\,2^{-n}$, which is Theorem 1.
$\blacksquare$

**Interpretation.** With $n=256$, the $Q_v\,2^{-n}$ term is negligible for any
feasible $Q_v$; the bound is dominated by the mu-PRF term, which — critically — does
not grow with the number of tenants $u$. Cross-tenant attribution is therefore as hard
as breaking HMAC, at enterprise tenant scale.

## B.5 Extension to key rotation (Theorem 2)

Model each currently-valid pair $(t_i,\kappa)$, $t_i\in\mathcal{U}$, as one instance;
let $u'=\sum_{t_i\in\mathcal{U}}|\{\kappa: k_{i,\kappa}\text{ valid}\}|\le uL$. The
rotation verifier accepts a $t_b$-attributed message iff some valid $(t_b,\kappa)$
verifies it, i.e. iff it is a forgery under one of these instances. Since $\kappa$ is
inside $m$ (authenticated), Lemma B.1 extends: a message with a given
$(\mathsf{tid}_b,\kappa)$ is fresh input to instance $(b,\kappa)$. Re-running §B.4 with
the instance set enlarged from $u$ to $u'$ gives
$\mathbf{Adv}^{\text{bind-rot}}\le\mathbf{Adv}^{\text{mu-prf}}_{H,u'}+Q_v\,2^{-n}$,
which by [BBT16] is again independent of $u'$ (hence of both $u$ and $L$).
$\blacksquare$

## B.6 Replay resistance (orthogonal freshness argument)

Theorem 1 permits replay of an *already-signed* $(m,\tau)$: $m\in\mathcal{Q}_b$ is not
a win. Freshness is enforced separately. With tolerance window $\Delta$, nonce cache
$\mathcal{N}$ (TTL $2\Delta$), and $\lambda$-bit nonces, a replayed
$(m,\tau)$ is accepted only if it arrives within $\Delta$ of $t_s$ (else the timestamp
check rejects) *and* its nonce $\eta$ has been evicted from $\mathcal{N}$ (else the
replay check rejects). Since $\mathcal{N}$ retains $\eta$ for $2\Delta\ge\Delta$, within
the timestamp window $\eta$ is necessarily present, so
$$\Pr[\text{replay accepted}]\le\Pr[\text{nonce-store loss over }2\Delta]+2^{-\lambda},$$
where the first term is the cache's availability failure probability and $2^{-\lambda}$
bounds an accidental nonce collision. For $\lambda=128$ the collision term is
negligible; replay resistance reduces to nonce-store reliability. $\blacksquare$

## B.7 Remarks

- **Tightness.** The reduction is tight up to the mu-PRF term; there is no
  target-guessing $1/u$ loss (a forgery under *any* uncorrupted instance wins the
  mu-game).
- **No forward secrecy.** Keys are symmetric; a leaked $k_{i,\kappa}$ forges within
  $\kappa$'s window. Rotation bounds, but does not retroactively protect, that window.
- **Constant-time verification** is required so that $\mathsf{Ver}$ leaks only the
  accept/reject bit modelled in the game, not tag bytes via timing.

---

# Appendix C. Signature Corpus and Reproducibility

## C.1 Signature families

The shipped corpus (`edge-firewall/src/signatures.ts`) contains 24 signatures across
the OWASP LLM01 families of §II-C. Each is `blocking` (a single hit forces reject,
favouring the low-FPR operating point) or weighted (contributes to the soft score
$\theta$, §V-C).

**TABLE C.1. Signature families (shipped corpus).**

| Family (§II-C) | Example signatures | Blocking | Weighted |
|----------------|--------------------|----------|----------|
| Direct override | `ignore previous instructions`, `disregard all previous`, `forget everything above` | 3 | 2 |
| Extraction | `reveal your system prompt`, `repeat the words above`, `print your configuration` | 1 | 3 |
| Role-play / persona | `you are now dan`, `enable developer mode`, `do anything now` | 2 | 3 |
| Safety bypass | `jailbreak mode`, `without any content filter`, `unlock full capabilities` | 1 | 2 |
| Delimiter / tag | `<|system|>`, `<|im_start|>`, `### system`, `assistant:` | 2 | 4 |
| Control-token | `<|endoftext|>`, `</s>` | 1 | 1 |

The compactness of this set is deliberate and is exactly what §VII, Table III
measures: it yields 0 % FPR but low recall on diverse real injections. The set is *not*
tuned against the evaluation corpus (that would overfit and is methodologically
disallowed); expanding it is future work via threat-log-driven synthesis (§IX-2).

## C.2 Evaluation corpus

- **Source:** `deepset/prompt-injections`, Hugging Face, Apache 2.0.
- **Size:** 662 rows (546 train / 116 test); labels $0=$legit, $1=$injection; DE+EN.
- **Split used:** the full 662 rows ($|\mathcal{X}^+|=263$, $|\mathcal{X}^-|=399$).
- **Fetched by:** `benchmarks/corpus/fetch_corpus.mjs` (datasets-server rows API).

## C.3 Operating point and metrics

Decision threshold $\theta=1.0$ (§V-C). A payload is a predicted positive iff the
firewall does not `forward` (i.e. `reject` or `escalate`). Metrics as defined in §VII-D;
confidence intervals are Wilson score at 95 % (`benchmarks/lib/stats.mjs`); ROC AUC by
trapezoidal integration over the swept threshold, with a blocking hit treated as a
maximal-confidence positive.

## C.4 Reproduction

```bash
cd benchmarks && npm install
npm run corpus      # deepset/prompt-injections -> corpus/payloads.json (662 rows)
npm run detection   # confusion matrix + Wilson CIs  -> results/detection.{json,md}
npm run roc         # ROC/AUC over the real screen()  -> results/roc.json
npm run report      # Section VII placeholder table
```

Committed artifacts of the run reported in Table III live in
`benchmarks/results/deepset-662-local/`. Latency (§VII-C) requires a live edge
deployment; run `benchmarks/latency.k6.js` with `WORKER_URL` and a provisioned bench
tenant key.

> Evidence status: Appendix A extends the CONFIRMED §II taxonomy and the MEASURED §VII
> residuals. Appendix B reduces solely to the mu-PRF assumption ([BBT16]) and the
> standard EUF-CMA framework — no unverified external facts. Appendix C's corpus facts
> are CONFIRMED by direct fetch (verified-facts Part 4b) and its metrics are the
> executed harness output.

---

# Data and Code Availability

The Phase-5 injection-classifier pipeline is released to support reproduction of the
99.9 % out-of-distribution result: the corpus builder and leakage-control deduplication
(`build_corpus.py`), the frozen Prompt Guard 2 embedding extractor
(`extract_pg2_embeddings.py`), the head-training and single-touch OOD evaluation
(`train_head.py`, `phase5a_bis.py`, `phase5a_ter.py`), the production head finalizer
(`finalize_head.py`), and the pre-registration protocol (`docs/phase5a_finetune_scoping.md`)
that fixed the success criteria before any training code. All evaluation datasets are the
license-confirmed public corpora enumerated in Appendix C. The deterministic seeds
(20260705/06/07) reproduce the exact train / validation / OOD splits.

Repository: <https://github.com/mosafariuk/prompt-guard-2-frozen-head>

Artifacts are additionally available from the corresponding author (mo@aioapex.com) on
request.

---

# Acknowledgment

During the preparation of this manuscript, the author used Anthropic's Claude (Opus)
as an AI assistant to support drafting, code and benchmark implementation, LaTeX
preparation, and analysis. The author critically reviewed, edited, and verified all
content, experimental results, and claims — including the pre-registered evaluation
protocol and every reported number — and takes full responsibility for the integrity
of the work. No AI system is listed as an author, consistent with IEEE authorship policy.
