# III. Edge Interception Layer: The V8 Isolate Execution Envelope

This section characterizes the runtime in which the firewall executes and converts its published
resource limits into an *operation budget* against which §V's algorithms are checked. We first
describe the isolate execution model (§III-A), fix the resource envelope from primary sources
(§III-B), derive the cost model and budget (§III-C), restate the CPU/wall-clock correction and its
consequences (§III-D), and give the reverse-proxy dataflow (§III-E).

## III-A. The Isolate Execution Model

Cloudflare Workers execute in **V8 isolates** rather than per-request containers or processes. An
isolate is a lightweight, memory-safe sandbox within a shared V8 runtime; thousands coexist in one
OS process, and a single isolate serves *many* concurrent requests. This has three consequences
that shape the firewall's design.

1. **No per-request process spin-up.** Unlike a container-per-request model, isolate reuse means
   module-scope initialization (parsing configuration, *building the Aho–Corasick automaton*)
   executes once when the isolate is created and is then amortized across every request that
   isolate serves. Only work performed *inside* the request handler counts against per-request CPU.
2. **Cold start vs. warm path.** A request routed to a location with no warm isolate pays a
   one-time initialization cost (the module top-level), after which the isolate stays warm and
   subsequent requests skip it. Our design places all heavy precomputation at module top level
   precisely so that it is paid at most once per isolate lifetime, never on the warm request path.
3. **Single-threaded, event-loop concurrency.** Each isolate runs JavaScript on a single thread;
   concurrency is cooperative via the event loop. CPU-bound work therefore *blocks* the isolate for
   its duration, which is why the per-request CPU cost of screening must be small in absolute terms,
   not merely asymptotically linear. This motivates the operation-budget analysis of §III-C.

The isolate model also underlies the memory constraint: because one isolate hosts many requests,
the 128 MB cap (§III-B) is a *per-isolate*, not per-request, limit, and long-lived module-scope
structures (the automaton, signature tables) are counted against it once, not per request.

## III-B. The Resource Envelope

Table II fixes the operative limits from primary Cloudflare documentation. **Every figure is
date-stamped (accessed 2026-07-04); the platform revises these quarterly, and any reuse of this
table must re-verify.**

**TABLE II. Cloudflare Workers resource envelope (accessed 2026-07-04).**

| Resource | Free plan | Paid (Standard) plan | Source |
|---|---|---|---|
| CPU time / invocation | **10 ms** | **30 s default**, configurable to **300 s (5 min)** via `limits.cpu_ms` | [C-limits], [C-changelog-2025] |
| Wall-clock duration (HTTP trigger) | no hard limit | no hard limit / no charge | [C-limits], [C-pricing] |
| Memory / isolate | 128 MB | 128 MB | [C-limits] |
| Subrequests / invocation | 50 external + 1,000 to CF services | **10,000 default** (to 10 M), since 2026-02-11 | [C-limits], [C-changelog-2026] |
| I/O wait counted as CPU? | **No** | **No** | [C-limits] |

Three properties of this envelope are decisive for the architecture:

- **CPU time excludes I/O wait.** Time awaiting the `fetch` to the origin LLM, a KV read for a
  nonce (§IV), or the database write (§VI) does *not* accrue against the CPU limit [C-limits].
  Consequently the firewall's CPU budget is consumed *only* by local computation — signature
  scanning, HMAC verification, sanitization — and not by the network operations that dominate
  wall-clock time.
- **Wall-clock is effectively unbounded for HTTP-triggered Workers.** The webhook path is
  HTTP-triggered, so there is no duration cap to design against; the "<50 ms" target (§VII) is a
  self-imposed *latency SLO*, not a platform limit.
- **The subrequest budget is ample.** Forwarding to origin plus at most a small constant number of
  KV/queue operations per request sits far within even the Free-plan 50-external ceiling.

## III-C. From CPU Limit to Operation Budget

Asymptotic complexity bounds *scaling* but not *absolute* latency; a linear algorithm with a large
constant on an unbounded input can exceed any fixed budget. A defensible sub-millisecond guarantee
therefore requires three ingredients: (i) a hard bound on input size, (ii) a per-operation constant
on the target runtime, and (iii) a worst-case operation count. We supply (i) and (iii) here
analytically and pin (ii) empirically in §VII.

**Operation budget.** Let $\rho$ (operations · ms$^{-1}$) be the effective scalar-operation
throughput of the edge V8 runtime for the byte-scanning workload of §V, and let $L_{\text{CPU}}$ be
the per-invocation CPU limit. The available operation budget for one request is
$$B = \rho \cdot L_{\text{CPU}}.$$
On the Free plan, $L_{\text{CPU}} = 10\text{ ms}$; on paid plans the *default* is $L_{\text{CPU}} =
30{,}000\text{ ms}$. We deliberately evaluate the firewall against the **Free-plan** budget as the
worst case — if screening fits in 10 ms of CPU, it fits everywhere. $\rho$ is left symbolic here
and measured in §VII; the analysis below yields a bound of the form "$C_{\text{req}}/B$" that is
independent of $\rho$'s exact value once $\rho$ is known.

**Input bound.** The firewall rejects any request whose body exceeds a configured maximum
$N_{\max}$ bytes *before* invoking the scanner (Algorithm in §V). Oversized-payload rejection is
simultaneously (a) a precondition for the latency guarantee and (b) a DoS control (Table I, row 7).
We take $N_{\max}$ as a deployment parameter (default 128 KiB in our implementation, §V/Phase 2).

**Per-request cost.** Under the isolate model (§III-A), the O($m$) Aho–Corasick construction over
total signature length $m$ executes once at module init and contributes **zero** to the per-request
budget. The per-request work is therefore:
$$C_{\text{req}} \;\le\; \underbrace{c_{\text{ac}}\,(N_{\max} + z)}_{\text{signature scan (§V-B)}}
\;+\; \underbrace{k\,c_{\text{lin}}\,N_{\max}}_{k \text{ linear feature passes (§V-C)}}
\;+\; \underbrace{c_{\text{hmac}}\,N_{\max}}_{\text{HMAC over payload (§IV)}},$$
where $z \le N_{\max}$ is the number of signature matches (bounded by input length and further
capped by early-exit, §V-B), $k$ is the fixed number of linear feature passes (entropy, structural
— a small constant, $k \le 4$), and $c_{\bullet}$ are per-byte constants. Since $z \le N_{\max}$,
this simplifies to
$$C_{\text{req}} \;\le\; \big(2c_{\text{ac}} + k\,c_{\text{lin}} + c_{\text{hmac}}\big)\,N_{\max}
\;=\; \kappa\, N_{\max},$$
a **constant $\kappa$ times a bounded input** — the only form that supports an absolute latency
claim. The sub-millisecond guarantee is then the assertion $\kappa N_{\max} \ll B$, i.e.
$$\frac{C_{\text{req}}}{B} = \frac{\kappa N_{\max}}{\rho\,L_{\text{CPU}}} \ll 1,$$
which §VII establishes by measuring $\kappa/\rho$ (the wall-normalized per-byte cost) and evaluating
at $N_{\max} = 128\text{ KiB}$, $L_{\text{CPU}} = 10\text{ ms}$. The critical structural point,
provable *without* the constant, is that per-request cost is **strictly linear in a bounded input
with all superlinear and one-time work excluded** — there is no per-request construction, no
backtracking (Aho–Corasick is backtrack-free), and no unbounded loop.

## III-D. The CPU/Wall-Clock Correction and Its Consequences

As established in §I-C, the commonly cited "50 ms Worker CPU limit" is a **legacy artifact** of the
deprecated Bundled usage model, auto-applied during the 2024-03-01 migration to Standard pricing
[C-pricing]; it is not the contemporary envelope. Table II supersedes it. Two engineering
consequences follow directly and are exploited by the architecture:

1. **The screening layer runs with vast headroom, not at the margin.** Against a 10 ms Free-plan
   CPU ceiling — and 30,000 ms on paid plans — a $\kappa N_{\max}$ cost on a 128 KiB bound is
   orders of magnitude under budget (§VII quantifies the ratio). The design problem is not "fit
   inside a tight CPU limit" but "spend a tiny, *bounded* fraction of an ample budget so that
   screening is invisible in the wall-clock latency envelope."
2. **I/O is free against the CPU budget, so decoupling is natural.** Because awaiting the origin
   `fetch` and the threat-log write does not accrue CPU (§III-B), the firewall can forward the
   request and hand off logging (§VI) without those operations competing with screening for the
   CPU limit. The CPU limit constrains *only* the local inspection, which §III-C has bounded.

## III-E. Reverse-Proxy Dataflow

The firewall is a reverse proxy on the request path (Fig. 1). For each inbound webhook:

```
                         ┌──────────────────────── Edge Isolate F ───────────────────────┐
 Producer ──HTTP(B1)──▶  │  (1) size guard: reject if |body| > N_max        [O(1)]        │
                         │  (2) HMAC-SHA256 verify + tenant binding (§IV)   [c_hmac·N]     │
                         │  (3) canonicalize + sanitize input (§V-E)        [O(N)]         │
                         │  (4) Aho–Corasick signature scan (§V-B)          [c_ac·(N+z)]   │
                         │  (5) structural + entropy scoring (§V-C)         [k·c_lin·N]    │
                         │  (6) decision: forward | reject                  [O(1)]         │
                         │        │ forward (B2)                                            │
                         │        ▼                                                         │
                         │   fetch → Origin O / model M   ── I/O, not CPU ──▶ response      │
                         │        │                                                         │
                         │  (7) ctx.waitUntil(logThreat(...))  ── async, post-response ──▶  │──▶ PostgreSQL (§VI)
                         └───────────────────────────────────────────────────────────────┘
```

**Fig. 1.** Request lifecycle in the edge isolate. Steps (1)–(6) are the CPU-bounded critical path
analyzed in §III-C; the origin `fetch` and the `waitUntil`-deferred threat log (§VI) are I/O and do
not accrue against the CPU limit. Steps (2), (4), (5) are the substance of §IV and §V; the size
guard (1) supplies the $N_{\max}$ bound that makes the latency analysis absolute.

The ordering is security-critical: authentication (step 2) precedes screening (steps 3–5), so
unauthenticated traffic is rejected before any content-inspection cost is incurred, and the size
guard (step 1) precedes everything, so no unbounded input reaches any linear pass.

---

### Citation keys
- **[C-limits]** Cloudflare, "Workers — Limits," developers.cloudflare.com/workers/platform/limits (accessed 2026-07-04).
- **[C-pricing]** Cloudflare, "Workers — Pricing," developers.cloudflare.com/workers/platform/pricing (accessed 2026-07-04).
- **[C-changelog-2025]** Cloudflare, "Higher CPU limits for Workers," changelog, 2025-03-25.
- **[C-changelog-2026]** Cloudflare, "Increased subrequest limits," changelog, 2026-02-11.

> Evidence status: all Table II figures are CONFIRMED at high confidence (verified-facts Part 1,
> 3-0). The cost model (§III-C) is original analysis; the constant $\rho$ (and hence $\kappa/\rho$)
> is deferred to empirical measurement in §VII and asserted nowhere as a literature value.
