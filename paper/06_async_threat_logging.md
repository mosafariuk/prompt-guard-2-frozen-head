# VI. Asynchronous Threat Logging and Data Architecture

Every interception decision (Fig. 1) must be recorded to a durable, queryable, immutable audit
trail — for forensics, for detection tuning, and for compliance (§VI-F) — yet the recording must
never appear on the request's critical path. This section resolves that tension: §VI-A states the
requirements, §VI-B gives the decoupled write path via `waitUntil` plus a durable queue, §VI-C–E
justify PostgreSQL JSONB with TOAST, WAL/GIN tuning, and date partitioning for high-velocity
ingestion at scale, and §VI-F maps the design to PCI-DSS and SOC 2 while enforcing data
minimization.

## VI-A. Requirements

The threat log must satisfy five properties simultaneously: **(R1) non-blocking** — logging adds
zero wall-clock latency to the webhook response; **(R2) durable** — an accepted event is not lost
under isolate eviction or transient DB unavailability; **(R3) high-velocity** — ingestion sustains
attack bursts (a flood produces one log row per rejected request) without back-pressuring the edge;
**(R4) queryable** — heterogeneous, schema-varying attack payloads remain indexable for analysis;
and **(R5) immutable and compliant** — the record is append-only and admissible as an audit trail
without itself becoming a data-exposure liability. R1 and R2 are in tension (durability usually
implies waiting); §VI-B resolves it by moving durability off the request path into a queue.

## VI-B. Decoupled Execution: `waitUntil` + Durable Queue

**`waitUntil` mechanics.** The Workers runtime exposes `ctx.waitUntil(promise)` (the successor to
`FetchEvent.waitUntil`), which registers a promise whose completion the runtime awaits *after the
`Response` has already been returned to the client*. Concretely, the handler computes the
block/forward decision (Fig. 1, steps 1–6), returns the response (step forward/reject), and calls
`ctx.waitUntil(logThreat(event))`; the isolate is kept alive to drain `logThreat` but the client's
latency is bounded by the response, not by the log write. Because the log write is network I/O, it
**does not consume the CPU budget** (§III-B) — R1 is met by construction, and the sub-millisecond
CPU analysis of §V-F is unaffected by logging.

**Why `waitUntil` alone is insufficient for R2.** `waitUntil` is *best-effort*: if the isolate is
evicted or the write fails, the event is lost, and it offers no back-pressure or batching. Writing
directly to PostgreSQL from the edge also couples every request to a database connection —
untenable at edge concurrency and a head-of-line risk if the DB slows. We therefore interpose a
**durable queue** (Cloudflare Queues, or a Durable Object buffer): `waitUntil` performs a single
fast `queue.send(event)` (one subrequest), and a separate **queue consumer** Worker batches events
and performs the PostgreSQL insert. This yields:

- **R1/R2 both:** the edge pays only a queue enqueue (fast, durable-once-acked); durability and
  retry live in the consumer, off the request path.
- **Batching for R3:** the consumer inserts in batches (multi-row `INSERT` / `COPY`), amortizing
  per-row WAL and round-trip cost — the single most effective throughput lever (§VI-D).
- **Back-pressure isolation:** a DB slowdown grows the queue, not the webhook latency; the edge
  never blocks. The queue depth is itself a monitorable DoS signal.

Delivery is at-least-once (consumer retries on failure), so the schema uses an idempotency key
(the authenticated nonce $\eta$ from §IV, or a synthetic event id) with `INSERT ... ON CONFLICT DO
NOTHING` to dedupe replays of the log write.

## VI-C. JSONB for Unstructured, High-Velocity Attack Payloads

Attack payloads are heterogeneous: different injection classes carry different fields, and the raw
webhook body has no fixed schema across tenants. A rigid relational schema would require migration
per new attack shape; a text blob is not queryable (R4). PostgreSQL `jsonb` resolves this:

- **Binary, decomposed storage.** Per the official documentation, `json` stores an exact text copy
  that "processing functions must reparse on each execution," whereas `jsonb` is stored "in a
  decomposed binary format that makes it slightly slower to input due to added conversion overhead,
  but significantly faster to process, since no reparsing is needed" [PG-json]. For a
  write-once/read-many audit log queried during investigations, the one-time input cost is worth the
  repeated query speedup, and — decisively for R4 — **`jsonb` supports indexing** (GIN, §VI-D)
  whereas `json` does not.
- **TOAST for oversized payloads.** A large injection payload (e.g., a multi-kilobyte obfuscated
  prompt) would otherwise threaten the 8 KB heap page. TOAST — "The Oversized-Attribute Storage
  Technique" — triggers automatically "only when a row value to be stored in a table is wider than
  `TOAST_TUPLE_THRESHOLD` bytes (normally 2 kB)," compressing and/or moving field values out-of-line
  "until the row value is shorter than `TOAST_TUPLE_TARGET` bytes (also normally 2 kB)" [PG-toast].
  The `jsonb` column uses the default `EXTENDED` strategy (compression then out-of-line) [PG-toast],
  so wide payloads are transparently compressed and relocated to the TOAST relation, keeping the
  main-heap tuples narrow and the table scannable. This is why unstructured, occasionally-large
  payloads do **not** bloat the primary heap: oversized values live out-of-line by construction.
  *(Precision note: "2 kB" is the documented nominal threshold; we state it as ≈2 kB, not an exact
  2048, per the docs' "normally 2 kB" wording.)*

## VI-D. WAL, Insert Throughput, and Avoiding GIN Index Bloat

**WAL and the durability/throughput trade.** Every insert is first written to the Write-Ahead Log
for durability. Two knobs govern the cost, both documentation-confirmed:

- **`synchronous_commit`.** Default `on` makes each commit wait for WAL flush to disk. Setting it
  `off` removes the wait; per the docs this risks losing recent committed transactions (maximum
  delay three times `wal_writer_delay`) but "does not create any risk of database inconsistency"
  [PG-wal-conf]. For a *threat log*, this trade is appropriate: losing the last few hundred
  milliseconds of log rows under a crash is acceptable (the queue's at-least-once retry recovers
  most), and there is no cross-row invariant to violate. We set `synchronous_commit = off` for the
  log database (not for any transactional tenant data).
- **Group commit.** `commit_delay` (default 0) "adds a time delay before a WAL flush … allowing a
  larger number of transactions to commit via a single WAL flush," active when at least
  `commit_siblings` (default 5) transactions are concurrent [PG-wal-conf]. With batched inserts from
  the consumer this further amortizes flush cost.
- **Checkpoints.** Checkpoints occur every `checkpoint_timeout` (default 5 min) or when
  `max_wal_size` (default 1 GB) is about to be exceeded [PG-wal-config]. Under sustained insert load
  we raise `max_wal_size` and keep `checkpoint_completion_target` at its default 0.9 (the
  recommended maximum) to spread checkpoint I/O and avoid write stalls [PG-wal-config]. With
  `full_page_writes` on (torn-page protection), frequent checkpoints inflate WAL volume, so fewer,
  wider-spaced checkpoints favor insert throughput.

**The GIN index-bloat problem and its mitigation.** To keep payloads queryable (R4) we index the
`jsonb` column with GIN. But GIN updates are "inherently slow … inserting or updating one heap row
can cause many inserts into the index (one for each key extracted from the indexed item)"
[PG-gin] — exactly the pathology that would throttle high-velocity ingestion. PostgreSQL's
`fastupdate` mechanism defers this: new entries go "into a temporary, unsorted list of pending
entries," flushed to the main GIN structure on vacuum/autoanalyze, on `gin_clean_pending_list()`,
or when the list exceeds `gin_pending_list_limit` [PG-gin]. We therefore (i) enable `fastupdate`
and size `gin_pending_list_limit` so pending-list flushes coincide with batch boundaries, turning
per-row index maintenance into periodic bulk maintenance; and (ii) index only the `jsonb`
sub-paths actually queried (e.g., a `jsonb_path_ops` GIN on the signature/verdict keys) rather than
the whole document, reducing extracted-key fan-out. *(The `jsonb_path_ops` vs `jsonb_ops`
operator-class trade is in scope but was not primary-verified; see evidence status.)*

## VI-E. Native Declarative Partitioning for Scale and Retention

A monotonically growing log table degrades: index size grows, autovacuum lengthens, and
time-window queries scan irrelevant history. PostgreSQL's **native declarative partitioning**
(built in since PG 10, distinct from and more performant than legacy inheritance/`UNION ALL`
[PG-partition]) addresses all three. We declare `PARTITION BY RANGE (created_at)` with one
partition per day (or week), bounds "inclusive at the lower end and exclusive at the upper end"
[PG-partition]:

- **Ingestion locality.** Inserts route automatically to the current partition [PG-partition]; its
  indexes stay small and cache-resident, so index maintenance cost is bounded by *today's* volume,
  not all history — directly countering the bloat of §VI-D at the table level.
- **Query pruning.** Investigations are time-scoped ("attacks in the last 24 h"); partition pruning
  restricts the scan to the relevant partitions.
- **O(1) retention.** Aging out old logs uses `DETACH PARTITION`/`DROP TABLE`, which the docs note
  is "far faster than a bulk operation" and "entirely avoid[s] the VACUUM overhead caused by a bulk
  DELETE" [PG-partition]. Retention rollover (§VI-F) becomes a metadata operation, not a
  billion-row delete.
- **Constraint.** Any primary/unique key on a partitioned table "must include all of the partition
  key columns" [PG-partition]; our idempotency key is therefore `(created_at, event_id)`, which both
  satisfies the constraint and aligns dedup with the partition.

## VI-F. Compliance Guardrails: PCI-DSS, SOC 2, and Data Minimization

An immutable attack-log serves compliance, but a naïvely-implemented one *becomes* a breach: an
attack payload aimed at a payment gateway may itself contain a Primary Account Number (PAN) or PII.
The design must satisfy the audit-trail mandate **and** the data-minimization mandate at once.

**Audit-trail mapping.** PCI-DSS v4.0.1 **Requirement 10** ("Log and monitor all access to system
components and cardholder data") governs the audit trail; sub-requirement **10.5.1** mandates
retaining audit-log history for **at least 12 months**, with the **most recent 3 months
immediately available** for analysis ("hot" storage) [PCI-DSS]. SOC 2 maps to the AICPA Trust
Services Criteria Common Criteria family **CC7**: **CC7.2** (monitor system components to detect
anomalies and security events) and **CC7.3** (evaluate security events and trigger incident
response), CC7.1 (vulnerability detection), and CC7.4 (incident response) [AICPA-TSC]. An immutable,
asynchronously-written PostgreSQL audit trail supplies exactly the *detection and record* evidence
these criteria require; unlike PCI-DSS, SOC 2 fixes no statutory retention period (it is
auditor/period-defined). **Immutability** is enforced architecturally, satisfying PCI-DSS **10.3.2**
(audit logs protected from modification) and **10.3.1** (read access limited to a job-related need):
the log role has `INSERT` and `SELECT` privileges only — no `UPDATE`/`DELETE` — so records are
append-only; the *sole* deletion path is time-based partition `DROP` (§VI-E), executed by a separate
retention role on a fixed schedule, which is precisely the controlled, policy-driven expiry the
retention clause expects rather than ad hoc row deletion. What to log is governed by **10.2** (logs
sufficient to support anomaly detection and forensics); the firewall records every interception
decision to that end.

**Data minimization (the critical guardrail).** We never persist raw sensitive data. Before the
edge enqueues an event (§VI-B), a bounded redaction pass (an extension of the §V-E sanitization,
$O(n)$) masks high-confidence sensitive tokens: PAN candidates (Luhn-valid digit runs) are replaced
by a truncated token (first-6/last-4 with the middle masked — exactly the maximum display exposure
PCI-DSS **3.4.1** permits, BIN + last four — or a keyed hash rendering the value unreadable per
**3.5.1**, which lists one-way hashing, truncation, index tokens, or strong cryptography), and
recognizable PII patterns are masked. Sensitive authentication data (full track, CVV, PIN) is never
retained at all, per **3.3**. What the log stores is therefore the **attack metadata** —
which signatures fired (§V-B), the feature scores (§V-C), the verdict, tenant id, timestamps — and a
**redacted** payload sufficient for forensic pattern analysis but stripped of cardholder data. This
reconciles "log the attack" with "store no CHD": the forensic value of an injection payload lies in
its *instruction structure*, which survives redaction, not in any incidental PAN it carries, which
does not need to. Redaction at the *edge* (before the queue) ensures raw CHD never even reaches the
logging tier, minimizing the systems in PCI scope.

> **Evidence status for §VI-F:** the control references — PCI-DSS v4.0.1 **10.5.1** ("Retain audit
> log history for at least 12 months, with at least the most recent three months immediately
> available for analysis," verbatim standard text), **10.3.1/10.3.2** (log protection), **10.2**
> (logging scope), **3.3** (no SAD after authorization), **3.4.1** (PAN display max BIN + last 4),
> **3.5.1** (stored PAN rendered unreadable); and AICPA TSC **CC7.1–CC7.4** — are all CONFIRMED
> against the primary PCI SSC v4.0.1 standard and the AICPA 2017 TSC (2022 revised) in a dedicated
> verification pass. §VI-F is now on the same primary-sourced footing as the rest of §VI.

---

### Citation keys (PostgreSQL claims: all CONFIRMED 3-0, verified-facts Part 4)
- **[PG-json]** PostgreSQL Global Dev. Group, "JSON Types," postgresql.org/docs/current/datatype-json.html.
- **[PG-toast]** "Database Physical Storage — TOAST," postgresql.org/docs/current/storage-toast.html.
- **[PG-wal-conf]** "Write Ahead Log — runtime config," postgresql.org/docs/current/runtime-config-wal.html.
- **[PG-wal-config]** "WAL Configuration," postgresql.org/docs/current/wal-configuration.html.
- **[PG-gin]** "GIN Indexes," postgresql.org/docs/current/gin.html.
- **[PG-partition]** "Table Partitioning," postgresql.org/docs/current/ddl-partitioning.html.
- **[PCI-DSS]** PCI Security Standards Council, "Payment Card Industry Data Security Standard v4.0.1," June 2024. Req 10.2 (logging), 10.3.1/10.3.2 (log protection), 10.5.1 (12-month retention / 3-month hot); Req 3.3 (no SAD), 3.4.1 (PAN display masking), 3.5.1 (PAN rendered unreadable).
- **[AICPA-TSC]** AICPA, "Trust Services Criteria for Security, Availability, Processing Integrity, Confidentiality, and Privacy" (2017, rev. 2022), Common Criteria CC7.1–CC7.4.

> Evidence status: §VI-C/D/E PostgreSQL internals — TOAST thresholds and strategies, JSONB-vs-JSON,
> `synchronous_commit`/`commit_delay`/checkpoint/`full_page_writes` behavior, GIN `fastupdate`/
> `gin_pending_list_limit`, and native RANGE partitioning with DETACH/DROP retention — are all
> CONFIRMED at high confidence (verified-facts Part 4, 25/25 claims 3-0, official docs). `waitUntil`
> semantics (§VI-B) follow the Workers execution model of §III (CONFIRMED). §VI-F compliance clauses
> (PCI Req 10.2/10.3.1/10.3.2/10.5.1, 3.3/3.4.1/3.5.1; SOC 2 CC7.1–CC7.4) are CONFIRMED against the
> primary PCI SSC v4.0.1 standard and AICPA 2017 TSC. The `jsonb_path_ops` choice (§VI-D) is noted as
> not-yet-verified.
