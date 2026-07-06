-- ============================================================================
-- 001_initial_schema.sql
-- Threat-log schema for the Edge LLM Firewall (paper Section VI).
--
-- Design decisions, each traceable to a PRIMARY-SOURCED PostgreSQL fact
-- (verified-facts Part 4) or a compliance clause (Part 6):
--   * JSONB (not JSON) for unstructured attack payloads: decomposed binary,
--     faster to process, INDEXABLE (datatype-json.html).
--   * Native DECLARATIVE RANGE partitioning by day on created_at: ingestion
--     locality, partition pruning, and O(1) retention via DROP/DETACH
--     (ddl-partitioning.html). NOT inheritance-based.
--   * PK includes the partition key (created_at) as required for a unique
--     constraint on a partitioned table (ddl-partitioning.html); the pair
--     (created_at, event_id) is also the idempotency key for at-least-once
--     queue delivery (Section VI-B).
--   * GIN index with fastupdate to bound high-velocity insert cost (gin.html).
--   * Append-only immutability via role privileges => PCI-DSS 10.3.1/10.3.2.
-- ============================================================================

-- Enumerated decision/verdict types keep the hot columns narrow and typed while
-- the variable-shape data lives in JSONB.
CREATE TYPE firewall_decision AS ENUM ('forward', 'reject', 'escalate');
CREATE TYPE firewall_auth_result AS ENUM (
  'ok', 'bad_signature', 'replay', 'stale', 'unknown_tenant'
);

-- ----------------------------------------------------------------------------
-- Parent partitioned table. No rows live here directly; every row is routed to
-- a daily child partition by created_at (ddl-partitioning.html auto-routing).
-- ----------------------------------------------------------------------------
CREATE TABLE threat_log (
    event_id            text                 NOT NULL,   -- = nonce (Section IV/VI-B)
    tenant_id           text                 NOT NULL,
    created_at          timestamptz          NOT NULL,   -- RANGE partition key
    decision            firewall_decision    NOT NULL,
    auth_result         firewall_auth_result NOT NULL,
    score               real                 NOT NULL DEFAULT 0,
    entropy             real                 NOT NULL DEFAULT 0,
    -- Variable-shape, queryable data as JSONB. TOAST auto-compresses/relocates
    -- any value wider than ~2 kB out-of-line, keeping heap tuples narrow
    -- (storage-toast.html), so large obfuscated payloads do not bloat the heap.
    blocking_signatures jsonb                NOT NULL DEFAULT '[]'::jsonb,
    features            jsonb                NOT NULL DEFAULT '{}'::jsonb,
    -- REDACTED payload only (Section VI-F): PAN masked to BIN+last4 (PCI 3.4.1),
    -- PII stripped, at the EDGE before enqueue. Raw CHD never reaches this table.
    redacted_payload    text,
    source_ip           inet,
    user_agent          text,
    -- PK must include the partition key (created_at). Doubles as the dedup key.
    PRIMARY KEY (created_at, event_id)
) PARTITION BY RANGE (created_at);

-- OPTIONAL second level (commented): at extreme write rates, sub-partition each
-- daily partition by HASH(tenant_id) to spread a hot day across buffers/spindles.
-- Retention still operates by dropping the daily parent, which cascades to subs.
--   ... PARTITION BY RANGE (created_at)   -- then each day: PARTITION BY HASH (tenant_id)
-- Default: single-level daily RANGE (retention stays a trivial DROP).

-- ----------------------------------------------------------------------------
-- Indexes (created on the PARENT => propagated to every partition).
-- ----------------------------------------------------------------------------
-- Tenant-scoped forensic queries. Partition pruning already restricts by time.
CREATE INDEX threat_log_tenant_idx ON threat_log (tenant_id, created_at DESC);

-- Filter to actionable rows (rejects/escalations) fast.
CREATE INDEX threat_log_decision_idx ON threat_log (decision, created_at DESC);

-- GIN over the JSONB feature document for containment/path queries (@>, ?).
-- jsonb_path_ops is smaller and faster for the @> containment queries we run
-- (index only the keys we actually query). fastupdate=on defers per-row index
-- maintenance into the pending list, flushed at gin_pending_list_limit or on
-- (auto)vacuum (gin.html) -> bounds the per-insert index cost under attack bursts.
CREATE INDEX threat_log_features_gin ON threat_log
    USING gin (features jsonb_path_ops)
    WITH (fastupdate = on, gin_pending_list_limit = 8192);

-- ----------------------------------------------------------------------------
-- A default partition catches rows whose day-partition has not yet been created,
-- so an insert never fails on a missing partition (belt-and-suspenders with the
-- partition-management job in 002).
-- ----------------------------------------------------------------------------
CREATE TABLE threat_log_default PARTITION OF threat_log DEFAULT;

-- ----------------------------------------------------------------------------
-- Immutability via least privilege (PCI-DSS 10.3.1 / 10.3.2).
-- ----------------------------------------------------------------------------
-- Writer: the queue consumer. INSERT only — cannot UPDATE or DELETE.
CREATE ROLE firewall_writer NOLOGIN;
GRANT INSERT ON threat_log TO firewall_writer;

-- Reader: analysts/SIEM. SELECT only.
CREATE ROLE firewall_reader NOLOGIN;
GRANT SELECT ON threat_log TO firewall_reader;

-- Retention: the ONLY role permitted to remove data, and only by dropping whole
-- expired partitions (policy-driven expiry, not ad hoc row deletion).
CREATE ROLE firewall_retention NOLOGIN;
-- (DROP TABLE on a partition requires ownership; the retention job runs as owner
--  or via a SECURITY DEFINER function; see 002_partition_management.sql.)

-- Explicitly ensure no UPDATE/DELETE is granted to the writer path.
REVOKE UPDATE, DELETE, TRUNCATE ON threat_log FROM firewall_writer, firewall_reader;
