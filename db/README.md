# Database Component — Threat Log (paper Section VI)

Partitioned JSONB threat-log store, its tuning, and the queue consumer that writes
to it off the request path.

```
db/
├── migrations/
│   ├── 001_initial_schema.sql        # partitioned table, GIN, immutability roles
│   └── 002_partition_management.sql  # daily roll-forward + O(1) retention (DROP)
├── postgresql.conf.tuning            # high-velocity JSONB insert tuning
└── consumer/                         # Cloudflare Queue consumer (postgres.js)
```

## Apply the migrations

```bash
# Against any reachable PostgreSQL 14+ (declarative partitioning needs 10+,
# unique-key-on-partition needs 11+; tested target is 15/17).
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_initial_schema.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_partition_management.sql

# Apply the tuning (append to the server's postgresql.conf, then reload):
cat postgresql.conf.tuning >> "$PGDATA/postgresql.conf" && psql "$DATABASE_URL" -c "SELECT pg_reload_conf();"
```

## Validate in a throwaway container (recommended)

The migrations were authored against primary PostgreSQL docs (see
`paper/refs/verified-facts.md` Part 4) but **could not be executed in the
authoring environment** (Docker daemon down + a macOS SysV `shmall` limit blocked
a local cluster). Validate them yourself in one command:

```bash
docker run --rm -d --name mldef-pg -e POSTGRES_PASSWORD=test -e POSTGRES_DB=threatlog -p 55432:5432 postgres:17
sleep 4
export DATABASE_URL="postgres://postgres:test@localhost:55432/threatlog"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_initial_schema.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_partition_management.sql

# Smoke test: insert routes to a daily partition; UPDATE/DELETE denied to writer.
psql "$DATABASE_URL" <<'SQL'
INSERT INTO threat_log (event_id, tenant_id, created_at, decision, auth_result,
  score, entropy, blocking_signatures, features, redacted_payload)
VALUES ('n1','tenant-a', now(), 'reject','ok', 1.2, 4.1,
  '["override.ignore_previous"]'::jsonb, '{"override.ignore_previous":1}'::jsonb,
  'ignore previous instructions ...');
-- confirm it landed in today's child partition:
SELECT tableoid::regclass AS partition, tenant_id, decision FROM threat_log;
-- confirm containment query uses the GIN index:
EXPLAIN (COSTS OFF) SELECT 1 FROM threat_log WHERE features @> '{"override.ignore_previous":1}';
-- confirm idempotency (second insert of same key is a no-op):
INSERT INTO threat_log (event_id, tenant_id, created_at, decision, auth_result, score, entropy)
  VALUES ('n1','tenant-a',(SELECT created_at FROM threat_log LIMIT 1),'reject','ok',0,0)
  ON CONFLICT (created_at, event_id) DO NOTHING;
SQL

docker rm -f mldef-pg
```

Expected: the row appears under partition `threat_log_YYYYMMDD` (not the parent or
default), the `EXPLAIN` shows a `Bitmap Index Scan` on `threat_log_features_gin`,
and the duplicate insert changes nothing.

## Deploy the consumer

```bash
cd consumer
npm install
# Provision a Hyperdrive config pointing at the DB, put its id in wrangler.toml,
# then:
npm run deploy
```

The consumer role should be `firewall_writer` (INSERT-only). Never grant it
UPDATE/DELETE — immutability is enforced by privilege (PCI-DSS 10.3.2).
