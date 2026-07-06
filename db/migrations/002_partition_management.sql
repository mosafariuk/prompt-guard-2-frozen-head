-- ============================================================================
-- 002_partition_management.sql
-- Daily partition roll-forward + O(1) retention (paper Section VI-E).
--
-- Retention policy = PCI-DSS 10.5.1: keep >= 12 months; the most recent 3 months
-- are the "immediately available" hot window. We DROP partitions older than the
-- retention horizon, which "entirely avoids the VACUUM overhead caused by a bulk
-- DELETE" (ddl-partitioning.html) and is O(1) in the row count.
--
-- In production, pg_partman or pg_cron would schedule these; the functions below
-- are dependency-free so the mechanism is auditable and portable.
-- ============================================================================

-- Create the daily partition covering [day, day+1) if it does not exist.
-- Bounds are inclusive-lower / exclusive-upper (ddl-partitioning.html).
CREATE OR REPLACE FUNCTION ensure_threat_log_partition(target date)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    part_name text := format('threat_log_%s', to_char(target, 'YYYYMMDD'));
    start_ts  text := to_char(target, 'YYYY-MM-DD');
    end_ts    text := to_char(target + 1, 'YYYY-MM-DD');
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_class WHERE relname = part_name) THEN
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF threat_log FOR VALUES FROM (%L) TO (%L)',
            part_name, start_ts, end_ts
        );
    END IF;
END;
$$;

-- Pre-create partitions for today .. today+ahead_days so inserts always land in a
-- concrete partition (the DEFAULT partition in 001 is only a safety net).
CREATE OR REPLACE FUNCTION provision_threat_log_partitions(ahead_days int DEFAULT 7)
RETURNS void
LANGUAGE plpgsql
AS $$
DECLARE
    d int;
BEGIN
    FOR d IN 0..ahead_days LOOP
        PERFORM ensure_threat_log_partition((current_date + d));
    END LOOP;
END;
$$;

-- Drop partitions whose entire range is older than `retain_days`. Runs as the
-- table owner (or wrap SECURITY DEFINER and grant EXECUTE to firewall_retention).
-- Default 400 days > the 12-month PCI-DSS 10.5.1 minimum.
CREATE OR REPLACE FUNCTION drop_expired_threat_log_partitions(retain_days int DEFAULT 400)
RETURNS TABLE(dropped text)
LANGUAGE plpgsql
AS $$
DECLARE
    horizon date := current_date - retain_days;
    part record;
BEGIN
    FOR part IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'threat_log'
          AND c.relname ~ '^threat_log_[0-9]{8}$'
          AND to_date(right(c.relname, 8), 'YYYYMMDD') < horizon
    LOOP
        EXECUTE format('DROP TABLE %I', part.relname);
        dropped := part.relname;
        RETURN NEXT;
    END LOOP;
END;
$$;

-- Suggested schedule (pg_cron):
--   SELECT cron.schedule('provision', '0 12 * * *',
--                        $$SELECT provision_threat_log_partitions(7)$$);
--   SELECT cron.schedule('retention', '30 3 * * *',
--                        $$SELECT drop_expired_threat_log_partitions(400)$$);

-- Bootstrap: create the initial window now.
SELECT provision_threat_log_partitions(7);
