\set ON_ERROR_STOP on
\pset pager off

-- Inputs expected from runner:
--   :K                  (integer, informational only)
--   :POLICY_PATH        (path to enabled policies file)
--   :ARTIFACT_BUILDER_SO (path to artifact_builder.so readable by backend)

SET search_path TO public, pg_catalog;

CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);

-- 1) Clean artifacts.
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT n.nspname, c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND (
        c.relname = 'files'
        OR c.relname LIKE '%\_code\_base' ESCAPE '\'
        OR c.relname LIKE '%\_ctid\_base' ESCAPE '\'
        OR c.relname LIKE '%\_artifact%' ESCAPE '\'
      )
  LOOP
    EXECUTE format('TRUNCATE TABLE %I.%I', r.nspname, r.relname);
  END LOOP;
END $$;

CHECKPOINT;

-- 2) Ensure artifact builder entrypoint and build artifacts.
LOAD :'ARTIFACT_BUILDER_SO';
DROP FUNCTION IF EXISTS public.build_base(text);
CREATE FUNCTION public.build_base(text) RETURNS void
AS :'ARTIFACT_BUILDER_SO', 'build_base'
LANGUAGE C STRICT;

SELECT public.build_base(:'POLICY_PATH');

CHECKPOINT;

-- 3) Report totals + per-table bytes + row counts.
DROP TABLE IF EXISTS pg_temp.artifact_relstats;
CREATE TEMP TABLE pg_temp.artifact_relstats (
  nspname text,
  relname text,
  bytes bigint,
  row_count bigint
);

DO $$
DECLARE
  r record;
  rc bigint;
BEGIN
  FOR r IN
    SELECT c.oid, n.nspname, c.relname
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'r'
      AND (
        c.relname = 'files'
        OR c.relname LIKE '%\_code\_base' ESCAPE '\'
        OR c.relname LIKE '%\_ctid\_base' ESCAPE '\'
        OR c.relname LIKE '%\_artifact%' ESCAPE '\'
      )
  LOOP
    EXECUTE format('SELECT count(*)::bigint FROM %I.%I', r.nspname, r.relname) INTO rc;
    INSERT INTO pg_temp.artifact_relstats(nspname, relname, bytes, row_count)
    VALUES (r.nspname, r.relname, pg_total_relation_size(r.oid), rc);
  END LOOP;
END $$;

\echo __ARTIFACT_TOTAL_BYTES__
SELECT COALESCE(SUM(bytes), 0) FROM pg_temp.artifact_relstats;

\echo __ARTIFACT_TOTAL_ROWS__
SELECT COALESCE(SUM(row_count), 0) FROM pg_temp.artifact_relstats;

\echo __ARTIFACT_TABLE_COUNT__
SELECT COUNT(*) FROM pg_temp.artifact_relstats;

\echo __ARTIFACT_TABLE_STATS__
SELECT nspname, relname, bytes, row_count
FROM pg_temp.artifact_relstats
ORDER BY bytes DESC, nspname, relname
LIMIT 100;
