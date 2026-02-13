\set ON_ERROR_STOP on
\pset pager off

SET search_path TO public, pg_catalog;

-- backend PID marker (used by shell sampler for VmHWM)
SELECT pg_backend_pid() AS pid \gset
\echo __BACKEND_PID__ :pid

-- record key knobs for comparability
\echo __PG_SETTINGS__
SHOW maintenance_work_mem;
SHOW max_parallel_maintenance_workers;
SHOW synchronous_commit;
\echo __END_PG_SETTINGS__

DROP TABLE IF EXISTS pg_temp.rls_idx_names;
CREATE TEMP TABLE pg_temp.rls_idx_names (
  idx_name text PRIMARY KEY
);

\i bench/rls_index_names.sql

\echo __DROP_INDEXES_BEGIN__
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT indexname
    FROM pg_indexes
    WHERE schemaname = 'public'
      AND indexname LIKE 'cf_rls_k%'
  LOOP
    EXECUTE format('DROP INDEX IF EXISTS public.%I', r.indexname);
  END LOOP;
END $$;
DROP INDEX IF EXISTS public.idx_orders_o_custkey;
DROP INDEX IF EXISTS public.idx_customer_c_custkey;
DROP INDEX IF EXISTS public.idx_lineitem_l_orderkey;
DROP INDEX IF EXISTS public.idx_customer_c_custkey_mktsegment;
\i bench/rls_indexes_drop.sql
\echo __DROP_INDEXES_END__

\echo __RLS_INDEX_BUILD_BEGIN__
SELECT clock_timestamp() AS t0 \gset
\i bench/rls_indexes.sql
SELECT clock_timestamp() AS t1 \gset
\echo __RLS_INDEX_BUILD_END__ :t0 :t1

\echo __RLS_INDEX_TOTAL_BYTES__
SELECT COALESCE(SUM(pg_relation_size(to_regclass(format('public.%s', idx_name)))), 0) AS bytes
FROM pg_temp.rls_idx_names;
\echo __END_RLS_INDEX_TOTAL_BYTES__
