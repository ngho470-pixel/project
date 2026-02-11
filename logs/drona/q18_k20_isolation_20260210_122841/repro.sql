\set ON_ERROR_STOP on
SET client_min_messages=NOTICE;
SET statement_timeout='60s';
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;

-- Build artifacts for K=20
CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);
DROP FUNCTION IF EXISTS public.build_base(text);
CREATE FUNCTION public.build_base(text) RETURNS void AS '/tmp/z3_lab/artifact_builder.so', 'build_base' LANGUAGE C STRICT;
TRUNCATE public.files;
SELECT public.build_base('/tmp/z3_lab/policies_enabled_k20_20260210_122841.txt');

-- Run OURS (custom_filter)
LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='trace';
SET custom_filter.profile_rescan=on;
SET custom_filter.policy_path='/tmp/z3_lab/policies_enabled_k20_20260210_122841.txt';

SELECT COUNT(*) AS cnt FROM (
select c_name, c_custkey, o_orderkey, o_orderdate, o_totalprice, sum(l_quantity) from customer, orders, lineitem where o_orderkey in ( select l_orderkey from lineitem group by l_orderkey having sum(l_quantity) > 314 ) and c_custkey = o_custkey and o_orderkey = l_orderkey group by c_name, c_custkey, o_orderkey, o_orderdate, o_totalprice order by o_totalprice desc, o_orderdate
) AS __q;
