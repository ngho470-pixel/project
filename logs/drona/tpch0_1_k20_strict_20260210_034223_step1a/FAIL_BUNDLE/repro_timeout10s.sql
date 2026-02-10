\set ON_ERROR_STOP on
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='10s';

-- OURS
LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SET custom_filter.policy_path='/tmp/z3_lab/policy.txt';
SET client_min_messages = notice;
SELECT COUNT(*) FROM (select s_name, s_address from supplier, nation where s_suppkey in ( select ps_suppkey from partsupp where ps_partkey in ( select p_partkey from part where p_name like 'midnight%' ) and ps_availqty > ( select 0.5 * sum(l_quantity) from lineitem where l_partkey = ps_partkey and l_suppkey = ps_suppkey and l_shipdate >= date '1995-01-01' and l_shipdate < date '1995-01-01' + interval '1' year ) ) and s_nationkey = n_nationkey and n_name = 'BRAZIL' order by s_name) AS __q \gset ours_

-- RLS (as rls_user via SET ROLE, no password needed)
SET custom_filter.enabled=off;
RESET enable_indexscan;
RESET enable_bitmapscan;
SET client_min_messages = warning;
SET ROLE rls_user;
SELECT COUNT(*) FROM (select s_name, s_address from supplier, nation where s_suppkey in ( select ps_suppkey from partsupp where ps_partkey in ( select p_partkey from part where p_name like 'midnight%' ) and ps_availqty > ( select 0.5 * sum(l_quantity) from lineitem where l_partkey = ps_partkey and l_suppkey = ps_suppkey and l_shipdate >= date '1995-01-01' and l_shipdate < date '1995-01-01' + interval '1' year ) ) and s_nationkey = n_nationkey and n_name = 'BRAZIL' order by s_name) AS __q \gset rls_
RESET ROLE;

\echo ours=:ours_count rls=:rls_count
SELECT CASE WHEN :ours_count::bigint = :rls_count::bigint THEN 1 ELSE (SELECT 1/0) END AS __assert_ok;
\echo OK
