\set ON_ERROR_STOP on
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='30min';
LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SET custom_filter.policy_path='/tmp/z3_lab/policy.txt';
SET client_min_messages = warning;
EXPLAIN (VERBOSE, COSTS OFF) select sum(l_extendedprice * l_discount) as revenue from lineitem where l_shipdate >= date '1994-01-01' and l_shipdate < date '1994-01-01' + interval '1' year and l_discount between 0.04 - 0.01 and 0.04 + 0.01 and l_quantity < 24;
