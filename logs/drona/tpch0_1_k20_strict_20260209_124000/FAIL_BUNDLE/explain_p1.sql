\set ON_ERROR_STOP on
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='30min';
LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SET custom_filter.policy_path='/tmp/z3_lab/policy_min_p1.txt';
SET client_min_messages = warning;
EXPLAIN (VERBOSE, COSTS OFF) select o_orderpriority, count(*) as order_count from orders where o_orderdate >= date '1996-04-01' and o_orderdate < date '1996-04-01' + interval '3' month and exists ( select * from lineitem where l_orderkey = o_orderkey and l_commitdate < l_receiptdate ) group by o_orderpriority order by o_orderpriority;
