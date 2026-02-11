\set ON_ERROR_STOP on
\timing on

SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='60s';

LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SET custom_filter.policy_path='/tmp/z3_lab/policies_enabled.txt';

-- Simple smoke query that must touch a policy-target table.
SELECT COUNT(*) AS n FROM lineitem;
