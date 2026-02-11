\set ON_ERROR_STOP on
SET client_min_messages=NOTICE;
SET statement_timeout='60s';
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;

LOAD '/tmp/z3_lab/artifact_builder.so';
CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);
DROP FUNCTION IF EXISTS public.build_base(text);
CREATE FUNCTION public.build_base(text) RETURNS void AS '/tmp/z3_lab/artifact_builder.so', 'build_base' LANGUAGE C STRICT;
TRUNCATE public.files;
SELECT public.build_base('/tmp/z3_lab/policies_enabled.txt');

LOAD '/tmp/z3_lab/custom_filter.so';
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SET custom_filter.debug_ids=off;
SET custom_filter.profile_rescan=off;
SET custom_filter.policy_path='/tmp/z3_lab/policies_enabled.txt';
