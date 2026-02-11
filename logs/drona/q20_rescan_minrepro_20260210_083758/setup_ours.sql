\set ON_ERROR_STOP on
SET max_parallel_workers_per_gather=0;
SET statement_timeout='5min';
CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);
LOAD '/tmp/z3_lab/artifact_builder.so';
TRUNCATE public.files;
SELECT public.build_base('/tmp/z3_lab/policies_enabled_q20_rescan_20260211_080602.txt');
SELECT COALESCE(SUM(octet_length(file)),0) AS artifact_bytes FROM public.files;
