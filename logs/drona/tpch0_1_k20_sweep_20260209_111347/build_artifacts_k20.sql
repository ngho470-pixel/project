\set ON_ERROR_STOP on
\timing on
SET client_min_messages = WARNING;
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET statement_timeout='30min';

LOAD '/tmp/z3_lab/artifact_builder.so';
CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);
DROP FUNCTION IF EXISTS public.build_base(text);
CREATE FUNCTION public.build_base(text) RETURNS void AS '/tmp/z3_lab/artifact_builder.so', 'build_base' LANGUAGE C STRICT;
TRUNCATE public.files;
SELECT public.build_base('/tmp/z3_lab/policy.txt');
SELECT COUNT(*) AS artifacts, COALESCE(SUM(octet_length(file)),0) AS bytes FROM public.files;
