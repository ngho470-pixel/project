\set ON_ERROR_STOP on
LOAD '/tmp/z3_lab/artifact_builder.so';
CREATE TABLE IF NOT EXISTS public.files (name varchar, file bytea);
TRUNCATE public.files;
SELECT public.build_base('/tmp/z3_lab/policy_min_p1.txt');
