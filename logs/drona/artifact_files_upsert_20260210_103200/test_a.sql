\set ON_ERROR_STOP on
\timing on

CREATE TABLE IF NOT EXISTS public.files (name text, file bytea);
DROP INDEX IF EXISTS public.files_name_uidx;

DELETE FROM public.files WHERE name IN ('x','y','z');
INSERT INTO public.files(name,file) VALUES ('x', '\x01'::bytea), ('x','\x02'::bytea), ('y','\x03'::bytea);

SELECT name, count(*) AS n
FROM public.files
WHERE name IN ('x','y')
GROUP BY name
ORDER BY name;

LOAD '/tmp/z3_lab/artifact_builder.so';
CREATE OR REPLACE FUNCTION public.build_base(text) RETURNS void
AS '/tmp/z3_lab/artifact_builder.so', 'build_base' LANGUAGE C STRICT;

SELECT public.build_base('/tmp/z3_lab/policies_enabled.txt');

SELECT name, count(*) AS n
FROM public.files
GROUP BY name
HAVING count(*) > 1
ORDER BY name;

SELECT indexname, indexdef
FROM pg_indexes
WHERE schemaname='public' AND tablename='files'
ORDER BY indexname;

INSERT INTO public.files(name,file) VALUES ('z','\x01'::bytea)
ON CONFLICT(name) DO UPDATE SET file=EXCLUDED.file;
INSERT INTO public.files(name,file) VALUES ('z','\xFF'::bytea)
ON CONFLICT(name) DO UPDATE SET file=EXCLUDED.file;
SELECT octet_length(file) AS nbytes, encode(file,'hex') AS hex
FROM public.files
WHERE name='z';
