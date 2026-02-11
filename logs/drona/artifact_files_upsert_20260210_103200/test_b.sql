\set ON_ERROR_STOP on
\timing on

SELECT
  count(*) AS nrows_before,
  count(distinct name) AS ndistinct_before,
  pg_total_relation_size('public.files') AS bytes_before,
  COALESCE(SUM(octet_length(file)), 0) AS payload_bytes_before
FROM public.files;

DO $$
DECLARE i int;
BEGIN
  FOR i IN 1..10 LOOP
    PERFORM public.build_base('/tmp/z3_lab/policies_enabled.txt');
  END LOOP;
END $$;

SELECT
  count(*) AS nrows_after,
  count(distinct name) AS ndistinct_after,
  pg_total_relation_size('public.files') AS bytes_after,
  COALESCE(SUM(octet_length(file)), 0) AS payload_bytes_after
FROM public.files;

VACUUM (ANALYZE) public.files;

SELECT
  count(*) AS nrows_after_vacuum,
  count(distinct name) AS ndistinct_after_vacuum,
  pg_total_relation_size('public.files') AS bytes_after_vacuum,
  COALESCE(SUM(octet_length(file)), 0) AS payload_bytes_after_vacuum
FROM public.files;

SELECT name, count(*) AS n
FROM public.files
GROUP BY name
HAVING count(*) > 1
ORDER BY name;
