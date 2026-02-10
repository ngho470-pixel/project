SET ROLE postgres;
SET max_parallel_workers_per_gather = 0;
SELECT COUNT(*)
FROM orders o
WHERE EXISTS (
  SELECT 1
  FROM customer c
  WHERE c.c_custkey = o.o_custkey
    AND (c.c_acctbal > 0)
    AND ((c.c_mktsegment = 'FURNITURE') OR (c.c_mktsegment = 'HOUSEHOLD'))
    AND (c.c_nationkey < 10)
    AND (c.c_mktsegment = 'AUTOMOBILE' OR c.c_mktsegment = 'HOUSEHOLD')
);
