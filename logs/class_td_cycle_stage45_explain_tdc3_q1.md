# TDC3 q1 EXPLAIN (ANALYZE, BUFFERS)

## Ours
```
Sort  (cost=397592.31..397592.32 rows=6 width=236) (never executed)
  Output: l_returnflag, l_linestatus, (sum(l_quantity)), (sum(l_extendedprice)), (sum((l_extendedprice * ('1'::numeric - l_discount)))), (sum(((l_extendedprice * ('1'::numeric - l_discount)) * ('1'::numeric + l_tax)))), (avg(l_quantity)), (avg(l_extendedprice)), (avg(l_discount)), (count(*))
  Sort Key: lineitem.l_returnflag, lineitem.l_linestatus
  ->  HashAggregate  (cost=397592.06..397592.23 rows=6 width=236) (never executed)
        Output: l_returnflag, l_linestatus, sum(l_quantity), sum(l_extendedprice), sum((l_extendedprice * ('1'::numeric - l_discount))), sum(((l_extendedprice * ('1'::numeric - l_discount)) * ('1'::numeric + l_tax))), avg(l_quantity), avg(l_extendedprice), avg(l_discount), count(*)
        Group Key: lineitem.l_returnflag, lineitem.l_linestatus
        ->  Custom Scan (custom_filter) on public.lineitem  (cost=0.00..187570.19 rows=6000625 width=25) (never executed)
              Output: l_returnflag, l_linestatus, l_quantity, l_extendedprice, l_discount, l_tax
              custom_filter: 
              ->  Seq Scan on public.lineitem  (cost=0.00..187570.19 rows=6000625 width=25) (never executed)
                    Output: l_returnflag, l_linestatus, l_quantity, l_extendedprice, l_discount, l_tax
                    Filter: (lineitem.l_shipdate <= '1998-11-30 00:00:00'::timestamp without time zone)
Planning:
  Buffers: shared hit=82 read=31 written=31
Planning Time: 0.837 ms
JIT:
  Functions: 10
  Options: Inlining false, Optimization false, Expressions true, Deforming true
  Timing: Generation 0.827 ms, Inlining 0.000 ms, Optimization 0.000 ms, Emission 0.000 ms, Total 0.827 ms
Execution Time: 3735.863 ms
```

## RLS+Index
```
GroupAggregate  (cost=151763911.85..151820173.41 rows=6 width=236) (actual time=3754.975..3754.977 rows=0 loops=1)
  Output: lineitem.l_returnflag, lineitem.l_linestatus, sum(lineitem.l_quantity), sum(lineitem.l_extendedprice), sum((lineitem.l_extendedprice * ('1'::numeric - lineitem.l_discount))), sum(((lineitem.l_extendedprice * ('1'::numeric - lineitem.l_discount)) * ('1'::numeric + lineitem.l_tax))), avg(lineitem.l_quantity), avg(lineitem.l_extendedprice), avg(lineitem.l_discount), count(*)
  Group Key: lineitem.l_returnflag, lineitem.l_linestatus
  Buffers: shared hit=33106 read=112526
  ->  Sort  (cost=151763911.85..151767662.61 rows=1500304 width=25) (actual time=3754.973..3754.975 rows=0 loops=1)
        Output: lineitem.l_returnflag, lineitem.l_linestatus, lineitem.l_quantity, lineitem.l_extendedprice, lineitem.l_discount, lineitem.l_tax
        Sort Key: lineitem.l_returnflag, lineitem.l_linestatus
        Sort Method: quicksort  Memory: 25kB
        Buffers: shared hit=33106 read=112526
        ->  Seq Scan on public.lineitem  (cost=0.00..151538212.49 rows=1500304 width=25) (actual time=3754.949..3754.951 rows=0 loops=1)
              Output: lineitem.l_returnflag, lineitem.l_linestatus, lineitem.l_quantity, lineitem.l_extendedprice, lineitem.l_discount, lineitem.l_tax
              Filter: ((SubPlan 1) AND (lineitem.l_shipdate <= '1998-11-30 00:00:00'::timestamp without time zone))
              Rows Removed by Filter: 6001215
              Buffers: shared hit=33103 read=112526
              SubPlan 1
                ->  Result  (cost=1.13..25.22 rows=1 width=0) (actual time=0.000..0.000 rows=0 loops=6001215)
                      One-Time Filter: (lineitem.l_quantity > '10'::numeric)
                      Buffers: shared hit=33007 read=67
                      ->  Nested Loop  (cost=1.13..25.22 rows=1 width=0) (actual time=0.000..0.000 rows=0 loops=4802275)
                            Join Filter: (customer.c_nationkey = supplier.s_nationkey)
                            Rows Removed by Join Filter: 0
                            Buffers: shared hit=33007 read=67
                            ->  Nested Loop  (cost=0.85..16.90 rows=1 width=4) (actual time=0.000..0.000 rows=0 loops=4802275)
                                  Output: customer.c_nationkey
                                  Buffers: shared hit=32933 read=63
                                  ->  Index Scan using cf_rls_k4501_orders_o_orderkey_7 on public.orders  (cost=0.43..8.45 rows=1 width=4) (actual time=0.000..0.000 rows=0 loops=4802275)
                                        Output: orders.o_orderkey, orders.o_custkey, orders.o_orderstatus, orders.o_totalprice, orders.o_orderdate, orders.o_orderpriority, orders.o_clerk, orders.o_shippriority, orders.o_comment
                                        Index Cond: ((orders.o_orderkey <= lineitem.l_orderkey) AND (orders.o_orderkey <= 10000) AND (orders.o_orderkey = lineitem.l_orderkey))
                                        Buffers: shared hit=31782 read=50
                                  ->  Index Scan using cf_rls_k4501_customer_c_custkey_1 on public.customer  (cost=0.42..8.44 rows=1 width=8) (actual time=0.000..0.000 rows=0 loops=7958)
                                        Output: customer.c_custkey, customer.c_name, customer.c_address, customer.c_nationkey, customer.c_phone, customer.c_acctbal, customer.c_mktsegment, customer.c_comment
                                        Index Cond: ((customer.c_custkey = orders.o_custkey) AND (customer.c_custkey <= 5000))
                                        Buffers: shared hit=1151 read=13
                            ->  Index Scan using cf_rls_k4501_supplier_s_suppkey_9 on public.supplier  (cost=0.29..8.30 rows=1 width=4) (actual time=0.000..0.000 rows=0 loops=291)
                                  Output: supplier.s_suppkey, supplier.s_name, supplier.s_address, supplier.s_nationkey, supplier.s_phone, supplier.s_acctbal, supplier.s_comment
                                  Index Cond: ((supplier.s_suppkey <= 1000) AND (supplier.s_suppkey = lineitem.l_suppkey))
                                  Buffers: shared hit=74 read=4
Planning:
  Buffers: shared hit=363 read=32
Planning Time: 1.348 ms
JIT:
  Functions: 32
  Options: Inlining true, Optimization true, Expressions true, Deforming true
  Timing: Generation 1.440 ms, Inlining 64.869 ms, Optimization 109.863 ms, Emission 86.365 ms, Total 262.536 ms
Execution Time: 3771.380 ms
```
