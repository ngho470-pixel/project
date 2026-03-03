# Q21 RLS+Index Explain

- elapsed_ms: 1651.765
- error: -

```sql
Sort  (cost=535334.06..535334.06 rows=1 width=34) (actual time=1615.118..1631.382 rows=438 loops=1)
  Output: supplier.s_name, (count(*))
  Sort Key: (count(*)) DESC, supplier.s_name
  Sort Method: quicksort  Memory: 52kB
  Buffers: shared hit=2637 read=361951, temp read=10035 written=10240
  ->  GroupAggregate  (cost=535334.03..535334.05 rows=1 width=34) (actual time=1613.867..1630.643 rows=438 loops=1)
        Output: supplier.s_name, count(*)
        Group Key: supplier.s_name
        Buffers: shared hit=2631 read=361951, temp read=10035 written=10240
        ->  Sort  (cost=535334.03..535334.03 rows=1 width=26) (actual time=1613.845..1630.242 rows=4210 loops=1)
              Output: supplier.s_name
              Sort Key: supplier.s_name
              Sort Method: quicksort  Memory: 357kB
              Buffers: shared hit=2631 read=361951, temp read=10035 written=10240
              ->  Gather  (cost=370853.64..535334.02 rows=1 width=26) (actual time=1558.330..1622.244 rows=4210 loops=1)
                    Output: supplier.s_name
                    Workers Planned: 2
                    Workers Launched: 2
                    Buffers: shared hit=2631 read=361951, temp read=10035 written=10240
                    ->  Parallel Hash Semi Join  (cost=369853.64..534333.92 rows=1 width=26) (actual time=1543.563..1592.474 rows=1403 loops=3)
                          Output: supplier.s_name
                          Hash Cond: (orders.o_orderkey = l2.l_orderkey)
                          Join Filter: (l2.l_suppkey <> l1.l_suppkey)
                          Rows Removed by Join Filter: 1510
                          Buffers: shared hit=2631 read=361951, temp read=10035 written=10240
                          Worker 0:  actual time=1538.373..1585.399 rows=1337 loops=1
                            JIT:
                              Functions: 58
                              Options: Inlining true, Optimization true, Expressions true, Deforming true
                              Timing: Generation 1.891 ms, Inlining 55.616 ms, Optimization 205.350 ms, Emission 135.713 ms, Total 398.571 ms
                            Buffers: shared hit=881 read=120911, temp read=3378 written=3392
                          Worker 1:  actual time=1534.435..1587.076 rows=1620 loops=1
                            JIT:
                              Functions: 58
                              Options: Inlining true, Optimization true, Expressions true, Deforming true
                              Timing: Generation 1.889 ms, Inlining 55.452 ms, Optimization 205.873 ms, Emission 136.861 ms, Total 400.075 ms
                            Buffers: shared hit=896 read=121258, temp read=3334 written=3524
                          ->  Parallel Hash Right Anti Join  (cost=194337.90..352755.17 rows=1 width=38) (actual time=737.495..738.721 rows=2375 loops=3)
                                Output: supplier.s_name, l1.l_suppkey, l1.l_orderkey, orders.o_orderkey
                                Hash Cond: (l3.l_orderkey = l1.l_orderkey)
                                Join Filter: (l3.l_suppkey <> l1.l_suppkey)
                                Rows Removed by Join Filter: 26641
                                Buffers: shared hit=1994 read=249913
                                Worker 0:  actual time=737.487..737.496 rows=0 loops=1
                                  Buffers: shared hit=650 read=83247
                                Worker 1:  actual time=737.501..740.770 rows=7126 loops=1
                                  Buffers: shared hit=680 read=83605
                                ->  Parallel Seq Scan on public.lineitem l3  (cost=0.00..156313.86 rows=517124 width=8) (actual time=0.017..255.325 rows=620885 loops=3)
                                      Output: l3.l_orderkey, l3.l_partkey, l3.l_suppkey, l3.l_linenumber, l3.l_quantity, l3.l_extendedprice, l3.l_discount, l3.l_tax, l3.l_returnflag, l3.l_linestatus, l3.l_shipdate, l3.l_commitdate, l3.l_receiptdate, l3.l_shipinstruct, l3.l_shipmode, l3.l_comment
                                      Filter: ((l3.l_receiptdate > l3.l_commitdate) AND ((l3.l_returnflag = 'R'::bpchar) OR (l3.l_linestatus = 'F'::bpchar)))
                                      Rows Removed by Filter: 1379520
                                      Buffers: shared hit=709 read=111846
                                      Worker 0:  actual time=0.018..255.530 rows=620710 loops=1
                                        Buffers: shared hit=230 read=37334
                                      Worker 1:  actual time=0.014..255.085 rows=620616 loops=1
                                        Buffers: shared hit=259 read=37222
                                ->  Parallel Hash  (cost=194211.92..194211.92 rows=10078 width=38) (actual time=413.404..413.542 rows=26636 loops=3)
                                      Output: supplier.s_name, l1.l_suppkey, l1.l_orderkey, orders.o_orderkey
                                      Buckets: 131072 (originally 32768)  Batches: 1 (originally 1)  Memory Usage: 7456kB
                                      Buffers: shared hit=1285 read=138067
                                      Worker 0:  actual time=413.437..413.444 rows=26592 loops=1
                                        Buffers: shared hit=420 read=45913
                                      Worker 1:  actual time=413.441..413.447 rows=27061 loops=1
                                        Buffers: shared hit=421 read=46383
                                      ->  Parallel Hash Join  (cost=159088.52..194211.92 rows=10078 width=38) (actual time=310.565..402.531 rows=26636 loops=3)
                                            Output: supplier.s_name, l1.l_suppkey, l1.l_orderkey, orders.o_orderkey
                                            Hash Cond: (orders.o_orderkey = l1.l_orderkey)
                                            Buffers: shared hit=1285 read=138067
                                            Worker 0:  actual time=310.564..401.973 rows=26592 loops=1
                                              Buffers: shared hit=420 read=45913
                                            Worker 1:  actual time=310.569..403.675 rows=27061 loops=1
                                              Buffers: shared hit=421 read=46383
                                            ->  Parallel Seq Scan on public.orders  (cost=0.00..33937.50 rows=305042 width=4) (actual time=0.023..50.273 rows=243138 loops=3)
                                                  Output: orders.o_orderkey, orders.o_custkey, orders.o_orderstatus, orders.o_totalprice, orders.o_orderdate, orders.o_orderpriority, orders.o_clerk, orders.o_shippriority, orders.o_comment
                                                  Filter: (orders.o_orderstatus = 'F'::bpchar)
                                                  Rows Removed by Filter: 256862
                                                  Buffers: shared read=26125
                                                  Worker 0:  actual time=0.025..50.017 rows=242592 loops=1
                                                    Buffers: shared read=8687
                                                  Worker 1:  actual time=0.024..50.936 rows=245976 loops=1
                                                    Buffers: shared read=8807
                                            ->  Parallel Hash  (cost=158830.40..158830.40 rows=20650 width=34) (actual time=310.449..310.454 rows=27130 loops=3)
                                                  Output: supplier.s_name, l1.l_suppkey, l1.l_orderkey
                                                  Buckets: 131072 (originally 65536)  Batches: 1 (originally 1)  Memory Usage: 7296kB
                                                  Buffers: shared hit=1285 read=111942
                                                  Worker 0:  actual time=310.504..310.508 rows=27192 loops=1
                                                    Buffers: shared hit=420 read=37226
                                                  Worker 1:  actual time=310.509..310.513 rows=27115 loops=1
                                                    Buffers: shared hit=421 read=37576
                                                  ->  Hash Join  (cost=370.82..158830.40 rows=20650 width=34) (actual time=2.097..299.804 rows=27130 loops=3)
                                                        Output: supplier.s_name, l1.l_suppkey, l1.l_orderkey
                                                        Hash Cond: (l1.l_suppkey = supplier.s_suppkey)
                                                        Buffers: shared hit=1285 read=111942
                                                        Worker 0:  actual time=2.111..300.061 rows=27192 loops=1
                                                          Buffers: shared hit=420 read=37226
                                                        Worker 1:  actual time=2.153..301.986 rows=27115 loops=1
                                                          Buffers: shared hit=421 read=37576
                                                        ->  Parallel Seq Scan on public.lineitem l1  (cost=0.00..156313.86 rows=517124 width=8) (actual time=0.027..250.304 rows=620885 loops=3)
                                                              Output: l1.l_orderkey, l1.l_partkey, l1.l_suppkey, l1.l_linenumber, l1.l_quantity, l1.l_extendedprice, l1.l_discount, l1.l_tax, l1.l_returnflag, l1.l_linestatus, l1.l_shipdate, l1.l_commitdate, l1.l_receiptdate, l1.l_shipinstruct, l1.l_shipmode, l1.l_comment
                                                              Filter: ((l1.l_receiptdate > l1.l_commitdate) AND ((l1.l_returnflag = 'R'::bpchar) OR (l1.l_linestatus = 'F'::bpchar)))
                                                              Rows Removed by Filter: 1379520
                                                              Buffers: shared hit=613 read=111942
                                                              Worker 0:  actual time=0.030..250.660 rows=619552 loops=1
                                                                Buffers: shared hit=196 read=37226
                                                              Worker 1:  actual time=0.029..251.981 rows=624563 loops=1
                                                                Buffers: shared hit=197 read=37576
                                                        ->  Hash  (cost=365.82..365.82 rows=400 width=30) (actual time=2.017..2.020 rows=438 loops=3)
                                                              Output: supplier.s_name, supplier.s_suppkey
                                                              Buckets: 1024  Batches: 1  Memory Usage: 36kB
                                                              Buffers: shared hit=672
                                                              Worker 0:  actual time=2.046..2.049 rows=438 loops=1
                                                                Buffers: shared hit=224
                                                              Worker 1:  actual time=2.044..2.047 rows=438 loops=1
                                                                Buffers: shared hit=224
                                                              ->  Hash Join  (cost=1.32..365.82 rows=400 width=30) (actual time=0.047..1.937 rows=438 loops=3)
                                                                    Output: supplier.s_name, supplier.s_suppkey
                                                                    Hash Cond: (supplier.s_nationkey = nation.n_nationkey)
                                                                    Buffers: shared hit=672
                                                                    Worker 0:  actual time=0.047..1.956 rows=438 loops=1
                                                                      Buffers: shared hit=224
                                                                    Worker 1:  actual time=0.045..1.964 rows=438 loops=1
                                                                      Buffers: shared hit=224
                                                                    ->  Seq Scan on public.supplier  (cost=0.00..323.00 rows=10000 width=34) (actual time=0.012..0.829 rows=10000 loops=3)
                                                                          Output: supplier.s_suppkey, supplier.s_name, supplier.s_address, supplier.s_nationkey, supplier.s_phone, supplier.s_acctbal, supplier.s_comment
                                                                          Buffers: shared hit=669
                                                                          Worker 0:  actual time=0.014..0.866 rows=10000 loops=1
                                                                            Buffers: shared hit=223
                                                                          Worker 1:  actual time=0.013..0.895 rows=10000 loops=1
                                                                            Buffers: shared hit=223
                                                                    ->  Hash  (cost=1.31..1.31 rows=1 width=4) (actual time=0.018..0.019 rows=1 loops=3)
                                                                          Output: nation.n_nationkey
                                                                          Buckets: 1024  Batches: 1  Memory Usage: 9kB
                                                                          Buffers: shared hit=3
                                                                          Worker 0:  actual time=0.019..0.021 rows=1 loops=1
                                                                            Buffers: shared hit=1
                                                                          Worker 1:  actual time=0.016..0.017 rows=1 loops=1
                                                                            Buffers: shared hit=1
                                                                          ->  Seq Scan on public.nation  (cost=0.00..1.31 rows=1 width=4) (actual time=0.013..0.015 rows=1 loops=3)
                                                                                Output: nation.n_nationkey
                                                                                Filter: (nation.n_name = 'IRAQ'::bpchar)
                                                                                Rows Removed by Filter: 24
                                                                                Buffers: shared hit=3
                                                                                Worker 0:  actual time=0.015..0.016 rows=1 loops=1
                                                                                  Buffers: shared hit=1
                                                                                Worker 1:  actual time=0.011..0.013 rows=1 loops=1
                                                                                  Buffers: shared hit=1
                          ->  Parallel Hash  (cost=150062.59..150062.59 rows=1551372 width=8) (actual time=795.885..795.886 rows=998739 loops=3)
                                Output: l2.l_orderkey, l2.l_suppkey
                                Buckets: 262144  Batches: 32  Memory Usage: 5792kB
                                Buffers: shared hit=517 read=112038, temp written=10112
                                Worker 0:  actual time=789.334..789.334 rows=1008131 loops=1
                                  Buffers: shared hit=171 read=37664, temp written=3392
                                Worker 1:  actual time=790.794..790.795 rows=1006330 loops=1
                                  Buffers: shared hit=156 read=37653, temp written=3396
                                ->  Parallel Seq Scan on public.lineitem l2  (cost=0.00..150062.59 rows=1551372 width=8) (actual time=406.010..663.549 rows=998739 loops=3)
                                      Output: l2.l_orderkey, l2.l_suppkey
                                      Filter: ((l2.l_returnflag = 'R'::bpchar) OR (l2.l_linestatus = 'F'::bpchar))
                                      Rows Removed by Filter: 1001666
                                      Buffers: shared hit=517 read=112038
                                      Worker 0:  actual time=396.639..655.891 rows=1008131 loops=1
                                        Buffers: shared hit=171 read=37664
                                      Worker 1:  actual time=398.135..657.482 rows=1006330 loops=1
                                        Buffers: shared hit=156 read=37653
Planning:
  Buffers: shared hit=241 read=2
Planning Time: 1.271 ms
JIT:
  Functions: 178
  Options: Inlining true, Optimization true, Expressions true, Deforming true
  Timing: Generation 5.956 ms, Inlining 167.599 ms, Optimization 630.531 ms, Emission 420.051 ms, Total 1224.138 ms
Execution Time: 1648.757 ms
```
