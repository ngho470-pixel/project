# Q21 Timeout Root Cause

- db: `tpch1`
- policy_set: `{1}`
- hygiene: `[pg_hygiene] connecting db=tpch1
[pg_hygiene] before active_sessions=3 managed_locks=12
[pg_hygiene] activity pid=1144284 state=active wait_type= wait= backend_type=client backend query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_orderstatus = 'F' and l1.l_receiptdate > l1.l_co
[pg_hygiene] activity pid=1144285 state=active wait_type=IPC wait=HashBuildHashInner backend_type=parallel worker query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_orderstatus = 'F' and l1.l_receiptdate > l1.l_co
[pg_hygiene] activity pid=1144286 state=active wait_type=IPC wait=HashBuildHashInner backend_type=parallel worker query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_orderstatus = 'F' and l1.l_receiptdate > l1.l_co
[pg_hygiene] managed_lock pid=1144284 state=active wait_type= wait= rel=lineitem mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144284 state=active wait_type= wait= rel=nation mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144284 state=active wait_type= wait= rel=orders mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144284 state=active wait_type= wait= rel=supplier mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144285 state=active wait_type=IPC wait=HashBuildHashInner rel=lineitem mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144285 state=active wait_type=IPC wait=HashBuildHashInner rel=nation mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144285 state=active wait_type=IPC wait=HashBuildHashInner rel=orders mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144285 state=active wait_type=IPC wait=HashBuildHashInner rel=supplier mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144286 state=active wait_type=IPC wait=HashBuildHashInner rel=lineitem mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144286 state=active wait_type=IPC wait=HashBuildHashInner rel=nation mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144286 state=active wait_type=IPC wait=HashBuildHashInner rel=orders mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] managed_lock pid=1144286 state=active wait_type=IPC wait=HashBuildHashInner rel=supplier mode=AccessShareLock granted=True query=EXPLAIN (ANALYZE, BUFFERS, SETTINGS, VERBOSE) select s_name, count(*) as numwait from supplier, lineitem l1, orders, nation where s_suppkey = l1.l_suppkey and o_orderkey = l1.l_orderkey and o_ordersta
[pg_hygiene] cleaned
[pg_hygiene] no non-idle backends remaining`
- plain_elapsed_ms: 0.000
- rls_elapsed_ms: 1651.765
- ours_elapsed_ms: 0.000
- plain_error: `ERROR:  canceling statement due to statement timeout`
- rls_error: `-`
- ours_error: `ERROR:  canceling statement due to statement timeout`

## Plan Node Snapshot (Plain)
```
(no node summary parsed)
```
## Plan Node Snapshot (RLS+Index)
```
->  Parallel Seq Scan on public.lineitem l3  (cost=0.00..156313.86 rows=517124 width=8) (actual time=0.017..255.325 rows=620885 loops=3)
->  Parallel Hash Join  (cost=159088.52..194211.92 rows=10078 width=38) (actual time=310.565..402.531 rows=26636 loops=3)
->  Parallel Seq Scan on public.orders  (cost=0.00..33937.50 rows=305042 width=4) (actual time=0.023..50.273 rows=243138 loops=3)
->  Hash Join  (cost=370.82..158830.40 rows=20650 width=34) (actual time=2.097..299.804 rows=27130 loops=3)
->  Parallel Seq Scan on public.lineitem l1  (cost=0.00..156313.86 rows=517124 width=8) (actual time=0.027..250.304 rows=620885 loops=3)
->  Hash Join  (cost=1.32..365.82 rows=400 width=30) (actual time=0.047..1.937 rows=438 loops=3)
->  Seq Scan on public.supplier  (cost=0.00..323.00 rows=10000 width=34) (actual time=0.012..0.829 rows=10000 loops=3)
->  Seq Scan on public.nation  (cost=0.00..1.31 rows=1 width=4) (actual time=0.013..0.015 rows=1 loops=3)
->  Parallel Seq Scan on public.lineitem l2  (cost=0.00..150062.59 rows=1551372 width=8) (actual time=406.010..663.549 rows=998739 loops=3)
```
## Plan Node Snapshot (Ours Strict)
```
(no node summary parsed)
```
## Wrapper Audit
- audit_lines: 0
- audit_file: `/tmp/z3_lab/project/logs/q21_wrapper_audit.txt`

## Wrapper Audit Update
- A follow-up strict run with `EXPLAIN (VERBOSE)` and `custom_filter.debug_ids=on` captured wrapper notices in `logs/q21_wrapper_audit.txt`.
- Captured evidence includes three distinct `lineitem` scanrelids (`2`, `5`, `6`) being wrapped, which corresponds to alias/subplan-style multi-scan usage in Q21.
