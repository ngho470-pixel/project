# Policy Lint (Stage 9)

- database: `tpch1`
- policy_file: `/tmp/z3_lab/project/policy.txt`
- strict_mode_ops: `{=,!=,<,<=,>,>=}`

| policy_id | target | status | atoms (col-col with domains) | note |
|---:|---|---|---|---|
| 1 | `lineitem` | supported_now |  |  |
| 2 | `lineitem` | supported_now |  |  |
| 3 | `lineitem` | supported_now |  |  |
| 4 | `lineitem` | supported_now |  |  |
| 5 | `lineitem` | supported_now |  |  |
| 6 | `customer` | supported_now |  |  |
| 7 | `customer` | supported_now |  |  |
| 8 | `customer` | supported_now |  |  |
| 9 | `customer` | supported_now |  |  |
| 10 | `customer` | supported_now |  |  |
| 11 | `orders` | supported_now | `orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1) |  |
| 12 | `orders` | supported_now | `orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1) |  |
| 13 | `orders` | supported_now | `orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1)<br>`customer.c_nationkey` = `nation.n_nationkey` old=(2,2) new=(0,0) |  |
| 14 | `orders` | supported_now | `orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1)<br>`customer.c_nationkey` = `nation.n_nationkey` old=(2,2) new=(0,0)<br>`nation.n_regionkey` = `region.r_regionkey` old=(13,13) new=(8,8) |  |
| 15 | `lineitem` | supported_now | `lineitem.l_orderkey` = `orders.o_orderkey` old=(6,6) new=(4,4) |  |
| 16 | `lineitem` | supported_now | `lineitem.l_orderkey` = `orders.o_orderkey` old=(6,6) new=(4,4)<br>`orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1) |  |
| 17 | `lineitem` | supported_now | `lineitem.l_orderkey` = `orders.o_orderkey` old=(6,6) new=(4,4)<br>`orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1)<br>`customer.c_nationkey` = `nation.n_nationkey` old=(2,2) new=(0,0)<br>`nation.n_regionkey` = `region.r_regionkey` old=(13,13) new=(8,8) |  |
| 18 | `lineitem` | supported_now | `lineitem.l_suppkey` = `supplier.s_suppkey` old=(11,11) new=(7,7)<br>`supplier.s_nationkey` = `nation.n_nationkey` old=(2,2) new=(0,0)<br>`nation.n_regionkey` = `region.r_regionkey` old=(13,13) new=(8,8) |  |
| 19 | `lineitem` | supported_now | `lineitem.l_partkey` = `part.p_partkey` old=(7,7) new=(5,5)<br>`lineitem.l_orderkey` = `orders.o_orderkey` old=(6,6) new=(4,4)<br>`orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1) |  |
| 20 | `partsupp` | supported_now | `partsupp.ps_suppkey` = `supplier.s_suppkey` old=(11,11) new=(7,7)<br>`supplier.s_nationkey` = `nation.n_nationkey` old=(2,2) new=(0,0)<br>`nation.n_regionkey` = `region.r_regionkey` old=(13,13) new=(8,8)<br>`partsupp.ps_partkey` = `part.p_partkey` old=(7,7) new=(5,5) |  |
| 21 | `lineitem` | supported_after_stage9 | `lineitem.l_commitdate` <= `lineitem.l_receiptdate` old=(3,9) new=(2,2) |  |
| 22 | `lineitem` | supported_after_stage9 | `lineitem.l_shipdate` <= `lineitem.l_commitdate` old=(10,3) new=(2,2) |  |
| 23 | `lineitem` | supported_after_stage9 | `lineitem.l_discount` <= `lineitem.l_tax` old=(4,12) new=(3,3) |  |
| 24 | `partsupp` | supported_after_stage9 | `partsupp.ps_supplycost` <= `partsupp.ps_availqty` old=(17,16) new=(6,6) |  |
| 25 | `supplier` | supported_after_stage9 | `supplier.s_acctbal` >= `supplier.s_nationkey` old=(18,2) new=(0,0) |  |
| 26 | `orders` | supported_after_stage9 | `orders.o_custkey` = `customer.c_custkey` old=(1,1) new=(1,1)<br>`orders.o_totalprice` >= `customer.c_acctbal` old=(14,0) new=(0,0) |  |
| 27 | `lineitem` | supported_after_stage9 | `lineitem.l_orderkey` = `orders.o_orderkey` old=(6,6) new=(4,4)<br>`lineitem.l_extendedprice` <= `orders.o_totalprice` old=(5,14) new=(0,0) |  |
| 28 | `partsupp` | supported_after_stage9 | `partsupp.ps_partkey` = `part.p_partkey` old=(7,7) new=(5,5)<br>`part.p_retailprice` >= `partsupp.ps_supplycost` old=(15,17) new=(6,6) |  |
| 29 | `lineitem` | supported_after_stage9 | `lineitem.l_partkey` = `partsupp.ps_partkey` old=(7,7) new=(5,5)<br>`lineitem.l_suppkey` = `partsupp.ps_suppkey` old=(11,11) new=(7,7)<br>`lineitem.l_quantity` <= `partsupp.ps_availqty` old=(8,16) new=(6,6) |  |
| 30 | `supplier` | supported_after_stage9 | `supplier.s_nationkey` = `customer.c_nationkey` old=(2,2) new=(0,0)<br>`supplier.s_acctbal` >= `customer.c_acctbal` old=(18,0) new=(0,0) |  |
