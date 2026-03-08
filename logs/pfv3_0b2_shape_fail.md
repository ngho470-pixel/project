# PFV3.0b-2 Shape Fail

- db: `tpch0_01`
- mode: `strict_mode=on`, `query_driven_mode=off`, `pfv3=on`, `pfv3_force=on`, `pfv3_allow_fallback=off`

## Cases
- XCMP q6: PASS status=error gate=NOTICE:  pfv3_gate_term: target=lineitem term_id=16793340702962716320 status=PFV3_UNSUPPORTED_CROSS_TABLE_COMPARATOR reason=lineitem.l_extendedprice < orders.o_totalprice atom_count=2 table_count=2 join_vars=3 unary_atoms=0 comparator_atoms=1 route=NOTICE:  pfv3_dispatch_taken: target=lineitem term_id=16793340702962716320 route=pfv3_gate_error supported=0 force=1 fallback=0 err=ERROR:  policy: PFV3 gate rejected term DETAIL:  status=PFV3_UNSUPPORTED_CROSS_TABLE_COMPARATOR reason=lineitem.l_extendedprice < orders.o_totalprice HINT:  PFV3.0b supports equality joins + unary atoms only; comparators
- XNEQ q6: PASS status=error gate=NOTICE:  pfv3_gate_term: target=lineitem term_id=16793340702962716320 status=PFV3_UNSUPPORTED_CROSS_TABLE_NEQ reason=lineitem.l_orderkey != orders.o_orderkey atom_count=2 table_count=2 join_vars=1 unary_atoms=0 comparator_atoms=1 route=NOTICE:  pfv3_dispatch_taken: target=lineitem term_id=16793340702962716320 route=pfv3_gate_error supported=0 force=1 fallback=0 err=ERROR:  policy: PFV3 gate rejected term DETAIL:  status=PFV3_UNSUPPORTED_CROSS_TABLE_NEQ reason=lineitem.l_orderkey != orders.o_orderkey HINT:  PFV3.0b supports equality joins + unary atoms only; comparators are deferred
- SCMP q1: PASS status=error gate=NOTICE:  pfv3_gate_term: target=lineitem term_id=10473572386864919714 status=PFV3_UNSUPPORTED_SAME_TABLE_COMPARATOR reason=lineitem.l_commitdate <= lineitem.l_receiptdate atom_count=1 table_count=1 join_vars=2 unary_atoms=0 comparator_atoms=1 route=NOTICE:  pfv3_dispatch_taken: target=lineitem term_id=10473572386864919714 route=pfv3_gate_error supported=0 force=1 fallback=0 err=ERROR:  policy: PFV3 gate rejected term DETAIL:  status=PFV3_UNSUPPORTED_SAME_TABLE_COMPARATOR reason=lineitem.l_commitdate <= lineitem.l_receiptdate HINT:  PFV3.0b supports equality joins + unary atoms only; comparators

## Result
- overall: PASS
