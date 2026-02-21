# correctnessfix b56

- db=tpch1 K=10 pool=11-20 queries=1,3,6,13,22
- all_correct=True

- q1: ours=4 rls=4 correctness=1
- q3: ours=0 rls=0 correctness=1
- q6: ours=2013 rls=2013 correctness=1
- q13: ours=27 rls=27 correctness=1
- q22: ours=7 rls=7 correctness=1
