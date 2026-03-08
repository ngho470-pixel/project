# Stage 5 Correctness Summary

- total_rows: 27
- pass: 27
- fail: 0
- error: 0
- csv: `logs/stage5_correctness.csv`

## Per Stage
- stage1: rows=6 pass=6 fail=0 error=0
- stage2: rows=10 pass=10 fail=0 error=0
- stage3: rows=7 pass=7 fail=0 error=0
- stage5: rows=2 pass=2 fail=0 error=0
- toy_audit: rows=2 pass=2 fail=0 error=0

## Stage5 Cases
- or_selector_union_regression: status=PASS ours=(7,c7e3ead249e68bbef52da1b29d32754f) gt=(7,c7e3ead249e68bbef52da1b29d32754f) note= detail=left_rows=[(10, 1), (10, 3), (30, 1), (30, 2), (30, 3)] right_rows=[(20, 2), (40, 1)] combined_rows=[(10, 1), (10, 3), (20, 2), (30, 1), (30, 2), (30, 3), (40, 1)] selector_signs={6: [-1, 1]}
- propagation_conflict_lemma: status=PASS ours=(5,d2cabcf4296fbedc0851af289d811d09) gt=(5,d2cabcf4296fbedc0851af289d811d09) note= detail=conflict_lemma_hits=1
