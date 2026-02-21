# tpch1 K=15 pool=1-20 (remote drona)
- setup ours: setup_ms=27830.989 disk_overhead_bytes=338916208
- setup rls_with_index: setup_ms=56146.990 disk_overhead_bytes=918839296

- q1: ours=5663.357ms rls_with_index=3012.426ms ratio=1.88x ours_rss=1155808KB rls_rss=241816KB
- q3: ours=3133.563ms rls_with_index=30.390ms ratio=103.11x ours_rss=1155648KB rls_rss=21304KB
- q6: ours=3584.906ms rls_with_index=1807.616ms ratio=1.98x ours_rss=1153520KB rls_rss=233804KB
- q13: ours=452.901ms rls_with_index=60.497ms ratio=7.49x ours_rss=280608KB rls_rss=187404KB
- q22: ours=482.755ms rls_with_index=30.532ms ratio=15.81x ours_rss=226920KB rls_rss=125968KB
- geomean_ratio(ours/rls_with_index)=8.54x
