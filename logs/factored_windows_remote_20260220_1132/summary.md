# Factored Windows Matrix + Layer Probe Summary

- matrix_runs: 4
- total_rows: 80
- non_ok_rows: 0
- correctness_not_1: 0
- geomean_ratio_all_ours_over_rls_with_index: 1.906x

## Matrix Performance by Run
- combo_11_20_1_10_k15: paired_rows=10 geomean_ratio=0.53x
  - tpch0_1 K=15 q1: ours=877.446ms rls=2217.327ms ratio=0.40x
  - tpch0_1 K=15 q3: ours=791.870ms rls=2045.270ms ratio=0.39x
  - tpch0_1 K=15 q6: ours=657.883ms rls=1843.331ms ratio=0.36x
  - tpch0_1 K=15 q13: ours=135.261ms rls=1097.507ms ratio=0.12x
  - tpch0_1 K=15 q22: ours=94.466ms rls=105.682ms ratio=0.89x
  - tpch1 K=15 q1: ours=8346.804ms rls=6979.013ms ratio=1.20x
  - tpch1 K=15 q3: ours=7780.925ms rls=3984.121ms ratio=1.95x
  - tpch1 K=15 q6: ours=6367.025ms rls=4261.294ms ratio=1.49x
  - tpch1 K=15 q13: ours=1428.595ms rls=9743.772ms ratio=0.15x
  - tpch1 K=15 q22: ours=1007.349ms rls=1643.500ms ratio=0.61x
- w11_20_k10: paired_rows=10 geomean_ratio=0.27x
  - tpch0_1 K=10 q1: ours=697.758ms rls=5615.925ms ratio=0.12x
  - tpch0_1 K=10 q3: ours=615.396ms rls=2006.330ms ratio=0.31x
  - tpch0_1 K=10 q6: ours=479.809ms rls=3714.149ms ratio=0.13x
  - tpch0_1 K=10 q13: ours=132.938ms rls=1094.589ms ratio=0.12x
  - tpch0_1 K=10 q22: ours=93.894ms rls=102.925ms ratio=0.91x
  - tpch1 K=10 q1: ours=6896.768ms rls=43772.453ms ratio=0.16x
  - tpch1 K=10 q3: ours=6281.173ms rls=3965.686ms ratio=1.58x
  - tpch1 K=10 q6: ours=4876.308ms rls=24885.969ms ratio=0.20x
  - tpch1 K=10 q13: ours=1412.279ms rls=9772.786ms ratio=0.14x
  - tpch1 K=10 q22: ours=970.528ms rls=1644.703ms ratio=0.59x
- w1_10_k10: paired_rows=10 geomean_ratio=7.86x
  - tpch0_1 K=10 q1: ours=532.086ms rls=154.256ms ratio=3.45x
  - tpch0_1 K=10 q3: ours=217.237ms rls=12.885ms ratio=16.86x
  - tpch0_1 K=10 q6: ours=276.544ms rls=44.267ms ratio=6.25x
  - tpch0_1 K=10 q13: ours=24.015ms rls=2.148ms ratio=11.18x
  - tpch0_1 K=10 q22: ours=26.895ms rls=1.366ms ratio=19.69x
  - tpch1 K=10 q1: ours=5179.487ms rls=1946.330ms ratio=2.66x
  - tpch1 K=10 q3: ours=2137.610ms rls=442.052ms ratio=4.84x
  - tpch1 K=10 q6: ours=2696.872ms rls=1192.837ms ratio=2.26x
  - tpch1 K=10 q13: ours=231.663ms rls=16.863ms ratio=13.74x
  - tpch1 K=10 q22: ours=254.806ms rls=9.026ms ratio=28.23x
- w5_15_k10: paired_rows=10 geomean_ratio=11.52x
  - tpch0_1 K=10 q1: ours=461.893ms rls=146.269ms ratio=3.16x
  - tpch0_1 K=10 q3: ours=220.354ms rls=2.818ms ratio=78.20x
  - tpch0_1 K=10 q6: ours=219.647ms rls=63.534ms ratio=3.46x
  - tpch0_1 K=10 q13: ours=42.208ms rls=2.891ms ratio=14.60x
  - tpch0_1 K=10 q22: ours=44.688ms rls=2.675ms ratio=16.71x
  - tpch1 K=10 q1: ours=4459.662ms rls=1967.005ms ratio=2.27x
  - tpch1 K=10 q3: ours=2145.303ms rls=8.712ms ratio=246.25x
  - tpch1 K=10 q6: ours=2146.593ms rls=1523.077ms ratio=1.41x
  - tpch1 K=10 q13: ours=409.973ms rls=65.789ms ratio=6.23x
  - tpch1 K=10 q22: ours=421.752ms rls=10.457ms ratio=40.33x

## Layer Choke Points (tpch1)
- combo_11_20_1_10_k15: avg_policy_total_ms=3336.5, avg_prop=165.0, avg_project=312.1, avg_filter=1230.1, avg_ctid_extract=298.2, avg_allow_check=59.4, max_clause_plans=36, max_prop_scans=70, max_join_evals=20, max_mask_mb=8.4, max_rss_mb=1322.4
- w11_20_k10: avg_policy_total_ms=2484.5, avg_prop=164.8, avg_project=173.6, avg_filter=1229.4, avg_ctid_extract=297.5, avg_allow_check=59.4, max_clause_plans=24, max_prop_scans=70, max_join_evals=14, max_mask_mb=5.1, max_rss_mb=1074.7
- w1_10_k10: avg_policy_total_ms=1144.4, avg_prop=0.0, avg_project=447.9, avg_filter=690.8, avg_ctid_extract=172.0, avg_allow_check=28.6, max_clause_plans=0, max_prop_scans=0, max_join_evals=0, max_mask_mb=0.0, max_rss_mb=926.3
- w5_15_k10: avg_policy_total_ms=940.4, avg_prop=1.1, avg_project=181.3, avg_filter=748.7, avg_ctid_extract=185.1, avg_allow_check=31.8, max_clause_plans=8, max_prop_scans=2, max_join_evals=0, max_mask_mb=0.0, max_rss_mb=867.3
