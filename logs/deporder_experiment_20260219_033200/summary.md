# Dep-Ordered RLS-Semantics Experiment (tpch0_1 + tpch1)

This run enforces **transitive RLS semantics** during policy evaluation by building policy-target allow-bitmaps in a dependency order (referenced tables first).

Policy windows are implemented as **policy-pools** (wrap-around to keep K=15 possible):
- wstart1: `--policy-pool 1-20`
- wstart5: `--policy-pool 5-20,1-4`
- wstart11: `--policy-pool 11-20,1-10`

## Matrix (OURS vs RLS+index)

### matrix_deporder_wstart1_20260219_032110
- wstart1 pool=1-20 (K=5 ids 1-5, K=15 ids 1-15)
- rows=40 status_all_ok=True correctness_all_1=True

#### tpch0_1 K=5
- q1: ours=262.801ms rls+idx=62.574ms ratio=4.20x correctness=1 count=2
- q3: ours=143.848ms rls+idx=27.396ms ratio=5.25x correctness=1 count=311
- q6: ours=129.719ms rls+idx=22.488ms ratio=5.77x correctness=1 count=1
- q13: ours=46.789ms rls+idx=47.010ms ratio=1.00x correctness=1 count=37
- q22: ours=7.393ms rls+idx=7.044ms ratio=1.05x correctness=1 count=7
- geomean_ratio(ours/rls+idx)=2.66x

#### tpch0_1 K=15
- q1: ours=261.109ms rls+idx=437.064ms ratio=0.60x correctness=1 count=2
- q3: ours=114.376ms rls+idx=1.772ms ratio=64.55x correctness=1 count=0
- q6: ours=133.446ms rls+idx=326.799ms ratio=0.41x correctness=1 count=1
- q13: ours=13.509ms rls+idx=1.412ms ratio=9.57x correctness=1 count=0
- q22: ours=14.418ms rls+idx=3.864ms ratio=3.73x correctness=1 count=0
- geomean_ratio(ours/rls+idx)=3.55x

#### tpch1 K=5
- q1: ours=2571.579ms rls+idx=970.799ms ratio=2.65x correctness=1 count=2
- q3: ours=1943.114ms rls+idx=777.631ms ratio=2.50x correctness=1 count=3007
- q6: ours=1312.487ms rls+idx=601.519ms ratio=2.18x correctness=1 count=1
- q13: ours=562.779ms rls+idx=566.623ms ratio=0.99x correctness=1 count=42
- q22: ours=189.713ms rls+idx=188.609ms ratio=1.01x correctness=1 count=7
- geomean_ratio(ours/rls+idx)=1.71x

#### tpch1 K=15
- q1: ours=2604.775ms rls+idx=1572.830ms ratio=1.66x correctness=1 count=2
- q3: ours=1151.560ms rls+idx=1.733ms ratio=664.49x correctness=1 count=0
- q6: ours=1348.783ms rls+idx=903.557ms ratio=1.49x correctness=1 count=1
- q13: ours=131.777ms rls+idx=29.589ms ratio=4.45x correctness=1 count=0
- q22: ours=135.524ms rls+idx=5.180ms ratio=26.16x correctness=1 count=0
- geomean_ratio(ours/rls+idx)=11.39x

### matrix_deporder_wstart5_20260219_032408
- wstart5 pool=5-20,1-4 (K=5 ids 5-9, K=15 ids 5-19)
- rows=40 status_all_ok=True correctness_all_1=True

#### tpch0_1 K=5
- q1: ours=223.750ms rls+idx=73.438ms ratio=3.05x correctness=1 count=3
- q3: ours=91.981ms rls+idx=0.497ms ratio=185.07x correctness=1 count=0
- q6: ours=99.844ms rls+idx=39.767ms ratio=2.51x correctness=1 count=1
- q13: ours=5.957ms rls+idx=2.035ms ratio=2.93x correctness=1 count=0
- q22: ours=7.245ms rls+idx=3.021ms ratio=2.40x correctness=1 count=0
- geomean_ratio(ours/rls+idx)=6.30x

#### tpch0_1 K=15
- q1: ours=277.647ms rls+idx=1968.508ms ratio=0.14x correctness=1 count=0
- q3: ours=148.432ms rls+idx=4.810ms ratio=30.86x correctness=1 count=0
- q6: ours=165.662ms rls+idx=1694.327ms ratio=0.10x correctness=1 count=1
- q13: ours=15.836ms rls+idx=1.438ms ratio=11.01x correctness=1 count=0
- q22: ours=17.018ms rls+idx=2.150ms ratio=7.92x correctness=1 count=0
- geomean_ratio(ours/rls+idx)=2.06x

#### tpch1 K=5
- q1: ours=2100.145ms rls+idx=984.127ms ratio=2.13x correctness=1 count=3
- q3: ours=635.038ms rls+idx=42.760ms ratio=14.85x correctness=1 count=0
- q6: ours=971.883ms rls+idx=767.464ms ratio=1.27x correctness=1 count=1
- q13: ours=55.282ms rls+idx=15.965ms ratio=3.46x correctness=1 count=0
- q22: ours=66.275ms rls+idx=11.795ms ratio=5.62x correctness=1 count=0
- geomean_ratio(ours/rls+idx)=3.79x

#### tpch1 K=15
- q1: ours=2648.718ms rls+idx=8749.859ms ratio=0.30x correctness=1 count=0
- q3: ours=2114.848ms rls+idx=22.254ms ratio=95.03x correctness=1 count=0
- q6: ours=1649.454ms rls+idx=6369.815ms ratio=0.26x correctness=1 count=1
- q13: ours=147.820ms rls+idx=33.025ms ratio=4.48x correctness=1 count=0
- q22: ours=152.676ms rls+idx=5.404ms ratio=28.25x correctness=1 count=0
- geomean_ratio(ours/rls+idx)=3.93x

### matrix_deporder_wstart11_20260219_032608
- wstart11 pool=11-20,1-10 (K=5 ids 11-15, K=15 ids 11-20,1-5)
- rows=40 status_all_ok=True correctness_all_1=True

#### tpch0_1 K=5
- q1: ours=205.586ms rls+idx=1049.995ms ratio=0.20x correctness=1 count=4
- q3: ours=81.601ms rls+idx=394.877ms ratio=0.21x correctness=1 count=39
- q6: ours=92.515ms rls+idx=552.733ms ratio=0.17x correctness=1 count=1
- q13: ours=57.993ms rls+idx=527.848ms ratio=0.11x correctness=1 count=23
- q22: ours=22.462ms rls+idx=51.204ms ratio=0.44x correctness=1 count=7
- geomean_ratio(ours/rls+idx)=0.20x

#### tpch0_1 K=15
- q1: ours=1881.869ms rls+idx=1048.585ms ratio=1.79x correctness=1 count=2
- q3: ours=1703.928ms rls+idx=966.550ms ratio=1.76x correctness=1 count=0
- q6: ours=1702.660ms rls+idx=867.134ms ratio=1.96x correctness=1 count=1
- q13: ours=59.541ms rls+idx=527.372ms ratio=0.11x correctness=1 count=23
- q22: ours=24.883ms rls+idx=50.604ms ratio=0.49x correctness=1 count=7
- geomean_ratio(ours/rls+idx)=0.81x

#### tpch1 K=5
- q1: ours=2017.133ms rls+idx=9020.574ms ratio=0.22x correctness=1 count=4
- q3: ours=1588.580ms rls+idx=1380.524ms ratio=1.15x correctness=1 count=393
- q6: ours=918.143ms rls+idx=4196.834ms ratio=0.22x correctness=1 count=1
- q13: ours=613.325ms rls+idx=4817.374ms ratio=0.13x correctness=1 count=27
- q22: ours=417.852ms rls+idx=805.250ms ratio=0.52x correctness=1 count=7
- geomean_ratio(ours/rls+idx)=0.33x

#### tpch1 K=15
- q1: ours=19436.095ms rls+idx=3374.961ms ratio=5.76x correctness=1 count=2
- q3: ours=18494.700ms rls+idx=1955.951ms ratio=9.46x correctness=1 count=0
- q6: ours=17631.175ms rls+idx=2065.863ms ratio=8.53x correctness=1 count=1
- q13: ours=616.518ms rls+idx=4807.599ms ratio=0.13x correctness=1 count=27
- q22: ours=420.011ms rls+idx=811.372ms ratio=0.52x correctness=1 count=7
- geomean_ratio(ours/rls+idx)=1.99x

## Layer Probe (tpch1, K=15, OURS-only)
Focus: `project_ms` should be small; find the next bottleneck.

### Before Fix Reference
- logs/layer_probe_tpch1_k15_clausemask2_20260218_110326/layer_probe.csv
- tpch1 K=15 q1: policy_total_ms=3732.7 project_ms=2659.4 propagate_ms=258.0 artifact_parse_ms=801.5

### After Fix: wstart1 (layer_probe_deporder_tpch1_k15_wstart1_20260219_032835)
- q1: policy_total=896.1ms artifact_parse=811.4 propagate=23.9 project=45.8 (mask=0.5 row=35.8) filter=1193.2 child_exec=420.2 rss=1126.7
- q3: policy_total=903.0ms artifact_parse=820.3 propagate=24.0 project=44.9 (mask=0.5 row=35.1) filter=173.9 child_exec=97.8 rss=1127.8
- q6: policy_total=889.3ms artifact_parse=807.8 propagate=23.8 project=43.9 (mask=0.4 row=34.3) filter=384.4 child_exec=369.8 rss=1126.3
- q13: policy_total=104.5ms artifact_parse=92.0 propagate=0.7 project=9.6 (mask=0.0 row=0.0) filter=29.9 child_exec=17.2 rss=266.9
- q22: policy_total=102.7ms artifact_parse=90.6 propagate=0.7 project=9.3 (mask=0.0 row=0.0) filter=71.3 child_exec=68.0 rss=220.9

### After Fix: wstart5 (layer_probe_deporder_tpch1_k15_wstart5_20260219_032924)
- q1: policy_total=1181.0ms artifact_parse=1081.0 propagate=80.0 project=9.3 (mask=0.0 row=0.0) filter=1143.4 child_exec=408.1 rss=1316.1
- q3: policy_total=1188.1ms artifact_parse=1090.4 propagate=78.0 project=9.4 (mask=0.0 row=0.0) filter=751.9 child_exec=381.7 rss=1315.9
- q6: policy_total=1193.9ms artifact_parse=1093.4 propagate=80.3 project=9.7 (mask=0.0 row=0.0) filter=383.3 child_exec=370.1 rss=1314.8
- q13: policy_total=127.0ms artifact_parse=115.0 propagate=0.7 project=9.3 (mask=0.0 row=0.0) filter=29.4 child_exec=16.8 rss=250.8
- q22: policy_total=126.0ms artifact_parse=113.7 propagate=0.7 project=9.4 (mask=0.0 row=0.0) filter=70.0 child_exec=66.7 rss=205.0

### After Fix: wstart11 (layer_probe_deporder_tpch1_k15_wstart11_20260219_033000)
- q1: policy_total=17501.2ms artifact_parse=1469.3 propagate=15262.2 project=756.3 (mask=374.3 row=374.2) filter=1139.6 child_exec=410.4 rss=2930.9
- q3: policy_total=17613.3ms artifact_parse=1462.4 propagate=15363.8 project=773.6 (mask=380.9 row=384.9) filter=927.2 child_exec=470.2 rss=2942.8
- q6: policy_total=17539.4ms artifact_parse=1495.0 propagate=15269.7 project=761.6 (mask=374.7 row=379.1) filter=385.9 child_exec=372.4 rss=2941.5
- q13: policy_total=115.2ms artifact_parse=93.5 propagate=11.0 project=7.8 (mask=0.1 row=7.7) filter=375.4 child_exec=228.6 rss=224.5
- q22: policy_total=115.1ms artifact_parse=93.5 propagate=11.0 project=7.8 (mask=0.1 row=7.7) filter=201.2 child_exec=67.2 rss=178.6
