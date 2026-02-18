# tpch1 Matrix After Fastpaths

- status_all_ok=True
- correctness_all_1=True

## K=5
- q1: ours=5153.841ms rls=1948.278ms ratio=2.65x correctness=1 count=2
- q3: ours=3896.359ms rls=1567.020ms ratio=2.49x correctness=1 count=3007
- q6: ours=2604.526ms rls=1189.170ms ratio=2.19x correctness=1 count=1
- q13: ours=1241.379ms rls=1242.579ms ratio=1.00x correctness=1 count=42
- q22: ours=415.319ms rls=408.971ms ratio=1.02x correctness=1 count=7
- geomean_ratio(ours/rls)=1.71x

## K=15
- q1: ours=33645.735ms rls=3241.596ms ratio=10.38x correctness=1 count=2
- q3: ours=30315.491ms rls=3.480ms ratio=8711.35x correctness=1 count=0
- q6: ours=31026.398ms rls=1813.392ms ratio=17.11x correctness=1 count=1
- q13: ours=2117.672ms rls=63.266ms ratio=33.47x correctness=1 count=0
- q22: ours=2138.059ms rls=10.178ms ratio=210.07x correctness=1 count=0
- geomean_ratio(ours/rls)=101.70x

