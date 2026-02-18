# tpch0_1 + tpch1 Matrix Summary

- rows=40 status_all_ok=True correctness_all_1=True

## tpch0_1 K=5
- q1: ours=4403.098ms rls=111.014ms ratio=39.66x correctness=1 count=2
- q3: ours=4257.060ms rls=58.136ms ratio=73.23x correctness=1 count=311
- q6: ours=4143.958ms rls=41.033ms ratio=100.99x correctness=1 count=1
- q13: ours=98.700ms rls=100.771ms ratio=0.98x correctness=1 count=37
- q22: ours=35.301ms rls=34.389ms ratio=1.03x correctness=1 count=7
- geomean_ratio(ours/rls)=12.41x

## tpch0_1 K=15
- q1: ours=7030.753ms rls=919.301ms ratio=7.65x correctness=1 count=2
- q3: ours=6693.051ms rls=3.224ms ratio=2076.01x correctness=1 count=0
- q6: ours=6750.842ms rls=674.778ms ratio=10.00x correctness=1 count=1
- q13: ours=640.406ms rls=2.749ms ratio=232.96x correctness=1 count=0
- q22: ours=642.632ms rls=2.710ms ratio=237.13x correctness=1 count=0
- geomean_ratio(ours/rls)=97.42x

## tpch1 K=5
- q1: ours=43155.969ms rls=1945.192ms ratio=22.19x correctness=1 count=2
- q3: ours=41882.186ms rls=1563.413ms ratio=26.79x correctness=1 count=3007
- q6: ours=40612.936ms rls=1191.008ms ratio=34.10x correctness=1 count=1
- q13: ours=1252.638ms rls=1262.460ms ratio=0.99x correctness=1 count=42
- q22: ours=411.320ms rls=408.063ms ratio=1.01x correctness=1 count=7
- geomean_ratio(ours/rls)=7.27x

## tpch1 K=15
- q1: ours=68150.644ms rls=3241.812ms ratio=21.02x correctness=1 count=2
- q3: ours=64853.122ms rls=3.474ms ratio=18668.14x correctness=1 count=0
- q6: ours=65660.662ms rls=1812.852ms ratio=36.22x correctness=1 count=1
- q13: ours=6143.793ms rls=63.090ms ratio=97.38x correctness=1 count=0
- q22: ours=6154.245ms rls=10.161ms ratio=605.67x correctness=1 count=0
- geomean_ratio(ours/rls)=242.49x

