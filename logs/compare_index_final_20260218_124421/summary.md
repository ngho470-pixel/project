# Compare Index Summary (tpch0_1 + tpch1)

- rows=60 baselines=['ours', 'ours_with_index', 'rls_with_index']

## tpch0_1 K=5
- q1: ours=262.426ms ours+idx=262.863ms rls+idx=69.449ms | ours/rls+idx=3.78x ours+idx/rls+idx=3.78x count=2
- q3: ours=149.804ms ours+idx=125.593ms rls+idx=27.127ms | ours/rls+idx=5.52x ours+idx/rls+idx=4.63x count=311
- q6: ours=131.350ms ours+idx=130.446ms rls+idx=23.125ms | ours/rls+idx=5.68x ours+idx/rls+idx=5.64x count=1
- q13: ours=46.130ms ours+idx=47.930ms rls+idx=46.580ms | ours/rls+idx=0.99x ours+idx/rls+idx=1.03x count=37
- q22: ours=7.137ms ours+idx=6.932ms rls+idx=6.851ms | ours/rls+idx=1.04x ours+idx/rls+idx=1.01x count=7
- geomean_ratio(ours/rls+idx)=2.61x
- geomean_ratio(ours+idx/rls+idx)=2.53x

## tpch0_1 K=15
- q1: ours=539.454ms ours+idx=536.714ms rls+idx=439.215ms | ours/rls+idx=1.23x ours+idx/rls+idx=1.22x count=2
- q3: ours=373.925ms ours+idx=377.714ms rls+idx=1.675ms | ours/rls+idx=223.24x ours+idx/rls+idx=225.50x count=0
- q6: ours=408.904ms ours+idx=405.850ms rls+idx=335.739ms | ours/rls+idx=1.22x ours+idx/rls+idx=1.21x count=1
- q13: ours=14.992ms ours+idx=16.100ms rls+idx=1.391ms | ours/rls+idx=10.78x ours+idx/rls+idx=11.57x count=0
- q22: ours=16.109ms ours+idx=17.101ms rls+idx=2.665ms | ours/rls+idx=6.04x ours+idx/rls+idx=6.42x count=0
- geomean_ratio(ours/rls+idx)=7.37x
- geomean_ratio(ours+idx/rls+idx)=7.56x

## tpch1 K=5
- q1: ours=2563.114ms ours+idx=2579.001ms rls+idx=971.553ms | ours/rls+idx=2.64x ours+idx/rls+idx=2.65x count=2
- q3: ours=1939.274ms ours+idx=1926.995ms rls+idx=777.701ms | ours/rls+idx=2.49x ours+idx/rls+idx=2.48x count=3007
- q6: ours=1320.474ms ours+idx=1320.588ms rls+idx=600.964ms | ours/rls+idx=2.20x ours+idx/rls+idx=2.20x count=1
- q13: ours=566.764ms ours+idx=572.068ms rls+idx=567.906ms | ours/rls+idx=1.00x ours+idx/rls+idx=1.01x count=42
- q22: ours=191.310ms ours+idx=190.788ms rls+idx=191.756ms | ours/rls+idx=1.00x ours+idx/rls+idx=0.99x count=7
- geomean_ratio(ours/rls+idx)=1.70x
- geomean_ratio(ours+idx/rls+idx)=1.71x

## tpch1 K=15
- q1: ours=5430.171ms ours+idx=5417.577ms rls+idx=1572.321ms | ours/rls+idx=3.45x ours+idx/rls+idx=3.45x count=2
- q3: ours=3811.252ms ours+idx=3825.646ms rls+idx=1.778ms | ours/rls+idx=2143.56x ours+idx/rls+idx=2151.66x count=0
- q6: ours=4207.830ms ours+idx=4229.277ms rls+idx=907.407ms | ours/rls+idx=4.64x ours+idx/rls+idx=4.66x count=1
- q13: ours=154.852ms ours+idx=157.254ms rls+idx=29.913ms | ours/rls+idx=5.18x ours+idx/rls+idx=5.26x count=0
- q22: ours=154.668ms ours+idx=156.284ms rls+idx=5.287ms | ours/rls+idx=29.25x ours+idx/rls+idx=29.56x count=0
- geomean_ratio(ours/rls+idx)=22.04x
- geomean_ratio(ours+idx/rls+idx)=22.18x

