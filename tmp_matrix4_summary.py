import csv
from pathlib import Path
from statistics import geometric_mean
from collections import defaultdict

base = Path('/home/nghosh/research/z3/logs')
runs = [
    base / 'matrix_factored_w1_10_retry2_20260220_1132' / 'runs.csv',
    base / 'matrix_factored_w5_15_retry2_20260220_1120' / 'runs.csv',
    base / 'matrix_factored_w11_20_retry_20260220_1122' / 'runs.csv',
    base / 'matrix_factored_combo_11_20_1_10_retry_20260220_1125' / 'runs.csv',
]
rows = []
for p in runs:
    with p.open() as f:
        r = csv.DictReader(f)
        for row in r:
            row['_src'] = p.parent.name
            rows.append(row)

print('total_rows', len(rows))
non_ok = [r for r in rows if r.get('status') != 'ok']
print('non_ok', len(non_ok))
wrong = [r for r in rows if r.get('status') == 'ok' and r.get('correctness') != '1']
print('correctness_not_1_among_ok', len(wrong))

pairs = defaultdict(dict)
for r in rows:
    key=(r['_src'],r['db'],r['K'],r['query_id'])
    pairs[key][r['baseline']] = r

ratios=[]
per_src = defaultdict(list)
for k,v in pairs.items():
    if 'ours' in v and 'rls_with_index' in v:
        ro=v['ours']; rr=v['rls_with_index']
        if ro.get('status')!='ok' or rr.get('status')!='ok':
            continue
        try:
            o=float(ro['total_ms']); r=float(rr['total_ms'])
        except Exception:
            continue
        ratio=o/r if r>0 else float('inf')
        ratios.append(ratio)
        per_src[k[0]].append((k[1],k[2],k[3],o,r,ratio,ro['correctness']))

print('paired_ok_rows', len(ratios))
if ratios:
    print('geomean_ratio_all', geometric_mean([x for x in ratios if x>0]))

for src in sorted(per_src):
    vals = per_src[src]
    g = geometric_mean([x[5] for x in vals if x[5]>0]) if vals else 0
    c1 = sum(1 for x in vals if str(x[6])=='1')
    print('\n##', src, 'rows', len(vals), 'correctness1', c1, 'geomean_ratio', round(g,2))
    for db,K,q,o,r,ratio,c in vals:
        print(f'  {db} K={K} q{q}: ours={o:.3f} rls={r:.3f} ratio={ratio:.2f}x correctness={c}')
