import csv
from pathlib import Path
from statistics import geometric_mean, mean
from collections import defaultdict

ROOT = Path('/home/ng_lab/z3')
logs = ROOT / 'logs'
out_dir = logs / 'factored_windows_remote_20260220_1132'
out_dir.mkdir(parents=True, exist_ok=True)

matrix_runs = {
    'w1_10_k10': logs / 'matrix_factored_w1_10_retry2_20260220_1132' / 'runs.csv',
    'w5_15_k10': logs / 'matrix_factored_w5_15_retry2_20260220_1120' / 'runs.csv',
    'w11_20_k10': logs / 'matrix_factored_w11_20_retry_20260220_1122' / 'runs.csv',
    'combo_11_20_1_10_k15': logs / 'matrix_factored_combo_11_20_1_10_retry_20260220_1125' / 'runs.csv',
}

layer_runs = {
    'w1_10_k10': logs / 'layer_probe_factored_w1_10_tpch1_k10_20260220_1135' / 'layer_probe.csv',
    'w5_15_k10': logs / 'layer_probe_factored_w5_15_tpch1_k10_20260220_1136' / 'layer_probe.csv',
    'w11_20_k10': logs / 'layer_probe_factored_w11_20_tpch1_k10_20260220_1137' / 'layer_probe.csv',
    'combo_11_20_1_10_k15': logs / 'layer_probe_factored_combo_11_20_1_10_tpch1_k15_20260220_1138' / 'layer_probe.csv',
}

all_rows=[]
for name,p in matrix_runs.items():
    for r in csv.DictReader(p.open()):
        rr=dict(r)
        rr['_run']=name
        all_rows.append(rr)

# write consolidated csv
cons_csv = out_dir / 'matrix_runs_consolidated.csv'
if all_rows:
    with cons_csv.open('w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(all_rows[0].keys()))
        w.writeheader(); w.writerows(all_rows)

non_ok=[r for r in all_rows if r.get('status')!='ok']
bad=[r for r in all_rows if r.get('status')=='ok' and r.get('correctness')!='1']

pairs=defaultdict(dict)
for r in all_rows:
    key=(r['_run'], r['db'], r['K'], r['query_id'])
    pairs[key][r['baseline']]=r

per_run=defaultdict(list)
for key,v in pairs.items():
    if 'ours' not in v or 'rls_with_index' not in v:
        continue
    ro=v['ours']; rr=v['rls_with_index']
    if ro.get('status')!='ok' or rr.get('status')!='ok':
        continue
    o=float(ro['total_ms']); r=float(rr['total_ms'])
    per_run[key[0]].append((key[1], key[2], key[3], o, r, o/r if r>0 else float('inf')))

# layer summaries
layer_stats={}
for name,p in layer_runs.items():
    rows=list(csv.DictReader(p.open()))
    def f(r,k):
        try: return float(r.get(k) or 0)
        except: return 0.0
    def i(r,k):
        try: return int(float(r.get(k) or 0))
        except: return 0
    layer_stats[name]={
        'avg_policy_total_ms': mean([f(r,'policy_total_ms') for r in rows]) if rows else 0.0,
        'avg_propagate_ms': mean([f(r,'propagate_ms') for r in rows]) if rows else 0.0,
        'avg_project_ms': mean([f(r,'project_ms') for r in rows]) if rows else 0.0,
        'avg_filter_ms': mean([f(r,'filter_ms') for r in rows]) if rows else 0.0,
        'avg_ctid_extract_ms': mean([f(r,'ctid_extract_ms') for r in rows]) if rows else 0.0,
        'avg_allow_check_ms': mean([f(r,'allow_check_ms') for r in rows]) if rows else 0.0,
        'max_clause_plan_count': max([i(r,'clause_plan_count_max') for r in rows] or [0]),
        'max_prop_scans': max([i(r,'prop_join_scans_total') for r in rows] or [0]),
        'max_join_evals': max([i(r,'project_n_join_evals_max') for r in rows] or [0]),
        'max_mask_mb': max([i(r,'project_mask_bytes') for r in rows] or [0])/1048576.0,
        'max_rss_mb': max([f(r,'rss_mb') for r in rows] or [0.0]),
    }

lines=[]
lines.append('# Factored Windows Matrix + Layer Probe Summary')
lines.append('')
lines.append(f'- matrix_runs: {len(matrix_runs)}')
lines.append(f'- total_rows: {len(all_rows)}')
lines.append(f'- non_ok_rows: {len(non_ok)}')
lines.append(f'- correctness_not_1: {len(bad)}')
if per_run:
    ratios=[]
    for vals in per_run.values():
        ratios += [x[5] for x in vals if x[5] > 0]
    lines.append(f'- geomean_ratio_all_ours_over_rls_with_index: {geometric_mean(ratios):.3f}x')
lines.append('')
lines.append('## Matrix Performance by Run')
for run in sorted(per_run):
    vals=per_run[run]
    g=geometric_mean([x[5] for x in vals if x[5]>0]) if vals else 0.0
    c=len(vals)
    lines.append(f'- {run}: paired_rows={c} geomean_ratio={g:.2f}x')
    for db,K,q,o,r,ratio in vals:
        lines.append(f'  - {db} K={K} q{q}: ours={o:.3f}ms rls={r:.3f}ms ratio={ratio:.2f}x')
lines.append('')
lines.append('## Layer Choke Points (tpch1)')
for run in sorted(layer_stats):
    s=layer_stats[run]
    lines.append(f'- {run}: avg_policy_total_ms={s["avg_policy_total_ms"]:.1f}, avg_prop={s["avg_propagate_ms"]:.1f}, avg_project={s["avg_project_ms"]:.1f}, avg_filter={s["avg_filter_ms"]:.1f}, avg_ctid_extract={s["avg_ctid_extract_ms"]:.1f}, avg_allow_check={s["avg_allow_check_ms"]:.1f}, max_clause_plans={s["max_clause_plan_count"]}, max_prop_scans={s["max_prop_scans"]}, max_join_evals={s["max_join_evals"]}, max_mask_mb={s["max_mask_mb"]:.1f}, max_rss_mb={s["max_rss_mb"]:.1f}')

(out_dir / 'summary.md').write_text('\n'.join(lines) + '\n')
print(out_dir / 'summary.md')
print(cons_csv)
