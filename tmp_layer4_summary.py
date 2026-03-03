import csv
from pathlib import Path
from statistics import mean

runs = {
    'w1_10_k10': Path('/home/nghosh/research/z3/logs/layer_probe_factored_w1_10_tpch1_k10_20260220_1135/layer_probe.csv'),
    'w5_15_k10': Path('/home/nghosh/research/z3/logs/layer_probe_factored_w5_15_tpch1_k10_20260220_1136/layer_probe.csv'),
    'w11_20_k10': Path('/home/nghosh/research/z3/logs/layer_probe_factored_w11_20_tpch1_k10_20260220_1137/layer_probe.csv'),
    'combo_11_20_1_10_k15': Path('/home/nghosh/research/z3/logs/layer_probe_factored_combo_11_20_1_10_tpch1_k15_20260220_1138/layer_probe.csv'),
}

for name, path in runs.items():
    rows = list(csv.DictReader(path.open()))
    print('\n##', name, 'rows', len(rows))
    if not rows:
        continue
    def f(r,k):
        v=r.get(k,'')
        try:
            return float(v) if v!='' else 0.0
        except Exception:
            return 0.0
    def i(r,k):
        v=r.get(k,'')
        try:
            return int(float(v)) if v!='' else 0
        except Exception:
            return 0
    # averages
    for k in ['policy_total_ms','propagate_ms','project_ms','project_mask_ms','project_row_ms','filter_ms','allow_check_ms','child_exec_ms','rss_mb']:
        vals=[f(r,k) for r in rows]
        print(f'avg_{k}={mean(vals):.3f}')
    print('max_clause_plan_count_max=', max(i(r,'clause_plan_count_max') for r in rows))
    print('max_prop_join_scans_total=', max(i(r,'prop_join_scans_total') for r in rows))
    print('max_project_n_join_evals_max=', max(i(r,'project_n_join_evals_max') for r in rows))
    print('max_project_clause_words_max=', max(i(r,'project_clause_words_max') for r in rows))
    print('max_project_mask_bytes=', max(i(r,'project_mask_bytes') for r in rows))
    print('max_unique_join_struct_sigs_max=', max(i(r,'unique_join_struct_sigs_max') for r in rows))
    print('prop_table_scans_samples:')
    seen=set()
    for r in rows:
        s=r.get('prop_table_scans','')
        if s and s not in seen:
            seen.add(s)
            print(' ', s)
    print('per_query:')
    for r in rows:
        q=r['query_id']
        print(f" q{q}: total={f(r,'policy_total_ms'):.1f} prop={f(r,'propagate_ms'):.1f} proj={f(r,'project_ms'):.1f} filter={f(r,'filter_ms'):.1f} nclauses={i(r,'clause_plan_count_max')} scans={i(r,'prop_join_scans_total')} maskMB={i(r,'project_mask_bytes')/1048576:.1f}")
