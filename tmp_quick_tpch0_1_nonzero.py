import csv
import time
from pathlib import Path
import fast_sweep_profile_60s as h

DB = 'tpch0_1'
CASES = [
    ('w1_10_k5', 5, '1-10'),
    ('w5_15_k5', 5, '5-15'),
    ('w11_20_k10', 10, '11-20'),
]
QIDS = ['1', '3', '6', '13', '22']

policy_lines = h.load_policy_lines(Path('policy.txt'))
queries = h.load_queries(Path('queries.txt'))
queries = h.filter_queries_by_args(queries, QIDS, [])

run_id = f"quick_tpch0_1_nonzero_{time.strftime('%Y%m%d_%H%M%S')}"
out_dir = Path('logs') / run_id
out_dir.mkdir(parents=True, exist_ok=True)
rows = []
cols = [
    'db', 'case', 'K', 'pool', 'policy_ids', 'query_id',
    'ours_count', 'ours_hash', 'rls_count', 'rls_hash',
    'correctness', 'both_nonzero',
]

server_dir = '/tmp/nghosh_pgpol'
Path(server_dir).mkdir(parents=True, exist_ok=True)
stmt = 0


def run_count_hash(db, baseline, qid, qsql, enabled_path):
    fb = h.count_fallback_sql(qid)
    if fb is not None:
        c = h.count_query_sql(db, baseline, fb, enabled_path, stmt)
        hh = h.hash_query_sql(db, baseline, fb, enabled_path, stmt)
        return c, hh
    c = h.count_query(db, baseline, qsql, enabled_path, stmt)
    hh = h.hash_query(db, baseline, qsql, enabled_path, stmt)
    return c, hh


h.clear_artifacts(DB)
h.clear_rls_indexes_and_policies(DB)

for case_name, k, pool_spec in CASES:
    pool = h.parse_policy_pool(pool_spec, len(policy_lines))
    ids, enabled = h.select_enabled_policies(policy_lines, pool, k)
    ids_s = ','.join(str(x) for x in ids)

    local_path = out_dir / f'enabled_{case_name}.txt'
    h.write_enabled_policy_file(enabled, local_path)
    server_path = h.server_enabled_policy_path(server_dir, run_id, local_path)
    h.write_enabled_policy_file_on_server(DB, enabled, server_path)
    enabled_server = Path(server_path)

    h.clear_artifacts(DB)
    h.clear_rls_indexes_and_policies(DB)
    h.setup_ours_for_k(DB, k, enabled_server, stmt)

    ours = {}
    for qid, qsql in queries:
        ours[qid] = run_count_hash(DB, 'ours', qid, qsql, enabled_server)

    h.clear_artifacts(DB)
    h.apply_rls_policies_for_k(DB, enabled)
    h.create_rls_indexes_for_k(DB, k, enabled, stmt)

    for qid, qsql in queries:
        oc, oh = ours[qid]
        rc, rh = run_count_hash(DB, 'rls_with_index', qid, qsql, enabled_server)
        ok = (int(oc) == int(rc) and str(oh) == str(rh))
        both_nonzero = (int(oc) > 0 and int(rc) > 0)
        rows.append({
            'db': DB,
            'case': case_name,
            'K': str(k),
            'pool': pool_spec,
            'policy_ids': ids_s,
            'query_id': qid,
            'ours_count': str(oc),
            'ours_hash': str(oh),
            'rls_count': str(rc),
            'rls_hash': str(rh),
            'correctness': '1' if ok else '0',
            'both_nonzero': '1' if both_nonzero else '0',
        })

    h.clear_rls_indexes_and_policies(DB)

csv_path = out_dir / 'quick_correctness.csv'
with csv_path.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

nonzero = [r for r in rows if r['both_nonzero'] == '1']
ok_nonzero = [r for r in nonzero if r['correctness'] == '1']
summary = out_dir / 'summary.md'
with summary.open('w') as f:
    f.write('# Quick tpch0_1 non-zero check\n\n')
    f.write(f'- rows_total={len(rows)} nonzero_rows={len(nonzero)} ok_nonzero={len(ok_nonzero)}\n')
    f.write(f'- run_id={run_id}\n\n')
    f.write('## Non-zero rows\n')
    for r in nonzero:
        line = (
            f"- case={r['case']} q{r['query_id']}: "
            f"ours=({r['ours_count']},{r['ours_hash']}) "
            f"rls=({r['rls_count']},{r['rls_hash']}) "
            f"correctness={r['correctness']}\n"
        )
        f.write(line)

print(f'RUN_ID={run_id}')
print(f'CSV={csv_path}')
print(f'SUMMARY={summary}')
