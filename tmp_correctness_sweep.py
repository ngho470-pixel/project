import csv
import time
from pathlib import Path
import fast_sweep_profile_60s as h

h.CUSTOM_FILTER_SO = '/tmp/nghosh_pgext/custom_filter.so'
h.ARTIFACT_BUILDER_SO = '/tmp/nghosh_pgext/artifact_builder.so'

DBS = ['tpch0_1', 'tpch1']
CASES = [
    ('w1_10_k10', 10, '1-10'),
    ('w5_15_k10', 10, '5-15'),
    ('w11_20_k10', 10, '11-20'),
    ('combo_11_20_1_10_k15', 15, '11-20,1-10'),
]

policy_lines = h.load_policy_lines(Path('policy.txt'))
queries = h.load_queries(Path('queries.txt'))
query_ids = [str(i) for i in list(range(1, 20)) + [21, 22]]  # skip q20 for runtime
queries = h.filter_queries_by_args(queries, query_ids, [])

run_id = f"correctness_full_windows_noq20_{time.strftime('%Y%m%d_%H%M%S')}"
out_dir = Path('logs') / run_id
out_dir.mkdir(parents=True, exist_ok=True)
rows_path = out_dir / 'correctness_full.csv'
summary_path = out_dir / 'summary.md'

cols = [
    'db','case','pool','K','policy_ids','query_id',
    'ours_count','rls_count','correctness','status','reason'
]

rows = []
server_dir = '/tmp/nghosh_pgpol'
Path(server_dir).mkdir(parents=True, exist_ok=True)
statement_timeout_ms = 0

def run_count(db, baseline, qid, qsql, enabled_path):
    fb = h.count_fallback_sql(qid)
    if fb is not None:
        return h.count_query_sql(db, baseline, fb, enabled_path, statement_timeout_ms)
    return h.count_query(db, baseline, qsql, enabled_path, statement_timeout_ms)

for db in DBS:
    print(f'[db] {db} start', flush=True)
    h.clear_artifacts(db)
    h.clear_rls_indexes_and_policies(db)

    for case_name, k, pool_spec in CASES:
        pool = h.parse_policy_pool(pool_spec, len(policy_lines))
        enabled_ids, enabled = h.select_enabled_policies(policy_lines, pool, k)
        policy_ids = ','.join(str(x) for x in enabled_ids)
        print(f'[case] db={db} case={case_name} K={k} pool={pool_spec} ids={enabled_ids}', flush=True)

        enabled_local = out_dir / f'enabled_{db}_{case_name}.txt'
        h.write_enabled_policy_file(enabled, enabled_local)
        server_path = h.server_enabled_policy_path(server_dir, run_id, enabled_local)
        h.write_enabled_policy_file_on_server(db, enabled, server_path)
        enabled_server = Path(server_path)

        h.clear_artifacts(db)
        h.clear_rls_indexes_and_policies(db)
        h.setup_ours_for_k(db, k, enabled_server, statement_timeout_ms)

        ours = {}
        ours_err = {}
        for qid, qsql in queries:
            try:
                ours[qid] = run_count(db, 'ours', qid, qsql, enabled_server)
            except Exception as exc:
                ours[qid] = None
                msg = str(exc).replace('\n', ' ')[:200]
                ours_err[qid] = msg
                print(f'[count][ours][ERR] db={db} case={case_name} q={qid} err={msg}', flush=True)

        h.clear_artifacts(db)

        h.apply_rls_policies_for_k(db, enabled)
        h.create_rls_indexes_for_k(db, k, enabled, statement_timeout_ms)

        for qid, qsql in queries:
            if ours.get(qid) is None:
                rows.append({
                    'db': db, 'case': case_name, 'pool': pool_spec, 'K': str(k), 'policy_ids': policy_ids,
                    'query_id': qid, 'ours_count': '', 'rls_count': '', 'correctness': 'skip',
                    'status': 'ours_error', 'reason': ours_err.get(qid, 'ours_count_failed'),
                })
                continue
            try:
                rc = run_count(db, 'rls_with_index', qid, qsql, enabled_server)
                oc = ours[qid]
                ok = int(oc) == int(rc)
                rows.append({
                    'db': db, 'case': case_name, 'pool': pool_spec, 'K': str(k), 'policy_ids': policy_ids,
                    'query_id': qid, 'ours_count': str(oc), 'rls_count': str(rc),
                    'correctness': '1' if ok else '0',
                    'status': 'ok' if ok else 'mismatch',
                    'reason': '' if ok else 'count_mismatch',
                })
                tag = 'OK' if ok else 'MISMATCH'
                print(f'[count][{tag}] db={db} case={case_name} q={qid} ours={oc} rls={rc}', flush=True)
            except Exception as exc:
                msg = str(exc).replace('\n', ' ')[:200]
                oc = ours.get(qid)
                rows.append({
                    'db': db, 'case': case_name, 'pool': pool_spec, 'K': str(k), 'policy_ids': policy_ids,
                    'query_id': qid, 'ours_count': '' if oc is None else str(oc), 'rls_count': '',
                    'correctness': 'skip', 'status': 'rls_error', 'reason': msg,
                })
                print(f'[count][rls][ERR] db={db} case={case_name} q={qid} err={msg}', flush=True)

        h.clear_rls_indexes_and_policies(db)

    print(f'[db] {db} done', flush=True)

with rows_path.open('w', newline='') as f:
    w = csv.DictWriter(f, fieldnames=cols)
    w.writeheader()
    w.writerows(rows)

mismatches = [r for r in rows if r['status'] == 'mismatch']
skips = [r for r in rows if r['correctness'] == 'skip']
oks = [r for r in rows if r['correctness'] == '1']

by_case = {}
for r in rows:
    key = (r['db'], r['case'])
    agg = by_case.setdefault(key, {'ok': 0, 'mismatch': 0, 'skip': 0})
    if r['correctness'] == '1':
        agg['ok'] += 1
    elif r['correctness'] == '0':
        agg['mismatch'] += 1
    else:
        agg['skip'] += 1

lines = []
lines.append('# Full Correctness Sweep (q20 skipped)')
lines.append('')
lines.append(f'- run_id: {run_id}')
lines.append(f'- dbs: {DBS}')
lines.append(f'- cases: {[c[0] for c in CASES]}')
lines.append(f'- queries: {[qid for qid, _ in queries]}')
lines.append(f'- ok: {len(oks)}')
lines.append(f'- mismatch: {len(mismatches)}')
lines.append(f'- skip: {len(skips)}')
lines.append('')
lines.append('## By Case')
for (db, case), agg in sorted(by_case.items()):
    lines.append(f"- {db} {case}: ok={agg['ok']} mismatch={agg['mismatch']} skip={agg['skip']}")

if mismatches:
    lines.append('')
    lines.append('## Mismatches')
    for r in mismatches:
        lines.append(f"- db={r['db']} case={r['case']} q={r['query_id']} ours={r['ours_count']} rls={r['rls_count']}")

if skips:
    lines.append('')
    lines.append('## Skips/Errors')
    for r in skips[:120]:
        lines.append(f"- db={r['db']} case={r['case']} q={r['query_id']} status={r['status']} reason={r['reason']}")

summary_path.write_text('\n'.join(lines) + '\n')
print(f'[done] rows={rows_path}', flush=True)
print(f'[done] summary={summary_path}', flush=True)
