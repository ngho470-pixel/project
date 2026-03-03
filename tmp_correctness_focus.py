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
QUERY_IDS = ['1','2','3','6','9','11','13','16','22']

policy_lines = h.load_policy_lines(Path('policy.txt'))
queries = h.load_queries(Path('queries.txt'))
queries = h.filter_queries_by_args(queries, QUERY_IDS, [])

run_id = f"correctness_focus_windows_{time.strftime('%Y%m%d_%H%M%S')}"
out_dir = Path('logs') / run_id
out_dir.mkdir(parents=True, exist_ok=True)
rows_path = out_dir / 'correctness.csv'
summary_path = out_dir / 'summary.md'

cols = [
    'db','case','pool','K','policy_ids','query_id',
    'ours_count','ours_hash','rls_count','rls_hash','correctness','status','reason'
]
rows = []
server_dir = '/tmp/nghosh_pgpol'
Path(server_dir).mkdir(parents=True, exist_ok=True)
statement_timeout_ms = 0

def run_count_hash(db, baseline, qid, qsql, enabled_path):
    fb = h.count_fallback_sql(qid)
    if fb is not None:
        cnt = h.count_query_sql(db, baseline, fb, enabled_path, statement_timeout_ms)
        hsh = h.hash_query_sql(db, baseline, fb, enabled_path, statement_timeout_ms)
        return cnt, hsh
    cnt = h.count_query(db, baseline, qsql, enabled_path, statement_timeout_ms)
    hsh = h.hash_query(db, baseline, qsql, enabled_path, statement_timeout_ms)
    return cnt, hsh

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
                ours[qid] = run_count_hash(db, 'ours', qid, qsql, enabled_server)
            except Exception as exc:
                ours[qid] = None
                msg = str(exc).replace('\n', ' ')[:240]
                ours_err[qid] = msg
                print(f'[ours][ERR] db={db} case={case_name} q={qid} err={msg}', flush=True)

        h.clear_artifacts(db)

        h.apply_rls_policies_for_k(db, enabled)
        h.create_rls_indexes_for_k(db, k, enabled, statement_timeout_ms)

        for qid, qsql in queries:
            if ours.get(qid) is None:
                rows.append({
                    'db': db, 'case': case_name, 'pool': pool_spec, 'K': str(k), 'policy_ids': policy_ids,
                    'query_id': qid, 'ours_count': '', 'ours_hash': '', 'rls_count': '', 'rls_hash': '',
                    'correctness': 'skip', 'status': 'ours_error', 'reason': ours_err.get(qid, 'ours_failed'),
                })
                continue
            try:
                rc, rh = run_count_hash(db, 'rls_with_index', qid, qsql, enabled_server)
                oc, oh = ours[qid]
                ok = (int(oc) == int(rc)) and (str(oh) == str(rh))
                rows.append({
                    'db': db, 'case': case_name, 'pool': pool_spec, 'K': str(k), 'policy_ids': policy_ids,
                    'query_id': qid, 'ours_count': str(oc), 'ours_hash': str(oh),
                    'rls_count': str(rc), 'rls_hash': str(rh),
                    'correctness': '1' if ok else '0', 'status': 'ok' if ok else 'mismatch',
                    'reason': '' if ok else 'count_or_hash_mismatch',
                })
                tag = 'OK' if ok else 'MISMATCH'
                print(f'[cmp][{tag}] db={db} case={case_name} q={qid} ours=({oc},{oh}) rls=({rc},{rh})', flush=True)
            except Exception as exc:
                msg = str(exc).replace('\n', ' ')[:240]
                oc, oh = ours.get(qid, ('',''))
                rows.append({
                    'db': db, 'case': case_name, 'pool': pool_spec, 'K': str(k), 'policy_ids': policy_ids,
                    'query_id': qid, 'ours_count': str(oc), 'ours_hash': str(oh), 'rls_count': '', 'rls_hash': '',
                    'correctness': 'skip', 'status': 'rls_error', 'reason': msg,
                })
                print(f'[rls][ERR] db={db} case={case_name} q={qid} err={msg}', flush=True)

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
lines.append('# Correctness Focus Sweep')
lines.append('')
lines.append(f'- run_id: {run_id}')
lines.append(f'- dbs: {DBS}')
lines.append(f'- cases: {[c[0] for c in CASES]}')
lines.append(f'- queries: {QUERY_IDS}')
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
        lines.append(f"- db={r['db']} case={r['case']} q={r['query_id']} ours=({r['ours_count']},{r['ours_hash']}) rls=({r['rls_count']},{r['rls_hash']})")
if skips:
    lines.append('')
    lines.append('## Skips/Errors')
    for r in skips[:120]:
        lines.append(f"- db={r['db']} case={r['case']} q={r['query_id']} status={r['status']} reason={r['reason']}")

summary_path.write_text('\n'.join(lines) + '\n')
print(f'[done] rows={rows_path}', flush=True)
print(f'[done] summary={summary_path}', flush=True)
