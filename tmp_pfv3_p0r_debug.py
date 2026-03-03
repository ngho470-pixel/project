import os, sys
from pathlib import Path
REPO = Path('/tmp/z3_lab/project')
sys.path.insert(0, str(REPO))
import fast_sweep_profile_60s as h
h.CUSTOM_FILTER_SO = str(REPO / 'custom_filter' / 'custom_filter.so')
h.ARTIFACT_BUILDER_SO = str(REPO / 'artifact_builder' / 'artifact_builder.so')
os.environ['PGOPTIONS'] = '-c custom_filter.strict_mode=on -c custom_filter.query_driven_mode=off -c custom_filter.policy_first_v2=off'
os.environ['CF_POLICY_STRICT_MODE'] = '1'
policy_line = "7. lineitem: lineitem.l_partkey = partsupp.ps_partkey AND lineitem.l_suppkey = partsupp.ps_suppkey AND partsupp.ps_supplycost > 500"
db='tpch0_01'; qid='1'; timeout_ms=h.parse_timeout_ms('20min')
queries = {k:v for k,v in h.load_queries(REPO/'queries.txt')}
qsql = queries[qid]
enabled = Path('/tmp/pfv3_p0r_debug.txt')
h.write_enabled_policy_file([policy_line], enabled)
os.chmod(enabled, 0o644)
run_id = h.artifact_run_id_for_enabled(enabled)
os.system(f'cd {REPO} && python3 scripts/pg_hygiene.py --db {db}')
h.clear_artifacts_run_id(db, run_id); h.clear_rls_indexes_and_policies(db)
h.setup_ours_for_k(db, 444, enabled, timeout_ms)
conn = h.connect(db, h.role_for_baseline('ours'))
try:
    with conn.cursor() as cur:
        h.set_session_for_baseline(cur, 'ours', enabled, timeout_ms, ours_debug_mode='off')
        cur.execute('SET client_min_messages = notice;')
        cur.execute('SET custom_filter.profile_rescan = off;')
        cur.execute('SET custom_filter.profile_k = 1444;')
        cur.execute("SET custom_filter.profile_query = '1444';")
        cur.execute('SET custom_filter.pfv3 = on;')
        cur.execute('SET custom_filter.pfv3_force = on;')
        cur.execute('SET custom_filter.pfv3_allow_fallback = off;')
        m, notices = h.execute_with_rss_and_notices(cur, qsql)
        print('status', m.status, 'elapsed_ms', f'{m.elapsed_ms:.3f}')
        for n in notices:
            if 'pfv3_' in n or 'policy_profile_query:' in n:
                print(n)
        if m.status == 'ok':
            cnt, hh = h.result_count_and_hash_in_session(cur, qid, qsql)
            print('ours', cnt, hh)
finally:
    conn.close()
