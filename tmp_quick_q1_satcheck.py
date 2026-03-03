from pathlib import Path
import fast_sweep_profile_60s as h

DB='tpch0_1'
CASE=('w1_10_k5',5,'1-10')
QID='1'

policy_lines=h.load_policy_lines(Path('policy.txt'))
queries=h.load_queries(Path('queries.txt'))
queries=h.filter_queries_by_args(queries,[QID],[])
qid,qsql=queries[0]

case_name,k,pool_spec=CASE
pool=h.parse_policy_pool(pool_spec,len(policy_lines))
ids,enabled=h.select_enabled_policies(policy_lines,pool,k)

run_id='quick_q1_satcheck'
server_dir='/tmp/nghosh_pgpol'
Path(server_dir).mkdir(parents=True,exist_ok=True)
local_path=Path('logs')/f'{run_id}_enabled.txt'
local_path.parent.mkdir(parents=True,exist_ok=True)
h.write_enabled_policy_file(enabled,local_path)
server_path=h.server_enabled_policy_path(server_dir,run_id,local_path)
h.write_enabled_policy_file_on_server(DB,enabled,server_path)
enabled_server=Path(server_path)
stmt=0

PARALLEL_OFF=[
    "SET max_parallel_workers_per_gather = 0;",
    "SET max_parallel_workers = 0;",
    "SET enable_parallel_append = off;",
    "SET enable_parallel_hash = off;",
]

def enforce_no_parallel(cur):
    for s in PARALLEL_OFF:
        cur.execute(s)

h.clear_artifacts(DB)
h.clear_rls_indexes_and_policies(DB)
h.setup_ours_for_k(DB,k,enabled_server,stmt)

conn=h.connect(DB,'postgres')
with conn:
    with conn.cursor() as cur:
        h.set_session_for_baseline(cur,'ours',enabled_server,stmt,ours_debug_mode='off')
        enforce_no_parallel(cur)
        oc,oh=h.result_count_and_hash_in_session(cur,qid,qsql)

h.clear_artifacts(DB)
h.apply_rls_policies_for_k(DB,enabled)
h.create_rls_indexes_for_k(DB,k,enabled,stmt)

conn=h.connect(DB,'rls_user')
with conn:
    with conn.cursor() as cur:
        h.set_session_for_baseline(cur,'rls_with_index',enabled_server,stmt)
        enforce_no_parallel(cur)
        rc,rh=h.result_count_and_hash_in_session(cur,qid,qsql)

h.clear_rls_indexes_and_policies(DB)

ok=(int(oc)==int(rc) and str(oh)==str(rh))
print(f'case={case_name} q={qid} ours=({oc},{oh}) rls=({rc},{rh}) correctness={1 if ok else 0}')
