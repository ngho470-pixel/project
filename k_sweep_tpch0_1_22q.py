import subprocess
import time
from pathlib import Path

ROOT = Path('/home/ng_lab/z3')
POLICY_PATH = ROOT / 'policy.txt'
QUERIES_PATH = ROOT / 'queries.txt'
LOG_PATH = ROOT / 'k_sweep_tpch0_1_22q.log'

Ks = [5, 10, 15, 20]

policy_lines = [line.strip() for line in POLICY_PATH.read_text().splitlines() if line.strip()]

queries = []
for line in QUERIES_PATH.read_text().splitlines():
    line = line.strip()
    if not line:
        continue
    if ":" not in line:
        continue
    qid, sql = line.split(":", 1)
    qid = qid.strip()
    sql = sql.strip()
    if not sql.endswith(";"):
        sql += ";"
    queries.append((qid, sql))

LOG_PATH.write_text("")

def wait_db(timeout_s=120):
    start = time.time()
    while time.time() - start < timeout_s:
        try:
            res = subprocess.run(
                ["psql", "-d", "tpch0_1", "-c", "SELECT 1"],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False

def run_psql_file(sql_path, logf, label, retries=2):
    for attempt in range(retries + 1):
        res = subprocess.run(
            ["psql", "-d", "tpch0_1", "-v", "ON_ERROR_STOP=1", "-f", str(sql_path)],
            check=False,
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
        if res.returncode == 0:
            return 0
        logf.write(f"-- ERROR rc={res.returncode} {label} --\n")
        # wait for recovery if server restarted
        wait_db()
    return res.returncode

for k in Ks:
    if len(policy_lines) < k:
        raise SystemExit(f"policy.txt has only {len(policy_lines)} lines, cannot take K={k}")
    tmp_policy = Path(f"/tmp/policy_k{k}.txt")
    tmp_policy.write_text("\n".join(policy_lines[:k]) + "\n")

    base_lines = [
        "\\c tpch0_1",
        "SET client_min_messages = notice;",
        "SET statement_timeout = '30min';",
        "SET max_parallel_workers_per_gather = 0;",
        "SET max_parallel_workers = 0;",
        "SET enable_nestloop = on;",
        "SET enable_hashjoin = on;",
        "SET enable_mergejoin = on;",
        "SET enable_indexonlyscan = off;",
        "SET enable_indexscan = off;",
        "SET enable_bitmapscan = off;",
        "SET enable_seqscan = on;",
        "SET enable_tidscan = off;",
    ]

    # Build artifacts once per K
    build_sql = base_lines + [
        "LOAD '/home/ng_lab/z3/artifact_builder/artifact_builder.so';",
        "TRUNCATE public.files;",
        f"SELECT build_base('{tmp_policy}');",
    ]
    tmp_build = Path(f"/tmp/k_sweep22_build_k{k}.sql")
    tmp_build.write_text("\n".join(build_sql) + "\n")

    with LOG_PATH.open("a") as logf:
        logf.write(f"\n-- K={k} --\n")
        rc = run_psql_file(tmp_build, logf, f"build K={k}", retries=3)
        if rc != 0:
            logf.write(f"-- BUILD FAILED K={k}, skipping queries --\n")
            continue
        for qid, sql in queries:
            q_lines = base_lines + [
                "LOAD '/home/ng_lab/z3/custom_filter/custom_filter.so';",
                f"SET custom_filter.policy_path = '{tmp_policy}';",
                "SET custom_filter.contract_mode = off;",
                "SET custom_filter.debug_mode = 'off';",
                "SET custom_filter.enabled = on;",
                f"SET custom_filter.profile_k = {k};",
                f"SET custom_filter.profile_query = 'Q{qid}';",
                sql,
            ]
            tmp_q = Path(f"/tmp/k_sweep22_k{k}_q{qid}.sql")
            tmp_q.write_text("\n".join(q_lines) + "\n")
            logf.write(f"-- query=Q{qid} --\n")
            rc = run_psql_file(tmp_q, logf, f"query=Q{qid} K={k}", retries=1)
            if rc != 0:
                logf.write(f"-- ERROR rc={rc} query=Q{qid} K={k} --\n")

print(f"Wrote log to {LOG_PATH}")
