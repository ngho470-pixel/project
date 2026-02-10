import subprocess
from pathlib import Path

ROOT = Path('/home/ng_lab/z3')
POLICY_PATH = ROOT / 'policy.txt'
LOG_PATH = ROOT / 'k_sweep_tpch0_1.log'

Ks = [5, 10, 15, 20]

queries = [
    ("Q1", "SELECT COUNT(*) FROM customer;"),
    ("Q2", "SELECT COUNT(*) FROM lineitem;"),
    ("Q3", "SELECT COUNT(*) FROM orders o JOIN customer c ON o.o_custkey = c.c_custkey;"),
    ("Q4", "SELECT COUNT(*) FROM lineitem l JOIN orders o ON l.l_orderkey = o.o_orderkey JOIN customer c ON o.o_custkey = c.c_custkey;"),
]

policy_lines = [line.strip() for line in POLICY_PATH.read_text().splitlines() if line.strip()]

LOG_PATH.write_text("")

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
    tmp_build = Path(f"/tmp/k_sweep_build_k{k}.sql")
    tmp_build.write_text("\n".join(build_sql) + "\n")

    with LOG_PATH.open("a") as logf:
        logf.write(f"\n-- K={k} --\n")
        subprocess.run(
            ["psql", "-d", "tpch0_1", "-v", "ON_ERROR_STOP=1", "-f", str(tmp_build)],
            check=True,
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
        for qid, sql in queries:
            q_lines = base_lines + [
                "LOAD '/home/ng_lab/z3/custom_filter/custom_filter.so';",
                f"SET custom_filter.policy_path = '{tmp_policy}';",
                "SET custom_filter.contract_mode = off;",
                "SET custom_filter.debug_mode = 'off';",
                "SET custom_filter.enabled = on;",
                f"SET custom_filter.profile_k = {k};",
                f"SET custom_filter.profile_query = '{qid}';",
                sql,
            ]
            tmp_q = Path(f"/tmp/k_sweep_k{k}_{qid}.sql")
            tmp_q.write_text("\n".join(q_lines) + "\n")
            logf.write(f"-- query={qid} --\n")
            res = subprocess.run(
                ["psql", "-d", "tpch0_1", "-v", "ON_ERROR_STOP=1", "-f", str(tmp_q)],
                check=False,
                stdout=logf,
                stderr=subprocess.STDOUT,
            )
            if res.returncode != 0:
                logf.write(f"-- ERROR rc={res.returncode} query={qid} K={k} --\n")

print(f"Wrote log to {LOG_PATH}")
