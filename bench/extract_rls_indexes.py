#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def import_harness():
    try:
        import fast_sweep_profile_60s as h  # type: ignore

        return h
    except ModuleNotFoundError as exc:
        if exc.name != "psycopg2":
            raise

    # Allow importing fast_sweep_profile_60s on hosts where psycopg2 is absent.
    psycopg2_stub = types.ModuleType("psycopg2")
    psycopg2_stub.Error = Exception
    psycopg2_stub.OperationalError = Exception
    sql_stub = types.ModuleType("psycopg2.sql")
    psycopg2_stub.sql = sql_stub
    sys.modules["psycopg2"] = psycopg2_stub
    sys.modules["psycopg2.sql"] = sql_stub

    import fast_sweep_profile_60s as h  # type: ignore

    return h


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract exact rls_with_index CREATE INDEX statements for K.")
    p.add_argument("--policy-file", default="policy_supported.txt")
    p.add_argument("--policy-pool", default="1-20")
    p.add_argument("--k", type=int, required=True)
    p.add_argument("--out-sql", default="bench/rls_indexes.sql")
    p.add_argument("--out-drop-sql", default="bench/rls_indexes_drop.sql")
    p.add_argument("--out-names-sql", default="bench/rls_index_names.sql")
    p.add_argument("--manifest", default="")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    h = import_harness()

    policy_path = Path(args.policy_file)
    policy_lines = h.load_policy_lines(policy_path)
    pool_ids = h.parse_policy_pool(str(args.policy_pool), len(policy_lines))
    enabled_ids, enabled_lines = h.select_enabled_policies(policy_lines, pool_ids, int(args.k))
    specs = h.infer_index_specs(enabled_lines)

    create_lines = []
    drop_lines = []
    names = []
    spec_payload = []

    for i, spec in enumerate(specs, start=1):
        idx_name = f"cf_rls_k{args.k}_{spec.table}_{spec.column}_{i}"
        if spec.pattern_ops:
            create_sql = (
                "DO $$ BEGIN BEGIN "
                f"EXECUTE 'CREATE INDEX {idx_name} ON {spec.table} ({spec.column} text_pattern_ops)'; "
                "EXCEPTION WHEN OTHERS THEN "
                f"EXECUTE 'CREATE INDEX {idx_name} ON {spec.table} ({spec.column})'; "
                "END; END $$;"
            )
        else:
            create_sql = f"CREATE INDEX {idx_name} ON {spec.table} ({spec.column});"
        drop_sql = f"DROP INDEX IF EXISTS {idx_name};"

        create_lines.append(create_sql)
        drop_lines.append(drop_sql)
        names.append(idx_name)
        spec_payload.append(
            {
                "table": spec.table,
                "column": spec.column,
                "pattern_ops": bool(spec.pattern_ops),
                "index_name": idx_name,
            }
        )

    out_sql = Path(args.out_sql)
    out_drop_sql = Path(args.out_drop_sql)
    out_names_sql = Path(args.out_names_sql)
    out_sql.parent.mkdir(parents=True, exist_ok=True)

    out_sql.write_text("\n".join(create_lines) + ("\n" if create_lines else ""), encoding="utf-8")
    out_drop_sql.write_text("\n".join(drop_lines) + ("\n" if drop_lines else ""), encoding="utf-8")

    if names:
        values = ",\n  ".join(f"('{n}')" for n in names)
        names_sql = "INSERT INTO pg_temp.rls_idx_names(idx_name) VALUES\n  " + values + ";\n"
    else:
        names_sql = "INSERT INTO pg_temp.rls_idx_names(idx_name) SELECT NULL WHERE FALSE;\n"
    out_names_sql.write_text(names_sql, encoding="utf-8")

    if args.manifest:
        manifest_path = Path(args.manifest)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(
                {
                    "policy_file": str(policy_path),
                    "policy_pool": str(args.policy_pool),
                    "k": int(args.k),
                    "enabled_ids": enabled_ids,
                    "index_count": len(names),
                    "indexes": spec_payload,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    print(f"generated {out_sql} ({len(names)} CREATE INDEX statements)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
