#!/usr/bin/env python3
import argparse
import os
import struct
import subprocess
import tempfile
from pathlib import Path


def run(cmd, check=True, capture=True):
    return subprocess.run(
        cmd,
        check=check,
        text=True,
        capture_output=capture,
    )


def psql_sql(db: str, user: str, sql: str, on_error_stop: bool = True, host: str | None = None):
    cmd = [
        "psql",
        "-U",
        user,
        "-d",
        db,
        "-X",
        "-A",
        "-t",
    ]
    if host:
        cmd[1:1] = ["-h", host]
    if on_error_stop:
        cmd += ["-v", "ON_ERROR_STOP=1"]
    cmd += ["-c", sql]
    return run(cmd, check=on_error_stop)


def psql_file(db: str, user: str, sql_text: str, on_error_stop: bool = True, host: str | None = None):
    with tempfile.NamedTemporaryFile("w", suffix=".sql", delete=False) as tf:
        tf.write(sql_text)
        path = tf.name
    try:
        cmd = [
            "psql",
            "-U",
            user,
            "-d",
            db,
            "-X",
            "-A",
            "-t",
        ]
        if host:
            cmd[1:1] = ["-h", host]
        if on_error_stop:
            cmd += ["-v", "ON_ERROR_STOP=1"]
        cmd += ["-f", path]
        return run(cmd, check=on_error_stop)
    finally:
        os.unlink(path)


def load_query(path: Path, qid: int) -> str:
    lines = [ln.strip() for ln in path.read_text().splitlines() if ln.strip()]
    if qid < 1 or qid > len(lines):
        raise ValueError(f"query id {qid} out of range (1..{len(lines)})")
    q = lines[qid - 1].rstrip(";")
    return q


def decode_cb02(blob: bytes):
    if len(blob) < 12 or blob[:4] != b"CB02":
        raise ValueError("missing CB02 header")
    nrows, payload_len = struct.unpack_from("<ii", blob, 4)
    if nrows < 0 or payload_len < 0:
        raise ValueError("negative nrows/payload")
    if 12 + payload_len != len(blob):
        raise ValueError("payload len mismatch")
    off = 12
    end = 12 + payload_len
    rows = []
    ntoks = None
    for _ in range(nrows):
        if off + 2 > end:
            raise ValueError("truncated ntoks")
        (nrow_toks,) = struct.unpack_from("<H", blob, off)
        off += 2
        if nrow_toks > 4096:
            raise ValueError(f"ntoks too large: {nrow_toks}")
        if ntoks is None:
            ntoks = nrow_toks
        elif ntoks != nrow_toks:
            raise ValueError(f"ntoks changed across rows: {ntoks} -> {nrow_toks}")
        need = nrow_toks * 4
        if off + need > end:
            raise ValueError("truncated row tokens")
        toks = list(struct.unpack_from(f"<{nrow_toks}i", blob, off))
        off += need
        rows.append(toks)
    if off != end:
        raise ValueError("extra bytes in payload")
    return rows


def encode_cb02(rows):
    payload = bytearray()
    for toks in rows:
        payload += struct.pack("<H", len(toks))
        if toks:
            payload += struct.pack(f"<{len(toks)}i", *toks)
    return b"CB02" + struct.pack("<ii", len(rows), len(payload)) + bytes(payload)


def encode_v1(rows):
    out = bytearray()
    for rid, toks in enumerate(rows):
        out += struct.pack("<i", rid)
        if toks:
            out += struct.pack(f"<{len(toks)}i", *toks)
    return bytes(out)


def make_enabled_file(policy_src: Path, enabled_dst: Path, k: int):
    lines = [ln for ln in policy_src.read_text().splitlines() if ln.strip()]
    enabled_dst.write_text("\n".join(lines[:k]) + "\n")


def run_count_query(
    db: str,
    user: str,
    query_sql: str,
    policy_path: str,
    custom_filter_so: str,
    host: str | None = None,
):
    sql = f"""
LOAD '{custom_filter_so}';
SET statement_timeout='120s';
SET max_parallel_workers_per_gather=0;
SET enable_indexonlyscan=off;
SET enable_tidscan=off;
SET custom_filter.enabled=on;
SET custom_filter.contract_mode=off;
SET custom_filter.debug_mode='off';
SET custom_filter.policy_path='{policy_path}';
{query_sql};
"""
    return psql_file(db, user, sql, on_error_stop=False, host=host)


def main():
    ap = argparse.ArgumentParser(description="CB02 decoder regression checks")
    ap.add_argument("--db", default="tpch0_01")
    ap.add_argument("--k", type=int, default=20)
    ap.add_argument("--query-id", type=int, default=22)
    ap.add_argument("--table", default="customer")
    ap.add_argument("--policy", default="/tmp/z3_lab/policy.txt")
    ap.add_argument("--enabled", default="/tmp/z3_lab/policies_enabled_cb02_regress.txt")
    ap.add_argument("--queries", default="queries.txt")
    ap.add_argument("--custom-filter-so", default="/tmp/z3_lab/custom_filter.so")
    ap.add_argument("--artifact-builder-so", default="/tmp/z3_lab/artifact_builder.so")
    ap.add_argument("--admin-user", default="postgres")
    ap.add_argument("--query-user", default="postgres")
    ap.add_argument("--host", default="")
    ap.add_argument("--out-dir", default="logs/drona/cb02_decoder_regression")
    args = ap.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    policy_src = Path(args.policy)
    enabled_path = Path(args.enabled)
    make_enabled_file(policy_src, enabled_path, args.k)
    (out_dir / "enabled_policies.txt").write_text(enabled_path.read_text())

    setup_sql = f"""
DROP FUNCTION IF EXISTS public.build_base(text);
CREATE FUNCTION public.build_base(text) RETURNS void
AS '{args.artifact_builder_so}', 'build_base'
LANGUAGE C STRICT;
DELETE FROM public.files;
SELECT public.build_base('{enabled_path}');
"""
    host = args.host if args.host else None
    setup = psql_file(args.db, args.admin_user, setup_sql, on_error_stop=True, host=host)
    (out_dir / "setup.out").write_text(setup.stdout + setup.stderr)

    art_name = f"{args.table}_code_base"
    get_hex = psql_sql(
        args.db,
        args.admin_user,
        f"SELECT encode(file,'hex') FROM public.files WHERE name='{art_name}';",
        host=host,
    )
    hex_blob = get_hex.stdout.strip()
    if not hex_blob:
        raise RuntimeError(f"missing artifact row for {art_name}")
    blob = bytes.fromhex(hex_blob)
    (out_dir / "artifact_magic.txt").write_text(blob[:4].hex() + "\n")

    rows = decode_cb02(blob)
    reencoded = encode_cb02(rows)
    if reencoded != blob:
        raise RuntimeError("CB02 roundtrip mismatch")
    (out_dir / "roundtrip.txt").write_text(
        f"table={args.table}\nrows={len(rows)}\nstatus=cb02_roundtrip_ok\n"
    )

    # Use a direct table COUNT query so the target table artifact is always exercised.
    qsql = f"SELECT COUNT(*) FROM {args.table}"
    (out_dir / "query.sql").write_text(qsql + ";\n")

    original_path = Path("/tmp") / f"{art_name}.orig.bin"
    corrupt_path = Path("/tmp") / f"{art_name}.corrupt.bin"
    v1_path = Path("/tmp") / f"{art_name}.v1.bin"
    original_path.write_bytes(blob)
    corrupt = bytearray(blob)
    # Force deterministic decoder failure by corrupting CB02 payload_len header.
    payload_len = struct.unpack_from("<i", blob, 8)[0]
    struct.pack_into("<i", corrupt, 8, payload_len + 1)
    corrupt_path.write_bytes(bytes(corrupt))
    v1_path.write_bytes(encode_v1(rows))

    def update_artifact_from(path: Path):
        psql_sql(
            args.db,
            args.admin_user,
            (
                f"UPDATE public.files SET file=pg_read_binary_file('{path}') "
                f"WHERE name='{art_name}';"
            ),
            host=host,
        )

    update_artifact_from(corrupt_path)
    corrupt_run = run_count_query(args.db, args.query_user, qsql, str(enabled_path), args.custom_filter_so, host=host)
    (out_dir / "corrupt_run.out").write_text(corrupt_run.stdout + corrupt_run.stderr)
    if "invalid CB02 code_base artifact" not in (corrupt_run.stdout + corrupt_run.stderr):
        raise RuntimeError("corrupt CB02 did not fail with expected error message")

    update_artifact_from(v1_path)
    v1_run = run_count_query(args.db, args.query_user, qsql, str(enabled_path), args.custom_filter_so, host=host)
    (out_dir / "v1_run.out").write_text(v1_run.stdout + v1_run.stderr)
    if "ERROR:" in (v1_run.stdout + v1_run.stderr):
        raise RuntimeError("v1 fallback run failed")

    update_artifact_from(original_path)
    restored_run = run_count_query(args.db, args.query_user, qsql, str(enabled_path), args.custom_filter_so, host=host)
    (out_dir / "restored_run.out").write_text(restored_run.stdout + restored_run.stderr)
    if "ERROR:" in (restored_run.stdout + restored_run.stderr):
        raise RuntimeError("restored CB02 run failed")

    (out_dir / "summary.txt").write_text(
        "cb02_roundtrip=ok\n"
        "corrupt_cb02_error=ok\n"
        "v1_fallback=ok\n"
        "restored_cb02=ok\n"
    )


if __name__ == "__main__":
    main()
