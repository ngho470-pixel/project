#!/usr/bin/env bash
set -euo pipefail

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"
PGPASSWORD="${PGPASSWORD:-12345}"

POLICY_FILE="${POLICY_FILE:-policy_supported.txt}"
ARTIFACT_BUILDER_SO="${ARTIFACT_BUILDER_SO:-/tmp/z3_lab/artifact_builder.so}"

DBS=(${DBS:-tpch0_01 tpch0_1 tpch1 tpch10})
KS=(${KS:-1 15 20})
REPS="${REPS:-3}"

OUT="${OUT:-artifact_build_bench.csv}"
LOG_DIR="${LOG_DIR:-bench/logs/artifact_build_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$LOG_DIR"

PSQL=(
  psql
  -X
  -A
  -t
  -P pager=off
  -v ON_ERROR_STOP=1
  -h "$PGHOST"
  -p "$PGPORT"
  -U "$PGUSER"
)

if [[ ! -f "$POLICY_FILE" ]]; then
  echo "missing POLICY_FILE: $POLICY_FILE" >&2
  exit 1
fi

extract_after_marker() {
  local marker="$1"
  local path="$2"
  awk -v marker="$marker" '
    $0 == marker {
      while (getline > 0) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
        if ($0 != "") {
          print $0
          exit
        }
      }
    }
  ' "$path"
}

wall_to_seconds() {
  local wall="$1"
  python3 - "$wall" <<'PY'
import sys
t = (sys.argv[1] or "").strip()
if not t:
    print("0")
    raise SystemExit(0)
parts = t.split(":")
if len(parts) == 3:
    h, m, s = parts
    print(float(h) * 3600.0 + float(m) * 60.0 + float(s))
elif len(parts) == 2:
    m, s = parts
    print(float(m) * 60.0 + float(s))
else:
    print(float(t))
PY
}

echo "ts,git_commit,db,K,rep,wall_s,user_s,sys_s,maxrss_kb,total_bytes,total_rows,artifact_tables" > "$OUT"
GIT_COMMIT="${GIT_COMMIT_OVERRIDE:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"

for db in "${DBS[@]}"; do
  echo "[prep] db=$db VACUUM (ANALYZE)"
  PGPASSWORD="$PGPASSWORD" "${PSQL[@]}" -d "$db" -c "VACUUM (ANALYZE);" >/dev/null

  for k in "${KS[@]}"; do
    for rep in $(seq 1 "$REPS"); do
      ts="$(date -Is)"
      enabled_policy="$(mktemp "/tmp/policies_enabled_${db}_k${k}_rep${rep}_XXXX.txt")"
      tmp_out="$(mktemp)"
      tmp_time="$(mktemp)"
      run_tag="${db}_k${k}_rep${rep}"

      head -n "$k" "$POLICY_FILE" > "$enabled_policy"
      chmod 0644 "$enabled_policy"

      set +e
      PGPASSWORD="$PGPASSWORD" /usr/bin/time -v -o "$tmp_time" \
        "${PSQL[@]}" \
        -d "$db" \
        -v K="$k" \
        -v POLICY_PATH="$enabled_policy" \
        -v ARTIFACT_BUILDER_SO="$ARTIFACT_BUILDER_SO" \
        -f bench/bench_artifact_build.sql \
        > "$tmp_out" 2>&1
      rc=$?
      set -e

      cp "$tmp_out" "$LOG_DIR/${run_tag}.out"
      cp "$tmp_time" "$LOG_DIR/${run_tag}.timev"
      printf '%s\n' "$enabled_policy" > "$LOG_DIR/${run_tag}.policy_path.txt"

      if [[ "$rc" -ne 0 ]]; then
        echo "run failed: db=$db K=$k rep=$rep (see $LOG_DIR/${run_tag}.out)" >&2
        rm -f "$enabled_policy" "$tmp_out" "$tmp_time"
        exit "$rc"
      fi

      wall_raw="$(sed -n 's/^.*Elapsed (wall clock) time.*: *//p' "$tmp_time" | head -n 1)"
      user_s="$(sed -n 's/^.*User time (seconds): *//p' "$tmp_time" | head -n 1)"
      sys_s="$(sed -n 's/^.*System time (seconds): *//p' "$tmp_time" | head -n 1)"
      maxrss_kb="$(sed -n 's/^.*Maximum resident set size (kbytes): *//p' "$tmp_time" | head -n 1)"
      wall_s="$(wall_to_seconds "${wall_raw:-0}")"

      total_bytes="$(extract_after_marker "__ARTIFACT_TOTAL_BYTES__" "$tmp_out" | awk -F'|' 'NR==1{print $1}')"
      total_rows="$(extract_after_marker "__ARTIFACT_TOTAL_ROWS__" "$tmp_out" | awk -F'|' 'NR==1{print $1}')"
      artifact_tables="$(extract_after_marker "__ARTIFACT_TABLE_COUNT__" "$tmp_out" | awk -F'|' 'NR==1{print $1}')"

      total_bytes="${total_bytes:-0}"
      total_rows="${total_rows:-0}"
      artifact_tables="${artifact_tables:-0}"
      user_s="${user_s:-0}"
      sys_s="${sys_s:-0}"
      maxrss_kb="${maxrss_kb:-0}"

      echo "$ts,$GIT_COMMIT,$db,$k,$rep,$wall_s,$user_s,$sys_s,$maxrss_kb,$total_bytes,$total_rows,$artifact_tables" >> "$OUT"

      rm -f "$enabled_policy" "$tmp_out" "$tmp_time"
      echo "[ok] db=$db K=$k rep=$rep wall_s=$wall_s bytes=$total_bytes rows=$total_rows"
    done
  done
done

echo "Wrote $OUT"
echo "Logs in $LOG_DIR"
