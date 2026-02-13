#!/usr/bin/env bash
set -euo pipefail

PGHOST="${PGHOST:-localhost}"
PGPORT="${PGPORT:-5432}"
PGUSER="${PGUSER:-postgres}"
PGPASSWORD="${PGPASSWORD:-12345}"

POLICY_FILE="${POLICY_FILE:-policy_supported.txt}"
POLICY_POOL="${POLICY_POOL:-1-20}"
ARTIFACT_BUILDER_SO="${ARTIFACT_BUILDER_SO:-/tmp/z3_lab/artifact_builder.so}"

DBS=(${DBS:-tpch0_01 tpch0_1 tpch1 tpch10})
KS=(${KS:-1 15 20})
REPS="${REPS:-3}"

OUT="${OUT:-build_vs_index_bench.csv}"
LOG_DIR="${LOG_DIR:-bench/logs/build_vs_index_$(date +%Y%m%d_%H%M%S)}"
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

RUN_RC=0
RUN_WALL_S="0"
RUN_BACKEND_PID=""
RUN_BACKEND_PEAK_RSS_KB=0

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

ns_delta_to_s() {
  local start_ns="$1"
  local end_ns="$2"
  python3 - "$start_ns" "$end_ns" <<'PY'
import sys
s = int(sys.argv[1])
e = int(sys.argv[2])
print(f"{(e - s) / 1_000_000_000.0:.6f}")
PY
}

sample_vm_hwm_kb() {
  local backend_pid="$1"
  if [[ ! -r "/proc/$backend_pid/status" ]]; then
    return 0
  fi
  awk '/VmHWM:/{print $2; exit}' "/proc/$backend_pid/status" 2>/dev/null || true
}

run_psql_with_sampling() {
  local db="$1"
  local out_file="$2"
  shift 2
  local -a psql_args=("$@")

  RUN_RC=0
  RUN_WALL_S="0"
  RUN_BACKEND_PID=""
  RUN_BACKEND_PEAK_RSS_KB=0

  local start_ns end_ns psql_pid candidate hwm
  start_ns="$(date +%s%N)"

  PGPASSWORD="$PGPASSWORD" "${PSQL[@]}" -d "$db" "${psql_args[@]}" > "$out_file" 2>&1 &
  psql_pid=$!

  while kill -0 "$psql_pid" 2>/dev/null; do
    if [[ -z "$RUN_BACKEND_PID" ]]; then
      candidate="$(sed -n 's/^__BACKEND_PID__[[:space:]]*//p' "$out_file" | head -n 1 | tr -d '\r' | awk '{print $1}')"
      if [[ "$candidate" =~ ^[0-9]+$ ]]; then
        RUN_BACKEND_PID="$candidate"
      fi
    fi

    if [[ "$RUN_BACKEND_PID" =~ ^[0-9]+$ ]]; then
      hwm="$(sample_vm_hwm_kb "$RUN_BACKEND_PID")"
      if [[ "$hwm" =~ ^[0-9]+$ ]] && (( hwm > RUN_BACKEND_PEAK_RSS_KB )); then
        RUN_BACKEND_PEAK_RSS_KB="$hwm"
      fi
    fi
    sleep 0.02
  done

  set +e
  wait "$psql_pid"
  RUN_RC=$?
  set -e

  if [[ "$RUN_BACKEND_PID" =~ ^[0-9]+$ ]]; then
    hwm="$(sample_vm_hwm_kb "$RUN_BACKEND_PID")"
    if [[ "$hwm" =~ ^[0-9]+$ ]] && (( hwm > RUN_BACKEND_PEAK_RSS_KB )); then
      RUN_BACKEND_PEAK_RSS_KB="$hwm"
    fi
  fi

  end_ns="$(date +%s%N)"
  RUN_WALL_S="$(ns_delta_to_s "$start_ns" "$end_ns")"
}

echo "ts,git_commit,db,K,rep,task,wall_s,backend_peak_rss_kb,bytes,rows,tables" > "$OUT"
GIT_COMMIT="${GIT_COMMIT_OVERRIDE:-$(git rev-parse --short HEAD 2>/dev/null || echo unknown)}"

for db in "${DBS[@]}"; do
  echo "[prep] db=$db VACUUM (ANALYZE)"
  PGPASSWORD="$PGPASSWORD" "${PSQL[@]}" -d "$db" -c "VACUUM (ANALYZE);" >/dev/null

  sanity_file="$LOG_DIR/${db}.sanity_counts.txt"
  PGPASSWORD="$PGPASSWORD" "${PSQL[@]}" -d "$db" -c \
    "SELECT 'customer' AS rel, count(*) AS rows FROM customer UNION ALL SELECT 'orders', count(*) FROM orders UNION ALL SELECT 'lineitem', count(*) FROM lineitem ORDER BY 1;" \
    > "$sanity_file"
  echo "[sanity] db=$db $(tr '\n' ';' < "$sanity_file" | sed 's/;*$//')"

  for k in "${KS[@]}"; do
    for rep in $(seq 1 "$REPS"); do
      ts="$(date -Is)"
      run_tag="${db}_k${k}_rep${rep}"

      enabled_policy="$(mktemp "/tmp/policies_enabled_${db}_k${k}_rep${rep}_XXXX.txt")"
      head -n "$k" "$POLICY_FILE" > "$enabled_policy"
      chmod 0644 "$enabled_policy"

      python3 bench/extract_rls_indexes.py \
        --policy-file "$POLICY_FILE" \
        --policy-pool "$POLICY_POOL" \
        --k "$k" \
        --out-sql bench/rls_indexes.sql \
        --out-drop-sql bench/rls_indexes_drop.sql \
        --out-names-sql bench/rls_index_names.sql \
        --manifest "$LOG_DIR/${run_tag}.rls_manifest.json" \
        > "$LOG_DIR/${run_tag}.extract.log" 2>&1

      artifact_out="$LOG_DIR/${run_tag}.artifact.out"
      run_psql_with_sampling \
        "$db" \
        "$artifact_out" \
        -v "K=$k" \
        -v "POLICY_PATH=$enabled_policy" \
        -v "ARTIFACT_BUILDER_SO=$ARTIFACT_BUILDER_SO" \
        -f bench/bench_artifact_build.sql

      if [[ "$RUN_RC" -ne 0 ]]; then
        echo "artifact_build failed: db=$db K=$k rep=$rep (see $artifact_out)" >&2
        rm -f "$enabled_policy"
        exit "$RUN_RC"
      fi

      artifact_bytes="$(extract_after_marker "__ARTIFACT_TOTAL_BYTES__" "$artifact_out" | awk -F'|' 'NR==1{print $1}')"
      artifact_rows="$(extract_after_marker "__ARTIFACT_TOTAL_ROWS__" "$artifact_out" | awk -F'|' 'NR==1{print $1}')"
      artifact_tables="$(extract_after_marker "__ARTIFACT_TABLE_COUNT__" "$artifact_out" | awk -F'|' 'NR==1{print $1}')"
      artifact_bytes="${artifact_bytes:-0}"
      artifact_rows="${artifact_rows:-0}"
      artifact_tables="${artifact_tables:-0}"

      echo "$ts,$GIT_COMMIT,$db,$k,$rep,artifact_build,$RUN_WALL_S,$RUN_BACKEND_PEAK_RSS_KB,$artifact_bytes,$artifact_rows,$artifact_tables" >> "$OUT"
      echo "[ok] db=$db K=$k rep=$rep task=artifact_build wall_s=$RUN_WALL_S bytes=$artifact_bytes rows=$artifact_rows tables=$artifact_tables rss=$RUN_BACKEND_PEAK_RSS_KB"

      index_out="$LOG_DIR/${run_tag}.rls_index.out"
      run_psql_with_sampling \
        "$db" \
        "$index_out" \
        -v "K=$k" \
        -f bench/bench_rls_index_build.sql

      if [[ "$RUN_RC" -ne 0 ]]; then
        echo "rls_index_build failed: db=$db K=$k rep=$rep (see $index_out)" >&2
        rm -f "$enabled_policy"
        exit "$RUN_RC"
      fi

      index_bytes="$(extract_after_marker "__RLS_INDEX_TOTAL_BYTES__" "$index_out" | awk -F'|' 'NR==1{print $1}')"
      index_bytes="${index_bytes:-0}"

      echo "$ts,$GIT_COMMIT,$db,$k,$rep,rls_index_build,$RUN_WALL_S,$RUN_BACKEND_PEAK_RSS_KB,$index_bytes,0,0" >> "$OUT"
      echo "[ok] db=$db K=$k rep=$rep task=rls_index_build wall_s=$RUN_WALL_S bytes=$index_bytes rss=$RUN_BACKEND_PEAK_RSS_KB"

      rm -f "$enabled_policy"
    done
  done
done

echo "Wrote $OUT"
echo "Logs in $LOG_DIR"
