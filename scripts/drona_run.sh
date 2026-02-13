#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  scripts/drona_run.sh [options] -- <remote command>
  scripts/drona_run.sh [options]

Options:
  --host <user@host>       Remote SSH host (default: nghosh@drona.cse.iitd.ac.in)
  --remote-root <path>     Remote working directory (default: /tmp/z3_lab/project)
  --full-tree              Include heavy local dirs (cvc/, cvc5/) in sync
  --no-sync                Skip local -> remote sync
  --no-pull                Skip remote -> local sync
  -h, --help               Show this help

Notes:
  - By default this script excludes cvc/ and cvc5/ for faster syncs.
  - If a remote command is provided, it runs inside <remote-root>.
  - Remote outputs are pulled back even if the remote command fails.
EOF
}

HOST="nghosh@drona.cse.iitd.ac.in"
REMOTE_ROOT="/tmp/z3_lab/project"
SYNC_PUSH=1
SYNC_PULL=1
FULL_TREE=0

while (($# > 0)); do
  case "$1" in
    --host)
      HOST="$2"
      shift 2
      ;;
    --remote-root)
      REMOTE_ROOT="$2"
      shift 2
      ;;
    --full-tree)
      FULL_TREE=1
      shift
      ;;
    --no-sync)
      SYNC_PUSH=0
      shift
      ;;
    --no-pull)
      SYNC_PULL=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

REMOTE_CMD=()
if (($# > 0)); then
  REMOTE_CMD=("$@")
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

SSH_OPTS=(-o ConnectTimeout=10 -o StrictHostKeyChecking=no)
RSYNC_RSH=(ssh "${SSH_OPTS[@]}")
BASE_EXCLUDES=(
  --exclude=.git/
  --exclude=__pycache__/
  --exclude=.pytest_cache/
  --exclude=.mypy_cache/
)
if [[ "$FULL_TREE" -eq 0 ]]; then
  BASE_EXCLUDES+=(--exclude=cvc/ --exclude=cvc5/)
fi
PUSH_EXCLUDES=("${BASE_EXCLUDES[@]}" --exclude=logs/)
PULL_EXCLUDES=("${BASE_EXCLUDES[@]}")

echo "[remote] host=$HOST"
echo "[remote] root=$REMOTE_ROOT"

ssh "${SSH_OPTS[@]}" "$HOST" "mkdir -p $(printf '%q' "$REMOTE_ROOT")"

if [[ "$SYNC_PUSH" -eq 1 ]]; then
  echo "[sync] local -> remote"
  RSYNC_RSH="${RSYNC_RSH[*]}" rsync -az --delete "${PUSH_EXCLUDES[@]}" ./ "$HOST:$REMOTE_ROOT/"
fi

run_rc=0
if ((${#REMOTE_CMD[@]} > 0)); then
  remote_cmd_str="${REMOTE_CMD[*]}"
  echo "[run] $remote_cmd_str"
  set +e
  ssh "${SSH_OPTS[@]}" "$HOST" "cd $(printf '%q' "$REMOTE_ROOT") && bash -lc $(printf '%q' "$remote_cmd_str")"
  run_rc=$?
  set -e
  echo "[run] exit_code=$run_rc"
fi

if [[ "$SYNC_PULL" -eq 1 ]]; then
  echo "[sync] remote -> local"
  RSYNC_RSH="${RSYNC_RSH[*]}" rsync -az "${PULL_EXCLUDES[@]}" "$HOST:$REMOTE_ROOT/" ./
fi

echo "[done]"
exit "$run_rc"
