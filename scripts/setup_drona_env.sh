#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${1:-/home/nghosh/setu}"
cd "$ROOT_DIR"

python3 -m venv venv
source venv/bin/activate
python -m pip install --no-index --find-links wheels pip setuptools wheel || true

if [ -d wheels ] && [ "$(find wheels -type f | wc -l)" -gt 0 ]; then
  python -m pip install --no-index --find-links wheels \
    psycopg2-binary numpy pandas matplotlib seaborn scipy plotly scikit-learn statsmodels openpyxl jupyterlab notebook ipykernel
else
  echo "[setup_drona_env] wheels directory is empty; cannot install offline packages" >&2
  exit 2
fi

python - <<'PY'
mods=['psycopg2','numpy','pandas','matplotlib','seaborn','scipy','plotly','sklearn','statsmodels','openpyxl','jupyterlab']
ok=True
for m in mods:
    try:
        __import__(m)
        print(f"OK {m}")
    except Exception as exc:
        ok=False
        print(f"FAIL {m}: {exc}")
if not ok:
    raise SystemExit(1)
PY

echo "[setup_drona_env] done: $ROOT_DIR/venv"
