#!/usr/bin/env bash
# Bootstrap a virtualenv and install deps.
# Re-run safely: if .venv already exists, it is reused.
set -euo pipefail

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Error: $PYTHON not found. Install Python 3.10+ or set PYTHON=/path/to/python." >&2
  exit 1
fi

if [ ! -d "$VENV_DIR" ]; then
  echo ">>> Creating virtualenv at $VENV_DIR"
  "$PYTHON" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo ">>> Upgrading pip"
python -m pip install --upgrade pip

echo ">>> Installing requirements"
pip install -r requirements.txt

if [ ! -f ".env" ]; then
  echo ">>> Creating .env from .env.example (replace the placeholder secrets!)"
  cp .env.example .env
fi

cat <<'EOF'

Done. To run the API:

  source .venv/bin/activate
  uvicorn main:app --reload

Docs: http://localhost:8000/docs
EOF