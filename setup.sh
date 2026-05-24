#!/usr/bin/env bash
# Bootstrap the Mini Static Findings Scanner (Linux / macOS).
# Creates a virtual environment, installs pinned dependencies, and installs the
# `scanner` command. Run once, then activate the venv to use `scanner`.
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"

echo "==> Creating virtual environment in .venv ..."
"$PY" -m venv .venv

echo "==> Upgrading pip ..."
.venv/bin/python -m pip install --upgrade pip >/dev/null

echo "==> Installing pinned dependencies ..."
.venv/bin/python -m pip install -r requirements.txt

echo "==> Installing the scanner (editable) ..."
.venv/bin/python -m pip install -e . --no-deps

echo ""
echo "Done. Use the scanner like this:"
echo "    source .venv/bin/activate"
echo "    scanner ./sample-project"
echo ""
echo "Or without activating:"
echo "    .venv/bin/scanner ./sample-project"
