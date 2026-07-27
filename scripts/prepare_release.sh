#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3.13 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python scripts/verify_release.py --full "$@"
git status --short --branch
