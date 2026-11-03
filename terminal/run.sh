#!/usr/bin/env sh
# CyberWatch dashboard launcher (macOS / Linux): ./run.sh
set -e
cd "$(dirname "$0")"
if [ ! -x .venv/bin/python ]; then
  echo "First run: setting up the Python environment, this takes a minute..."
  python3 -m venv .venv
  .venv/bin/python -m pip install -q -r requirements.txt
fi
if [ ! -f .env ]; then
  echo "Missing .env: copy .env.example to .env and fill in your API URL and token."
  exit 1
fi
exec .venv/bin/python -m cyberwatch_tui
