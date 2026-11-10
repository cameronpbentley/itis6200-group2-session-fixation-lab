#!/usr/bin/env bash
# One command: create venv, install deps, run the full demo.
set -e
cd "$(dirname "$0")"
python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
python demo.py -v
