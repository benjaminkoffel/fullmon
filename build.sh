#!/bin/bash

set -euo pipefail

python3 -m pip install -q nuitka --upgrade
python3 -m nuitka --follow-imports agent/agent.py
rm -rf agent.build
mv agent.bin fullmon
