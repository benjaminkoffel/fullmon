#!/usr/bin/env bash

set -eux

python3 -m unittest discover -s agent/ -v
python3 -m pip install --user nuitka --upgrade
python3 -m nuitka --standalone --follow-imports agent/agent.py
tar -zcvf fullmon.tar.gz agent.dist/ fullmon.sh fullmon.service fullmon.conf audit.rules install-debian.sh
