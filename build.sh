#!/usr/bin/env bash

set -eux

python3 -m unittest discover -s agent/ -v
python3 -m pip install --user nuitka --upgrade
python3 -m nuitka --follow-imports -o fullmon agent/agent.py
tar -zcvf fullmon.tar.gz fullmon fullmon.sh fullmon.service fullmon.conf audit.rules install-debian.sh
