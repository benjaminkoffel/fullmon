#!/bin/bash

set -euxo pipefail

python3 -m unittest discover -s agent/ -v
sudo python3 -m pip install nuitka --upgrade
python3 -m nuitka --follow-imports -o fullmon agent/agent.py
