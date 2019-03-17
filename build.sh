#!/usr/bin/env bash

set -euxo pipefail

python3 -m unittest discover -s agent/ -v
tar -zcvf fullmon.tar.gz agent/
