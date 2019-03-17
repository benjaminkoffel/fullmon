#!/usr/bin/env bash

set -euxo pipefail

python3 -m unittest discover -s agent -v
tar -zcvf fullmon.tar.gz audit.rules fullmon.conf fullmon.service fullmon.sh install-debian.sh agent/*.py
