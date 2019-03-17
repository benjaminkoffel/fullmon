#!/usr/bin/env bash

set -euxo pipefail

apt update
apt install -y auditd python3
cp audit.rules /etc/audit/rules.d/
service auditd restart
rm -rf /opt/fullmon/
cp -r agent/ /opt/fullmon/
service fullmon restart
