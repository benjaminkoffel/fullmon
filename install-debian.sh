#!/usr/bin/env bash

set -eux

apt update
apt install -y auditd
cp audit.rules /etc/audit/rules.d/
service auditd restart
cp fullmon fullmon.sh /usr/local/bin/
cp fullmon.service /etc/systemd/system/
service fullmon start
