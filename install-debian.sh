#!/usr/bin/env bash

set -euxo pipefail

apt update
apt install -y auditd python3
cp audit.rules /etc/audit/rules.d/
service auditd restart
rm -rf /opt/fullmon
cp -r agent/ /opt/fullmon
chmod 700 /opt/fullmon
cp fullmon.sh /opt/fullmon
cp fullmon.service /etc/systemd/system/
chmod 700 /etc/systemd/system/fullmon.service
touch /var/log/fullmon.log
chmod 600 /var/log/fullmon.log
service fullmon restart
systemctl daemon-reload
