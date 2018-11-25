#!/usr/bin/env bash

set -eux

apt update
apt install -y auditd
cp audit.rules /etc/audit/rules.d/
service auditd restart
rm -rf /usr/local/bin/fullmon/
cp -r agent.dist/ /usr/local/bin/fullmon/
cp fullmon.sh /usr/local/bin/
service fullmon restart
