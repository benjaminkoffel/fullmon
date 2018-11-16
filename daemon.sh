#!/bin/sh
python3 /opt/fullmon/agent.py --auditd /var/log/audit/audit.log --baseline 3600 --monitor 60 --rebase >> /var/log/fullmon.log
