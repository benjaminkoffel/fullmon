#!/bin/sh
python3 /opt/fullmon/agent.py --auditd /var/log/audit/audit.log --baseline 5 --monitor 10 >> /var/log/fullmon.log