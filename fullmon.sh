#!/bin/bash

./usr/local/bin/fullmon --auditd /var/log/audit/audit.log --baseline 3600 --monitor 60 --rebase >> /var/log/fullmon.log
