# fullmon

Poor man's EDR using Auditd and Dnsmasq. 

Process execution, network connections and file modifications are logged via Auditd to `/var/log/audit/audit.log`.

DNS traffic is proxied and logged via Dnsmasq to `/var/log/dns.log` and can be correlated to network connections.

The generated logs are intended to be shipped to event storage where analysts can define use cases.

The size of logs generated is excessive but the project's aim is just to demonstrate an incident response / threat hunting capability can be obtained with readily available system tools.

A work in progress is an agent that uses comparison of machine behaviour graphs to detect anomalies.

## Usage

```
sh install.sh
python3 agent.py --auditd /var/log/audit/audit.log --baseline 60 --monitor 10
```

## Example

```
$ sudo python3 agent.py --auditd /var/log/audit/audit.log --baseline 5 --monitor 10
2018-10-26 06:33:57,684	root	INFO	baseline
2018-10-26 06:34:03,725	root	INFO	collect
2018-10-26 06:34:14,790	root	INFO	detect
2018-10-26 06:34:14,916	root	INFO	collect
2018-10-26 06:34:25,991	root	INFO	detect
2018-10-26 06:34:25,993	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.192.176:0
2018-10-26 06:34:25,997	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.192.145:0
2018-10-26 06:34:25,998	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.192.221:0
2018-10-26 06:34:25,999	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.193.171:0
2018-10-26 06:34:26,000	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.192.176:0
2018-10-26 06:34:26,006	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.192.145:0
2018-10-26 06:34:26,007	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.192.221:0
2018-10-26 06:34:26,010	root	INFO	ANOMALY DETECTED: proc:0:/usr/bin/traceroute.db->host:104.36.193.171:0
2018-10-26 06:34:26,105	root	INFO	collect
2018-10-26 06:34:37,192	root	INFO	detect
```

## References

- http://snap.stanford.edu/class/cs224w-2015/projects_2015/Anomaly_Detection_in_Graphs.pdf
- https://www.sciencedirect.com/science/article/pii/S2352664516300177
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files
