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
$ python3 agent.py --auditd /var/log/audit/audit.log --baseline 10 --monitor 10
2018-10-27 18:49:39,807	INFO	baseline
2018-10-27 18:49:50,821	INFO	collect
2018-10-27 18:50:01,886	INFO	detect
2018-10-27 18:50:01,949	INFO	collect
2018-10-27 18:50:12,959	INFO	detect
2018-10-27 18:50:13,045	INFO	collect
2018-10-27 18:50:24,057	INFO	detect
2018-10-27 18:50:24,066	WARNING	proc:1000:/usr/bin/curl->host:67.195.231.10:80
2018-10-27 18:50:24,066	WARNING	proc:1000:/usr/bin/curl->host:188.125.72.165:80
2018-10-27 18:50:24,066	WARNING	proc:1000:/usr/bin/curl->host:124.108.115.87:80
2018-10-27 18:50:24,067	WARNING	proc:1000:/usr/bin/curl->host:66.218.87.12:80
2018-10-27 18:50:24,113	INFO	collect
```

## References

- http://snap.stanford.edu/class/cs224w-2015/projects_2015/Anomaly_Detection_in_Graphs.pdf
- https://www.sciencedirect.com/science/article/pii/S2352664516300177
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files
