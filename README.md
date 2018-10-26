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
tail -f /var/log/audit/audit.log | python3 agent.py
```

## References

- http://snap.stanford.edu/class/cs224w-2015/projects_2015/Anomaly_Detection_in_Graphs.pdf
- https://www.sciencedirect.com/science/article/pii/S2352664516300177
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files
