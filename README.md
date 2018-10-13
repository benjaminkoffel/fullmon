# fullmon

Poor man's EDR using Auditd and Dnsmasq. 

Process execution, network connections and file modifications are logged via Auditd to `/var/log/audit/audit.log`.

DNS traffic is proxied and logged via Dnsmasq to `/var/log/dns.log` and can be correlated to network connections.

Included is `saddr.py` which demonstrates how to decode `saddr` values containing network connection information.

The generated logs are intended to be shipped to event storage where analysts can define use cases.

The size of logs generated is excessive but the project's aim is just to demonstrate an incident response / threat hunting capability can be obtained with readily available system tools.

## Usage

`sh install.sh`
