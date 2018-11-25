# fullmon

[![CircleCI](https://circleci.com/gh/benjaminkoffel/fullmon.svg?style=svg)](https://circleci.com/gh/benjaminkoffel/fullmon)

Poor man's EDR using Auditd and Dnsmasq. 

Process execution, network connections and file modifications are logged via Auditd to `/var/log/audit/audit.log`.

DNS traffic is proxied and logged via Dnsmasq to `/var/log/dns.log` and can be correlated to network connections.

The generated logs are intended to be shipped to event storage where analysts can define use cases.

The size of logs generated is excessive but the project's aim is just to demonstrate an incident response / threat hunting capability can be obtained with readily available system tools.

A work in progress is an agent that uses comparison of machine behaviour graphs to detect anomalies. The `--rebase` switch
enables continuous update of the baseline behaviour graph with newly detected anomalous behaviour to create a rolling
baseline. Ignore patterns to reduce noise from temp file modifications are also calculated at baseline creation and rebasing to reduce false positives.

## Usage

```
# run tests and build statically linked binary
sh build.sh

# install as systemd service
sudo sh install-debian.sh

# run monitoring on cli
python3 agent/agent.py --auditd /var/log/audit/audit.log --baseline 60 --monitor 10 --rebase
```

## Example

```
$ sudo python3 agent.py --auditd /var/log/audit/audit.log --baseline 5 --monitor 5 --rebase
2018-11-10 11:06:00,203	INFO	baseline
2018-11-10 11:06:06,544	INFO	normalize
2018-11-10 11:06:07,467	INFO	+ignore /home/debian/\.local/share/gvfs\-metadata/[^/]+
2018-11-10 11:06:07,468	INFO	+ignore /opt/nessus_agent/var/nessus/[^/]+
2018-11-10 11:06:07,468	INFO	+ignore /var/cache/apt/archives/partial/[^/]+
2018-11-10 11:06:07,468	INFO	+ignore /dev/shm/[^/]+
2018-11-10 11:06:07,468	INFO	+ignore /var/lib/apt/lists/[^/]+
2018-11-10 11:06:07,469	INFO	+ignore /var/lib/apt/lists/partial/[^/]+
2018-11-10 11:06:07,469	INFO	+ignore /var/lib/upower/[^/]+
2018-11-10 11:06:07,469	INFO	+ignore /dev/char/[^/]+
2018-11-10 11:06:07,469	INFO	+ignore /run/udev/data/[^/]+
2018-11-10 11:06:07,469	INFO	+ignore /opt/nessus_agent/[^/]+/nessus/[^/]+/[^/]+
2018-11-10 11:06:07,470	INFO	+ignore \.git/objects/[^/]+/[^/]+
2018-11-10 11:06:07,470	INFO	+ignore /tmp/[^/]+
2018-11-10 11:06:07,470	INFO	+ignore /tmp/[^/]+/[^/]+
2018-11-10 11:06:07,470	INFO	prepare
2018-11-10 11:06:07,525	INFO	collect
2018-11-10 11:06:20,001	INFO	detect
...
2018-11-10 11:06:20,337	INFO	prepare
2018-11-10 11:06:20,391	INFO	collect
2018-11-10 11:06:26,441	INFO	detect
2018-11-10 11:06:26,447	WARNING	host:104.16.117.221:80
2018-11-10 11:06:26,448	WARNING	host:104.16.120.221:80
2018-11-10 11:06:26,448	WARNING	proc::1000:curl
2018-11-10 11:06:26,448	WARNING	host:104.16.119.221:80
2018-11-10 11:06:26,448	WARNING	host:104.16.118.221:80
2018-11-10 11:06:26,448	WARNING	host:104.16.116.221:80
2018-11-10 11:06:26,448	WARNING	proc::1000:curl->host:127.0.0.1:53
2018-11-10 11:06:26,448	WARNING	proc::1000:curl->host:104.16.119.221:80
2018-11-10 11:06:26,448	WARNING	proc::1000:curl->host:104.16.120.221:80
2018-11-10 11:06:26,448	WARNING	proc::1000:curl->host:None:None
2018-11-10 11:06:26,448	WARNING	proc::1000:curl->host:104.16.117.221:80
2018-11-10 11:06:26,448	WARNING	proc::1000:curl->host:None:None
2018-11-10 11:06:26,448	WARNING	proc::1000:curl->host:None:None
2018-11-10 11:06:26,449	WARNING	proc::1000:curl->host:None:None
2018-11-10 11:06:26,449	WARNING	proc::1000:curl->host:104.16.118.221:80
2018-11-10 11:06:26,449	WARNING	proc::1000:curl->host:104.16.116.221:80
```

## References

- http://snap.stanford.edu/class/cs224w-2015/projects_2015/Anomaly_Detection_in_Graphs.pdf
- https://www.sciencedirect.com/science/article/pii/S2352664516300177
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files
