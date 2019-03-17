# fullmon

[![CircleCI](https://circleci.com/gh/benjaminkoffel/fullmon.svg?style=svg)](https://circleci.com/gh/benjaminkoffel/fullmon)

An experimental host intrusion detection system using behaviour anomaly detection.

The agent consumes logs produced by auditd to monitor process execution, network connections and file modifications.

It works by building a baseline and then periodically compares that to observed behaviour.

There is also a rebase option available to continually update the baseline to reduce noise.

The use case for this system is the monitoring of static servers that are not prone to manual user interaction.

To do is the consumption of DNS request answers to reduce false positives caused by ephemeral IP addresses.

## Usage

```
# install python3 and auditd with verbose rules
sudo apt install -y python3 auditd
sudo cp audit.rules /etc/audit/rules.d/
sudo service auditd restart

# run monitoring on cli
sudo ./agent/agent.py
sudo ./agent/agent.py --auditd /var/log/audit/audit.log --baseline 3600 --monitor 60 --rebase

# run tests and package
./build.sh

# install from bundled package
wget https://circleci.com/api/v1/project/benjaminkoffel/fullmon/latest/artifacts/0/home/circleci/project/fullmon.tar.gz
tar -xvzf fullmon.tar.gz
sudo ./install-debian.sh
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
