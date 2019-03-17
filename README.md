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
debian@debian:/var/log$ tail -f fullmon.log 
2019-03-17 17:47:58,984	INFO	initialize
2019-03-17 17:47:58,985	INFO	monitor
2019-03-17 17:48:09,165	INFO	analyze
2019-03-17 17:48:09,354	INFO	ignore /opt/fullmon/__pycache__/[^/]+
2019-03-17 17:48:09,355	INFO	ignore /dev/shm/[^/]+
2019-03-17 17:48:09,356	INFO	ignore /run/systemd/generator\.late/[^/]+
2019-03-17 17:48:09,356	INFO	ignore \.git/objects/[^/]+
2019-03-17 17:48:09,357	INFO	ignore /var/lib/apt/lists/partial/[^/]+
2019-03-17 17:48:09,357	INFO	ignore /tmp/[^/]+
2019-03-17 17:48:09,358	INFO	ignore /tmp/[^/]+/[^/]+
2019-03-17 17:48:09,359	INFO	ignore /opt/fullmon/[^/]+
2019-03-17 17:48:09,359	INFO	ignore /home/debian/\.local/share/keyrings/[^/]+
2019-03-17 17:48:09,360	INFO	ignore \.git/objects/[^/]+/[^/]+
2019-03-17 17:48:09,361	INFO	ignore /var/cache/apt/[^/]+
2019-03-17 17:48:09,361	INFO	monitor
2019-03-17 17:48:19,422	INFO	analyze
...
2019-03-17 17:48:59,873	INFO	monitor
2019-03-17 17:49:09,961	INFO	analyze
2019-03-17 17:49:09,967	WARNING	host:151.101.65.140:80
2019-03-17 17:49:09,968	WARNING	file:CREATE:blah.txt
2019-03-17 17:49:09,968	WARNING	proc::1000:Chrome_IOThread
2019-03-17 17:49:09,969	WARNING	proc::1000:touch->file:CREATE:blah.txt
2019-03-17 17:49:09,969	WARNING	proc::1000:curl->host:151.101.65.140:80
```

## References

- http://snap.stanford.edu/class/cs224w-2015/projects_2015/Anomaly_Detection_in_Graphs.pdf
- https://www.sciencedirect.com/science/article/pii/S2352664516300177
- https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files
