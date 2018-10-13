#!/usr/bin/env bash

set -e

apt update
apt install -y auditd dnsmasq
cp audit.rules /etc/audit/rules.d/audit.rules
service auditd restart
echo "log-queries
log-dhcp
log-facility=/var/log/dns.log" >> /etc/dnsmasq.conf
service dnsmasq restart
echo "prepend domain-name-servers 127.0.0.1;" >> /etc/dhcp/dhclient.conf
service network-manager restart
