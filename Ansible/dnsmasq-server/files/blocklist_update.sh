#!/bin/bash

wget -O /opt/dnsmasq.blacklist.txt https://github.com/notracking/hosts-blocklists/raw/master/dnsmasq/dnsmasq.blacklist.txt

systemctl restart dnsmasq.service