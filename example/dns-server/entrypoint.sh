#!/bin/sh

# Running dnsmasq server in the background
dnsmasq --conf-file=/etc/conf/dnsmasq.conf

# Running routedns server in the foreground
blocky --config /etc/conf/blocky.yml
