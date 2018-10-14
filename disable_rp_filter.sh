#!/bin/sh

for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
    echo 0 > $i
done

for i in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
    echo 0 > $i
done
