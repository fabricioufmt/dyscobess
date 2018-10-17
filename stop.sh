#!/bin/bash

echo "killing iperf"
sudo pkill -9 iperf
echo "killing proxy"
sudo pkill -9 tcp_proxy
echo "killing tcpdump"
sudo pkill tcpdump

echo "stopping BESS daemon..."
sudo ./bessctl/bessctl daemon stop
