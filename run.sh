#!/bin/bash

sudo ip netns exec s1 iperf -s 1>/dev/null 2>/dev/null &
sudo ip netns exec m1 ./tcp_proxy 5001 10.0.2.2 5001 5 1>/dev/null 2>/dev/null &
sudo ip netns exec LA tcpdump -i LA-1 -w /home/fabricio/LA-1 1>/dev/null 2>/dev/null &
sudo ip netns exec m1 tcpdump -i m1-0 -w /home/fabricio/m1-0 1>/dev/null 2>/dev/null &
sudo ip netns exec m2 tcpdump -i m2-0 -w /home/fabricio/m2-0 1>/dev/null 2>/dev/null &
sudo ip netns exec RA tcpdump -i RA-1 -w /home/fabricio/RA-1 1>/dev/null 2>/dev/null &
echo "sleeping for 2 seconds..."
sleep 2
sudo ip netns exec c1 iperf -c 10.0.5.2 -i 1
