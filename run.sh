#!/bin/bash

export RTE_SDK=$PWD/deps/dpdk-17.05
export RTE_TARGET=x86_64-native-linuxapp-gcc
HUGEPGSZ=`cat /proc/meminfo | grep Hugepagesize | cut -d: -f2 | tr -d ' '`

echo "removing reserved hugepages"
echo > .echo_tmp
for d in /sys/devices/system/node/node? ; do
    echo "echo 0 > $d/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" >> .echo_tmp
done
sudo sh .echo_tmp
rm -rf .echo_tmp

sudo umount /mnt/huge 1>/dev/null 2>/dev/null
sudo rm -R /mnt/huge 1>/dev/null 2>/dev/null

echo "reserving 1024 hugepages(2048kB)"
echo "echo 1024 > /sys/kernel/mm/hugepages/hugepages-${HUGEPGSZ}/nr_hugepages" > .echo_tmp
sudo sh .echo_tmp
rm -rf .echo_tmp

echo "creating /mnt/huge and mouting as hugetlbfs"
sudo mkdir -p /mnt/huge
sudo mount -t hugetlbfs nodev /mnt/huge

echo "removing bess module..."
sudo rmmod bess 1>/dev/null 2>/dev/null
echo "starting BESS daemon"
sudo ./bessctl/bessctl daemon start
echo "running dysco/ex6 script file..."
sudo ./bessctl/bessctl run dysco/ex6

echo "sleeping for 1 second..."
sleep 1

echo "starting iperf -s..."
sudo ip netns exec s1 iperf -s 1>/dev/null 2>/dev/null &
echo "starting proxy..."
sudo ip netns exec m1 ./tcp_proxy 5001 10.0.2.2 5001 5 1>/dev/null 2>/dev/null &
echo "starting tcpdumps..."
sudo ip netns exec LA tcpdump -i LA-1 -w /home/fabricio/LA-1.pcap 1>/dev/null 2>/dev/null &
sudo ip netns exec m1 tcpdump -i m1-0 -w /home/fabricio/m1-0.pcap 1>/dev/null 2>/dev/null &
sudo ip netns exec m1 tcpdump -i m1-1 -w /home/fabricio/m1-1.pcap 1>/dev/null 2>/dev/null &
sudo ip netns exec m2 tcpdump -i m2-0 -w /home/fabricio/m2-0.pcap 1>/dev/null 2>/dev/null &
sudo ip netns exec RA tcpdump -i RA-1 -w /home/fabricio/RA-1.pcap 1>/dev/null 2>/dev/null &
echo "sleeping for 2 seconds..."
sleep 2
echo "starting iperf -c..."
sudo ip netns exec c1 iperf -c 10.0.5.2 -i 1
