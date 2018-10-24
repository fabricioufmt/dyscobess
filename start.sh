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
echo "running ex2 script file..."
sudo ./bessctl/bessctl run ex2
