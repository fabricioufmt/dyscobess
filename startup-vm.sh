echo "setting environment variables..."
export RTE_SDK=/home/vagrant/dyscobess/deps/dpdk-17.05
export RTE_TARGET=x86_64-native-linuxapp-gcc

echo "turning down the interfaces..."
sudo ifconfig enp0s8 down
sudo ifconfig enp0s9 down

echo "loading igb_uio module ..."
sudo /sbin/modprobe uio 1>/dev/null 2>/dev/null
sudo /sbin/insmod $RTE_SDK/$RTE_TARGET/kmod/igb_uio.ko 1>/dev/null 2>/dev/null

echo "binding interfaces with igb_uio..."
sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b igb_uio 0000:00:08.0 1>/dev/null 2>/dev/null
sudo ${RTE_SDK}/usertools/dpdk-devbind.py -b igb_uio 0000:00:09.0 1>/dev/null 2>/dev/null
