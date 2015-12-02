#!/bin/sh
echo $RTE_SDK
echo $RTE_TARGET

if [ ! -d /mnt/huge ]
then
	mkdir /mnt/huge
fi

umount /mnt/huge/
mount -t hugetlbfs hugetlbfs /mnt/huge/

rmmod igb_uio
rmmod uio

modprobe uio
insmod /home/lilifeng/DPDK/x86_64-default-linuxapp-gcc/kmod/igb_uio.ko

cd /home/lilifeng/DPDK/tools/
./pci_unbind.py -b igb_uio 0000:81:00.0
./pci_unbind.py -b igb_uio 0000:81:00.1
./pci_unbind.py  --status

cd -

