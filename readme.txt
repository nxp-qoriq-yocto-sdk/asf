Edit build-p2020.sh script as mentioned below from steps 1 to 5.

1) Append path of Cross-Compilter Tool-Chain to 'PATH' variable.
e.g:
# Set the PATH variable to collect compiler tools.
PATH=/opt/freescale/usr/local/gcc-4.3.74-eglibc-2.8.74-dp-2/powerpc-none-linux-gnuspe/bin/:$PATH
PATH=/opt/freescale/ltib/usr/share/:$PATH
export PATH

2) Assign LTIB_DIR an absolute path where ltib has been installed.
   Using 'LTIB_DIR' you may derive ROOTFS_DIR(root file system path) and KERNEL_PATH(Kernel Sources Path),
   as seen later in steps 3) and 4), which are used for compilation.
e.g:
LTIB_DIR=/home/user/p2020/ltib-p2020rdb-20100428
export LTIB_DIR

3) Assign 'ROOTFS_DIR' with the target machine's rootfs path.
e.g:
ROOTFS_DIR=$LTIB_DIR/rootfs
export ROOTFS_DIR

4) Assign 'KERNEL_PATH' with target machines Kernel-Sources path.
e.g:
KERNEL_PATH=$LTIB_DIR/rpm/BUILD/linux
export KERNEL_PATH
   This 'KERNEL_PATH' will be used to invoke Kernel's main Makefile (KERNEL_PATH/Makefile)
   to externally compile ASF modules as Kernel-Modules.

5) Prefix for tools in Cross compiler tool chain varies from one platform to other.
   So assign CROSS_PREFIX with appropriate prefix, so that ASF sources are compiled using correct tools.
e.g: For p2020 platform
CROSS_PREFIX=powerpc-none-linux-gnuspe-
export CROSS_PREFIX

6) Now issue command 'make' to build and 'make clean' to clean, from asfgrp/ directory.

7) The generated kernel modules are
   'asfgrp/asfffp/driver/asf.ko' and 'asfgrp/asfipsec/driver/asfipsec.ko'
   for 'firewall' and 'ipsec' respectively.

8) You can insmod asf.ko and then asfipsec.ko on the target machine.
   insmod asf.ko
   insmod asfipsec.ko
   NOTE: Please maintain the above order when you insmod.
