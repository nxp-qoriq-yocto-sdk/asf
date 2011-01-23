Compiling and Loading ASF Modules

1) Compile Linux Kernel with ASF feature enabled

2) Export 'KERNEL_PATH' with Kernel-Sources path.
e.g:
KERNEL_PATH=$LTIB_DIR/rpm/BUILD/linux
export KERNEL_PATH
This 'KERNEL_PATH' will be used to invoke Kernel's main Makefile (KERNEL_PATH/Makefile)
to externally compile ASF modules as Kernel-Modules.

3) Export cross compiler tool path
e.g: For p2020/P1020/P1010 platform
CROSS_COMPILE=powerpc-none-linux-gnuspe-
export CROSS_COMPILE

4) Now issue command 'make' to build and 'make clean' to clean, from asf top level directory.

5) The generated kernel modules are
   asfffp/driver/asf.ko  		- ASF core and datapath for Firewall/NAT
   asfipsec/driver/asfipsec.ko		- ASF datapath for IPSec
   asffwd/driver/adffwd.ko		- ASF datapath for IPv4 Forwarding
   asfctrl/linux/ffp/asfctrl.ko		- ASF control for Firewall/NAT
   asfctrl/linux/fwd/asfctrl_fwd.ko	- ASF control for IPv4 Forwarding
   asfctrl/linux/ipsec/asfctrl_ipsec.ko	- ASF control for IPSec

6) insmod above .ko on the target machine in following order.
	insmod asf.ko
	insmod asffwd.ko
	insmod asfipsec.ko
	insmod asfctrl.ko
	insmod asfctrl_fwd.ko
	insmod asfctrl_ipsec.ko
