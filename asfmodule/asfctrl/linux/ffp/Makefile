#/**************************************************************************
#  * Copyright 2010-2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# */
include $(KERNEL_PATH)/.config
include $(TOPDIR)/asfconfig.mk


KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfffp/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS


obj-m += asfctrl.o

asfctrl-y := asfctrl_sysfs.o \
             asfctrl_linux.o \
	     asfctrl_linux_ffp.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
