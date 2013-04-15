#/**************************************************************************
# * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */

include $(KERNEL_PATH)/.config
include $(TOPDIR)/asfconfig.mk

KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfffp/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS
#EXTRA_CFLAGS += -DASF_DEBUG=1

obj-m += asfqos.o

asfqos-y := asfqos_sysfs.o asfqosapi.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
