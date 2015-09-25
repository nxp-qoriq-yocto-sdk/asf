#/**************************************************************************
#  * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
# *
# */

include $(KBUILD_OUTPUT)/.config
include $(TOPDIR)/asfconfig.mk


KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfqos/driver/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(TOPDIR)/asfctrl/linux/ffp/Module.symvers
export KBUILD_EXTRA_SYMBOLS

#EXTRA_CFLAGS += -DASFCTRL_DEBUG

obj-m += asfctrl_qos.o

asfctrl_qos-y := asfctrl_linux_qos.o

all:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) clean
