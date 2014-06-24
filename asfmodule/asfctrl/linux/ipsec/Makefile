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

KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfipsec/driver/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(TOPDIR)/asfctrl/linux/ffp/Module.symvers
export KBUILD_EXTRA_SYMBOLS


#EXTRA_CFLAGS += -DASFCTRL_DEBUG
#EXTRA_CFLAGS += -DASFCTRL_IPSEC_DEBUG

obj-m += asfctrl_ipsec.o

asfctrl_ipsec-y := \
             asfctrl_linux_ipsec.o asfctrl_linux_ipsec_hooks.o

all:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) clean
