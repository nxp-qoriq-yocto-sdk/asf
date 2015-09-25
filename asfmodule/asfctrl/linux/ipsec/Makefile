#/**************************************************************************
#  * Copyright 2010-2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# */

include $(KBUILD_OUTPUT)/.config
include $(TOPDIR)/asfconfig.mk

KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfipsec/driver/Module.symvers
KBUILD_EXTRA_SYMBOLS += $(TOPDIR)/asfctrl/linux/ffp/Module.symvers
export KBUILD_EXTRA_SYMBOLS


#EXTRA_CFLAGS += -DASFCTRL_DEBUG
#EXTRA_CFLAGS += -DASFCTRL_IPSEC_DEBUG

obj-m += asfctrl_ipsec.o

ifeq ($(CONFIG_ASFCTRL_IPSEC_SA_MULTI_POLICY), y)
asfctrl_ipsec-y := asfctrl_linux_ipsec.o asfctrl_linux_ipsec_hooks_multisa.o
else
asfctrl_ipsec-y := asfctrl_linux_ipsec.o asfctrl_linux_ipsec_hooks.o
endif

all:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) clean
