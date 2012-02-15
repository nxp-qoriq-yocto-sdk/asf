#/**************************************************************************
#  * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# */

include $(KERNEL_PATH)/.config
PWD=$(shell pwd)
CC	= $(CROSS_COMPILE)gcc
AR	= $(CROSS_COMPILE)ar
LD	= $(CROSS_COMPILE)ld
EXTRA_CFLAGS := -mno-spe -mspe=no -mabi=no-spe

HOSTCC=/usr/bin/gcc
# ASF FEATURE OPTIONS
# For Peformance
#ASF_MINIMAL 	:= 1
#ASF_LINUX 	:= 2
#ASF_FULL 	:= 3

#ETHDRVDIR=$(shell dirname $(shell pwd))/gianfar
ifneq ($(CONFIG_AS_FASTPATH),y)
 fatal := $(error ASF is Disabled in Kernel. Try to fix)
endif
ifeq ($(CONFIG_ASF_FEATURE_OPTION_FULL),y)
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=3
else
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=1
endif
ifeq ($(CONFIG_ASF_IPV6), y)
EXTRA_CFLAGS += -DASF_IPV6_FP_SUPPORT
endif

KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfipsec/driver/Module.symvers
KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfctrl/linux/ffp/Module.symvers
export KBUILD_EXTRA_SYMBOLS

EXTRA_CFLAGS += -DCONFIG_ASF=1 -DCONFIG_AS_FASTPATH=1 -I$(KERNEL_PATH)/net/bridge
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/net

#EXTRA_CFLAGS += -DASFCTRL_DEBUG
#EXTRA_CFLAGS += -DASFCTRL_IPSEC_DEBUG
EXTRA_CFLAGS += -DASFCTRL_IPSEC_FP_SUPPORT
EXTRA_CFLAGS += -DASFCTRL_FWD_FP_SUPPORT
ifeq ($(CONFIG_ASF_TERMINATION), y)
EXTRA_CFLAGS += -DASFCTRL_TERM_FP_SUPPORT
endif

obj-m += asfctrl_ipsec.o

asfctrl_ipsec-y := \
             asfctrl_linux_ipsec.o asfctrl_linux_ipsec_hooks.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
