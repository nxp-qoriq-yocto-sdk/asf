#/**************************************************************************
# * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
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


ifneq ($(CONFIG_AS_FASTPATH),y)
 fatal := $(error ASF is Disabled in Kernel. Try to fix)
endif
ifeq ($(CONFIG_ASF_FEATURE_OPTION_FULL),y)
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=3
else
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=1
endif

KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfffp/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS

EXTRA_CFLAGS += -DCONFIG_ASF=1 -DCONFIG_AS_FASTPATH=1 -I$(KERNEL_PATH)/net/bridge
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/net
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/crypto
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/crypto/caam
EXTRA_CFLAGS += -DASF_IPSEC_FP_SUPPORT
ifeq ($(CONFIG_ASF_TERMINATION), y)
EXTRA_CFLAGS += -DASF_TERM_FP_SUPPORT
endif
#EXTRA_CFLAGS += -DASF_DEBUG
#EXTRA_CFLAGS += -DASF_IPSEC_DEBUG
#EXTRA_CFLAGS += -DASFIPSEC_DEBUG_FRAME
#EXTRA_CFLAGS += -DASF_FFP_XTRA_STATS=1

obj-m += asfipsec.o

asfipsec-y := \
	     ipsecfp.o \
	     ipsfpapi.o \
	     ipsecproc.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
