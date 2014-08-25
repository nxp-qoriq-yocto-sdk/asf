#/**************************************************************************
# * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */


include $(KERNEL_PATH)/.config
include $(TOPDIR)/asfconfig.mk


KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfffp/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS

#EXTRA_CFLAGS += -DASF_DEBUG
#EXTRA_CFLAGS += -DASF_IPSEC_DEBUG
#EXTRA_CFLAGS += -DASFIPSEC_DEBUG_FRAME
obj-m += asfipsec.o

asfipsec-y := \
	ipsecfp.o \
	ipsfpapi.o \
	ipsecproc.o \
	ipsecfp_ah.o \
	ipsecfp_innerapi.o

asfipsec-$(CONFIG_ASF_SEC3x) += ipsecfp_sec3x.o
asfipsec-$(CONFIG_ASF_SEC4x) += ipsecfp_sec4x.o
asfipsec-$(CONFIG_DPA) += ipsecfp_qman.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
