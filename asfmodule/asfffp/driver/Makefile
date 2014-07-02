#/**************************************************************************
# * Copyright 2010-2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */
include $(KERNEL_PATH)/.config
include $(TOPDIR)/asfconfig.mk


#EXTRA_CFLAGS += -DASF_DEBUG
#EXTRA_CFLAGS += -DASF_DEBUG_L2
#EXTRA_CFLAGS += -DASF_FFP_XTRA_STATS=1

obj-m += asf.o

asf-y := asfproc.o \
	    asfparry.o \
	    asfmpool.o \
	    asftmr.o \
	    asftcp.o \
	    asfreasm.o \
	    asfcore.o \
	    gplcode.o

ifeq ($(CONFIG_ASF_IPV6), y)
asf-y += asfipv6core.o
endif

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
