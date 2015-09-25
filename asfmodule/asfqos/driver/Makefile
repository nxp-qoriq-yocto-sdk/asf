#/**************************************************************************
# * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */

include $(KBUILD_OUTPUT)/.config
include $(TOPDIR)/asfconfig.mk

KBUILD_EXTRA_SYMBOLS := $(TOPDIR)/asfffp/driver/Module.symvers
export KBUILD_EXTRA_SYMBOLS

#EXTRA_CFLAGS += -DASF_DEBUG=1

obj-m += asfqos.o

ifeq ($(CONFIG_DPA), y)
	asfqos-y := asfqos_sysfs.o asfqosapi_dpa.o
else
	asfqos-y := asfqos_sysfs.o asfqosapi.o
endif

all:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=$(ARCH) -C $(KERNEL_PATH) M=$(PWD) clean
