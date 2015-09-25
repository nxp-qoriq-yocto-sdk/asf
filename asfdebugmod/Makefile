#/**************************************************************************
# * Copyright 2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# *

PWD=$(shell pwd)
CC	= $(CROSS_COMPILE)gcc
AR	= $(CROSS_COMPILE)ar
LD	= $(CROSS_COMPILE)ld

include $(KBUILD_OUTPUT)/.config
ifeq ($(CONFIG_FSL_DPAA_ETH), y)
include $(KERNEL_PATH)/drivers/net/ethernet/freescale/fman/ncsw_config.mk
endif

EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/net/ethernet/freescale
EXTRA_CFLAGS += -I$(KERNEL_PATH)/net/bridge
EXTRA_CFLAGS += -I$(KERNEL_PATH)/net

obj-m += asf_debug.o

asf_debug-y := asfdebugcore.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
