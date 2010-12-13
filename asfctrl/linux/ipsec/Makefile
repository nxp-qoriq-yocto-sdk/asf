#/**************************************************************************
# * Copyright 2010 by Freescale Semiconductor, Inc.
# * All modifications are confidential and proprietary information
# * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# */

PWD=$(shell pwd)
CC	= $(CROSS_PREFIX)gcc
AR	= $(CROSS_PREFIX)ar
LD	= $(CROSS_PREFIX)ld
EXTRA_CFLAGS := -mno-spe -mspe=no -mabi=no-spe

HOSTCC=/usr/bin/gcc
# ASF FEATURE OPTIONS
# For Peformance
#ASF_MINIMAL 	:= 1
#ASF_LINUX 	:= 2
#ASF_FULL 	:= 3

#ETHDRVDIR=$(shell dirname $(shell pwd))/gianfar

EXTRA_CFLAGS += -DCONFIG_ASF=1 -DCONFIG_AS_FASTPATH=1 -I$(KERNEL_PATH)/net/bridge
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=3 -I$(KERNEL_PATH)/drivers/net

EXTRA_CFLAGS += -DASFCTRL_DEBUG
EXTRA_CFLAGS += -DASFCTRL_IPSEC_FP_SUPPORT
EXTRA_CFLAGS += -DASFCTRL_FWD_FP_SUPPORT

obj-m += asfctrl_ipsec.o

asfctrl_ipsec-y := \
             asfctrl_linux_ipsec.o asfctrl_linux_ipsec_hooks.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
