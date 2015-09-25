#/**************************************************************************
# * Copyright 2010-2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */

TOPDIR := $(shell pwd)
export TOPDIR

include $(KBUILD_OUTPUT)/.config
include asfconfig.mk
ifeq ($(CONFIG_AS_FASTPATH), y)
#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
.NOTPARALLEL :
all: min full

min : export ASF_FEATURE_OPTION_FULL := n
full : export ASF_FEATURE_OPTION_FULL := y

min :
	make -w -C asfffp -f Makefile
ifeq ($(CONFIG_XFRM), y)
	make -w -C asfipsec -f Makefile
endif
ifneq ($(CONFIG_FSL_DPAA_ETH), y)
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	make -w -C asfqos -f Makefile
endif
endif
	make -w -C asfctrl -f Makefile
	mkdir -p bin
	mkdir -p bin/min
	cp asfffp/driver/asf.ko asfctrl/linux/ffp/asfctrl.ko bin/min
	cp asfipsec/driver/asfipsec.ko asfctrl/linux/ipsec/asfctrl_ipsec.ko bin/min
	$(CROSS_COMPILE)strip --strip-unneeded bin/min/*.ko

full :
	mkdir -p bin
	mkdir -p bin/full
	make -w -C asfffp -f Makefile
ifeq ($(CONFIG_XFRM), y)
	make -w -C asfipsec -f Makefile
endif
ifneq ($(CONFIG_FSL_DPAA_ETH), y)
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	make -w -C asfqos -f Makefile
endif
endif
	make -w -C asfctrl -f Makefile

	cp asfffp/driver/asf.ko asfctrl/linux/ffp/asfctrl.ko bin/full
	cp asfipsec/driver/asfipsec.ko asfctrl/linux/ipsec/asfctrl_ipsec.ko bin/full
ifneq ($(CONFIG_FSL_DPAA_ETH), y)
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	cp asfqos/driver/asfqos.ko asfctrl/linux/qos/asfctrl_qos.ko bin/full 2>/dev/null
endif
endif
	$(CROSS_COMPILE)strip --strip-unneeded bin/full/*.ko

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C asfffp -f Makefile clean
ifeq ($(CONFIG_XFRM), y)
	make -w -C asfipsec -f Makefile clean
endif
ifneq ($(CONFIG_FSL_DPAA_ETH), y)
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	make -w -C asfqos -f Makefile clean
endif
endif
	make -w -C asfctrl -f Makefile clean
	rm -rf bin
else
.PHONY: all
all:
	mkdir -p bin
	mkdir -p bin/full
	mkdir -p bin/min
.PHONY: clean
clean :
	rm -rf bin
endif
