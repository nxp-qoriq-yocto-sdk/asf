#/**************************************************************************
# * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# */

#/*------------------------------------------------------------------------*/
include $(KBUILD_OUTPUT)/.config

#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
all: build

build:
	make -w -C ffp -f Makefile
ifeq ($(CONFIG_XFRM), y)
	make -w -C ipsec -f Makefile
endif
ifneq ($(CONFIG_FSL_DPAA_ETH), y)
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	make -w -C qos -f Makefile
endif
endif
#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C ffp -f Makefile clean
	make -w -C ipsec -f Makefile clean
ifneq ($(CONFIG_FSL_DPAA_ETH), y)
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	make -w -C qos -f Makefile clean
endif
endif
