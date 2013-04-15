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
include $(KERNEL_PATH)/.config

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
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	make -w -C qos -f Makefile
endif
#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C ffp -f Makefile clean
	make -w -C ipsec -f Makefile clean
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
	make -w -C qos -f Makefile clean
endif
