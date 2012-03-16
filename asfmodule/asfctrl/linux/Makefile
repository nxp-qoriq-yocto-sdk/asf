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
	make -w -C fwd -f Makefile
ifeq ($(CONFIG_ASF_TERMINATION), y)
	make -w -C term -f Makefile
endif
#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C ffp -f Makefile clean
	make -w -C ipsec -f Makefile clean
	make -w -C fwd -f Makefile clean
	make -w -C term -f Makefile clean
