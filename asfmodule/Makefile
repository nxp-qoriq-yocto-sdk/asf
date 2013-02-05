#/**************************************************************************
# * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */

include $(KERNEL_PATH)/.config
TOPDIR := $(shell pwd)
export TOPDIR
#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
all: build

build:
	make -w -C asfffp -f Makefile
ifeq ($(CONFIG_XFRM), y)
	make -w -C asfipsec -f Makefile
endif
	make -w -C asfctrl -f Makefile

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C asfffp -f Makefile clean
ifeq ($(CONFIG_XFRM), y)
	make -w -C asfipsec -f Makefile clean
endif
	make -w -C asfctrl -f Makefile clean

