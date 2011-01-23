#/**************************************************************************
# * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# */

#/*------------------------------------------------------------------------*/

#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
all: build

build:
	make -w -C ffp -f Makefile
	make -w -C ipsec -f Makefile
	make -w -C fwd -f Makefile

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C ffp -f Makefile clean
	make -w -C ipsec -f Makefile clean
	make -w -C fwd -f Makefile clean
