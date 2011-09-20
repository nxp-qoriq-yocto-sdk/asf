#/**************************************************************************
# * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Description: Top level file for application & API compilation
# * *
# * Authors:	Sachin Saxena <b32168@freescale.com>
# */
# /* History
# */

#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
all: build

build:
	make -w -C api -f Makefile
	make -w -C apps -f Makefile

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C apps -f Makefile clean
	make -w -C api -f Makefile clean
