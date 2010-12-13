#/**************************************************************************
# * Copyright 2010 by Freescale Semiconductor, Inc.
# * All modifications are confidential and proprietary information
# * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
# ***************************************************************************/
#/*
# * File:	makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# *
# */
.PHONY: all
all: build

build:
	make -w -C linux -f makefile

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C linux -f makefile clean
