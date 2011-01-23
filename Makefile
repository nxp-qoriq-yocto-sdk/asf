#/**************************************************************************
# * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */


#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
all: build

build:
	make -w -C asfcmn -f Makefile
	make -w -C asfffp -f Makefile
	make -w -C asffwd -f Makefile
	make -w -C asfipsec -f Makefile
	make -w -C asfctrl -f Makefile

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C asfcmn -f Makefile clean
	make -w -C asfffp -f Makefile clean
	make -w -C asffwd -f Makefile clean
	make -w -C asfipsec -f Makefile clean
	make -w -C asfctrl -f Makefile clean

