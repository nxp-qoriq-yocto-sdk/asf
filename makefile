#/**************************************************************************
# * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	makefile
# *
# */


#------------------------------------------------------------------------------
#  Include Definitions
#------------------------------------------------------------------------------
.PHONY: all
all: build

build:
	make -w -C asfcmn -f makefile
	make -w -C asfffp -f makefile
	make -w -C asffwd -f makefile
	make -w -C asfipsec -f makefile
	make -w -C asfctrl -f makefile

#--------------------------------------------------------------
.PHONY: clean
clean:
	make -w -C asfcmn -f makefile clean
	make -w -C asfffp -f makefile clean
	make -w -C asffwd -f makefile clean
	make -w -C asfipsec -f makefile clean
	make -w -C asfctrl -f makefile clean

