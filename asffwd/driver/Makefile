#/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
# *
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *		Sachin Saxena  <sachin.saxena@freescale.com>
# *
# * This program is free software; you can redistribute it and/or modify it
# * under the terms of the GNU General Public License as published by the
# * Free Software Foundation; either version 2 of the  License, or (at your
# * option) any later version.
# *
# * This program is distributed in the hope that it will be useful, but
# * WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# * General Public License for more details.
# *
# * You should have received a copy of the  GNU General Public License along
# * with this program; if not, write  to the Free Software Foundation, Inc.,
# * 675 Mass Ave, Cambridge, MA 02139, USA.
# *
# */

PWD=$(shell pwd)

CC	= $(CROSS_PREFIX)gcc
AR	= $(CROSS_PREFIX)ar
LD	= $(CROSS_PREFIX)ld
EXTRA_CFLAGS := -mno-spe -mspe=no -mabi=no-spe

HOSTCC=/usr/bin/gcc

# ASF FEATURE OPTIONS
# For Peformance
#ASF_MINIMAL 	:= 1
#ASF_LINUX 	:= 2
#ASF_FULL 	:= 3

#ETHDRVDIR=$(shell dirname $(shell pwd))/gianfar

EXTRA_CFLAGS += -DCONFIG_ASF=1 -DCONFIG_AS_FASTPATH=1  -DASF_IPSEC_FP_SUPPORT=1 -DASF_FWD_FP_SUPPORT=1 -I$(KERNEL_PATH)/net/bridge -I$(KERNEL_PATH)/drivers/net
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=3
EXTRA_CFLAGS += -DASF_IPSEC_FP_SUPPORT
EXTRA_CFLAGS += -DASF_FWD_FP_SUPPORT
#EXTRA_CFLAGS += -DASF_DEBUG=1
#EXTRA_CFLAGS += -DASF_FFP_XTRA_STATS=1

obj-m += asffwd.o

asffwd-y := asffwdproc.o asffwdapi.o

all:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make ARCH=powerpc -C $(KERNEL_PATH) M=$(PWD) clean
