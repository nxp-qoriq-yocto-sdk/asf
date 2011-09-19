#/**************************************************************************
# * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Description: Compilation support for ASF API Library.
# * *
# * Authors:	Sachin Saxena <b32168@freescale.com>
# */
#/* History
# *  Version	Date		Author		Change Description
#*/
ifeq ($(ASF_PATH),)
     $(error ERROR: ASF_PATH is not defined...!))
endif

ifeq ($(DEBUG_ON),1)
DEBUG_FLAGS=-DDEBUG_ON
else
DEBUG_FLAGS=
endif

CC = $(CROSS_COMPILE)gcc
AS = $(CROSS_COMPILE)as
LD = $(CROSS_COMPILE)ld
CPP = $(CROSS_COMPILE)cpp
NM = $(CROSS_COMPILE)nm
STRIP = $(CROSS_COMPILE)strip
OBJCOPY = $(CROSS_COMPILE)objcopy
AR = $(CROSS_COMPILE)ar
RM = rm

# These are defaults.  Individual makefiles might override them.

CINCS = -I . -I ../include -I $(LIBPDKDIR)/include
CLIBS = -L $(LIBPDKDIR)/lib -lpdk
CFLAGS = -g -O -Wall $(CINCS)


INCLUDE = -I $(ASF_PATH)/asfffp/driver

CFLAGS = -Wall -g -O -I. $(INCLUDE)

SRCS = asf_api.c

OBJS = $(SRCS:%.c=%.o)
DEPS = $(SRCS:%.c=%.d)

all:	libasf_api.a

%.d:	%.c
	$(CC) $(DEBUG_FLAGS) $(TARGET_FLAGS) $(CFLAGS)  -c -MD $<

libasf_api.a: $(OBJS)
	ar rsc libasf_api.a $(OBJS)

clean:
	$(RM) -f $(OBJS) $(DEPS) *.d *.a *~ *.tar

tar:	clean
	$(RM) -rf *~
	tar cvf soc_app.tar *

-include $(DEPS)

