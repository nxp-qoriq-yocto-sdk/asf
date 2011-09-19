#/**************************************************************************
# * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Description: Compile the ASF Tool application.
# * *
# * Authors:	Sachin Saxena <b32168@freescale.com>
# */
# /* History
# */

ifeq ($(ASF_PATH),)
     $(error ERROR: ASF_PATH is not defined...!))
endif


ifeq ($(DEBUG_ON),1)
DEBUG_FLAGS=-DDEBUG_ON
else
DEBUG_FLAGS=
endif

# Set tool names
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
CINCS = -I . -I ../api -I $(ASF_PATH)/asfffp/driver
CLIBS = -L $(LIBPDKDIR)/lib -lpdk
CFLAGS = -g -O -Wall $(CINCS)



CLIBS = -L ../api -lasf_api


SRCS = asf_tool.c
EXECS = $(SRCS:%.c=%)
OBJS = $(SRCS:%.c=%.o)
DEPS = $(SRCS:%.c=%.d)

#../api/libasf_api.a

all:	$(EXECS)

execs:	$(EXECS)

%.d:	%.c
	$(CC) $(DEBUG_FLAGS) $(TARGET_FLAGS) $(CFLAGS) -c -MD $<

asf_tool:	$(OBJS) ../api/libasf_api.a
	$(CC) -o $@ $(CFLAGS) $@.o $(CLIBS)


# We dont really do installs, since these are for target
# not this host.  These aren't exactly correct either.
#
# install requires root access

clean:
	$(RM) -f $(EXECS) $(OBJS) $(DEPS) *.d *.a *.tar

tar:	clean
	$(RM) -rf *~
	tar cvf msc7120_app.tar *

-include $(DEPS)

