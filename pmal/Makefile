# Common Makefile include file for all ASF IPSEC Termination apps
#
# Copyright (C) 2011 Freescale Semiconductor, Inc. All rights reserved.
#


#CC ?= gcc
CC = $(CROSS_COMPILE)gcc
AS ?= as

#PREFIX ?= /usr/local
#SYSROOT ?= /usr/local
O ?= $(DESTDIR)

CC_OPTS += -m32 -Wa, -I. -g -std=gnu99

CC_OPTS_C= -Wall \
  -Wundef \
  -Wstrict-prototypes \
  -Wno-trigraphs \
  -fno-strict-aliasing \
  -fno-common \
  -O3 \
  -pipe \
  -fomit-frame-pointer \
  -Wno-unused \
  -fno-builtin \
  -Werror

LD ?= ld
MKDIR=mkdir -p

APP_SRCS = pmal_api.c pmal_demo.c

APP_OBJS = $(basename $(APP_SRCS))
APP_OBJS := $(APP_OBJS:%=%.o)

APP_OBJS += $(LIB_OBJS)

APP_DEPS := $(APP_OBJS:%.o=%.d)

CC_OPTS+=-DPMAL_SG_SUPPORT -I$(KERNEL_PATH)/include -I$(KERNEL_PATH)/arch/powerpc/include

APP=pmal_demo

all:	$(APP)

# compile and gen dependency file
%.o:	 %.c
	$(CC) $(LIBC_INC) $(CC_OPTS) $(CC_OPTS_C) -MD -c -o $@ $<

$(APP):	$(APP_OBJS)
		$(CC) -o $@ $(APP_OBJS) $(LIBC_CC_OPTS)

packet_udp:	packet_udp.o

packet_udp.o: packet_udp.c
	$(CC) $(LIBC_INC) $(CC_OPTS) $(CC_OPTS_C) -MD -c -o $@ $<

clean:
	rm -rf *.o *.d  $(APP) packet_udp

-include $(APP_DEPS)

.PHONY: clean
