#/**************************************************************************
# * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#
# Makefile config for the Freescale ASF SW
#

PWD=$(shell pwd)
CC	= $(CROSS_COMPILE)gcc
AR	= $(CROSS_COMPILE)ar
LD	= $(CROSS_COMPILE)ld
EXTRA_CFLAGS := -mno-spe -mspe=no -mabi=no-spe

ifneq ($(CONFIG_AS_FASTPATH),y)
 fatal := $(error ASF is Disabled in Kernel. Try to fix)
endif

#EXTRA_CFLAGS += -DASF_DEBUG
#EXTRA_CFLAGS += -DASF_DEBUG_L2
#EXTRA_CFLAGS += -DASF_IPSEC_DEBUG
#EXTRA_CFLAGS += -DASFIPSEC_DEBUG_FRAME
#EXTRA_CFLAGS += -DASFCTRL_DEBUG

# ASF FEATURE OPTIONS
# For Peformance
#ASF_MINIMAL 	:= 1
#ASF_LINUX 	:= 2
#ASF_FULL 	:= 3

ifeq ($(CONFIG_DPA_ETH),y)
EXTRA_CFLAGS += -DCONFIG_DPA
endif
ifeq ($(ASF_FEATURE_OPTION_FULL),y)
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=3
else
EXTRA_CFLAGS += -DASF_FEATURE_OPTION=1
endif

# ASF IPSEC control plane is required only for non-vortiQa case.
ifeq ($(CONFIG_XFRM), y)
EXTRA_CFLAGS += -DASF_IPSEC_FP_SUPPORT
EXTRA_CFLAGS += -DASFCTRL_IPSEC_FP_SUPPORT
endif

ifdef CONFIG_CRYPTO_DEV_TALITOS
ifdef CONFIG_SMP
CONFIG_ASF_SEC3x=y
EXTRA_CFLAGS += -DCONFIG_ASF_SEC3x
else
CONFIG_ASF_SEC4x=y
EXTRA_CFLAGS += -DCONFIG_ASF_SEC4x
endif
else
CONFIG_ASF_SEC4x=y
EXTRA_CFLAGS += -DCONFIG_ASF_SEC4x
endif

#ASF IPv6 Support
ifeq ($(CONFIG_ASF_IPV6), y)
EXTRA_CFLAGS += -DASF_IPV6_FP_SUPPORT
endif
ifeq ($(CONFIG_DPA_ETH), y)
include $(KERNEL_PATH)/drivers/net/ethernet/freescale/fman/ncsw_config.mk
endif

ifeq ($(CONFIG_ASF_SEC4x), y)
EXTRA_CFLAGS += -DASF_SECFP_PROTO_OFFLOAD
endif
ifeq ($(CONFIG_DPA), y)
	EXTRA_CFLAGS += -DASF_QMAN_IPSEC
endif
EXTRA_CFLAGS += -I$(KERNEL_PATH)/net/bridge
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/net/ethernet/freescale
EXTRA_CFLAGS += -I$(KERNEL_PATH)/net
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/crypto
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/crypto/caam
