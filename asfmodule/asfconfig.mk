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
ifeq ($(ARCH),powerpc)
EXTRA_CFLAGS := -mno-spe -mspe=no -mabi=no-spe
endif

ifneq ($(CONFIG_AS_FASTPATH),y)
$(warning ASF is Disabled in Kernel.)
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

# SCTP Flags
# Please enable IP_SCTP & NF_CT_PROTO_SCTP in kernel
# for SCTP flows to be offloaded by ASF.
EXTRA_CFLAGS += -DASFCTRL_SCTP_SUPPORT
EXTRA_CFLAGS += -DASF_SCTP_SUPPORT

ifeq ($(CONFIG_FSL_SDK_DPAA_ETH),y)
CONFIG_DPA=y
EXTRA_CFLAGS += -DCONFIG_DPA
ifeq ($(CONFIG_ASF_LINUX_QOS),y)
EXTRA_CFLAGS += -DASF_LINUX_QOS
endif
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
#EXTRA_CFLAGS += -DASFCTRL_IPSEC_SA_MULTI_POLICY
#CONFIG_ASFCTRL_IPSEC_SA_MULTI_POLICY=y
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
# QOS related function.
ifeq ($(CONFIG_ASF_QOS), y)
EXTRA_CFLAGS += -DASF_QOS
endif
ifeq ($(CONFIG_ASF_EGRESS_QOS), y)
EXTRA_CFLAGS += -DASF_EGRESS_QOS
endif
ifeq ($(CONFIG_ASF_TC_QOS), y)
EXTRA_CFLAGS += -DASF_TC_QOS
endif
ifeq ($(CONFIG_ASF_EGRESS_SCH), y)
EXTRA_CFLAGS += -DASF_EGRESS_SCH
endif
ifeq ($(CONFIG_ASF_EGRESS_SHAPER), y)
EXTRA_CFLAGS += -DASF_EGRESS_SHAPER
endif
ifeq ($(CONFIG_ASF_INGRESS_MARKER), y)
EXTRA_CFLAGS += -DASF_INGRESS_MARKER
endif
ifeq ($(CONFIG_ASF_HW_SCH), y)
EXTRA_CFLAGS += -DASF_HW_SCH
endif
ifeq ($(CONFIG_ASF_SCH_MWRR), y)
EXTRA_CFLAGS += -DASF_SCH_MWRR
endif
ifeq ($(CONFIG_ASF_HW_SHAPER), y)
EXTRA_CFLAGS += -DASF_HW_SHAPER
endif
ifeq ($(CONFIG_FSL_SDK_DPAA_ETH), y)
include $(KERNEL_PATH)/drivers/net/ethernet/freescale/sdk_fman/ncsw_config.mk
endif

ifeq ($(CONFIG_ASF_SEC4x), y)
EXTRA_CFLAGS += -DASF_SECFP_PROTO_OFFLOAD
endif
ifeq ($(CONFIG_DPA), y)
	EXTRA_CFLAGS += -DASF_QMAN_IPSEC
endif

ifeq ($(ARCH), arm)
EXTRA_CFLAGS += -DASF_ARM
endif

EXTRA_CFLAGS += -I$(KERNEL_PATH)/net/bridge
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/net/ethernet/freescale
EXTRA_CFLAGS += -I$(KERNEL_PATH)/net
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/crypto
EXTRA_CFLAGS += -I$(KERNEL_PATH)/drivers/crypto/caam
