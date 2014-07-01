/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfreasm.c
 * Description: Contains the reassembly/fragmentation function
 * and macro definations for ASF
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/

/*******************Include files ************************************************/
#ifndef _ASF_REASM_H
#define _ASF_REASM_H

#define REASM_IPv4	0
#define REASM_IPv6	1

int asfReasmInit(void);
void asfReasmDeInit(void);

#ifdef ASF_REASM_DEBUG
#define asf_reasm_debug(fmt, args...)\
	printk(KERN_INFO"[CPU %d line %d %s] " fmt, smp_processor_id(),\
	__LINE__, __func__, ##args)
#else
#define asf_reasm_debug(fmt, args...)
#endif
void asfReasmInitConfig(void);
#ifdef ASF_TERM_FP_SUPPORT
extern struct sk_buff *packet_new_skb(struct net_device *dev);
#endif
#ifndef CONFIG_DPA
extern struct sk_buff *gfar_new_skb(struct net_device *dev);
#ifdef ASF_SG_SUPPORT
extern void gfar_skb_destructor(struct sk_buff *skb);
#endif
#endif
#endif
