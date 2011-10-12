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


int asfReasmInit(void);
void asfReasmDeInit(void);

void asfReasmInitConfig(void);
#ifdef ASF_TERM_FP_SUPPORT
extern struct sk_buff *packet_new_skb(struct net_device *dev);
#endif
extern struct sk_buff *gfar_new_skb(struct net_device * dev);
#ifdef ASF_SG_SUPPORT
extern void gfar_skb_destructor(struct sk_buff *skb);
#endif
#endif
