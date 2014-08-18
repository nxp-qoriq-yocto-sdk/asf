/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asftcp.c
 *
 * Authors:	K Muralidhar-B22243 <B22243@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/


#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/crc32.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/phy_fixed.h>
#include <net/xfrm.h>
#include <linux/sysctl.h>
#include <net/tcp.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif

#include <linux/version.h>
#include "asf.h"
#include "asfcmn.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfpvt.h"
#include "asftcp.h"

#define _MIN(a, b) ((a) < (b) ? (a) : (b))




extern int asf_tcp_oos_drop;
extern int asf_tcp_fin_timeout;
extern int asf_tcp_rst_timeout;


static inline int asfTcpCheckForNormalOos(
					 ffp_flow_t *flow,
					 ffp_flow_t *oth_flow,
					 unsigned long ulSeqNum,
					unsigned long ulAckNum,
					asf_vsg_info_t *vsgInfo)
{
	unsigned long ulSendNext, ulOtherRcvNext;

	ulOtherRcvNext  = oth_flow->tcpState.ulRcvNext;
	if (flow->tcpState.bPositiveDelta)
		ulOtherRcvNext -= flow->tcpState.ulSeqDelta;
	else
		ulOtherRcvNext += flow->tcpState.ulSeqDelta;

	if (!asfTcpSeqWithin(ulSeqNum, ulOtherRcvNext -
			     _MIN((oth_flow->tcpState.ulMaxRcvWin << oth_flow->tcpState.ucWinScaleFactor),
						vsgInfo->ulTcpSeqNumRange),
			     ulOtherRcvNext +
			     _MIN((oth_flow->tcpState.ulMaxRcvWin << oth_flow->tcpState.ucWinScaleFactor),
				vsgInfo->ulTcpSeqNumRange))) {
		return ASF_LOG_ID_TCP_BAD_SEQ_NO;
	}

	ulSendNext  = oth_flow->tcpState.ulHighSeqNum;
	if (oth_flow->tcpState.bPositiveDelta) {
		ulSendNext += oth_flow->tcpState.ulSeqDelta;
	} else {
		ulSendNext -= oth_flow->tcpState.ulSeqDelta;
	}

	if (!asfTcpSeqWithin(ulAckNum,
			     flow->tcpState.ulRcvNext -
			     _MIN((flow->tcpState.ulMaxRcvWin <<  flow->tcpState.ucWinScaleFactor),
				vsgInfo->ulTcpSeqNumRange),
			     ulSendNext)) {
		return ASF_LOG_ID_TCP_BAD_ACK_SEQ;
	}
	return ASF_LOG_ID_DUMMY;
}


static inline int asfTcpCheckForRstOos(
				      ffp_flow_t *flow,
				      ffp_flow_t *oth_flow,
				      unsigned long ulSeqNum,
				unsigned long ulAckNum,
				struct tcphdr *tcph,
				asf_vsg_info_t *vsgInfo)
{
	unsigned long ulSendNext, ulOtherRcvNext;

	ulSendNext = flow->tcpState.ulHighSeqNum;

	if (asfTcpSeqLt(ulSeqNum, ulSendNext)) {
		return ASF_LOG_ID_TCP_BAD_RST_SEQ;
	}

	ulOtherRcvNext  = oth_flow->tcpState.ulRcvNext;
	if (flow->tcpState.bPositiveDelta) {
		ulOtherRcvNext -= flow->tcpState.ulSeqDelta;
	} else {
		ulOtherRcvNext += flow->tcpState.ulSeqDelta;
	}

	if (!asfTcpSeqWithin(ulSeqNum,
			     ulOtherRcvNext -
			     _MIN((oth_flow->tcpState.ulRcvWin <<  oth_flow->tcpState.ucWinScaleFactor),
					vsgInfo->ulTcpRstSeqNumRange),
			     ulOtherRcvNext +
			     _MIN((oth_flow->tcpState.ulRcvWin <<  oth_flow->tcpState.ucWinScaleFactor),
					vsgInfo->ulTcpRstSeqNumRange))) {
		return ASF_LOG_ID_TCP_BAD_RST_SEQ;
	}

	if (tcph->ack) {
		ulSendNext  = oth_flow->tcpState.ulHighSeqNum;
		if (oth_flow->tcpState.bPositiveDelta) {
			ulSendNext += oth_flow->tcpState.ulSeqDelta;
		} else {
			ulSendNext -= oth_flow->tcpState.ulSeqDelta;
		}

		if (!asfTcpSeqWithin(ulAckNum,
			     flow->tcpState.ulRcvNext -
			     _MIN((flow->tcpState.ulMaxRcvWin << flow->tcpState.ucWinScaleFactor),
					vsgInfo->ulTcpSeqNumRange),
			     ulSendNext)) {
			return ASF_LOG_ID_TCP_BAD_RST_ACK_SEQ;
		}
	}
	return ASF_LOG_ID_DUMMY;
}

int asfTcpCheckForOutOfSeq(ffp_flow_t *flow, ffp_flow_t *oth_flow,
					struct tcphdr *tcph,
					unsigned short data_len,
					asf_vsg_info_t *vsgInfo)
{
	int iRetVal;
	unsigned long ulSeqNum = ASF_NTOHL(tcph->seq);
	unsigned long ulAckNum = ASF_NTOHL(tcph->ack_seq);

	if (tcph->rst)
		iRetVal = asfTcpCheckForRstOos(flow, oth_flow, ulSeqNum,
					ulAckNum, tcph, vsgInfo);
	else
		iRetVal = asfTcpCheckForNormalOos(flow, oth_flow, ulSeqNum,
					ulAckNum, vsgInfo);

	if (iRetVal != ASF_LOG_ID_DUMMY)
		return iRetVal;


	if (tcph->urg) {
		if (tcph->urg_ptr && (ASF_NTOHS(tcph->urg_ptr) > data_len))
			return ASF_LOG_ID_TCP_BAD_URG_PTR;

		if (data_len < 1)
			return ASF_LOG_ID_TCP_BAD_URG_PTR_BUT_NO_DATA;
	} else if (tcph->urg_ptr)
		return ASF_LOG_ID_TCP_NO_URG_BIT;

	return ASF_LOG_ID_DUMMY;
}
