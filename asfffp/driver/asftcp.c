/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asftcp.c
 *
 * Authors:	K Muralidhar-B22243 <B22243@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the  GNU General Public License along
 * with this program; if not, write  to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
/*
 * History
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
					 unsigned long ulAckNum)
{
	unsigned long ulSendNext, ulOtherRcvNext;

	ulOtherRcvNext  = oth_flow->tcpState.ulRcvNext;
	if (flow->tcpState.bPositiveDelta)
		ulOtherRcvNext -= flow->tcpState.ulSeqDelta;
	else
		ulOtherRcvNext += flow->tcpState.ulSeqDelta;

	if (!asfTcpSeqWithin(ulSeqNum, ulOtherRcvNext -
			     _MIN((oth_flow->tcpState.ulMaxRcvWin << oth_flow->tcpState.ucWinScaleFactor),
				  ASF_TCP_MAX_SEQNUM),
			     ulOtherRcvNext +
			     _MIN((oth_flow->tcpState.ulMaxRcvWin << oth_flow->tcpState.ucWinScaleFactor),
				  ASF_TCP_MAX_SEQNUM))) {
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
				  ASF_TCP_MAX_SEQNUM),
			     ulSendNext)) {
		return ASF_LOG_ID_TCP_BAD_ACK_SEQ;
	}
	return ASF_LOG_ID_DUMMY;
}


static inline int asfTcpCheckForRstOos(
				      ffp_flow_t *flow,
				      ffp_flow_t *oth_flow,
				      unsigned long ulSeqNum,
				      unsigned long ulAckNum)
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
				  ASF_TCP_MAX_SEQNUM),
			     ulOtherRcvNext +
			     _MIN((oth_flow->tcpState.ulRcvWin <<  oth_flow->tcpState.ucWinScaleFactor),
				  ASF_TCP_MAX_SEQNUM))) {
		return ASF_LOG_ID_TCP_BAD_RST_SEQ;
	}

	ulSendNext  = oth_flow->tcpState.ulHighSeqNum;
	if (oth_flow->tcpState.bPositiveDelta) {
		ulSendNext += oth_flow->tcpState.ulSeqDelta;
	} else {
		ulSendNext -= oth_flow->tcpState.ulSeqDelta;
	}

	if (!asfTcpSeqWithin(ulAckNum,
			     flow->tcpState.ulRcvNext -
			     _MIN((flow->tcpState.ulMaxRcvWin << flow->tcpState.ucWinScaleFactor),
				  ASF_TCP_MAX_SEQNUM),
			     ulSendNext)) {
		return ASF_LOG_ID_TCP_BAD_RST_ACK_SEQ;
	}
	return ASF_LOG_ID_DUMMY;
}

int asfTcpCheckForOutOfSeq(ffp_flow_t *flow, ffp_flow_t *oth_flow,
			   struct tcphdr *tcph, unsigned short data_len)
{
	int iRetVal;
	unsigned long ulSeqNum = ntohl(tcph->seq);
	unsigned long ulAckNum = ntohl(tcph->ack_seq);

	if (tcph->rst)
		iRetVal = asfTcpCheckForRstOos(flow, oth_flow, ulSeqNum, ulAckNum);
	else
		iRetVal	= asfTcpCheckForNormalOos(flow, oth_flow, ulSeqNum, ulAckNum);

	if (iRetVal != ASF_LOG_ID_DUMMY)
		return iRetVal;


	if (tcph->urg) {
		if (tcph->urg_ptr && (ntohs(tcph->urg_ptr) > data_len))
			return ASF_LOG_ID_TCP_BAD_URG_PTR;

		if (data_len < 1)
			return ASF_LOG_ID_TCP_BAD_URG_PTR_BUT_NO_DATA;
	} else if (tcph->urg_ptr) {
		/*tcph->up = 0;
		TODO: do this at the caller and update tcp checksum accordingly */

		return ASF_LOG_ID_TCP_NO_URG_BIT;
	}

	return ASF_LOG_ID_DUMMY;
}




/*
		optlen = tcph->doff*4-20;

*/

