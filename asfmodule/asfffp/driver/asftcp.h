/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asftcp.h
 *
 * Description: Contains the macros, type defintions, exported and imported
 * functions for application specific fast path
 *
 * Authors:	K Muralidhar-B22243 <B22243@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
 /******************************************************************************/
#ifndef _ASF_TCP_H
#define _ASF_TCP_H

#include <net/tcp.h>

/*  internal flags used to identify curent state */
#define ASF_TCP_FLAGS_SYN_RCVD	0x1
#define ASF_TCP_FLAGS_SYN_ACK_RCVD	0x2
#define ASF_TCP_FLAGS_FIN_RCVD	0x4
#define ASF_TCP_FLAGS_RST_RCVD	0x8
#define ASF_TCP_FLAGS_RST_LOCK	0x10


#define ASF_TCP_TIMESTAMP_LIMIT 0x80000000
#define ASF_TCP_MAX_SEQNUM	65535

#define ASF_TCP_IS_BIT_SET(flow, bit) (flow->tcpState.usReserved & ASF_TCP_FLAGS_##bit)
#define ASF_TCP_SET_BIT(flow, bit) do { flow->tcpState.usReserved |= ASF_TCP_FLAGS_##bit; } while (0)
#define ASF_TCP_CLEAR_BIT(flow, bit) do { flow->tcpState.usReserved &= ~ASF_TCP_FLAGS_##bit; } while (0)


static inline int asfTcpSeqWithin(unsigned long x, unsigned long low, unsigned long high)
{
	return ((high-low) >= (x-low));
}

static inline int asfTcpSeqLt(unsigned long x, unsigned long y)
{
	return (int)(x-y) < 0;
}

static inline int asfTcpSeqLe(unsigned long x, unsigned long y)
{
	return (int)(x-y) <= 0;
}


static inline int asfTcpSeqGt(unsigned long x, unsigned long y)
{
	return (int)(x-y) > 0;
}


static inline int asfTimeStampLessThan(unsigned long ts_val1, unsigned long ts_val2)
{
	int diff = (ts_val2-ts_val1);
	if ((diff >= 0) && (diff < ASF_TCP_TIMESTAMP_LIMIT))
		return 1;
	return 0;
}



static inline int asfGetTimeStamp(unsigned char *tcpopt, int optlen, unsigned long *ts_val)
{

	unsigned char *endptr;

	endptr = tcpopt + optlen;
	while (tcpopt < endptr) {
		if (tcpopt[1] <= 0)
			break;

		switch (*tcpopt) {
		case TCPOPT_EOL:
		case TCPOPT_NOP:
			tcpopt++;
			break;
		case TCPOPT_MSS:
			tcpopt += 4; /* 4 byte option length */
			break;
		case TCPOPT_WINDOW:
			tcpopt += 3; /* 3 byte option length */
			break;
		case TCPOPT_TIMESTAMP:
			*ts_val = ASF_NTOHL(*((unsigned long *)  (tcpopt + 2)));
			return 0;
		default:
			tcpopt += tcpopt[1];
			break;
		}
	}
	return -1;
}


static inline int asfTcpProcessOptions(ffp_flow_t *flow, unsigned char *tcpopt, int optlen)
{
	{
		unsigned long   ts_val;
		if (asfGetTimeStamp(tcpopt, optlen, &ts_val) == 0) {
			if (!asfTimeStampLessThan(ts_val, flow->ulTcpTimeStamp-1)) {
				flow->ulTcpTimeStamp = ts_val;
				return 0;
			} else
				return -1;
		}
	}
	return 0;
}

static inline void asfTcpApplyDelta(ffp_flow_t *flow, ffp_flow_t *oth_flow, struct tcphdr *tcph,
				    unsigned long ulSeqNum, unsigned long ulAckNum)
{
	unsigned long   ulTmpDelta;

	/* Update ack number */
	if (tcph->ack) {
		ulTmpDelta = oth_flow->tcpState.ulSeqDelta;
		if (oth_flow->tcpState.bPositiveDelta) {
			tcph->ack_seq = ASF_HTONL(ulAckNum - ulTmpDelta);
		} else {
			tcph->ack_seq = ASF_HTONL(ulAckNum + ulTmpDelta);
		}
	}

	if (flow->tcpState.bPositiveDelta)
		tcph->seq = ASF_HTONL(ulSeqNum + flow->tcpState.ulSeqDelta);
	else
		tcph->seq = ASF_HTONL(ulSeqNum - flow->tcpState.ulSeqDelta);
}


int asfTcpCheckForOutOfSeq(ffp_flow_t *flow, ffp_flow_t *oth_flow,
					struct tcphdr *tcph,
					unsigned short data_len,
					asf_vsg_info_t *vsgInfo);


static inline void asfTcpUpdateState(
				    ffp_flow_t      *flow,
				    unsigned long   ulOrgSeqNum,
				    unsigned long   ulOrgAckNum,
				    struct tcphdr   *tcph,
				    unsigned long   data_len)
{
	unsigned short usWindow;

	usWindow = ASF_NTOHS(tcph->window);
	if (!asfTcpSeqGt(flow->tcpState.ulHighSeqNum, (ulOrgSeqNum + data_len))) {
		if (!(tcph->syn))
			flow->tcpState.ulHighSeqNum = ulOrgSeqNum + data_len;
		else {
			if (data_len)
				flow->tcpState.ulHighSeqNum = ulOrgSeqNum + data_len;
			else
				flow->tcpState.ulHighSeqNum = ulOrgSeqNum + 1;
		}

		if (tcph->fin)
			flow->tcpState.ulHighSeqNum += 1;
	}

	if (asfTcpSeqLe(flow->tcpState.ulRcvNext, ulOrgAckNum)) {
		flow->tcpState.ulRcvNext = ulOrgAckNum;
		flow->tcpState.ulRcvWin = usWindow;

		if (usWindow > flow->tcpState.ulMaxRcvWin) {
			flow->tcpState.ulMaxRcvWin = usWindow;
		}
	}
}



/*
  returns < 0 if the packet should be dropped
  0 if everything is fine
  > 0 in case the flow refresh indication is to be sent
	1 means FIN or RST packet recevied for the first time
	2 means FIN exchaneg and last ACk is seen
*/
static inline int asfTcpProcess(ffp_flow_t *flow, ffp_flow_t *oth_flow, struct tcphdr *tcph)
{
	int     bOldState;

	/* Connection should be offloaded only after it is established.
	 * Don't expect any SYN packets after flows are created
	 */
	if (tcph->syn)
		return -1;

	if (ASF_TCP_IS_BIT_SET(flow, RST_RCVD) && !(tcph->rst))
		return -1;

	if (ASF_TCP_IS_BIT_SET(flow, RST_LOCK) && tcph->rst)
		return -1;
	else if (ASF_TCP_IS_BIT_SET(oth_flow, RST_LOCK) && !tcph->rst)
		ASF_TCP_CLEAR_BIT(oth_flow, RST_LOCK);

	if (tcph->fin && !tcph->ack)
		return -1;

	bOldState = ASF_TCP_IS_BIT_SET(flow, FIN_RCVD) && ASF_TCP_IS_BIT_SET(oth_flow, FIN_RCVD);
	if (tcph->fin || tcph->rst) {
		ASF_TCP_SET_BIT(flow, FIN_RCVD);

		if (tcph->rst) {
			ASF_TCP_SET_BIT(oth_flow, FIN_RCVD);
			ASF_TCP_SET_BIT(flow, RST_LOCK);
		}

		/*
		 * Do the following only when both flows have
		 * FIN_RCVD bits set for the first time.
		 */
		if (!bOldState && ASF_TCP_IS_BIT_SET(flow, FIN_RCVD) && ASF_TCP_IS_BIT_SET(oth_flow, FIN_RCVD)) {
			return 1; /* requires flow TCP special packet indication for FIN/RST */
		}
	} else {
		if (tcph->ack) {
			if (ASF_TCP_IS_BIT_SET(flow, FIN_RCVD) && ASF_TCP_IS_BIT_SET(oth_flow, FIN_RCVD)) {
				flow->bDrop = oth_flow->bDrop = 1;
				return 2; /* requires flow_end indication to be sent */
			}
		}
	}

	return 0;
}


#endif
