/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
 ***************************************************************************/
/*
 * File:	asfpvt.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/

#ifndef __ASF_PVT_H
#define __ASF_PVT_H

#include "asfdeps.h"

#ifdef ASF_FFP_XTRA_STATS
typedef struct ASFFFPXtraFlowStats_s {

} ASFFFPXtraFlowStats_t;

typedef struct ASFFFPXtraGlobalStats_s {
	unsigned long   ulBridgePkts;
	unsigned long   ulInvalidBridgeDev;
	unsigned long   ulVlanPkts;
	unsigned long   ulInvalidVlanDev;
	unsigned long   ulPPPoEPkts;
	unsigned long   ulPPPoEUnkPkts;
	unsigned long   ulInvalidPPPoEDev;

	unsigned long   ulNonIpPkts;
	unsigned long   ulNonTcpUdpPkts;
	unsigned long   ulVsgSzoneUnk;
	unsigned long   ulInvalidCsum;

	unsigned long   ulIpOptPkts;

	unsigned long   ulLocalCsumVerify;
	unsigned long   ulLocalBadCsum;
	unsigned long   ulUdpBlankCsum;

	unsigned long   ulIpOptProcFail;

	unsigned long   ulIpFragPkts;
	unsigned long   ulbDropPkts;

	unsigned long   ulCondition1;
	unsigned long   ulCondition2;

	unsigned long   ulUdpPkts;
	unsigned long   ulTcpPkts;
	unsigned long   ulTcpHdrLenErr;
	unsigned long   ulTcpTimeStampErr;
	unsigned long   ulTcpOutOfSequenceErr;
	unsigned long   ulTcpProcessErr;

	unsigned long   ulNatPkts;
	unsigned long   ulBlankL2blobInd;
	unsigned long   ulFragAndXmit;
	unsigned long   ulNormalXmit;
	unsigned long   ulL2hdrAdjust;
	unsigned long   ulDevXmitErr;
	unsigned long   ulFlowEndInd;
	unsigned long   ulPktCtxInacRefreshInd;
	unsigned long   ulPktCtxL2blobInd;
	unsigned long   ulNetIfQStopped;

	unsigned long   ulCreateFlowsCmd;
	unsigned long   ulCreateFlowsCmdVsgErr;
	unsigned long   ulCreateFlowsCmdErrDown;
	unsigned long   ulCreateFlowsCmdErrDown1;
	unsigned long   ulCreateFlowsCmdErrDown2;
	unsigned long   ulCreateFlowsCmdFailures;
	unsigned long   ulDeleteFlowsCmd;
	unsigned long   ulDeleteFlowsCmdFailures;
	unsigned long   ulModifyFlowsCmd;
	unsigned long   ulModifyFlowsCmdFailures;

	unsigned long   ulBlobTmrCalls;
	unsigned long   ulTmrCtxL2blobInd;
	unsigned long   ulBlobTmrCtxBadFlow;

	unsigned long   ulInacTmrCalls;
	unsigned long   ulTmrCtxInacInd;
	unsigned long   ulInacTmrCtxBadFlow1;
	unsigned long   ulInacTmrCtxBadFlow2;

	unsigned long   ulInacTmrCtxAutoFlowDel;

	unsigned long   ulPktCmdTxInPkts;
	unsigned long   ulPktCmdTxBlobRefresh;
	unsigned long   ulPktCmdTxAutoFlowCreate;
	unsigned long   ulPktCmdTxAutoFlowBlobRefresh;
	unsigned long   ulPktCmdTxLogicalDevErr;
	unsigned long   ulPktCmdTxNonIpErr;

	unsigned long   ulPktCmdTxDummyPkt;
	unsigned long   ulPktCmdTxValidPkt;
	unsigned long   ulPktCmdTxFlowFound;
	unsigned long   ulPktCmdTxBlobInitialUpdates;
	unsigned long   ulPktCmdTxBlobTmrErr;
	unsigned long   ulPktCmdTxInacTmrErr;
	unsigned long   ulPktCmdTxVlanTag;
	unsigned long   ulPktCmdTxSkbFrees;
	unsigned long   ulPktCmdTxInvalidFlowErr;

	unsigned long   ulPktCtxAutoFlowDel;
	unsigned long   ulAutoFlowBlobRefreshSentUp;
	unsigned long   ulAutoFlowCreateSentUp;

	unsigned long   ulPktCmdTxHdrSizeErr;
	unsigned long   ulPktCmdBlobSkbFrees;
	unsigned long   ulPktCmdTxAutoDelFlows;
	unsigned long   ulPktCmdTxAutoFlowCreateErr;


} ASFFFPXtraGlobalStats_t;

#define ACCESS_XGSTATS()	ASFFFPXtraGlobalStats_t	*xgstats = asfPerCpuPtr(asf_xgstats, smp_processor_id())
#define XGSTATS_INC(f)	(xgstats->ul##f++)
#define XGSTATS_DEC(f)	(xgstats->ul##f--)

#else
#define ACCESS_XGSTATS()
#define XGSTATS_INC(f)
#define XGSTATS_DEC(f)
#endif

typedef struct ASFFFPFlowId_s {

	unsigned long ulArg1;	/* Flow Index */
	unsigned long ulArg2;	/* Flow Magic Number */

} ASFFFPFlowId_t;


extern char *asf_version;

extern int ffp_max_flows;
extern int ffp_hash_buckets;
extern int asf_tcp_fin_timeout;

extern int asf_unregister_proc(void);
extern int asf_register_proc(void);

/* Need to hold (ETH_HDR+VLAN_HDR+PPPOE_HDR+PPP_HDR)
 *	14+4+6+2 = 26 (rounded to 28 to make it multiple of 4)
 */

typedef struct ffp_flow_s {
	/* Must be first entries in this structure to enable circular list */
	struct rcu_head	 rcu;
	struct ffp_flow_s       *pPrev;
	struct ffp_flow_s       *pNext;

	ASF_uint32_t	ulVsgId;
	ASF_uint32_t	ulZoneId;
	ASF_IPv4Addr_t	ulSrcIp; /* Source IP Address */
	ASF_IPv4Addr_t	ulDestIp; /* Destination IP Address */
	ASF_uint32_t	ulPorts; /* Source Port and Destination Port */
	ASF_uint8_t	ucProtocol; /* IP Protocol */
	ASF_void_t	*as_flow_info;

	/* Source IP Address */
	ASF_IPv4Addr_t    ulSrcNATIp;

	/* Destination IP Address */
	ASF_IPv4Addr_t    ulDestNATIp;

	ASF_uint32_t	    ulNATPorts; /* Source NAT Port and Destination NAT Port */

	unsigned short	  bDrop:1, bNat:1, bVLAN:1, bPPPoE:1, bIPsecIn:1, bIPsecOut:1;
	unsigned short	  bTcpOutOfSeqCheck:1; /* TCP state processing to be on or not */
	unsigned short	  bTcpTimeStampCheck:1; /* tcp time stamp option to be checked or not ? */
	unsigned short	  bDeleted:1; /* tcp time stamp option to be checked or not ? */

	ASFFFPConfigIdentity_t  configIdentity;
	ASFFFPIpsecInfo_t       ipsecInfo;
	unsigned char	   bHeap;
	unsigned short	  pmtu;
	struct net_device       *odev;
	unsigned char	   l2blob[ASF_MAX_L2BLOB_LEN];
	unsigned short	  l2blob_len;
	unsigned short	  tx_vlan_id; /*valid if bVLAN is 1*/
	ASFFFPFlowStats_t       stats;
#ifdef ASF_FFP_XTRA_STATS
	ASFFFPXtraFlowStats_t   xstats;
#endif
	unsigned long	   ulInacTime; /* time in jiffies */
	unsigned long	   ulLastPktInAt; /* jiffies at which last packet was seen */
	unsigned long	   ulLastL2ValidationTime;

	unsigned int	    ulTcpTimeStamp;	/* current time stamp value */
	ASFFFPTcpState_t	tcpState;
	asfTmr_t		*pL2blobTmr;
	asfTmr_t		*pInacRefreshTmr;
	ASFFFPFlowId_t	  id;
	ASFFFPFlowId_t	  other_id;

	/*bool bStatic;  -> 1 for Static and 0 for dynamic  */
} ffp_flow_t;


/* this structure is mapped to ffp_flow_t structure to maintain circular list.
 * So first two entries pPrev and pNext must be at the beginning of both structures.
 */
typedef struct ffp_bucket_s {
	/* Must be first two entries in this structure to enable circular list */
	struct rcu_head	 rcu;
	ffp_flow_t	      *pPrev;
	ffp_flow_t	      *pNext;

	spinlock_t	      lock;

} ffp_bucket_t;



typedef struct asf_vsg_info_s {
	ASF_uint32_t    ulReasmTimeout;
	ASF_uint32_t    ulReasmMaxFrags;
	ASF_uint32_t    ulReasmMinFragSize;
	ASF_boolean_t   bDropOutOfSeq;
	ASFFFPConfigIdentity_t configIdentity;
	ASF_Modes_t		curMode;
	ASF_boolean_t 	bIPsec; /*IPsec function */
} asf_vsg_info_t;

extern asf_vsg_info_t *asf_ffp_get_vsg_info_node(ASF_uint32_t ulVSGId);

#ifdef ASF_DEBUG
#define SEARCH_MAX_PER_BUCKET	(1024)
#endif

#endif
