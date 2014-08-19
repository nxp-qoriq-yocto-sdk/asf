/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfpvt.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 * 22 Jul 2011 - Sachin Saxena - Changes to introduce ASF tool kit support.
 *
*/
/******************************************************************************/

#ifndef __ASF_PVT_H
#define __ASF_PVT_H

#include "asf.h"
#include "asfdeps.h"
#include "asfipsec.h"


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

	unsigned long   ulSctpPkts;

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

	unsigned long	ulTmrProcCalls;
	unsigned long	ulTmrProcReclCalls;
	unsigned long	ulTmrStarts;
	unsigned long	ulTmrStopExpireSoon;
	unsigned long	ulTmrStopSameCore;
	unsigned long	ulTmrStopOtherCore;
	unsigned long	ulTmrStopOtherCoreReclaimQFull;
	unsigned long	ulTmrProcTimerRestart;
	unsigned long	ulTmrProcTimerDelete;
	unsigned long	ulTmrProcReclaimQTimerDelete;
	unsigned long	ulDefragCalls;
	unsigned long	ulDefragCallsTcp;
	unsigned long	ulDefragCallsUdp;
	unsigned long	ulDefragCallsOther;
	unsigned long	ulDefragIntegrityErr;
	unsigned long	ulDefragTotLenExceedErr;
	unsigned long	ulDefragCompleted;
	unsigned long	ulDefragFragHandleErr;
	unsigned long	ulDefragCbAllocErr;
	unsigned long	ulDefragCbMatches;
	unsigned long	ulDefragCbAllocs;
	unsigned long	ulDefragCbDeletes;
	unsigned long	ulDefragCbTimerStart;
	unsigned long	ulDefragCbTimerStartErr;
	unsigned long	ulDefragCbAllocIndexArrayErr;
	unsigned long	ulDefragCbTimerCalls;
	unsigned long	ulDefragCbTimerMagicMatched;
	unsigned long	ulDefragCbTimerTimeout;
	unsigned long	ulDefragCbTimerWillRestart;
	unsigned long	ulDefragCbTimerMagicMatchErr;
	unsigned long	ulFragHandleCalls;

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

	unsigned int ulArg1;	/* Flow Index */
	unsigned int ulArg2;	/* Flow Magic Number */

} ASFFFPFlowId_t;


extern char *asf_version;
extern int asf_max_vsgs;
extern int ffp_max_flows;
extern int ffp_hash_buckets;
extern bool asf_enable;
extern int asf_l2blob_refresh_npkts;
extern int asf_l2blob_refresh_interval;
extern ASFFFPGlobalStats_t *asf_gstats;
#ifdef ASF_FFP_XTRA_STATS
extern ASFFFPXtraGlobalStats_t *asf_xgstats;
#endif
extern ASFFFPVsgStats_t *asf_vsg_stats;
extern int asf_reasm_timeout;
extern int asf_reasm_maxfrags;
extern int asf_reasm_min_fragsize;
extern unsigned int asf_vlan_magicnumber;
extern int asf_tcp_fin_timeout;

extern int asf_unregister_proc(void);
extern int asf_register_proc(void);

#ifdef ASF_IPSEC_FP_SUPPORT
extern ASFFFPIPSecInv4_f pFFPIPSecIn;
extern ASFFFPIPSecOutv4_f pFFPIPSecOut;
extern ASFFFPIPSecInVerifyV4_f pFFPIpsecInVerify;
extern ASFFFPIPSecProcessPkt_f pFFPIpsecProcess;
#endif
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
	union {
		ASF_IPv4Addr_t	ulSrcIp; /* Source IP Address */
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t	ipv6SrcIp; /* Source IPV6 Address */
#endif
	};
	union {
		ASF_IPv4Addr_t	ulDestIp; /* Destination IP Address */
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t	ipv6DestIp; /* Destination IPV6 Address */
#endif
	};
	ASF_uint32_t	ulPorts; /* Source Port and Destination Port */
	ASF_uint8_t	ucProtocol; /* IP Protocol */
	ASF_void_t	*as_flow_info;

	/* Source IP Address */
	union {
		ASF_IPv4Addr_t    ulSrcNATIp;
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t    ipv6SrcNATIp;
#endif
	};

	/* Destination IP Address */
	union {
		ASF_IPv4Addr_t    ulDestNATIp;
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t    ipv6DestNATIp;
#endif
	};

	ASF_uint32_t	    ulNATPorts; /* Source NAT Port and Destination NAT Port */

	unsigned short	  bDrop:1, bNat:1, bVLAN:1, bPPPoE:1, bIPsecIn:1, bIPsecOut:1, bIP6IP4In:1, bIP6IP4Out:1,  bIP4IP6In:1, bIP4IP6Out:1;
	unsigned short	  bTcpOutOfSeqCheck:1; /* TCP state processing to be on or not */
	unsigned short	  bTcpTimeStampCheck:1; /* tcp time stamp option to be checked or not ? */
	unsigned short	  bDeleted:1; /* tcp time stamp option to be checked or not ? */
	unsigned short	bHeap:1;
	unsigned short	  pmtu;

	ASFFFPConfigIdentity_t  configIdentity;
	ASFFFPIpsecInfo_t       ipsecInfo;
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
#ifdef ASF_INGRESS_MARKER
	ASFMKInfo_t	mkinfo;
#endif
#ifdef ASF_EGRESS_QOS
	unsigned int tc_filter_res;
#endif
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
	ASF_uint32_t	ulTcpSeqNumRange;
	ASF_uint32_t	ulTcpRstSeqNumRange;
	ASFFFPConfigIdentity_t configIdentity;
	ASF_Modes_t		curMode;
	ASF_boolean_t 	bIPsec; /*IPsec function */
} asf_vsg_info_t;

extern asf_vsg_info_t *asf_ffp_get_vsg_info_node(ASF_uint32_t ulVSGId);
extern void asfReasmSetConfigParams(unsigned int ulVSGId,
			unsigned int ulReasmMaxFrags,
			unsigned int ulReasmMinFragSize,
			unsigned int ulReasmTimeout,
			unsigned int ulreasmMaxPktSize);

extern const struct	file_operations asf_interface_fops;
extern spinlock_t	asf_app_lock;
extern ffp_bucket_t *ffp_flow_table;

#ifdef ASF_DEBUG
#define SEARCH_MAX_PER_BUCKET	(1024)
#endif

#endif
