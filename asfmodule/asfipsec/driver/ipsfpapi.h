/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsfpapi.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/***************************************************************************/

#ifndef IPS_FP_API_H
#define IPS_FP_API_H

#ifdef VQA_IPSEC_ASF_SUPPORT
#include "asf.h"
#else
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfipsec.h"
#endif
#include <linux/types.h>

#define ASF_IPSEC_IKE_NATtV1    1
#define ASF_IPSEC_IKE_NATtV2    2

typedef atomic_t ASFAtomic_t;

typedef struct ASFIPSecAuthAlgoCap_s {
	ASF_uint32_t bMD5:1,
	bSHA1:1,
	bAES_XBC:1;
} ASFIPSecAuthAlgoCap_t;


typedef struct ASFIPSecEncryptAlgoCap_s {
	ASF_uint32_t bDES:1,
	b3DES:1,
	bAES:1,
	bAES_CTR:1;
} ASFIPSecEncryptAlgoCap_t;

typedef struct ASFIPSecCap_s {
	ASF_uint32_t bSelStoreInSPD:1,
	bAH:1,
	bESP:1,
	bIpComp:1,
	bTunnelMode:1,
	bTransportMode:1,
	bEsn:1,
	bMultiSecProto:1,
	bLifeTimeSec:1,
	bLifeTimeKB:1,
	bNATTraversal:1,
	bRedSideFragmentation:1,
	bPeerGWAdoption:1,
	bLocalGWAdoption:1;
	ASF_uint32_t	     ulFragOptions;
	ASFIPSecAuthAlgoCap_t    AuthAlgoCap;
	ASFIPSecEncryptAlgoCap_t EncryptAlgoCap;
	ASF_uint32_t	     ulMaxVSGs;
	ASF_uint32_t	     ulMaxTunnels;
	ASF_uint32_t	     ulMaxSPDContainers;
	ASF_uint32_t	     ulMaxSupportedIPSecSAs;
	ASF_boolean_t	    bBufferHomogenous;
} ASFIPSecCap_t;

enum ASFIPSecConfigCommands {
	ASF_IPSEC_CONFIG_ADD_OUTSPDCONTAINER = 1,
	ASF_IPSEC_CONFIG_DEL_OUTSPDCONTAINER,
	ASF_IPSEC_CONFIG_ADD_INSPDCONTAINER,
	ASF_IPSEC_CONFIG_DEL_INSPDCONTAINER,
};

typedef ASF_uint32_t ASF_IPSecPolicyRule_ID_t;

typedef enum {
	ASF_IPSEC_POLICY_ACTION_IPSEC = 1,
	ASF_IPSEC_POLICY_ACTION_DISCARD = 2,
	ASF_IPSEC_POLICY_ACTION_BYPASS = 3
} ASF_IPSecPolicyRule_Action_t;

typedef enum {
	ASF_IPSEC_ADDR_TYPE_SUBNET = 0,
	ASF_IPSEC_ADDR_TYPE_RANGE = 1
} ASF_IPSecSelectorAddrType_t;

typedef ASF_uint32_t  ASF_IPv4Address_t;
typedef struct {
	ASF_IPv4Address_t IPv4Addrs; /* IPv4 address */	/* iGateway */
	ASF_uint8_t       IPv4Plen; /* Prefix length in bits (1-32) */
} ASF_IPv4Prefix_t;

typedef struct {
	union {
		ASF_uchar8_t b_addr[16];
		ASF_uint32_t w_addr[4];
	} u;
} ASF_IPv6Address_t;

typedef struct {
	ASF_IPv6Address_t IPv6Addr;
	ASF_uint8_t       IPv6Plen;
} ASF_IPv6Prefix_t;

typedef union {
	ASF_IPv4Prefix_t v4;
	ASF_IPv6Prefix_t v6;
} ASF_IPSecPrefix_t;

typedef struct {
	ASF_IPv4Address_t start;
	ASF_IPv4Address_t end;
} ASF_IPSecIPv4RangeAddr_t;

typedef struct {
	ASF_IPv6Address_t start;
	ASF_IPv6Address_t end;
} ASF_IPSecIPv6RangeAddr_t;

typedef union {
	ASF_IPSecIPv4RangeAddr_t v4;
	ASF_IPSecIPv6RangeAddr_t v6;
} ASF_IPSecRangeAddr_t;

typedef struct ASF_IPSecSelectorAddr_s {
	ASF_IPSecSelectorAddrType_t addrType;
	ASF_uint8_t nIpRangeCnt;
	union {
		ASF_IPSecPrefix_t prefixAddr;
		ASF_IPSecRangeAddr_t *rangeAddr;
	} u;
} ASF_IPSecSelectorAddr_t;

typedef struct {
	ASF_uint16_t start;
	ASF_uint16_t end;
} ASF_IPSecSelectorPort_t;

#define ASF_IPSEC_SELECTORRULEFLAG_CLEAR (0) /* default */
#define ASF_IPSEC_SELECTORRULEFLAG_NOT_SET (1 << 0)
#define ASF_IPSEC_SELECTORRULEFLAG_AND_SET (1 << 1)

typedef struct {
	ASF_uint8_t	       ruleFlags;
	ASF_uint8_t	       IP_Version;
	ASF_uint8_t	       protocol;
	ASF_uint8_t	       nSrcIPCnt;
	ASF_IPSecSelectorAddr_t  *srcIP;
	ASF_uint8_t	       nDstIPCnt;
	ASF_IPSecSelectorAddr_t  *dstIP;
	ASF_uint8_t	       nSrcPortCnt;
	ASF_IPSecSelectorPort_t  *srcPort;
	ASF_uint8_t	       nDstPortCnt;
	ASF_IPSecSelectorPort_t  *dstPort;
} ASF_IPSecSelector_t;

typedef struct {
	ASF_uint8_t start;
	ASF_uint8_t end;
} ASF_IPSecPolicyRule_DscpRange_t;

typedef enum {
	ASF_IPSEC_POLICY_STATUS_ENABLE = 0,
	ASF_IPSEC_POLICY_STATUS_DISABLE = 1
} ASF_IPSecPolicyRule_Status_t;

typedef enum {
	ASF_IPSEC_POLICY_POSITION_BEGIN = 1,
	ASF_IPSEC_POLICY_POSITION_BEFORE = 2,
	ASF_IPSEC_POLICY_POSITION_AFTER = 3,
	ASF_IPSEC_POLICY_POSITION_END = 4
} ASF_IPSecPolicyRule_Position_t;

typedef enum {
	ASF_IPSEC_POLICY_FRAGOPTS_REASSEMBLE_BEFORE_IPSEC = 0,
	ASF_IPSEC_POLICY_FRAGOPTS_SAMESA_FOR_NONINITIAL_FRAG = 1,
	ASF_IPSEC_POLICY_FRAGOPTS_STATEFULL_FRAG_CHECK = 2,
	ASF_IPSEC_POLICY_FRAGOPTS_SEPARATESA_FOR_NONINITIAL_FRAG = 3
} ASF_IPSecFragHandle_t;

#define ASF_IPSEC_POLICY_FLAGS_PFP_SOURCE_IP	0x01
#define ASF_IPSEC_POLICY_FLAGS_PFP_DESTINATION_IP   0x02
#define ASF_IPSEC_POLICY_FLAGS_PFP_SOURCE_PORT      0x04
#define ASF_IPSEC_POLICY_FLAGS_PFP_DESTINATION_PORT 0x08
#define ASF_IPSEC_POLICY_FLAGS_PFP_PROTOCOL	 0x10
#define ASF_IPSEC_POLICY_FLAGS_PFP_DSCP_RANGE       0x20

typedef enum asfIPSecPolicyPPStats {
	ASF_IPSEC_PP_POL_CNT1 = 1,
	ASF_IPSEC_PP_POL_CNT2,
	ASF_IPSEC_PP_POL_CNT3,
	ASF_IPSEC_PP_POL_CNT4,
	ASF_IPSEC_PP_POL_CNT5,
	ASF_IPSEC_PP_POL_CNT6,
	ASF_IPSEC_PP_POL_CNT7,
	ASF_IPSEC_PP_POL_CNT8,
	ASF_IPSEC_PP_POL_CNT9, /*23 */
	ASF_IPSEC_PP_POL_CNT10, /*11 */
	ASF_IPSEC_PP_POL_CNT11, /* 65 */
	ASF_IPSEC_PP_POL_CNT12, /*66 */
	ASF_IPSEC_PP_POL_CNT13, /*60*/
	ASF_IPSEC_PP_POL_CNT14, /*20 */
	ASF_IPSEC_PP_POL_CNT15, /*22 */
	ASF_IPSEC_PP_POL_CNT16, /*21 */
	ASF_IPSEC_PP_POL_CNT17, /*29*/
	ASF_IPSEC_PP_POL_CNT18, /*60*/
	ASF_IPSEC_PP_POL_CNT19, /*22*/
	ASF_IPSEC_PP_POL_CNT20, /*38*/
	ASF_IPSEC_PP_POL_CNT21, /*57*/
	ASF_IPSEC_PP_POL_CNT22,
	ASF_IPSEC_PP_POL_CNT_MAX
} asfIPSecPolicyPPStats_e;

#define ASF_IPSEC4_PP_POL_CNT_MAX  ASF_IPSEC_PP_POL_CNT_MAX

typedef enum asfIPSecGlobalPPStats {
	ASF_IPSEC_PP_GBL_CNT1  = 1, /* Total Received Inbound Pkts*/
	ASF_IPSEC_PP_GBL_CNT2, /* Total Processed Inbound Pkts */
	ASF_IPSEC_PP_GBL_CNT3, /* Total Received Outbound Pkts */
	ASF_IPSEC_PP_GBL_CNT4, /* Total Processed Outbound Pkts */
	ASF_IPSEC_PP_GBL_CNT5, /* Total Received Inbound Sec. Pkts*/
	ASF_IPSEC_PP_GBL_CNT6, /* Total Processed Inbound Sec. Pkts */
	ASF_IPSEC_PP_GBL_CNT7, /* Total Received Outbound Pkts to apply security */
	ASF_IPSEC_PP_GBL_CNT8, /* Total Outbound Pkts applied security*/
	ASF_IPSEC_PP_GBL_CNT9, /* Does not enough tail room to continue 30*/
	ASF_IPSEC_PP_GBL_CNT10, /*No of packets Invalid ESP */
	ASF_IPSEC_PP_GBL_CNT11, /*Decrypted Protocol != IPV4 88  */
	ASF_IPSEC_PP_GBL_CNT12, /*Invalid Pad legth */
	ASF_IPSEC_PP_GBL_CNT13, /*Inbound Submission to SEC failed 83*/
	ASF_IPSEC_PP_GBL_CNT14, /*Invalid sequence number */
	ASF_IPSEC_PP_GBL_CNT15, /*Anti-replay window check failed */
	ASF_IPSEC_PP_GBL_CNT16, /*Replay packet */
	ASF_IPSEC_PP_GBL_CNT17, /*ICV Comp Failed */
	ASF_IPSEC_PP_GBL_CNT18, /*Crypto Operation Failed */
	ASF_IPSEC_PP_GBL_CNT19, /*Anti Replay window -- Drop the packet  */
	ASF_IPSEC_PP_GBL_CNT20, /*Verification of SA Selectross Failed  */
	ASF_IPSEC_PP_GBL_CNT21, /* Packet size is > Path MTU and fragment bit set in SA or packet  */
	ASF_IPSEC_PP_GBL_CNT22, /*Fragmentation Failed 78*/
	ASF_IPSEC_PP_GBL_CNT23, /*In SA Not Found*/
	ASF_IPSEC_PP_GBL_CNT24, /*Out SA not Found*/
	ASF_IPSEC_PP_GBL_CNT_MAX
} asfIPSecGlobalPPStats_e;

#define ASF_IPSEC4_PP_GBL_CNT_MAX ASF_IPSEC_PP_GBL_CNT_MAX

typedef struct asfIPSecPPGlobalStats_st {
	ASF_uint32_t  ulTotInRecvPkts;
	ASF_uint32_t  ulTotInProcPkts;
	ASF_uint32_t  ulTotOutRecvPkts;
	ASF_uint32_t  ulTotOutProcPkts;
	ASF_uint32_t  ulTotInRecvSecPkts;
	ASF_uint32_t  ulTotInProcSecPkts;
	ASF_uint32_t  ulTotOutRecvPktsSecApply;
	ASF_uint32_t  ulTotOutPktsSecAppled;
} AsfIPSecPPGlobalStats_t;


typedef struct ASFIPSec4GlobalPPStats_st {
	ASF_uint32_t IPSec4GblPPStat[ASF_IPSEC4_PP_GBL_CNT_MAX];
	ASF_uint32_t ulMax;
} ASFIPSec4GlobalPPStats_t;

typedef struct ASFSPDPolPPStats_st {
	ASF_uint32_t  IPSecPolPPStats[ASF_IPSEC_PP_POL_CNT_MAX];
	ASF_uint32_t ulMax;
} ASFSPDPolPPStats_t;

typedef struct asfIPSec4GlobalPPStats_st {
	ASFAtomic_t IPSec4GblPPStat[ASF_IPSEC4_PP_GBL_CNT_MAX];
	ASF_uint32_t ulMax;
} AsfIPSec4GlobalPPStats_t;

typedef struct asfSPDPolicyPPStats_st {
	ASF_uint32_t	   NumInBoundInPkts;
	ASF_uint32_t	   NumInBoundOutPkts;
	ASF_uint32_t	   NumOutBoundInPkts;
	ASF_uint32_t	   NumOutBoundOutPkts;
} AsfSPDPolicyPPStats_t;


typedef struct asfSPDPolPPStats_st {
	ASFAtomic_t    IPSecPolPPStats[ASF_IPSEC_PP_POL_CNT_MAX];
	ASF_uint32_t ulMax;
} AsfSPDPolPPStats_t;

typedef struct {
	ASF_IPSecPolicyRule_ID_t	 policyID; /* Policy ID */
	ASF_IPSecPolicyRule_Action_t     policyAction; /* Action */
	ASF_uint32_t		     selectorCount;	/* No of selectors */
	ASF_IPSecSelector_t	     *selectorArray;	/* Selector array */
	ASF_uint8_t		      dscpRangeCount; /* No of selectors */
	ASF_IPSecPolicyRule_DscpRange_t *dscpRange;
	ASF_uint8_t		      PFP_flags; /* PFP Selectors */
	ASF_IPSecPolicyRule_Status_t     policyStatus; /* Disable / Enable */
	ASF_IPSecPolicyRule_Position_t   policyPosition; /* Policy Position */
	ASF_IPSecPolicyRule_ID_t	 relativePolicyID; /* Relative Policy ID */
	ASF_boolean_t		    fragBeforeEncap;
	ASF_IPSecFragHandle_t	    fragHandleOpts;
} ASF_IPSecPolicy_t;

typedef struct ASFIPSecConfigAddOutSPDContainerArgs_s {
	ASF_uint32_t       ulTunnelId;
	ASF_uint32_t       ulSPDContainerIndex;
	ASF_uint32_t       ulMagicNumber;
	ASF_IPSecPolicy_t *pSPDParams;
} ASFIPSecConfigAddOutSPDContainerArgs_t;


typedef struct ASFIPSecConfigDelOutSPDContainerArgs_s {
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulContainerIndex;
	ASF_uint32_t ulMagicNumber;
} ASFIPSecConfigDelOutSPDContainerArgs_t;

typedef struct ASFIPSecConfigAddInSPDContainerArgs_s {
	ASF_uint32_t       ulTunnelId;
	ASF_uint32_t       ulSPDContainerIndex;
	ASF_uint32_t       ulMagicNumber;
	ASF_IPSecPolicy_t *pSPDParams;
} ASFIPSecConfigAddInSPDContainerArgs_t;


typedef struct ASFIPSecConfigDelInSPDContainerArgs_s {
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulContainerIndex;
	ASF_uint32_t ulMagicNumber;
} ASFIPSecConfigDelInSPDContainerArgs_t;


enum ASFIPSecRunTimeCommands {
	ASF_IPSEC_RUNTIME_ADD_OUTSA = 1,
	ASF_IPSEC_RUNTIME_DEL_OUTSA,
	ASF_IPSEC_RUNTIME_ADD_INSA,
	ASF_IPSEC_RUNTIME_DEL_INSA,
	ASF_IPSEC_RUNTIME_MOD_OUTSA,
	ASF_IPSEC_RUNTIME_MOD_INSA,
	ASF_IPSEC_RUNTIME_SET_DPD,
	ASF_IPSEC_RUNTIME_MOD_INFLOW
};

typedef struct ASF_IPSecSASelectorAddr_s {
	ASF_IPSecSelectorAddrType_t addrType;
	union {
		ASF_IPSecPrefix_t prefixAddr;
		ASF_IPSecRangeAddr_t rangeAddr;
	} u;
} ASF_IPSecSASelectorAddr_t;

typedef struct {
	ASF_uint16_t start; /* First port in range */
	ASF_uint16_t end; /* Last port in range */
} ASF_IPSecPortRange_t;

typedef struct ASF_IPSecSelectorSet_s {
	ASF_uint8_t ruleFlags;
	ASF_uint8_t IP_Version;
	ASF_uint8_t protocol;
	ASF_IPSecSASelectorAddr_t addr;
	ASF_IPSecPortRange_t port;
} ASF_IPSecSelectorSet_t;


typedef struct ASF_IPSecSASelector_s {
	ASF_uint8_t	      nsrcSel;
	ASF_IPSecSelectorSet_t  *srcSel;
	ASF_uint8_t	      ndstSel;
	ASF_IPSecSelectorSet_t  *dstSel;
} ASF_IPSecSASelector_t;


#define ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED  0x0
#define ASF_IPSEC_RED_SIDE_FRAGMENTATION_ENABLED   0x1

#define ASF_IPSEC_SA_SELECTOR_VERIFICATION_NOT_NEEDED  0x0
#define ASF_IPSEC_SA_SELECTOR_VERIFICATION_NEEDED      0x1

#define ASF_IPSEC_ADAPT_PEER_GATEWAY_DISABLE  0x0
#define ASF_IPSEC_ADAPT_PEER_GATEWAY_ENABLE   0x01

#define ASF_IPSEC_NAT_TRAVERSAL_NOT_PRESENT  0x0
#define ASF_IPSEC_NAT_TRAVERSAL_PRESENT      0x01

#define ASF_IPSEC_ESN_DISABLE  0x0
#define ASF_IPSEC_ESN_ENABLE   0x01

#define ASF_IPSEC_QOS_TOS_ECN_CHECK_OFF  0x0
#define ASF_IPSEC_QOS_TOS_ECN_CHECK_ON   0x01

#define ASF_IPSEC_SA_SAFLAGS_LIFESECS_ON   0x01
#define ASF_IPSEC_SA_SAFLAGS_LIFESECS_OFF  0x00

#define ASF_IPSEC_SA_SAFLAGS_REPLAY_ON   0x01
#define ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF  0x00

#define ASF_IPSEC_SA_SAFLAGS_TUNNELMODE     0x0
#define ASF_IPSEC_SA_SAFLAGS_TRANSPORTMODE  0x01


#define ASF_IPSEC_QOS_TOS_COPY	 0x0
#define ASF_IPSEC_QOS_TOS_CLEAR	0x01
#define ASF_IPSEC_QOS_TOS_SET	  0x02

#define ASF_IPSEC_QOS_DSCP_COPY	0x0
#define ASF_IPSEC_QOS_DSCP_CLEAR       0x01
#define ASF_IPSEC_QOS_DSCP_SET	 0x02
#define ASF_IPSEC_QOS_FLOWLABEL_COPY   0x00
#define ASF_IPSEC_QOS_FLOWLABEL_CLEAR  0x10
#define ASF_IPSEC_QOS_FLOWLABEL_SET    0x20

#define ASF_IPSEC_DF_COPY      0x0
#define ASF_IPSEC_DF_CLEAR     0x01
#define ASF_IPSEC_DF_SET       0x02


#define ASF_IPSEC_PROTOCOL_ESP		50
#define ASF_IPSEC_PROTOCOL_AH		51
#define ASF_IPSEC_PROTOCOL_IPCOMP	108


typedef  struct {
	ASF_uint32_t ulNATt;
	ASF_uint16_t usDstPort;
	ASF_uint16_t usSrcPort;
} ASF_IPSec_Nat_Info_t;

typedef struct {
	ASF_uint32_t  spi;
	ASF_uint8_t   qos;
	ASF_uint32_t  flags;
	ASF_uint32_t  reserved:4,
	bRedSideFragment:1,
	bVerifyInPktWithSASelectors:1,
	bDoPeerGWIPAddressChangeAdaptation:1,
	bDoUDPEncapsulationForNATTraversal:1,
	bUseExtendedSequenceNumber:1,
	bPropogateECN:1,
	bSALifeTimeInSecs:1,
	bDoAntiReplayCheck:1,
	bEncapsulationMode:1,
	handleToSOrDSCPAndFlowLabel:8,
	handleDFBit:2,
	protocol:8;
	int   authAlgo;
	int  encAlgo;
	ASF_uint32_t softKbyteLimit;
	ASF_uint32_t hardKbyteLimit;
	__u64 softSecsLimit;
	__u64 hardSecsLimit;
	ASF_IPSecTunEndAddr_t TE_Addr;
	ASF_uint8_t   *authKey;
	ASF_uint32_t   authKeyLenBits;
	ASF_uint8_t   *encDecKey;
	ASF_uint32_t   encDecKeyLenBits;
	ASF_uint32_t    replayWindowSize;
	ASF_uint8_t    compAlgo;
	ASF_uint16_t   aesCtrBlkLenBits;
	ASF_uint8_t   *aesCtrCounterBlock;
	ASF_uint32_t   ulMtu;
	ASF_IPSec_Nat_Info_t IPsecNatInfo;
	ASF_uint32_t ulCommonInterfaceId;
} ASF_IPSecSA_t;


typedef struct ASFIPSecRuntimeAddOutSAArgs_s {
	ASF_uint32_t   ulTunnelId;
	ASF_uint32_t   ulSPDContainerIndex;
	ASF_uint32_t   ulMagicNumber ;
	ASF_uint16_t   usDscpStart;
	ASF_uint16_t   usDscpEnd;
	ASF_IPSecSASelector_t  *pSASelector;
	ASF_IPSecSA_t  *pSAParams;
} ASFIPSecRuntimeAddOutSAArgs_t;


typedef struct ASFIPSecRuntimeDelOutSAArgs_s {
	ASF_uint32_t     ulTunnelId;
	ASF_uint32_t     ulSPDContainerIndex;
	ASF_uint32_t     ulSPDMagicNumber;
	ASF_uint32_t     ulSPI;
	ASF_IPAddr_t     DestAddr;
	ASF_uint8_t      ucProtocol;
	ASF_uint16_t      usDscpStart;
	ASF_uint16_t      usDscpEnd;
} ASFIPSecRuntimeDelOutSAArgs_t;


typedef struct ASFIPSecRuntimeAddInSAArgs_s {
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulInSPDContainerIndex;
	ASF_uint32_t ulInSPDMagicNumber;
	ASF_uint32_t ulOutSPDContainerIndex;
	ASF_uint32_t ulOutSPDMagicNumber;
	ASF_uint32_t ulOutSPI;
	ASF_IPAddr_t DestAddr;
	ASF_IPSecSASelector_t  *pSASelector;
	ASF_IPSecSA_t *pSAParams;
} ASFIPSecRuntimeAddInSAArgs_t;


typedef struct ASFIPSecRuntimeDelInSAArgs_s {
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulSPDContainerIndex;
	ASF_uint32_t ulSPDMagicNumber;
	ASF_uint32_t ulSPI;
	ASF_IPAddr_t DestAddr;
	ASF_uint8_t  ucProtocol;
} ASFIPSecRuntimeDelInSAArgs_t;

typedef struct ASFIPSecRuntimeModOutSAArgs_s {
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulSPDContainerIndex;
	ASF_uint32_t ulSPDContainerMagicNumber;
	ASF_IPAddr_t DestAddr;
	ASF_uint8_t  ucProtocol;
	ASF_uint32_t ulSPI;
	ASF_uchar8_t ucChangeType;
	union {
		struct {
			ASF_uint16_t  usPort;
			ASF_IPAddr_t  IPAddr;
		} addrInfo;
		ASF_uint32_t ulMtu;
		struct {
			ASF_uchar8_t l2blob[ASF_MAX_L2BLOB_LEN];
			ASF_uint16_t ulL2BlobLen;
			ASF_uint16_t ulDeviceID;
			ASF_uint16_t bTxVlan:1, bUpdatePPPoELen:1;
			ASF_uint16_t usTxVlanId;
			ASF_uint32_t ulL2blobMagicNumber;
		} l2blob;
	} u;
} ASFIPSecRuntimeModOutSAArgs_t;

typedef struct ASFIPSecRuntimeModInSAArgs_s {
	ASF_uint32_t  ulTunnelId;
	ASF_uint32_t  ulSPDContainerIndex;
	ASF_uint32_t  ulSPDContainerMagicNumber;
	ASF_IPAddr_t  DestAddr;
	ASF_uint8_t   ucProtocol;
	ASF_uint32_t  ulSPI;
	ASF_uchar8_t  ucChangeType;
	ASF_uint16_t  usPort;
	ASF_IPAddr_t  IPAddr;
} ASFIPSecRuntimeModInSAArgs_t;

typedef struct ASFIPSecRuntimeSetDPDArgs_s {
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulInSPDContainerIndex;
	ASF_uint32_t ulMagicNumber;
} ASFIPSecRuntimeSetDPDArgs_t;

typedef struct ASFIPSecRuntimeSetFlowL2BlobArgs_s {
	ASF_IPAddr_t  srcAddr;
	ASF_IPAddr_t  destAddr;
	ASF_uint8_t   ucProtocol;
	ASF_uint16_t  srcPort;
	ASF_uint16_t  destPort;
	struct {
		ASF_uchar8_t l2blob[ASF_MAX_L2BLOB_LEN];
		ASF_uint32_t ulL2BlobLen;
		ASF_uint32_t ulDeviceID;
		ASF_uint16_t bTxVlan:1, bUpdatePPPoELen:1;
		ASF_uint16_t usTxVlanId;
		ASF_uint32_t ulL2blobMagicNumber;
	} l2blob;
} ASFIPSecRuntimeSetFlowL2BlobArgs_t;

typedef struct ASFIPSecUpdateVSGMagicNumber_s {
	ASF_uint32_t  ulVSGId;
	ASF_uint32_t  ulVSGMagicNumber;
	ASF_uint32_t  ulL2blobMagicNumber;
} ASFIPSecUpdateVSGMagicNumber_t;

typedef struct ASFIPSecUpdateTunnelMagicNumber_s {
	ASF_uint32_t  ulVSGId;
	ASF_uint32_t  ulTunnelId;
	ASF_uint32_t  ulTunnelMagicNumber;
} ASFIPSecUpdateTunnelMagicNumber_t;

typedef struct ASFIPSecInitConfigIdentity_s {
	ASF_uint32_t  ulMaxVSGs;
	ASF_uint32_t  ulMaxTunnels;
	ASF_uint32_t  *pulVSGMagicNumber;
	ASF_uint32_t  *pulVSGL2blobMagicNumber;
	ASF_uint32_t  **pulTunnelMagicNumber;
} ASFIPSecInitConfigIdentity_t;

/* Function Poineters for Callbacks */

typedef ASF_void_t (*genericFreeFn_f)(ASF_void_t   *freeArg);

typedef ASF_void_t (*pASFIPSecCbFnNoInSA_f) (ASF_uint32_t ulVSGId, ASFBuffer_t Buffer,
					     genericFreeFn_f pFreeFn,
					     ASF_void_t   *freeArg,
					     ASF_uint32_t ulCommonInterfaceId);

typedef ASF_void_t    (*pASFIPSecCbFnNoOutSA_f)(ASF_uint32_t ulVSGId,
						ASFFFPFlowTuple_t *tuple,
						ASFBuffer_t Buffer,
						genericFreeFn_f pFreeFn,
						ASF_void_t *freeArg,
						ASF_uchar8_t bSPDContainerPresent,
						ASF_uchar8_t bRevalidate);

typedef ASF_void_t    (*pASFIPSecCbFnVerifySPD_f)(ASF_uint32_t ulVSGId,
						  ASF_uint32_t ulInSPDContainerIndex,
						  ASF_uint32_t ulMagicNumber,
						  ASF_uint32_t ulSPI,
						  ASF_uint8_t ucProtocol,
						  ASF_IPAddr_t DestAddr,
						  ASFBuffer_t Buffer,
						  genericFreeFn_f pFreeFn,
						  ASF_void_t    *freeArg,
						  ASF_uchar8_t bRevalidate,
						  ASF_uint32_t ulCommonInterfaceId);

typedef  ASF_void_t    (*pASFIPSecSendWithL2Blob_f)(ASF_uint32_t ulVSGId,
						    ASF_uint32_t ulTunnelId,
						    ASF_uint32_t ulOutSPDContainerIndex,
						    ASF_uint32_t ulOutSPDMagicNumber,
						    ASF_IPSecTunEndAddr_t *addresses,
						    ASF_uint8_t ucProtocol);

typedef ASF_void_t    (*pASFIPSecCbFnDPDAlive_f)(ASF_uint32_t ulVSGId,
						 ASF_uint32_t ulTunnelId,
						 ASF_uint32_t ulSPI,
						 ASF_uint8_t ucProtocol,
						 ASF_IPAddr_t  DestAddr,
						 ASF_uint32_t ulSPDContainerIndex);

typedef ASF_void_t    (*pASFIPSecCbFnSeqNoOverFlow_f)(ASF_uint32_t ulVSGId,
						      ASF_uint32_t ulTunnelId,
						      ASF_uint32_t ulSPI,
						      ASF_uint8_t ucProtocol,
						      ASF_IPAddr_t  DestAddr);

typedef  ASF_void_t   (*pASFIPSecCbFnRefreshL2Blob_f)(ASF_uint32_t ulVSGId,
						      ASF_uint32_t ulTunnelId,
						      ASF_uint32_t ulOutSPDContainerIndex,
						      ASF_uint32_t ulOutSPDMagicNumber,
						      ASF_IPSecTunEndAddr_t *addresses,
						      ASF_uint32_t ulSPI,
						      ASF_uchar8_t ucProtocol);
typedef ASF_void_t    (*pASFIPSecCbFnNoOutFlowFound_f)(ASF_uint32_t ulVSGId,
						       ASF_IPAddr_t  srcAddr,
						       ASF_IPAddr_t destAddr,
						       ASF_uint8_t ucProtocol,
						       ASF_uint16_t srcPort,
						       ASF_uint16_t destPort,
						       ASFBuffer_t Buffer,
						       genericFreeFn_f pFreeFn,
						       ASF_void_t *freeArg);

typedef ASF_void_t    (*pASFIPSecCbFnVSGMappingNotFound_f)(
							  ASF_uint32_t ulCommonInterfaceid,
							  ASFFFPFlowTuple_t tuple,
							  ASFBuffer_t Buffer,
							  genericFreeFn_f pFreeFn,
							  ASF_void_t *freeArg);

typedef ASF_void_t    (*pASFIPSecCbFnInterfaceInfoNotFound_f)(
							     ASFFFPFlowTuple_t tuple,
							     ASFBuffer_t Buffer,
							     genericFreeFn_f pFreeFn,
							     ASF_void_t *freeArg);

typedef ASF_void_t    (*pASFIPSecCbFnConfig_f)(ASF_uint32_t ulVSGId,
					       ASF_uint32_t cmd,
					       ASF_uint32_t response,
					       ASF_void_t   *pRequestIdentifier,
					       ASF_uint32_t ulRequestIdentifierLen,
					       ASF_uint32_t ulResult);

typedef ASF_void_t  (*pASFIPSecCbFnRuntime_f)(ASF_uint32_t ulVSGId,
					      ASF_uint32_t   cmd,
					      ASF_void_t    *pRequestIdentifier,
					      ASF_uint32_t  ulRequestIdentifierLen,
					      ASF_void_t    *pResult,
					      ASF_uint32_t   ulResultLen);

typedef ASF_void_t    (*pASFIPSecCbPeerGatewayChange_f)(
						       ASF_uint32_t ulVSGId,
						       ASF_uint32_t ulInSPDContainerIndex,
						       ASF_uint32_t ulSPI,
						       ASF_uint8_t  ucProtocol,
						       ASF_IPAddr_t OldDstAddr,
						       ASF_IPAddr_t NewDstAddr,
						       ASF_uint16_t usOldPort,
						       ASF_uint16_t usNewport);

typedef ASF_void_t (*pASFIPSecCbFnAuditLog_f)(ASFLogInfo_t  *pLogInfo);


typedef struct ASFIPSecCbfFn_s {
	pASFIPSecCbFnNoInSA_f	       pFnNoInSA;
	pASFIPSecCbFnNoOutFlowFound_f       pFnNoOutFlow;
	pASFIPSecCbFnVSGMappingNotFound_f   pFnVSGMap;
	pASFIPSecCbFnNoOutSA_f	      pFnNoOutSA;
	pASFIPSecCbFnInterfaceInfoNotFound_f pFnIfaceNotFound;
	pASFIPSecCbFnVerifySPD_f	    pFnVerifySPD;
	pASFIPSecCbFnRefreshL2Blob_f	pFnRefreshL2Blob;
	pASFIPSecCbFnDPDAlive_f	     pFnDPDAlive;
	pASFIPSecCbFnAuditLog_f	     pFnAuditLog;
	pASFIPSecCbFnSeqNoOverFlow_f	pFnSeqNoOverFlow;
	pASFIPSecCbFnConfig_f	       pFnConfig;
	pASFIPSecCbFnRuntime_f	      pFnRuntime;
	pASFIPSecCbPeerGatewayChange_f      pFnPeerChange;
} ASFIPSecCbFn_t;


typedef enum asfIPSeLogMsgId {
	ASF_IPSEC_LOG_MSG_ID1 = 0,
	ASF_IPSEC_LOG_MSG_ID2,
	ASF_IPSEC_LOG_MSG_ID3,
	ASF_IPSEC_LOG_MSG_ID4,
	ASF_IPSEC_LOG_MSG_ID5,
	ASF_IPSEC_LOG_MSG_ID6,
	ASF_IPSEC_LOG_MSG_ID7,
	ASF_IPSEC_LOG_MSG_ID8,
	ASF_IPSEC_LOG_MSG_ID9,
	ASF_IPSEC_LOG_MSG_ID10
} asfIPSeLogMsgId_e;





#define ASF_IPSEC_SELECTORRULEFLAG_CLEAR (0) /* default */
#define ASF_IPSEC_SELECTORRULEFLAG_NOT_SET (1 << 0)
#define ASF_IPSEC_SELECTORRULEFLAG_AND_SET (1 << 1)

#define ASF_IPSEC_POLICY_FLAGS_PFP_SOURCE_IP 0x01
#define ASF_IPSEC_POLICY_FLAGS_PFP_DESTINATION_IP 0x02
#define ASF_IPSEC_POLICY_FLAGS_PFP_SOURCE_PORT 0x04
#define ASF_IPSEC_POLICY_FLAGS_PFP_DESTINATION_PORT 0x08
#define ASF_IPSEC_POLICY_FLAGS_PFP_PROTOCOL 0x10
#define ASF_IPSEC_POLICY_FLAGS_PFP_DSCP_RANGE 0x20

typedef  struct ASFIPSecContainerInfo_s {
	ASF_uint32_t ulContainerId;
	ASF_uint32_t ulContainerMagicNumber;
} ASFIPSecContainerInfo_t;



typedef struct ASFIPSecGetContainerParams_s {
	ASF_uint32_t ulVSGId;
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulNumSPDContainers; /* Number of SPD policies (N) requested.  */
	struct {
		ASF_uint8_t ucDirection;
		ASF_uint32_t ulSPDContainerIndex;
		ASF_uint32_t  ulMagicNumber;
	} containerInfo;
} ASFIPSecGetContainerParams_t;


typedef struct ASFIPSecContainers_s {
	ASF_uint32_t ulNumSPDContainers;
	struct {
		ASF_uint32_t ulSPDContainerIndex;
		ASF_uint32_t  ulMagicNumber;
		ASF_IPSecPolicy_t  *pSPDDetails;
	} containerData[10]; /* SYAM -- array must have value */
	ASF_boolean_t ucMoreSPDs;/* TRUE/FALSE.  TRUE indicates more SPD rules present. */
} ASFIPSecContainers_t;

typedef struct ASFIPSecGetSAParams_s {
	ASF_uint32_t ulVSGId;
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulNumSAs;
	struct {
		ASF_uint8_t bDir;
		ASF_uint32_t ulContainerId;
		ASF_uint32_t ulMagicNumber;
		struct {
			ASF_uint32_t ulSPI;
			ASF_IPAddr_t gwAddr;
			ASF_uint8_t ucProtocol;
		} SAInfo[];
	} SPDContainer;
} ASFIPSecGetSAParams_t;

typedef struct ASFIPSecSAsData_s {
	ASF_uint32_t ulNumSAs;
	struct {
		ASF_uint32_t ulSPI;
		ASF_IPAddr_t gwAddr;
		ASF_uint8_t ucProtocol;
		ASF_IPSecSA_t *pSA;
	} SA[10]; /* SYAM */
	ASF_boolean_t  ucMoreSAs; /* TRUE/FALSE.  TRUE indicates more SAs present */
} ASFIPSecSAsData_t;

typedef struct  ASFIPSecGetContainerQueryParams_s {
	ASF_uint32_t ulVSGId;
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulSPDContainerIndex;
	ASF_uint8_t  bDir;
} ASFIPSecGetContainerQueryParams_t;

typedef struct ASFIPSecGetSAQueryParams_s {
	ASF_uint32_t ulVSGId;
	ASF_uint32_t ulTunnelId;
	ASF_uint32_t ulSPDContainerIndex;
	ASF_uint32_t ulSPI;
	ASF_IPAddr_t gwAddr;
	ASF_uint8_t  ucProtocol;
	ASF_uint8_t  bDir;
} ASFIPSecGetSAQueryParams_t;

typedef struct ASFSAStats_s {
	ASF_uint32_t ulPkts;
	ASF_uint32_t ulBytes;
} ASFSAStats_t;

/* Max capacity default values */
#define SECFP_MAX_SAS	      600
#define SECFP_INSA_HASH_TABLE_SZE  64

enum ASFIPSecErrorCodes {
	ASF_IPSEC_INVALID_VSG_ID = 1,
	ASF_IPSEC_INVALID_TUNNEL_ID,
	ASF_IPSEC_INVALID_CONTAINER_ID,
	ASF_IPSEC_INVALID_MAGIC_NUMBER,
	ASF_IPSEC_TUNNEL_NOT_FOUND,
	ASF_IPSEC_INSPDCONTAINER_NOT_FOUND,
	ASF_IPSEC_OUTSPDCONTAINER_NOT_FOUND,
	ASF_IPSEC_RESOURCE_NOT_AVAILABLE,
	ASF_IPSEC_OUTSA_NOT_FOUND,
	ASF_IPSEC_INSA_NOT_FOUND,
};

/* Prototypes for APIs */

ASF_void_t ASFGetExactSPDContainers(ASFIPSecGetContainerParams_t   *params,
				    ASFIPSecContainers_t  *pSPDContainers);

ASF_void_t ASFIPSecGetFirstNSAs(ASFIPSecGetSAParams_t  *pSAParams,
				ASFIPSecSAsData_t *pSAs);

ASF_void_t ASFIPSecGetNextNSAs(ASFIPSecGetSAParams_t  *pSAParams,
			       ASFIPSecSAsData_t *pSAs);

ASF_void_t ASFIPSecGetExactSAs(ASFIPSecGetSAParams_t  *pSAParams,
			       ASFIPSecSAsData_t *pSAs);

ASF_void_t  ASFIPSecEncryptAndSendPkt  (ASF_uint32_t ulVSGId,
					ASF_uint32_t ulTunnelId,
					ASF_uint32_t ulSPDContainerIndex,
					ASF_uint32_t ulSPDMagicNumber,
					ASF_uint32_t ulSPI,
					ASF_IPAddr_t daddr,
					ASF_uint8_t ucProtocol,
					ASFBuffer_t Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t    *freeArg);

ASF_void_t    ASFIPSecDecryptAndSendPkt(ASF_uint32_t ulVSGId,
					ASFBuffer_t Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t    *freeArg,
					ASF_uint32_t ulCommonInterfaceId);
ASF_uint32_t ASFIPSecFlushContainers(ASF_uint32_t  ulVSGId,
					ASF_uint32_t ulTunnelId);

ASF_uint32_t ASFIPSecFlushAllSA(ASF_uint32_t ulVSGId, ASF_uint32_t ulTunnelId);

ASF_uint32_t ASFIPSecFlushSAsWithinContainer(ASF_uint32_t ulVSGId,
				ASF_uint32_t ulTunnelId,
				ASF_uint32_t ulSPDOutContainerId,
				ASF_uint32_t ulSPDOutContainerMagicNumber,
				ASF_uint32_t ulSPDInContainerId,
				ASF_uint32_t ulSPDInContainerMagicNumber);

ASF_void_t  ASFIPSecGetFirstNSPDContainers(
				ASFIPSecGetContainerParams_t *pParams,
				ASFIPSecContainers_t  *pSPDContainers);
ASF_void_t ASFIPSecConfig(ASF_uint32_t   ulVSGId,
			  int     cmd,
			  ASF_void_t    *args,
			  ASF_uint32_t   ulArgsLen,
			  ASF_void_t    *pReqIdentifier,
			  ASF_uint32_t   ulReqIdentifierlen);
ASF_void_t ASFIPSecRuntime(ASF_uint32_t   ulVSGId,
			   int	      cmd,
			   ASF_void_t      *args,
			   ASF_uint32_t     ulArgslen,
			   ASF_void_t    *pReqIdentifier,
			   ASF_uint32_t   ulReqIdentifierlen);
ASF_void_t  ASFIPSecGetCapabilities(ASFIPSecCap_t *pCap);
ASF_uint32_t ASFIPSecRegisterCallbacks(ASFIPSecCbFn_t *pFnPtr);
ASF_void_t ASFIPSecSetNotifyPreference(ASF_boolean_t  bEnable);

ASF_void_t  ASFIPSecv4MapFlowToContainer(ASF_uint32_t ulVSGId,
					 ASF_IPAddr_t   srcAddr,
					 ASF_IPAddr_t   destAddr,
					 ASF_uint8_t ucProtocol,
					 ASF_uint16_t  srcPort,
					 ASF_uint16_t destPort,
					 ASF_uint32_t ulTunnelId,
					 ASF_uint8_t ucActionFlag,
					 ASFIPSecContainerInfo_t outContainer,
					 ASFIPSecContainerInfo_t inContainer
/*   bIpsecInProcess:1,
   bIPsecOutProcess:1, SYAM*/
					);
ASF_void_t ASFIPSecSPDContainerQueryStats(ASFIPSecGetContainerQueryParams_t *pInParams, ASFSPDPolPPStats_t *pOutParams);
ASF_void_t ASFIPSecGlobalQueryStats(ASFIPSec4GlobalPPStats_t *pOutparams);
ASF_void_t  ASFIPSecSAQueryStats(ASFIPSecGetSAQueryParams_t *pInParams, ASFSAStats_t *pOutParams);
ASF_void_t  ASFIPSecInitConfigIdentity(ASFIPSecInitConfigIdentity_t  *pConfigIdentity);
ASF_void_t  ASFIPSecUpdateTunnelMagicNumber(ASFIPSecUpdateTunnelMagicNumber_t *pTunnelMagicInfo);
ASF_void_t  ASFIPSecUpdateVSGMagicNumber(ASFIPSecUpdateVSGMagicNumber_t *pVSGMagicInfo);


typedef struct ASFIPSecGlobalErrorCounters_st {
	unsigned int ulInvalidVSGId; /* Invalid VSG Id passed to API */
	unsigned int ulInvalidTunnelId;	/* Invalid Tunnel Id passed to API */
	unsigned int ulInvalidMagicNumber; /* Invalid Magic Number */
	unsigned int ulInvalidInSPDContainerId;	/* Invalid InSPD Container Id passed to API */
	unsigned int ulInvalidOutSPDContainerId; /* Invalid OutSPD Container Id passed to API */
	unsigned int ulInSPDContainerAlreadyPresent; /* InSPD Container already present */
	unsigned int ulOutSPDContainerAlreadyPresent; /* InSPD Container already present */
	unsigned int ulResourceNotAvailable; /* Resources not available */
	unsigned int ulTunnelIdNotInUse; /* Tunnel Record Not in Use */

	unsigned int ulTunnelIfaceFull;	/* Unable to find not in use Tunnel Interface to add Tunnel Interface */
	unsigned int ulOutSPDContainersFull; /* Maximum OutSPD Containers reached, unable to add new one */
	unsigned int ulInSPDContainersFull; /* Maximum InSPD Containers reached, unable to add new one */
	unsigned int ulSPDOutContainerNotFound;	/* Unable to find Out SPD Container */
	unsigned int ulSPDInContainerNotFound; /* Unable to find Out SPD Container */
	unsigned int ulOutDuplicateSA; /* Duplicate outSA - Matching with destaddr, protocol and spi */
	unsigned int ulInDuplicateSA; /* Duplicate outSA - Matching with destaddr, protocol and spi */
	unsigned int ulInvalidAuthEncAlgo; /* Invalid/Unsupported Authentication/Encryption alogorithm passed */
	unsigned int ulOutSAFull; /* Maximum OutSA reached, unable to add new one */
	unsigned int ulOutSANotFound; /* Unable to find outSa - Matching with destaddr, protocol and spi */
	unsigned int ulInSAFull; /* Maximum InSA reached, unable to add new one */
	unsigned int ulInSANotFound; /* Unable to find outSa - Matching with destaddr, protocol and spi */
	unsigned int ulInSASPDContainerMisMatch; /* SPD container value in InSA is not matching */
	unsigned int ulOutSASPDContainerMisMatch; /* SPD container value in InSA is not matching */
} ASFIPSecGlobalErrorCounters_t;

#define ASF_IPSEC_AALG_NONE		    0
#define ASF_IPSEC_AALG_MD5HMAC		 2
#define ASF_IPSEC_AALG_SHA1HMAC		3
#define ASF_IPSEC_AALG_AESXCBC		 4
#define ASF_IPSEC_AALG_SHA256HMAC	5

#define ASF_IPSEC_AALG_NONE_KEYBITS_LENGTH     0
#define ASF_IPSEC_AALG_MD5HMAC_KEYBITS_LENGTH  128
#define ASF_IPSEC_AALG_SHA1HMAC_KEYBITS_LENGTH 160
#define ASF_IPSEC_AALG_AESXCBC_KEYBITS_LENGTH  128


#define ASF_IPSEC_EALG_NONE		    0
#define ASF_IPSEC_EALG_DESCBC		  2
#define ASF_IPSEC_EALG_3DESCBC		 3
#define ASF_IPSEC_EALG_NULL		    11
#define ASF_IPSEC_EALG_AES		     12
#define ASF_IPSEC_EALG_AES_CTR		 13

#define ASF_IPSEC_EALG_DESCBC_KEYBITS_LENGTH   64
#define ASF_IPSEC_EALG_3DESCBC_KEYBITS_LENGTH  192
#define ASF_IPSCE_EALG_NULL_KEYBITS_LENGTH     0
#define ASF_IPSEC_EALG_AES128_KEYBITS_LENGTH   128
#define ASF_IPSEC_EALG_AES192_KEYBITS_LENGTH   192
#define ASF_IPSEC_EALG_AES256_KEYBITS_LENGTH   256

#define ASF_IPSEC_ATOMIC_READ(Var)     atomic_read((atomic_t *) &Var)
#define ASF_IPSEC_ATOMIC_SET(Var, Val)  atomic_set((atomic_t *) &Var, Val)
#define ASF_IPSEC_ATOMIC_ADD(Var, Val)  atomic_add(Val, (atomic_t *) &Var)
#define ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(AtomicDst, AtomicSrc) {\
  ASF_uint32_t xTemp;\
  xTemp = ASF_IPSEC_ATOMIC_READ(AtomicSrc);\
  ASF_IPSEC_ATOMIC_SET(AtomicDst, xTemp);\
}
#define ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(AtomicDst, AtomicSrc)\
{\
  ASF_uint32_t xTemp;\
  xTemp = ASF_IPSEC_ATOMIC_READ(AtomicSrc);\
  ASF_IPSEC_ATOMIC_ADD(AtomicDst, xTemp);\
}
#define ASF_IPSEC_PPS_ATOMIC_INC(Var)    atomic_inc((atomic_t *) &Var)
#define ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, Var)\
{\
 if (pSA) {\
  atomic_inc((atomic_t *) &(pSA->PPStats.IPSecPolPPStats[Var]));\
} \
}

#define ASFIPSEC_ERR	asf_err

#ifdef ASF_IPSEC_DEBUG
#define ASFIPSEC_PRINT	asf_print
#define ASFIPSEC_WARN	asf_warn
#define ASFIPSEC_DEBUG	asf_debug
#define ASFIPSEC_DBGL2	asf_debug_l2

#define ASFIPSEC_TRACE	asf_trace
#define ASFIPSEC_FENTRY	asf_fentry
#define ASFIPSEC_FEXIT	asf_fexit
#else

#define ASFIPSEC_PRINT(fmt, arg...)
#define ASFIPSEC_WARN(fmt, arg...)
#define ASFIPSEC_DEBUG(fmt, arg...)
#define ASFIPSEC_DBGL2(fmt, arg...)
#define ASFIPSEC_DEBUG(fmt, arg...)

#define ASFIPSEC_TRACE
#define ASFIPSEC_FENTRY
#define ASFIPSEC_FEXIT
#endif

#endif
