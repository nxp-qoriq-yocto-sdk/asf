/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecfp.h
 * Description: Contains the macros, type defintions, exported and imported
 * functions for IPsec fast path
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 *
 */
/* History
 * Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#ifndef _IPSECFP_H
#define _IPSECFP_H

#include <linux/ip.h>
#include <linux/ipv6.h>

#ifdef CONFIG_ASF_SEC3x
#include "linux/hw_random.h"
#include <talitos.h>
#endif

#ifdef CONFIG_ASF_SEC4x
#include "ipseccaam.h"
#endif

#ifdef ASF_IPV6_FP_SUPPORT
/* Header length validation information */
#define SECFP_IPV6_HDR_LEN	40
#define SECFP_IPV6_TCLASS_MASK    0x0FF00000
#define SECFP_IPV6_TCLASS_SHIFT 20
#define ipv6_traffic_class(ipv6TClass, ipv6h) \
{ \
	ipv6TClass = (((*(ASF_uint32_t *)ipv6h) & SECFP_IPV6_TCLASS_MASK) \
				>> SECFP_IPV6_TCLASS_SHIFT); \
}
#endif
#define ASF_IPSEC_SEC_SA_SHDESC_SIZE (64 * sizeof(u32))
/* DF related bits */
#define SECFP_DF_COPY	0
#define SECFP_DF_CLEAR	1
#define SECFP_DF_SET	2

/* Protocol related values */
#define SECFP_PROTO_ESP		IPPROTO_ESP /*50*/
#define SECFP_PROTO_AH		IPPROTO_AH /*50*/
#define SECFP_PROTO_IP		IPPROTO_IPIP /*4*/
#define SECFP_PROTO_IPV6	IPPROTO_IPV6/*41*/
#define SECFP_IPPROTO_ICMP	IPPROTO_ICMP /*1*/

/* Header length validation information */
#define SECFP_ESP_HDR_LEN	8
#define SECFP_IPV4_HDR_LEN	20
#define SECFP_AH_MAX_HDR_LEN	16
#define SECFP_ESP_TRAILER_LEN	2

/* Options to set up descriptors */
#define SECFP_AUTH		1
#define SECFP_CIPHER		2
#define SECFP_BOTH		3
#define SECFP_AESCTR_BOTH	4
#define SECFP_NONE		5


/* Different algorithm macros */
#define SECFP_HMAC_MD5		1 /* For HmachHash calculation	*/
#define SECFP_HMAC_SHA1		2
#define SECFP_HMAC_AES_XCBC_MAC	3
#define SECFP_HMAC_NULL		4 /* No Authentication */
#define SECFP_HMAC_SHA256	5
#define SECFP_HMAC_SHA384	6
#define SECFP_HMAC_SHA512	7
#define SECFP_HMAC_SHA1_160	8

#define SECFP_DES		2 /* generic DES transform using DES-SBC */
#define SECFP_3DES		3 /* generic triple-DES transform	*/
#define SECFP_ESP_NULL		11
#define SECFP_AES		12
#define SECFP_AESCTR		13
#define SECFP_AES_CCM_ICV8	14
#define SECFP_AES_CCM_ICV12	15
#define SECFP_AES_CCM_ICV16	16
#define SECFP_AES_GCM_ICV8	18
#define SECFP_AES_GCM_ICV12	19
#define SECFP_AES_GCM_ICV16	20
#define SECFP_NULL_AES_GMAC	23

#define DES_CBC_BLOCK_SIZE	8
#define TDES_CBC_BLOCK_SIZE	8
#define AES_CBC_BLOCK_SIZE	16
#define AES_CTR_BLOCK_SIZE	8
#define AES_CCM_BLOCK_SIZE	16
#define AES_GCM_BLOCK_SIZE	16
#define AES_GMAC_BLOCK_SIZE	16

#define DES_IV_LEN		8
#define TDES_IV_LEN		8
#define AES_CBC_IV_LEN	16
#define AES_CTR_IV_LEN	8
#define AES_CCM_IV_LEN	8
#define AES_GCM_IV_LEN	8
#define AES_GMAC_IV_LEN	8

#define AES_CTR_SALT_LEN	4
#define AES_CCM_SALT_LEN	3
#define AES_GCM_SALT_LEN	4
#define AES_GMAC_SALT_LEN	4

#define AES_CTR_INIT_COUNTER	0x00000001
#define AES_CCM_INIT_COUNTER	0x0

#define AES_CCM_ICV8_IV_FLAG	0x5B
#define AES_CCM_ICV12_IV_FLAG	0x6B
#define AES_CCM_ICV16_IV_FLAG	0x7B

#define AES_CCM_CTR_FLAG	0x03


/* Sequence number related */
#define SECFP_APPEND_BUF_LEN_FIELD	4
#define SECFP_HO_SEQNUM_LEN		4
#define SECFP_NOUNCE_IV_LEN		16

/* Used for AES_CTR */
#define SECFP_COUNTER_BLK_LEN		16

/* Number of DHCP based SAs */
#define SECFP_MAX_TOS_INDICES		8

/* Information for preparing outer IP header */
#define SECFP_IP_TTL			120


/* skb Cb indices where various information is kept for post SEC operation */
/* Common for outbound and inbound */
#define SECFP_SKB_SG_DMA_INDEX 		0
#define SECFP_SKB_DATA_DMA_INDEX 	4
#define SECFP_ACTION_INDEX		8
#define SECFP_ICV_LENGTH		11
#define SECFP_REF_INDEX 		45
#define SECFP_UDP_SOURCE_PORT		46

/* Inbound */
#define SECFP_LOOKUP_SA_INDEX		9
#define SECFP_3X_SA_OPTION_INDEX	10
#define SECFP_4X_NAT_HDR_SIZE		10
#define SECFP_SPI_INDEX			12
#define SECFP_IPHDR_INDEX		16
#define SECFP_HASH_VALUE_INDEX		20
#define SECFP_SEQNUM_INDEX		24
#define SECFP_SABITMAP_DIFF_INDEX	28
#define SECFP_SABITMAP_INFO_INDEX	32
#define SECFP_TOS_INDEX 		33
#define SECFP_UPDATE_TOS_INDEX		34
#define SECFP_SABITMAP_COEF_INDEX	35
#define SECFP_SABITMAP_REMAIN_INDEX	36
#define SECFP_VSG_ID_INDEX		40


/* For Outbound skb indices */
#define SECFP_OUTB_FRAG_REQD		9
#define SECFP_SPD_CI_INDEX		12
#define SECFP_SPD_CI_MAGIC_INDEX	16
#define SECFP_SAD_SAI_INDEX		20
#define SECFP_SAD_SAI_MAGIC_INDEX	24
#define SECFP_IV_DATA_INDEX		28
#define SECFP_OUTB_PATH_MTU		32
#define SECFP_OUTB_L2_OVERHEAD		36
#define SECFP_OUTB_L2_WITH_PPPOE	40

#define SECFP_NUM_IV_DATA_GET_AT_ONE_TRY	1

#define SECFP_DROP 1

#define SECFP_MAX_SECPROC_ITERATIONS 2

#define SECFP_IN_GATHER_NO_SCATTER	1
#define SECFP_IN_GATHER_SCATTER		0

/* Bit position 1 */
/*
(1|0) = 1 SECFP_OUT | SECFP_NO_SCATTER_GATHER
(1|2) = 3 SECFP_OUT | SECFP_SCATTER_GATHER
(0|0)= 0 SECFP_IN | SECFP_NO_SCATTER_GATHER
(0|2) = 2 SECFP_IN | SECFP_SCATTER_GATHER
*/
#define SECFP_OUT 0x1
#define SECFP_IN 0x0

/* Bit position 2 */
#define SECFP_NO_SCATTER_GATHER 0
#define SECFP_SCATTER_GATHER	2

#define ASF_IPSEC_MAX_NON_IKE_MARKER_LEN 8
#define ASF_IPSEC_MAX_NON_ESP_MARKER_LEN 4

#define SECFP_MAX_UDP_HDR_LEN 8

#define SECFP_ESN_MARKER_POSITION	\
	(12 + SECFP_NOUNCE_IV_LEN + SECFP_APPEND_BUF_LEN_FIELD)

#define SECFP_ERROR_STR_MAX		302

/* Assumes skb->data points to beginning of IP header */
/* assumes ESP or AH only */

#define SECFP_EXTRACT_PKTINFO(skb, iph, iphlen, spi, seqnum)	\
{\
	if (iph->protocol == SECFP_PROTO_ESP) {\
		spi = *(unsigned long int *)	&(skb->data[iphlen]); \
		seqnum = *(unsigned long int *)	&(skb->data[iphlen+4]); \
	} \
	else {\
		spi = *(unsigned long int *)	&(skb->data[iphlen+4]); \
		seqnum = *(unsigned long int *)	&(skb->data[iphlen+8]); \
	} \
}
#ifdef ASF_IPV6_FP_SUPPORT
#define SECFP_EXTRACT_IPV6_PKTINFO(skb, ipv6h, iphlen, spi, seqnum)    \
{\
	if (ipv6h->nexthdr == SECFP_PROTO_ESP) {\
		spi = *(unsigned long int *)    &(skb->data[iphlen]); \
		seqnum = *(unsigned long int *) &(skb->data[iphlen+4]); \
	} \
	else {\
		spi = *(unsigned long int *)    &(skb->data[iphlen+4]); \
		seqnum = *(unsigned long int *) &(skb->data[iphlen+8]); \
	} \
}
#endif

#define SECFP_NUM_IV_ENTRIES 8

#define secfp_compute_hash(spi)	\
		(spi & (SECFP_MAX_SPI_ENTRIES-1))

#define SECFP_SET_DMA_DESC_PTR(descPtr, len, data, extent)	\
{\
	descPtr->len = cpu_to_be16(len);\
	descPtr->ptr = cpu_to_be32(dma_map_single(dev, data, len, DMA_TO_DEVICE));\
	descPtr->j_extent = extent;\
}

#ifndef CONFIG_ASF_SEC4x
#define SECFP_SET_DESC_PTR(a, b, c, d)\
	(a).len = cpu_to_be16(b);\
	(a).ptr = cpu_to_be32(lower_32_bits((c)));\
	(a).eptr = cpu_to_be32(upper_32_bits((c)));\
	(a).j_extent = d;

#define SECFP_UNMAP_SINGLE_DESC(dev, data, len) \
	dma_unmap_single(dev, data, len, DMA_TO_DEVICE)
#else
#define SECFP_UNMAP_SINGLE_DESC(dev, data, len) {}
#endif


/* Definition copied into asfreasm.c */
#define SECFP_OUTSA_TABLE_SIZE (sizeof(ptrIArry_nd_t)*SECFP_MAX_OB_SAS)

#define SECFP_INSA_TABLE_SIZE (sizeof(inSA_t *)*SECFP_MAX_SPI_ENTRIES)

#define SECFP_IV_TABLE_SIZE (NR_CPUS * SECFP_NUM_IV_ENTRIES * sizeof(unsigned int))

#define SECFP_TOT_SRAM_SIZE (SECFP_OUTSA_TABLE_SIZE + SECFP_INSA_TABLE_SIZE + SECFP_IV_TABLE_SIZE + SECFP_SRAM_SIZE)
/* End of copied definitions */


#define SECFP_MAX_SELECTORS 5

#define SECFP_MAX_IB_SAS 128
#define SECFP_MAX_IN_SEL_TBL_ENTRIES SECFP_MAX_IB_SAS

/* These are not right, but we will go with this for now */

#define SECFP_PREOVERHEAD 64
#define SECFP_POSTOVERHEAD 64

#define SECFP_HO_SEQNUM_LEN 4

#define SECFP_ECN_ECT_CE (0x3)

#define SECFP_FAILURE 1
#define SECFP_SUCCESS 0


#define SECFP_MAX_32BIT_VALUE	0xffffffff /* 2^32-1 */

typedef struct ASFIPSecOpqueInfo_st {
	unsigned int ulInSPDContainerId;
	unsigned int ulInSPDMagicNumber;
	unsigned char ucProtocol;
	ASF_IPAddr_t DestAddr;
} ASFIPSecOpqueInfo_t;

#define IGW_SAD_SET_BIT_IN_WINDOW(pSA, ulNunOfBits, ucSize, ucCnt, ucCo_efficient, ucRemainder) \
{\
	ucSize	= pSA->SAParams.AntiReplayWin >> 5;	\
	if (ulNunOfBits >= pSA->SAParams.AntiReplayWin) { \
		for (ucCnt = 0; ucCnt < ucSize ; ucCnt++) \
			pSA->pWinBitMap[ucCnt] = 0; \
	pSA->pWinBitMap[ucSize-1]	|= 1; \
	} else { \
		ucCo_efficient	= ulNunOfBits >> 5; \
		if (ucCo_efficient) {\
			for (ucCnt = 0; (ucCnt + ucCo_efficient) < ucSize;\
					ucCnt++) \
				pSA->pWinBitMap[ucCnt] =\
				pSA->pWinBitMap[ucCnt + ucCo_efficient]; \
			for (ucCnt = 0; ucCnt < ucCo_efficient ; ucCnt++) \
				pSA->pWinBitMap[(ucSize-1) - ucCnt] = 0; \
	} \
	ucRemainder	= ulNunOfBits & 31; \
	if (ucRemainder) {\
	for (ucCnt = 0; ucCnt < (ucSize - ucCo_efficient); ucCnt++) {\
		pSA->pWinBitMap[ucCnt] <<= ucRemainder; \
		if ((ucCnt+1) < (ucSize - ucCo_efficient)) \
		pSA->pWinBitMap[ucCnt] |= (pSA->pWinBitMap[ucCnt+1] >> (32-ucRemainder)); \
	} \
	} \
	pSA->pWinBitMap[ucSize-1] |= 1; \
	} \
}


/* descriptor pointer entry */
struct secfp_descPtr {
	__be16 len;	/* length */
	u8 j_extent;	/* jump to sg link table and/or extent */
	u8 eptr;	/* extended address */
	__be32 ptr;	/* address */
} ;

typedef struct SPDInParams_s {
	unsigned int bUdpEncap:1,
	bESN:1,
	bCopyEcn:1,
	bCopyDscp:1,
	bDPDAlive:1;
	unsigned char ucProto;
	unsigned char ucDscp;
} SPDInParams_t;

typedef struct SPDOutParams_s {
	unsigned int bUdpEncap:1,
	bOnlySaPerDSCP:1,
	bRedSideFrag:1,
	bESN:1,
	bCopyDscp:1,
	handleDf:2;
	unsigned char ucProto;
	unsigned char ucDscp;
} SPDOutParams_t;

#define SECFP_MAX_AUTH_KEY_SIZE 64
#define SECFP_MAX_CIPHER_KEY_SIZE 64

typedef struct SAParams_s {
	unsigned int ulSPI;
	struct {
		bool bIPv4OrIPv6; /* 0= IPv4, 1= IPv6 */
		union {
			struct {
				unsigned int saddr;
				unsigned int daddr;
			} iphv4;
			struct {
				unsigned int saddr[4];
				unsigned int daddr[4];
			} iphv6;
		} addr;
	} tunnelInfo;
	unsigned short	bAuth:1,
	bEncrypt:1,
	bRedSideFragment:1,
	bVerifyInPktWithSASelectors:1,
	bDoPeerGWIPAddressChangeAdaptation:1,
	bDoUDPEncapsulationForNATTraversal:1,
	bUseExtendedSequenceNumber:1,
	bPropogateECN:1,
	bSALifeTimeInSecs:1,
	bDoAntiReplayCheck:1,
	bEncapsulationMode:1,
	bCopyDscp:1,
	handleDf:2;
	unsigned short ulCId;
	unsigned char ucProtocol;
	unsigned char ucDscp;
	unsigned char ucAuthAlgo;
	unsigned char ucCipherAlgo;
	unsigned char AuthKeyLen; /* in Bytes*/
	unsigned char EncKeyLen; /*in Bytes */
	unsigned char ulBlockSize;
	unsigned char ulIvSize;
	unsigned char uICVSize;
	unsigned char ucAuthKey[SECFP_MAX_AUTH_KEY_SIZE];
	unsigned char ucEncKey[SECFP_MAX_CIPHER_KEY_SIZE];
	unsigned int AntiReplayWin;
	unsigned char ucNounceIVCounter[16];
	/* Nonce:4 bytes, followed by 8 bytes IV + 4 bytes counter */
	ASF_IPSec_Nat_Info_t IPsecNatInfo;

	unsigned long softPacketLimit;
	unsigned long hardPacketLimit;
	unsigned long softKbyteLimit;
	unsigned long hardKbyteLimit;
} SAParams_t;




typedef struct inSA_s {
	struct rcu_head rcu;
	unsigned int magicNum;
	SAParams_t SAParams;
	SPDInParams_t SPDParams;
	unsigned int ulVSGId;
	unsigned int ulSPDInContainerIndex;
	unsigned int ulSPDInMagicNum;
	unsigned int ulSPDSelSetIndex;
	unsigned int ulSPDSelSetIndexMagicNum;
	unsigned int ulLastSeqNum;
	unsigned int *pWinBitMap;
#ifdef CONFIG_ASF_SEC4x
	struct caam_ctx ctx;
#else
	int chan;
	int last_chan[2];
	__be32 desc_hdr_template;
	__be32	hdr_Auth_template_0; /* when proto is AH and
					only Auth needs to be performed*/
	__be32	hdr_Auth_template_1; /* when proto is ESP and auth
					algorithm is set */
	dma_addr_t	AuthKeyDmaAddr;
	dma_addr_t	EncKeyDmaAddr;
#endif
	unsigned int validIpPktLen; /* Sum of ESP or AH header + IP header
					 IF ESP
					 + CipherIV Len +
					 if (AUTH_ALGO) ? ulAHICVLen : 0
					 If AH
					+ ICVLen + Padding len
					 */
	unsigned int ulReqTailRoom; /* Required tail room goes like this -
					4 bytes for appending buffer length +
					if Extended Sequence number +4
					for high order sequence number
					 if AH, ICV length */
	unsigned int ulRcvMTU;
	unsigned int ulTunnelId;
	unsigned long ulPkts[NR_CPUS];
	unsigned long ulBytes[NR_CPUS];
	AsfSPDPolicyPPStats_t	PolicyPPStats[NR_CPUS];
	AsfSPDPolPPStats_t	 PPStats;
	/* For Gateway Adaptation purposes */
	unsigned int ulSPDOutContainerIndex;
	unsigned int ulSPDOutContainerMagicNumber;
	unsigned int ulOutSPI;
	unsigned int ulHOSeqNum;
	unsigned int ulHashVal;
	unsigned short ucIfaceId;
	unsigned char option[SECFP_MAX_SECPROC_ITERATIONS];
	unsigned char usNatHdrSize;
	unsigned char ulSecHdrLen;
	unsigned char bVerifySASel:1,
		bVerifySPDSel:1,
		bSendPktToNormalPath:1,
		bSoftExpiry:1,
		bHeap:1;
	struct inSA_s *pNext;
	struct inSA_s *pPrev;
} inSA_t;

typedef struct {
	inSA_t *pHeadSA;
} inSAList_t;

struct selNode_s {
	ASF_IPSecRangeAddr_t ipAddrRange;
	ASF_uint8_t	  IP_Version;
	unsigned short int prtStart;
	unsigned short int prtEnd;
	unsigned char proto;
	unsigned char ucMask;
} ;

typedef struct SASel_s {
	struct SASel_s *pPrev;
	struct SASel_s *pNext;
	struct selNode_s selNodes[SECFP_MAX_SELECTORS];
	bool bHeap;
	unsigned char ucNumSelectors;
} SASel_t;

#define SECFP_SA_XPORT_SELECTOR 1
#define SECFP_SA_SRCPORT_SELECTOR 2
#define SECFP_SA_DESTPORT_SELECTOR 4
#define SECFP_SA_SRCIPADDR_SELECTOR 8
#define SECFP_SA_DESTIPADDR_SELECTOR 16
#define SECFP_SA_DSCP_SELECTOR 32

typedef struct OutSelList_s {
	unsigned short usDscpStart;
	unsigned short usDscpEnd;
	SASel_t srcSel;
	SASel_t destSel;
	unsigned int ucSelFlags;
	char	bHeap;
} OutSelList_t;

typedef struct InSelList_s {
	struct rcu_head rcu;
	SASel_t *pSrcSel;
	SASel_t *pDestSel;
	unsigned int ucSelFlags;
	char bHeap;
} InSelList_t;

typedef struct SAInfo_s {
	unsigned int ulVSGId;
	unsigned int ulSPDIndex;

	SASel_t pSrcSel;
	SASel_t pDstSel;
	unsigned char bDscpBasedSA;
	unsigned char ucTosVal;
	SAParams_t SAParams;
} SAInfo_t;

typedef struct SPDOutSALinkNode_s {
	struct rcu_head rcu ____cacheline_aligned_in_smp;
	unsigned int ulSAIndex;
	char	bHeap;
	struct SPDOutSALinkNode_s *pNext;
	struct SPDOutSALinkNode_s *pPrev;
} SPDOutSALinkNode_t;

typedef struct SPDOutContainer_s {
	struct rcu_head rcu ____cacheline_aligned_in_smp;
	SPDOutParams_t		SPDParams ;
	AsfSPDPolPPStats_t	PPStats;
	spinlock_t		spinlock;
	union {
		unsigned int ulSAIndex[SECFP_MAX_DSCP_SA];
		SPDOutSALinkNode_t *pSAList;
	} SAHolder;
	unsigned int action;
	char bHeap;
	unsigned int dummy____cacheline_aligned_in_smp;
} SPDOutContainer_t ;

typedef struct SPDInSelTblIndexLinkNode_s {
	struct rcu_head rcu ____cacheline_aligned_in_smp;
	unsigned int ulIndex;
	char	bHeap;
	struct SPDInSelTblIndexLinkNode_s *pNext;
	struct SPDInSelTblIndexLinkNode_s *pPrev;
} SPDInSelTblIndexLinkNode_t;


typedef struct SPDInSPIValLinkNode_s {
	struct rcu_head rcu ____cacheline_aligned_in_smp;
	unsigned int ulSPIVal;
	char bHeap;
	struct SPDInSPIValLinkNode_s *pPrev;
	struct SPDInSPIValLinkNode_s *pNext;
} SPDInSPIValLinkNode_t;

typedef struct SPDInContainer_s {
	struct rcu_head rcu ____cacheline_aligned_in_smp;
	spinlock_t spinlock;
	SPDInParams_t SPDParams;
	AsfSPDPolPPStats_t			PPStats;
	/* Not sure if this is link is needed, if not can be
		removed in productization */
	SPDInSelTblIndexLinkNode_t *pSelIndex;
	SPDInSPIValLinkNode_t *pSPIValList;
	char bHeap;
	unsigned int dummy ____cacheline_aligned_in_smp;
} SPDInContainer_t;

struct SPDCILinkNode_s {
	struct rcu_head rcu ____cacheline_aligned_in_smp;
	unsigned int ulIndex;
	char bHeap;
	struct SPDCILinkNode_s *pPrev;
	struct SPDCILinkNode_s *pNext;
} ;

typedef struct secTunnelIface_s {
	bool bInUse; /* 0 - Not in Use, 1 - In Use */
	struct SPDCILinkNode_s *pSPDCIOutList;
	struct SPDCILinkNode_s *pSPDCIInList;
	unsigned int		ulTunnelMagicNumber;
} SecTunnelIface_t;


typedef struct outSA_s {
	struct rcu_head rcu;
	SAParams_t SAParams;
	SPDOutParams_t SPDParams;
	/* Hardware option AES_CBC or BOTH or only encryption etc. */
#ifdef CONFIG_ASF_SEC4x
	struct caam_ctx ctx;
#else
	int chan;
	int last_chan[2];
	__be32 desc_hdr_template;
	__be32	hdr_Auth_template_0; /* when proto is AH and
					only Auth needs to be performed*/
	__be32	hdr_Auth_template_1; /* when proto is ESP and auth
					algorithm is set */
	dma_addr_t	AuthKeyDmaAddr;
	dma_addr_t	EncKeyDmaAddr;
#endif
	struct {
		bool bIpVersion; /* 0-IPv4 or 1-IPv6 */
		union {
			struct iphdr iphv4;
			struct ipv6hdr iphv6;
		} hdrdata;
	} ipHdrInfo;
	void (*prepareOutPktFnPtr)(struct sk_buff *, struct outSA_s *,
				SPDOutContainer_t *, unsigned int **) ;
	void (*finishOutPktFnPtr)(struct sk_buff *,
				struct outSA_s *, SPDOutContainer_t *,
				unsigned int *, unsigned int, unsigned int);
#ifndef ASF_SECFP_PROTO_OFFLOAD
	atomic_t ulLoSeqNum;
	atomic_t ulHiSeqNum;
#else
	unsigned int ulLoSeqNum;
	unsigned int ulHiSeqNum;
#endif
	unsigned char l2blob[ASF_MAX_L2BLOB_LEN];
	unsigned char bIVDataPresent:1,
		bl2blob:1,
		bSoftExpiry:1,
		bVLAN:1,
		bPPPoE:1,
		bHeap:1;
	unsigned char usNatHdrSize;
	unsigned char ulL2BlobLen;
	unsigned char ulIvSizeInWords;
	unsigned char ulSecHdrLen;
	unsigned char ulSecOverHead;
	unsigned char ulSecLenIncrease;
	unsigned char option[SECFP_MAX_SECPROC_ITERATIONS];
	unsigned short ulTunnelId;
	unsigned short tx_vlan_id; /*valid if bVLAN is 1*/
	unsigned int ulCompleteOverHead;
	unsigned int ulInnerPathMTU;
	unsigned long ulPkts[NR_CPUS];
	unsigned long ulBytes[NR_CPUS];
	AsfSPDPolicyPPStats_t	PolicyPPStats[NR_CPUS];
	AsfSPDPolPPStats_t	PPStats;
	struct net_device *odev;
	OutSelList_t *pSelList;

	asfTmr_t	*pL2blobTmr;
	ASFFFPL2blobConfig_t	l2blobConfig;
} outSA_t;


struct saInfo_s {
	unsigned int ulSAIndex;
	unsigned int ulMagicNum;
};

typedef struct secfp_sgEntry_s {
	__be16 len;
	u8 flags;
	u8 eptr;
	__be32 ptr;
} secfp_sgEntry_t;

#define DESC_PTR_LNKTBL_JUMP			0x80
#define DESC_PTR_LNKTBL_RETURN			0x02
#define DESC_PTR_LNKTBL_NEXT			0x01


/* Definitions for indices where information is available from firewall */
#define SECFP_OUT_CI_INDEX 0
#define SECFP_OUT_CI_MAGIC_NUM	1
#define SECFP_OUT_SA_INDEX	2
#define SECFP_OUT_SA_MAGIC_NUM	3
#define SECFP_IN_CI_INDEX	4
#define SECFP_IN_CI_MAGIC_NUM	5
#define SECFP_IN_SPI_INDEX	6
#define SECFP_UNUSED_INDEX	7
#define MAX_IPSEC_RECYCLE_DESC		128

#ifndef CONFIG_ASF_SEC4x
extern void secfp_outComplete(struct device *dev,
				struct talitos_desc *desc,
				void *context, int error);
extern void secfp_inComplete(struct device *dev,
				struct talitos_desc *desc,
				void *context, int err);
extern void secfp_inCompleteWithFrags(struct device *dev,
				struct talitos_desc *desc,
				void *context, int err);
extern unsigned int secfp_inHandleICVCheck3x(void *dsc,
	struct sk_buff *skb);

extern void secfp_dma_unmap_sglist(struct sk_buff *skb);
extern int secfp_createInSATalitosDesc(inSA_t *pSA);
extern int secfp_createOutSATalitosDesc(outSA_t *pSA);

extern int talitos_submit(struct device *dev, int ch,
			struct talitos_desc *desc,
		void (*callback)(struct device *dev, struct talitos_desc *desc,
		void *context, int err), void *context);
#else

/* This is due to different prototype of the SEC return function*/
extern void secfp_outComplete(struct device *dev,
		u32 *pdesc, u32 error, void *context);
extern void secfp_inComplete(struct device *dev,
		u32 *pdesc, u32 err, void *context);
extern void secfp_inCompleteWithFrags(struct device *dev,
		u32 *pdesc, u32 err, void *context);

int secfp_buildProtocolDesc(struct caam_ctx *ctx, void *pSA, int dir);

extern int secfp_createInSACaamCtx(inSA_t *pSA);
extern int secfp_createOutSACaamCtx(outSA_t *pSA);

extern int secfp_prepareDecapShareDesc(struct caam_ctx *ctx, u32 *sh_desc,
		inSA_t *pSA, bool keys_fit_inline);

extern int secfp_prepareEncapShareDesc(struct caam_ctx *ctx, u32 *sh_desc,
		outSA_t *pSA, bool keys_fit_inline);
#endif

extern int gfar_start_xmit(struct sk_buff *skb,
				struct net_device *dev);
extern __be16 eth_type_trans(struct sk_buff *skb,
				struct net_device *dev);
extern int secfp_try_fastPathIn(struct sk_buff *skb1,
				ASF_boolean_t bCheckLen, unsigned int ulVSGId,
				ASF_uint32_t	ulCommonInterfaceId);

/* Initialization Data Structures Interfaces */
int secfp_data_init(void);
void secfp_data_deinit(void);
int secfp_init(void);
void secfp_deInit(void);
int secfp_register_proc(void);
int secfp_unregister_proc(void);

inSA_t *secfp_findInSA(unsigned int ulVSGId,
			unsigned char ucProto,
			unsigned long int ulSPI,
			ASF_IPAddr_t daddr,
			unsigned int *pHashVal);

unsigned int secfp_SPDOutContainerCreate(
				unsigned int	ulVSGId,
				unsigned int	ulTunnelId,
				unsigned int	ulContainerIndex,
				unsigned int	ulMagicNum,
				SPDOutParams_t *pSPDParams);

unsigned int secfp_SPDInContainerCreate(
				unsigned int	ulVSGId,
				unsigned int	ulTunnelId,
				unsigned int	ulContainerIndex,
				unsigned int	ulMagicNum,
				SPDInParams_t	*pSPDParams);

unsigned int secfp_SPDOutContainerDelete(
				unsigned int ulVSGId,
				unsigned int ulTunnelId,
				unsigned int ulContainerIndex,
				unsigned int ulMagicNumber);

unsigned int secfp_SPDInContainerDelete(
				unsigned int ulVSGId,
				unsigned int ulTunnelId,
				unsigned int ulContainerIndex,
				unsigned int ulMagicNumber);

unsigned int secfp_DeleteOutSA(unsigned int	 ulSPDContainerIndex,
				unsigned int	 ulSPDMagicNumber,
				ASF_IPAddr_t	 daddr,
				unsigned char	ucProtocol,
				unsigned int	 ulSPI,
				unsigned short	usDscpStart,
				unsigned short	usDscpEnd);

unsigned int secfp_DeleteInSA(unsigned int	ulVSGId,
				unsigned int	ulContainerIndex,
				unsigned int	ulMagicNumber,
				ASF_IPAddr_t	daddr,
				unsigned char	ucProtocol,
				unsigned int	ulSPI);

unsigned int secfp_ModifyOutSA(unsigned int long ulVSGId,
				ASFIPSecRuntimeModOutSAArgs_t *pModSA);

unsigned int secfp_ModifyInSA(unsigned int long ulVSGId,
				ASFIPSecRuntimeModInSAArgs_t *pModSA);

unsigned int secfp_SetDPD(unsigned int long ulVSGId,
				ASFIPSecRuntimeSetDPDArgs_t *pSetDPD);

unsigned int secfp_createOutSA(
				unsigned int	ulVSGId,
				unsigned int	ulTunnelId,
				unsigned int	ulSPDContainerIndex,
				unsigned int	ulMagicNumber,
				SASel_t	 *pSrcSel,
				SASel_t	 *pDstSel,
				unsigned char	ucSelMask,
				SAParams_t	*SAParams,
				unsigned	short usDscpStart,
				unsigned	short usDscpEnd,
				unsigned int	ulMtu);

unsigned int secfp_CreateInSA(
				unsigned int ulVSGId,
				unsigned int ulTunnelId,
				unsigned int ulContainerIndex,
				unsigned int ulMagicNumber,
				SASel_t	*pSrcSel,
				SASel_t	*pDstSel,
				unsigned int ucSelFlags,
				SAParams_t *pSAParams,
				unsigned int ulSPDOutContainerIndex,
				unsigned int ulOutSPI,
				unsigned int ulMtu);

/* Finds the SPI node in the container; Used for SPI verification as well
	as for SA deletion */
static inline SPDInSPIValLinkNode_t *secfp_findInSPINode(
		SPDInContainer_t *pContainer,
		unsigned int ulSPIVal)
{
	SPDInSPIValLinkNode_t *pNode;

	for (pNode = pContainer->pSPIValList;
		pNode != NULL; pNode = pNode->pNext) {
			if (pNode->ulSPIVal == ulSPIVal)
				break;
	}
	return pNode;
}

extern SPDOutSALinkNode_t *secfp_findOutSALinkNode(
		SPDOutContainer_t *pContainer,
		ASF_IPAddr_t	daddr,
		unsigned char	ucProtocol,
		unsigned int	ulSPI);

extern outSA_t *secfp_findOutSA(
		unsigned int ulVsgId,
		ASFFFPIpsecInfo_t *pSecInfo,
		struct sk_buff *skb,
		unsigned char tos,
		SPDOutContainer_t **ppContainer,
		ASF_boolean_t *pbRevalidate);

extern inSA_t *secfp_findInv6SA(unsigned int ulVSGId,
		unsigned char ucProto,
		unsigned long int ulSPI,
		unsigned int *daddr,
		unsigned int *pHashVal);

extern inSA_t *secfp_findInv4SA(unsigned int ulVSGId,
		unsigned char ucProto,
		unsigned long int ulSPI,
		unsigned int daddr,
		unsigned int *pHashVal);

extern SPDOutSALinkNode_t *secfp_cmpPktSelWithSelSet(
		SPDOutContainer_t *pContainer,
		struct sk_buff *skb);

extern bool secfp_verifySASels(inSA_t *pSA,
		unsigned char protocol,
		unsigned short int sport,
		unsigned short int dport,
		ASF_IPAddr_t saddr,
		ASF_IPAddr_t daddr);

#ifdef ASF_SECFP_PROTO_OFFLOAD
extern void secfp_finishOffloadOutPacket(
		struct sk_buff *skb, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int *pIpHdr,
		unsigned int ulVSGId,
		unsigned int ulSPDContainerIndex);
#else
extern void secfp_finishOutPacket(
		struct sk_buff *skb, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int *pOuterIpHdr,
		unsigned int ulVSGId,
		unsigned int ulSPDContainerIndex);
extern void secfp_prepareOutPacket(
		struct sk_buff *skb1, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int **pOuterIpHdr);
#endif /*ASF_SECFP_PROTO_OFFLOAD*/

#ifdef ASF_QMAN_IPSEC
#define DEBUG_ASF_QMAN_IPSEC

extern int secfp_qman_init(void);
extern void secfp_qman_deinit(void);
extern int secfp_qman_in_submit(inSA_t *pSA, void *context);
extern int secfp_qman_out_submit(outSA_t *pSA, void *context);

extern void secfp_qman_release_fq(struct caam_ctx *ctx, int dir);

#else
extern	void secfp_prepareOutDescriptor(
		struct sk_buff *skb,
		void *pSA, void *, unsigned int);

extern	void secfp_prepareInDescriptor(
		struct sk_buff *skb,
		void *pSA, void *, unsigned int);

#ifndef CONFIG_ASF_SEC4x
extern void secfp_prepareInDescriptorWithFrags(
		struct sk_buff *skb,
		void *pData, void *, unsigned int);

extern void secfp_prepareOutDescriptorWithFrags(
		struct sk_buff *skb,
		void *pData, void *, unsigned int);
#else
#define secfp_prepareOutDescriptorWithFrags secfp_prepareOutDescriptor
#endif
#endif
#endif
