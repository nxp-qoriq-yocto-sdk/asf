/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
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
 *  Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#ifndef _IPSECFP_H
#define _IPSECFP_H

#include <linux/ip.h>
#include <linux/ipv6.h>
#include <talitos.h>

#define FALSE 0
#define TRUE 1

/* DF related bits */
#define SECFP_DF_COPY   0
#define SECFP_DF_CLEAR  1
#define SECFP_DF_SET    2

/* Protocol related values */
#define SECFP_PROTO_ESP 50
#define SECFP_PROTO_AH 51
#define SECFP_PROTO_IP 4
#define SECFP_PROTO_IPV6 41

/* Header length validation information */
#define SECFP_ESP_HDR_LEN 8
#define SECFP_IP_HDR_LEN 20
#define SECFP_AH_MAX_HDR_LEN 16
#define SECFP_ESP_TRAILER_LEN  2
#define SECFP_ICV_LEN 12

/* Capacity information */
#define SECFP_MAX_SPI_ENTRIES 64
#define SECFP_MAX_DSCP_SA 8
#define SECFP_MAX_SPD_CONTAINERS   300
#define SECFP_MAX_NUM_TUNNEL_IFACES		64

/* Options to set up descriptors */
#define SECFP_AUTH     1
#define SECFP_CIPHER   2
#define SECFP_BOTH     3
#define SECFP_AESCTR_BOTH  4
#define SECFP_NONE	5


/* Different algorithm macros */
#define SECFP_HMAC_MD5    1 /* For HmachHash calculation  */
#define SECFP_HMAC_SHA1   2
#define SECFP_HMAC_AES_XCBC_MAC 3
#define SECFP_HMAC_NULL 4 /* No Authentication */
#define SECFP_DES  2   /* generic DES transform using DES-SBC */
#define SECFP_3DES 3   /* generic triple-DES transform    */
#define SECFP_ESP_NULL	   11
#define SECFP_AES 12
#define SECFP_AESCTR 13
#define DES_CBC_BLOCK_SIZE 8
#define TDES_CBC_BLOCK_SIZE    8
#define AES_CBC_BLOCK_SIZE 16
#define AES_CTR_BLOCK_SIZE 8
#define DES_IV_LEN     8
#define TDES_IV_LEN    8
#define AES_CBC_IV_LEN 16
#define AES_CTR_IV_LEN  8

/* Sequence number related */
#define SECFP_APPEND_BUF_LEN_FIELD  4
#define SECFP_HO_SEQNUM_LEN 4
#define SECFP_NOUNCE_IV_LEN 16

/* Used for AES_CTR */
#define SECFP_COUNTER_BLK_LEN 16


/* Number of DHCP based SAs */
#define SECFP_MAX_TOS_INDICES 8

/* Information for preparing outer IP header */
#define SECFP_IPVERSION  4   /* IP Version */
#define SECFP_IP_TTL 120


/* skb Cb indices where various information is kept for post SEC operation */
/* Common for outbound and inbound */
#define SECFP_SKB_SG_DMA_INDEX 0
#define SECFP_SKB_DATA_DMA_INDEX 4
#define SECFP_ACTION_INDEX	8
#define SECFP_REF_INDEX 45

/* Inbound */
#define SECFP_LOOKUP_SA_INDEX	9
#define SECFP_SA_OPTION_INDEX		10
#define SECFP_SPI_INDEX	12
#define SECFP_IPHDR_INDEX	16
#define SECFP_HASH_VALUE_INDEX 20
#define SECFP_SEQNUM_INDEX	24
#define SECFP_SABITMAP_DIFF_INDEX	28
#define SECFP_SABITMAP_INFO_INDEX		32
#define SECFP_TOS_INDEX 33
#define SECFP_UPDATE_TOS_INDEX	34
#define SECFP_SABITMAP_COEF_INDEX		35
#define SECFP_SABITMAP_REMAIN_INDEX	36
#define SECFP_VSG_ID_INDEX	40


/* For Outbound skb indices */
#define SECFP_OUTB_FRAG_REQD   9
#define SECFP_SPD_CI_INDEX		12
#define SECFP_SPD_CI_MAGIC_INDEX 16
#define SECFP_SAD_SAI_INDEX	20
#define SECFP_SAD_SAI_MAGIC_INDEX 24
#define SECFP_IV_DATA_INDEX	28
#define SECFP_OUTB_PATH_MTU	32
#define SECFP_OUTB_L2_OVERHEAD 36


#define SECFP_NUM_IV_DATA_GET_AT_ONE_TRY	1

#define SECFP_DROP 1

#define SECFP_MAX_SECPROC_ITERATIONS 2

#define SECFP_PRESUMED_INTERFACE_MTU 1500
#define SECFP_IN_GATHER_NO_SCATTER	1
#define SECFP_IN_GATHER_SCATTER	0

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
#define SECFP_SCATTER_GATHER  2

/* Assumes skb->data points to beginning of IP header */
/* assumes ESP or AH only */

#define SECFP_EXTRACT_PKTINFO(skb, iph, iphlen, spi, seqnum)	\
{\
	if (iph->protocol == SECFP_PROTO_ESP) {\
		spi = *(unsigned long int *)  &(skb->data[iphlen]); \
		seqnum = *(unsigned long int *)  &(skb->data[iphlen+4]); \
	} \
	else {\
		spi = *(unsigned long int *)  &(skb->data[iphlen+4]); \
		seqnum = *(unsigned long int *)  &(skb->data[iphlen+8]); \
	} \
}
#define SECFP_NUM_IV_ENTRIES 8

#define secfp_compute_hash(spi)	\
		(spi & (SECFP_MAX_SPI_ENTRIES-1))

#define SECFP_SET_DMA_DESC_PTR(descPtr, len, data, extent)	\
{\
	descPtr->len = cpu_to_be16(len);\
	descPtr->ptr = cpu_to_be32(dma_map_single(dev, data, len, DMA_TO_DEVICE));\
	descPtr->j_extent = extent;\
}

#define SECFP_SET_DESC_PTR(a, b, c, d)\
	(a).len = cpu_to_be16(b);\
	(a).ptr = cpu_to_be32(lower_32_bits((c)));\
	(a).eptr = cpu_to_be32(upper_32_bits((c)));\
	(a).j_extent = d;


extern dma_addr_t talitos_dma_map_single(void *data,
			unsigned int len, int dir);
extern dma_addr_t talitos_dma_unmap_single(void *data,
			unsigned int len, int dir);
#define SECFP_DMA_MAP_SINGLE(data, len, dir) \
				talitos_dma_map_single(data, len, dir)
#define SECFP_DMA_UNMAP_SINGLE(data, len, dir) \
				talitos_dma_unmap_single(data, len, dir)

#define SECFP_UNMAP_SINGLE_DESC(data, len) \
	talitos_dma_unmap_single(data, len, DMA_TO_DEVICE)

#define SECFP_MAX_OB_SAS 600

/* Definition copied into asfreasm.c */
#define SECFP_OUTSA_TABLE_SIZE (sizeof(ptrIArry_nd_t)*SECFP_MAX_OB_SAS)

#define SECFP_INSA_TABLE_SIZE (sizeof(inSA_t *)*SECFP_MAX_SPI_ENTRIES)

#define SECFP_IV_TABLE_SIZE (NR_CPUS * SECFP_NUM_IV_ENTRIES * sizeof(unsigned int))

#define SECFP_TOT_SRAM_SIZE (SECFP_OUTSA_TABLE_SIZE + SECFP_INSA_TABLE_SIZE + SECFP_IV_TABLE_SIZE + SECFP_SRAM_SIZE)
/* End of copied definitions */


#define SECFP_MAX_SELECTORS 5

#define ICV_LEN	12

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

#define IGW_SAD_SET_BIT_IN_WINDOW(pSA , ulNunOfBits, ucSize , ucCnt , ucCo_efficient, ucRemainder) \
{\
  ucSize  = pSA->SAParams.AntiReplayWin >> 5;  \
	if (ulNunOfBits >= pSA->SAParams.AntiReplayWin) { \
		for (ucCnt = 0; ucCnt < ucSize ; ucCnt++) \
			pSA->pWinBitMap[ucCnt] = 0; \
	pSA->pWinBitMap[ucSize-1]  |= 1; \
	} else { \
		ucCo_efficient  = ulNunOfBits >> 5; \
		if (ucCo_efficient) {\
			for (ucCnt = 0; (ucCnt + ucCo_efficient) < ucSize;\
					ucCnt++) \
				pSA->pWinBitMap[ucCnt] =\
				pSA->pWinBitMap[ucCnt + ucCo_efficient]; \
			for (ucCnt = 0; ucCnt < ucCo_efficient ; ucCnt++) \
				pSA->pWinBitMap[(ucSize-1) - ucCnt] = 0; \
    } \
    ucRemainder  = ulNunOfBits & 31; \
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
	bCopyDscp:1;
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
	unsigned int bAuth:1,
	bEncrypt:1;
	unsigned int ulSPI;
	struct {
		bool bIPv4OrIPv6; /* 0= IPv4, 1= IPv6 */
		union {
			struct {
				unsigned int saddr;
				unsigned int daddr;
			} iphv4;
			struct {
				unsigned int saddr[32];
				unsigned int daddr[32];
			} iphv6;
		} addr;
	} tunnelInfo;
	unsigned int  bRedSideFragment:1,
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

	unsigned char  ucProtocol;
	unsigned char ucAuthAlgo;
	unsigned char ucCipherAlgo;
	unsigned int AuthKeyLen;
	unsigned short int ulIvSize;
	unsigned int EncKeyLen;
	unsigned short int ulBlockSize;
	unsigned char ucAuthKey[SECFP_MAX_AUTH_KEY_SIZE];
	unsigned char ucEncKey[SECFP_MAX_CIPHER_KEY_SIZE];
	unsigned  int AntiReplayWin;
	unsigned char ucDscp;
	unsigned char ucNounceIVCounter[16]; /* Nonce:4 bytes, followed by 8 bytes IV + 4 bytes counter */
	ASF_IPSec_Nat_Info_t IPsecNatInfo;
	unsigned int ulCId;
} SAParams_t;




typedef struct inSA_s {
	struct rcu_head rcu;
	unsigned int magicNum;
	SAParams_t SAParams;
	int chan;
	SPDInParams_t SPDParams;
	unsigned int ulVSGId;
	unsigned int ulSPDInContainerIndex;
	unsigned int ulSPDInMagicNum;
	unsigned int ulSPDSelSetIndex;
	unsigned int ulSPDSelSetIndexMagicNum;
	unsigned int ulSecHdrLen;
	unsigned int ulLastSeqNum;
	unsigned int *pWinBitMap;
	unsigned char option[SECFP_MAX_SECPROC_ITERATIONS];
	__be32 desc_hdr_template;
	__be32    hdr_Auth_template_0; /* when proto is AH and
					  only Auth needs to be performed*/
	__be32    hdr_Auth_template_1; /* when proto is ESP and auth
					  algorithm is set */
	dma_addr_t	AuthKeyDmaAddr;
	dma_addr_t    EncKeyDmaAddr;

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
	unsigned int ulPkts[NR_CPUS];
	unsigned int ulBytes[NR_CPUS];
	unsigned int ulTunnelId;
	AsfSPDPolicyPPStats_t    PolicyPPStats[NR_CPUS];
	AsfSPDPolPPStats_t	 PPStats;
	/* For Gateway Adaptation purposes */
	unsigned int ulSPDOutContainerIndex;
	unsigned int ulSPDOutContainerMagicNumber;
	unsigned int ulOutSPI;
	unsigned int ulHOSeqNum;
	unsigned char bVerifySASel:1,
	bVerifySPDSel:1,
	bSendPktToNormalPath:1,
	bDPDAlive:1;
	unsigned int ulHashVal;
	char bHeap;
	struct inSA_s *pNext;
	struct inSA_s *pPrev;
} inSA_t;

typedef struct {
	inSA_t *pHeadSA;
} inSAList_t;

struct selNode_s {
	unsigned int ipAddrStart;
	unsigned int ipAddrEnd;
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
	char    bHeap;
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
	char  bHeap;
	struct SPDOutSALinkNode_s *pNext;
	struct SPDOutSALinkNode_s *pPrev;
} SPDOutSALinkNode_t;

typedef struct SPDOutContainer_s {
	struct rcu_head rcu ____cacheline_aligned_in_smp;
	SPDOutParams_t  SPDParams ;
	AsfSPDPolPPStats_t		   PPStats;
	spinlock_t spinlock;
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
	char  bHeap;
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
	AsfSPDPolPPStats_t		   PPStats;
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
	int chan;
	unsigned char option[SECFP_MAX_SECPROC_ITERATIONS]; /* Hardware option AES_CBC or BOTH or only encryption etc. */
	__be32 desc_hdr_template;
	__be32    hdr_Auth_template_0; /* when proto is AH and
					  only Auth needs to be performed*/
	__be32    hdr_Auth_template_1; /* when proto is ESP and auth
					  algorithm is set */
	dma_addr_t	AuthKeyDmaAddr;
	dma_addr_t    EncKeyDmaAddr;
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
				  struct outSA_s *, SPDOutContainer_t *, unsigned int *, unsigned int, unsigned int);
	atomic_t ulLoSeqNum;
	atomic_t ulHiSeqNum;
	unsigned int ulIvSizeInWords;
	unsigned int ulSecHdrLen;
	unsigned int ulSecOverHead;
	unsigned int ulSecLenIncrease;
	unsigned int ulPathMTU;
	unsigned int ulPkts[NR_CPUS];
	unsigned int ulBytes[NR_CPUS];
	AsfSPDPolicyPPStats_t    PolicyPPStats[NR_CPUS];
	AsfSPDPolPPStats_t	 PPStats;
	unsigned int macAddr[6];
	unsigned int ulTunnelId;
	struct net_device *odev;
	OutSelList_t *pSelList;
	bool bl2blob;
	asfTmr_t		    *pL2blobTmr;
	bool bIVDataPresent;
	char bHeap;
	unsigned char	bVLAN:1, bPPPoE:1;
	unsigned char	l2blob[ASF_MAX_L2BLOB_LEN];
	unsigned short	ulL2BlobLen;
	unsigned short	tx_vlan_id; /*valid if bVLAN is 1*/
} outSA_t;


struct saInfo_s {
	unsigned int ulSAIndex;
	unsigned int ulMagicNum;
};

/*
struct secfp_info_s
{
	unsigned int ulCIndex;
	unsigned int ulMagicNum;
	struct saInfo_s saInfo[SECFP_MAX_DSCP_SA];
};
*/

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


typedef struct secfp_ivInfo_s {
	dma_addr_t paddr;
	unsigned long *vaddr;
	unsigned long int ulIVIndex;
	bool bUpdatePending;
	unsigned int ulNumAvail;
	unsigned int ulUpdateIndex;
} secfp_ivInfo_t;

/* to satisfy the compiler */
struct talitos_desc;

extern  void secfp_prepareOutDescriptor(struct sk_buff *skb, void *pSA, struct talitos_desc *, unsigned int);
extern  void secfp_prepareInDescriptor(struct sk_buff *skb, void *pSA, struct talitos_desc *, unsigned int);
void secfp_prepareInDescriptorWithFrags(struct sk_buff *skb,
					void *pData, struct talitos_desc *desc, unsigned int ulIndex);
void secfp_prepareOutDescriptorWithFrags(struct sk_buff *skb, void *pData,
					 struct talitos_desc *desc, unsigned int ulOptionIndex);
extern inline void secfp_outComplete(struct device *dev,
		struct talitos_desc *desc, void *context, int error);
extern inline void secfp_inComplete(struct device *dev,
		struct talitos_desc *desc, void *context, int err);
extern inline void secfp_inv6Complete(struct talitos_desc *desc, struct sk_buff *context, int err);
extern int gfar_start_xmit(struct sk_buff *skb, struct net_device *dev);
extern int try_fastroute_fwnat(struct sk_buff *skb, struct net_device *dev, int length);
extern __be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev);
extern int secfp_try_fastPathInv4(struct sk_buff *skb1,
			   ASF_boolean_t bCheckLen, unsigned int ulVSGId,
			   ASF_uint32_t  ulCommonInterfaceId);

extern void secfp_inCompleteWithFrags(struct device *dev,
		struct talitos_desc *desc, void *context, int err);

extern struct sk_buff *gfar_new_skb(struct net_device *dev);

int secfp_init(void);
void secfp_deInit(void);
int secfp_register_proc(void);
int secfp_unregister_proc(void);

inSA_t *ASF_findInv4SA(unsigned int ulVSGId,
			 unsigned char ucProto,
			 unsigned long int ulSPI, unsigned int daddr, unsigned int *pHashVal);

unsigned int secfp_SPDOutContainerCreate(unsigned int    ulVSGId,
					 unsigned int    ulTunnelId,
					 unsigned int    ulContainerIndex,
					 unsigned int    ulMagicNum,
					 SPDOutParams_t *pSPDParams);
unsigned int secfp_SPDInContainerCreate(unsigned int    ulVSGId,
					unsigned int    ulTunnelId,
					unsigned int    ulContainerIndex,
					unsigned int    ulMagicNum,
					SPDInParams_t  *pSPDParams);

unsigned int secfp_SPDOutContainerDelete(unsigned int ulVSGId,
					 unsigned int ulTunnelId,
					 unsigned int ulContainerIndex,
					 unsigned int ulMagicNumber);

unsigned int secfp_SPDInContainerDelete(unsigned int ulVSGId,
					unsigned int ulTunnelId,
					unsigned int ulContainerIndex,
					unsigned int ulMagicNumber);

unsigned int secfp_DeleteOutSA(unsigned int	 ulSPDContainerIndex,
				 unsigned int	 ulSPDMagicNumber,
				 unsigned int	 daddr,
				 unsigned char	ucProtocol,
				 unsigned int	 ulSPI,
				 unsigned short	usDscpStart,
				 unsigned short	usDscpEnd);

unsigned int secfp_DeleteInSA(unsigned int  ulVSGId,
				unsigned int  ulContainerIndex,
				unsigned int  ulMagicNumber,
				unsigned int  daddr,
				unsigned char  ucProtocol,
				unsigned int  ulSPI);

unsigned int secfp_ModifyOutSA(unsigned int long ulVSGId,
				 ASFIPSecRuntimeModOutSAArgs_t *pModSA);

unsigned int secfp_ModifyInSA(unsigned int long ulVSGId,
				ASFIPSecRuntimeModInSAArgs_t *pModSA);

unsigned int secfp_SetDPDInSA(unsigned int long ulVSGId,
				ASFIPSecRuntimeSetDPDArgs_t *pSetDPD);

ASF_void_t ASFSkbFree(ASF_void_t   *freeArg);
unsigned int secfp_createOutSA(
				unsigned int  ulVSGId,
				unsigned int  ulTunnelId,
				unsigned int  ulSPDContainerIndex,
				unsigned int  ulMagicNumber,
				SASel_t	 *pSrcSel,
				SASel_t	 *pDstSel,
				unsigned char  ucSelMask,
				SAParams_t    *SAParams,
				unsigned  short usDscpStart,
				unsigned  short usDscpEnd,
				unsigned int   ulMtu);

unsigned int secfp_CreateInSA(
			     unsigned int ulVSGId,
			     unsigned int ulTunnelId,
			     unsigned int ulContainerIndex,
			     unsigned int ulMagicNumber,
			     SASel_t     *pSrcSel,
			     SASel_t     *pDstSel,
			     unsigned int ucSelFlags,
			     SAParams_t *pSAParams,
			     unsigned int ulSPDOutContainerIndex,
			     unsigned int ulOutSPI);

#endif
