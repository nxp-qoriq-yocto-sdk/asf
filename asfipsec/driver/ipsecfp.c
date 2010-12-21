/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
 ***************************************************************************/
/*
 * File:	ipsecfp.c
 * Description: Contains the routines for ipsec fast path at the
 * device driver level
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#include <linux/ip.h>
#include <net/ip.h>
#include <gianfar.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#include <linux/version.h>
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"

#include <net/dst.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include "ipseccmn.h"
#define SECFP_MF_OFFSET_FLAG_NET_ORDER  htons(IP_MF|IP_OFFSET)


struct device *pdev;
int secfp_CheckInPkt(
			unsigned int ulVSGId,
			struct sk_buff *skb1, ASF_uint32_t ulCommonInterfaceId,
			ASFFFPIpsecInfo_t  *pSecInfo, void *pIpsecOpq);

int ASFIPSec4SendIcmpErrMsg (unsigned char *pOrgData,
				unsigned char  ucType,
				unsigned char  ucCode,
				unsigned int   ulUnused,
				unsigned int   ulSNetId);
unsigned short ASFIPCkSum(char *data, unsigned short cnt);
unsigned short ASFascksum(unsigned short *pusData, unsigned short usLen);
unsigned short ASFIpEac(unsigned int sum);  /* Carries in high order 16 bits */

int secfp_try_fastPathOutv4 (
				unsigned int ulVSGId,
				struct sk_buff *skb,
				ASFFFPIpsecInfo_t *pSecInfo);

AsfIPSecPPGlobalStats_t IPSecPPGlobalStats_g[NR_CPUS];
AsfIPSec4GlobalPPStats_t IPSec4GblPPStats_g;

static  inline void asfFillLogInfo(ASFLogInfo_t *pAsfLogInfo , inSA_t *pSA);
static inline  void asfFillLogInfoOut(ASFLogInfo_t *pAsfLogInfo, outSA_t *pSA);

#define ASF_ICMP_PROTO  1
#define ASF_ICMP_DEST_UNREACH   3
#define ASF_ICMP_CODE_FRAG_NEEDED 4
#define  ASF_NON_NATT_PACKET 0
#define ASF_NATT_PACKET 1

#define ASF_ICMP_ECHO_REPLY	0  /* Echo Reply */
#define ASF_ICMP_QUENCH	4  /* Source Quench */
#define ASF_ICMP_REDIRECT	5  /* Redirect */
#define ASF_ICMP_TIME_EXCEED  11  /* Time-to-live Exceeded */
#define ASF_ICMP_PARAM_PROB 12
#define BUFPUT16(cp, val)   (*((unsigned short *)  (cp))) = ((unsigned short) (val))
#define BUFPUT32(cp, val)  (*((unsigned int *)  (cp)) = (unsigned int) (val))
#define BUFGET32(cp)		 (*(unsigned int *) (cp))
#define UCHAR(x) ((unsigned char) (x))

#define ASF_IPLEN  20
#define ASF_ICMPLEN 8
#define ASF_IPV4_MAC_CODE 0x800
#define ASF_IPPROTO_ICMP 1
#define MAX_TTL 30
#define ASF_IPSEC_IKE_SERVER_PORT	500
#define ASF_IPSEC_IKE_NAT_FLOAT_PORT   4500

#define ASF_IPSEC_MAX_UDP_ENCAPS_HDR_LEN       8

#define ASF_IPSEC_MAX_NON_IKE_MARKER_LEN	 8
#define ASF_IPSEC_MAX_NON_ESP_MARKER_LEN	 4

#define ASF_NAT_UDP_HDR_LEN 8
#define SECFP_MAX_UDP_HDR_LEN 8
#define ASF_IP_MAXOPT 40

/* Data Structure initialization */
/* Inbound SA SPI Table */
spinlock_t secFP_InSATableLock;
inSAList_t *secFP_SPIHashTable;
char aNonIkeMarker_g[ASF_IPSEC_MAX_NON_IKE_MARKER_LEN];
char aNonESPMarker_g[ASF_IPSEC_MAX_NON_ESP_MARKER_LEN];

/* pad_words to be used for creating padding */
unsigned int pad_words[] = {
	0x01020304,
	0x05060708,
	0x090a0b0c,
	0x0d0e0f10
} ;

unsigned int ulLastOutSAChan_g;
unsigned int ulLastInSAChan_g = 1;

/* Data structure to hold IV data */
secfp_ivInfo_t *secfp_IVData;

typedef struct ASFIPSecOpqueInfo_st {
	unsigned int ulInSPDContainerId;
	unsigned int ulInSPDMagicNumber;
	unsigned char ucProtocol;
	ASF_IPAddr_t DestAddr;
} ASFIPSecOpqueInfo_t;


/* Global Outbound SPD Container */
/* SPDOutContainer_t */
ptrIArry_tbl_t secfp_OutDB;

/*SPDInContainer_t  */
ptrIArry_tbl_t secfp_InDB;

/* An array of outbound SAs */
spinlock_t outSATableBitMapLock;

ptrIArry_tbl_t secFP_OutSATable;

/* Pointer table to hold inbound selector sets */
ptrIArry_tbl_t secFP_InSelTable;

/* An array of VSG based Tunnel interfaces and lock for protecting container
indices within the tunnel */
SecTunnelIface_t **secFP_TunnelIfaces;
spinlock_t secfp_TunnelIfaceCIIndexListLock;

static int SPDCILinkNodePoolId_g = -1;
static int SPDOutContainerPoolId_g = -1;
static int OutSelListPoolId_g = -1;
static int SASelPoolId_g = -1;
static int OutSAPoolId_g = -1;
static int OutSAl2blobPoolId_g = -1;
static int SPDInContainerPoolId_g = -1;
static int SPDInSelTblIndexLinkNodePoolId_g = -1;
static int SPDInSPIValLinkNodePoolId_g = -1;
static int InSelListPoolId_g = -1;
static int InSAPoolId_g = -1;
static int SPDOutSALinkNodePoolId_g = -1;

unsigned int   *pulVSGMagicNumber;
unsigned int ulTimeStamp_g;
static inline inSA_t  *secfp_findInv4SA(unsigned int ulVSGId,
					unsigned char ucProto,
					unsigned long int ulSPI, unsigned int daddr, unsigned int *pHashVal);

#define ASF_IPSEC4_GET_START_ADDR(addr, maskbits)\
 ((maskbits) == 32) ? (addr) : (((addr)&(0xffffffff << (32-(maskbits)))) + 1)

#define ASF_IPSEC4_GET_END_ADDR(addr, maskbits)\
 ((maskbits) == 32) ? (addr) : (((addr)|(0xffffffff >> (maskbits))) - 1)

#define SECFP_ESN_MARKER_POSITION	   (12 + SECFP_NOUNCE_IV_LEN + SECFP_APPEND_BUF_LEN_FIELD)
#define SECFP_COMMON_INTERFACE_ID_POSITION   (SECFP_ESN_MARKER_POSITION + 4)

struct kmem_cache *desc_cache __read_mostly;
struct talitos_desc *desc_rec_queue[NR_CPUS][MAX_IPSEC_RECYCLE_DESC];
static unsigned int curr_desc[NR_CPUS];

struct talitos_desc *secfp_desc_alloc(void)
{
	u32 smp_processor_id = smp_processor_id();
	u32 current_edesc = curr_desc[smp_processor_id];
	if (unlikely(current_edesc == 0)) {
		return kmem_cache_alloc(desc_cache, GFP_KERNEL);
	} else {
		curr_desc[smp_processor_id] = current_edesc - 1;
		return desc_rec_queue[smp_processor_id][current_edesc - 1];
	}
}

void secfp_desc_free(struct talitos_desc *desc)
{
	u32 smp_processor_id = smp_processor_id();
	u32 current_edesc = curr_desc[smp_processor_id];
	if (desc == NULL)
		return ;
	if (unlikely(current_edesc == (MAX_IPSEC_RECYCLE_DESC - 1))) {
		kmem_cache_free(desc_cache, desc);
	} else {
		desc_rec_queue[smp_processor_id][current_edesc] = desc;
		curr_desc[smp_processor_id] = current_edesc + 1;
	}
}

/* DUMMY FUNCTIONS */
int try_fastroute_fwnat(struct sk_buff *skb, struct net_device *dev,
			int length)
{
	return 0;
}
/*
 * This is a stub function. This function is required in VPN Only
 * fast path to determine the VSG ID of the incoming packet
 */
unsigned int secfp_findVSG(struct sk_buff *skb)
{
	return 0;
}

/* Initialization routines/De-Initialization routines */

/* Initialization Tunnel Interfaces */
static int secfp_InitTunnelIfaces(void)
{
	int ii;
	secFP_TunnelIfaces = kzalloc(sizeof(SecTunnelIface_t *) * ulMaxVSGs_g,  GFP_KERNEL);
	if (secFP_TunnelIfaces == NULL) {
		ASFIPSEC_ERR("secfp_TunnelIfaces Initialization failed");
		return 1;
	}
	for (ii = 0; ii < ulMaxVSGs_g; ii++) {
		secFP_TunnelIfaces[ii] = kzalloc(sizeof(SecTunnelIface_t) * ulMaxTunnels_g, GFP_KERNEL);
		if (!secFP_TunnelIfaces[ii]) {
			ASFIPSEC_ERR("secfp_TunnelIfaces Initialization failed");
			return 1;
		}
	}
	return 0;
}

static void secfp_DeInitTunnelIfaces(void)
{
	int ii;
	if (secFP_TunnelIfaces) {
		for (ii = 0; ii < ulMaxVSGs_g; ii++) {
			if (secFP_TunnelIfaces[ii])
				kfree(secFP_TunnelIfaces[ii]);
		}
		kfree(secFP_TunnelIfaces);
	}
}

/*
 * Initializes the Global SA Table
 */


static int secfp_InitOutSATable(void)
{
	ptrIArry_nd_t *pNode;
#ifdef SECFP_USE_L2SRAM
	dma_addr_t addr;
	addr = (unsigned long)(SECFP_SRAM_BASE + SECFP_SRAM_SIZE);
	pNode = ioremap_flags(addr,
				(sizeof(ptrIArry_nd_t)*ulMaxSupportedIPSecSAs_g),
				PAGE_KERNEL | _PAGE_COHERENT);
#else
	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSupportedIPSecSAs_g), GFP_KERNEL);
#endif
	if (pNode) {
		ptrIArray_setup(&secFP_OutSATable, pNode, ulMaxSupportedIPSecSAs_g, 1);
		return 0;
	}
	return 1;
}

static void secfp_DeInitOutSATable(void)
{
#ifndef SECFP_USE_L2SRAM
	ptrIArray_cleanup(&secFP_OutSATable);
#endif
}


/* Initialize the Container Tables */
static int secfp_InitOutContainerTable(void)
{
	ptrIArry_nd_t *pNode;
	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSPDContainers_g), GFP_KERNEL);
	if (pNode) {
		ptrIArray_setup(&(secfp_OutDB), pNode,
				ulMaxSPDContainers_g, 1);
		return 0;
	} else {
		return 1;
	}
}

static void secfp_DeInitOutContainerTable(void)
{
	/* Need to clean up node pointers if any */
	ptrIArray_cleanup(&(secfp_OutDB));
}


/* IV table initialization */
unsigned int secfp_IVinit(void)
{
	int ii;
	secfp_ivInfo_t *ptr;

	secfp_IVData = asfAllocPerCpu(sizeof(secfp_ivInfo_t));
	if (secfp_IVData) {
		for_each_possible_cpu(ii) {
			ptr = per_cpu_ptr(secfp_IVData, ii);

#ifdef SECFP_USE_L2SRAM
			ptr->paddr  = (unsigned long) (SECFP_SRAM_BASE +
				 SECFP_SRAM_SIZE + SECFP_OUTSA_TABLE_SIZE  +
				 SECFP_INSA_TABLE_SIZE +
				 (ii * SECFP_NUM_IV_ENTRIES *
				  sizeof(unsigned int)));
			ptr->vaddr  = ioremap_flags(ptr->paddr,
				(sizeof(unsigned int)*SECFP_NUM_IV_ENTRIES),
				PAGE_KERNEL | _PAGE_COHERENT);
#else
			ptr->vaddr = kzalloc(sizeof(unsigned int) *
					SECFP_NUM_IV_ENTRIES, GFP_KERNEL);
			ptr->paddr = SECFP_DMA_MAP_SINGLE(ptr->vaddr,
					  sizeof(unsigned int) *
					  SECFP_NUM_IV_ENTRIES,
					  DMA_TO_DEVICE);
#endif
			if (!ptr->vaddr) {
				ASFIPSEC_ERR("Allocation of IV Data"
						" storage failed");
				return 1;
			}
		}
	} else {
		ASFIPSEC_ERR("Allocation of Per CPU holder of IV Data failed");
		return 1;
	}
	return 0;
}

void secfp_IVDeInit(void)
{
	secfp_ivInfo_t *ptr;
	int ii;
	if (secfp_IVData) {
		for_each_possible_cpu(ii) {
			ptr = per_cpu_ptr(secfp_IVData, ii);
#ifndef SECFP_USE_L2SRAM
			SECFP_UNMAP_SINGLE_DESC((void *) ptr->paddr,
				sizeof(unsigned int)*SECFP_NUM_IV_ENTRIES);
			kfree(ptr->vaddr);
#endif
		}
		asfFreePerCpu(secfp_IVData);
	}
}

/* In Container table initialization/de-initialization */
static int secfp_InitInContainerTable(void)
{
	ptrIArry_nd_t *pNode;
	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSPDContainers_g), GFP_KERNEL);
	if (pNode) {
		ptrIArray_setup(&(secfp_InDB), pNode, ulMaxSPDContainers_g, 1);
		return 0;
	} else {
		return 1;
	}
}

static void secfp_DeInitInContainerTable(void)
{
	/* Need to clean up node pointers if any */
	ptrIArray_cleanup(&(secfp_InDB));
}

/* In Selector Table */
static int secfp_InitInSelTable(void)
{
	ptrIArry_nd_t *pNode;

	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSupportedIPSecSAs_g), GFP_KERNEL);
	if (pNode) {
		ptrIArray_setup(&secFP_InSelTable, pNode, ulMaxSupportedIPSecSAs_g, 1);
		return 0;
	}
	return 1;
}

static void secfp_DeInitInSelTable(void)
{
	ptrIArray_cleanup(&secFP_InSelTable);
}



/* Inbound SA Table Initialization */
static int secfp_InitInSATable(void)
{
#ifdef SECFP_USE_L2SRAM
	dma_addr_t addr;
	addr = (unsigned long)(SECFP_SRAM_BASE + SECFP_SRAM_SIZE +
			(sizeof(ptrIArry_nd_t) * usMaxInSAHashTaleSize_g));
	secFP_SPIHashTable = (inSAList_t *)  ioremap_flags(addr,
							 (sizeof(inSA_t *) * usMaxInSAHashTaleSize_g),
							 PAGE_KERNEL | _PAGE_COHERENT);
	memset(secFP_SPIHashTable, 0, sizeof(inSA_t *) * usMaxInSAHashTaleSize_g);

#else
	secFP_SPIHashTable = kzalloc(sizeof(inSAList_t *) * usMaxInSAHashTaleSize_g, GFP_KERNEL);
#endif
	if (secFP_SPIHashTable) {
		return 0;
	}
	return 1;
}
#define ASF_SECFP_BLOB_TIME_INTERVAL 1
#define ASF_SECFP_NUM_RQ_ENTRIES   256


unsigned int asfsecfpBlobTmrCb(unsigned int ulVSGId,
				 unsigned int ulIndex, unsigned int ulMagicNum, unsigned int ulSPDContainerIndex)
{
	outSA_t  *pSA;
	ASF_IPSecTunEndAddr_t  TunAddress;

	pSA = ptrIArray_getData(&secFP_OutSATable, ulIndex);
	if (pSA) {
		if (ASFIPSecCbFn.pFnRefreshL2Blob
		&& (ptrIArray_getMagicNum(&secFP_OutSATable, ulIndex) ==
			ulMagicNum)) {
			TunAddress.IP_Version = 4;
			TunAddress.dstIP.bIPv4OrIPv6 = 0;
			TunAddress.srcIP.bIPv4OrIPv6 = 0;
			TunAddress.dstIP.ipv4addr =
				pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
			TunAddress.srcIP.ipv4addr =
				pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
			ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId, pSA->ulTunnelId,
				ulSPDContainerIndex,
				ptrIArray_getMagicNum(&(secfp_OutDB),
					ulSPDContainerIndex),
				&TunAddress,
				pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
			return 0;
		}
		return 1;
	}
	return 1;
}

static int secfp_InitMemPools(void)
{
	unsigned int ulMaxNumber;

	ulMaxNumber = (ulMaxSPDContainers_g * 2) / 10;
	if (asfCreatePool("SPDCILinkNodePool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(struct SPDCILinkNode_s),
			  &SPDCILinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for SPDCILinkNodePoolId_g");
		return 1;
	}
	ulMaxNumber = ulMaxSPDContainers_g / 10;
	if (asfCreatePool("SPDOutContainerPool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(SPDOutContainer_t),
			  &SPDOutContainerPoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed"
				" for SPDOutContainerPoolId_g");
		return 1;
	}
	ulMaxNumber = ulMaxSupportedIPSecSAs_g / 10;
	if (asfCreatePool("OutSelListPool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(OutSelList_t),
			  &OutSelListPoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for OutSelListPoolId_g");
		return 1;
	}

	ulMaxNumber = (ulMaxSupportedIPSecSAs_g * 8) / 10;
	if (asfCreatePool("SASelPoolId", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(SASel_t),
			  &SASelPoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for SASelPoolId_g");
		return 1;
	}

	ulMaxNumber = ulMaxSupportedIPSecSAs_g / 10;
	if (asfCreatePool("OutSAPool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(outSA_t),
			  &OutSAPoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for OutSAPoolId_g");
		return 1;
	}

	if (asfCreatePool("secfpBlobTimer", ulMaxNumber,
			  ulMaxNumber, (ulMaxNumber/2),
			  sizeof(asfTmr_t),
			  &OutSAl2blobPoolId_g)) {
		ASFIPSEC_ERR("asfCreatePool failed for OutSAl2blobPoolId_g");
		return 1;
	}

	if (asfTimerWheelInit(ASF_SECFP_BLOB_TMR_ID, 0,
				1024, ASF_TMR_TYPE_SEC_TMR,
				ASF_SECFP_BLOB_TIME_INTERVAL, ASF_SECFP_NUM_RQ_ENTRIES) == 1) {
		ASFIPSEC_ERR("Error in initializing L2blob Timer wheel\n");
		return 1;
	}

	if (asfTimerAppRegister(ASF_SECFP_BLOB_TMR_ID, 0,
				asfsecfpBlobTmrCb,
				OutSAl2blobPoolId_g)) {
		ASFIPSEC_ERR("Error in Registering L2blob Timer\n");
		return 1;
	}

	ulMaxNumber = ulMaxSPDContainers_g / 10;
	if (asfCreatePool("SPDInContainerPool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(SPDInContainer_t),
			  &SPDInContainerPoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for SPDInContainerPoolId_g");
		return 1;
	}

	ulMaxNumber = ulMaxSupportedIPSecSAs_g / 10;
	if (asfCreatePool("SPDInSelTblIndexLinkNode", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(SPDInSelTblIndexLinkNode_t),
			  &SPDInSelTblIndexLinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for"
			" SPDInSelTblIndexLinkNodePool_g");
		return 1;
	}
	ulMaxNumber = ulMaxSupportedIPSecSAs_g / 10;
	if (asfCreatePool("SPDInSPIValLinkNodePool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(SPDInSPIValLinkNode_t),
			  &SPDInSPIValLinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for"
				" SPDInSPIValLinkNodePoolId_g");
		return 1;
	}
	ulMaxNumber = ulMaxSupportedIPSecSAs_g / 10;
	if (asfCreatePool("InSelListPool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(InSelList_t),
			  &InSelListPoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for InSelListPoolId_g");
		return 1;
	}
	ulMaxNumber = ulMaxSupportedIPSecSAs_g / 10;
	if (asfCreatePool("InSAPool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(inSA_t),
			  &InSAPoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for =InSAPoolId_g");
		return 1;
	}
	ulMaxNumber = ulMaxSupportedIPSecSAs_g / 10;
	if (asfCreatePool("SPDOutSALinkNodePool", ulMaxNumber, ulMaxNumber,
			  ulMaxNumber/2, sizeof(SPDOutSALinkNode_t),
			  &SPDOutSALinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfCreatePool failed for"
				" SPDOutSALinkNodePoolId_g");
		return 1;
	}

	return 0;
}
int secfp_InitConfigIdentitiy(void)
{
	pulVSGMagicNumber = kzalloc(sizeof(unsigned int) * ulMaxVSGs_g,
					GFP_KERNEL);
	if (pulVSGMagicNumber == NULL) {
		ASFIPSEC_ERR("Memory allocation failed for pulVSGMagicNumber");
		return 1;
	}
	return 0;
}

void secfp_DeInitInSATable(void)
{
#ifndef SECFP_USE_L2SRAM
	kfree(secFP_SPIHashTable);
#endif
}

void secfp_DeInitMemPools(void)
{
	if ((SPDOutSALinkNodePoolId_g != -1)
		&& asfDestroyPool(SPDOutSALinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
				" SPDOutSALinkNodePoolId_g");
	}
	if ((InSAPoolId_g != -1)
		&& asfDestroyPool(InSAPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for InSAPoolId_g");
	}
	if ((InSelListPoolId_g != -1)
		&& asfDestroyPool(InSelListPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for InSelListPoolId_g");
	}
	if ((SPDInSPIValLinkNodePoolId_g != -1)
		&& asfDestroyPool(SPDInSPIValLinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
				" SPDInSPIValLinkNodePoolId_g");
	}
	if ((SPDInSelTblIndexLinkNodePoolId_g != -1)
		&& asfDestroyPool(SPDInSelTblIndexLinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
			"SPDInSelTblIndexLinkNodePoolId_g");
	}
	if ((SPDInContainerPoolId_g != -1)
		&& asfDestroyPool(SPDInContainerPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
				" SPDInContainerPoolId_g");
	}
	if (OutSAl2blobPoolId_g != -1) {
		asfTimerWheelDeInit(ASF_SECFP_BLOB_TMR_ID, 0);
		if (asfDestroyPool(OutSAl2blobPoolId_g) != 0)
			ASFIPSEC_ERR("asfDestroyPool failed for"
				" OutSAl2blobPoolId_g");
	}

	synchronize_rcu();

	if ((OutSAPoolId_g != -1)
		&& asfDestroyPool(OutSAPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for OutSAPoolId_g");
	}
	if ((SASelPoolId_g != -1)
		&& asfDestroyPool(SASelPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for SASelPoolId_g");
	}
	if ((OutSelListPoolId_g != -1)
		&& asfDestroyPool(OutSelListPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for OutSelListPoolId_g");
	}
	if ((SPDOutContainerPoolId_g != -1)
		&& asfDestroyPool(SPDOutContainerPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
			" SPDOutContainerPoolId_g");
	}
	if ((SPDCILinkNodePoolId_g != -1)
		&& asfDestroyPool(SPDCILinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for SPDCILinkNodePoolId_g");
	}
	ASFIPSEC_PRINT("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();
}

void secfp_DeInitConfigIdentitiy(void)
{
	if (pulVSGMagicNumber) {
		kfree(pulVSGMagicNumber);
		pulVSGMagicNumber =  NULL;
	}
}

void secfp_deInit(void)
{
	ASFIPSEC_PRINT("DeInitializing Sec FP ");

	secfp_DeInitInSelTable();
	secfp_DeInitInSATable();

	secfp_DeInitMemPools();
	secfp_DeInitConfigIdentitiy();
	secfp_DeInitOutContainerTable();
	secfp_IVDeInit();
	secfp_DeInitInContainerTable();
	secfp_DeInitTunnelIfaces();
	secfp_DeInitOutSATable();
	if (desc_cache)
		kmem_cache_destroy(desc_cache);

}

int secfp_init(void)
{
	/* Global SA Ptr Array Table */
	if (secfp_InitOutSATable()) {
		secfp_deInit();
		ASFIPSEC_ERR("SEC_FP Global SA Table Out failed");
		return SECFP_FAILURE;
	}
	if (secfp_InitTunnelIfaces()) {
		secfp_deInit();
		ASFIPSEC_ERR("SECFP Initialization InitTunnelIfaces failed");
		return SECFP_FAILURE;
	}

	/* Global SPD Container Table */
	if (secfp_InitOutContainerTable()) {
		secfp_deInit();
		ASFIPSEC_ERR("SEC_FP Initialization: Container Table Out failed");
		return SECFP_FAILURE;
	}

	/* Global IV Table setup */
	if (secfp_IVinit()) {
		secfp_deInit();
		ASFIPSEC_ERR("IV Initialization failed ");
		return SECFP_FAILURE;
	}
	if (secfp_InitInContainerTable()) {
		secfp_deInit();
		ASFIPSEC_ERR("Init In Container Table failed");
		return SECFP_FAILURE;
	}

	if (secfp_InitInSelTable()) {
		secfp_deInit();
		ASFIPSEC_ERR(" Selector Table In failed");
		return SECFP_FAILURE;
	}

	if (secfp_InitInSATable()) {
		secfp_deInit();
		ASFIPSEC_ERR(" SPI Table failed");
		return SECFP_FAILURE;
	}
	if (secfp_InitMemPools()) {
		secfp_deInit();
		ASFIPSEC_ERR("Mempool failed");
		return SECFP_FAILURE;
	}
	if (secfp_InitConfigIdentitiy()) {
		secfp_deInit();
		ASFIPSEC_ERR("secfp_InitConfigIdentitiy failed");
		return SECFP_FAILURE;
	}

	ASFFFPRegisterIPSecFunctions(secfp_try_fastPathInv4,
					secfp_try_fastPathOutv4,
					secfp_CheckInPkt,
					NULL);

	memset(&IPSecPPGlobalStats_g, 0x0, sizeof(IPSecPPGlobalStats_g));
	memset(&IPSec4GblPPStats_g, 0x0, sizeof(IPSec4GblPPStats_g));
	memset(aNonIkeMarker_g, 0, ASF_IPSEC_MAX_NON_IKE_MARKER_LEN);
	memset(aNonESPMarker_g, 0, ASF_IPSEC_MAX_NON_ESP_MARKER_LEN);

	pdev = talitos_getdevice();

	desc_cache = kmem_cache_create("desc_cache",
				sizeof(struct talitos_desc),
				__alignof__(struct talitos_desc),
				SLAB_HWCACHE_ALIGN, NULL);

		if (desc_cache == NULL)
			return -ENOMEM;

	return SECFP_SUCCESS;
}

/* Memory Allocation/Freeup routines */
/* These Container Index Link Nodes hold the container indices within the tunnel */
static inline struct SPDCILinkNode_s *secfp_allocSPDCILinkNode(void)
{
	struct SPDCILinkNode_s *pNode;
	char  bHeap;
	pNode = (struct SPDCILinkNode_s *)  asfGetNode(SPDCILinkNodePoolId_g,
							 &bHeap);
	if (pNode && bHeap) {
		pNode->bHeap = bHeap;
	}
	return pNode;
}

static void secfp_freeSDPCILinkNode(struct rcu_head *pData)
{
	struct SPDCILinkNode_s *pNode = (struct SPDCILinkNode_s *)  (pData);
	asfReleaseNode(SPDCILinkNodePoolId_g, pNode, pNode->bHeap);

}

/* Out container alloc/free routine */
static inline SPDOutContainer_t *secfp_allocSPDOutContainer(void)
{
	SPDOutContainer_t *pContainer;
	char bHeap;

	pContainer = (SPDOutContainer_t *)  asfGetNode(SPDOutContainerPoolId_g,
							 &bHeap);
	if (pContainer && bHeap) {
		pContainer->bHeap = bHeap;
	}
	return pContainer;
}

static void secfp_freeSPDOutContainer(struct rcu_head *rcu)
{
	SPDOutContainer_t *pContainer = (SPDOutContainer_t *)  rcu;
	asfReleaseNode(SPDOutContainerPoolId_g, pContainer, pContainer->bHeap);
}


/* Cleanup function for SAList Node */
static void secfp_cleanupSelList(OutSelList_t *pSelList)
{
	struct SASel_s *pSel, *pTmpSel;

	for (pSel = pSelList->srcSel.pNext; pSel != NULL; pSel = pTmpSel) {
		pTmpSel = pSel->pNext;
		asfReleaseNode(SASelPoolId_g, pSel, pSel->bHeap);
	}
	for (pSel = pSelList->destSel.pNext; pSel != NULL; pSel = pTmpSel) {
		pTmpSel = pSel->pNext;
		asfReleaseNode(SASelPoolId_g, pSel, pSel->bHeap);
	}
	asfReleaseNode(OutSelListPoolId_g, pSelList, pSelList->bHeap);
}

/* Out SA Sel Set alloc/free routines */
static void  secfp_addOutSelSet(outSA_t *pSA,
				SASel_t *pSrcSel,
				SASel_t *pDstSel,
				unsigned char ucSelFlags,
				unsigned short usDscpStart,
				unsigned short usDscpEnd)
{
	SASel_t *pTmpSel, *pPrevSel, *pNewSel;
	int ii;
	char bHeap;


	pSA->pSelList = (OutSelList_t *) asfGetNode(OutSelListPoolId_g, &bHeap);
	if (pSA->pSelList == NULL) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_WARN("secfp_addOutSelSet: Allocation of SASelList failed");
		return;
	}
	if (bHeap) {
		pSA->pSelList->bHeap = bHeap;
	}

	pSA->pSelList->ucSelFlags = ucSelFlags;
	pSA->pSelList->usDscpStart = usDscpStart;
	pSA->pSelList->usDscpEnd = usDscpEnd;

	/* Allocate and copy the source selector list */
	for (pPrevSel = NULL, pTmpSel = pSrcSel;
		pTmpSel != NULL;
		pTmpSel = pTmpSel->pNext) {
		if (pTmpSel == pSrcSel) {
			/* Memory for the 1st selector is allocated as part of pSAList*/
			pNewSel = &(pSA->pSelList->srcSel);
		} else {
			pNewSel = (struct SASel_s *)
					asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel && bHeap) {
				pNewSel->bHeap = bHeap;
			}
		}
		if (pNewSel) {
			for (ii = 0; ii < pTmpSel->ucNumSelectors; ii++) {
				memcpy(&(pNewSel->selNodes[ii]),
					 &(pTmpSel->selNodes[ii]),
					 sizeof(struct selNode_s));
			}
			pNewSel->ucNumSelectors  =  pTmpSel->ucNumSelectors;

			if (pPrevSel) {
				pPrevSel->pNext = pNewSel;
				pNewSel->pPrev = pPrevSel;
				pNewSel->pNext = NULL;
			}
			pPrevSel = pNewSel;
		} else {
			GlobalErrors.ulResourceNotAvailable++;
			secfp_cleanupSelList(pSA->pSelList);
			pSA->pSelList = NULL;
			return ;
		}
	}

	for (pPrevSel = NULL, pTmpSel = pDstSel;
		pTmpSel != NULL;
		pTmpSel = pTmpSel->pNext) {
		if (pTmpSel == pDstSel) {
			/* Memory for the 1st selector is allocated as part of pSAList*/
			pNewSel = &(pSA->pSelList->destSel);
		} else {
			pNewSel = (struct SASel_s *)
					asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel && bHeap) {
				pNewSel->bHeap = bHeap;
			}
		}
		if (pNewSel) {
			for (ii = 0; ii < pTmpSel->ucNumSelectors; ii++) {
				memcpy(&(pNewSel->selNodes[ii]),
					 &(pTmpSel->selNodes[ii]),
					 sizeof(struct selNode_s));
			}
			pNewSel->ucNumSelectors  =  pTmpSel->ucNumSelectors;

			if (pPrevSel) {
				pPrevSel->pNext = pNewSel;
				pNewSel->pPrev = pPrevSel;
				pNewSel->pNext = NULL;
			}
			pPrevSel = pNewSel;
		} else {
			GlobalErrors.ulResourceNotAvailable++;
			secfp_cleanupSelList(pSA->pSelList);
			pSA->pSelList = NULL;
			return ;
		}
	}
}

/* Out SA alloc/free routine */
static inline outSA_t *secfp_allocOutSA(void)
{
	outSA_t *pSA;
	char	bHeap;

	pSA = (outSA_t *) asfGetNode(OutSAPoolId_g, &bHeap);
	if (pSA && bHeap) {
		pSA->bHeap = bHeap;
	}
	return pSA;
}
static void secfp_freeOutSA(struct rcu_head *pData)
{
	outSA_t *pSA = (outSA_t *)  pData;

	if (pSA->pL2blobTmr)
		asfTimerStop(ASF_SECFP_BLOB_TMR_ID, 0, pSA->pL2blobTmr);

	if (pSA->pSelList) {
		secfp_cleanupSelList(pSA->pSelList);
	}
	asfReleaseNode(OutSAPoolId_g, pSA, pSA->bHeap);
}

/* In container alloc/free routine */
static inline SPDInContainer_t *secfp_allocSPDInContainer(void)
{
	SPDInContainer_t *pContainer;
	char  bHeap;
	pContainer = (SPDInContainer_t *)
		asfGetNode(SPDInContainerPoolId_g, &bHeap);
	if (pContainer && bHeap) {
		pContainer->bHeap = bHeap;
	}
	return pContainer;
}

static void secfp_freeSPDInContainer(struct rcu_head *rcu)
{
	SPDInContainer_t *pContainer = (SPDInContainer_t *)  rcu;
	asfReleaseNode(SPDInContainerPoolId_g, pContainer, pContainer->bHeap);

}

/* Link Nodes that contain index to the Selector Set in the Selector set table for In containers/SAs */
static void secfp_freeLinkNode(struct rcu_head *rcu)
{
	SPDInSelTblIndexLinkNode_t *pNode = (SPDInSelTblIndexLinkNode_t *)  rcu;
	asfReleaseNode(SPDInSelTblIndexLinkNodePoolId_g, pNode, pNode->bHeap);
}

static SPDInSelTblIndexLinkNode_t  *secfp_allocLinkNode(void)
{
	SPDInSelTblIndexLinkNode_t *pNode;
	char  bHeap;

	pNode = (SPDInSelTblIndexLinkNode_t *)
			asfGetNode(SPDInSelTblIndexLinkNodePoolId_g, &bHeap);
	if (pNode && bHeap) {
		pNode->bHeap = bHeap;
	}
	return pNode;
}

/* SPI values are held in the SPD In container. Used for SPI verification */
static SPDInSPIValLinkNode_t *secfp_allocSPILinkNode(void)
{
	SPDInSPIValLinkNode_t   *pNode;
	char  bHeap;

	pNode = (SPDInSPIValLinkNode_t *)  asfGetNode(SPDInSPIValLinkNodePoolId_g,
							&bHeap);
	if (pNode && bHeap) {
		pNode->bHeap = bHeap;
	}
	return pNode;
}

static void secfp_freeSPILinkNode(struct rcu_head *pNode)
{
	SPDInSPIValLinkNode_t *pLinkNode = (SPDInSPIValLinkNode_t *)  pNode;
	asfReleaseNode(SPDInSPIValLinkNodePoolId_g,
		pLinkNode, pLinkNode->bHeap);
}

/* Updates the selector set within the In Container;
Called when SA is allocated  */
static inline void secfp_updateInContainerSelList(SPDInContainer_t *pContainer,
				SPDInSelTblIndexLinkNode_t *pNode)
{
	SPDInSelTblIndexLinkNode_t *pTempNode;
	spin_lock(&pContainer->spinlock);
	if (pContainer->pSelIndex) {
		pTempNode = pNode->pNext = pContainer->pSelIndex;
		pNode->pPrev = NULL;
		rcu_assign_pointer(pContainer->pSelIndex, pNode);
		if (pTempNode)
			pTempNode->pPrev = pNode;
	} else {
		pNode->pPrev = NULL;
		pNode->pNext = NULL;
		pContainer->pSelIndex = pNode;
	}
	spin_unlock(&pContainer->spinlock);
}



/* Removes selector set index from the In Container */

static inline void secfp_deleteInContainerSelList(SPDInContainer_t *pContainer,
				SPDInSelTblIndexLinkNode_t *pNode)
/*secfp_delInSelTblIndexLinkNode */
{
	spin_lock(&pContainer->spinlock);
	if (pNode == pContainer->pSelIndex) {
		if (pNode->pNext)
			pNode->pNext->pPrev = NULL;
		pContainer->pSelIndex = pNode->pNext;
	} else {
		if (pNode->pNext)
			pNode->pNext->pPrev = pNode->pPrev;
		if (pNode->pPrev)
			pNode->pPrev->pNext = pNode->pNext;
	}
	spin_unlock(&pContainer->spinlock);
	call_rcu((struct rcu_head *)  pNode,  secfp_freeLinkNode);
}

/* Updates SPI value index in a linked node in the SDD In container (called when SA
is allocated */
static inline void secfp_updateInContainerSPIList(SPDInContainer_t *pContainer,
						  SPDInSPIValLinkNode_t *pNode)
{
	SPDInSPIValLinkNode_t *pTempNode;
	spin_lock(&pContainer->spinlock);
	if (pContainer->pSPIValList) {
		pTempNode = pNode->pNext = pContainer->pSPIValList;
		pNode->pPrev = NULL;
		rcu_assign_pointer(pContainer->pSPIValList, pNode);
		if (pTempNode)
			pTempNode->pPrev = pNode;
	} else {
		pNode->pPrev = NULL;
		pNode->pNext = NULL;
		pContainer->pSPIValList = pNode;
	}
	spin_unlock(&pContainer->spinlock);
}

/* Finds the SPI node in the container; Used for SPI verification as well
	as for SA deletion */
static inline SPDInSPIValLinkNode_t *secfp_findInSPINode(SPDInContainer_t *pContainer,
							 unsigned int ulSPIVal)
{
	SPDInSPIValLinkNode_t *pNode;

	for (pNode = pContainer->pSPIValList; pNode != NULL; pNode = pNode->pNext) {
		if (pNode->ulSPIVal == ulSPIVal) {
			break;
		}
	}
	return pNode;
}

/* This deletes the SPI Link node from the SPD In container */
static inline void secfp_deleteInContainerSPIList(SPDInContainer_t *pContainer,
						  SPDInSPIValLinkNode_t *pNode)
{
	spin_lock(&pContainer->spinlock);
	if (pNode == pContainer->pSPIValList) {
		if (pNode->pNext)
			pNode->pNext->pPrev = NULL;
		pContainer->pSPIValList = pNode->pNext;
	} else {
		if (pNode->pNext)
			pNode->pNext->pPrev = pNode->pPrev;
		if (pNode->pPrev)
			pNode->pPrev->pNext = pNode->pNext;
	}
	spin_unlock(&pContainer->spinlock);
	call_rcu((struct rcu_head *)  pNode,  secfp_freeSPILinkNode);
}

/* Free/alloc functions for In Selector sets */
void secfp_freeInSelSet(struct rcu_head *pData)
{
	InSelList_t *pList = (InSelList_t *)  (pData);
	SASel_t *pTempSel, *pTempNextSel;

	if (pList) {
		pTempSel = (pList->pSrcSel);
		while (pTempSel) {
			pTempNextSel = pTempSel->pNext;
			asfReleaseNode(SASelPoolId_g, pTempSel, pTempSel->bHeap);
			pTempSel = pTempNextSel;
		}
		pTempSel = (pList->pDestSel);
		while (pTempSel) {
			pTempNextSel = pTempSel->pNext;
			asfReleaseNode(SASelPoolId_g, pTempSel, pTempSel->bHeap);
			pTempSel = pTempNextSel;
		}
		asfReleaseNode(InSelListPoolId_g, pList, pList->bHeap);
	}
}
/* This function secfp_createInSelSet creates and populates Selector set */
SPDInSelTblIndexLinkNode_t *secfp_updateInSelSet(
					SPDInContainer_t	*pContainer,
					SASel_t		  *pSrcSel,
					SASel_t		  *pDstSel,
					unsigned int		ucSelFlags)
{
	InSelList_t *pList;
	SASel_t *pTempSel;
	SASel_t *pNewSel, *pPrevSel;
	bool bFail;
	SPDInSelTblIndexLinkNode_t *pNode;
	unsigned int ulIndex;
	char bHeap;

	pList = (InSelList_t *)  asfGetNode(InSelListPoolId_g, &bHeap);
	if (pList) {
		if (bHeap)
			pList->bHeap = bHeap;
		pList->ucSelFlags = ucSelFlags;
		pPrevSel = NULL;
		bFail = FALSE;
		for (pTempSel = pSrcSel; pTempSel != NULL; pTempSel = pTempSel->pNext) {
			pNewSel = (SASel_t *)  asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel) {
				if (bHeap)
					pNewSel->bHeap = bHeap;
				memcpy(pNewSel, pTempSel, sizeof(SASel_t));
				pNewSel->pPrev = NULL;
				pNewSel->pNext = NULL;
			} else {
				bFail = TRUE;
				break;
			}
			if (pPrevSel) {
				pPrevSel->pNext = pNewSel;
				pNewSel->pPrev = pPrevSel;
			}
			if (!pList->pSrcSel)
				pList->pSrcSel = pNewSel;

			pPrevSel = pNewSel;
		}
		if (bFail != TRUE) {
			pPrevSel = NULL;
			for (pTempSel = pDstSel; pTempSel != NULL; pTempSel = pTempSel->pNext) {
				pNewSel = (SASel_t *)  asfGetNode(SASelPoolId_g, &bHeap);
				if (pNewSel) {
					if (bHeap)
						pNewSel->bHeap = bHeap;
					memcpy(pNewSel, pTempSel, sizeof(SASel_t));
					pNewSel->pPrev = NULL;
					pNewSel->pNext = NULL;
				} else {
					bFail = TRUE;
					break;
				}
				if (pPrevSel) {
					pPrevSel->pNext = pNewSel;
					pNewSel->pPrev = pPrevSel;
				}
				if (!pList->pDestSel)
					pList->pDestSel = pNewSel;

				pPrevSel = pNewSel;
			}
		}
	} else {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_WARN("InSelList allocation failed ");
		return NULL;
	}

	if (bFail != TRUE) {
		pNode = secfp_allocLinkNode();
		if (pNode) {
			ulIndex = ptrIArray_add(&secFP_InSelTable, pList);
			if (ulIndex != secFP_InSelTable.nr_entries) {
				pNode->ulIndex = ulIndex;
				/* Success condition */
				secfp_updateInContainerSelList(pContainer, pNode);
			} else {
				GlobalErrors.ulInSAFull++;
				ASFIPSEC_WARN("Could not find index to hold Selector:Maximum count reached ");
				secfp_freeInSelSet((struct rcu_head *)  pList);
				secfp_freeLinkNode((struct rcu_head *)  pNode);
				return NULL;
			}
		} else {
			GlobalErrors.ulResourceNotAvailable++;
			ASFIPSEC_WARN("Failure in allocating Link node");
			secfp_freeInSelSet((struct rcu_head *)  pList);
			return NULL;
		}
	} else {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_WARN("Failure in setting up selector set node");
		/* Need to clean up */
		secfp_freeInSelSet((struct rcu_head *)  pList);
		return NULL;
	}
	return pNode;
}

/* Alloc & Append the SPI index value within the SPD In container;
	Called when In SA is populated */
unsigned int secfp_allocAndAppendSPIVal(SPDInContainer_t *pContainer,
					inSA_t *pSA)
{
	SPDInSPIValLinkNode_t *pSPILinkNode = secfp_allocSPILinkNode();

	if (pSPILinkNode) {
		/* Need to add value and append to list */
		pSPILinkNode->ulSPIVal = pSA->SAParams.ulSPI;
		/* Now add to the list */
		secfp_updateInContainerSPIList(pContainer, pSPILinkNode);
		return 1;
	}
	ASFIPSEC_WARN("secfp_allocSPILinkNode returned null");
	return 0;
}


/* Alloc/free routines for In SA */

static inline inSA_t *secfp_allocInSA(unsigned int AntiReplayWin)
{
	inSA_t *pSA;
	char   bHeap;

	pSA = (inSA_t *)  asfGetNode(InSAPoolId_g, &bHeap);
	if (pSA) {
		if (bHeap)
			pSA->bHeap = bHeap;
		if (AntiReplayWin) {
			pSA->pWinBitMap = kzalloc((AntiReplayWin/32 *
					sizeof(unsigned int)), GFP_ATOMIC);
			if (!pSA->pWinBitMap) {
				ASFIPSEC_WARN("Memory allocation for Replay Window failed");
				asfReleaseNode(InSAPoolId_g, pSA, pSA->bHeap);
				return NULL;
			}
		}
	}
	return pSA;
}

static void secfp_freeInSA(struct rcu_head *rcu_data)
{
	inSA_t *pSA = (inSA_t *)  rcu_data;
	if (pSA->pWinBitMap) {
		kfree(pSA->pWinBitMap);
	}
	asfReleaseNode(InSAPoolId_g, pSA, pSA->bHeap);
}


/* Appends SA to the SPI based hash list  */
static inline void secfp_appendInSAToSPIList(inSA_t *pSA)
{
	unsigned int hashVal = secfp_compute_hash(pSA->SAParams.ulSPI);
	inSA_t *pTempSA;

	pSA->ulHashVal = hashVal;

	spin_lock_bh(&secFP_InSATableLock);
	if (secFP_SPIHashTable[hashVal].pHeadSA) {
		pTempSA = pSA->pNext = secFP_SPIHashTable[hashVal].pHeadSA;
		pSA->pPrev = NULL;
		rcu_assign_pointer(secFP_SPIHashTable[hashVal].pHeadSA, pSA);
		if (pTempSA)
			pTempSA->pPrev = pSA;
	} else {
		pSA->pPrev = NULL;
		pSA->pNext = NULL;
		secFP_SPIHashTable[hashVal].pHeadSA = pSA;
	}
	spin_unlock_bh(&secFP_InSATableLock);
}


/* Deletes inbound SA from the SPI based hash list */
static inline void secfp_deleteInSAFromSPIList(inSA_t *pSA)
{
	inSA_t *pTempSA = pSA;

	if (pTempSA) {
		spin_lock_bh(&secFP_InSATableLock);
		if (pTempSA == secFP_SPIHashTable[pSA->ulHashVal].pHeadSA) {
			if (pTempSA->pNext)
				pTempSA->pNext->pPrev = NULL;
			secFP_SPIHashTable[pSA->ulHashVal].pHeadSA = pTempSA->pNext;
		} else {
			if (pTempSA->pNext)
				pTempSA->pNext->pPrev = pTempSA->pPrev;
			if (pTempSA->pPrev)
				pTempSA->pPrev->pNext = pTempSA->pNext;
		}
		spin_unlock_bh(&secFP_InSATableLock);
		call_rcu((struct rcu_head *)  pTempSA,  secfp_freeInSA);
	}
}



/* SELECTOR SET Related functions: Currently Stubbed out */
/* Functions to
  a) find matching selector set based SA
  b) Add selector set based SA
  b) Delete selector set based SA
  */

static SPDOutSALinkNode_t *secfp_findOutSALinkNode(SPDOutContainer_t *pContainer,
					unsigned int	 daddr,
					unsigned char	ucProtocol,
					unsigned int	 ulSPI)
{
	SPDOutSALinkNode_t *pOutSALinkNode;
	outSA_t		*pSA;
	bool		   bMatchFound = FALSE;

	for (pOutSALinkNode = pContainer->SAHolder.pSAList;
		pOutSALinkNode != NULL;
		pOutSALinkNode = pOutSALinkNode->pNext) {
		pSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
		if ((pSA) &&
			(pSA->SAParams.ulSPI == ulSPI) &&
			(pSA->SAParams.tunnelInfo.addr.iphv4.daddr == daddr) &&
			(pSA->SAParams.ucProtocol == ucProtocol)) {
			bMatchFound = TRUE;
			break;
		}
	}
	if (bMatchFound == TRUE)
		return pOutSALinkNode;
	return NULL;
}


static SPDOutSALinkNode_t *secfp_cmpPktSelWithSelSet(
				SPDOutContainer_t *pContainer,
				struct sk_buff *skb)
{
	SASel_t *pSel;
	struct selNode_s *pSelNode;
	unsigned char ucMatchSrcSelFlag, ucMatchDstSelFlag;
	struct iphdr  *iph = ip_hdr(skb);
	unsigned short int *ptrhdrOffset;
	unsigned short int sport, dport;
	bool bMatchFound = FALSE;
	SPDOutSALinkNode_t *pSALinkNode;
	outSA_t *pSA;
	int ii;

	ptrhdrOffset = (unsigned short int *)  (&(skb->data[(iph->ihl*4)]));
	sport = *ptrhdrOffset;
	dport = *(ptrhdrOffset+1);

	for (pSALinkNode = pContainer->SAHolder.pSAList; pSALinkNode != NULL; pSALinkNode = pSALinkNode->pNext) {
		pSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable, pSALinkNode->ulSAIndex);
		if ((pSA) && (pSA->pSelList)) {
			ucMatchSrcSelFlag = ucMatchDstSelFlag = 0;

			for (pSel = &(pSA->pSelList->srcSel); pSel != NULL; pSel = pSel->pNext) {
				for (ii = 0; ii < pSel->ucNumSelectors; ii++) {
					pSelNode = &(pSel->selNodes[ii]);
					ucMatchSrcSelFlag = 0;

					if (pSA->pSelList->ucSelFlags & SECFP_SA_XPORT_SELECTOR) {
						if (iph->protocol == pSelNode->proto)
							ucMatchSrcSelFlag = SECFP_SA_XPORT_SELECTOR;
						else
							continue;
					}
					if (pSA->pSelList->ucSelFlags & SECFP_SA_SRCPORT_SELECTOR) {
						if ((sport >= pSelNode->prtStart) &&
							(sport <= pSelNode->prtEnd)) {
							ucMatchSrcSelFlag |= SECFP_SA_SRCPORT_SELECTOR;
						} else
							continue;
					}
					if (pSA->pSelList->ucSelFlags & SECFP_SA_SRCIPADDR_SELECTOR) {
						if ((iph->saddr >= pSelNode->ipAddrStart) &&
							(iph->saddr <= pSelNode->ipAddrEnd)) {
							ucMatchSrcSelFlag |= SECFP_SA_SRCIPADDR_SELECTOR;
						} else
							continue;
					}
					bMatchFound = TRUE;
					break;
				}
				if (bMatchFound == TRUE)
					break;
			}
			bMatchFound = FALSE;
			for (pSel = &(pSA->pSelList->destSel); pSel != NULL; pSel = pSel->pNext) {
				for (ii = 0; ii < pSel->ucNumSelectors; ii++) {
					pSelNode = &(pSel->selNodes[ii]);
					ucMatchDstSelFlag = 0;

					if (pSA->pSelList->ucSelFlags & SECFP_SA_XPORT_SELECTOR) {
						if (iph->protocol == pSelNode->proto)
							ucMatchDstSelFlag = SECFP_SA_XPORT_SELECTOR;
						else
							continue;
					}
					if (pSA->pSelList->ucSelFlags & SECFP_SA_DESTPORT_SELECTOR) {
						if ((dport >= pSelNode->prtStart) &&
							(dport <= pSelNode->prtEnd)) {
							ucMatchDstSelFlag |= SECFP_SA_DESTPORT_SELECTOR;
						} else
							continue;
					}
					if (pSA->pSelList->ucSelFlags & SECFP_SA_DESTIPADDR_SELECTOR) {
						if ((iph->daddr >= pSelNode->ipAddrStart) &&
							(iph->daddr <= pSelNode->ipAddrEnd)) {
							ucMatchDstSelFlag |= SECFP_SA_DESTIPADDR_SELECTOR;
						} else
							continue;
					}
					bMatchFound = TRUE;
					break;
				}
				if (bMatchFound == TRUE)
					break;
			}
			if (pSA->pSelList->ucSelFlags & SECFP_SA_DSCP_SELECTOR) {
				if ((iph->tos >= pSA->pSelList->usDscpStart) &&
					(iph->tos <= pSA->pSelList->usDscpEnd))
					ucMatchSrcSelFlag |= SECFP_SA_DSCP_SELECTOR;
			}
			if ((ucMatchSrcSelFlag | ucMatchDstSelFlag) == pSA->pSelList->ucSelFlags) {
				return pSALinkNode;
			}
		}
	}
	return NULL;
}

SPDOutSALinkNode_t *secfp_allocOutSALinkNode(void)
{
	SPDOutSALinkNode_t *pOutSALinkNode;
	char			bHeap;
	pOutSALinkNode = (SPDOutSALinkNode_t *)  asfGetNode(SPDOutSALinkNodePoolId_g,
								&bHeap);
	if (pOutSALinkNode && bHeap) {
		pOutSALinkNode->bHeap = bHeap;
	}
	return pOutSALinkNode;
}

void secfp_freeOutSALinkNode(struct rcu_head *rcu)
{
	SPDOutSALinkNode_t *pOutSALinkNode = (SPDOutSALinkNode_t *)  rcu;
	asfReleaseNode(SPDOutSALinkNodePoolId_g, pOutSALinkNode, pOutSALinkNode->bHeap);
}

static void secfp_addOutSALinkNode(SPDOutContainer_t *pContainer,
	SPDOutSALinkNode_t *pOutSALinkNode)
{
	/* Adding new SAList to pContainer */
	spin_lock_bh(&pContainer->spinlock);
	pOutSALinkNode->pNext = pContainer->SAHolder.pSAList;
	pOutSALinkNode->pPrev =  NULL;

	if (pContainer->SAHolder.pSAList)
		pContainer->SAHolder.pSAList->pPrev = pOutSALinkNode;

	rcu_assign_pointer(pContainer->SAHolder.pSAList, pOutSALinkNode);

	spin_unlock_bh(&pContainer->spinlock);

}

static void secfp_delOutSALinkNode(SPDOutContainer_t *pContainer,
	SPDOutSALinkNode_t *pOutSALinkNode)
{
	spin_lock_bh(&pContainer->spinlock);
	if (pContainer->SAHolder.pSAList == pOutSALinkNode) {
		pContainer->SAHolder.pSAList = pOutSALinkNode->pNext;
		if (pOutSALinkNode->pNext)
			pOutSALinkNode->pNext->pPrev = NULL;
	} else {
		if (pOutSALinkNode->pPrev)
			pOutSALinkNode->pPrev->pNext = pOutSALinkNode->pNext;

		if (pOutSALinkNode->pNext)
			pOutSALinkNode->pNext->pPrev = pOutSALinkNode->pPrev;
	}

	spin_unlock_bh(&pContainer->spinlock);
	call_rcu((struct rcu_head *)  pOutSALinkNode,  secfp_freeOutSALinkNode);

}

/*
 * In the VPN only fast path build, there needs to be a cache that holds the
  * flow entries and corresponding Out SA Index/magic number, In/Out
  * SPD containers and magic number like what firewall fast path does
  * Currently stub function
  */
static inline unsigned int secfp_findflow (unsigned int ulVSGId,
					unsigned int *pSPDContainerIndex,
					struct sk_buff *skb,  unsigned char tos)
{
	return 0;
}


/*
 * Following are the API definitions which Normal Path/Control Planes
 * can use
 */


/* Stub function: This is an indication to IKE to stop sending keep
alive messages */

void secfp_sendIndToIke(outSA_t *pSA)
{
	ASFIPSEC_PRINT("Stub function: needs to be filled in");
}

/* Packet Processing routines */
/* Check if IVLength required is always 8 bytes To be checked */
/* This function reads from the SEC random number registers. If data is not available
	it reads from the internal IV Array maintained. Upon encryption, some blob is copied
	into this array for use if any
	*/
unsigned int ulRndMisses[NR_CPUS];
static inline void secfp_GetIVData(unsigned int *pData, unsigned int ulNumWords)
{
	int ii;
	int coreId = smp_processor_id();
	secfp_ivInfo_t *ptr = per_cpu_ptr(secfp_IVData, coreId);

	if (secfp_rng_read_data((unsigned int *) ptr))
		return;

	for (ii = 0; ii < ulNumWords; ii++) {
		*pData  = ptr->vaddr[ptr->ulIVIndex];
		ptr->ulIVIndex = (ptr->ulIVIndex + 1) & (SECFP_NUM_IV_ENTRIES - 1);
	}
	if (ulNumWords <= ptr->ulNumAvail) {
		ptr->ulNumAvail -= ulNumWords;
	} else {
		ulRndMisses[coreId]++;
		if ((ulRndMisses[coreId] % 0xffffffff) == 0)
			ASFIPSEC_PRINT("ulRndMisses[%d] = %d",  coreId, ulRndMisses[coreId]);
	}
	return;
}

int vqentr_talitos_rng_data_read(unsigned int len, unsigned int *data)
{
	secfp_GetIVData(data, len/4);
	return len;
}
EXPORT_SYMBOL(vqentr_talitos_rng_data_read);

/* Function called at the end of Outbound processing. Some part of
	the encrypted blob is retained to be reused as IV data
   */
static inline void secfp_updateIVData(unsigned int *pData)
{
	secfp_ivInfo_t *ptr;

	ptr = per_cpu_ptr(secfp_IVData, smp_processor_id());
	if (ptr->ulNumAvail <= SECFP_NUM_IV_ENTRIES) {
		ptr->vaddr[ptr->ulUpdateIndex] = *pData;
		ptr->ulIVIndex = (ptr->ulUpdateIndex + 1) & (SECFP_NUM_IV_ENTRIES - 1);
		ptr->vaddr[ptr->ulUpdateIndex] = *(pData + 1);
		ptr->ulIVIndex = (ptr->ulUpdateIndex + 1) & (SECFP_NUM_IV_ENTRIES - 1);
		ptr->vaddr[ptr->ulUpdateIndex] = *pData;
		ptr->ulIVIndex = (ptr->ulUpdateIndex + 1) & (SECFP_NUM_IV_ENTRIES - 1);
		ptr->vaddr[ptr->ulUpdateIndex] = *(pData + 1);
		ptr->ulIVIndex = (ptr->ulUpdateIndex + 1) & (SECFP_NUM_IV_ENTRIES - 1);
		ptr->ulNumAvail += 4;
	}
	return;
}

/*
 * This populates the ID field to be supplied as the IP identifier field of the Outer
 * IP header
 */

/* TBD make this data structure cache aligned */
__be16 secfp_IPv4_IDs[NR_CPUS];
static inline __be16 secfp_getNextId(void)
{
	/* Stub : To be filled */
	return secfp_IPv4_IDs[smp_processor_id()]++;
}

/*
 * Outbound packet processing is split as follows -
 * Lookup SA
 * prepare the packet sufficiently for SEC processing such as SEC header
 * addition, padding etc. This is done in prepareOutPacket function. Also required
 * information is copied from the inner IP header to the outer IP header
 * Then secfp_talitos_submit is called, which internally calls
 * prepareOutDescriptor and submits descriptors to the SEC block
 * While SEC is processing, finishOutPacket is called by core. This will finish
 * the remaining processing including updating the outer IP header, adjusting
 * the length, skb data, preparing the ethernet header etc.
 * when SEC completes, it calls outComplete, which will call the ethernet
 * driver transmit routine.  IV data if available in the packet is copied into
 * the IV array
 */

static void
secfp_finishOutPacket(struct sk_buff *skb, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int *pOuterIpHdr,
		unsigned int ulVSGId,
		unsigned int ulSPDContainerIndex)
{
	struct iphdr *iph, *org_iphdr;
	unsigned int *pIpHdrInSA, usNatOverHead = 0;
	char *pUDPHdr;
	int ii;
	AsfSPDPolicyPPStats_t   *pIPSecPolicyPPStats;
	ASF_IPSecTunEndAddr_t  TunAddress;

	pIpHdrInSA = (unsigned int *)  &(pSA->ipHdrInfo.hdrdata.iphv4);
	org_iphdr = (struct iphdr *) pIpHdrInSA;
	/* Outer IP already has the TOS and the length field */
	/* Since length and TOS bits are already set, copy the rest */

	ASFIPSEC_PRINT("FinishPkt: pOuterIpHdr = 0x%x", (int)pOuterIpHdr);
	for (ii = 1; ii < 5; ii++) {
		/* Copy prepared header from SA */
		*(unsigned int *)  &(pOuterIpHdr[ii]) = pIpHdrInSA[ii];
	}
	iph = (struct iphdr *)  pOuterIpHdr;

	iph->version = pSA->ipHdrInfo.hdrdata.iphv4.version;
	iph->ihl = (unsigned char)5;
	iph->id = secfp_getNextId();

	if (!pSA->SAParams.bCopyDscp) {
		/* We have set the DSCP value from the SA, We need to copy the ESN related from
				the packet */
		iph->tos |= (unsigned char)(org_iphdr->tos & 0x1100);
	}
	skb->ip_summed = CHECKSUM_PARTIAL;

	/* Update skb->len with ICV in the case where SA Option is set to BOTH which is ESP+Auth */
	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		usNatOverHead = ASF_NAT_UDP_HDR_LEN;
		pUDPHdr = ((char *) pOuterIpHdr) + SECFP_IP_HDR_LEN;
		BUFPUT16(pUDPHdr, pSA->SAParams.IPsecNatInfo.usSrcPort);
		BUFPUT16(pUDPHdr+2, pSA->SAParams.IPsecNatInfo.usDstPort);
		BUFPUT16(pUDPHdr+4, iph->tot_len - SECFP_IP_HDR_LEN);
		BUFPUT16(pUDPHdr+6, 0);
		if (pSA->SAParams.IPsecNatInfo.ulNATt == ASF_IPSEC_IKE_NATtV1) {
			memset(pUDPHdr+8, 0, 8);
			usNatOverHead += 8;
		}
		iph->protocol = IPPROTO_UDP;
	}

	/* Update SA Statistics */
	pSA->ulPkts[smp_processor_id()]++;
	pSA->ulBytes[smp_processor_id()] += iph->tot_len - pSA->ulSecHdrLen;
	pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
	pIPSecPolicyPPStats->NumOutBoundOutPkts++;

	/* Update the skb fields */
	skb->len += pSA->ulSecLenIncrease;
	skb->data = skb->data - SECFP_IP_HDR_LEN - usNatOverHead;
	skb->len +=  usNatOverHead;
	ASFIPSEC_PRINT("Finish packet: ulSecLenIncrease = %d, IP_HDR_LEN=%d "\
		"Updated skb->data = 0x%x",
		pSA->ulSecLenIncrease, SECFP_IP_HDR_LEN, (int)skb->data);

	/* Update L2 Blob information and send pkt out */
	if (pSA->bl2blob) {
		skb->data -= pSA->ulL2BlobLen;
		skb->len += pSA->ulL2BlobLen;

		/* make following unconditional*/
		if (pSA->bVLAN)
			skb->vlan_tci = pSA->tx_vlan_id;
		else
			skb->vlan_tci = 0;

		asfCopyWords((unsigned int *)  skb->data,
				(unsigned int *)  pSA->l2blob, pSA->ulL2BlobLen);
		if (pSA->bPPPoE) {
			/* PPPoE packet.. Set Payload length in PPPoE header */
			*((short *)&(skb->data[pSA->ulL2BlobLen-4])) = htons(ntohs(iph->tot_len) + 2);
		}
		ASFIPSEC_DEBUG("skb->network_header = 0x%x, skb->transport_header = 0x%x\r\n",
			skb_network_header(skb), skb_transport_header(skb));
		skb_set_network_header(skb, pSA->ulL2BlobLen);
		skb_set_transport_header(skb, (20 + pSA->ulL2BlobLen));
	} else {
		ASFIPSEC_DEBUG("OutSA - L2blob info not available");
		/* Update the ethernet header */
		skb->data -= ETH_HLEN;
		skb->len += ETH_HLEN;
		*(unsigned short *)  &(skb->data[12]) = __constant_htons(ETH_P_IP);
		*(unsigned int *)  &(skb->data[0]) = pSA->macAddr[0];
		*(unsigned int *)  &(skb->data[4]) = pSA->macAddr[1];
		*(unsigned int *)  &(skb->data[8]) = pSA->macAddr[2];

		/* set up the network header etc. that may be needed subsequently */
		skb_set_network_header(skb, ETH_HLEN);
		skb_set_transport_header(skb, (20 + ETH_HLEN));
		skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		return;
	}


	if (iph->tot_len > pSA->odev->mtu) {
		/* Need to fragment the packet */
		ASFIPSEC_PRINT("Need to fragment the packet and send it out ");
		skb->cb[SECFP_OUTB_FRAG_REQD] = 1;
	} else {
		skb->cb[SECFP_OUTB_FRAG_REQD] = 0;
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	hexdump(skb->data, 64);
	ASFIPSEC_PRINT("");
#endif

	/* set up the Skb dev pointer */
	skb->dev = pSA->odev;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (ASFIPSecCbFn.pFnRefreshL2Blob &&
		((pSA->ulPkts[0] + pSA->ulPkts[1]) % ulL2BlobRefreshPktCnt_g == 0)) {
		TunAddress.IP_Version = 4;
		TunAddress.dstIP.bIPv4OrIPv6 = 0;
		TunAddress.srcIP.bIPv4OrIPv6 = 0;
		TunAddress.dstIP.ipv4addr =
			pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
		TunAddress.srcIP.ipv4addr =
			pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId, pSA->ulTunnelId,
			ulSPDContainerIndex,
			ptrIArray_getMagicNum(&(secfp_OutDB),
				ulSPDContainerIndex), &TunAddress,
			pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
}


#ifdef ASF_IPSEC_DEBUG_L2
void print_desc(struct talitos_desc *desc)
{
	int ii;
	ASFIPSEC_PRINT("Hdr: 0x%x",  desc->hdr);
	ASFIPSEC_PRINT("hdr_lo: 0x%x",  desc->hdr_lo);
	for (ii = 0; ii < 7; ii++) {
		ASFIPSEC_PRINT("PrtrIndex %d: Ptr[].len = %d, ptr[].extent=%d, ptr[].eptr=0x%x, ptr[].ptr=0x%x\n",
			 ii, desc->ptr[ii].len, desc->ptr[ii].j_extent, desc->ptr[ii].eptr, desc->ptr[ii].ptr);
	}
}
#else
#define print_desc(a)
#endif

/*
 * Prepares packet for SEC submission: including setting up ESP header, sequence
 * number etc.
 */

static void
secfp_prepareOutPacket(struct sk_buff *skb1, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int **pOuterIpHdr)
{
	struct iphdr *iph, *org_iphdr;
	int ii;
	unsigned short usPadLen, usNatOverHead, usLastByte;
	unsigned int ulLoSeqNum, ulHiSeqNum;
	struct sk_buff *pHeadSkb, *pTailSkb;

	pTailSkb = pHeadSkb = skb1;
	if (skb_shinfo(skb1)->frag_list) {
		for (pTailSkb = skb_shinfo(skb1)->frag_list; pTailSkb->next != NULL; pTailSkb = pTailSkb->next)
			;
	}

	org_iphdr = ip_hdr(skb1);

	/* Padding length calculation assumes that the block size is always 8 or 16
		as is the case for DES/3DES/AES); In which case we don't need to
	   check the 4 byte alignment post padding
			  */
	if (pSA->SAParams.ucCipherAlgo != SECFP_ESP_NULL) {
		usPadLen = (org_iphdr->tot_len + SECFP_ESP_TRAILER_LEN)
				& (pSA->SAParams.ulBlockSize - 1);
		usPadLen = (usPadLen == 0) ? 0 : pSA->SAParams.ulBlockSize
				- usPadLen;
		/* We need to fill the padding field with 010203 etc. */
		/* Instead of implementing a while loop for this based on the pad length, if pad length
			is non-zero, write block size worth of words i.e. either 8/4 or 16/4 starting at tail
		 */
		for (ii = 0; ii < (pSA->SAParams.ulBlockSize >> 2); ii++)
			*(unsigned int *)  &(pTailSkb->data[pTailSkb->len+ii]) = pad_words[ii];
	} else {
		usPadLen = 0;
	}


	/* Forming the ESP packet */
	usLastByte = usPadLen << 8 | SECFP_PROTO_IP;
	*(unsigned short int *)  &(pTailSkb->data[pTailSkb->len + usPadLen])
				= usLastByte;

	pTailSkb->tail = pTailSkb->data + pTailSkb->len + usPadLen
				+ SECFP_ESP_TRAILER_LEN;


	/* skb->data is at the Original IP header */

	/* If UDP Encapsulation is enabled the headers are as follows -
		IP:UDP:ESP:IV:Payload:Trailer:OptionalICV
		else
		IP:ESP:IV:Payload:Trailer:OptionalICV
	 */

	usNatOverHead = 0;
	/* We now set the outer IP header information  */
	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		usNatOverHead = ASF_NAT_UDP_HDR_LEN;
		if (pSA->SAParams.IPsecNatInfo.ulNATt == ASF_IPSEC_IKE_NATtV1) {
			usNatOverHead += 8;
		}
	}
	/* Just copy enough information from inner header */
	/* the rest can be filled in later */
	ASFIPSEC_DEBUG("(Pointer update:)pOuterIpHdr = 0x%x",
					(int)*pOuterIpHdr);
	*pOuterIpHdr = (unsigned int *) (pHeadSkb->data - usNatOverHead - SECFP_IP_HDR_LEN - pSA->ulSecHdrLen);

	iph = (struct iphdr *)  (*pOuterIpHdr);

	/* Total length = Outer IP hdr + Sec hdr len (inclusive of IV) + payload len + padding length + Trailer len */
	iph->tot_len = org_iphdr->tot_len + usNatOverHead +
				(unsigned short)pSA->ulSecHdrLen +
				(unsigned short)pSA->ulSecLenIncrease
				+ usPadLen + SECFP_ESP_TRAILER_LEN ;
	iph->tos = org_iphdr->tos;


	/* Indicate where IV data may be present post encryption */
	if (pSA->bIVDataPresent)
		*(unsigned int *)  &(pHeadSkb->cb[SECFP_IV_DATA_INDEX]) = (unsigned int)pHeadSkb->data;
	else
		*(unsigned int *)  &(pHeadSkb->cb[SECFP_IV_DATA_INDEX])	= 0;

	/* Now get into ESP header construction */
	/* Assign the end pointer */
	ASFIPSEC_PRINT("PrepareOut Packet ulSecHdrLen = %d",
				pSA->ulSecHdrLen);
	pHeadSkb->data -= pSA->ulSecHdrLen;

	ASFIPSEC_DBGL2("After preparing sec header skb->data = 0x%x",
			(int)pHeadSkb->data);

	*(unsigned int *)  &(pHeadSkb->data[0]) = pSA->SAParams.ulSPI;

	ulHiSeqNum = 0;
	/* TBD Sequence number */
	if (pSA->SAParams.bDoAntiReplayCheck) {
		if (pSA->SAParams.bUseExtendedSequenceNumber) {
			ulLoSeqNum = atomic_inc_return(&pSA->ulLoSeqNum);
			if (ulLoSeqNum  == 0) {
				ulHiSeqNum = atomic_inc_return(&pSA->ulHiSeqNum);
				if ((ulHiSeqNum == 0) && ASFIPSecCbFn.pFnSeqNoOverFlow) {
					ASF_IPAddr_t	  DstAddr;
					DstAddr.bIPv4OrIPv6 = 0;
					DstAddr.ipv4addr =  pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
					ASFIPSecCbFn.pFnSeqNoOverFlow(*(unsigned int *)  &(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
									pSA->ulTunnelId, pSA->SAParams.ulSPI,
									pSA->SAParams.ucProtocol, DstAddr);
				}
			}
		} else {
			ulLoSeqNum = atomic_inc_return(&pSA->ulLoSeqNum);
			if ((ulLoSeqNum  == 0) && ASFIPSecCbFn.pFnSeqNoOverFlow) {
				ASF_IPAddr_t	  DstAddr;
				DstAddr.bIPv4OrIPv6 = 0;
				DstAddr.ipv4addr =  pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
				ASFIPSecCbFn.pFnSeqNoOverFlow(*(unsigned int *)  &(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
								pSA->ulTunnelId, pSA->SAParams.ulSPI,
								pSA->SAParams.ucProtocol,
								DstAddr);
			}
		}
	} else {
		pSA->ulLoSeqNum.counter++;
		if (pSA->ulLoSeqNum.counter == 0)
			pSA->ulLoSeqNum.counter = 1;
		ulLoSeqNum = pSA->ulLoSeqNum.counter;
	}
	*(unsigned int *)  &(pHeadSkb->data[4]) = ulLoSeqNum;

	/* Alright sequence number will be either the right one in extended sequence number
		support or it will be set to 0 */

	*(unsigned int *)  &(pTailSkb->tail[0]) = ulHiSeqNum;

	/* Finished handling the SEC Header */
	/* Now prepare the IV Data */
	if (pSA->SAParams.ucCipherAlgo != SECFP_ESP_NULL)
		secfp_GetIVData((unsigned int *)  &pHeadSkb->data[SECFP_ESP_HDR_LEN], pSA->ulIvSizeInWords);


	/* Update skb->len */
	pHeadSkb->len += pSA->ulSecHdrLen /*ulSecHdrLen includes IV */ ;
	pTailSkb->len += usPadLen + SECFP_ESP_TRAILER_LEN;
	pHeadSkb->data_len = org_iphdr->tot_len + pSA->ulSecHdrLen + usPadLen
				+ SECFP_ESP_TRAILER_LEN;

	ASFIPSEC_DBGL2("pHeadSkb->data_len = %d",
		(int)pHeadSkb->data_len);
	ASFIPSEC_DBGL2("HeadSkb: skb->data = 0x%x, skb->len = %d,"\
		"usPadLen =%d, trailer=%d",
		(int)pHeadSkb->data, pHeadSkb->len, usPadLen, SECFP_ESP_TRAILER_LEN);
	ASFIPSEC_DBGL2("TailSkb: skb->data = 0x%x, skb->len = %d,"\
		"usPadLen =%d, trailer=%d",
		(int)pTailSkb->data, pTailSkb->len, usPadLen, SECFP_ESP_TRAILER_LEN);

#ifdef ASFIPSEC_DEBUG_FRAME
	hexdump(skb1->data, 64);
	ASFIPSEC_PRINT("");
#endif
}


/*
 * Function prepares the descriptors based on the encryption and authentication
 * algorithm. The prepared descriptor is submitted to SEC.
 */
void secfp_prepareOutDescriptor(struct sk_buff *skb, void *pData, struct talitos_desc *desc, unsigned int ulOptionIndex)
{
	dma_addr_t ptr;
	unsigned int *src, *tgt;
	unsigned char *pNounceIVCounter;
	outSA_t *pSA = (outSA_t *) (pData);
	int iDword, iDword1;
	unsigned int *ptr1;

	if (!ulOptionIndex) {		/* 1st iteration */
		ASFIPSEC_DBGL2("prepareOutDescriptor: Doing DMA mapping");
		ptr = SECFP_DMA_MAP_SINGLE(skb->data, (skb->len+12 +
			SECFP_APPEND_BUF_LEN_FIELD+SECFP_NOUNCE_IV_LEN),
			DMA_TO_DEVICE);
		ptr1 = (unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		*ptr1 = ptr;
	} else {
		/* Take it from the skb->cb */
		ptr = *(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);

		ASFIPSEC_DBGL2("ptr = 0x%x",  ptr);
	}
	switch (pSA->option[ulOptionIndex]) {
	case SECFP_AUTH:
		{
			desc->hdr = pSA->hdr_Auth_template_0;


			SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);
			SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0);
			SECFP_SET_DESC_PTR(desc->ptr[2],
					   pSA->SAParams.AuthKeyLen,
					   pSA->AuthKeyDmaAddr,
					   0);

			if (pSA->SAParams.bUseExtendedSequenceNumber) {
				/* To be checked */
				SECFP_SET_DESC_PTR(desc->ptr[3],
						   skb->len + SECFP_APPEND_BUF_LEN_FIELD,
						   ptr , 0);
			} else {
				SECFP_SET_DESC_PTR(desc->ptr[3],
						   skb->len,
						   ptr , 0);
			}
			SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0);
			if (!((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBS_MAC)
				 == DESC_HDR_MODE0_AES_XCBS_MAC)) {
				iDword = 5;
				iDword1 = 6;
			} else {
				iDword = 6;
				iDword1 = 5;
			}
			SECFP_SET_DESC_PTR(desc->ptr[iDword],
					   SECFP_ICV_LEN,
					   ptr+skb->len , 0);

			SECFP_SET_DESC_PTR(desc->ptr[iDword1],
					   0, 0, 0);
			print_desc(desc);
			break;
		}
	case SECFP_CIPHER:
		{
			desc->hdr = pSA->desc_hdr_template;

			SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);

			if (((pSA->desc_hdr_template &
				(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
				 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)))
			/* Set up the AES Context field - Need to validate this with soft crypto */
			{
				src = (unsigned int *)  pSA->SAParams.ucNounceIVCounter;
				pNounceIVCounter = skb->data + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12;
				tgt = (unsigned int *)  pNounceIVCounter;

				/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
				is set to 128; not sure why though? */
				*(tgt) = *src;
				*(tgt + 3) = src[3];
				src = (unsigned int *)  (skb->data + SECFP_ESP_HDR_LEN);
				*(tgt+1) = src[0];
				*(tgt+2) = src[1];

				/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
				SECFP_SET_DESC_PTR(desc->ptr[1],
						   SECFP_COUNTER_BLK_LEN,
						   ptr + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12,
						   0);
			} else {
				SECFP_SET_DESC_PTR(desc->ptr[1],
						   pSA->SAParams.ulIvSize,
						   ptr + SECFP_ESP_HDR_LEN,
						   0);
			}

			/* Copy the prepared encryption key */
			SECFP_SET_DESC_PTR(desc->ptr[2],
					   pSA->SAParams.EncKeyLen,
					   pSA->EncKeyDmaAddr,
					   0);

			SECFP_SET_DESC_PTR(desc->ptr[3],
					   skb->len - pSA->ulSecHdrLen,
					   ptr + pSA->ulSecHdrLen,
					   0);


			SECFP_SET_DESC_PTR(desc->ptr[4],
					   skb->len - pSA->ulSecHdrLen,
					   ptr + pSA->ulSecHdrLen,
					   0);

			/* removed 12 for extent */

			SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
			SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
			print_desc(desc);

			break;
		}
	case  SECFP_BOTH:
		{
			desc->hdr = pSA->desc_hdr_template;
			ASFIPSEC_PRINT("Desc->hdr = 0x%x",  desc->hdr);
			/* Set up Auth Key */
			/* Copy the prepared authentication key */
			SECFP_SET_DESC_PTR(desc->ptr[0],
					   pSA->SAParams.AuthKeyLen,
					   pSA->AuthKeyDmaAddr,
					   0);
			ASFIPSEC_DBGL2("AuthkeyLen %d AuthKeyDmaAddr %x\n",
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr);
			ASFIPSEC_DBGL2("ulSecHdrLen = %d Auth Only data :"
				"data ptr=0x%x", pSA->ulSecHdrLen, ptr);
			SECFP_SET_DESC_PTR(desc->ptr[1],
					   pSA->ulSecHdrLen,
					   ptr,
					   0);
			ASFIPSEC_DBGL2("ulSecHdrLen %d ptr %x\n",
				pSA->ulSecHdrLen, ptr);
			ASFIPSEC_DBGL2("IVSize = %d, IVdataptr=0x%x, ",
				pSA->SAParams.ulIvSize, ptr+SECFP_ESP_HDR_LEN);
			SECFP_SET_DESC_PTR(desc->ptr[2],
					   pSA->SAParams.ulIvSize,
					   ptr + SECFP_ESP_HDR_LEN,
					   0);

			/* Copy the prepared encryption key */
			SECFP_SET_DESC_PTR(desc->ptr[3],
					   pSA->SAParams.EncKeyLen,
					   pSA->EncKeyDmaAddr,
					   0);
			ASFIPSEC_DBGL2("EnckeyLen %d EncKeyDmaAddr %x\n",
				pSA->SAParams.EncKeyLen, pSA->EncKeyDmaAddr);

			ASFIPSEC_DBGL2("Input data setup at 0x%x: len = %d",
				ptr + pSA->ulSecHdrLen,
				skb->len - pSA->ulSecHdrLen);

			SECFP_SET_DESC_PTR(desc->ptr[4],
					   skb->len - pSA->ulSecHdrLen,
					   ptr + pSA->ulSecHdrLen,
					   0);

			ASFIPSEC_DBGL2("Output data setup at 0x%x: len = %d",
				ptr + pSA->ulSecHdrLen,
				skb->len - pSA->ulSecHdrLen);

			SECFP_SET_DESC_PTR(desc->ptr[5],
					   skb->len - pSA->ulSecHdrLen,
					   ptr + pSA->ulSecHdrLen,
					   12);
			SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
			print_desc(desc);
			break;
		}
	case SECFP_AESCTR_BOTH:
		{
			desc->hdr = pSA->desc_hdr_template | pSA->hdr_Auth_template_1;
			/* Set up Auth Key */
			/* Copy the prepared authentication key */
			SECFP_SET_DESC_PTR(desc->ptr[0],
					   pSA->SAParams.AuthKeyLen,
					   pSA->AuthKeyDmaAddr,
					   0);

			SECFP_SET_DESC_PTR(desc->ptr[1],
					   pSA->ulSecHdrLen,
					   ptr ,
					   0);

			/* Copy the prepared encryption key */
			SECFP_SET_DESC_PTR(desc->ptr[2],
					   pSA->SAParams.EncKeyLen,
					   pSA->EncKeyDmaAddr,
					   0);


			/* Set up the AES Context field - Need to validate this with soft crypto */

			src = (unsigned int *)  pSA->SAParams.ucNounceIVCounter;
			pNounceIVCounter = skb->data + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12;

			tgt = (unsigned int *)  pNounceIVCounter;

			/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
			is set to 128; not sure why though? */
			*(tgt) = *src;
			*(tgt + 3) = src[3];
			src = (unsigned int *)  (skb->data + SECFP_ESP_HDR_LEN);
			*(tgt+1) = src[0];
			*(tgt+2) = src[1];

			/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
			SECFP_SET_DESC_PTR(desc->ptr[3],
					   SECFP_COUNTER_BLK_LEN,
					   ptr + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12,
					   0);

			SECFP_SET_DESC_PTR(desc->ptr[4],
					   skb->len - pSA->ulSecHdrLen,
					   ptr + pSA->ulSecHdrLen ,
					   0);

			SECFP_SET_DESC_PTR(desc->ptr[5],
					   skb->len - pSA->ulSecHdrLen,
					   ptr + pSA->ulSecHdrLen,
					   0);

			/* Where to put the ICV */
			SECFP_SET_DESC_PTR(desc->ptr[6],
					   12,
					   ptr + skb->len ,
					   0);

			break;
		}
	default:
		ASFIPSEC_WARN("Unknown Option :: Index = %d ",
			 pSA->option[ulOptionIndex]);
		break;

	}
}

void secfp_dump_sg(secfp_sgEntry_t  *pSgEntry)
{
	ASFIPSEC_PRINT("pSgEntry->len = %d, pSgentry->flags = %d,"\
		"pSgEntry->eptr = 0x%x, pSgEntry->ptr = 0x%x",
		 pSgEntry->len, pSgEntry->flags, pSgEntry->eptr, pSgEntry->ptr);
}

void secfp_dump_sg_in_skb(struct sk_buff *skb)
{
	int ii;
	secfp_sgEntry_t *pSgEntry =
		(secfp_sgEntry_t *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX+4]);

	ASFIPSEC_DEBUG("Printing from Cb fields to check consistency");
	for (ii = 0; ii < 3; ii++, pSgEntry++) {
		ASFIPSEC_PRINT("pSgEntry = 0x%x", (unsigned int) pSgEntry);
		secfp_dump_sg(pSgEntry);
	}
}

inline void SECFP_SG_MAP(secfp_sgEntry_t *pSgEntry,
	unsigned int len, u8 flags, u8 eptr, u32 ptr)
{
	pSgEntry->len = cpu_to_be16(len);
	pSgEntry->flags = flags;
	pSgEntry->eptr = eptr;
	pSgEntry->ptr = cpu_to_be32(ptr);
}

dma_addr_t secfp_prepareGatherList(
				  struct sk_buff *skb, struct sk_buff **pTailSkb,
				  unsigned int ulOffsetHeadLen, unsigned int ulExtraTailLen)
{
	/* Use the skb->frag_list->cb[8] onwards for a scatter gather list [3] followed by a link pointer,
	if more fragments are present */
	struct sk_buff *pSgSkb = skb_shinfo(skb)->frag_list; /* where to start for the link table ptrs */
	struct sk_buff *pTempSkb;
	secfp_sgEntry_t *pSgEntry = (secfp_sgEntry_t *)  &(pSgSkb->cb[SECFP_SKB_DATA_DMA_INDEX + 4]);
	secfp_sgEntry_t  *pNextSgEntry, *pFirstSgEntry;
	unsigned int ulNumIteration;


	pFirstSgEntry = pSgEntry;
	*(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) =
			SECFP_DMA_MAP_SINGLE(skb->data + ulOffsetHeadLen,
				(skb->end - skb->data), DMA_TO_DEVICE);

	SECFP_SG_MAP (pSgEntry, (skb->len - ulOffsetHeadLen), 0, 0, (*(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX])));
	secfp_dump_sg(pSgEntry);

	ASFIPSEC_PRINT("pFirstSgEntry =0x%x", (unsigned int) pFirstSgEntry);
	ASFIPSEC_PRINT("pSGEntry->len = %d",  pSgEntry->len);

	for (ulNumIteration = 1, pSgEntry++, pTempSkb = skb_shinfo(skb)->frag_list;
		pTempSkb != NULL; pTempSkb = pTempSkb->next, ulNumIteration++) {

		*(unsigned int *)  &(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX]) =
				SECFP_DMA_MAP_SINGLE(pTempSkb->data,
					pTempSkb->end - pTempSkb->data,
					DMA_TO_DEVICE);

		if (pTempSkb->next == NULL) {
			SECFP_SG_MAP(pSgEntry, (pTempSkb->len + ulExtraTailLen),
					DESC_PTR_LNKTBL_RETURN, 0, *(unsigned int *)  &(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX]));
			secfp_dump_sg(pSgEntry);
			*pTailSkb = pTempSkb;
		} else {
			if (ulNumIteration == 3) {	 /* Need to arrange the next link table */
							 /* Need to allocate a new link table from next buffer to pSgskb */
				ASFIPSEC_PRINT("Setting up Link to Next Link Table ");
				pSgSkb = pSgSkb->next;
				pNextSgEntry = (secfp_sgEntry_t *)  &(pSgSkb->cb[SECFP_SKB_DATA_DMA_INDEX + 4]);
				*(unsigned int *)  &(pSgSkb->cb
						[SECFP_SKB_SG_DMA_INDEX]) =
						SECFP_DMA_MAP_SINGLE(
							pNextSgEntry,
							32, DMA_TO_DEVICE);
				SECFP_SG_MAP(pSgEntry, 0,
						DESC_PTR_LNKTBL_NEXT, 0, *(unsigned int *)  &(pSgSkb->cb[SECFP_SKB_SG_DMA_INDEX]));
				secfp_dump_sg(pSgEntry);
				ulNumIteration = 0;
				pSgEntry = pNextSgEntry;
			} else {
				ASFIPSEC_PRINT("Setting up next entry within same link table");
				SECFP_SG_MAP(pSgEntry, pTempSkb->len,
						0, 0, *(unsigned int *)  &(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX]));
				secfp_dump_sg(pSgEntry);
				pSgEntry++;
			}
		}
	}
	secfp_dump_sg_in_skb(skb_shinfo(skb)->frag_list);
	*(unsigned int *)  &(skb->cb[SECFP_SKB_SG_DMA_INDEX]) =
			SECFP_DMA_MAP_SINGLE(pFirstSgEntry, 32, DMA_TO_DEVICE);
	ASFIPSEC_PRINT("pFirstSgEntry = 0x%x, *(unsigned int *)"
			"  &(skb->cb[SECFP_SKB_SG_DMA_INDEX]) = 0x%x",
		 (unsigned int) pFirstSgEntry,
		 *(unsigned int *)  &(skb->cb[SECFP_SKB_SG_DMA_INDEX]));
	return *(unsigned int *) (&skb->cb[SECFP_SKB_SG_DMA_INDEX]);
}


static inline void secfp_dma_unmap_sglist(struct sk_buff  *skb)
{
	struct sk_buff *pSgSkb = NULL;
	secfp_sgEntry_t *pSgEntry;
	if (skb_shinfo(skb)->frag_list) {
		/* where to start for the link table ptrs */
		pSgSkb = skb_shinfo(skb)->frag_list;
	} else if (skb->prev) {
		pSgSkb = skb->prev;
	}
	if (pSgSkb) {
		pSgEntry = (secfp_sgEntry_t *)  &(pSgSkb->cb
				[SECFP_SKB_DATA_DMA_INDEX + 4]);
		SECFP_UNMAP_SINGLE_DESC((void *) *(unsigned int *)
			&(skb->cb[SECFP_SKB_SG_DMA_INDEX]), 32);
		while (1) {
			if (pSgEntry->flags == DESC_PTR_LNKTBL_RETURN) {
				/* Last one to unmap */
				break;
			}
			if (pSgEntry->flags == DESC_PTR_LNKTBL_NEXT) {
				SECFP_UNMAP_SINGLE_DESC((void *) pSgEntry->ptr,
						32);
				pSgSkb = pSgSkb->next;
				pSgEntry = (secfp_sgEntry_t *)  &(pSgSkb->cb
						[SECFP_SKB_DATA_DMA_INDEX+4]);
			} else
				pSgEntry++;
		}
	}
}

dma_addr_t secfp_prepareScatterList(struct sk_buff *skb,
					unsigned int ulOffsetFromHead, unsigned int ulExtraTailLen)
{
	/* In all cases, we atmost prepare a scatter list for 2 fragments only, the second fragment is
	   in skb->prev */
	struct sk_buff *pSgSkb = skb->prev; /* where to start for the link table ptrs */
	secfp_sgEntry_t *pSgEntry = (secfp_sgEntry_t *)  &(pSgSkb->cb[SECFP_SKB_DATA_DMA_INDEX + 4]);
	secfp_sgEntry_t  *pFirstSgEntry = pSgEntry;

	*(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) =
	SECFP_DMA_MAP_SINGLE((skb->data + ulOffsetFromHead),
		(skb->end - skb->data), DMA_TO_DEVICE);
	SECFP_SG_MAP (pSgEntry, (skb->len - ulOffsetFromHead - (skb->prev->len + ulExtraTailLen)), 0, 0, (*(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX])));
	secfp_dump_sg(pSgEntry);

	pSgEntry++;
	*(unsigned int *)  &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX]) =
	SECFP_DMA_MAP_SINGLE(skb->prev->data,
		(skb->prev->end - skb->prev->data), DMA_TO_DEVICE);
	SECFP_SG_MAP (pSgEntry, (skb->prev->len + ulExtraTailLen),
			DESC_PTR_LNKTBL_RETURN, 0, (*(unsigned int *)  &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX])));
	secfp_dump_sg(pSgEntry);

	secfp_dump_sg_in_skb(skb->prev);

	return *(unsigned int *)  &(skb->cb[SECFP_SKB_SG_DMA_INDEX]) =
				SECFP_DMA_MAP_SINGLE(pFirstSgEntry, 32,
						DMA_TO_DEVICE);
}

void secfp_prepareOutDescriptorWithFrags(struct sk_buff *skb, void *pData,
					 struct talitos_desc *desc, unsigned int ulOptionIndex) {
	dma_addr_t ptr = 0, ptr2 = 0;
	unsigned int *src, *tgt;
	unsigned char *pNounceIVCounter;
	outSA_t *pSA = (outSA_t *) (pData);
	int iDword, iDword1;
	unsigned int ulAppendLen;
	struct sk_buff *pTailSkb;

	if (!ulOptionIndex) {		/* 1st iteration */
		ASFIPSEC_DEBUG("Doing DMA mapping");
		if (!skb_shinfo(skb)->frag_list) {
			ptr = *(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
				= SECFP_DMA_MAP_SINGLE(skb->data, skb->tail -
						skb->head, DMA_TO_DEVICE);
		}
	} else {
		/* Take it from the skb->cb */
		if (skb_shinfo(skb)->frag_list) {
			ptr = *(unsigned int *)  &(skb->cb[SECFP_SKB_SG_DMA_INDEX]);
		} else {
			ptr = *(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
			/*if (skb->prev) {
				ptr2 = *(unsigned int *)  &(skb->cb[SECFP_SKB_SG_DMA_INDEX]);
			} Commented for klocwork warning*/
		}
	}
		ASFIPSEC_PRINT("ptr = 0x%x",  ptr);
		switch (pSA->option[ulOptionIndex]) {
		case SECFP_AUTH:
			{
				desc->hdr = pSA->hdr_Auth_template_0;

				SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);
				SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0);
				SECFP_SET_DESC_PTR(desc->ptr[2],
						   pSA->SAParams.AuthKeyLen,
						   pSA->AuthKeyDmaAddr,
						   0);

				if (pSA->SAParams.bUseExtendedSequenceNumber) {
					ulAppendLen = SECFP_APPEND_BUF_LEN_FIELD;
				} else {
					ulAppendLen = 0;
				}

				if (!((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBS_MAC)
					 == DESC_HDR_MODE0_AES_XCBS_MAC)) {
					iDword = 5;
					iDword1 = 6;
				} else {
					iDword = 6;
					iDword1 = 5;
				}

				if (skb_shinfo(skb)->frag_list) {
					ptr = secfp_prepareGatherList(skb, &pTailSkb, 0, ulAppendLen);
					SECFP_SET_DESC_PTR(desc->ptr[3],
							   skb->data_len + ulAppendLen, ptr, DESC_PTR_LNKTBL_JUMP);
					SECFP_SET_DESC_PTR(desc->ptr[iDword],
							   SECFP_ICV_LEN,
							   *(unsigned int *)  &(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX]) +
							   pTailSkb->len - SECFP_ICV_LEN,
							   0);
				} else {
					SECFP_SET_DESC_PTR(desc->ptr[3],
							   skb->len + ulAppendLen, ptr , 0);
					if (skb->prev) {
						SECFP_SET_DESC_PTR(desc->ptr[iDword],
								   SECFP_ICV_LEN,
								   *(unsigned int *)  &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX]) +
								   skb->prev->len - SECFP_ICV_LEN, 0);
					} else {
						ASFIPSEC_DEBUG("Not prev and Not frag lst: Error : Outdesc");
					}
				}

				SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0)
				SECFP_SET_DESC_PTR(desc->ptr[iDword1],
						   0, 0, 0);
				print_desc(desc);
				break;
			}
		case SECFP_CIPHER:
			{
				desc->hdr = pSA->desc_hdr_template;

				SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);

				if (skb_shinfo(skb)->frag_list) {
					ptr = secfp_prepareGatherList(skb, &pTailSkb, pSA->ulSecHdrLen, 0);

					SECFP_SET_DESC_PTR(desc->ptr[1],
							   pSA->SAParams.ulIvSize,
							   *(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) +
							   + SECFP_ESP_HDR_LEN,
							   0);

					SECFP_SET_DESC_PTR(desc->ptr[3],
							   skb->data_len - pSA->ulSecHdrLen,
							   ptr, DESC_PTR_LNKTBL_JUMP);

					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->data_len - pSA->ulSecHdrLen,
							   ptr, DESC_PTR_LNKTBL_JUMP);
				} else {
					SECFP_SET_DESC_PTR(desc->ptr[1],
							   pSA->SAParams.ulIvSize,
							   ptr + SECFP_ESP_HDR_LEN,
							   0);

					SECFP_SET_DESC_PTR(desc->ptr[3],
							   skb->len - pSA->ulSecHdrLen,
							   ptr + pSA->ulSecHdrLen,
							   0);

					if (skb->prev) {
						pTailSkb = skb->prev;

						ptr2 = secfp_prepareScatterList(skb, pSA->ulSecHdrLen, 0);

						SECFP_SET_DESC_PTR(desc->ptr[4],
								   skb->data_len - pSA->ulSecHdrLen,
								   ptr2, DESC_PTR_LNKTBL_JUMP);
					} else {
						ASFIPSEC_DEBUG("Not prev and Not frag lst: Error : Outdesc");
					}
				}


				if (((pSA->desc_hdr_template &
					(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)))
				/* Set up the AES Context field - Need to validate this with soft crypto */
				{
					src = (unsigned int *)  pSA->SAParams.ucNounceIVCounter;

					pNounceIVCounter = (unsigned char *)
							   (*(unsigned int *)  &(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
								+ pTailSkb->len + (SECFP_APPEND_BUF_LEN_FIELD) + 12);
					tgt = (unsigned int *)  pNounceIVCounter;

					/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
					is set to 128; not sure why though? */
					*(tgt) = *src;
					src = (unsigned int *)  (skb->data + SECFP_ESP_HDR_LEN);
					*(tgt+1) = src[0];
					*(tgt+2) = src[1];

					/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
					SECFP_SET_DESC_PTR(desc->ptr[1],
						SECFP_COUNTER_BLK_LEN,
						(dma_addr_t)pNounceIVCounter,
						0);
				}

				/* Copy the prepared encryption key */
				SECFP_SET_DESC_PTR(desc->ptr[2],
						   pSA->SAParams.EncKeyLen,
						   pSA->EncKeyDmaAddr,
						   0);

				/* removed 12 for extent */
				SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
				SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
				print_desc(desc);

				break;
			}
		case  SECFP_BOTH:
			{
				desc->hdr = pSA->desc_hdr_template;
				ASFIPSEC_DEBUG("Desc->hdr = 0x%x",  desc->hdr);

				/* Set up Auth Key */
				/* Copy the prepared authentication key */
				SECFP_SET_DESC_PTR(desc->ptr[0],
						   pSA->SAParams.AuthKeyLen,
						   pSA->AuthKeyDmaAddr,
						   0);

				ASFIPSEC_DEBUG("ulSecHdrLen = %d Auth Onlydata"\
					": data ptr=0x%x skb->data_len = %d",
					pSA->ulSecHdrLen, ptr, skb->data_len);
				if (skb_shinfo(skb)->frag_list) {
					ASFIPSEC_DEBUG("Fragment list present for scatter/gather ");
					ptr = secfp_prepareGatherList(skb, &pTailSkb, pSA->ulSecHdrLen, 12);
					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->data_len - pSA->ulSecHdrLen,
							   ptr, DESC_PTR_LNKTBL_JUMP);

					SECFP_SET_DESC_PTR(desc->ptr[5],
							   skb->data_len - pSA->ulSecHdrLen,
							   ptr, 12 | DESC_PTR_LNKTBL_JUMP);

				} else {
					ASFIPSEC_DEBUG("Single buffer for gather; scatter for output");
					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->len - pSA->ulSecHdrLen,
							   ptr + pSA->ulSecHdrLen,
							   0);

					if (skb->prev) {
						pTailSkb = skb->prev;
						ptr2 = secfp_prepareScatterList(skb, pSA->ulSecHdrLen, 0);
						SECFP_SET_DESC_PTR(desc->ptr[5],
								   skb->data_len - pSA->ulSecHdrLen,
								   ptr2, 12 | DESC_PTR_LNKTBL_JUMP);
					} else {
						ASFIPSEC_WARN("Not prev and Not frag lst: Error : Outdesc");
					}
				}

				SECFP_SET_DESC_PTR(desc->ptr[1],
						   pSA->ulSecHdrLen,
						   *(unsigned int *)  &skb->cb[SECFP_SKB_DATA_DMA_INDEX],
						   0);
				ASFIPSEC_DBGL2("IVSize = %d, IVdataptr=0x%x, ",
					pSA->SAParams.ulIvSize,
					ptr+SECFP_ESP_HDR_LEN);
				SECFP_SET_DESC_PTR(desc->ptr[2],
						   pSA->SAParams.ulIvSize,
						   *(unsigned int *)  &skb->cb[SECFP_SKB_DATA_DMA_INDEX] + SECFP_ESP_HDR_LEN,
						   0);

				/* Copy the prepared encryption key */
				SECFP_SET_DESC_PTR(desc->ptr[3],
						   pSA->SAParams.EncKeyLen,
						   pSA->EncKeyDmaAddr,
						   0);

				ASFIPSEC_DEBUG("Input data setup at 0x%x:"\
					"len = %d", ptr + pSA->ulSecHdrLen,
					skb->len - pSA->ulSecHdrLen);

				ASFIPSEC_DEBUG("Output data setup at 0x%x:"\
					"len = %d", ptr + pSA->ulSecHdrLen,
					skb->len - pSA->ulSecHdrLen);

				SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
				print_desc(desc);
				break;
			}
		case SECFP_AESCTR_BOTH:
			{
				desc->hdr = pSA->desc_hdr_template | pSA->hdr_Auth_template_1;
				/* Set up Auth Key */
				/* Copy the prepared authentication key */
				SECFP_SET_DESC_PTR(desc->ptr[0],
						   pSA->SAParams.AuthKeyLen,
						   pSA->AuthKeyDmaAddr,
						   0);

				if (skb_shinfo(skb)->frag_list) {
					ptr = secfp_prepareGatherList(skb, &pTailSkb, pSA->ulSecHdrLen, 0);

					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->data_len - pSA->ulSecHdrLen,
							   ptr, DESC_PTR_LNKTBL_JUMP);

					SECFP_SET_DESC_PTR(desc->ptr[5],
							   skb->data_len - pSA->ulSecHdrLen,
							   ptr, DESC_PTR_LNKTBL_JUMP);

					/* Where to put the ICV */
					SECFP_SET_DESC_PTR(desc->ptr[6],
							   12,
							   (*(unsigned int *)  &(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX]) + pTailSkb->len - SECFP_ICV_LEN),
							   0);

				} else {
					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->len - pSA->ulSecHdrLen,
							   ptr + pSA->ulSecHdrLen ,
							   0);

					if (skb->prev) {
						pTailSkb = skb->prev;
						ptr2 = secfp_prepareScatterList(skb, pSA->ulSecHdrLen, 0);
						SECFP_SET_DESC_PTR(desc->ptr[5],
								   skb->data_len - pSA->ulSecHdrLen,
								   ptr2, DESC_PTR_LNKTBL_JUMP);

						/* Where to put the ICV */
						SECFP_SET_DESC_PTR(desc->ptr[6],
								   12,
								   (*(unsigned int *)  &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX]) + skb->prev->len - SECFP_ICV_LEN),
								   0);
					} else {
						ASFIPSEC_WARN("Error : Not frag list and not skb->prev");
					}
				}


				SECFP_SET_DESC_PTR(desc->ptr[1],
						   pSA->ulSecHdrLen,
						   *(unsigned int *)  &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]),
						   0);

				/* Copy the prepared encryption key */
				SECFP_SET_DESC_PTR(desc->ptr[2],
						   pSA->SAParams.EncKeyLen,
						   pSA->EncKeyDmaAddr,
						   0);

				src = (unsigned int *)  pSA->SAParams.ucNounceIVCounter;

				pNounceIVCounter = (unsigned char *)
						   (*(unsigned int *)  &(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX]) + pTailSkb->len + (SECFP_APPEND_BUF_LEN_FIELD) + 12);
				tgt = (unsigned int *)  pNounceIVCounter;

				/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
				is set to 128; not sure why though? */
				*(tgt) = *src;
				src = (unsigned int *)  (skb->data + SECFP_ESP_HDR_LEN);
				*(tgt+1) = src[0];
				*(tgt+2) = src[1];


				/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
				SECFP_SET_DESC_PTR(desc->ptr[3],
					SECFP_COUNTER_BLK_LEN,
					(dma_addr_t)pNounceIVCounter,
					0);

				break;
			}
		default:
			ASFIPSEC_WARN("Unknown Option ");
			break;

	}
}


/*
 * Function finds the right SA for the given packet. Logic
 * already explained in the beginning of the file
 */
static inline outSA_t  *secfp_findOutSA(
					 unsigned int ulVsgId,
					 ASFFFPIpsecInfo_t *pSecInfo,
					 struct sk_buff *skb,
					 unsigned char tos,
					 SPDOutContainer_t **ppContainer,
					 ASF_boolean_t   *pbRevalidate) {
	SPDOutContainer_t *pContainer;
	outSA_t *pSA;
	SPDOutSALinkNode_t *pOutSALinkNode;

	ASFIPSEC_FENTRY;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (unlikely(pSecInfo->outContainerInfo.ulTimeStamp < ulTimeStamp_g)) {
		if ((pSecInfo->outContainerInfo.configIdentity.ulVSGConfigMagicNumber !=
			pulVSGMagicNumber[ulVsgId]) ||
			(pSecInfo->outContainerInfo.configIdentity.ulTunnelConfigMagicNumber !=
			secFP_TunnelIfaces[ulVsgId][pSecInfo->outContainerInfo.ulTunnelId].ulTunnelMagicNumber)) {
			ASFIPSEC_DEBUG("VSG:%d=%d, tunnel:%d=%d",
			pSecInfo->outContainerInfo.configIdentity.ulVSGConfigMagicNumber,
			pulVSGMagicNumber[ulVsgId],
			pSecInfo->outContainerInfo.configIdentity.ulTunnelConfigMagicNumber,
			secFP_TunnelIfaces[ulVsgId][pSecInfo->outContainerInfo.ulTunnelId].ulTunnelMagicNumber);

			*ppContainer = NULL;
			*pbRevalidate = TRUE;
			return NULL;
		}
		pSecInfo->outContainerInfo.ulTimeStamp = ulTimeStamp_g;
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	*ppContainer = pContainer = (SPDOutContainer_t *) ptrIArray_getData(&(secfp_OutDB), pSecInfo->outContainerInfo.ulSPDContainerId);

	ASFIPSEC_DEBUG("Valid Container found pContainer = 0x%x",
			(unsigned int) pContainer);

	/* Check the container magic value */
	if (ptrIArray_getMagicNum(&(secfp_OutDB),
				  pSecInfo->outContainerInfo.ulSPDContainerId) ==
		pSecInfo->outContainerInfo.ulSPDMagicNumber) {

		ASFIPSEC_DEBUG("SA within Container : Container Matched SA=%d ",
			pSecInfo->outSAInfo.ulSAIndex);
		if ((pSecInfo->outSAInfo.ulSAIndex == ulMaxSupportedIPSecSAs_g) ||
			(ptrIArray_getMagicNum(&secFP_OutSATable, pSecInfo->outSAInfo.ulSAIndex)
			!= pSecInfo->outSAInfo.ulSAMagicNumber)) {
			/* Either we don't have the SA or our magic numbers are different */
			if (pContainer->SPDParams.bOnlySaPerDSCP) {
				if (pContainer->SAHolder.ulSAIndex[tos] != ulMaxSupportedIPSecSAs_g) {
					/* We don't have the SA yet, Get it from global table  */
					pSecInfo->outSAInfo.ulSAIndex = pContainer->SAHolder.ulSAIndex[tos];

					ASFIPSEC_DEBUG("Found SA ");
				} else {
					ASFIPSEC_DEBUG("Matching DSCP Based SA"\
						"could not be found");
					return NULL;

				}
			} else {
				/* Handle SA Selector case */
				pOutSALinkNode = secfp_cmpPktSelWithSelSet(pContainer, skb);
				if (!pOutSALinkNode) {
					ASFIPSEC_DEBUG("Matching Sel Set Not SA Not found ");
					ASFIPSEC_DEBUG("Send packet to CP ");
					return NULL;
				}
				ASFIPSEC_DEBUG("Got the SA = %d", pOutSALinkNode->ulSAIndex);
				/* We don't have the SA yet, Get it from global table  */
				pSecInfo->outSAInfo.ulSAIndex = pOutSALinkNode->ulSAIndex;
			}

			/* Now update our magic number from Global table */
			pSecInfo->outSAInfo.ulSAMagicNumber =
			ptrIArray_getMagicNum(&secFP_OutSATable, pSecInfo->outSAInfo.ulSAIndex);

		}

		/* If we reached here, we have the SA in our cache */
		pSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable, pSecInfo->outSAInfo.ulSAIndex);

		ASFIPSEC_FEXIT;
		return pSA;
	} else {
		/* Send packet to control plane : We don't have right SPD pointer */
		return NULL;
	}
}

/*
 * Stub function: V6 hook function
 */
 #define SECFP_MAX_BYTES_TO_LINEARIZE 128
inline int secfp_try_fastPathOutv6(
				  unsigned int *pVSGId,
				  struct sk_buff *skb,
				  unsigned int *pSecInfo) {
	ASFIPSEC_WARN("Stub function: Currently not implemented ");
	return 0;
}

/*
 * Outbound fast path function invoked from the ethernet driver. Passed information
 * includes cached VSGId, skbuffer, cached Outbound SPD container  index/magic
 * Outbound SA/magic. If Outbound SA/magic is not available or does not match
 * the SA lookup happens, and if SA is found based on Selector Set match or DSCP
 * match, the cache variables are updated. If SPD container does not exist, or
 * SA does not exist, packet has to be given to normal path
 * If SA exists, fragmentation options are determined such as red side fragmentation
 * Post that prepareOutPacket() for sec submission is called, Subsequently
 * secfp_talitos_submit()
 * is called for descriptor submission. secfp_talitos_submit() is defined in
 * talitos.c. It allcoates
 * descriptor and calls prepareOutDescriptor() to prepare the descriptor. Post that
 * the descriptor is submitted to SEC. The function continues to finishOutPacket()
 * - i.e. put the outer IP address, update the length, MAC address etc. and makes it
 * ready for transmission. outComplete() is called from talitos.c (flush_channel() as
 * part of talitos_done() finally submits the packet to the ethernet driver for
 * transmission
 * Return values: 1 means packet is absorbed by SEC. 0 means packet is available
 * for caller.
 */
int secfp_try_fastPathOutv4 (
				unsigned int ulVSGId,
				struct sk_buff *skb1, ASFFFPIpsecInfo_t *pSecInfo) {
	outSA_t *pSA ;
	struct iphdr *iph = ip_hdr(skb1);
#ifdef ASFIPSEC_DEBUG_FRAME
	unsigned int nr_frags;
#endif
	unsigned int *pOuterIpHdr;
	struct sk_buff *pNextSkb;
	SPDOutContainer_t *pContainer;
	struct sk_buff *skb = skb1;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	AsfSPDPolicyPPStats_t   *pIPSecPolicyPPStats;
	ASFLogInfo_t AsfLogInfo;
	char  aMsg[ASF_MAX_MESG_LEN + 1];
	ASF_boolean_t	bRevalidate = FALSE;
	struct talitos_desc *desc = NULL;
#ifdef SECFP_SG_SUPPORT
	char bScatterGatherList = SECFP_NO_SCATTER_GATHER;
	unsigned char secout_sg_flag;
#endif
	unsigned short usPadLen = 0;

	rcu_read_lock();

	skb1->pkt_type = PACKET_FASTROUTE;

	pIPSecPPGlobalStats = &(IPSecPPGlobalStats_g[smp_processor_id()]);
	pIPSecPPGlobalStats->ulTotOutRecvPkts++;
	pIPSecPPGlobalStats->ulTotOutRecvPktsSecApply++;

#ifdef ASFIPSEC_DEBUG_FRAME
	ASFIPSEC_PRINT("*****secfp_out: Pkt received skb->len = %d,"\
		"iph->tot_len = %d",  skb1->len, iph->tot_len);
	hexdump(skb->data - 14, skb1->len + 14);
#endif
	ASFIPSEC_FENTRY;
	pSA = secfp_findOutSA(ulVSGId, pSecInfo, skb1, iph->tos,
			&pContainer, &bRevalidate);
	if (pSA) {

		ASFIPSEC_DEBUG("SA Found");
		pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
		pIPSecPolicyPPStats->NumOutBoundInPkts++;
		/* Check if there is enough head room and tail room */

		/* Fragment handling and TTL decrement already done in FW Fast Path */
		/* Need to remove decrement TTL by firewall */
		ip_decrease_ttl(iph);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		usPadLen = (iph->tot_len + SECFP_ESP_TRAILER_LEN)
				& (pSA->SAParams.ulBlockSize - 1);
		usPadLen = (usPadLen == 0) ? 0 : pSA->SAParams.ulBlockSize - usPadLen;
#ifndef SECFP_SG_SUPPORT
		if ((iph->tot_len > (pSA->ulPathMTU - (pSA->ulSecOverHead + usPadLen))) || (skb_shinfo(skb1)->frag_list)) {
			if (((iph->frag_off & IP_DF) && (pSA->SAParams.bRedSideFragment)) ||
				((!pSA->SAParams.bRedSideFragment) && ((pSA->SAParams.handleDf == SECFP_DF_SET) ||
								   ((iph->frag_off & IP_DF) && (pSA->SAParams.handleDf == SECFP_DF_COPY))))) {
				ASFIPSEC_DEBUG("Packet size is > Path MTU and fragment bit set in SA or packet");
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Packet size is > Path MTU and fragment bit set in SA or packet");
				AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID10;
				AsfLogInfo.ulVSGId = ulVSGId;
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.u.IPSecInfo.ulSPDContainerIndex =  pSecInfo->outContainerInfo.ulSPDContainerId;
				asfFillLogInfoOut(&AsfLogInfo, pSA);
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT21]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT21);
				ASFIPSec4SendIcmpErrMsg(skb1->data, ASF_ICMP_DEST_UNREACH, ASF_ICMP_CODE_FRAG_NEEDED, pSA->ulPathMTU, ulVSGId);
				rcu_read_unlock();
				return 0;
			}
			if (skb_shinfo(skb1)->frag_list) {
				if (asfReasmLinearize(&skb1, iph->tot_len, 1400+32, 1100+32)) {
					ASFIPSEC_WARN("asflLinearize failed");
					kfree_skb(skb1);
					rcu_read_unlock();
					return 1; /* DOUBT */
				}

				ASFIPSEC_DEBUG("skb1->len = %d",  skb->len);
				skb_reset_network_header(skb1);
				iph = ip_hdr(skb1);

				skb = skb1;
				ASFIPSEC_DEBUG("skb->len = %d, skb1->len = %d",
					skb->len, skb1->len);
			}

			if (pSA->SAParams.bRedSideFragment) {
				ASFIPSEC_DEBUG("Red side fragmentation is enabled");
				if (unlikely(asfIpv4Fragment(skb1,
					pSA->ulPathMTU - (pSA->ulSecOverHead + usPadLen),
					pSA->ulL2BlobLen + (pSA->ulSecOverHead + usPadLen),
					TRUE, skb1->dev, &skb))) {
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT22]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT22);
					return 1;
				}
			}
		}
#else
		if ((iph->tot_len > (pSA->ulPathMTU - (pSA->ulSecOverHead + usPadLen))) || (skb_shinfo(skb1)->frag_list)) {
			ASFIPSEC_DEBUG("Total Leng is > ulPathMTU or has a frag list:"\
				"tot_len = %d, ulPathMTU = %d, frag_list = %d",
				iph->tot_len, pSA->ulPathMTU,
				skb_shinfo(skb1)->frag_list);
			if (unlikely((iph->tot_len) < (pSA->ulPathMTU - (pSA->ulSecOverHead + usPadLen)))) {
				ASFIPSEC_DEBUG("TotalLength is"\
					" less than path MTU, but frag_list "\
					"present: Calling skb_copy_bits ");

				/* Example : Ingress device MTU is much lesser to Egress device MTU */
				/* So we entered here because of frag_list */
				/* Saves us a  lot if we get all information into single fragment */
				if (skb_copy_bits(skb_shinfo(skb1)->frag_list, 0, skb1->data + skb1->len, iph->tot_len - skb1->len) < 0) {
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT22]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT22);
					ASFIPSEC_DEBUG("Trying to flatten the data failed");
					kfree_skb(skb1);
					return 1;
				}
				skb_shinfo(skb1)->frag_list = NULL;
				skb = skb1;
			} else {
				ASFIPSEC_DEBUG("skb has a fragment list or "\
				"total length + ulSecOverHead exceeds PathMTU ");
				if (((iph->frag_off & IP_DF) && ((pSA->SAParams.bRedSideFragment)) ||
					((!(pSA->SAParams.bRedSideFragment) && ((pSA->SAParams.handleDf == SECFP_DF_SET) ||
					((iph->frag_off & IP_DF) && (pSA->SAParams.handleDf == SECFP_DF_COPY))))))) {
					ASFIPSEC_DEBUG("Packet size is > Path MTU and fragment bit set in SA or packet");
					/* Need to send to normal path */
					snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Packet size is > Path MTU and fragment bit set in SA or packet");
					AsfLogInfo.aMsg = aMsg;
					AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID10;
					asfFillLogInfo(&AsfLogInfo, pSA);
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT21]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT21);
					ASFIPSec4SendIcmpErrMsg(skb1->data, ASF_ICMP_DEST_UNREACH, ASF_ICMP_CODE_FRAG_NEEDED, pSA->ulPathMTU, ulVSGId);
					rcu_read_unlock();
					return 0;
				}

				if (pSA->SAParams.bRedSideFragment) {
					ASFIPSEC_DEBUG("Red side fragmentation is enabled");
						if (unlikely(asfIpv4Fragment(skb1,
							pSA->ulPathMTU - (pSA->ulSecOverHead + usPadLen),
							pSA->ulL2BlobLen + (pSA->ulSecOverHead + usPadLen),
							TRUE, skb1->dev, &skb))) {
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT22]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT22);
						return 1;
						}
				} else{
					ASFIPSEC_DEBUG("bScatterGather Enabling");
					/*Check for  most common two fragment case */
					bScatterGatherList = SECFP_SCATTER_GATHER;
					skb = skb1;
					if (!(skb_shinfo(skb1)->frag_list)) {
						ASFIPSEC_DEBUG("Trying to see if we can fit in two fragment");
						/* In the 2 fragment case, total packet size would include additional ip header length */
						/* Assumption: rest are accounted in ulPathMTU */
						if ((iph->tot_len + pSA->ulSecOverHead) <= (pSA->ulPathMTU * 2) &&
						(pSA->SAParams.ucCipherAlgo != SECFP_ESP_NULL)) { /* Can fit in 2 fragments */
							ASFIPSEC_DEBUG("IP packet fits into 2 fragments");
							ASFIPSEC_DEBUG("Current packet does not have a fragments, but  will be fragmented subsequently ");
							/* Temporary holder for the extra fragment */
							skb1->prev = gfar_new_skb(pSA->odev);
							if (skb1->prev) {
								ASFIPSEC_DEBUG("Allocated skb->prev");
								skb_reserve(skb1->prev, ETH_HLEN + SECFP_IP_HDR_LEN);
								skb1->prev->len = (iph->tot_len + (pSA->ulSecOverHead + usPadLen) - pSA->ulPathMTU);
								skb1->prev->tail = skb1->prev->data + skb1->prev->len;
							}
						} else { /*  Will not fit in 2 fragments */
						ASFIPSEC_DEBUG("Single packet case: Will not fit into 2 fragments");
						bScatterGatherList = SECFP_NO_SCATTER_GATHER;
						} /* Will not fit in 2 fragments or algorithm is ESP_NULL */
					} /* If there is a frag_list, let is be in SCATTER - GATHER Mode */
				} /* handled Non- Red side fragmentation cases */
			} /* Cases where the total length exceeds Path MTU, irrespective of fragments present */
		} /* Handled all cases where there is either a fragment list or length is > Path MTU */
#endif /* SECFP_SG_SUPPORT */
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
#ifdef SECFP_SG_SUPPORT
		secout_sg_flag = SECFP_OUT|bScatterGatherList;
		ASFIPSEC_DEBUG("outV4: bScatterGather = %d", bScatterGatherList);
#endif
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		for (; skb != NULL; skb = pNextSkb)
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		{
			pNextSkb = skb->next;
			skb->next = NULL;
			ASFIPSEC_DEBUG("outv4: skb = 0x%x skb1 = 0x%x, nextSkb = 0x%x",
				(unsigned int) skb, (unsigned int) skb1, (unsigned int) pNextSkb);

			(*pSA->prepareOutPktFnPtr)(skb, pSA, pContainer, &pOuterIpHdr);

			ASFIPSEC_DBGL2("Out Process; pOuterIPHdr set to 0x%x",
				(int)pOuterIpHdr);
			/* Put sufficient data in the skb for futher processing post SEC */
			/*	*(unsigned int *)  &(skb->cb[SECFP_SKB_SG_DMA_INDEX]) = skb->len + 12; */
			*(unsigned int *)  &(skb->cb[SECFP_SPD_CI_INDEX]) = pSecInfo->outContainerInfo.ulSPDContainerId;
			*(unsigned int *)  &(skb->cb[SECFP_VSG_ID_INDEX]) = ulVSGId;
			*(unsigned int *)  &(skb->cb[SECFP_SPD_CI_MAGIC_INDEX]) = pSecInfo->outContainerInfo.ulSPDMagicNumber;
			*(unsigned int *)  &(skb->cb[SECFP_SAD_SAI_INDEX]) = pSecInfo->outSAInfo.ulSAIndex;
			*(unsigned int *)  &(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX]) =  pSecInfo->outSAInfo.ulSAMagicNumber;

			ASFIPSEC_DBGL2("IOut SA Index =%d, Magic No = %d",
				pSecInfo->outContainerInfo.ulSPDContainerId,
				pSecInfo->outSAInfo.ulSAMagicNumber);
			ASFIPSEC_DBGL2("Out SA Index =%d, Magic Number = %d",
				*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_INDEX]),
				*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX]));

			ASFIPSEC_DBGL2("Before secfp_talitos_submit:"
				"skb= 0x%x, skb->data= 0x%x, skb->dev= 0x%x\n",
				(int)skb, (int)skb->data, (int)skb->dev);
#ifdef ASFIPSEC_DEBUG_FRAME
			ASFIPSEC_PRINT("secfp_out: Pkt Pre submission Processing");
			hexdump(skb->data, skb->len);
#endif
			/* Keeping REF_INDEX as 2, one for the h/w
			and one for the core */
			skb->cb[SECFP_REF_INDEX] = 2;
			desc = secfp_desc_alloc();
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef SECFP_SG_SUPPORT
			if ((secout_sg_flag & SECFP_SCATTER_GATHER)
				== SECFP_SCATTER_GATHER)
				secfp_prepareOutDescriptorWithFrags(skb, pSA,
							desc, 0);
			else
#endif
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
				secfp_prepareOutDescriptor(skb, pSA, desc, 0);

			if (secfp_talitos_submit(pdev, desc, secfp_outComplete,
				(void *)skb) == -EAGAIN) {
#ifdef ASFIPSEC_LOG_MSG
				ASFIPSEC_DEBUG("secfp_talitos_submit failed ");
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
					"Cipher Operation Failed-5");
				AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
				AsfLogInfo.u.IPSecInfo.ulSPDContainerIndex =
					pSecInfo->outContainerInfo.ulSPDContainerId;
				AsfLogInfo.ulVSGId = ulVSGId;
				AsfLogInfo.aMsg = aMsg;
				asfFillLogInfoOut(&AsfLogInfo, pSA);
#endif
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);

				skb->data_len = 0;
				kfree_skb(skb);
				secfp_desc_free(desc);
				rcu_read_unlock();
				return 1;
			}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (pSA->option[1] != SECFP_NONE) {
				/* 2nd iteration required ICV */
				skb->cb[SECFP_REF_INDEX]++;
				desc = secfp_desc_alloc();
#ifdef SECFP_SG_SUPPORT
				if ((secout_sg_flag & SECFP_SCATTER_GATHER)
						== SECFP_SCATTER_GATHER)
					secfp_prepareOutDescriptorWithFrags(skb,
						pSA, desc, 1);
				else
#endif
					secfp_prepareOutDescriptor(skb, pSA, desc, 1);

				if (secfp_talitos_submit(pdev, desc,
					secfp_outComplete,
					(void *)skb) == -EAGAIN) {
					ASFIPSEC_WARN("secfp_talitos_submit failed ");
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
					/* We cannot free the skb now, as it is submitted to h/w */
					skb->cb[SECFP_REF_INDEX] -= 2; /* Removed for the core and current submission */
					if (skb->cb[SECFP_REF_INDEX] != 0) {
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
					} else { /* CB already happened, and returned */

						/* So, we can release it */
						skb->data_len = 0;
						kfree_skb(skb);
					}
					secfp_desc_free(desc);
					/* Increment statistics */
					rcu_read_unlock();
					return 1;
				}
			}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
			(*pSA->finishOutPktFnPtr)(skb, pSA, pContainer, pOuterIpHdr, ulVSGId, pSecInfo->outContainerInfo.ulSPDContainerId);
#ifdef ASFIPSEC_DEBUG_FRAME
			ASFIPSEC_PRINT("secfp_out: Pkt Post Processing");
			hexdump(skb->data, skb->len);
			nr_frags = skb_shinfo(skb)->nr_frags;
			ASFIPSEC_PRINT("nf_frags after finish function = %d", nr_frags);
#endif
			skb->cb[SECFP_REF_INDEX]--;
			if (skb->cb[SECFP_REF_INDEX] == 0) {
				/* Some error happened in the c/b. Free the skb */
				ASFIPSEC_DEBUG("O/b Proc Completed REF_CNT == 0, freeing the skb");
				skb->data_len = 0;
				kfree_skb(skb);
				rcu_read_unlock();
				return 1;
			}
		}
		rcu_read_unlock();
		return 1;
	} else if (ASFIPSecCbFn.pFnNoOutSA) {
		ASF_uchar8_t  bSPDContainerPresent;
		ASFBuffer_t Buffer;
		/* Homogenous buffer */
		rcu_read_unlock();
		if (skb_shinfo(skb1)->frag_list) {
			if (asfReasmLinearize(&skb1, iph->tot_len, 1400+32, 1100+32)) {
				ASFIPSEC_DEBUG("asflLinearize failed");
				kfree_skb(skb1);
				return 1;
			}
			skb_reset_network_header(skb1);
		}

		Buffer.nativeBuffer = skb1;
		if (pContainer)
			bSPDContainerPresent = 1;
		else
			bSPDContainerPresent = 0;
			ASFIPSecCbFn.pFnNoOutSA(ulVSGId , NULL, Buffer,
				ASFSkbFree, skb1, bSPDContainerPresent, bRevalidate);
		return 1;
	}
	return 0;
}

static inline void secfp_unmap_descs(struct sk_buff *skb)
{
	struct sk_buff *pTempSkb;

	for (pTempSkb = skb_shinfo(skb)->frag_list; pTempSkb != NULL;
		pTempSkb = pTempSkb->next) {
		SECFP_UNMAP_SINGLE_DESC((void *)*((unsigned int *)
				&(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX])),
				pTempSkb->end - pTempSkb->head);
	}
	secfp_dma_unmap_sglist(skb);
}

/*
 * Called from talitos driver flush_channel() when descriptor is done by SEC. In the
 * two case submission, where two descriptors have to be submitted for same packet,
 * e.g. AES_XCBC with 3DES, the first callback should do nothing. We just decrement
 * the REF_INDEX. If there is an error, we note the action to be taken later
 * Error is noted. If no error IV data is updated and packet submitted to ethernet
 * driver
 */

void secfp_outComplete(struct device *dev, struct talitos_desc *desc,
		void *context, int error)
{
	struct sk_buff *skb = (struct sk_buff *) context;
	struct sk_buff *pOutSkb, *pTempSkb;
	outSA_t *pSA;
	struct iphdr *iph;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	pIPSecPPGlobalStats = &(IPSecPPGlobalStats_g[smp_processor_id()]);
	pIPSecPPGlobalStats->ulTotOutPktsSecAppled++;
	pIPSecPPGlobalStats->ulTotInProcPkts++;
	secfp_desc_free(desc);
	skb->cb[SECFP_REF_INDEX]--;
	if (skb->cb[SECFP_REF_INDEX]) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
		/* Waiting for another iteration to complete */
		if (error)
			skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		return;
	}
	SECFP_UNMAP_SINGLE_DESC((void *)(*(unsigned int *)
			&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])),
			skb->end - skb->head);

	if ((!error) && skb->cb[SECFP_ACTION_INDEX] != SECFP_DROP) {
		skb->data_len = 0; /* No requirement for this field anymore */

		if (skb->prev) {
			/* Put the prev pointer in the frag list and release frag list
				some dirty work
			   */
			skb_shinfo(skb)->frag_list = skb->prev;
			skb->len -= skb->prev->len;
			skb->prev = NULL;
		}

#ifdef ASFIPSEC_DEBUG_FRAME
		ASFIPSEC_DEBUG("OutComplete: Sending packet to gfar: skb = 0x%x, skb->data = 0x%x, skb->dev = 0x%x, skb->len = %d*****",
			 skb, skb->data, skb->dev, skb->len);
		ASFIPSEC_DEBUG("out_complete : Printing SEC Header ");
		hexdump(skb->data, skb->len);
		ASFIPSEC_DEBUG("");
#endif
		if (!skb->cb[SECFP_OUTB_FRAG_REQD]) {
			skb->pkt_type = 6;
			if (asfDevHardXmit(skb->dev, skb) != 0) {
				kfree_skb(skb);
				return;
			}
		} else {
			ASFIPSEC_DEBUG("Need to call fragmentation module ");
			/* Need to do dma unmapping for rest of the fragments */
			if (skb_shinfo(skb)->frag_list) {
				secfp_unmap_descs(skb);
			}

			rcu_read_lock();
			ASFIPSEC_DEBUG("Out SA Index =%d, Magic Number = %d",
				*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]),
				 *(unsigned int *)&(skb->cb[SECFP_OUT_SA_MAGIC_NUM]));
			if (ptrIArray_getMagicNum(&secFP_OutSATable, *(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]))
				 == *(unsigned int *)&(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX])) {

				ASFIPSEC_DEBUG("Magic number matched ");
				pSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable, *(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]));
				if (pSA) {
					ASFIPSEC_DEBUG("Found SA : outCb");
#ifdef ASFIPSEC_DEBUG_FRAME
					ASFIPSEC_DEBUG("OutComplete: Sending packet to gfar: skb = 0x%x, skb->data = 0x%x, skb->dev = 0x%x, skb->len = %d*****",
						skb, skb->data, skb->dev, skb->len);
					ASFIPSEC_DEBUG("out_complete : Printing SEC Header ");
					hexdump(skb->data, skb->len);
					ASFIPSEC_DEBUG("");
#endif
					skb->data += pSA->ulL2BlobLen;
					skb->len -= pSA->ulL2BlobLen;
					if (unlikely(asfIpv4Fragment(skb,
						pSA->odev->mtu,
						pSA->ulL2BlobLen,
						FALSE, pSA->odev, &pOutSkb))) {
						ASFIPSEC_DEBUG("Error in Fragmentation");
						rcu_read_unlock();
						return;
					}

					for (; pOutSkb != NULL; pOutSkb = pTempSkb) {
						pTempSkb = pOutSkb->next;
						pOutSkb->pkt_type = 6;
						iph = ip_hdr(pOutSkb);
						pOutSkb->next = NULL;

						pOutSkb->pkt_type = PACKET_FASTROUTE;
						pOutSkb->data -= pSA->ulL2BlobLen;
						pOutSkb->len += pSA->ulL2BlobLen;

						pOutSkb->dev = pSA->odev;
#ifdef ASFIPSEC_DEBUG_FRAME
						ASFIPSEC_DEBUG("Next skb = 0x%x",  pTempSkb);
						ASFIPSEC_DEBUG("Frag : skb = 0x%x, skb->data = 0x%x, skb->dev = 0x%x, skb->len = %d*****",
							 pOutSkb, pOutSkb->data, pOutSkb->dev, pOutSkb->len);
						hexdump(pOutSkb->data, pOutSkb->len);
						ASFIPSEC_DEBUG("");
#endif

						if (pSA->bVLAN)
							pOutSkb->vlan_tci = pSA->tx_vlan_id;
						else
							pOutSkb->vlan_tci = 0;

						asfCopyWords((unsigned int *)pOutSkb->data,
							(unsigned int *)pSA->l2blob, pSA->ulL2BlobLen);
						if (pSA->bPPPoE) {
							/* PPPoE packet.. Set Payload length in PPPoE header */
							*((short *)&(pOutSkb->data[pSA->ulL2BlobLen-4])) = htons(ntohs(iph->tot_len) + 2);
						}
						ASFIPSEC_DEBUG("skb->network_header = 0x%x, skb->transport_header = 0x%x\r\n",
							  skb_network_header(pOutSkb), skb_transport_header(pOutSkb));


#ifdef ASFIPSEC_DEBUG_FRAME
						ASFIPSEC_DEBUG("skb->network_header = 0x%x, skb->transport_header = 0x%x",
							 skb_network_header(pOutSkb), skb_transport_header(pOutSkb));
						ASFIPSEC_DEBUG("Transmitting  buffer = 0x%x dev->index = %d",  pOutSkb, pOutSkb->dev->ifindex);

						ASFIPSEC_DEBUG("Fragment offset field = 0x%x",   iph->frag_off);
#endif
						if (asfDevHardXmit(pOutSkb->dev, pOutSkb) != 0) {
							ASFIPSEC_WARN("Error in transmit: Should not happen");
							kfree_skb(pOutSkb);
						}
					}
					rcu_read_unlock();
					return;
				} else {
					ASFIPSEC_WARN("Magic number mismatch");
					kfree_skb(skb);
					rcu_read_unlock();
					return;
				}
			} else {
				ASFIPSEC_DEBUG("SA Not found");
				kfree_skb(skb);
				rcu_read_unlock();
				return;
			}
		}
	} else {
		skb->data_len = 0;
		ASFIPSEC_WARN("error = %d DROP PKT ", error);
		kfree_skb(skb);
	}
}


/*
 * This function does sequence number tracking for Anti replay
 * window check. Called post SEC inbound processing. Most the
 * calculated values such as co-ef/remainder etc. are carried
 * over from the calculation done prior to SEC inbound processing
 * for anti-replay window check.  This function just updates the
 * bitmap based on previously calculated values.
 */
void secfp_updateBitMap(inSA_t *pSA, struct sk_buff *skb)
{
	unsigned int usSize = pSA->SAParams.AntiReplayWin >> 5;
	unsigned int ulDiff;
	int   uiCount = 0;
	unsigned int  ucCo_Efficient = 0, ucRemainder = 0;

	ASFIPSEC_DEBUG("updateBitMap: parameters: SeqNum in packet=0x%x,"\
		"Last seen sequence number = 0x%x, AntiReplayWin = 0x%x",
		*(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]),
		pSA->ulLastSeqNum, pSA->SAParams.AntiReplayWin);

	if (!pSA->SAParams.bUseExtendedSequenceNumber) {
		if (*(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]) <= pSA->ulLastSeqNum) {
			ulDiff = pSA->ulLastSeqNum - *(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]);
			if (ulDiff >= pSA->SAParams.AntiReplayWin) {
				ASFIPSEC_DEBUG("Ignoring a corner case condition, where the Seq Number Index has already removed from the bitmap");
				return;
			}
		}
	}

	ASFIPSEC_DEBUG("Bitmap update variables: Index = %d, CO-eff = %d ,"\
		"ucSize = %d, remainder = %d ",
		skb->cb[SECFP_SABITMAP_INFO_INDEX],
		skb->cb[SECFP_SABITMAP_COEF_INDEX], usSize,
		skb->cb[SECFP_SABITMAP_REMAIN_INDEX]);

	switch (skb->cb[SECFP_SABITMAP_INFO_INDEX]) {
	case 1:
		pSA->pWinBitMap[(usSize - 1) - skb->cb[
			SECFP_SABITMAP_COEF_INDEX]] |=
		((u32)1 << skb->cb[SECFP_SABITMAP_REMAIN_INDEX]);
		break;
	case  2:
		IGW_SAD_SET_BIT_IN_WINDOW(pSA, *(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]),
					  usSize, uiCount,
					  ucCo_Efficient, ucRemainder);
		pSA->ulLastSeqNum = *(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]);
		break;
	case 3:
		IGW_SAD_SET_BIT_IN_WINDOW(pSA, *(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]),
					  usSize, uiCount,
					  ucCo_Efficient, ucRemainder);
		pSA->ulHOSeqNum++;
		break;
	default:
		ASFIPSEC_WARN("Error in updating SA Bitmap ");
		break;
	}

	ASFIPSEC_DEBUG("Bitmap update variables: pSA->pWinBitMap = 0x%8x",
		pSA->pWinBitMap[0]);
}

/*
 * Currently stub: Need to fill this with code to check if given packet selectors
 * match with SA selectors
 */
bool secfp_verifySASels(inSA_t *pSA, unsigned char protocol,
			unsigned short int sport,
			unsigned short int dport,
			unsigned int saddr,
			unsigned int daddr) {
	InSelList_t *pList;
	SASel_t *pSel;
	struct selNode_s *pSelNode;
	unsigned char ucMatchSrcSelFlag, ucMatchDstSelFlag;
	int ii;
	bool bMatchFound = FALSE;


	if (pSA->ulSPDSelSetIndexMagicNum == ptrIArray_getMagicNum(&secFP_InSelTable,
								   pSA->ulSPDSelSetIndex)) {
		pList = ptrIArray_getData(&secFP_InSelTable, pSA->ulSPDSelSetIndex);
		if (pList) {
			ucMatchSrcSelFlag = ucMatchDstSelFlag = 0;
			for (pSel = pList->pSrcSel; pSel != NULL; pSel = pSel->pNext) {
				for (ii = 0; ii < pSel->ucNumSelectors; ii++) {
					pSelNode = &(pSel->selNodes[ii]);
					ucMatchSrcSelFlag = 0;
					if (pList->ucSelFlags & SECFP_SA_XPORT_SELECTOR) {
						if (protocol == pSelNode->proto)
							ucMatchSrcSelFlag = SECFP_SA_XPORT_SELECTOR;
						else
							continue;
					}
					if (pList->ucSelFlags & SECFP_SA_SRCPORT_SELECTOR) {
						if ((sport >= pSelNode->prtStart) &&
							(sport <= pSelNode->prtEnd)) {
							ucMatchSrcSelFlag |= SECFP_SA_SRCPORT_SELECTOR;
						} else
							continue;
					}
					if (pList->ucSelFlags & SECFP_SA_SRCIPADDR_SELECTOR) {
						if ((saddr >= pSelNode->ipAddrStart) &&
							(saddr <= pSelNode->ipAddrEnd)) {
							ucMatchSrcSelFlag |= SECFP_SA_SRCIPADDR_SELECTOR;
						} else
							continue;
					}
					bMatchFound = TRUE;
					break;
				}
				if (bMatchFound == TRUE)
					break;
			}
			bMatchFound = FALSE;
			for (pSel = pList->pDestSel; pSel != NULL; pSel = pSel->pNext) {
				for (ii = 0; ii < pSel->ucNumSelectors; ii++) {
					pSelNode = &(pSel->selNodes[ii]);
					ucMatchDstSelFlag = 0;

					if (pList->ucSelFlags & SECFP_SA_XPORT_SELECTOR) {
						if (protocol == pSelNode->proto)
							ucMatchDstSelFlag = SECFP_SA_XPORT_SELECTOR;
						else
							continue;
					}
					if (pList->ucSelFlags & SECFP_SA_DESTPORT_SELECTOR) {
						if ((dport >= pSelNode->prtStart) &&
							(dport <= pSelNode->prtEnd)) {
							ucMatchDstSelFlag |= SECFP_SA_DESTPORT_SELECTOR;
						} else
							continue;
					}
					if (pList->ucSelFlags & SECFP_SA_DESTIPADDR_SELECTOR) {
						if ((daddr >= pSelNode->ipAddrStart) &&
							(daddr <= pSelNode->ipAddrEnd)) {
							ucMatchDstSelFlag |= SECFP_SA_DESTIPADDR_SELECTOR;
						} else
							continue;
					}
					bMatchFound = TRUE;
					break;
				}
				if (bMatchFound == TRUE)
					break;
			}
			if ((ucMatchSrcSelFlag | ucMatchDstSelFlag) == pList->ucSelFlags) {
				return TRUE;
			}
		} else {
			ASFIPSEC_DEBUG("SelList not found in Ptr Array for comparison");
		}
	} else {
		ASFIPSEC_DEBUG("Sel Set (In) Magic number mismatch between SA and pointer array");
	}
	return FALSE;
}



/*
 * This code needs to be filled for Gateway adaptation. i.e. When the remote gateway
 * changes, the gateway address has to be udpated in the the outbound SAs.
 * For this purpose the Out SPD container index is maintained along with the
 * In SA
 */
void secfp_adaptPeerGW(unsigned int ulVSGId, inSA_t *pSA, unsigned int saddr)
{
	outSA_t *pOutSA = NULL;
	SPDOutContainer_t *pOutContainer;
	SPDOutSALinkNode_t *pOutSALinkNode;
	ASF_IPAddr_t	  OldDstAddr;
	ASF_IPAddr_t	  NewDstAddr;
	int ii;

	OldDstAddr.bIPv4OrIPv6 = NewDstAddr.bIPv4OrIPv6 = 0;
	OldDstAddr.ipv4addr =  pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
	NewDstAddr.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.saddr =  saddr;

	if (pSA->ulSPDOutContainerMagicNumber == ptrIArray_getMagicNum(&secfp_OutDB,
									 pSA->ulSPDOutContainerIndex)) {
		pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
									pSA->ulSPDOutContainerIndex));
		if (pOutContainer) {
			if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
				for (ii = 0; ii < SECFP_MAX_DSCP_SA; ii++) {
					pOutSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
										pOutContainer->SAHolder.ulSAIndex[ii]);
					/* NEEDS */
				}
			} else {
				pOutSALinkNode = secfp_findOutSALinkNode(pOutContainer,
							OldDstAddr.ipv4addr,
							pSA->SAParams.ucProtocol
							, pSA->ulOutSPI);
				if (pOutSALinkNode) {
					pOutSA = (outSA_t *)ptrIArray_getData(
										&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
				}
			}
			if (pOutSA && ASFIPSecCbFn.pFnPeerChange) {
				pOutSA->ipHdrInfo.hdrdata.iphv4.daddr = saddr;
				ASFIPSecCbFn.pFnPeerChange(ulVSGId,
							   pSA->SAParams.ulSPI,
							   pSA->ulSPDInContainerIndex,
							   pSA->SAParams.ucProtocol,
							   OldDstAddr, NewDstAddr, 0, 0);
			} else {
				GlobalErrors.ulOutSANotFound++;
				ASFIPSEC_DEBUG("IP Address adaptation: pOutSA not found");
			}
		} else {
			GlobalErrors.ulSPDOutContainerNotFound++;
			ASFIPSEC_DEBUG("SPD Out Container not found for Address adaptation");
		}
	} else {
		ASFIPSEC_DEBUG("Address adaptation: IP Address mismatch");
	}
}


/*
 * This should do a lookup of SA for post IPsec inbound processing and update
 * the error statistics. Currently stub */
void secfp_updateErr(struct sk_buff *skb)
{
	ASFIPSEC_PRINT("Stub function");
}


/*
 * Post inbound processing, in some cases, we need to do ICV check
 * This function does that and updates the packet length
 * For AES-XCBC-HMAC, currently h/w ICV comparison is failing, so
 * doing this through memcmp
 * In the 2 descriptor submission case, appropriate option index has
 * to be updated, so that check is not done again when the 2nd
 * iteration completes
 */
static inline unsigned int secfp_inHandleICVCheck(struct talitos_desc *desc,
						  struct sk_buff *skb) {
	int ii;
	if (skb->cb[SECFP_SA_OPTION_INDEX] == SECFP_BOTH) {
		ASFIPSEC_DEBUG("desc->hdr_lo = 0x%x, desc->hdr = 0x%x",
			desc->hdr_lo, desc->hdr);

		if ((desc->hdr_lo & DESC_HDR_LO_ICCR1_MASK) !=
			DESC_HDR_LO_ICCR1_PASS) {
			ASFIPSEC_WARN("hw cmp: ICV Verification failed");
			return 1;
		} else {
			skb->len -= ICV_LEN;
		}
	} else if (skb->cb[SECFP_SA_OPTION_INDEX] == SECFP_AUTH) {
	/* In the two submission case, only first time around, we need to do the ICV comparison, hence using the REF_INDEX
	to find out first or second time */
		ASFIPSEC_DEBUG("desc->hdr_lo = 0x%x, desc->hdr = 0x%x",
			desc->hdr_lo, desc->hdr);

		/* In the 2 submission case, it will not hit the ICV verification again */
		if (skb->cb[SECFP_REF_INDEX])
			skb->cb[SECFP_SA_OPTION_INDEX] = 0;

		if (desc->hdr_lo & DESC_HDR_LO_ICCR0_MASK) {
			/* If ICV verification was done in h/w */
			if ((desc->hdr_lo & DESC_HDR_LO_ICCR0_MASK) !=
				DESC_HDR_LO_ICCR0_PASS) {
				ASFIPSEC_WARN("hw comparison ICV Verification failed desc->hdr_lo = 0x%x", desc->hdr_lo);
				return 1;
			} else {
				skb->len -= ICV_LEN;
				return 0;
			}
		} else {
			unsigned long int  ulESNLen;
			if (*((unsigned int *)(skb->data + skb->len +  SECFP_ESN_MARKER_POSITION)) == 0xAAAAAAAA) {
				ulESNLen = SECFP_APPEND_BUF_LEN_FIELD;
			} else {
				ulESNLen = 0;
			}

#ifdef ASF_IPSEC_DEBUG
			for (ii = 0; ii < 3; ii++) {
				ASFIPSEC_DEBUG("Computed ICV = 0x%8x, Received ICV =0x%8x",  *(unsigned int *)&(skb->data[skb->len + (ii*4) + ulESNLen]), *(unsigned int *)&skb->data[skb->len - 12 + (ii*4) + ulESNLen]);
			}
#endif

			for (ii = 0; ii < 3; ii++) {
				if (*(unsigned int *)&(skb->data[skb->len + (ii*4) + ulESNLen]) != *(unsigned int *)&(skb->data[skb->len - 12 + (ii*4) + ulESNLen])) {
					break;
				}
			}
			if (ii != 3) {
				ASFIPSEC_WARN("byte comparison ICV Comparison failed");
				return 1;
			}
			skb->len -= ICV_LEN;
			return 0;
		}
	} else if (skb->cb[SECFP_SA_OPTION_INDEX] == SECFP_AESCTR_BOTH) {
	/* SECFP_AESCTR_BOTH */

		ASFIPSEC_DEBUG("desc->hdr_lo = 0x%x",  desc->hdr_lo);
		for (ii = 0; ii < 3; ii++) {
			if (*(unsigned int *)&(skb->data[skb->len + (ii*4)]) != *(unsigned int *)&(skb->data[skb->len - 12 + (ii*4)]))
				break;
		}
		if (ii != 3) {
			ASFIPSEC_WARN("ICV Comparison failed");
			return 1;
		}
		skb->len -= ICV_LEN;
	}
	return 0;
}

/*
  * IPv6 In complete : Currently stub
  */
inline void secfp_inv6Complete(struct talitos_desc *desc, struct sk_buff *skb, int err)
{
	ASFIPSEC_DEBUG("Stub function: need to implement for IPv6 Gateways");
}

/* In complete for v4 gateways */
/* This does ICV verification completion, updates ICV length,
 * compares padding in the case of ESP-non-NULL, verifies
 * IPv4 header as next expected header. It should also
 * inner header checksum verification. Currently stubbed out
 * It updates the sequence number in the sequence number
 * bitmap. If peer gateway adaption is enabled, records changes
 * outbound SAs if any. If SA selector verification is enabled
 * packet selectors are verified with SA selectors.  If packet
 * survives all this, it is given to firewall fast path. If firewall
 * is not able to find the flow, the packet is given to the stack
 * SPI verification does not happen here. Firewall calls
 * checkInPacket ( ) function to do SPI verification. The SPD
 * in container index is cached in firewall flow
 */

#ifdef ASF_IPSEC_DEBUG
unsigned int ulNumIter[NR_CPUS];
#endif

#define SECFP_TRANSPORT_HEADER_LEN 28

static inline int secfp_inCompleteCheckAndTrimPkt(struct sk_buff *pHeadSkb, struct sk_buff * pTailSkb,
						  unsigned int *pTotLen, unsigned char *pNextProto) {
	unsigned int ulPadLen;
	struct iphdr *iph;
	inSA_t *pSA;

#ifdef ASFIPSEC_DEBUG_FRAME
	ASFIPSEC_PRINT("pHeadSkb->data = 0x%x, pHeadSkb->data - 20 - 16 =0x%x,"\
		"pHeadSkb->len = %d",
		pHeadSkb->data, pHeadSkb->data - 20 - 16, *pTotLen);
	hexdump(pHeadSkb->data, ((pHeadSkb->len + 20 + 16 + 20) < 256 ?
		(pHeadSkb->len + 20 + 16 + 20) : 256));
	ASFIPSEC_PRINT("");
#endif

	/* Look at the Next protocol field */
	*pNextProto = pTailSkb->data[pTailSkb->len - 1];
	if ((*pNextProto != SECFP_PROTO_IP) && (*pNextProto != SECFP_PROTO_IPV6)) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT11]);
		iph = (struct iphdr *)*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]);
		rcu_read_lock();

		pSA = secfp_findInv4SA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
					 SECFP_PROTO_ESP,
					 *(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
					 iph->daddr,
					 (unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT11);
			pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();
		ASFIPSEC_PRINT(KERN_INFO "Decrypted Protocol != IPV4");
		return 1;
	}

	/* Look at the padding length and verify length of packet */
	if (*pTotLen  <= 2 + pTailSkb->data[pTailSkb->len - 2]) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT12]);
		iph = (struct iphdr *)*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]);
		rcu_read_lock();
		pSA = secfp_findInv4SA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
					 SECFP_PROTO_ESP,
					 *(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
					 iph->daddr,
					 (unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
			pSA->ulPkts[smp_processor_id()]--;
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT12);
		}
		ASFIPSEC_WARN("Invalid Pad length");
		rcu_read_unlock();
		return 1;
	}
	/* Padding length is is in skb->len-2 */
	ulPadLen = 2 + pTailSkb->data[pTailSkb->len-2];
	pTailSkb->len -= ulPadLen;
	*pTotLen -= ulPadLen;

	return 0;
}

static inline int secfp_inCompleteSAProcess(struct sk_buff **pSkb,
						ASFIPSecOpqueInfo_t *pIPSecOpaque,
						unsigned int *pulCommonInterfaceId,
						unsigned int ulBeforeTrimLen) {
	ASFLogInfo_t AsfLogInfo;
	char aMsg[ASF_MAX_MESG_LEN + 1];
	unsigned short int *ptrhdrOffset;
	unsigned short sport, dport;
	unsigned int ulPathMTU, ii, fragCnt = 0, saddr;
	unsigned char protocol;
	SPDOutSALinkNode_t *pOutSALinkNode;
	SPDOutContainer_t *pOutContainer;
	outSA_t *pOutSA = NULL;
	char	 *pIcmpHdr;
	inSA_t *pSA;
	struct iphdr *iph, *inneriph;
	struct sk_buff *pHeadSkb;

	pHeadSkb = *pSkb;

	ASFIPSEC_DEBUG("inComplete: Doing SA related processing");
	ASFIPSEC_DEBUG("Saved values: ulSPI=%d, ipaddr_ptr=0x%x, ulHashVal=%d",
		*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
		*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]),
		*(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));

	iph = (struct iphdr *)*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]);

	rcu_read_lock();

	pSA = secfp_findInv4SA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
				 SECFP_PROTO_ESP,
				 *(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
				 iph->daddr,
				 (unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));

	if (pSA) {
		pIPSecOpaque->ulInSPDContainerId = pSA->ulSPDInContainerIndex;
		pIPSecOpaque->ulInSPDMagicNumber =  pSA->ulSPDInMagicNum;
		pIPSecOpaque->ucProtocol = pSA->SAParams.ucProtocol;
		pIPSecOpaque->DestAddr.ipv4addr = iph->daddr;
		saddr = iph->saddr;
		if (pSA->SAParams.bAuth) {
			*pulCommonInterfaceId = *((unsigned int *)(pHeadSkb->data + ulBeforeTrimLen + ICV_LEN + SECFP_COMMON_INTERFACE_ID_POSITION));
		} else {
			*pulCommonInterfaceId = *((unsigned int *)(pHeadSkb->data + ulBeforeTrimLen + SECFP_COMMON_INTERFACE_ID_POSITION));
		}

		if (pSA->SAParams.bDoAntiReplayCheck) {
			ASFIPSEC_DEBUG("Doing Anti Replay window check");
			if (pHeadSkb->cb[SECFP_ACTION_INDEX] == 1) { /* drop */
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT19]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT19);
				pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
				pSA->ulPkts[smp_processor_id()]--;
				secfp_updateErr(pHeadSkb);
				rcu_read_unlock();
				return 1;
			} else {
				if (pSA->SAParams.bAuth)
					secfp_updateBitMap(pSA, pHeadSkb);
			}
		}
		inneriph = (struct iphdr *)(pHeadSkb->data);
		if ((inneriph->frag_off) & SECFP_MF_OFFSET_FLAG_NET_ORDER) {
			skb_reset_network_header(pHeadSkb);
			pHeadSkb = asfIpv4Defrag((*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX])),
						 pHeadSkb, NULL, NULL, NULL, &fragCnt);
			if (pHeadSkb == NULL) {
				ASFIPSEC_DEBUG(" ESP Packet absorbed by IP reasembly module");
				rcu_read_unlock();
				return 2; /*Pkt absorbed */
			}
			inneriph = (struct iphdr *)(pHeadSkb->data);
			if (asfReasmLinearize(&pHeadSkb, inneriph->tot_len, 1400+32, 1100+32)) {
				ASFIPSEC_WARN(" skb->linearize failed ");
				kfree_skb(pHeadSkb);
				rcu_read_unlock();
				return 1;
			}
			skb_reset_network_header(pHeadSkb);
			inneriph = (struct iphdr *)(pHeadSkb->data);
			if (unlikely(pHeadSkb->len < ((inneriph->ihl*4) + SECFP_ESP_HDR_LEN))) {
				ASFIPSEC_WARN("ESP header length is invalid len = %d ",   pHeadSkb->len);
				kfree_skb(pHeadSkb);
				rcu_read_unlock();
				return 1;
			}
			*pSkb = pHeadSkb;
		}
		if (pSA->SAParams.bVerifyInPktWithSASelectors) {
			inneriph = (struct iphdr *)(pHeadSkb->data);
			ptrhdrOffset = (unsigned short int *)(&(pHeadSkb->data[(inneriph->ihl*4)]));
			sport = *ptrhdrOffset;
			protocol = inneriph->protocol;
			dport = *(ptrhdrOffset+1);

			if ((secfp_verifySASels(pSA, protocol, sport, dport, inneriph->saddr, inneriph->daddr)) ==  FALSE) {

				if (protocol == ASF_ICMP_PROTO) {

					pIcmpHdr = ((char *)pHeadSkb->data) + (inneriph->ihl*4);
					if ((pIcmpHdr[0] == ASF_ICMP_DEST_UNREACH) ||
						(pIcmpHdr[0] == ASF_ICMP_QUENCH) ||
						(pIcmpHdr[0] == ASF_ICMP_REDIRECT) ||
						(pIcmpHdr[0] == ASF_ICMP_TIME_EXCEED) ||
						(pIcmpHdr[0] == ASF_ICMP_PARAM_PROB)) {
						sport = pIcmpHdr[0];
						dport = pIcmpHdr[1];

						if ((secfp_verifySASels(pSA, protocol, dport, sport, inneriph->daddr, inneriph->saddr)) ==  TRUE) {
							if ((pIcmpHdr[0] == ASF_ICMP_DEST_UNREACH) &&
								(pIcmpHdr[1] == ASF_ICMP_CODE_FRAG_NEEDED)) {
								ulPathMTU =  BUFGET32((unsigned char *)(pIcmpHdr + 4));
								ASFIPSEC_DEBUG("Path MTU = %d",  ulPathMTU);

								if (pSA->ulSPDOutContainerMagicNumber == ptrIArray_getMagicNum(&secfp_OutDB,
																 pSA->ulSPDOutContainerIndex)) {
									pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
																pSA->ulSPDOutContainerIndex));
									if (pOutContainer) {
										if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
											for (ii = 0; ii < SECFP_MAX_DSCP_SA; ii++) {
												pOutSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
																	pOutContainer->SAHolder.ulSAIndex[ii]);
											}
										} else {

	pOutSALinkNode = secfp_findOutSALinkNode(
	pOutContainer, pSA->SAParams.tunnelInfo.addr.iphv4.saddr,
	pSA->SAParams.ucProtocol, pSA->ulOutSPI);
											if (pOutSALinkNode) {
												pOutSA = (outSA_t *)ptrIArray_getData(
																	&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
											}
										}
										if (pOutSA) {

											pOutSA->ulPathMTU = ulPathMTU;
										}
									}
								}
							}
						}
					}
				}

				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT20]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT20);
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "SA Selectos Verification Failed");
				AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID9;
				AsfLogInfo.aMsg = aMsg;
				asfFillLogInfo(&AsfLogInfo, pSA);
				pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
				pSA->ulPkts[smp_processor_id()]--;
				rcu_read_unlock();
				return 1;
			}
		}
		/* Add code for reassembly after SA Verification */
		if (pSA->SAParams.bDoPeerGWIPAddressChangeAdaptation) {
			/* igwIPSec4CheckPeerGW */
			if (pSA->SAParams.tunnelInfo.addr.iphv4.saddr != saddr) {
				ASFIPSEC_DEBUG("Gateway address has changed: need to adapt");
				secfp_adaptPeerGW((*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX])), pSA, saddr);
			}
		}
		rcu_read_unlock();
		return 0;
	} else {
		ASFIPSEC_DEBUG("SA Not found ");
		rcu_read_unlock();
		return 1;
	}
}


static inline void secfp_inCompleteUpdateIpv4Pkt(struct sk_buff *pHeadSkb /*, unsigned char *pOrgEthHdr */)
{
	struct iphdr *iph;
	u8 tos;

	skb_reset_network_header(pHeadSkb);

	iph = ip_hdr(pHeadSkb);

	/* Do header checksum verification */
	if (!ip_compute_csum(iph, (iph->ihl * sizeof(unsigned int))))
		pHeadSkb->ip_summed = CHECKSUM_UNNECESSARY;
	else {
		pHeadSkb->ip_summed = CHECKSUM_NONE;
	}

	/* ECN Handling*/
	if ((pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX]) &&
		(pHeadSkb->cb[SECFP_TOS_INDEX] & SECFP_ECN_ECT_CE) &&
		!(iph->tos & SECFP_ECN_ECT_CE)) {
		tos = iph->tos | SECFP_ECN_ECT_CE;
		ASFIPSEC_DEBUG("doing incremntal checksum here");
		csum_replace4(&iph->check, iph->tos, tos);
		iph->tos = tos;
	}
}

static inline void secfp_inCompletePreparePktForStack(struct sk_buff *pHeadSkb, unsigned char *pOrgEthHdr)
{
	int ii;
	/* Let us copy the orig mac header */
	for (ii = 1; ii < 3; ii++) {
		*(unsigned int *)&pHeadSkb->data[ii*4] = *(unsigned int *)&(pOrgEthHdr[ii*4]);
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	ASFIPSEC_DEBUG("Before eth_type_trans skb->data = %x, skb->len = %d",
		pHeadSkb->data, pHeadSkb->len);
	hexdump(pHeadSkb->data, (pHeadSkb->len < 64 ? pHeadSkb->len : 64));
	ASFIPSEC_DEBUG("");
#endif
	pHeadSkb->protocol = eth_type_trans(pHeadSkb, pHeadSkb->dev);

#ifdef ASFIPSEC_DEBUG_FRAME
	ASFIPSEC_DEBUG("After eth_type_trans skb->protocol = %d, "\
		"skb->pkt_type =%d, skb->len=%d, skb->data = 0x%x",
		pHeadSkb->protocol, pHeadSkb->pkt_type,
		pHeadSkb->len, pHeadSkb->data);
	hexdump(pHeadSkb->data, (pHeadSkb->len < 64 ? pHeadSkb->len : 64));
	ASFIPSEC_DEBUG("");
#endif
}


void secfp_inCompleteWithFrags(struct device *dev,
				struct talitos_desc *desc,
				void *context, int err)
{
	struct sk_buff *skb1 = (struct sk_buff *) context;
	unsigned int ulFragCnt;
	struct sk_buff *pHeadSkb, *pTailSkb, *pTempSkb;
	unsigned int ulTotLen;
	unsigned char ucNextProto;
	unsigned char *pOrgEthHdr;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	struct iphdr *iph;
	inSA_t *pSA;
	char  aMsg[ASF_MAX_MESG_LEN + 1];
	ASFLogInfo_t AsfLogInfo;
	ASFIPSecOpqueInfo_t IPSecOpqaue;
	unsigned int ulCommonInterfaceId, ulBeforeTrimLen;

	pIPSecPPGlobalStats = &(IPSecPPGlobalStats_g[smp_processor_id()]);
	pIPSecPPGlobalStats->ulTotInProcSecPkts++;
	pIPSecPPGlobalStats->ulTotInProcPkts++;

	ASFIPSEC_DEBUG("InComplete: iteration=%d, desc=0x%x, err = %d"
			" refIndex = %d\n",
			++ulNumIter[smp_processor_id()],
			(unsigned int) desc, err, skb1->cb[SECFP_REF_INDEX]);
	ASFIPSEC_FENTRY;
	skb1->cb[SECFP_REF_INDEX]--;
	if (unlikely(err < 0)) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
		iph = (struct iphdr *)*(unsigned int *)&(skb1->cb[SECFP_IPHDR_INDEX]);
		rcu_read_lock();
		pSA = secfp_findInv4SA(*(unsigned int *)&(skb1->cb[SECFP_VSG_ID_INDEX]), SECFP_PROTO_ESP,
					 *(unsigned int *)&(skb1->cb[SECFP_SPI_INDEX]), iph->daddr,
					 (unsigned int *)&(skb1->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			pSA->ulBytes[smp_processor_id()] -= skb1->len;
			pSA->ulPkts[smp_processor_id()]--;
			snprintf((aMsg), ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-1");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID3;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
		}
		rcu_read_unlock();
		if (skb1->cb[SECFP_REF_INDEX]) {
			skb1->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		} else {
			SECFP_UNMAP_SINGLE_DESC((void *)*((unsigned int *)
					&(skb1->cb[SECFP_SKB_DATA_DMA_INDEX])),
					skb1->end - skb1->head);
			skb1->prev = NULL;
			secfp_unmap_descs(skb1);
			secfp_desc_free(desc);
			kfree_skb(skb1);
			return;
		}
	} else {
		if (skb_shinfo(skb1)->frag_list) {
			pHeadSkb = skb1;
			if ((unsigned int)(skb1->prev) == SECFP_IN_GATHER_NO_SCATTER) {	 /* Using this as a hint, this means output buffer is single */
				pTailSkb = skb1;
			} else {
				for (ulFragCnt = 1, pTailSkb = skb_shinfo(skb1)->frag_list; pTailSkb->next != NULL; pTailSkb = pTailSkb->next, ulFragCnt++)
					;
			}
		} else {
			pHeadSkb = pTailSkb  = skb1;
		}


		if (secfp_inHandleICVCheck(desc,  pTailSkb)) {
			/* Failure case */
			iph = (struct iphdr *)*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]);
			rcu_read_lock();
			pSA = secfp_findInv4SA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]), SECFP_PROTO_ESP,
						 *(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]), iph->daddr,
						 (unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
			if (pSA) {
				pSA->ulBytes[smp_processor_id()] -= skb1->len;
				pSA->ulPkts[smp_processor_id()]--;
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "ICV Comparision Failed");
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID8;
				asfFillLogInfo(&AsfLogInfo, pSA);
			}
			rcu_read_unlock();
			if (pHeadSkb->cb[SECFP_REF_INDEX]) {
				pHeadSkb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				secfp_desc_free(desc);
				return;
			}
		}
		secfp_desc_free(desc);
		if (pHeadSkb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
			ASFIPSEC_DEBUG("Due to prior operation failure, skb has to be dropped");
			iph = (struct iphdr *)*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]);
			rcu_read_lock();
			pSA = secfp_findInv4SA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]), SECFP_PROTO_ESP,
						 *(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]), iph->daddr,
						 (unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
			if (pSA) {
				pSA->ulBytes[smp_processor_id()] -= skb1->len;
				pSA->ulPkts[smp_processor_id()]--;
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-2");
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID3;
				asfFillLogInfo(&AsfLogInfo, pSA);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
			}
			rcu_read_unlock();
			kfree_skb(pHeadSkb);
			return;
		}

		/* In the 2nd iteration if pTailSkb len is 0, we can go ahead and release it */
		if ((unsigned int)(skb1->prev) == SECFP_IN_GATHER_NO_SCATTER) {
			/* Hint says, we made 2 buffers into one, so go ahead and eliminate frag_list completely */
			kfree_skb(skb_shinfo(skb1)->frag_list);
			skb_shinfo(skb1)->frag_list = NULL;
			pTailSkb = skb1; /* For any further manipulations in the code */
		} else {
			/* Ok: We had a frag list, but let us say, the last skb had only the ICV, and hence it got
				elimated, time to clean up */
			if (unlikely(pTailSkb->len == 0)) {
				ASFIPSEC_DEBUG("This should not happen :pTailSkb->len = 0");
				pTempSkb = pTailSkb;
				if (pTempSkb == skb_shinfo(pHeadSkb)->frag_list) {
					skb_shinfo(pHeadSkb)->frag_list = NULL;
					pTailSkb = pHeadSkb;
				} else {
					for (pTailSkb = skb_shinfo(pHeadSkb)->frag_list; pTailSkb->next == pTempSkb; pTailSkb = pTailSkb->next)
						;
					pTailSkb->next = NULL;
				}
				kfree_skb(pTempSkb);
			}
		}
		/* We have no requirement for the hint field anymore, let us clean up */
		pHeadSkb->prev = NULL;

		SECFP_UNMAP_SINGLE_DESC((void *)*((unsigned int *)
				&(pHeadSkb->cb[SECFP_SKB_DATA_DMA_INDEX])),
				pHeadSkb->end - pHeadSkb->head);
		secfp_unmap_descs(pHeadSkb);
		ulBeforeTrimLen = pHeadSkb->data_len;
		if (secfp_inCompleteCheckAndTrimPkt(pHeadSkb, pTailSkb, &pHeadSkb->data_len, &ucNextProto)) {
			ASFIPSEC_WARN("Packet check failed");
			kfree_skb(pHeadSkb);
			return;
		}

		if ((skb_shinfo(pHeadSkb)->frag_list) && (pHeadSkb->len < SECFP_TRANSPORT_HEADER_LEN)) {
			if (!asfReasmPullBuf(pHeadSkb, SECFP_TRANSPORT_HEADER_LEN, &ulFragCnt)) {
				ASFIPSEC_WARN("asfReasmPullBuf Failed");
				kfree_skb(pHeadSkb);
				return;
			}
		}

		if (pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX]) {
			if (secfp_inCompleteSAProcess(&pHeadSkb, &IPSecOpqaue, &ulCommonInterfaceId, ulBeforeTrimLen)) {
				ASFIPSEC_WARN("secfp_inCompleteSAProcess: Error ");
				kfree_skb(pHeadSkb);
				return;
			}
			ASFIPSEC_DEBUG("inComplete: Exiting SA related processing");
		}

		ulTotLen = pHeadSkb->data_len;
		pHeadSkb->data_len = 0;

		if (ucNextProto == SECFP_PROTO_IP) {
			pOrgEthHdr = skb_network_header(pHeadSkb)-ETH_HLEN;
			secfp_inCompleteUpdateIpv4Pkt(pHeadSkb);
			/* Packet is ready to go */
			/* Assuming ethernet as the receiving device of original packet */
			if (try_fastroute_fwnat(pHeadSkb, pHeadSkb->dev, ulTotLen) != 1) {
				ASFIPSEC_WARN("try_fastroute_fwnat failed");

				/* Need to give it to the stack */
				ASFIPSEC_DEBUG("pOrgEthHdr = 0x%x:0x%x:0x%x",
					*(unsigned int *)&pOrgEthHdr[0],
					*(unsigned int *)&(pOrgEthHdr[4]),
					*(unsigned int *)&(pOrgEthHdr[8]));
				if (skb_shinfo(pHeadSkb)->frag_list) {
					/* Need to change ETH_HLEN to some cb field carrying L2 header length */
					return;
				} else {
					secfp_inCompletePreparePktForStack(pHeadSkb, pOrgEthHdr);
					if (netif_receive_skb(pHeadSkb) == NET_RX_DROP) {
						ASFIPSEC_WARN("Stack dropped the packet");
					}
				}
				pIPSecPPGlobalStats->ulTotInProcSecPkts++;
			}
		} else {
			ASFIPSEC_DEBUG("Stub function: Need to handle IPv6 ");
			rcu_read_unlock();
			return;
		}
	}
}

inline void secfp_inComplete(struct device *dev, struct talitos_desc *desc,
		void *context, int err)
{
	struct sk_buff *skb = (struct sk_buff *) context;
	unsigned char ucNextProto;
	unsigned int ulTempLen, iRetVal;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	inSA_t *pSA;
	struct iphdr *iph;
	ASFLogInfo_t AsfLogInfo;
	char  aMsg[ASF_MAX_MESG_LEN + 1];
	ASFIPSecOpqueInfo_t  IPSecOpque;
	ASFBuffer_t Buffer;
	unsigned int ulCommonInterfaceId, ulBeforeTrimLen;

	ASFIPSEC_FENTRY;

	pIPSecPPGlobalStats = &(IPSecPPGlobalStats_g[smp_processor_id()]);
	pIPSecPPGlobalStats->ulTotInProcSecPkts++;
	pIPSecPPGlobalStats->ulTotInProcPkts++;
	memset(&IPSecOpque, 0 , sizeof(IPSecOpque));

	ASFIPSEC_DEBUG("InComplete: iteration=%d, desc=0x%x, err = %d"
			"refIndex = %d\n", ++ulNumIter[smp_processor_id()],
			(unsigned int) desc, err, skb->cb[SECFP_REF_INDEX]);

	skb->cb[SECFP_REF_INDEX]--;
	if (err < 0) {
		secfp_desc_free(desc);
		iph = (struct iphdr *)*(unsigned int *)&(skb->cb[SECFP_IPHDR_INDEX]);
		rcu_read_lock();
		pSA = secfp_findInv4SA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
					 SECFP_PROTO_ESP,
					 *(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
					 iph->daddr,
					 (unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
		if (pSA) {
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-3");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID3;
			asfFillLogInfo(&AsfLogInfo, pSA);
			pSA->ulBytes[smp_processor_id()] -= skb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();

		if (skb->cb[SECFP_REF_INDEX]) {
			skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
			return;
		}
		SECFP_UNMAP_SINGLE_DESC((void *) *((unsigned int *)
				&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])),
				skb->end - skb->head);
		skb->data_len = 0;
		skb->next = NULL;
		kfree_skb(skb);
		return;
	} else {
		if (secfp_inHandleICVCheck(desc,  skb)) {
			secfp_desc_free(desc);
			/* Failure case */
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT17]);
			iph = (struct iphdr *)*(unsigned int *)&(skb->cb[SECFP_IPHDR_INDEX]);
			rcu_read_lock();
			pSA = secfp_findInv4SA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
						 SECFP_PROTO_ESP, *(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),  iph->daddr,
						 (unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
			if (pSA) {
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "ICV Comparision Failed");
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID8;
				asfFillLogInfo(&AsfLogInfo, pSA);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT17);
				pSA->ulBytes[smp_processor_id()] -= skb->len;
				pSA->ulPkts[smp_processor_id()]--;
			}
			rcu_read_unlock();
			if (skb->cb[SECFP_REF_INDEX]) {
				skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				return;
			} else {
				SECFP_UNMAP_SINGLE_DESC((void *)
					*((unsigned int *) &(skb->cb
					[SECFP_SKB_DATA_DMA_INDEX])),
					skb->end - skb->head);
				skb->data_len = 0;
				skb->next = NULL;
				kfree_skb(skb);
				return;
			}
		}
		secfp_desc_free(desc);
		if (skb->cb[SECFP_REF_INDEX])
			return;

		SECFP_UNMAP_SINGLE_DESC((void *) *((unsigned int *)
			&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])),
			skb->end - skb->head);
		if (skb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
			iph = (struct iphdr *)*(unsigned int *)&(skb->cb[SECFP_IPHDR_INDEX]);
			rcu_read_lock();
			pSA = secfp_findInv4SA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
						 SECFP_PROTO_ESP, *(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),  iph->daddr,
						 (unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
			if (pSA) {
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-4");
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID3;
				asfFillLogInfo(&AsfLogInfo, pSA);
				pSA->ulBytes[smp_processor_id()] -= skb->len;
				pSA->ulPkts[smp_processor_id()]--;
			}
			rcu_read_unlock();
			ASFIPSEC_DEBUG("Due to prior operation failure, skb has to be dropped");
			skb->data_len = 0;
			skb->next = NULL;
			kfree_skb(skb);
			return;
		}
#ifdef ASFIPSEC_DEBUG_FRAME
		ASFIPSEC_DEBUG("skb->data = 0x%x, skb->data - 20 - 16 =0x%x,"\
			"skb->len = %d",
			skb->data, skb->data - 20 - 16, skb->len);
		hexdump(skb->data, 64);
		ASFIPSEC_DEBUG("");
#endif
		skb->data_len = 0;
		skb->next = NULL;

		/* Look at the Next protocol field */
		ulTempLen = ulBeforeTrimLen = skb->len;
		ulCommonInterfaceId = *((unsigned int *)(skb->data + skb->len + ICV_LEN + SECFP_COMMON_INTERFACE_ID_POSITION));

		if (secfp_inCompleteCheckAndTrimPkt(skb, skb, &ulTempLen, &ucNextProto)) {
			ASFIPSEC_WARN("secfp_incompleteCheckAndTrimPkt failed");
			kfree_skb(skb);
			return;
		}

/*tbd- SM check it	if (skb->cb[SECFP_LOOKUP_SA_INDEX]) */{
			iRetVal =  secfp_inCompleteSAProcess(&skb, &IPSecOpque, &ulCommonInterfaceId, ulBeforeTrimLen);
			if (iRetVal == 1) {
				ASFIPSEC_WARN("secfp_inCompleteSAProcess failed");
				kfree_skb(skb);
				return;
			} else if (iRetVal == 2) {
				ASFIPSEC_DEBUG("Absorbed by frag process");
				return;
			}
			ASFIPSEC_DEBUG("inComplete: Exiting SA related processing");
		}

		/* Packet is ready to go */
		/* Assuming ethernet as the receiving device of original packet */

		if (ucNextProto == SECFP_PROTO_IP) {
			secfp_inCompleteUpdateIpv4Pkt(skb);
#ifdef ASFIPSEC_DEBUG_FRAME
			ASFIPSEC_PRINT("Pkt received skb->len = %d", skb->len);
			hexdump(skb->data, skb->len);
#endif
			/* Homogenous buffer */
			Buffer.nativeBuffer = skb;
			ASFFFPProcessAndSendPkt(
						 *(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
						 ulCommonInterfaceId,
						 Buffer,
						 ASFSkbFree,
						 skb,
						 &IPSecOpque);
		} else {
			ASFIPSEC_DEBUG("Stub function: Need to handle IPv6 ");
			return;
		}
	}
}

/*
  * When we receive fragments (inbound or outbound) we nned
  * to reassembe them, prior to processing
  */
inline void secfp_handleFragments(struct sk_buff *skb)
{

}


/*
  *  This function prepares the In descriptor.
  * Prepares the descriptor based on the SA encryption/authentication
  * algorithms.
  */
void secfp_prepareInDescriptor(struct sk_buff *skb,
					void *pData, struct talitos_desc *desc,
					unsigned int ulIndex)
{
	unsigned int *tgt, *src;
	dma_addr_t addr;
	inSA_t *pSA = (inSA_t *)pData;
	unsigned char *pNounceIVCounter;
	unsigned int *ptr1;
	int len;

	if (desc) {

		if (!ulIndex) {	/* first iteration */
			addr = SECFP_DMA_MAP_SINGLE(skb->data,
					(skb->len + 12 +
					 SECFP_APPEND_BUF_LEN_FIELD +
					SECFP_NOUNCE_IV_LEN), DMA_TO_DEVICE);
			ptr1 = (unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
			*ptr1 = addr;
			ASFIPSEC_DEBUG("ulIndex = %d: addr =  0x%x",
				ulIndex, addr);
		} else {
			/* Take information from the cb field */
			addr = *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
			ASFIPSEC_DEBUG("ulIndex= %d: addr =  0x%x",
				ulIndex, addr);
		}

		switch (pSA->option[ulIndex]) {
		case SECFP_AUTH:
			{
				desc->hdr = pSA->hdr_Auth_template_0;

				ASFIPSEC_DEBUG("skb->len = %d, addr = 0x%x, "\
					"SECFP_ICV_LEN =%d",
					skb->len, addr, SECFP_ICV_LEN);

				SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0)
				SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0)
				SECFP_SET_DESC_PTR(desc->ptr[2],
						pSA->SAParams.AuthKeyLen,
					pSA->AuthKeyDmaAddr, 0)
				if (pSA->SAParams.bUseExtendedSequenceNumber) {
					len = skb->len + SECFP_APPEND_BUF_LEN_FIELD;
				} else {
					len = skb->len;
				}
				/* Setting up data */
				SECFP_SET_DESC_PTR(desc->ptr[3], len - 12, addr, 0)

				/* Setting up ICV Check : Only when AES_XCBC_MAC is not programmed */
				if (pSA->SAParams.ucAuthAlgo != SECFP_HMAC_AES_XCBC_MAC) {
					SECFP_SET_DESC_PTR(desc->ptr[4], SECFP_ICV_LEN, addr + len - SECFP_ICV_LEN, 0)
					SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
				} else {
					SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0)
					SECFP_SET_DESC_PTR(desc->ptr[6], SECFP_ICV_LEN, addr + len, 0);
#ifdef ASF_IPSEC_DEBUG
				{
					int ii;
					for (ii = 0; ii < 3; ii++)
						ASFIPSEC_DEBUG("Offset ii=%d  0x%8x",  ii, *(unsigned int *)&(skb->data[skb->len + ii*4]));
				}
#endif
				}
				SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
				print_desc(desc);
				break;
			}
		case SECFP_CIPHER:
			{
				desc->hdr = pSA->desc_hdr_template;

				if ((pSA->desc_hdr_template &
					(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)) {
					/* Set up the AES Context field - Need to validate this with soft crypto */

					src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
#if 0
					pNounceIVCounter = (unsigned char *)
							   (*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) + skb->len
								+(SECFP_APPEND_BUF_LEN_FIELD * 2) + 12);
#else
					pNounceIVCounter = skb->data + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12;
#endif
					tgt = (unsigned int *)pNounceIVCounter;

					/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
						is set to 128; not sure why though? */
					*(tgt) = *src;
					*(tgt+3) = src[3];
					src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
					*(tgt+1) = src[0];
					*(tgt+2) = src[1];

					SECFP_SET_DESC_PTR(desc->ptr[1], SECFP_COUNTER_BLK_LEN,
							   addr + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12, 0)
				} else {
					SECFP_SET_DESC_PTR(desc->ptr[1], pSA->SAParams.ulIvSize, addr + SECFP_ESP_HDR_LEN, 0)
				}

				SECFP_SET_DESC_PTR(desc->ptr[2],
						pSA->SAParams.EncKeyLen,
						pSA->EncKeyDmaAddr, 0)

				if ((ulIndex) && (skb->cb[SECFP_REF_INDEX] == 3)) {
					/* We have queued the packet and c/b has not yet triggered */
					/* if 2nd iteration is encryption, then we need to reduce the length by ICV Length */
					SECFP_SET_DESC_PTR(desc->ptr[3],
							   skb->len - pSA->ulSecHdrLen - 12,
							   addr + pSA->ulSecHdrLen,
							   0)

					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->len - pSA->ulSecHdrLen - 12,
							   addr + pSA->ulSecHdrLen,
							   0)
				} else {
					/* In the 2 descriptor case, callback has triggered, so we need not to
					   reduce by the ICV length
					*/
					SECFP_SET_DESC_PTR(desc->ptr[3],
							   skb->len - pSA->ulSecHdrLen,
							   addr + pSA->ulSecHdrLen,
							   0);
					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->len - pSA->ulSecHdrLen,
							   addr + pSA->ulSecHdrLen,
							   0);
				}
				/* Set the descriptors 5 and 6 and 6 to 0 */
				SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0)
				SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0)
				print_desc(desc);
				break;
			}
		case SECFP_BOTH:
			{
				desc->hdr = pSA->desc_hdr_template;

				SECFP_SET_DESC_PTR(desc->ptr[0],
						pSA->SAParams.AuthKeyLen,
						pSA->AuthKeyDmaAddr, 0)
				SECFP_SET_DESC_PTR(desc->ptr[1], pSA->ulSecHdrLen, addr, 0)
				SECFP_SET_DESC_PTR(desc->ptr[2], pSA->SAParams.ulIvSize, addr+SECFP_ESP_HDR_LEN, 0)
				SECFP_SET_DESC_PTR(desc->ptr[3],
						pSA->SAParams.EncKeyLen,
						pSA->EncKeyDmaAddr, 0)

				SECFP_SET_DESC_PTR(desc->ptr[4],
						   skb->len - pSA->ulSecHdrLen - 12,
						   addr + pSA->ulSecHdrLen,
						   12);

				SECFP_SET_DESC_PTR(desc->ptr[5],
						   skb->len - pSA->ulSecHdrLen - 12,
						   addr + pSA->ulSecHdrLen,
						   0);

				SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
			}
			break;
		case SECFP_AESCTR_BOTH:
			{
				desc->hdr = pSA->desc_hdr_template |
						pSA->hdr_Auth_template_1 ;

				SECFP_SET_DESC_PTR(desc->ptr[0],
						   pSA->SAParams.AuthKeyLen,
						   pSA->AuthKeyDmaAddr,
						   0);

				SECFP_SET_DESC_PTR(desc->ptr[1],
						   pSA->ulSecHdrLen,
						   addr,
						   0);

				SECFP_SET_DESC_PTR(desc->ptr[2],
						   pSA->SAParams.EncKeyLen,
						   pSA->EncKeyDmaAddr,
						   0);

				/* Set up the AES Context field - Need to validate this with soft crypto */

				src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
#if 0
				pNounceIVCounter = (unsigned char *)
						   (*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) + skb->len
							+(SECFP_APPEND_BUF_LEN_FIELD * 2));
#else
				pNounceIVCounter = skb->data + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12;
#endif
				tgt = (unsigned int *)pNounceIVCounter;

				/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
					is set to 128; not sure why though? */
				*(tgt) = *src;
				*(tgt + 3) = src[3];
				src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
				*(tgt+1) = src[0];
				*(tgt+2) = src[1];

				/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
				SECFP_SET_DESC_PTR(desc->ptr[3], SECFP_COUNTER_BLK_LEN,
						   addr + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12, 0)

				SECFP_SET_DESC_PTR(desc->ptr[4],
						   (skb->len - pSA->ulSecHdrLen - 12),
						   (addr + pSA->ulSecHdrLen),
						   0);

				SECFP_SET_DESC_PTR(desc->ptr[5],
						   (skb->len - pSA->ulSecHdrLen - 12),
						   (addr + pSA->ulSecHdrLen),
						   0);

				/* Not sure about this
							talitosDescriptor->bRecvICV = T_TRUE;


							memcpy(desc->aRecvICV, (skb->tail - 12), 12);
				  */
				/*	Having extra length in the buffer to hold the calculated ICV value */

				/* Looks like in this case, ICV is calculated and supplied always  */
				SECFP_SET_DESC_PTR(desc->ptr[6],
						   12,
						   addr + skb->len,
						   0);
			}
			break;
		default:
			ASFIPSEC_DEBUG("SECFP: Not supported");
			SECFP_UNMAP_SINGLE_DESC((void *)addr,  (skb->len + 12 +
				SECFP_APPEND_BUF_LEN_FIELD +
				SECFP_NOUNCE_IV_LEN));
			break;
		}

		/* Correcting this: Only for the first time , ICV check, this option needs to be recorded */
		if (ulIndex == 0)
			skb->cb[SECFP_SA_OPTION_INDEX] = pSA->option[ulIndex];

	}
	return;
}

void secfp_prepareInDescriptorWithFrags(struct sk_buff *skb,
				 void *pData, struct talitos_desc *desc,
				 unsigned int ulIndex)
{
	unsigned int *tgt, *src;
	dma_addr_t addr;
	inSA_t *pSA = (inSA_t *)pData;
	unsigned char *pNounceIVCounter;
	unsigned int *ptr1;
	int len;
	struct sk_buff *pTailSkb;
	unsigned int ulOffsetIcvLen;

	if (desc) {
		if (!ulIndex) {	/* first iteration */
			if (!skb_shinfo(skb)->frag_list) {
				addr = *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
					 = SECFP_DMA_MAP_SINGLE(skb->data,
							 skb->tail - skb->head,
						 DMA_TO_DEVICE);
			} else {
				addr = SECFP_DMA_MAP_SINGLE(skb->data,
						skb->tail - skb->head,
						DMA_TO_DEVICE);
				ptr1 = (unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
				*ptr1 = addr;
			}
			ASFIPSEC_DEBUG("ulIndex = %d: addr =  0x%x",
				ulIndex, addr);
		} else {
			/* Take information from the cb field */
			addr = *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
			ASFIPSEC_DEBUG("ulIndex= %d: addr =  0x%x",
				ulIndex, addr);
		}

			switch (pSA->option[ulIndex]) {
			case SECFP_AUTH:
				{
					desc->hdr = pSA->hdr_Auth_template_0;

					ASFIPSEC_DEBUG("skb->len = %d, addr = "\
						"0x%x, SECFP_ICV_LEN =%d",
						skb->len, addr, SECFP_ICV_LEN);
					SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0)
					SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0)
					SECFP_SET_DESC_PTR(desc->ptr[2],
						pSA->SAParams.AuthKeyLen,
						pSA->AuthKeyDmaAddr, 0)

					if (pSA->SAParams.bUseExtendedSequenceNumber) {
						len = SECFP_APPEND_BUF_LEN_FIELD;
					} else {
						len = 0;
					}

					addr = secfp_prepareGatherList(skb, &pTailSkb, 0, (12+len));
					/* Setting up data */
					SECFP_SET_DESC_PTR(desc->ptr[3], skb->data_len - 12, addr, DESC_PTR_LNKTBL_JUMP);


					/* Setting up ICV Check : Only when AES_XCBC_MAC is not programmed */
					if (pSA->SAParams.ucAuthAlgo != SECFP_HMAC_AES_XCBC_MAC) {
						SECFP_SET_DESC_PTR(desc->ptr[4],
								   SECFP_ICV_LEN,
								   (*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])+len - SECFP_ICV_LEN), 0)

						SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
					} else {
						SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0)

						SECFP_SET_DESC_PTR(desc->ptr[6],
								   SECFP_ICV_LEN,
								   (*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])+len - SECFP_ICV_LEN), 0)

#ifdef ASF_IPSEC_DEBUG
						{
						int ii;
						for (ii = 0; ii < 3; ii++)
							ASFIPSEC_DEBUG("Offset ii=%d  0x%8x",
							  ii, *(unsigned int *)&(skb->data[skb->len + ii*4]));
						}
#endif
					}
					SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
					print_desc(desc);
					break;
				}
			case SECFP_CIPHER:
				{
					desc->hdr = pSA->desc_hdr_template;

					addr = secfp_prepareGatherList(skb, &pTailSkb, pSA->ulSecHdrLen, 0);

					if ((pSA->desc_hdr_template &
						(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
						 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)) {
						/* Set up the AES Context field - Need to validate this with soft crypto */

						src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
						/* To be verified
						tgt  = *(unsigned int *)desc->ucNounceIVCounter;
						*/
						pNounceIVCounter = (unsigned char *)(*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
											+ pTailSkb->len + (SECFP_APPEND_BUF_LEN_FIELD * 2) + 12);

						tgt = (unsigned int *)pNounceIVCounter;

						/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
							is set to 128; not sure why though? */
						*(tgt) = *src;
						src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
						*(tgt+1) = src[0];
						*(tgt+2) = src[1];

						/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
						SECFP_SET_DESC_PTR(desc->ptr[1],
							SECFP_COUNTER_BLK_LEN,
						(dma_addr_t)pNounceIVCounter,
						0);
					} else {
						SECFP_SET_DESC_PTR(desc->ptr[1], pSA->SAParams.ulIvSize,
								   (*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])+SECFP_ESP_HDR_LEN), 0)
					}

					SECFP_SET_DESC_PTR(desc->ptr[2],
							pSA->SAParams.EncKeyLen,
							pSA->EncKeyDmaAddr, 0)

					if ((ulIndex) && (skb->cb[SECFP_REF_INDEX] == 3)) {
						/* We have queued the packet and c/b has not yet triggered */
						/* if 2nd iteration is encryption, then we need to reduce the length by ICV Length */
						ulOffsetIcvLen = 12;
					} else {
						/* In the 2 descriptor case, callback has triggered, so we need not to
						   reduce by the ICV length
						*/
						ulOffsetIcvLen = 0;
					}

					SECFP_SET_DESC_PTR(desc->ptr[3],
							   skb->data_len - pSA->ulSecHdrLen-ulOffsetIcvLen,
							   addr,
							   DESC_PTR_LNKTBL_JUMP)

					if ((unsigned int)skb->prev == SECFP_IN_GATHER_NO_SCATTER) {
						SECFP_SET_DESC_PTR(desc->ptr[4],
								   skb->data_len - pSA->ulSecHdrLen-ulOffsetIcvLen,
								   addr + pSA->ulSecHdrLen,
								   0)
					} else { /* skb->prev = SECFP_IN_GATHER_SCATTER */
						SECFP_SET_DESC_PTR(desc->ptr[4],
								   skb->data_len - pSA->ulSecHdrLen-ulOffsetIcvLen,
								   addr,
								   DESC_PTR_LNKTBL_JUMP)
					}
					/* Set the descriptors 5 and 6 and 6 to 0 */
					SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0)
					SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0)
					print_desc(desc);
					break;
				}
			case SECFP_BOTH:
				{
					desc->hdr = pSA->desc_hdr_template;

					addr = secfp_prepareGatherList(skb, &pTailSkb, pSA->ulSecHdrLen, 12);

					SECFP_SET_DESC_PTR(desc->ptr[0],
						pSA->SAParams.AuthKeyLen,
						pSA->AuthKeyDmaAddr, 0)
					SECFP_SET_DESC_PTR(desc->ptr[1], pSA->ulSecHdrLen,
							   *(unsigned int *)(&skb->cb[SECFP_SKB_DATA_DMA_INDEX]), 0)
					SECFP_SET_DESC_PTR(desc->ptr[2], pSA->SAParams.ulIvSize,
							   *(unsigned int *)(&skb->cb[SECFP_SKB_DATA_DMA_INDEX])+SECFP_ESP_HDR_LEN, 0)
					SECFP_SET_DESC_PTR(desc->ptr[3],
							pSA->SAParams.EncKeyLen,
							pSA->EncKeyDmaAddr, 0)

					SECFP_SET_DESC_PTR(desc->ptr[4],
							   skb->data_len - pSA->ulSecHdrLen - 12,
							   addr ,
							   (12 | DESC_PTR_LNKTBL_JUMP))

					if (skb->prev == SECFP_IN_GATHER_SCATTER) {
						SECFP_SET_DESC_PTR(desc->ptr[5],
								   skb->data_len - pSA->ulSecHdrLen - 12,
								   addr ,
								   DESC_PTR_LNKTBL_JUMP);
					} else {
						SECFP_SET_DESC_PTR(desc->ptr[5],
								   skb->data_len - pSA->ulSecHdrLen - 12,
								   *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) + pSA->ulSecHdrLen,
								   0);
					}

					SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
				}
				break;
			case SECFP_AESCTR_BOTH:
				{
					desc->hdr = pSA->desc_hdr_template |
							pSA->hdr_Auth_template_1 ;

					addr = secfp_prepareGatherList(skb, &pTailSkb, pSA->ulSecHdrLen, 12);

					SECFP_SET_DESC_PTR(desc->ptr[0],
						pSA->SAParams.AuthKeyLen,
						pSA->AuthKeyDmaAddr,
						0);

					SECFP_SET_DESC_PTR(desc->ptr[1],
							   pSA->ulSecHdrLen,
							   *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]),
							   0);

					SECFP_SET_DESC_PTR(desc->ptr[2],
						pSA->SAParams.EncKeyLen,
						pSA->EncKeyDmaAddr,
						0);

					/* Set up the AES Context field - Need to validate this with soft crypto */

					src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
					/* To be verified
					tgt  = *(unsigned int *)desc->ucNounceIVCounter;
					*/
					pNounceIVCounter = (unsigned char *)
							   (*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
								+ pTailSkb->len + (SECFP_APPEND_BUF_LEN_FIELD * 2) + 12);

					tgt = (unsigned int *)pNounceIVCounter;

					/* Copying 2 integers of IV, Assumes that the first 4 bytes of Nounce is valid and the 16th byte
						is set to 128; not sure why though? */
					*(tgt) = *src;
					src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
					*(tgt+1) = src[0];
					*(tgt+2) = src[1];

					/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
					SECFP_SET_DESC_PTR(desc->ptr[3],
							SECFP_COUNTER_BLK_LEN,
						(dma_addr_t)pNounceIVCounter,
						0);

					SECFP_SET_DESC_PTR(desc->ptr[4],
							   (skb->data_len - pSA->ulSecHdrLen - 12),
							   (addr),
							   DESC_PTR_LNKTBL_JUMP);

					if (skb->prev == SECFP_IN_GATHER_SCATTER) {
						SECFP_SET_DESC_PTR(desc->ptr[5],
								   (skb->data_len - pSA->ulSecHdrLen - 12),
								   (addr),
								   DESC_PTR_LNKTBL_JUMP);

						/* Not sure about this
				talitosDescriptor->bRecvICV = T_TRUE;

				memcpy(desc->aRecvICV, (skb->tail - 12), 12);
				 */
						/*	Having extra length in the buffer to hold the calculated ICV value */

						/* Looks like in this case, ICV is calculated and supplied always  */

						SECFP_SET_DESC_PTR(desc->ptr[6],
								   12,
								   *(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX]) + pTailSkb->len,
								   0);
					} else {
						/* In Gather, Out No scatter */
						SECFP_SET_DESC_PTR(desc->ptr[5],
								   (skb->data_len - pSA->ulSecHdrLen - 12),
								   (*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
									+ pSA->ulSecHdrLen),
								   0)

						/* Not sure about this
					talitosDescriptor->bRecvICV = T_TRUE;

					memcpy(desc->aRecvICV, (skb->tail - 12), 12);
					 */
						/*	Having extra length in the buffer to hold the calculated ICV value */

						/* Looks like in this case, ICV is calculated and supplied always  */

						SECFP_SET_DESC_PTR(desc->ptr[6],
								   12,
								   *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) + skb->data_len,
								   0);
					}

				}
				break;
			default:
				ASFIPSEC_WARN("SECFP: Not supported");
				SECFP_UNMAP_SINGLE_DESC((void *) addr,
						(skb->len + 12 +
						 SECFP_APPEND_BUF_LEN_FIELD +
						 SECFP_NOUNCE_IV_LEN));
				break;
		}

		/* Correcting this: Only for the first time , ICV check, this option needs to be recorded */
		if (ulIndex == 0)
			skb->cb[SECFP_SA_OPTION_INDEX] = pSA->option[ulIndex];

	}
	return;
}



/*
 * This function finds out the Extended sequence number to be appended to the
 * end of the packet when ICV calculation. This value is passed back in *pData
 */
static inline void secfp_appendESN(inSA_t *pSA, unsigned int ulSeqNum,
				   unsigned int *ulLBoundSeqNum, unsigned int *pData)
{
	int uiCount = pSA->ulLastSeqNum - pSA->SAParams.AntiReplayWin + 1;
	unsigned int ulHOSeqNum;

	if (uiCount < 0) {
		uiCount = (-uiCount);
		*ulLBoundSeqNum = (~uiCount) + 1;
	} else {
		*ulLBoundSeqNum = uiCount;
	}
	if (pSA->ulLastSeqNum >= (unsigned int)(pSA->SAParams.AntiReplayWin -
				1)) {
		if (ulSeqNum >= (pSA->ulLastSeqNum - pSA->SAParams.AntiReplayWin
					+ 1))
			ulHOSeqNum = pSA->ulHOSeqNum;
		else
			ulHOSeqNum = pSA->ulHOSeqNum + 1;
	} else {
		if (ulSeqNum >= *ulLBoundSeqNum)
			ulHOSeqNum = pSA->ulHOSeqNum - 1;
		else
			ulHOSeqNum = pSA->ulHOSeqNum;
	}
	(*(unsigned int *)(pData)) = ulHOSeqNum;
}


/* When an inbound packet arrives, first it is checked to see if it
 * is a replay packet. This routine does the replay check
 */
static inline void secfp_checkSeqNum(inSA_t *pSA,
					u32 ulSeqNum, u32 ulLowerBoundSeqNum, struct sk_buff *skb)
{
	unsigned int usSize = 0;
	unsigned int uiDiff;
	unsigned int usCo_Efficient = 0, usRemainder = 0;
	ASFLogInfo_t AsfLogInfo;
	char  aMsg[ASF_MAX_MESG_LEN + 1];

	skb->cb[SECFP_SABITMAP_INFO_INDEX] = 0;
	/* if sequence number is 0 drop the packet and increment stats */
	if (ulSeqNum == 0) {
		ASFIPSEC_DEBUG("Invalid sequence number");
		snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Invalid sequence number");
		AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID4;
		AsfLogInfo.aMsg = aMsg;
		asfFillLogInfo(&AsfLogInfo, pSA);
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT14]);
		ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT14);
		/* Increment stats */
		skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
		return;
	}
	if (!pSA->SAParams.bUseExtendedSequenceNumber) {
		if (ulSeqNum <= pSA->ulLastSeqNum) {
			uiDiff = pSA->ulLastSeqNum - ulSeqNum;
			if (uiDiff >= pSA->SAParams.AntiReplayWin) {
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
				AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID5;
				ASFIPSEC_WARN("Anti-replay window check failed");
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
					"Anti-replay window check failed #1");
				AsfLogInfo.aMsg = aMsg;
				asfFillLogInfo(&AsfLogInfo, pSA);
				/* Update SA Statistics */
				skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
				return;
			}
			usSize = pSA->SAParams.AntiReplayWin >> 5;
			usCo_Efficient  = uiDiff >> 5; /* or uiDiff / 32 */
			usRemainder	= uiDiff & 31; /* or uiDiff % 32 */
			if ((pSA->pWinBitMap[(usSize - 1) - usCo_Efficient]) &
				((unsigned int)1 << usRemainder)) {
				ASFIPSEC_WARN("Replay packet");
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet");
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID6;
				asfFillLogInfo(&AsfLogInfo, pSA);
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
				skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				return;
			} else {	/* Have it ready for Post SEC update */
				skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
				skb->cb[SECFP_SABITMAP_COEF_INDEX] =
					usCo_Efficient;
				skb->cb[SECFP_SABITMAP_REMAIN_INDEX] =
					usRemainder;
			}
			return;
		} else {
			skb->cb[SECFP_SABITMAP_INFO_INDEX] = 2;	/* available */
			*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]) = ulSeqNum - pSA->ulLastSeqNum;
			ASFIPSEC_DEBUG("Sequence Number check: ulLastSeqNum = %d, ulSeqNum = %d",  pSA->ulLastSeqNum, ulSeqNum);
		}
		return;
	} else {
		if (pSA->ulLastSeqNum >= pSA->SAParams.AntiReplayWin - 1) {
			/*
			window size			ulLastSeqNum
			<-----------><----------------------->
			*/
			if (ulSeqNum >= (pSA->ulLastSeqNum  -
					pSA->SAParams.AntiReplayWin + 1)) {
				/* sequence number is more than lower bound */
				if (ulSeqNum <= pSA->ulLastSeqNum) {
					/* sequence number is lesser than
					 * last seen highest sequence number */
					uiDiff = pSA->ulLastSeqNum - ulSeqNum;
					if (uiDiff > pSA->SAParams.
							AntiReplayWin) {
						ASFIPSEC_WARN("Anti-replay window check failed#2");
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Anti-replay window check failed #2");
						AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID5;
						AsfLogInfo.aMsg = aMsg;
						asfFillLogInfo(&AsfLogInfo, pSA);
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
						/* Update SA Statistics */
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
						return;
					}
					usSize = pSA->SAParams.AntiReplayWin
							>> 5;
					usCo_Efficient  = uiDiff >> 5;
					usRemainder	= uiDiff & 31;
					if ((pSA->pWinBitMap[(usSize - 1) -
						usCo_Efficient]) &
						((unsigned int)1 <<
						 usRemainder)) {
						ASFIPSEC_DEBUG("Replay packeti#2");
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet");
						AsfLogInfo.aMsg = aMsg;
						asfFillLogInfo(&AsfLogInfo, pSA);
						AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID6;
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
						/* Update SA Statistics */
						return;
					} else {
						/* Have it ready for Post SEC update */
						skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
						skb->cb[
						SECFP_SABITMAP_COEF_INDEX] =
							usCo_Efficient;
						skb->cb[
						SECFP_SABITMAP_REMAIN_INDEX] =
							usRemainder;
					}
				}
				/* else of this is a good condition - nothing to check */
				else {	/* Update the information */
					skb->cb[SECFP_SABITMAP_INFO_INDEX] = 2;	/* available */
					*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]) = ulSeqNum - pSA->ulLastSeqNum;
				}
			} /* else of this seems to be bad case, but not handled */
			else {
				skb->cb[SECFP_SABITMAP_INFO_INDEX] = 3;	/* available, update higher order sequence number also */
				skb->cb[SECFP_SABITMAP_INFO_INDEX] =  ulSeqNum + (SECFP_MAX_32BIT_VALUE - pSA->ulLastSeqNum);
			}
			return;
		} else {
			/*
			window								  window
			<-------><----------------------><---->
			*/
			if (ulSeqNum >= ulLowerBoundSeqNum) {
				/* sequence number is in the right hand side window */
				uiDiff =  pSA->ulLastSeqNum + (SECFP_MAX_32BIT_VALUE - ulSeqNum);
				if (uiDiff >= pSA->SAParams.AntiReplayWin) {
					ASFIPSEC_WARN("Anti-replay window check failed#3");
					AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID5;
					/* Update SA Statistics */
					snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
					"Anti-replay window check failed #3");
					AsfLogInfo.aMsg = aMsg;
					asfFillLogInfo(&AsfLogInfo, pSA);
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
					return;
				}
				usSize = pSA->SAParams.AntiReplayWin >> 5;
				usCo_Efficient  = uiDiff >> 5;
				usRemainder	= uiDiff & 31;
				if ((pSA->pWinBitMap[(usSize - 1) -
							usCo_Efficient]) &
					((unsigned int)1 << usRemainder)) {
					ASFIPSEC_DEBUG("Replay packet#3");
					snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet");
					AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID6;
					AsfLogInfo.aMsg = aMsg;
					asfFillLogInfo(&AsfLogInfo, pSA);
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
					/* Update SA Statistics */
					return;
				} else {
					/* Have it ready for Post SEC update */
					skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
					skb->cb[SECFP_SABITMAP_COEF_INDEX] =
							usCo_Efficient;
					skb->cb[SECFP_SABITMAP_REMAIN_INDEX] =
							usRemainder;
				}
				return;
			} else {	 /* sequence number is in the left hand side window */
				if (ulSeqNum <= pSA->ulLastSeqNum) {
					uiDiff = pSA->ulLastSeqNum - ulSeqNum;
					if (uiDiff >= pSA->SAParams.
							AntiReplayWin) {
						ASFIPSEC_WARN("Anti-replay window check failed#4");
						/* Update SA Statistics */
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Anti-replay window check failed #4");
						AsfLogInfo.aMsg = aMsg;
						AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID5;
						asfFillLogInfo(&AsfLogInfo, pSA);
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
					}
					usSize = pSA->SAParams.AntiReplayWin
							>> 5;
					usCo_Efficient  = uiDiff >> 5;
					usRemainder	= uiDiff & 31;
					if ((pSA->pWinBitMap[(usSize - 1) -
						usCo_Efficient]) &
						((unsigned int)1 <<
						 usRemainder)) {
						ASFIPSEC_DEBUG("Replay packet#4");
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet");
						AsfLogInfo.aMsg = aMsg;
						AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID6;
						asfFillLogInfo(&AsfLogInfo, pSA);
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
						/* Update SA Statistics */
						return;
					} else {
						/* Have it ready for Post SEC update */
						skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
						skb->cb[
						SECFP_SABITMAP_COEF_INDEX] =
							usCo_Efficient;
						skb->cb[
						SECFP_SABITMAP_REMAIN_INDEX] =
							usRemainder;
					}
					return;
				} else {
					skb->cb[SECFP_SABITMAP_INFO_INDEX] = 2;	/* available */
					*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]) = ulSeqNum - pSA->ulLastSeqNum;
				}
				return;
			}
		}
	}
}



/* Checks for SPI based matching entry */

inSA_t *ASF_findInv4SA(unsigned int ulVSGId,
		unsigned char ucProto,
		unsigned long int ulSPI, unsigned int daddr, unsigned int *pHashVal)
{
	return secfp_findInv4SA(ulVSGId, ucProto, ulSPI, daddr, pHashVal);
}

static inline inSA_t *secfp_findInv4SA(unsigned int ulVSGId,
		unsigned char ucProto,
		unsigned long int ulSPI, unsigned int daddr, unsigned int *pHashVal)
{
	inSA_t *pSA = NULL;

	if (*pHashVal == usMaxInSAHashTaleSize_g) {
		*pHashVal = secfp_compute_hash(ulSPI);
	}

	ASFIPSEC_DEBUG("findInv4SA hashVal = %d, ulSPI=0x%x, daddr=%x ",
			*pHashVal, (unsigned int) ulSPI, daddr);
	ASFIPSEC_DEBUG("ucProto = %d",  ucProto);

	for (pSA = secFP_SPIHashTable[*pHashVal].pHeadSA;
		pSA != NULL; pSA = pSA->pNext) {
		if ((ulSPI == pSA->SAParams.ulSPI)
			&& (ucProto == pSA->SAParams.ucProtocol)
			&& (daddr == pSA->SAParams.tunnelInfo.addr.iphv4.daddr)
			&& (ulVSGId == pSA->ulVSGId))
			break;
	}
	return pSA;
}

/*
 * return values = 0, pkt consumed
			   = 1, send packet up to stack
 */
/* Inbound IPv6 packet handling
  * Currently stub
  */
inline int secfp_try_fastPathInv6(struct sk_buff *skb, bool bCheckLen)
{
	ASFIPSEC_DEBUG("Stub function: Need to be implemented ");
	return 0;

}


int secfp_process_udp_encapsulator(struct sk_buff *skb, unsigned int ulVSGId)
{
	struct udphdr *uh;
	char *pData;
	char ucNatT, ucSkipLen;
	unsigned short usIPHdrLen;
	char aIpHeader[ASF_IPLEN + ASF_IP_MAXOPT];

	uh =  (struct udphdr *) skb_transport_header(skb);
	usIPHdrLen = ip_hdr(skb)->ihl * 4;

	if (uh->len < (SECFP_MAX_UDP_HDR_LEN + 8))
		return ASF_NON_NATT_PACKET;

	if ((uh->source  == ASF_IPSEC_IKE_SERVER_PORT) ||
		(uh->dest  == ASF_IPSEC_IKE_SERVER_PORT)) {
		ucNatT = ASF_IPSEC_IKE_NATtV1;
	} else if ((uh->source == ASF_IPSEC_IKE_NAT_FLOAT_PORT) ||
		   (uh->dest  == ASF_IPSEC_IKE_NAT_FLOAT_PORT)) {
		ucNatT = ASF_IPSEC_IKE_NATtV2;
	} else {
		/****
		 * If UDP packet's port values not matching with IKE port values
		 * then it is plain packet and returning with T_SUCCESS
		 ****/
		return ASF_NON_NATT_PACKET;
	}
	pData = skb->data + usIPHdrLen + SECFP_MAX_UDP_HDR_LEN;
	if (ucNatT == ASF_IPSEC_IKE_NATtV1) {
		/****
		 * If UDP packet contains the matching IKE port values
		 * then check with the NON-IKE marker header
		 * If not matched , then return T_SUCCESS
		 ****/
		if (memcmp(pData, aNonIkeMarker_g, ASF_IPSEC_MAX_NON_IKE_MARKER_LEN) != 0) {
			return ASF_NON_NATT_PACKET;
		}
		/* Copy the IP header */
		memcpy(aIpHeader, skb->data, usIPHdrLen);
		ucSkipLen = ASF_IPSEC_MAX_NON_IKE_MARKER_LEN + SECFP_MAX_UDP_HDR_LEN;
	} else {
		if (memcmp(pData, aNonESPMarker_g, ASF_IPSEC_MAX_NON_ESP_MARKER_LEN) == 0) {
			return ASF_NON_NATT_PACKET;
		}
		memcpy(aIpHeader, skb->data, usIPHdrLen);
		ucSkipLen = SECFP_MAX_UDP_HDR_LEN;
	}
	skb->data = skb->data + ucSkipLen;
	memcpy(skb->data, aIpHeader, usIPHdrLen);
	skb->len  -=  ucSkipLen;
	skb_reset_network_header(skb);
	ip_hdr(skb)->tot_len -= ucSkipLen;
	ip_hdr(skb)->protocol = SECFP_PROTO_ESP;
	return ASF_NATT_PACKET;
}

/* Inbound IPv4 fast path handling
  * Finds the SA based on the SPI value. If SA is found,
  * it reassembles the packet if required
  * It does anti-replay check. It appends ESN to the packet
  * if enabled.
  * Then submits the packet to SEC. If multiple submissions are
  * required, multiple descriptors are prepared and submitted
  * Any packet length adjustment such as removal of outer
  * IP header/SEC header happens.
  * Post sec submission and completion, inComplete() is called by
  * flush_channel() in talitos.c file. inComplete does the remaining
  * processing such as ICV verification, updating the Sequence
  * number bitmap,  doing remote gateway adaptation,  SA selector
  * set verification etc. before giving packet to the firewall for
  * further procession
  * Sufficient information is passed through the skb->cb fields
  * to handle post SEC In processing.
  */
int secfp_try_fastPathInv4(struct sk_buff *skb1,
			   ASF_boolean_t bCheckLen, unsigned int ulVSGId,
			   ASF_uint32_t  ulCommonInterfaceId)
{
	unsigned int ulSPI, ulSeqNum;
	inSA_t *pSA;
	struct iphdr *iph = ip_hdr(skb1);
	unsigned int ulLowerBoundSeqNum;
	unsigned int ulHashVal = usMaxInSAHashTaleSize_g;
	unsigned int *pCurICVLoc = 0, *pNewICVLoc = 0;
	unsigned int fragCnt = 0;
	int kk;
	struct sk_buff *pHeadSkb, *pTailSkb;
#ifdef SECFP_SG_SUPPORT
	struct sk_buff *pTailPrevSkb = 0;
	int ii;
	unsigned int ulICVInPrevFrag;
	unsigned char *pCurICVLocBytePtrInPrevFrag, *pCurICVLocBytePtr, *pNewICVLocBytePtr;
#endif
	bool bScatterGather;
	unsigned int len;
	char  aMsg[ASF_MAX_MESG_LEN + 1];
	ASFLogInfo_t AsfLogInfo;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	AsfSPDPolicyPPStats_t   *pIPSecPolicyPPStats;
	unsigned char secin_sg_flag;
	struct talitos_desc *desc;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (ulVSGId == ulMaxVSGs_g) {
		ulVSGId = secfp_findVSG(skb1);
		if (ulVSGId == ulMaxVSGs_g) {
			ASFIPSEC_DEBUG("Stub: Need to send packet up for VSG determination");
			ASFIPSEC_DEBUG("Need to call registered callback function ");
			kfree_skb(skb1);
			return 1; /* Send it up to Stack */
		}
	}

	if (iph->protocol == IPPROTO_UDP) {
		if (secfp_process_udp_encapsulator(skb1, ulVSGId) == ASF_NON_NATT_PACKET) {
			return ASF_NON_NATT_PACKET;
		}
		iph = ip_hdr(skb1);
	}
	if (((ip_hdr(skb1)->frag_off) & SECFP_MF_OFFSET_FLAG_NET_ORDER)) {
		skb_reset_network_header(skb1);
		skb1 = asfIpv4Defrag(ulVSGId, skb1, NULL, NULL, NULL, &fragCnt);
		if (skb1 == NULL) {
			ASFIPSEC_DEBUG("ESP Packet absorbed by IP reasembly module");
			return 1; /*Pkt absorbed */
		}
		fragCnt = 0;
		iph = ip_hdr(skb1);
		if (asfReasmLinearize(&skb1, iph->tot_len, 1400+32, 1100+32)) {
			ASFIPSEC_WARN("skb->linearize failed ");
			kfree_skb(skb1);
			return 1;
		}
		skb_reset_network_header(skb1);
		iph = ip_hdr(skb1);
#ifdef ASFIPSEC_DEBUG_FRAME
		ASFIPSEC_PRINT("Pkt received skb->len = %d", skb1->len);
		hexdump(skb1->data - 14, skb1->len);
#endif

		if (unlikely(skb1->len < ((iph->ihl*4) + SECFP_ESP_HDR_LEN))) {
			ASFIPSEC_WARN("ESP header length is invalid len = %d ",   skb1->len);
			kfree_skb(skb1);
			return 1;
		}
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	rcu_read_lock();
	SECFP_EXTRACT_PKTINFO(skb1, iph, (iph->ihl*4), ulSPI, ulSeqNum)
	pSA = secfp_findInv4SA(ulVSGId, iph->protocol, ulSPI, iph->daddr, &ulHashVal);
	if (pSA) {

		ASFIPSEC_DEBUG(" pSA Found coreId=%d",  smp_processor_id());
		pIPSecPPGlobalStats = &(IPSecPPGlobalStats_g[smp_processor_id()]);
		pIPSecPPGlobalStats->ulTotInRecvPkts++;
		pIPSecPPGlobalStats->ulTotInRecvSecPkts++;

		pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
		pIPSecPolicyPPStats->NumInBoundInPkts++;

		if (pSA->bSendPktToNormalPath) {
			/* This can happen if SPDs have been modified and there is
					a requirement for revalidation
				  */
			ASFIPSEC_DEBUG("Need to send packet up to Normal Path");
			rcu_read_unlock();
			return 0;
		}
		/* SA Found */
		/* Need to have this check when packets are coming in from upper layer, but not from the driver interface */
		if (!fragCnt) {
			pHeadSkb = pTailSkb = skb1;
			len  = skb1->len;
			bScatterGather = SECFP_NO_SCATTER_GATHER;
		} else {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef SECFP_SG_SUPPORT
			pHeadSkb = skb1;
			for (pTailPrevSkb = skb1, pTailSkb = skb_shinfo(skb1)->frag_list;
				pTailSkb->next != NULL; pTailPrevSkb = pTailSkb, pTailSkb = pTailSkb->next)
				;
			bScatterGather = SECFP_SCATTER_GATHER;

			if (likely((iph->tot_len - (pSA->ulSecHdrLen + (iph->ihl*4))) < SECFP_PRESUMED_INTERFACE_MTU)
				&& (pSA->SAParams.ucCipherAlgo != SECFP_ESP_NULL)) {
				/* We go into gather input , single output */
				/* use skb->prev for indicating single output */
				skb1->prev = SECFP_IN_GATHER_NO_SCATTER;
			} else {
				/* We go into gather input, scatter output */
				skb1->prev = SECFP_IN_GATHER_SCATTER;
			}
			len = iph->tot_len;
#else
			ASFIPSEC_DEBUG("Before Linearize : skb1->dev = 0x%x\n",
				(unsigned int) skb1->dev);
			if (asfReasmLinearize(&skb1, iph->tot_len, 1400+32, 1100+32)) {
				ASFIPSEC_WARN("skb->linearize failed");
				kfree_skb(skb1);
				rcu_read_unlock();
				return 1;
			}
			skb_reset_network_header(skb1);
			iph = ip_hdr(skb1);
			len = iph->tot_len;
			pHeadSkb = pTailSkb = skb1;
			bScatterGather = SECFP_NO_SCATTER_GATHER;

			ASFIPSEC_DEBUG("skb1->len = %d",  skb1->len);
			ASFIPSEC_DEBUG("skb->dev = 0x%x",
					(unsigned int) skb1->dev);
#endif
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		}
		secin_sg_flag = SECFP_IN|bScatterGather;

		if ((bCheckLen) && ((pTailSkb->end - pTailSkb->tail)
					< pSA->ulReqTailRoom)) {
			ASFIPSEC_WARN("Received Skb does not have"
					" enough tail room to continue");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				 "SPI = 0x%x, Seq. No = %u ::"
				 " No free Buffer is available."
				 " Returning with out processing"
				 " the packet", ulSPI, ulSeqNum);
			AsfLogInfo.ulMsgId =   ASF_IPSEC_LOG_MSG_ID1;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT9]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT9);
		}

		if (iph->tot_len < pSA->validIpPktLen) {
			ASFIPSEC_DEBUG("Invalid ESP or AH Pkt");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				 "SPI = 0x%x, Seq. No = %u"
				 " Packet length is less than the"
				 " sum of IP Header, ESP Header length,"
				 " IV  and ICV length", ulSPI, ulSeqNum);
			AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID2;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT10]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT10);
			kfree_skb(pHeadSkb);
			rcu_read_unlock();
			return 1;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (pSA->bDPDAlive == 1) {
			ASF_IPAddr_t   DestAddr;
			DestAddr.bIPv4OrIPv6 = 0;
			DestAddr.ipv4addr = iph->daddr;
			ASFIPSEC_DEBUG("Calling DPD alive callback VSG=%u, Tunnel=%u, address=%x, Container=%u, SPI=%x",  \
					 ulVSGId, pSA->ulTunnelId, iph->daddr, pSA->ulSPDInContainerIndex, ulSPI);
			if (ASFIPSecCbFn.pFnDPDAlive)
				ASFIPSecCbFn.pFnDPDAlive(ulVSGId, pSA->ulTunnelId, ulSPI, iph->protocol,
						 DestAddr, pSA->ulSPDInContainerIndex);
			pSA->bDPDAlive = 0;
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		ulLowerBoundSeqNum = 0;
		if (pSA->SAParams.bAuth) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef SECFP_SG_SUPPORT
			if (unlikely(pTailSkb->len < SECFP_ICV_LEN)) {
				/* pTailPrevSkb gets initialized in the case of fragments; This case comes
				   into picture only when we have fragments */
				ulICVInPrevFrag = SECFP_ICV_LEN - pTailSkb->len;
				pCurICVLocBytePtrInPrevFrag = pTailPrevSkb->tail -  ulICVInPrevFrag;
				pCurICVLocBytePtr = pTailSkb->data;

				pTailPrevSkb->len -= ulICVInPrevFrag;
				pTailSkb->len += ulICVInPrevFrag;

				if (pSA->SAParams.bDoAntiReplayCheck) {
					pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
					if (pSA->SAParams.bUseExtendedSequenceNumber) {
						/* Packet has ICV towards the end, so we need to put the ESN and then the ICV */
						/* Leave a 4 byte gap for the ESN and move the ICV */
						/* In this case copy the entire ICV to pTailSkb->data + sizeof (unsigned int);
							Trim the previous skb->len by ulICVInPrevLen
							Update the data for the Tail frag

							Eg: Input:
							<--prevTailFrag----><-----Tail Frag------>
								   <-------ICV----->

							Output:
							<-prevTailFrag-><---Tail Frag----------->
										   < 1 integer gap, ICV----------->

						  */

						pNewICVLocBytePtr = pTailSkb->data + sizeof(unsigned int);

						/* Real exception case, do byte copy */
						/* Good question here would be why not pull into previous frag, but not sure if
							 there will be enough room there, but we have already checked for tail room
							 in tail skb */
						for (ii = pTailSkb->len - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii +
							ulICVInPrevFrag] =
							pCurICVLocBytePtr[ii];

						for (ii = ulICVInPrevFrag - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

						secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pCurICVLoc);
					} else {
						/* Copy to Tail frag */
						pNewICVLocBytePtr = pTailSkb->data;
						for (ii = pTailSkb->len - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii +
							ulICVInPrevFrag]
							= pCurICVLocBytePtr[ii];

						for (ii = ulICVInPrevFrag - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

					}
				} else {
					/* Copy to Tail frag */
					pNewICVLocBytePtr = pTailSkb->data;
					for (ii = pTailSkb->len - 1;
							ii >= 0; ii--)
						pNewICVLocBytePtr[ii +
							ulICVInPrevFrag] =
							pCurICVLocBytePtr[ii];


					for (ii = ulICVInPrevFrag - 1;
							ii >= 0; ii--)
						pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

				}
			} else
#endif
			{
				if (pSA->SAParams.bDoAntiReplayCheck) {
					pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
					if (pSA->SAParams.ucAuthAlgo == SECFP_HMAC_AES_XCBC_MAC) {
						if (pSA->SAParams.bUseExtendedSequenceNumber) {
							*((unsigned int *)(pTailSkb->tail + SECFP_ESN_MARKER_POSITION)) = 0xAAAAAAAA;
						} else {
							*((unsigned int *)(pTailSkb->tail + SECFP_ESN_MARKER_POSITION)) = 0;
						}
					}
					if (pSA->SAParams.bUseExtendedSequenceNumber) {
						pCurICVLoc = (unsigned int *)(pTailSkb->tail - SECFP_ICV_LEN);
						pNewICVLoc = (unsigned int *)(pTailSkb->tail - SECFP_ICV_LEN + sizeof(unsigned int));
						for (kk = 2; kk >= 0; kk--) {
							*(pNewICVLoc + kk) = *(pCurICVLoc + kk);
						}
						secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pCurICVLoc);
					}

				} else
					ASFIPSEC_DEBUG("No Antoreplay check\n");
			}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		} else {
			pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 0;
			/* No need to do post SEC Lookup */
			pTailSkb->tail = pTailSkb->data + pTailSkb->len;
			*(unsigned int *)pTailSkb->tail = 0;
		}

		if (pSA->SAParams.bVerifyInPktWithSASelectors) {
			pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* No need to do post SEC Lookup */
		}

		/* Copying information that is required post SEC operation */

		*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]) = ulVSGId;
		*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]) = pSA->SAParams.ulSPI;
		/* Pass the skb data pointer */
		*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]) = (unsigned int)(&(pHeadSkb->data[0]));
		*(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]) = ulHashVal;

		ASFIPSEC_DBGL2("In Packet ulSPI=%d, ipaddr_ptr=0x%x,"
			" ulHashVal= %d, Saved values: ulSPI=%d,"
			" ipaddr_ptr=0x%x, ulHashVal=%d",
			 pSA->SAParams.ulSPI, (unsigned int)&(pHeadSkb->data[0])
			 , ulHashVal,
			 *(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
			 *(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]),
			 *(unsigned int *)
			 &(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));

		if (pSA->SAParams.bPropogateECN) {
			pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX] = 1;
			pHeadSkb->cb[SECFP_TOS_INDEX] = iph->tos;
		} else
			pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX] = 0;

		if (pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX])
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SEQNUM_INDEX]) = ulSeqNum;

		/* Move the skb data pointer  to beginning of ESP header  */
		ASFIPSEC_DEBUG("In Offsetting data by ipheader len=%d", iph->ihl*4);
		pHeadSkb->data += (iph->ihl*4);
		pHeadSkb->len -= (iph->ihl*4);
		/* Storing Common Interface Id */
		if (!pSA->ulTunnelId) {
			*((unsigned int *)(pHeadSkb->data + pHeadSkb->len + SECFP_COMMON_INTERFACE_ID_POSITION)) = ulCommonInterfaceId;
		} else {
			*((unsigned int *)(pHeadSkb->data + pHeadSkb->len + SECFP_COMMON_INTERFACE_ID_POSITION)) = pSA->SAParams.ulCId;
		}

		/* Using skb->data_len for storing the total length submitted to SEC */
		skb1->data_len = iph->tot_len - (iph->ihl*4);
		ASFIPSEC_DEBUG("Calling secfp_talitos_submit");
		pHeadSkb->cb[SECFP_REF_INDEX] = 2;
		desc = secfp_desc_alloc();
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef SECFP_SG_SUPPORT
		if ((secin_sg_flag & SECFP_SCATTER_GATHER)
			== SECFP_SCATTER_GATHER)
			secfp_prepareInDescriptorWithFrags(pHeadSkb, pSA,
						desc, 0);
		else
#endif
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
			secfp_prepareInDescriptor(pHeadSkb, pSA, desc, 0);

		if (secfp_talitos_submit(pdev, desc,
			(secin_sg_flag & SECFP_SCATTER_GATHER) ?
			 secfp_inCompleteWithFrags : secfp_inComplete,
			 (void *)pHeadSkb) == -EAGAIN) {
#ifdef ASFIPSEC_LOG_MSG
			ASFIPSEC_DEBUG("Inbound Submission to SEC failed");
			AsfLogInfo.ulMsgId =  ASF_IPSEC_LOG_MSG_ID3;
			AsfLogInfo.aMsg = aMsg;
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "In Crypto  Operation Failed");
			asfFillLogInfo(&AsfLogInfo, pSA);
#endif
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
			pHeadSkb->data_len = 0;
			secfp_desc_free(desc);
			kfree_skb(pHeadSkb);
			rcu_read_unlock();
			/* Increment statistics */
			return 1;
		}
		pHeadSkb->len -= (pSA->ulSecHdrLen);
		pHeadSkb->data += (pSA->ulSecHdrLen);
		pHeadSkb->cb[SECFP_REF_INDEX]--;
		/* length of skb memory to unmap upon completion */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (pSA->option[1] != SECFP_NONE) {
			pHeadSkb->cb[SECFP_REF_INDEX]++;
			desc = secfp_desc_alloc();
#ifdef SECFP_SG_SUPPORT
			if ((secin_sg_flag & SECFP_SCATTER_GATHER)
				== SECFP_SCATTER_GATHER)
				secfp_prepareInDescriptorWithFrags(pHeadSkb,
						pSA, desc, 0);
			else
#endif
				secfp_prepareInDescriptor(pHeadSkb, pSA, desc, 0);

			if (secfp_talitos_submit(pdev, desc,
				(secin_sg_flag & SECFP_SCATTER_GATHER)
				? secfp_inCompleteWithFrags : secfp_inComplete,
				(void *)pHeadSkb) == -EAGAIN) {
				ASFIPSEC_WARN("Inbound Submission to SEC failed");

				/* Mark SKB action index to drop */
				pHeadSkb->cb[SECFP_REF_INDEX] -= 2 ;
				if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
					/* CB finished */
					kfree_skb(pHeadSkb);
				} else {
					pHeadSkb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				}
				secfp_desc_free(desc);
				/* Increment statistics */
				rcu_read_unlock();
				return 1;
			}
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		/* Post submission, we can move the data pointer beyond the ESP header */
		/* Trim the length accordingly */
		/* Since we will be giving packet to fwnat processing, keep the data pointer as 14 bytes before data start */
		ASFIPSEC_DEBUG("In: Offseting data by ulSecHdrLen = %d",
					pSA->ulSecHdrLen);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (pSA->SAParams.bAuth && pSA->SAParams.bDoAntiReplayCheck)
			secfp_checkSeqNum(pSA, ulSeqNum, ulLowerBoundSeqNum, pHeadSkb);
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
			ASFIPSEC_TRACE;
			pHeadSkb->data_len = 0;
			/* CB already finished processing the skb & there was an error*/
			kfree_skb(pHeadSkb);
		}
		/* Assumes successful processing of the Buffer */
		pSA->ulBytes[smp_processor_id()] += len;
		pSA->ulPkts[smp_processor_id()]++;
		pIPSecPolicyPPStats->NumInBoundOutPkts++;

		rcu_read_unlock();
		return 1;
	} else {
		ASFBuffer_t Buffer;
		rcu_read_unlock();
		ASFIPSEC_DEBUG("Inbound SA Not found ");
		/* Homogenous buffer */
		Buffer.nativeBuffer = skb1;
		if (ASFIPSecCbFn.pFnNoInSA)
			ASFIPSecCbFn.pFnNoInSA(ulVSGId, Buffer, ASFSkbFree,
				skb1, ulCommonInterfaceId);
		return 1;
	}
}

/*
  * This function called from firewall checks if the given packet came on the correct SA
  * by doing SPI verification
  */
int secfp_CheckInPkt(
			unsigned int ulVSGId,
			struct sk_buff *skb,
			ASF_uint32_t ulCommonInterfaceId,
			ASFFFPIpsecInfo_t  *pSecInfo,
			void *pIpsecOpq) {
	SPDInSPIValLinkNode_t *pNode;
	SPDInContainer_t *pContainer;
	ASFIPSecOpqueInfo_t  *pIPSecOpque;
	ASFBuffer_t Buffer;
	ASF_boolean_t  bRevalidate = FALSE;

	pIPSecOpque = (ASFIPSecOpqueInfo_t  *)pIpsecOpq;
	if (pSecInfo != NULL) {
		ASFIPSEC_DBGL2(" VSGId = %d, OCI= %d, OMN=%d ICN=%d IMN=%d ",
			 ulVSGId,
			 pSecInfo->outContainerInfo.ulSPDContainerId,
			 pSecInfo->outContainerInfo.ulSPDMagicNumber,
			 pSecInfo->inContainerInfo.ulSPDContainerId,
			 pSecInfo->inContainerInfo.ulSPDMagicNumber);
		ASFIPSEC_DBGL2("SPI value stored in cb field of skb is %p, ",
			 (void *) *(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]));
		if (unlikely(pSecInfo->inContainerInfo.ulTimeStamp < ulTimeStamp_g)) {
			if ((pSecInfo->inContainerInfo.configIdentity.ulVSGConfigMagicNumber !=
				pulVSGMagicNumber[ulVSGId]) ||
				(pSecInfo->inContainerInfo.configIdentity.ulTunnelConfigMagicNumber !=
				secFP_TunnelIfaces[ulVSGId][pSecInfo->inContainerInfo.ulTunnelId].ulTunnelMagicNumber)) {
				bRevalidate = TRUE;
				goto callverify;
			}
			pSecInfo->inContainerInfo.ulTimeStamp = ulTimeStamp_g;
		}


		pContainer = (SPDInContainer_t *)ptrIArray_getData(&(secfp_InDB),
								   pSecInfo->inContainerInfo.ulSPDContainerId);

		if (ptrIArray_getMagicNum(&(secfp_InDB),
					  pSecInfo->inContainerInfo.ulSPDContainerId)
			 == pSecInfo->inContainerInfo.ulSPDMagicNumber) {
			pNode = secfp_findInSPINode(pContainer,
							 *(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]));
			if (pNode) {
				ASFIPSEC_DEBUG("pNode->ulSPIVal = %d: matches "\
					"with stored value",  pNode->ulSPIVal);
				return 0 /* ASF_IPSEC_PROCEED */;
			} else {
				ASFIPSEC_DEBUG("Stored values don't match: Debug");
			}
		} else {
			ASFIPSEC_DEBUG("Stored SPD not matched");
		}
		kfree_skb(skb);
		IPSecPPGlobalStats_g[smp_processor_id()].ulTotInProcPkts++;
		IPSecPPGlobalStats_g[smp_processor_id()].ulTotInProcSecPkts++;
		return 1;
	}
callverify:
	ASFIPSEC_DEBUG("Calling Inbound SPD verification function");
	/* Homogenous buffer */
	Buffer.nativeBuffer = skb;
	if (ASFIPSecCbFn.pFnVerifySPD)
		ASFIPSecCbFn.pFnVerifySPD(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
				  pIPSecOpque->ulInSPDContainerId,
				  pIPSecOpque->ulInSPDMagicNumber,
				  *(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
				  pIPSecOpque->ucProtocol,
				  pIPSecOpque->DestAddr,
				  Buffer,
				  ASFSkbFree, skb, bRevalidate, ulCommonInterfaceId);
	return 1;
}
/************* Beginning of API Function and inner functions used by API****************
*  All APIs to normal path return SECFP_SUCCESS upon SUCCESS and SECFP_FAILURE upon
 * FAILURE																				*/

/* update descriptor information within SA, that can be held permanantly */
static inline int secfp_updateInSA(inSA_t *pSA, SAParams_t *pSAParams)
{
	memcpy(&pSA->SAParams, pSAParams,
		 sizeof(SAParams_t));
	if (pSA->SAParams.bAuth) {
			switch (pSA->SAParams.ucAuthAlgo) {
			case SECFP_HMAC_MD5:
				pSA->hdr_Auth_template_1 = DESC_HDR_SEL1_MDEUA|
							   DESC_HDR_MODE1_MDEU_INIT |
							   DESC_HDR_MODE1_MDEU_PAD |
							   DESC_HDR_MODE1_MDEU_MD5_HMAC;
				pSA->hdr_Auth_template_0 = DESC_HDR_SEL0_MDEUA|
							   DESC_HDR_MODE0_MDEU_INIT |
							   DESC_HDR_MODE0_MDEU_PAD |
							   DESC_HDR_MODE0_MDEU_MD5_HMAC;
				break;
			case SECFP_HMAC_SHA1:
				pSA->hdr_Auth_template_1 |=
				DESC_HDR_SEL1_MDEUA |
				DESC_HDR_MODE1_MDEU_INIT |
				DESC_HDR_MODE1_MDEU_PAD |
				DESC_HDR_MODE1_MDEU_SHA1_HMAC;

				pSA->hdr_Auth_template_0 |=
				DESC_HDR_SEL0_MDEUA |
				DESC_HDR_MODE0_MDEU_INIT |
				DESC_HDR_MODE0_MDEU_PAD |
				DESC_HDR_MODE0_MDEU_SHA1_HMAC;
				break;
			case SECFP_HMAC_AES_XCBC_MAC:
				pSA->hdr_Auth_template_0 |=
				DESC_HDR_SEL0_AESU |
				DESC_HDR_MODE0_AES_XCBS_MAC;
				break;
			default:
				ASFIPSEC_DEBUG("Invalid ucAuthAlgo");
				return -1;
		}
	}

	if (pSA->SAParams.bEncrypt) {
			switch (pSA->SAParams.ucCipherAlgo) {
			case SECFP_DES:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_DEU |
				DESC_HDR_MODE0_DEU_CBC;
				break;
			case SECFP_3DES:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_DEU |
				DESC_HDR_MODE0_DEU_CBC|
				DESC_HDR_MODE0_DEU_3DES;
				break;

			case SECFP_AES:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_AESU |
				DESC_HDR_MODE0_AESU_CBC;
				break;
			case SECFP_AESCTR:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_AESU |
				DESC_HDR_MODE0_AES_CTR;
				break;
			case SECFP_ESP_NULL:
				ASFIPSEC_DEBUG("NULL Encryption set");
				break;
			default:
				ASFIPSEC_WARN("Invalid ucEncryptAlgo");
				return -1;
		}
	}
	return 0;
}


/* Internal routines to support Control Plane/Normal Path API */

static inline int secfp_updateOutSA(outSA_t *pSA, void *buff)
{
	SAParams_t *pSAParams = (SAParams_t *)(buff);

	memcpy(&pSA->SAParams, pSAParams,
		 sizeof(SAParams_t));
	if (pSA->SAParams.bAuth) {
			switch (pSAParams->ucAuthAlgo) {
			case SECFP_HMAC_MD5:
				pSA->hdr_Auth_template_1 = DESC_HDR_SEL1_MDEUA|
							   DESC_HDR_MODE1_MDEU_INIT |
							   DESC_HDR_MODE1_MDEU_PAD |
							   DESC_HDR_MODE1_MDEU_MD5_HMAC;
				pSA->hdr_Auth_template_0 = DESC_HDR_SEL0_MDEUA|
							   DESC_HDR_MODE0_MDEU_INIT |
							   DESC_HDR_MODE0_MDEU_PAD |
							   DESC_HDR_MODE0_MDEU_MD5_HMAC;
				break;
			case SECFP_HMAC_SHA1:
				pSA->hdr_Auth_template_1 |=
				DESC_HDR_SEL1_MDEUA |
				DESC_HDR_MODE1_MDEU_INIT |
				DESC_HDR_MODE1_MDEU_PAD |
				DESC_HDR_MODE1_MDEU_SHA1_HMAC;

				pSA->hdr_Auth_template_0 |=
				DESC_HDR_SEL0_MDEUA |
				DESC_HDR_MODE0_MDEU_INIT |
				DESC_HDR_MODE0_MDEU_PAD |
				DESC_HDR_MODE0_MDEU_SHA1_HMAC;
				break;
			case SECFP_HMAC_AES_XCBC_MAC:
				pSA->hdr_Auth_template_0 |=
				DESC_HDR_SEL0_AESU |
				DESC_HDR_MODE0_AES_XCBS_MAC;
				break;
			default:
				ASFIPSEC_DEBUG("Invalid ucAuthAlgo");
				return -1;
		}
	}
	if (pSA->SAParams.bEncrypt) {
			switch (pSAParams->ucCipherAlgo) {
			case SECFP_DES:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_DEU |
				DESC_HDR_MODE0_DEU_CBC;
				break;
			case SECFP_3DES:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_DEU |
				DESC_HDR_MODE0_DEU_CBC|
				DESC_HDR_MODE0_DEU_3DES;
				break;
			case SECFP_AES:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_AESU |
				DESC_HDR_MODE0_AESU_CBC;
				break;
			case SECFP_AESCTR:
				pSA->desc_hdr_template |=
				DESC_HDR_SEL0_AESU |
				DESC_HDR_MODE0_AES_CTR;
				break;
			case SECFP_ESP_NULL:
				ASFIPSEC_DEBUG("NULL Encryption set");
				break;

			default:
				ASFIPSEC_WARN("Invalid ucEncryptAlgo");
				return -1;
		}
	}
	return 0;
}

/* To remove all container index nodes from the tunnel */
void secfp_removeAllCINodesFromTunnelList(unsigned int ulVSGId,
					  unsigned int ulTunnelId, ASF_boolean_t bDir)
{
	ASFIPSEC_DEBUG("Stub function: Need to handle RCUs ");
}

/* API functions for Control Plane/Normal Path */

/* Append Container node to tunnel list -internal function */

void secfp_appendCINodeToTunnelList(unsigned int ulVSGId,
					unsigned int ulTunnelId, struct SPDCILinkNode_s *pCINode, ASF_boolean_t bDir)
{
	struct SPDCILinkNode_s *pTempCINode;
	struct SPDCILinkNode_s **pList;

	spin_lock(&secfp_TunnelIfaceCIIndexListLock);

	if (bDir == SECFP_OUT) {
		pList = &(secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList);
	} else { /* for Inbound */
		pList = &secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	}
	if (*pList) {
		pTempCINode = pCINode->pNext = *pList;
		pCINode->pPrev = NULL;
		rcu_assign_pointer(*pList, pCINode);
		if (pTempCINode)
			pTempCINode->pPrev = pCINode;
	} else {
		pCINode->pPrev = NULL;
		pCINode->pNext = NULL;
		*pList = pCINode;
	}
	spin_unlock(&secfp_TunnelIfaceCIIndexListLock);
}

/* remove container node from tunnel list */
void secfp_removeCINodeFromTunnelList(unsigned int ulVSGId,
					unsigned int ulTunnelId,  struct SPDCILinkNode_s *pCINode, bool bDir) {
	struct SPDCILinkNode_s **pList;
	if (bDir == SECFP_OUT) {
		pList = &secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	} else { /* for Inbound */
		pList = &secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	}
	spin_lock(&secfp_TunnelIfaceCIIndexListLock);

	if (pCINode == *pList) {
		if (pCINode->pNext)
			pCINode->pNext->pPrev = NULL;
		*pList = pCINode->pNext;
	} else {
		if (pCINode->pNext)
			pCINode->pNext->pPrev = pCINode->pPrev;
		if (pCINode->pPrev)
			pCINode->pPrev->pNext = pCINode->pNext;
	}
	spin_unlock(&secfp_TunnelIfaceCIIndexListLock);
	call_rcu((struct rcu_head *)pCINode,  secfp_freeSDPCILinkNode);
}


/* Container create function */
unsigned int secfp_SPDOutContainerCreate(unsigned int	ulVSGId,
					 unsigned int	ulTunnelId,
					 unsigned int	ulContainerIndex,
					 unsigned int	ulMagicNum,
					 SPDOutParams_t *pSPDParams)
{
	SPDOutContainer_t *pContainer;
	struct SPDCILinkNode_s *pCINode;
	int ii;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	/* If tunnel interface not created, create the tunnel interface */
	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse = 1;
		ASFIPSEC_DEBUG("Tunnel Interface is not in use. TunnelId=%u, VSGId=%u",  ulTunnelId, ulVSGId);
	}

	pCINode =  secfp_allocSPDCILinkNode();
	if (pCINode == NULL) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("Tunnel LinkNode creation failure:secfp_allocSPDCILinkNode returned null");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_RESOURCE_NOT_AVAILABLE;;
	}

	pContainer = secfp_allocSPDOutContainer();
	if (pContainer) {
		memcpy(&(pContainer->SPDParams), pSPDParams, sizeof(SPDOutParams_t));
		if (pContainer->SPDParams.bOnlySaPerDSCP) {
			for (ii = 0; ii < SECFP_MAX_DSCP_SA; ii++) {
				pContainer->SAHolder.ulSAIndex[ii] = ulMaxSupportedIPSecSAs_g;
			}
		}

		if (ptrIArray_addInGivenIndex(&(secfp_OutDB), pContainer,
						ulContainerIndex, ulMagicNum) != 0) {
			ASFIPSEC_DEBUG("ptrIArray_addInGivenIndex retruned null");
			secfp_freeSPDOutContainer((struct rcu_head *)pContainer);
			secfp_freeSDPCILinkNode((struct rcu_head *)pCINode);
			GlobalErrors.ulOutSPDContainerAlreadyPresent++;
			if (!bVal)
				local_bh_enable();
			return ASF_IPSEC_INVALID_CONTAINER_ID;
		}

		pCINode->ulIndex = ulContainerIndex;

		/* Append it to the list */
		secfp_appendCINodeToTunnelList(ulVSGId, ulTunnelId, pCINode, SECFP_OUT);
	} else {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("secfp_allocSPDOutContainer returned null");
		secfp_freeSDPCILinkNode((struct rcu_head *)pCINode);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_RESOURCE_NOT_AVAILABLE;
	}
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}

/* Container delete function */
unsigned int secfp_SPDOutContainerDelete(unsigned int ulVSGId,
					 unsigned int ulTunnelId,
					 unsigned int ulContainerIndex,
					 unsigned int ulMagicNumber)
{
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_DEBUG("Tunnel Interface is not in use. TunnelId=%u, VSGId=%u",  ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}

	for (pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
		pCINode != NULL;
		pCINode = pCINode->pNext) {
		if (pCINode->ulIndex == ulContainerIndex) {
			break;
		}
	}

	if (!pCINode) {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("Could not find CI Link Node");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_OUTSPDCONTAINER_NOT_FOUND;
	}
	secfp_removeCINodeFromTunnelList(ulVSGId, ulTunnelId, pCINode, SECFP_OUT);
	ptrIArray_delete(&(secfp_OutDB), ulContainerIndex, secfp_freeSPDOutContainer);
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}


/* In container create function */
unsigned int secfp_SPDInContainerCreate(unsigned int   ulVSGId,
					unsigned int   ulTunnelId,
					unsigned int   ulContainerIndex,
					unsigned int   ulMagicNum,
					SPDInParams_t *pSPDParams)
{
	SPDInContainer_t *pContainer;
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	/* If tunnel interface not created, create the tunnel interface */
	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse = 1;
		ASFIPSEC_DEBUG("Tunnel Interface is not in use. TunnelId=%u, VSGId=%u",  ulTunnelId, ulVSGId);
	}

	pCINode =  secfp_allocSPDCILinkNode();
	if (pCINode == NULL) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("Tunnel LinkNode creation failure:secfp_allocSPDCILinkNode returned null");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_RESOURCE_NOT_AVAILABLE;;
	}

	pContainer = secfp_allocSPDInContainer();
	if (pContainer) {
		memcpy(&pContainer->SPDParams, pSPDParams, sizeof(SPDInParams_t));
		if (ptrIArray_addInGivenIndex(&(secfp_InDB), pContainer,
						ulContainerIndex, ulMagicNum) != 0) {
			ASFIPSEC_DEBUG("ptrIArray_addInGivenIndex retruned failure");
			secfp_freeSPDInContainer((struct rcu_head *)pContainer);
			secfp_freeSDPCILinkNode((struct rcu_head *) pCINode);
			GlobalErrors.ulInSPDContainerAlreadyPresent++;
			if (!bVal)
				local_bh_enable();
			return ASF_IPSEC_INVALID_CONTAINER_ID;
		}
		pCINode->ulIndex = ulContainerIndex;
		/* Append it to the list */
		secfp_appendCINodeToTunnelList(ulVSGId, ulTunnelId, pCINode, SECFP_IN);
	} else {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("secfp_allocSPDInContainer returned null");
		secfp_freeSDPCILinkNode((struct rcu_head *)pCINode);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_RESOURCE_NOT_AVAILABLE;
	}
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}


/*  In container delete function */
unsigned int secfp_SPDInContainerDelete(unsigned int ulVSGId,
					unsigned int ulTunnelId,
					unsigned int ulContainerIndex,
					unsigned int ulMagicNumber)
{
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_softirq();

	/* Clean up the selector set SA Pointers and others */
	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_DEBUG("Tunnel Interface is not in use. TunnelId=%u, VSGId=%u",  ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}


	for (pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
		pCINode != NULL;
		pCINode = pCINode->pNext) {
		if (pCINode->ulIndex == ulContainerIndex) {
			break;
		}
	}

	if (!pCINode) {
		GlobalErrors.ulSPDInContainerNotFound++;
		ASFIPSEC_DEBUG("Could not find CI Link Node");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_INSPDCONTAINER_NOT_FOUND;
	}
	secfp_removeCINodeFromTunnelList(ulVSGId, ulTunnelId, pCINode, SECFP_IN);
	ptrIArray_delete(&(secfp_InDB),  ulContainerIndex, secfp_freeSPDInContainer);
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}


/* Out SA creation function */
unsigned int secfp_createOutSA(
				unsigned int  ulVSGId,
				unsigned int  ulTunnelId,
				unsigned int  ulSPDContainerIndex,
				unsigned int  ulMagicNumber,
				SASel_t	 *pSrcSel,
				SASel_t	 *pDstSel,
				unsigned char  ucSelMask,
				SAParams_t	*SAParams,
				unsigned  short usDscpStart,
				unsigned  short usDscpEnd,
				unsigned int   ulMtu)

{
	outSA_t *pSA;
	SPDOutContainer_t *pContainer;
	int ii;
	ASF_IPSecTunEndAddr_t  TunAddress;
	unsigned int ulIndex;
	struct flowi fl;
	outSA_t *pOldSA;
	SPDOutSALinkNode_t *pOutSALinkNode;

	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pContainer = (SPDOutContainer_t *)ptrIArray_getData(&(secfp_OutDB),
							   ulSPDContainerIndex);
	if (!pContainer) {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("SPDContainer not found");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	if ((usDscpStart == 0) && (usDscpEnd == 0)) {
		usDscpEnd = 7;
	}

	if (pContainer->SPDParams.bOnlySaPerDSCP) {
		for (ii = usDscpStart; ii < usDscpEnd; ii++) {
			if (pContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
				/* DSCP Index has already an SA, so compare the SPI values */
				pOldSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable, pContainer->SAHolder.ulSAIndex[ii]);
				if (SAParams->ulSPI == pOldSA->SAParams.ulSPI) {
					ASFIPSEC_DEBUG("SA Already exists: Ignore the new one");
					if (!bVal)
						local_bh_enable();
					return SECFP_SUCCESS;
				} else {
					ASFIPSEC_DEBUG("Missed a delete, need to see how to handle this");
					if (!bVal)
						local_bh_enable();
					return SECFP_FAILURE;
				}
			}
		}
	} else {
		pOutSALinkNode = secfp_findOutSALinkNode(pContainer, SAParams->tunnelInfo.addr.iphv4.daddr,
							 SAParams->ucProtocol, SAParams->ulSPI);
		if (pOutSALinkNode != NULL) {
			GlobalErrors.ulOutDuplicateSA++;
			ASFIPSEC_DEBUG("SA Already exists: Ignore the new one ");
			if (!bVal)
				local_bh_enable();
			return SECFP_SUCCESS;
		}
	}

	pSA = secfp_allocOutSA();
	if (pSA) {
		if (!pContainer->SPDParams.bOnlySaPerDSCP) {
			secfp_addOutSelSet(pSA, pSrcSel, pDstSel, ucSelMask,
					usDscpStart, usDscpEnd);
			if (!pSA->pSelList) {
				ASFIPSEC_DEBUG("secfp_addOutSelSet returned failure");
				if (!bVal)
					local_bh_enable();
				secfp_freeOutSA((struct rcu_head *)pSA);
				return SECFP_FAILURE;
			}
		}
		pSA->ulTunnelId = ulTunnelId;
		pSA->chan = ulLastOutSAChan_g;
		ulLastOutSAChan_g = (ulLastOutSAChan_g == 0) ? 1 : 0;
		memcpy(&(pSA->SPDParams), &(pContainer->SPDParams), sizeof(SPDOutParams_t));

		if (secfp_updateOutSA(pSA, SAParams)) {
			GlobalErrors.ulInvalidAuthEncAlgo++;
			ASFIPSEC_DEBUG("secfp_updateOutSA returned failure");
			secfp_freeOutSA((struct rcu_head *)pSA);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}

		pSA->ipHdrInfo.bIpVersion = pSA->SAParams.tunnelInfo.bIPv4OrIPv6;

		if ((pSA->SAParams.bUseExtendedSequenceNumber) ||
			((pSA->hdr_Auth_template_0 &  DESC_HDR_MODE0_AES_XCBS_MAC)
			 == DESC_HDR_MODE0_AES_XCBS_MAC)) {
			if (pSA->SAParams.bEncrypt) {
				pSA->option[0] = SECFP_CIPHER;
				pSA->bIVDataPresent = TRUE;
				if (!((pSA->desc_hdr_template &
					 (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
					pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU
								  |  DESC_HDR_MODE0_ENCRYPT;
				} else {
					pSA->desc_hdr_template |=  DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
				}
				if (pSA->SAParams.bAuth) {
					/* Prepare the header for performing the cryptographic operation */
					pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
					pSA->option[1] = SECFP_AUTH;
				}
			} else {
				pSA->option[0] = SECFP_AUTH;
				/* Prepare the header for performing the cryptographic operation */
				pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
				pSA->option[1] = SECFP_NONE;
			}
		} else {
			pSA->option[1] = SECFP_NONE;
			if (pSA->SAParams.bEncrypt  && pSA->SAParams.bAuth) {
				pSA->bIVDataPresent = TRUE;
				if (((pSA->desc_hdr_template &
					(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
					pSA->option[0] = SECFP_AESCTR_BOTH;
					pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_HMAC;
				} else {
					pSA->option[0] = SECFP_BOTH;
					pSA->desc_hdr_template |= DESC_HDR_TYPE_IPSEC_ESP |
								  DESC_HDR_MODE0_ENCRYPT;
					pSA->desc_hdr_template |= pSA->hdr_Auth_template_1;
				}
			} else if (pSA->SAParams.bEncrypt && (!pSA->SAParams.bAuth)) {
				pSA->option[0] = SECFP_CIPHER;
				pSA->bIVDataPresent = TRUE;
				if (!((pSA->desc_hdr_template &
					 (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
					pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU
								  |  DESC_HDR_MODE0_ENCRYPT;
				} else {
					pSA->desc_hdr_template |=  DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
				}
			} else {
				pSA->option[0] = SECFP_AUTH;
				if (pSA->SAParams.bAuth) {
					/* Prepare the header for performing the cryptographic operation */
					pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
				}
			}
		}
		/* Prepare the IP header and keep it for reuse */
		if (!pSA->ipHdrInfo.bIpVersion) { /* IPv4 */
			pSA->ipHdrInfo.hdrdata.iphv4.version = SECFP_IPVERSION;
			pSA->ipHdrInfo.hdrdata.iphv4.ihl = 5;
			pSA->ipHdrInfo.hdrdata.iphv4.tos = 0;
			if (!pSA->SAParams.bCopyDscp) {
				/* Revisit code */
				pSA->ipHdrInfo.hdrdata.iphv4.tos = pSA->SAParams.ucDscp;
			}
			pSA->ipHdrInfo.hdrdata.iphv4.tot_len = 0;
			pSA->ipHdrInfo.hdrdata.iphv4.id = 0;

				switch (pSA->SAParams.handleDf) {
				case SECFP_DF_CLEAR:
					pSA->ipHdrInfo.hdrdata.iphv4.frag_off = 0;
					break;
				case SECFP_DF_SET:
					pSA->ipHdrInfo.hdrdata.iphv4.frag_off = IP_DF;
					break;
				default:
					ASFIPSEC_DEBUG("DF Option not handled");
					break;
				}

			pSA->ipHdrInfo.hdrdata.iphv4.ttl = SECFP_IP_TTL;
			pSA->ipHdrInfo.hdrdata.iphv4.protocol = SECFP_PROTO_ESP;
			pSA->ipHdrInfo.hdrdata.iphv4.check = 0;
			pSA->ipHdrInfo.hdrdata.iphv4.saddr = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
			pSA->ipHdrInfo.hdrdata.iphv4.daddr = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
			/* Subha: removed SECFP_IP_HDR_LEN counted twice: */
			pSA->ulSecOverHead = SECFP_IP_HDR_LEN + SECFP_ESP_HDR_LEN + SECFP_ESP_TRAILER_LEN + pSA->SAParams.ulIvSize;
			pSA->ulPathMTU = ulMtu;
			pSA->ulSecLenIncrease = SECFP_IP_HDR_LEN;
			pSA->prepareOutPktFnPtr = secfp_prepareOutPacket;
			pSA->finishOutPktFnPtr = secfp_finishOutPacket;
		} else { /* Handle IPv6 case */
			ASFIPSEC_DEBUG("stub IPv6 gateway changes not done yet");
		}
		pSA->ulIvSizeInWords = pSA->SAParams.ulIvSize/4;
		pSA->ulSecHdrLen = SECFP_ESP_HDR_LEN + pSA->SAParams.ulIvSize;

		/* starting the seq number from 2 to avoid the conflict
		with the Networking Stack seq number */
		atomic_set(&pSA->ulLoSeqNum, 2);

		if (pSA->SAParams.bAuth) {
			pSA->ulSecOverHead += SECFP_ICV_LEN;
			pSA->ulSecLenIncrease += SECFP_ICV_LEN;
		}

		/* revisit - usAuthKeyLen or usAuthKeySize */
		if (pSA->SAParams.bAuth)
			pSA->AuthKeyDmaAddr = SECFP_DMA_MAP_SINGLE(&pSA->SAParams.ucAuthKey,
						pSA->SAParams.AuthKeyLen,
						DMA_TO_DEVICE);
		if (pSA->SAParams.bEncrypt)
			pSA->EncKeyDmaAddr = SECFP_DMA_MAP_SINGLE(&pSA->SAParams.ucEncKey,
						pSA->SAParams.EncKeyLen,
						DMA_TO_DEVICE);

		/* find the route and update it */
		fl.oif = 0;
		fl.fl4_dst =  pSA->ipHdrInfo.hdrdata.iphv4.daddr;
		fl.fl4_src =  pSA->ipHdrInfo.hdrdata.iphv4.saddr;
		fl.fl4_tos = 0;

		ulIndex = ptrIArray_add(&secFP_OutSATable, pSA);
		if (ulIndex != secFP_OutSATable.nr_entries) {
			if (pContainer->SPDParams.bOnlySaPerDSCP) {
				for (ii = usDscpStart; ii < usDscpEnd; ii++)
					pContainer->SAHolder.ulSAIndex[ii] = ulIndex;
			} else {
				pOutSALinkNode = secfp_allocOutSALinkNode();
				if (pOutSALinkNode == NULL) {
					GlobalErrors.ulResourceNotAvailable++;
					ASFIPSEC_DEBUG("secfp_allocOutSALinkNode returned null");
					secfp_freeOutSA((struct rcu_head *)pSA);
					if (!bVal)
						local_bh_enable();
					return SECFP_FAILURE;
				}
				pOutSALinkNode->ulSAIndex = ulIndex;
				secfp_addOutSALinkNode(pContainer, pOutSALinkNode);
			}
		} else {
			GlobalErrors.ulOutSAFull++;
			ASFIPSEC_DEBUG("Could not find index to hold SA:Maximum count reached ");
			secfp_freeOutSA((struct rcu_head *)pSA);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
		TunAddress.IP_Version = 4;
		TunAddress.dstIP.bIPv4OrIPv6 = 0;
		TunAddress.srcIP.bIPv4OrIPv6 = 0;
		TunAddress.dstIP.ipv4addr =
			pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
		TunAddress.srcIP.ipv4addr =
			pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		if (!bVal)
			local_bh_enable();
		if (ASFIPSecCbFn.pFnRefreshL2Blob)
			ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId, ulTunnelId,
				ulSPDContainerIndex, ulMagicNumber, &TunAddress,
				pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
		if (!ulL2BlobRefreshTimeInSec_g) {
			pSA->pL2blobTmr = asfTimerStart(
					ASF_SECFP_BLOB_TMR_ID, 0,
					ulL2BlobRefreshTimeInSec_g,
					ulVSGId, ulIndex,
					ptrIArray_getMagicNum(&secFP_OutSATable,
					ulIndex), ulSPDContainerIndex);
			if (!pSA->pL2blobTmr) {
				ASFIPSEC_WARN("asfTimerStart failed");
			}
		}
		ASFIPSEC_DEBUG("returned success");
		return SECFP_SUCCESS;
	} else {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("secfp_allocOutSA returned null");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}
}

/* Out SA Modification function */
unsigned int secfp_ModifyOutSA(unsigned long int ulVSGId,
				 ASFIPSecRuntimeModOutSAArgs_t *pModSA)
{
	outSA_t *pOutSA = NULL;
	SPDOutContainer_t *pOutContainer;
	SPDOutSALinkNode_t *pOutSALinkNode;
	unsigned  short usDscpStart = 0;
	unsigned  short usDscpEnd = SECFP_MAX_DSCP_SA - 1;
	int ii;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
								pModSA->ulSPDContainerIndex));

	if (pOutContainer) {
		if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
			for (ii = usDscpStart; ii < usDscpEnd; ii++) {
				if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
					/* DSCP Index has already an SA, so compare the SPI values */
					pOutSA = (outSA_t *)ptrIArray_getData(
						&secFP_OutSATable,
						pOutContainer->SAHolder.ulSAIndex[ii]);
					if (pModSA->ulSPI == pOutSA->SAParams.ulSPI)
						break;
					else
						pOutSA = NULL;
				}
			}
		} else {
			pOutSALinkNode = secfp_findOutSALinkNode(pOutContainer, pModSA->DestAddr.ipv4addr,
								 pModSA->ucProtocol, pModSA->ulSPI);
			if (pOutSALinkNode) {
				pOutSA = (outSA_t *)ptrIArray_getData(
									&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
			} else
				pOutSA = NULL;
		}
		if (pOutSA) {
			if (pModSA->ucChangeType == 0) {
				pOutSA->SAParams.tunnelInfo.addr.iphv4.saddr =  pModSA->u.addrInfo.IPAddr.ipv4addr;
			} else if (pModSA->ucChangeType == 1) {
				pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr =  pModSA->u.addrInfo.IPAddr.ipv4addr;
			} else if (pModSA->ucChangeType == 2) {
				pOutSA->ulPathMTU = pModSA->u.ulMtu;
			} else if (pModSA->ucChangeType == 3) {
				memcpy(pOutSA->l2blob, pModSA->u.l2blob.l2blob,
					pModSA->u.l2blob.ulL2BlobLen);
				pOutSA->ulL2BlobLen =
					pModSA->u.l2blob.ulL2BlobLen;
				pOutSA->bVLAN = pModSA->u.l2blob.bTxVlan;
				pOutSA->bPPPoE =
					pModSA->u.l2blob.bUpdatePPPoELen;
				pOutSA->tx_vlan_id =
						pModSA->u.l2blob.usTxVlanId;
				pOutSA->odev = ASFFFPGetDeviceInterface(
						pModSA->u.l2blob.ulDeviceID);
				if (!pOutSA->odev) {
					if (!bVal)
						local_bh_enable();
					return SECFP_FAILURE;
				}
				pOutSA->bl2blob = TRUE;
			}
			if (!bVal)
				local_bh_enable();
			return SECFP_SUCCESS;
		} else {
			GlobalErrors.ulOutSANotFound++;
			ASFIPSEC_DEBUG("OutSA not found");
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
	} else {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("OutContainer not found");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

}
/* Out SA deletion function */
unsigned int secfp_DeleteOutSA(unsigned int	 ulSPDContainerIndex,
				 unsigned int	 ulSPDMagicNumber,
				 unsigned int	 daddr,
				 unsigned char	ucProtocol,
				 unsigned int	 ulSPI,
				 unsigned short	usDscpStart,
				 unsigned short	usDscpEnd)
{
	unsigned int ulSAIndex, ii, Index;
	SPDOutContainer_t *pContainer;
	SPDOutSALinkNode_t *pOutSALinkNode;
	outSA_t *pOutSA;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
								ulSPDContainerIndex));
	if (pContainer) {
		if ((usDscpStart == 0) && (usDscpEnd == 0))
			usDscpEnd = 7;
		if (pContainer->SPDParams.bOnlySaPerDSCP) {
			ulSAIndex = pContainer->SAHolder.ulSAIndex[
						(unsigned int)usDscpStart];
			if (ulSAIndex == ulMaxSupportedIPSecSAs_g) {
				GlobalErrors.ulOutSANotFound++;
				ASFIPSEC_DEBUG("secfp_findOutSALinkNode returned null");
				if (!bVal)
					local_bh_enable();
				return ASF_IPSEC_OUTSA_NOT_FOUND;

			}
			pOutSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
								ulSAIndex);
			if (pOutSA) {
				for (Index = 0; Index < NR_CPUS; Index++) {
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[0], pOutSA->PolicyPPStats[Index].NumInBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[1], pOutSA->PolicyPPStats[Index].NumInBoundOutPkts);
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[2], pOutSA->PolicyPPStats[Index].NumOutBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[3], pOutSA->PolicyPPStats[Index].NumOutBoundOutPkts);
				}
				for (Index = 0; Index < 4; Index++) {
					ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(pContainer->PPStats.IPSecPolPPStats[Index + 4], pContainer->PPStats.IPSecPolPPStats[Index]);
				}
				for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
					ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(pContainer->PPStats.IPSecPolPPStats[Index], pOutSA->PPStats.IPSecPolPPStats[Index]);
					ASF_IPSEC_ATOMIC_SET(pOutSA->PPStats.IPSecPolPPStats[Index], 0);
				}
				if (pOutSA->pL2blobTmr) {
					asfTimerStop(ASF_SECFP_BLOB_TMR_ID, 0, pOutSA->pL2blobTmr);
				}
				memset(&pOutSA->PolicyPPStats, 0x0, sizeof(pOutSA->PolicyPPStats));
			}
			for (ii = usDscpStart; ii < usDscpEnd; ii++)
				pContainer->SAHolder.ulSAIndex[ii] = ulMaxSupportedIPSecSAs_g;
		} else {
			ASFIPSEC_DEBUG("Delete - dest %x, proto = %d spi= %x ",
				daddr, ucProtocol, ulSPI);

			pOutSALinkNode = secfp_findOutSALinkNode(pContainer, daddr,
								 ucProtocol, ulSPI);
			if (pOutSALinkNode) {
				pOutSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
				if (pOutSA) {
					for (Index = 0; Index < NR_CPUS; Index++) {
						ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[0], pOutSA->PolicyPPStats[Index].NumInBoundInPkts);
						ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[1], pOutSA->PolicyPPStats[Index].NumInBoundOutPkts);
						ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[2], pOutSA->PolicyPPStats[Index].NumOutBoundInPkts);
						ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[3], pOutSA->PolicyPPStats[Index].NumOutBoundOutPkts);
					}
					for (Index = 0; Index < 4; Index++) {
						ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(pContainer->PPStats.IPSecPolPPStats[Index + 4], pContainer->PPStats.IPSecPolPPStats[Index]);
					}
					for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
						ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(pContainer->PPStats.IPSecPolPPStats[Index], pOutSA->PPStats.IPSecPolPPStats[Index]);
						ASF_IPSEC_ATOMIC_SET(pOutSA->PPStats.IPSecPolPPStats[Index], 0);
					}
					memset(&pOutSA->PolicyPPStats, 0x0, sizeof(pOutSA->PolicyPPStats));
					if (pOutSA->pL2blobTmr) {
						asfTimerStop(ASF_SECFP_BLOB_TMR_ID, 0, pOutSA->pL2blobTmr);
					}
				}
				ulSAIndex = pOutSALinkNode->ulSAIndex;
				secfp_delOutSALinkNode(pContainer, pOutSALinkNode);
			} else {
				GlobalErrors.ulOutSANotFound++;
				ASFIPSEC_DEBUG("secfp_findOutSALinkNode returned null");
				if (!bVal)
					local_bh_enable();
				return ASF_IPSEC_OUTSA_NOT_FOUND;
			}
		}
		ptrIArray_delete(&secFP_OutSATable, ulSAIndex, secfp_freeOutSA);
	} else {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("SPDOutContainer not found");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_OUTSPDCONTAINER_NOT_FOUND;
	}
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}

/* In SA creation function */
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
				unsigned int ulOutSPI)
{
	inSA_t *pSA;
	SPDInContainer_t *pContainer;
	SPDInSelTblIndexLinkNode_t *pNode;
	SPDInSPIValLinkNode_t *pSPINode;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pContainer = (SPDInContainer_t *)(ptrIArray_getData(&(secfp_InDB),
								ulContainerIndex));
	if (pContainer == NULL) {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("SPDContainer not found");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	pSPINode = secfp_findInSPINode(pContainer, pSAParams->ulSPI);
	if (pSPINode) {
		GlobalErrors.ulInDuplicateSA++;
		ASFIPSEC_DEBUG("SA Already exists: Ignore the new one ");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	pSA = secfp_allocInSA(pSAParams->AntiReplayWin);
	if (pSA) {
		pSA->chan = ulLastInSAChan_g;
		ulLastInSAChan_g = (ulLastInSAChan_g == 0) ? 1 : 0;

		pSA->ulSPDOutContainerIndex = ulSPDOutContainerIndex;
		pSA->ulSPDOutContainerMagicNumber = ptrIArray_getMagicNum(&secfp_OutDB, ulSPDOutContainerIndex);
		pSA->ulOutSPI = ulOutSPI;
		pSA->ulTunnelId = ulTunnelId;

		memcpy(&(pSA->SPDParams), &(pContainer->SPDParams), sizeof(SPDInParams_t));
		if (secfp_updateInSA(pSA, pSAParams)) {
			GlobalErrors.ulInvalidAuthEncAlgo++;
			kfree(pSA);
			ASFIPSEC_DEBUG("secfp_updateInSA returned failure");
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}

		pSA->desc_hdr_template |= DESC_HDR_DIR_INBOUND;
		if ((pSA->SAParams.bUseExtendedSequenceNumber) ||
			((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBS_MAC)
			 == DESC_HDR_MODE0_AES_XCBS_MAC)) {
			if (pSA->SAParams.bEncrypt) {
				if (pSA->SAParams.bAuth) {
					pSA->option[0] = SECFP_AUTH;
					/* Need to check this */
					pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU |
									DESC_HDR_DIR_INBOUND;
					if (((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBS_MAC)
						 == DESC_HDR_MODE0_AES_XCBS_MAC)) {
		/*pSA->hdr_Auth_template_0 |= DESC_HDR_MODE0_AES_XCBS_CICV;*/
					} else {
						pSA->hdr_Auth_template_0 |= DESC_HDR_MODE0_MDEU_CICV;
					}

					pSA->option[1] = SECFP_CIPHER;
					if (!((pSA->desc_hdr_template &
						 (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
						 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
						pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
					} else {
						pSA->desc_hdr_template |=  DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
					}
					pSA->validIpPktLen = (SECFP_ESP_HDR_LEN + SECFP_IP_HDR_LEN) +
								pSA->SAParams.ulIvSize + SECFP_ICV_LEN;
				} else {
					pSA->option[0] = SECFP_CIPHER;
					if (!((pSA->desc_hdr_template &
						 (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
						 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
						pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
					} else {
						pSA->desc_hdr_template |=  DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
					}
					pSA->option[1] = SECFP_NONE;
					pSA->validIpPktLen = (SECFP_ESP_HDR_LEN + SECFP_IP_HDR_LEN) +
								pSA->SAParams.ulIvSize;
				}
			} else {
				pSA->option[0] = SECFP_AUTH;
				/* Need to check this */
				pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU |
								DESC_HDR_DIR_INBOUND;
				if (((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBS_MAC)
					 == DESC_HDR_MODE0_AES_XCBS_MAC)) {
					/*pSA->hdr_Auth_template_0 |= DESC_HDR_MODE0_AES_XCBS_CICV; */
				} else {
					pSA->hdr_Auth_template_0 |= DESC_HDR_MODE0_MDEU_CICV;
				}

				pSA->option[1] = SECFP_NONE;
				pSA->validIpPktLen = SECFP_ESP_HDR_LEN + SECFP_IP_HDR_LEN + SECFP_ICV_LEN;
			}
		} else {
			pSA->option[1] = SECFP_NONE;
			if (pSA->SAParams.bEncrypt  && pSA->SAParams.bAuth) {
				/* In the case of ESP_NULL, IV Size will be 0 */
				pSA->validIpPktLen = (SECFP_ESP_HDR_LEN + SECFP_IP_HDR_LEN) +
							pSA->SAParams.ulIvSize + SECFP_ICV_LEN;

				if (((pSA->desc_hdr_template &
					(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
					pSA->option[0] = SECFP_AESCTR_BOTH;
					pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_HMAC;
				} else {
					pSA->option[0] = SECFP_BOTH;
					pSA->desc_hdr_template |= DESC_HDR_TYPE_IPSEC_ESP;
					pSA->desc_hdr_template |= DESC_HDR_MODE1_MDEU_CICV;
					pSA->desc_hdr_template |= pSA->hdr_Auth_template_1;
				}
			} else if (pSA->SAParams.bEncrypt && (!pSA->SAParams.bAuth)) {
				pSA->option[0] = SECFP_CIPHER;
				if (!((pSA->desc_hdr_template &
					 (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					 == (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
					pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
				} else {
					pSA->desc_hdr_template |=  DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
				}
				pSA->validIpPktLen = (SECFP_ESP_HDR_LEN + SECFP_IP_HDR_LEN) +
							pSA->SAParams.ulIvSize;
			} else { /* This is the case of NULL Encryption */
				pSA->option[0] = SECFP_AUTH;
				/* Need to check this */
				pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU|
								DESC_HDR_MODE0_MDEU_CICV |
								DESC_HDR_DIR_INBOUND;
				pSA->validIpPktLen = SECFP_ESP_HDR_LEN + SECFP_IP_HDR_LEN + SECFP_ICV_LEN;
			}
		}

		/* Icv length is included as we are going to use it to store
		 * the recalculated Icv
		 */
		pSA->ulReqTailRoom = SECFP_APPEND_BUF_LEN_FIELD + SECFP_ICV_LEN;
		if (pSA->SAParams.bUseExtendedSequenceNumber)
			pSA->ulReqTailRoom += SECFP_HO_SEQNUM_LEN;
		/*
		 if (pSA->bAH)
		   pSA->ulReqTailRoom += SECFP_ICV_LEN;
		 */
		pSA->ulSecHdrLen = SECFP_ESP_HDR_LEN + pSA->SAParams.ulIvSize;

		if (pSA->SAParams.bAuth)
			pSA->AuthKeyDmaAddr = SECFP_DMA_MAP_SINGLE(&pSA->SAParams.ucAuthKey,
						pSA->SAParams.AuthKeyLen,
						DMA_TO_DEVICE);
		if (pSA->SAParams.bEncrypt)
			pSA->EncKeyDmaAddr = SECFP_DMA_MAP_SINGLE(&pSA->SAParams.ucEncKey,
						  pSA->SAParams.EncKeyLen,
						  DMA_TO_DEVICE);

		/* Need to create and append Selector Set */
		pNode = secfp_updateInSelSet(pContainer, pSrcSel, pDstSel, ucSelFlags);
		if (!pNode) {
			ASFIPSEC_DEBUG("secfp_updateInSelSet returned failure");
			kfree(pSA);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}

		/* Need to append SPI value to pSPIValList */
		if (!secfp_allocAndAppendSPIVal(pContainer, pSA)) {
			ASFIPSEC_DEBUG("secfp_allocAndAppendSPIVal returned failure");
			/* Remove from Selector List */
			secfp_deleteInContainerSelList(pContainer, pNode);
			kfree(pSA);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}

		/* Update the magic number and index in SPI table for easy reference */
		pSA->ulSPDInContainerIndex = ulContainerIndex;
		pSA->ulSPDInMagicNum = ptrIArray_getMagicNum(&secfp_InDB, ulContainerIndex);
		pSA->ulSPDSelSetIndex = pNode->ulIndex;
		pSA->ulSPDSelSetIndexMagicNum = ptrIArray_getMagicNum(&secFP_InSelTable,
									pNode->ulIndex);
		secfp_appendInSAToSPIList(pSA);
	} else {
		ASFIPSEC_WARN("Could not allocate In SA");
		GlobalErrors.ulResourceNotAvailable++;
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}
	if (!bVal)
		local_bh_enable();

	ASFIPSEC_DEBUG("returned successs");
	return SECFP_SUCCESS;
}

/* Setting DPD in INSA function */
unsigned int secfp_SetDPDInSA(unsigned long int ulVSGId,
				ASFIPSecRuntimeSetDPDArgs_t *pSetDPD)
{
	unsigned int hashVal = usMaxInSAHashTaleSize_g;
	inSA_t *pInSA;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pInSA = secfp_findInv4SA(ulVSGId, pSetDPD->ucProtocol, pSetDPD->ulSPI,
				 pSetDPD->DestAddr.ipv4addr, &hashVal);
	if (pInSA) {
		if (pInSA->ulSPDInContainerIndex == pSetDPD->ulInSPDContainerIndex) {
			pInSA->bDPDAlive = 1;
			if (!bVal)
				local_bh_enable();
			return SECFP_SUCCESS;
		} else {
			GlobalErrors.ulInSASPDContainerMisMatch++;
			ASFIPSEC_DEBUG("SPD Container mismatch  SA Container = %u, Passed Container = %u",
					 pInSA->ulSPDInContainerIndex, pSetDPD->ulInSPDContainerIndex);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
	}
	GlobalErrors.ulInSANotFound++;
	ASFIPSEC_DEBUG("InSA not found");
	if (!bVal)
		local_bh_enable();
	return SECFP_FAILURE;
}

/* In SA modification */
unsigned int secfp_ModifyInSA(unsigned long int ulVSGId,
				ASFIPSecRuntimeModInSAArgs_t *pModSA)
{
	unsigned int hashVal = usMaxInSAHashTaleSize_g;
	inSA_t *pInSA;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pInSA = secfp_findInv4SA(ulVSGId, pModSA->ucProtocol, pModSA->ulSPI,
				 pModSA->DestAddr.ipv4addr, &hashVal);
	if (pInSA) {
		if (pInSA->ulSPDInContainerIndex == pModSA->ulSPDContainerIndex) {
			if (pModSA->ucChangeType == 0) {
				pInSA->SAParams.tunnelInfo.addr.iphv4.daddr =  pModSA->IPAddr.ipv4addr;
			} else {
				pInSA->SAParams.tunnelInfo.addr.iphv4.saddr =  pModSA->IPAddr.ipv4addr;
			}
		} else {
			GlobalErrors.ulInSASPDContainerMisMatch++;
			ASFIPSEC_PRINT("SPD Container mismatch  SA Container = %u, Passed Container = %u",
					 pInSA->ulSPDInContainerIndex, pModSA->ulSPDContainerIndex);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
		if (!bVal)
			local_bh_enable();
		return SECFP_SUCCESS;
	}
	GlobalErrors.ulInSANotFound++;
	ASFIPSEC_PRINT("InSA not found");
	if (!bVal)
		local_bh_enable();
	return SECFP_FAILURE;
}

/* In SA deletion function */
unsigned int secfp_DeleteInSA(unsigned int  ulVSGId,
				unsigned int  ulContainerIndex,
				unsigned int  ulMagicNumber,
				unsigned int  daddr,
				unsigned char ucProtocol,
				unsigned int  ulSPI)

{
	unsigned int hashVal = usMaxInSAHashTaleSize_g;
	unsigned int Index;
	SPDInContainer_t *pContainer;
	SPDInSelTblIndexLinkNode_t *pNode;
	SPDInSPIValLinkNode_t *pSPINode;
	bool bFound;
	inSA_t *pSA;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pSA = secfp_findInv4SA(ulVSGId, ucProtocol, ulSPI, daddr, &hashVal);
	if (pSA) {
		pContainer = (SPDInContainer_t *)ptrIArray_getData(&(secfp_InDB),
								   pSA->ulSPDInContainerIndex);
		bFound = FALSE;
		if (pContainer) {
			for (pNode = pContainer->pSelIndex; pNode != NULL; pNode = pNode->pNext) {
				if (pSA->ulSPDSelSetIndex == pNode->ulIndex) {
					bFound = TRUE;
					break;
				}
			}
			if (bFound == TRUE) {
				secfp_deleteInContainerSelList(pContainer, pNode);
			} else {
				ASFIPSEC_PRINT("Error : Could not find selector list node");
			}

			pSPINode = secfp_findInSPINode(pContainer, pSA->SAParams.ulSPI);
			if (pSPINode) {
				secfp_deleteInContainerSPIList(pContainer, pSPINode);
			} else {
				ASFIPSEC_PRINT("Error: Could not find SPI Link node");
			}
		}
		if (pSA->ulSPDSelSetIndexMagicNum ==
			ptrIArray_getMagicNum(&secFP_InSelTable, pSA->ulSPDSelSetIndex)) {
			ptrIArray_delete(&secFP_InSelTable, pSA->ulSPDSelSetIndex, secfp_freeInSelSet);
		}

		for (Index = 0; Index < NR_CPUS; Index++) {
			ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[0], pSA->PolicyPPStats[Index].NumInBoundInPkts);
			ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[1], pSA->PolicyPPStats[Index].NumInBoundOutPkts);
			ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[2], pSA->PolicyPPStats[Index].NumOutBoundInPkts);
			ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[3], pSA->PolicyPPStats[Index].NumOutBoundOutPkts);
		}
		for (Index = 0; Index < 4; Index++) {
			ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(pContainer->PPStats.IPSecPolPPStats[Index + 4], pContainer->PPStats.IPSecPolPPStats[Index]);
		}
		for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
			ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(pContainer->PPStats.IPSecPolPPStats[Index], pSA->PPStats.IPSecPolPPStats[Index]);
			ASF_IPSEC_ATOMIC_SET(pSA->PPStats.IPSecPolPPStats[Index], 0);
		}
		memset(&pSA->PolicyPPStats, 0x0, sizeof(pSA->PolicyPPStats));
		secfp_deleteInSAFromSPIList(pSA);
		if (!bVal)
			local_bh_enable();
		return SECFP_SUCCESS;
	}
	GlobalErrors.ulInSANotFound++;
	ASFIPSEC_PRINT("secfp_findInv4SA returned NULL");
	if (!bVal)
		local_bh_enable();
	return SECFP_FAILURE;
}


ASF_void_t  ASFIPSecEncryptAndSendPkt  (ASF_uint32_t ulVSGId,
					ASF_uint32_t ulTunnelId,
					ASF_uint32_t ulSPDContainerIndex,
					ASF_uint32_t ulSPDMagicNumber,
					ASF_uint32_t ulSPI,
					ASF_IPAddr_t daddr,
					ASF_uint8_t ucProtocol,
					ASFBuffer_t Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t	*freeArg)
{
	ASFFFPIpsecInfo_t  SecInfo;
	unsigned int ulVsgId = ulVSGId;
	struct sk_buff *skb;
	unsigned char bHomogenous = 1;
	unsigned int ulSAIndex;
	SPDOutContainer_t *pOutContainer;
	SPDOutSALinkNode_t *pOutSALinkNode;

	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
								ulSPDContainerIndex));

	if (!pOutContainer) {
		if (pFreeFn)
			(pFreeFn)(freeArg);
		if (!bVal)
			local_bh_enable();
		return;
	}

	if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
		ulSAIndex = ulMaxSupportedIPSecSAs_g;
	} else {
		pOutSALinkNode = secfp_findOutSALinkNode(pOutContainer, daddr.ipv4addr,
							 ucProtocol, ulSPI);
		if (!pOutSALinkNode) {
			ASFIPSEC_PRINT("SA not found");
			if (pFreeFn)
				(pFreeFn)(freeArg);
			if (!bVal)
				local_bh_enable();
			return;
		}
		ulSAIndex = pOutSALinkNode->ulSAIndex;
	}

	SecInfo.outContainerInfo.ulSPDContainerId =  ulSPDContainerIndex;
	SecInfo.outContainerInfo.ulSPDMagicNumber = ulSPDMagicNumber;
	SecInfo.outContainerInfo.ulTunnelId = ulTunnelId;
	SecInfo.outContainerInfo.ulTimeStamp = ulTimeStamp_g;
	SecInfo.outContainerInfo.configIdentity.ulVSGConfigMagicNumber =
	pulVSGMagicNumber[ulVSGId];
	SecInfo.outContainerInfo.configIdentity.ulTunnelConfigMagicNumber =
	secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber;
	SecInfo.outSAInfo.ulSAIndex = ulSAIndex;
	SecInfo.outSAInfo.ulSAMagicNumber = ptrIArray_getMagicNum(&secFP_OutSATable, ulSAIndex);

	if (bHomogenous) {
		skb = (struct sk_buff *)Buffer.nativeBuffer;
	} else {
		/* NEEDS */
	}
	if (secfp_try_fastPathOutv4(ulVsgId, skb, &SecInfo) == 0) {
		if (pFreeFn)
			(pFreeFn)(freeArg);
	}
	if (!bVal)
		local_bh_enable();
	return;
}
EXPORT_SYMBOL(ASFIPSecEncryptAndSendPkt);

ASF_void_t	ASFIPSecDecryptAndSendPkt(ASF_uint32_t ulVSGId,
					ASFBuffer_t Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t	*freeArg,
					ASF_uint32_t ulCommonInterfaceId)
{
	struct sk_buff *skb;
	unsigned char bHomogenous = 1;

	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	if (bHomogenous) {
		skb = (struct sk_buff *)Buffer.nativeBuffer;
	} else {
		/* NEEDS */
	}
	secfp_try_fastPathInv4(skb, 0, ulVSGId, ulCommonInterfaceId);
	if (!bVal)
		local_bh_enable();

	return;
}
EXPORT_SYMBOL(ASFIPSecDecryptAndSendPkt);

ASF_void_t ASFSkbFree(ASF_void_t   *freeArg)
{
	kfree_skb((struct sk_buff *)freeArg);
}

void secfp_freeSelSet(SASel_t  *pSel)
{
	SASel_t   *pTempSel;
	while (pSel) {
		pTempSel = pSel->pNext;
		asfReleaseNode(SASelPoolId_g, pSel, pSel->bHeap);
		pSel = pTempSel;
	}
}

unsigned int secfp_copySrcAndDestSelSet(
					 SASel_t			**pSrcSel,
					 SASel_t			**pDstSel,
					 ASF_IPSecSASelector_t   *pSASel,
					 unsigned char		*pucSelFlags)
{
	SASel_t *pNewSel, *pPrevSel;
	int ii;
	unsigned char ucSelFlags, jj;
	char  bHeap;

	ucSelFlags = SECFP_SA_XPORT_SELECTOR | SECFP_SA_SRCPORT_SELECTOR | SECFP_SA_SRCIPADDR_SELECTOR |
			SECFP_SA_DESTPORT_SELECTOR | SECFP_SA_DESTIPADDR_SELECTOR;

	pNewSel = *pSrcSel = (struct SASel_s *)asfGetNode(SASelPoolId_g, &bHeap);
	if (pNewSel && bHeap) {
		pNewSel->bHeap = bHeap;
	}
	if (pNewSel == NULL) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_PRINT("Memory allocation failed for pNewSel#1");
		return SECFP_FAILURE;
	}
	pPrevSel = NULL;

	pNewSel->pPrev = NULL;
	pNewSel->pNext = NULL;

	for (ii = 0, jj = 0; ii < pSASel->nsrcSel; ii++, jj++) {
		if (jj == SECFP_MAX_SELECTORS) {
			if (pPrevSel) {
				pPrevSel->pNext = pNewSel;
				pNewSel->pPrev = pPrevSel;
			}
			pNewSel->ucNumSelectors = jj;
			pPrevSel = pNewSel;
			pNewSel = (struct SASel_s *)asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel && bHeap) {
				pNewSel->bHeap = bHeap;
			}
			if (pNewSel == NULL) {
				GlobalErrors.ulResourceNotAvailable++;
				ASFIPSEC_PRINT("Memory allocation failed for pNewSel#2");
				secfp_freeSelSet(*pSrcSel);
				return SECFP_FAILURE;
			}
			jj = 0;
		}

		pNewSel->selNodes[jj].proto = pSASel->srcSel[ii].protocol;
		if (pNewSel->selNodes[jj].proto == 0) {
			ucSelFlags &=  ~(SECFP_SA_XPORT_SELECTOR);
		}
		pNewSel->selNodes[jj].prtStart = pSASel->srcSel[ii].port.start;
		pNewSel->selNodes[jj].prtEnd = pSASel->srcSel[ii].port.end;
		if (((pNewSel->selNodes[jj].prtStart == 0) &&
			((pNewSel->selNodes[jj].prtEnd == 0) ||
			(pNewSel->selNodes[jj].prtEnd == 0xffff)))) {
			ucSelFlags &=  ~(SECFP_SA_SRCPORT_SELECTOR);
		}


		if (pSASel->srcSel[ii].IP_Version == 4) {
			if (pSASel->srcSel[ii].addr.addrType == ASF_IPSEC_ADDR_TYPE_RANGE) {
				pNewSel->selNodes[jj].ipAddrStart =
				pSASel->srcSel[ii].addr.u.rangeAddr.v4.start;
				pNewSel->selNodes[jj].ipAddrEnd =
				pSASel->srcSel[ii].addr.u.rangeAddr.v4.end;
				pNewSel->selNodes[jj].ucMask = 32;
			} else {
				pNewSel->selNodes[jj].ucMask =
				pSASel->srcSel[ii].addr.u.prefixAddr.v4.IPv4Plen;
				pNewSel->selNodes[jj].ipAddrStart =
				ASF_IPSEC4_GET_START_ADDR(\
							  pSASel->srcSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
							  pNewSel->selNodes[jj].ucMask);
				pNewSel->selNodes[jj].ipAddrEnd =
				ASF_IPSEC4_GET_END_ADDR(\
							pSASel->srcSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
							pNewSel->selNodes[jj].ucMask);

			}
			if ((pNewSel->selNodes[jj].ipAddrStart == 0) &&
				(pNewSel->selNodes[jj].ipAddrEnd == 0xffffffff)) {
				ucSelFlags &=  ~(SECFP_SA_SRCIPADDR_SELECTOR);
			}
		}
	}
	if (pPrevSel) {
		pPrevSel->pNext = pNewSel;
		pNewSel->pPrev = pPrevSel;
	}
	pNewSel->ucNumSelectors = jj;

	*pDstSel = pNewSel =  (struct SASel_s *)asfGetNode(SASelPoolId_g, &bHeap);
	if (pNewSel && bHeap) {
		pNewSel->bHeap = bHeap;
	}
	if (pNewSel == NULL) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_PRINT("Memory allocation failed for pNewSel#3");
		secfp_freeSelSet(*pSrcSel);
		return SECFP_FAILURE;
	}
	pPrevSel = NULL;

	pNewSel->pPrev = NULL;
	pNewSel->pNext = NULL;

	for (ii = 0, jj = 0; ii < pSASel->ndstSel; ii++, jj++) {
		if (jj == SECFP_MAX_SELECTORS) {
			if (pPrevSel) {
				pPrevSel->pNext = pNewSel;
				pNewSel->pPrev = pPrevSel;
			}
			pNewSel->ucNumSelectors = jj;
			pPrevSel = pNewSel;
			pNewSel = (struct SASel_s *)asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel && bHeap) {
				pNewSel->bHeap = bHeap;
			}
			if (pNewSel == NULL) {
				GlobalErrors.ulResourceNotAvailable++;
				ASFIPSEC_PRINT("Memory allocation failed for pNewSel#4");
				secfp_freeSelSet(*pSrcSel);
				secfp_freeSelSet(*pDstSel);
				return SECFP_FAILURE;
			}
			jj = 0;
		}

		pNewSel->selNodes[jj].proto = pSASel->dstSel[ii].protocol;
		if (pNewSel->selNodes[jj].proto == 0) {
			ucSelFlags &=  ~(SECFP_SA_XPORT_SELECTOR);
		}
		pNewSel->selNodes[jj].prtStart = pSASel->dstSel[ii].port.start;
		pNewSel->selNodes[jj].prtEnd = pSASel->dstSel[ii].port.end;
		if ((pNewSel->selNodes[jj].prtStart == 0) &&
			((pNewSel->selNodes[jj].prtEnd == 0) ||
			(pNewSel->selNodes[jj].prtEnd == 0xffff))) {
			ucSelFlags &=  ~(SECFP_SA_DESTPORT_SELECTOR);
		}

		if (pSASel->srcSel[ii].IP_Version == 4) {
			if (pSASel->dstSel[ii].addr.addrType == ASF_IPSEC_ADDR_TYPE_RANGE) {
				pNewSel->selNodes[jj].ipAddrStart =
				pSASel->dstSel[ii].addr.u.rangeAddr.v4.start;
				pNewSel->selNodes[jj].ipAddrEnd =
				pSASel->dstSel[ii].addr.u.rangeAddr.v4.end;
				pNewSel->selNodes[jj].ucMask = 32;
			} else {
				pNewSel->selNodes[jj].ucMask =
				pSASel->dstSel[ii].addr.u.prefixAddr.v4.IPv4Plen;
				pNewSel->selNodes[jj].ipAddrStart =
				ASF_IPSEC4_GET_START_ADDR(\
							  pSASel->dstSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
							  pNewSel->selNodes[jj].ucMask);
				pNewSel->selNodes[jj].ipAddrEnd =
				ASF_IPSEC4_GET_END_ADDR(\
							pSASel->dstSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
							pNewSel->selNodes[jj].ucMask);

			}
			if ((pNewSel->selNodes[jj].ipAddrStart == 0) &&
				(pNewSel->selNodes[jj].ipAddrEnd == 0xffffffff)) {
				ucSelFlags &=  ~(SECFP_SA_DESTIPADDR_SELECTOR);
			}

		}
	}
	if (pPrevSel) {
		pPrevSel->pNext = pNewSel;
		pNewSel->pPrev = pPrevSel;
	}
	pNewSel->ucNumSelectors = jj;

	*pucSelFlags = ucSelFlags;
	return SECFP_SUCCESS;
}
static inline void asfFillLogInfo(ASFLogInfo_t *pAsfLogInfo , inSA_t *pSA)
{
	int ii;
	if (!ASFIPSecCbFn.pFnAuditLog)
		return;
	pAsfLogInfo->u.IPSecInfo.ucDirection = 0;
	pAsfLogInfo->ulVSGId = pSA->ulVSGId;
	pAsfLogInfo->u.IPSecInfo.ucDirection = 0;
	pAsfLogInfo->u.IPSecInfo.ulSPDContainerIndex = pSA->ulSPDInContainerIndex;
	for (ii = 0; ii < NR_CPUS; ii++) {
		pAsfLogInfo->u.IPSecInfo.ulNumOfPktsProcessed += pSA->ulPkts[ii];
		pAsfLogInfo->u.IPSecInfo.ulNumOfBytesProcessed += pSA->ulBytes[ii];
	}
	pAsfLogInfo->u.IPSecInfo.ucProtocol = pSA->SAParams.ucProtocol;
	pAsfLogInfo->u.IPSecInfo.ulSeqNumber = pSA->ulLastSeqNum;
	pAsfLogInfo->u.IPSecInfo.ulPathMTU = 0xffff;
	pAsfLogInfo->u.IPSecInfo.ulSPI = pSA->SAParams.ulSPI;
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 0) {
		pAsfLogInfo->u.IPSecInfo.Address.IP_Version = 4;
		pAsfLogInfo->u.IPSecInfo.Address.srcIP.ipv4addr =  pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		pAsfLogInfo->u.IPSecInfo.Address.dstIP.ipv4addr =  pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
	} else {
		/* IPV6 Filling */
	}
	ASFIPSecCbFn.pFnAuditLog(pAsfLogInfo);
}

static inline void asfFillLogInfoOut(ASFLogInfo_t *pAsfLogInfo, outSA_t *pSA)
{
	int ii;
	if (!ASFIPSecCbFn.pFnAuditLog)
		return;
	pAsfLogInfo->u.IPSecInfo.ucDirection = 1;
	for (ii = 0; ii < NR_CPUS; ii++) {
		pAsfLogInfo->u.IPSecInfo.ulNumOfPktsProcessed += pSA->ulPkts[ii];
		pAsfLogInfo->u.IPSecInfo.ulNumOfBytesProcessed += pSA->ulBytes[ii];
	}
	pAsfLogInfo->u.IPSecInfo.ucProtocol = pSA->SAParams.ucProtocol;
	pAsfLogInfo->u.IPSecInfo.ulSeqNumber = 0xffff;
	pAsfLogInfo->u.IPSecInfo.ulPathMTU = pSA->ulPathMTU;
	pAsfLogInfo->u.IPSecInfo.ulSPI = pSA->SAParams.ulSPI;
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 0) {
		pAsfLogInfo->u.IPSecInfo.Address.IP_Version = 4;
		pAsfLogInfo->u.IPSecInfo.Address.srcIP.ipv4addr =  pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		pAsfLogInfo->u.IPSecInfo.Address.dstIP.ipv4addr =  pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
	} else {
		/* IPV6 Filling */
	}
	ASFIPSecCbFn.pFnAuditLog(pAsfLogInfo);
}

ASF_uint32_t  asfFlushInSA(SPDInContainer_t *pInContainer,
			   inSA_t *pInSA)
{
	SPDInSelTblIndexLinkNode_t *pNode;
	SPDInSPIValLinkNode_t *pSPINode;
	ASF_boolean_t bFound =  FALSE;

	if (!pInSA) {
		return SECFP_FAILURE;
	}

	for (pNode = pInContainer->pSelIndex; pNode != NULL; pNode = pNode->pNext) {
		if (pInSA->ulSPDSelSetIndex == pNode->ulIndex) {
			bFound = TRUE;
			break;
		}
	}

	if (bFound == TRUE) {
		secfp_deleteInContainerSelList(pInContainer, pNode);
	}

	pSPINode = secfp_findInSPINode(pInContainer, pInSA->SAParams.ulSPI);

	if (pSPINode) {
		secfp_deleteInContainerSPIList(pInContainer, pSPINode);
	}

	if (pInSA->ulSPDSelSetIndexMagicNum == ptrIArray_getMagicNum(&secFP_InSelTable,  pInSA->ulSPDSelSetIndex)) {
		ptrIArray_delete(&secFP_InSelTable, pInSA->ulSPDSelSetIndex, secfp_freeInSelSet);
	}
	secfp_deleteInSAFromSPIList(pInSA);
	return SECFP_SUCCESS;
}

ASF_uint32_t  asfFlushAllOutSAs(ASF_uint32_t ulSPDOutContainerIndex)
{
	int  ii, ulSAIndex, prevSAIndex = 0;
	SPDOutContainer_t *pOutContainer = NULL;
	SPDOutSALinkNode_t *pOutSALinkNode;

	pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
								ulSPDOutContainerIndex));
	if (!pOutContainer) {
		return SECFP_FAILURE;
	}

	if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
		for (ii = 0; ii < SECFP_MAX_DSCP_SA ; ii++) {
			if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
				ulSAIndex = pOutContainer->SAHolder.ulSAIndex[ii];
				pOutContainer->SAHolder.ulSAIndex[ii] = ulMaxSupportedIPSecSAs_g + 1;
				if (prevSAIndex == ulSAIndex)
					continue;
				prevSAIndex = ulSAIndex;
				ptrIArray_delete(&secFP_OutSATable, ulSAIndex, secfp_freeOutSA);
			}
		}
	} else {
		pOutSALinkNode = pOutContainer->SAHolder.pSAList;
		while (pOutSALinkNode != NULL) {
			ulSAIndex = pOutSALinkNode->ulSAIndex;
			secfp_delOutSALinkNode(pOutContainer, pOutSALinkNode);
			ptrIArray_delete(&secFP_OutSATable, ulSAIndex, secfp_freeOutSA);
			pOutSALinkNode = pOutContainer->SAHolder.pSAList;
		}
	}
	return SECFP_SUCCESS;
}

ASF_uint32_t  asfFlushAllInSAs(ASF_uint32_t ulSPDInContainerIndex)
{
	SPDInContainer_t *pInContainer = NULL;
	SPDInSPIValLinkNode_t  *pSPILinkNode;
	inSA_t  *pInSA =  NULL;
	unsigned int ulHashVal;

	pInContainer = (SPDInContainer_t *)(ptrIArray_getData(&(secfp_InDB),
								ulSPDInContainerIndex));
	if (!pInContainer) {
		return SECFP_FAILURE;
	}

	for (pSPILinkNode = pInContainer->pSPIValList; pSPILinkNode != NULL;
		pSPILinkNode = pSPILinkNode->pNext) {
		ulHashVal = secfp_compute_hash(pSPILinkNode->ulSPIVal);
		for (pInSA = secFP_SPIHashTable[ulHashVal].pHeadSA;
			pInSA != NULL; pInSA = pInSA->pNext) {
			asfFlushInSA(pInContainer, pInSA);
		}
	}
	return SECFP_SUCCESS;
}

ASF_uint32_t ASFIPSecFlushContainers(ASF_uint32_t  ulVSGId,
					ASF_uint32_t ulTunnelId)
{
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_softirq(), iRetVal;

	if (ulVSGId > ulMaxVSGs_g) {
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_WARN("Invalid VSG Id = %u",  ulVSGId);
		return SECFP_FAILURE;
	}

	if (ulTunnelId > ulMaxTunnels_g) {
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_WARN("Invalid Tunnel Id = %u",  ulTunnelId);
		return SECFP_FAILURE;
	}

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_PRINT("Tunnel Interface is not in use"\
			" TunnelId=%u, VSGId=%u",  ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}

	/* Deleting OutContainers */
	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	while (pCINode != NULL) {
		/* Deleting All Out SAs */
		iRetVal = asfFlushAllOutSAs(pCINode->ulIndex);
		if (iRetVal == SECFP_FAILURE) {
			ASFIPSEC_WARN("Failure while flushing Out SAs");
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
		secfp_removeCINodeFromTunnelList(ulVSGId,
					ulTunnelId, pCINode, SECFP_OUT);
		ptrIArray_delete(&(secfp_OutDB),
				pCINode->ulIndex, secfp_freeSPDOutContainer);
		pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	}
	/* Deleting InContainers */
	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	while (pCINode != NULL) {
		/* Deleting All In SAs */
		iRetVal = asfFlushAllInSAs(pCINode->ulIndex);
		if (iRetVal == SECFP_FAILURE) {
			ASFIPSEC_WARN("Failure while flushing SAs");
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
		secfp_removeCINodeFromTunnelList(ulVSGId,
					ulTunnelId, pCINode, SECFP_IN);
		ptrIArray_delete(&(secfp_InDB),
			pCINode->ulIndex, secfp_freeSPDInContainer);
		pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	}
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}
EXPORT_SYMBOL(ASFIPSecFlushContainers);

ASF_uint32_t ASFIPSecFlushAllSA(ASF_uint32_t ulVSGId, ASF_uint32_t ulTunnelId)
{
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_softirq(), iRetVal;

	if (ulVSGId > ulMaxVSGs_g) {
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_WARN("Invalid VSG Id = %u",  ulVSGId);
		return SECFP_FAILURE;
	}

	if (ulTunnelId > ulMaxTunnels_g) {
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_WARN("Invalid Tunnel Id = %u",  ulTunnelId);
		return SECFP_FAILURE;
	}

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_DEBUG("Tunnel Interface is not in use"
			" TunnelId=%u, VSGId=%u",  ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}

	/* Deleting All Out SAs in all Out Containers */
	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	while (pCINode != NULL) {
		/* Deleting All Out SAs */
		iRetVal = asfFlushAllOutSAs(pCINode->ulIndex);
		if (iRetVal == SECFP_FAILURE) {
			ASFIPSEC_WARN("Failure while flushing Out SAs");
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
		pCINode = pCINode->pNext;
	}
	/* Deleting All In SAs in all In Containers */
	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	while (pCINode != NULL) {
		/* Deleting All In SAs */
		iRetVal = asfFlushAllInSAs(pCINode->ulIndex);
		if (iRetVal == SECFP_FAILURE) {
			ASFIPSEC_WARN("Failure while flushing SAs");
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
		pCINode = pCINode->pNext;
	}
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}
EXPORT_SYMBOL(ASFIPSecFlushAllSA);

ASF_uint32_t ASFIPSecFlushSAsWithinContainer(ASF_uint32_t ulVSGId,
						ASF_uint32_t ulTunnelId,
						ASF_uint32_t ulSPDOutContainerId,
						ASF_uint32_t ulSPDOutContainerMagicNumber,
						ASF_uint32_t ulSPDInContainerId,
						ASF_uint32_t ulSPDInContainerMagicNumber)
{
	unsigned int iRetVal;
	int bVal = in_softirq();

	if (ulVSGId > ulMaxVSGs_g) {
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_WARN("Invalid VSG Id = %u",  ulVSGId);
		return SECFP_FAILURE;
	}

	if (ulTunnelId > ulMaxTunnels_g) {
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_WARN("Invalid Tunnel Id = %u",  ulTunnelId);
		return SECFP_FAILURE;
	}

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_PRINT("Tunnel Interface is not in use. TunnelId=%u, VSGId=%u",  ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}

	iRetVal = asfFlushAllOutSAs(ulSPDOutContainerId);
	if (iRetVal == SECFP_FAILURE) {
		ASFIPSEC_WARN("Failure in Flushing of Out SAs ");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	iRetVal = asfFlushAllInSAs(ulSPDInContainerId);
	if (iRetVal == SECFP_FAILURE) {
		ASFIPSEC_WARN("Failure in Flushing of In SAs ");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	if (!bVal)
		local_bh_enable();

	return SECFP_SUCCESS;
}
int ASFIPSec4SendIcmpErrMsg (unsigned char *pOrgData,
				unsigned char  ucType,
				unsigned char  ucCode,
				unsigned int   ulUnused,
				unsigned int   ulSNetId)
{
	unsigned char *pData;
	struct rtable *pRt = NULL;
	struct iphdr *iph;
	struct sk_buff *pSkb;
	unsigned char iplen;
	struct flowi fl;
	struct in_device *in_dev;

	pSkb = alloc_skb(1024, GFP_ATOMIC);

	if (pSkb) {
		pSkb->data += 60;
		pSkb->data += ASF_IPLEN + ASF_ICMPLEN;
		iplen = ((*(unsigned char *)(pOrgData) & 0xf) << 2);
		memcpy(pSkb->data, pOrgData, iplen + 8);

		/* Fill Icmp Hdr */
		pSkb->data -= ASF_ICMPLEN;
		pData = pSkb->data;
		pData[0] = ucType;
		pData[1] = ucCode;
		pData[2] = 0;
		pData[3] = 0;
		BUFPUT32(&pData[4], ulUnused);
		BUFPUT16(&pData[2], ASFIPCkSum((char *)pSkb->data, iplen + 8 + ASF_ICMPLEN));
		pSkb->data -= ASF_IPLEN;
		skb_reset_network_header(pSkb);
		skb_set_transport_header(pSkb, ASF_IPLEN);

		iph = ip_hdr(pSkb);
		iph->version = 4;
		iph->ihl = 5;
		iph->check = 0;
		iph->ttl = MAX_TTL;

		iph->daddr = BUFGET32((unsigned char  *)(pOrgData + 12));
		iph->protocol = ASF_IPPROTO_ICMP;
		pSkb->protocol = htons(ASF_IPV4_MAC_CODE);
		iph->tot_len = htons(ASF_IPLEN + ASF_ICMPLEN + iplen + 8);
		pSkb->len = htons(iph->tot_len);
		fl.oif = 0;
		fl.fl4_dst =  iph->daddr;
		fl.fl4_src =  0;
		fl.fl4_tos = 0;
		if (ip_route_output_key(&init_net, &pRt, &fl)) {
			kfree_skb(pSkb);
			return 1;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
		skb_dst_set(pSkb, dst_clone(&pRt->u.dst));
		ip_rt_put(pRt);
		pSkb->dev = skb_dst(pSkb)->dev;
		in_dev = (struct in_device *)(pSkb->dev->ip_ptr);
		if ((in_dev == NULL) || (in_dev->ifa_list == NULL)) {
			kfree_skb(pSkb);
			return 1;
		}
		iph->saddr = htonl(in_dev->ifa_list->ifa_local);
		BUFPUT16(&iph->check, ASFIPCkSum((char *)pSkb->data, ASF_IPLEN));
		if (skb_dst(pSkb)->hh)
			neigh_hh_output(skb_dst(pSkb)->hh, pSkb);
		else if (skb_dst(pSkb)->neighbour)
			skb_dst(pSkb)->neighbour->output(pSkb);
		else
			kfree_skb(pSkb);
#else
		pskb->dev = pSkb->dst->dev;
		ip_rt_put(pRt);
		pSkb->dev = skb_dst(pSkb)->dev;
		in_dev = (struct in_device *)pSkb->dev->ip_ptr;
		if ((in_dev == NULL) || (in_dev->ifa_list == NULL)) {
			kfree_skb(pSkb);
			return 1;
		}
		iph->saddr = htonl(in_dev->ifa_list->ifa_local);
		BUFPUT16(&iph->check, ASFIPCkSum((char *)pSkb->data, ASF_IPLEN));
		if (pSkb->dst->hh)
			neigh_hh_output(pSkb->dst->hh, pSkb);
		else if ((pSkb->dst->neighbour)
			pSkb->dst->neighbour->output(pSb);
		else
			kfree_skb(pSkb);
#endif

	}
	return 0;
}


unsigned short ASFIPCkSum(char *data, unsigned short cnt)
{
	unsigned short cnt1;
	unsigned int sum = 0, csum;
	unsigned short csum1;
	char	*pUp;
	bool  swap = FALSE;

	cnt1 = cnt;
	pUp = (char *)data;
	csum = csum1 = 0;

	if (((int)pUp) & 1) {
	/* Handle odd leading byte */
		if (swap)
			csum = (unsigned char)(*pUp++);
		else
			csum = ((unsigned short)UCHAR(*pUp++) << 8);
		cnt1--;
		swap = !swap;
	}

	if (cnt1 > 1) {
		csum1 = ASFascksum((unsigned short *)pUp, (cnt1  >> 1));
		if (swap)
			csum1 = (csum1 << 8) | (csum1 >> 8);
		csum += csum1;
	}

	if (cnt1 & 1) {
		if (swap)
			csum += UCHAR(pUp[--cnt1]);
		else
			csum += ((unsigned short)UCHAR(pUp[--cnt1]) << 8);
		swap = !swap;
	}
	sum += csum;

	/* Do final end-around carry, complement and return */

	return (unsigned short)(~(ASFIpEac (sum)) & 0xffff);
}

unsigned short ASFascksum(unsigned short *pusData, unsigned short usLen)
{
	unsigned int sum = 0;
	unsigned short csum1, csum2;
	char *pSum;

	for (; usLen; usLen--)
		sum += *pusData++;

	csum1 = ASFIpEac(sum) & 0xffffl;

	pSum = (char *)&csum1;
	csum2 = csum1;

	BUFPUT16(pSum, csum2);
	return csum1;
}

unsigned short ASFIpEac(unsigned int sum)  /* Carries in high order 16 bits */{
	unsigned short csum;

	while ((csum = ((sum >> 16)&0xffffl)) != 0)
		sum = csum + (sum & 0xffffL);

	return (unsigned short) (sum & 0xffffl);  /* Chops to 16 bits */
}

