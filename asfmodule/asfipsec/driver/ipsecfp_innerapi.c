/**************************************************************************
 * Copyright 2011-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecfp_innerapi.c
 * Description: Contains the routines for ipsec inner API implementation
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *		Hemant Agrawal <hemant@freescale.com>
 *
 */
/* History
 * Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#include <linux/ip.h>
#include <net/ip.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <linux/version.h>
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfterm.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include <net/dst.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include "ipseccmn.h"

#define ASF_SECFP_BLOB_TIME_INTERVAL	1
#define ASF_SECFP_NUM_RQ_ENTRIES	256

/* Data Structure initialization */
/* Inbound SA SPI Table */
DEFINE_SPINLOCK(secFP_InSATableLock);
inSAList_t *secFP_SPIHashTable;

unsigned int ulLastOutSAChan_g;
unsigned int ulLastInSAChan_g = 1;

/* Global Outbound SPD Container */
/* SPDOutContainer_t */
ptrIArry_tbl_t secfp_OutDB;
/*SPDInContainer_t */
ptrIArry_tbl_t secfp_InDB;

/* An array of outbound SAs */
spinlock_t outSATableBitMapLock;

ptrIArry_tbl_t secFP_OutSATable;

/* Pointer table to hold inbound selector sets */
ptrIArry_tbl_t secFP_InSelTable;

/* An array of VSG based Tunnel interfaces and lock for protecting container
indices within the tunnel */
SecTunnelIface_t **secFP_TunnelIfaces;
DEFINE_SPINLOCK(secfp_TunnelIfaceCIIndexListLock);

static unsigned int SPDCILinkNodePoolId_g = 0xFFFFFFFF;
static unsigned int SPDOutContainerPoolId_g = 0xFFFFFFFF;
static unsigned int OutSelListPoolId_g = 0xFFFFFFFF;
static unsigned int SASelPoolId_g = 0xFFFFFFFF;
static unsigned int OutSAPoolId_g = 0xFFFFFFFF;
static unsigned int OutSAl2blobPoolId_g = 0xFFFFFFFF;
static unsigned int SPDInContainerPoolId_g = 0xFFFFFFFF;
static unsigned int SPDInSelTblIndexLinkNodePoolId_g = 0xFFFFFFFF;
static unsigned int SPDInSPIValLinkNodePoolId_g = 0xFFFFFFFF;
static unsigned int InSelListPoolId_g = 0xFFFFFFFF;
static unsigned int InSAPoolId_g = 0xFFFFFFFF;
static unsigned int SPDOutSALinkNodePoolId_g = 0xFFFFFFFF;


#define ASF_IPSEC4_GET_START_ADDR(addr, maskbits)\
 ((maskbits) == 32) ? (addr) : (((addr)&(0xffffffff << (32-(maskbits)))) + 1)

#define ASF_IPSEC4_GET_END_ADDR(addr, maskbits)\
 ((maskbits) == 32) ? (addr) : (((addr)|(0xffffffff >> (maskbits))) - 1)

#define SHARED_GWV4_OFFSET(arg) (12 + offsetof(struct iphdr, arg))

#ifdef ASF_IPV6_FP_SUPPORT
#define SHARED_GWV6_OFFSET(arg) (12 + offsetof(struct ipv6hdr, arg))
#endif


/************* Beginning of API Function and inner functions used by API******
 * All APIs to normal path return SECFP_SUCCESS upon SUCCESS and
 * SECFP_FAILURE upon FAILURE
 */
/* Initialization routines/De-Initialization routines */

/* Initialization Tunnel Interfaces */
static int secfp_InitTunnelIfaces(void)
{
	int ii;
	secFP_TunnelIfaces = kzalloc(sizeof(SecTunnelIface_t *) * ulMaxVSGs_g,
		GFP_KERNEL);
	if (secFP_TunnelIfaces == NULL) {
		ASFIPSEC_ERR("secfp_TunnelIfaces alloc failed");
		return 1;
	}
	for (ii = 0; ii < ulMaxVSGs_g; ii++) {
		secFP_TunnelIfaces[ii] = kzalloc(sizeof(SecTunnelIface_t)
				* ulMaxTunnels_g, GFP_KERNEL);
		if (!secFP_TunnelIfaces[ii]) {
			ASFIPSEC_ERR("secfp_TunnelIfaces alloc1 failed");
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
	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSupportedIPSecSAs_g),
					GFP_KERNEL);
#endif
	if (pNode) {
		ptrIArray_setup(&secFP_OutSATable, pNode,
				ulMaxSupportedIPSecSAs_g, 1);
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
	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSPDContainers_g),
			GFP_KERNEL);
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

/* In Container table initialization/de-initialization */
static int secfp_InitInContainerTable(void)
{
	ptrIArry_nd_t *pNode;
	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSPDContainers_g),
			GFP_KERNEL);
	if (pNode) {
		ptrIArray_setup(&(secfp_InDB), pNode, ulMaxSPDContainers_g, 1);
		return 0;
	}
	return 1;
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

	pNode = kzalloc((sizeof(ptrIArry_nd_t) * ulMaxSupportedIPSecSAs_g),
			GFP_KERNEL);
	if (pNode) {
		ptrIArray_setup(&secFP_InSelTable, pNode,
				ulMaxSupportedIPSecSAs_g, 1);
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
	secFP_SPIHashTable = (inSAList_t *) ioremap_flags(addr,
				(sizeof(inSA_t *) * usMaxInSAHashTaleSize_g),
				PAGE_KERNEL | _PAGE_COHERENT);
	memset(secFP_SPIHashTable, 0,
		sizeof(inSA_t *) * usMaxInSAHashTaleSize_g);

#else
	secFP_SPIHashTable = kzalloc(sizeof(inSAList_t *)
				* usMaxInSAHashTaleSize_g, GFP_KERNEL);
#endif
	if (secFP_SPIHashTable)
		return 0;

	return 1;
}

unsigned int asfsecfpBlobTmrCb(unsigned int ulVSGId,
				unsigned int ulIndex, unsigned int ulMagicNum,
				unsigned int ulSPDContainerIndex,
				unsigned int bIpv6)
{
	outSA_t *pSA;
	ASF_IPSecTunEndAddr_t TunAddress;

	pSA = ptrIArray_getData(&secFP_OutSATable, ulIndex);

	if (!pSA) {
		ASFIPSEC_WARN("SA not available index = %d", ulIndex);
		return 1;
	}
	ASFIPSEC_DEBUG("SEC L2blob Timer pSA = %x, SPI=0x%x",
				pSA, pSA->SAParams.ulSPI);

	ASFIPSEC_DEBUG("SEC L2blob Magic(index=%d) %d = %d ", ulIndex,
		ptrIArray_getMagicNum(&secFP_OutSATable, ulIndex),
		ulMagicNum);
	if (ASFIPSecCbFn.pFnRefreshL2Blob
		&& (ptrIArray_getMagicNum(&secFP_OutSATable, ulIndex) ==
		ulMagicNum)) {
#ifdef ASF_IPV6_FP_SUPPORT
		if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
		TunAddress.IP_Version = 4;
		TunAddress.dstIP.bIPv4OrIPv6 = 0;
		TunAddress.srcIP.bIPv4OrIPv6 = 0;
		TunAddress.dstIP.ipv4addr =
			pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
		TunAddress.srcIP.ipv4addr =
			pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
#ifdef ASF_IPV6_FP_SUPPORT
		} else {
			TunAddress.IP_Version = 6;
			TunAddress.dstIP.bIPv4OrIPv6 = 1;
			TunAddress.srcIP.bIPv4OrIPv6 = 1;
			memcpy(TunAddress.dstIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
			memcpy(TunAddress.srcIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
		}
#endif
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
				ASF_SECFP_BLOB_TIME_INTERVAL,
				ASF_SECFP_NUM_RQ_ENTRIES) == 1) {
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
static int secfp_InitConfigIdentitiy(void)
{
	pulVSGMagicNumber = kzalloc(sizeof(unsigned int) * ulMaxVSGs_g,
					GFP_KERNEL);
	if (pulVSGMagicNumber == NULL) {
		ASFIPSEC_ERR("Memory allocation failed for pulVSGMagicNumber");
		return 1;
	}
	pulVSGL2blobMagicNumber = kzalloc(sizeof(unsigned int) * ulMaxVSGs_g,
					GFP_KERNEL);
	if (pulVSGL2blobMagicNumber == NULL) {
		ASFIPSEC_ERR("Memory allocation fail for pulVSGL2blobMagicNo");
		return 1;
	}

	return 0;
}

static void secfp_DeInitInSATable(void)
{
#ifndef SECFP_USE_L2SRAM
	kfree(secFP_SPIHashTable);
#endif
}

static void secfp_DeInitMemPools(void)
{
	if ((SPDOutSALinkNodePoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(SPDOutSALinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
				" SPDOutSALinkNodePoolId_g");
	}
	if ((InSAPoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(InSAPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for InSAPoolId_g");
	}
	if ((InSelListPoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(InSelListPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for InSelListPoolId_g");
	}
	if ((SPDInSPIValLinkNodePoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(SPDInSPIValLinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
				" SPDInSPIValLinkNodePoolId_g");
	}
	if ((SPDInSelTblIndexLinkNodePoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(SPDInSelTblIndexLinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
			"SPDInSelTblIndexLinkNodePoolId_g");
	}
	if ((SPDInContainerPoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(SPDInContainerPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
				" SPDInContainerPoolId_g");
	}
	if (OutSAl2blobPoolId_g != 0xFFFFFFFF) {
		asfTimerWheelDeInit(ASF_SECFP_BLOB_TMR_ID, 0);
		if (asfDestroyPool(OutSAl2blobPoolId_g) != 0)
			ASFIPSEC_ERR("asfDestroyPool failed for"
				" OutSAl2blobPoolId_g");
	}

	synchronize_rcu();

	if ((OutSAPoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(OutSAPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for OutSAPoolId_g");
	}
	if ((SASelPoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(SASelPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for SASelPoolId_g");
	}
	if ((OutSelListPoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(OutSelListPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for OutSelListPoolId_g");
	}
	if ((SPDOutContainerPoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(SPDOutContainerPoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for"
			" SPDOutContainerPoolId_g");
	}
	if ((SPDCILinkNodePoolId_g != 0xFFFFFFFF)
		&& asfDestroyPool(SPDCILinkNodePoolId_g) != 0) {
		ASFIPSEC_ERR("asfDestroyPool failed for SPDCILinkNodePoolId_g");
	}
	ASFIPSEC_PRINT("Waiting for all CPUs to finish existing RCU callback!");
	synchronize_rcu();
}

void secfp_DeInitConfigIdentitiy(void)
{
	kfree(pulVSGMagicNumber);
	pulVSGMagicNumber = NULL;

	kfree(pulVSGL2blobMagicNumber);
	pulVSGL2blobMagicNumber = NULL;

}

void secfp_data_deinit(void)
{
	secfp_DeInitInSelTable();
	secfp_DeInitInSATable();
	secfp_DeInitMemPools();
	secfp_DeInitConfigIdentitiy();
	secfp_DeInitOutContainerTable();
	secfp_DeInitInContainerTable();
	secfp_DeInitTunnelIfaces();
	secfp_DeInitOutSATable();
}

int secfp_data_init(void)
{
	/* Global SA Ptr Array Table */
	if (secfp_InitOutSATable()) {
		secfp_deInit();
		ASFIPSEC_ERR("SEC_FP Global SA Table Out failed");
		return SECFP_FAILURE;
	}
	if (secfp_InitTunnelIfaces()) {
		secfp_deInit();
		ASFIPSEC_ERR("InitTunnelIfaces failed");
		return SECFP_FAILURE;
	}

	/* Global SPD Container Table */
	if (secfp_InitOutContainerTable()) {
		secfp_deInit();
		ASFIPSEC_ERR("Container Table Out failed");
		return SECFP_FAILURE;
	}

	if (secfp_InitInContainerTable()) {
		secfp_deInit();
		ASFIPSEC_ERR("Init In Container Table failed");
		return SECFP_FAILURE;
	}

	if (secfp_InitInSelTable()) {
		secfp_deInit();
		ASFIPSEC_ERR("Selector Table In failed");
		return SECFP_FAILURE;
	}

	if (secfp_InitInSATable()) {
		secfp_deInit();
		ASFIPSEC_ERR("SPI Table failed");
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
	return SECFP_SUCCESS;
}

/* Memory Allocation/Freeup routines */
/* These Container Index Link Nodes hold
the container indices within the tunnel */
static inline struct SPDCILinkNode_s *secfp_allocSPDCILinkNode(void)
{
	struct SPDCILinkNode_s *pNode;
	char bHeap;
	pNode = (struct SPDCILinkNode_s *) asfGetNode(
			SPDCILinkNodePoolId_g, &bHeap);
	if (pNode && bHeap)
		pNode->bHeap = bHeap;

	return pNode;
}

static void secfp_freeSDPCILinkNode(struct rcu_head *pData)
{
	struct SPDCILinkNode_s *pNode = (struct SPDCILinkNode_s *) (pData);
	asfReleaseNode(SPDCILinkNodePoolId_g, pNode, pNode->bHeap);

}

/* Out container alloc/free routine */
static inline SPDOutContainer_t *secfp_allocSPDOutContainer(void)
{
	SPDOutContainer_t *pContainer;
	char bHeap;

	pContainer = (SPDOutContainer_t *) asfGetNode(
			SPDOutContainerPoolId_g, &bHeap);
	if (pContainer && bHeap)
		pContainer->bHeap = bHeap;

	return pContainer;
}

static void secfp_freeSPDOutContainer(struct rcu_head *rcu)
{
	SPDOutContainer_t *pContainer = (SPDOutContainer_t *) rcu;
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
static void secfp_addOutSelSet(outSA_t *pSA,
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
		ASFIPSEC_WARN("Allocation of SASelList failed");
		return;
	}
	if (bHeap)
		pSA->pSelList->bHeap = bHeap;

	pSA->pSelList->ucSelFlags = ucSelFlags;
	pSA->pSelList->usDscpStart = usDscpStart;
	pSA->pSelList->usDscpEnd = usDscpEnd;

	/* Allocate and copy the source selector list */
	for (pPrevSel = NULL, pTmpSel = pSrcSel;
		pTmpSel != NULL;
		pTmpSel = pTmpSel->pNext) {
		if (pTmpSel == pSrcSel)
			/* Memory for the 1st selector is
			allocated as part of pSAList*/
			pNewSel = &(pSA->pSelList->srcSel);
		else {
			pNewSel = (struct SASel_s *)
					asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel && bHeap)
				pNewSel->bHeap = bHeap;
		}
		if (pNewSel) {
			for (ii = 0; ii < pTmpSel->ucNumSelectors; ii++) {
				memcpy(&(pNewSel->selNodes[ii]),
					&(pTmpSel->selNodes[ii]),
					sizeof(struct selNode_s));
			}
			pNewSel->ucNumSelectors = pTmpSel->ucNumSelectors;

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
		if (pTmpSel == pDstSel)
			/* Memory for the 1st selector is allocated
			as part of pSAList*/
			pNewSel = &(pSA->pSelList->destSel);
		else {
			pNewSel = (struct SASel_s *)
					asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel && bHeap)
				pNewSel->bHeap = bHeap;
		}
		if (pNewSel) {
			for (ii = 0; ii < pTmpSel->ucNumSelectors; ii++) {
				memcpy(&(pNewSel->selNodes[ii]),
					&(pTmpSel->selNodes[ii]),
					sizeof(struct selNode_s));
			}
			pNewSel->ucNumSelectors = pTmpSel->ucNumSelectors;

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
	if (pSA && bHeap)
		pSA->bHeap = bHeap;

	return pSA;
}

static void secfp_freeOutSA(struct rcu_head *pData)
{
	outSA_t *pSA = (outSA_t *) pData;
	/* We cannot free the skb now, as it is submitted to h/w */
	/*h/w cb will check this flag */
	if (pSA->pL2blobTmr)
		asfTimerStop(ASF_SECFP_BLOB_TMR_ID, 0, pSA->pL2blobTmr);

	if (pSA->pSelList)
		secfp_cleanupSelList(pSA->pSelList);

#ifdef CONFIG_ASF_SEC4x
	kfree(pSA->ctx.key);
	kfree(pSA->ctx.sh_desc_mem);
#endif
	asfReleaseNode(OutSAPoolId_g, pSA, pSA->bHeap);
}

/* In container alloc/free routine */
static inline SPDInContainer_t *secfp_allocSPDInContainer(void)
{
	SPDInContainer_t *pContainer;
	char bHeap;
	pContainer = (SPDInContainer_t *)
		asfGetNode(SPDInContainerPoolId_g, &bHeap);
	if (pContainer && bHeap)
		pContainer->bHeap = bHeap;
	return pContainer;
}

static void secfp_freeSPDInContainer(struct rcu_head *rcu)
{
	SPDInContainer_t *pContainer = (SPDInContainer_t *) rcu;
	asfReleaseNode(SPDInContainerPoolId_g, pContainer, pContainer->bHeap);

}

/* Link Nodes that contain index to the Selector Set in the
Selector set table for In containers/SAs */
static void secfp_freeLinkNode(struct rcu_head *rcu)
{
	SPDInSelTblIndexLinkNode_t *pNode = (SPDInSelTblIndexLinkNode_t *) rcu;
	asfReleaseNode(SPDInSelTblIndexLinkNodePoolId_g, pNode, pNode->bHeap);
}

static SPDInSelTblIndexLinkNode_t *secfp_allocLinkNode(void)
{
	SPDInSelTblIndexLinkNode_t *pNode;
	char bHeap;

	pNode = (SPDInSelTblIndexLinkNode_t *)
			asfGetNode(SPDInSelTblIndexLinkNodePoolId_g, &bHeap);
	if (pNode && bHeap)
		pNode->bHeap = bHeap;

	return pNode;
}

/* SPI values are held in the SPD In container. Used for SPI verification */
static SPDInSPIValLinkNode_t *secfp_allocSPILinkNode(void)
{
	SPDInSPIValLinkNode_t *pNode;
	char bHeap;

	pNode = (SPDInSPIValLinkNode_t *) asfGetNode(
		SPDInSPIValLinkNodePoolId_g, &bHeap);
	if (pNode && bHeap) {
		pNode->bHeap = bHeap;
	}
	return pNode;
}

static void secfp_freeSPILinkNode(struct rcu_head *pNode)
{
	SPDInSPIValLinkNode_t *pLinkNode = (SPDInSPIValLinkNode_t *) pNode;
	asfReleaseNode(SPDInSPIValLinkNodePoolId_g,
		pLinkNode, pLinkNode->bHeap);
}

/* Updates the selector set within the In Container;
Called when SA is allocated */
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
	call_rcu((struct rcu_head *) pNode, secfp_freeLinkNode);
	spin_unlock(&pContainer->spinlock);
}

/* Updates SPI value index in a linked node in the SDD In container
(called when SA is allocated */
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
inline SPDInSPIValLinkNode_t *secfp_findInSPINode(SPDInContainer_t *pContainer,
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
	call_rcu((struct rcu_head *) pNode, secfp_freeSPILinkNode);
	spin_unlock(&pContainer->spinlock);
}

/* Free/alloc functions for In Selector sets */
void secfp_freeInSelSet(struct rcu_head *pData)
{
	InSelList_t *pList = (InSelList_t *) (pData);
	SASel_t *pTempSel, *pTempNextSel;

	if (pList) {
		pTempSel = (pList->pSrcSel);
		while (pTempSel) {
			pTempNextSel = pTempSel->pNext;
			asfReleaseNode(SASelPoolId_g, pTempSel,
				pTempSel->bHeap);
			pTempSel = pTempNextSel;
		}
		pTempSel = (pList->pDestSel);
		while (pTempSel) {
			pTempNextSel = pTempSel->pNext;
			asfReleaseNode(SASelPoolId_g, pTempSel,
				pTempSel->bHeap);
			pTempSel = pTempNextSel;
		}
		asfReleaseNode(InSelListPoolId_g, pList, pList->bHeap);
	}
}
/* This function secfp_createInSelSet creates and populates Selector set */
SPDInSelTblIndexLinkNode_t *secfp_updateInSelSet(
			SPDInContainer_t	*pContainer,
			SASel_t		*pSrcSel,
			SASel_t		*pDstSel,
			unsigned int		ucSelFlags)
{
	InSelList_t *pList;
	SASel_t *pTempSel;
	SASel_t *pNewSel, *pPrevSel;
	bool bFail;
	SPDInSelTblIndexLinkNode_t *pNode;
	unsigned int ulIndex;
	char bHeap;

	pList = (InSelList_t *) asfGetNode(InSelListPoolId_g, &bHeap);
	if (pList) {
		if (bHeap)
			pList->bHeap = bHeap;
		pList->ucSelFlags = ucSelFlags;
		pPrevSel = NULL;
		bFail = ASF_FALSE;
		for (pTempSel = pSrcSel; pTempSel != NULL;
				pTempSel = pTempSel->pNext) {
			pNewSel = (SASel_t *) asfGetNode(SASelPoolId_g, &bHeap);
			if (pNewSel) {
				if (bHeap)
					pNewSel->bHeap = bHeap;
				memcpy(pNewSel, pTempSel, sizeof(SASel_t));
				pNewSel->pPrev = NULL;
				pNewSel->pNext = NULL;
			} else {
				bFail = ASF_TRUE;
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
		if (bFail != ASF_TRUE) {
			pPrevSel = NULL;
			for (pTempSel = pDstSel; pTempSel != NULL;
				pTempSel = pTempSel->pNext) {
				pNewSel = (SASel_t *) asfGetNode(SASelPoolId_g,
							&bHeap);
				if (pNewSel) {
					if (bHeap)
						pNewSel->bHeap = bHeap;
					memcpy(pNewSel, pTempSel,
							sizeof(SASel_t));
					pNewSel->pPrev = NULL;
					pNewSel->pNext = NULL;
				} else {
					bFail = ASF_TRUE;
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

	if (bFail != ASF_TRUE) {
		pNode = secfp_allocLinkNode();
		if (pNode) {
			ulIndex = ptrIArray_add(&secFP_InSelTable, pList);
			if (ulIndex != secFP_InSelTable.nr_entries) {
				pNode->ulIndex = ulIndex;
				/* Success condition */
				secfp_updateInContainerSelList(pContainer,
								pNode);
			} else {
				GlobalErrors.ulInSAFull++;
				ASFIPSEC_WARN("Could not find index to hold"
					"Selector:Maximum count reached ");
				secfp_freeInSelSet((struct rcu_head *) pList);
				secfp_freeLinkNode((struct rcu_head *) pNode);
				return NULL;
			}
		} else {
			GlobalErrors.ulResourceNotAvailable++;
			ASFIPSEC_WARN("Failure in allocating Link node");
			secfp_freeInSelSet((struct rcu_head *) pList);
			return NULL;
		}
	} else {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_WARN("Failure in setting up selector set node");
		/* Need to clean up */
		secfp_freeInSelSet((struct rcu_head *) pList);
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
	char bHeap;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	pSA = (inSA_t *) asfGetNode(InSAPoolId_g, &bHeap);
	if (pSA) {
		if (bHeap)
			pSA->bHeap = bHeap;
		if (AntiReplayWin) {
			pSA->pWinBitMap = kzalloc((AntiReplayWin/32 *
					sizeof(unsigned int)), flags);
			if (!pSA->pWinBitMap) {
				ASFIPSEC_WARN("Memory allocation for"
					"Replay Window failed");
				asfReleaseNode(InSAPoolId_g, pSA, pSA->bHeap);
				return NULL;
			}
		}
	}
	return pSA;
}

static void secfp_freeInSA(struct rcu_head *rcu_data)
{
	inSA_t *pSA = (inSA_t *) rcu_data;
	/* We cannot free the skb now, as it is submitted to h/w */
	/*h/w cb will check this flag */
	kfree(pSA->pWinBitMap);

#ifdef CONFIG_ASF_SEC4x
	kfree(pSA->ctx.key);
	kfree(pSA->ctx.sh_desc_mem);
#endif
	asfReleaseNode(InSAPoolId_g, pSA, pSA->bHeap);
}


/* Appends SA to the SPI based hash list */
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
			secFP_SPIHashTable[pSA->ulHashVal].pHeadSA =
					pTempSA->pNext;
		} else {
			if (pTempSA->pNext)
				pTempSA->pNext->pPrev = pTempSA->pPrev;
			if (pTempSA->pPrev)
				pTempSA->pPrev->pNext = pTempSA->pNext;
		}
		call_rcu((struct rcu_head *) pTempSA, secfp_freeInSA);
		spin_unlock_bh(&secFP_InSATableLock);
	}
}


/* SELECTOR SET Related functions: Currently Stubbed out */
/* Functions to
 a) find matching selector set based SA
 b) Add selector set based SA
 b) Delete selector set based SA
 */
SPDOutSALinkNode_t *secfp_findOutSALinkNode(SPDOutContainer_t *pContainer,
					ASF_IPAddr_t	daddr,
					unsigned char	ucProtocol,
					unsigned int	ulSPI)
{
	SPDOutSALinkNode_t *pOutSALinkNode;
	outSA_t		*pSA;
	bool		bMatchFound = ASF_FALSE;
#ifdef ASF_IPV6_FP_SUPPORT
	if (!daddr.bIPv4OrIPv6) {
#endif
	for (pOutSALinkNode = pContainer->SAHolder.pSAList;
		pOutSALinkNode != NULL;
		pOutSALinkNode = pOutSALinkNode->pNext) {
		pSA = (outSA_t *) ptrIArray_getData(&secFP_OutSATable,
			pOutSALinkNode->ulSAIndex);
		if ((pSA) &&
			(pSA->SAParams.ulSPI == ulSPI) &&
			(pSA->SAParams.tunnelInfo.addr.iphv4.daddr ==
				daddr.ipv4addr) &&
			(pSA->SAParams.ucProtocol == ucProtocol)) {

			bMatchFound = ASF_TRUE;
			break;
			}
		}
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		for (pOutSALinkNode = pContainer->SAHolder.pSAList;
				pOutSALinkNode != NULL;
				pOutSALinkNode = pOutSALinkNode->pNext) {
			pSA = (outSA_t *) ptrIArray_getData(&secFP_OutSATable,
				pOutSALinkNode->ulSAIndex);
			if ((pSA) && (pSA->SAParams.ulSPI == ulSPI) &&
				(pSA->SAParams.ucProtocol == ucProtocol) &&
				(!memcmp(daddr.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr,
				sizeof(struct in6_addr)))) {

				bMatchFound = ASF_TRUE;
				break;
			}
		}
	}
#endif
	if (bMatchFound == ASF_TRUE)
		return pOutSALinkNode;
	return NULL;
}


SPDOutSALinkNode_t *secfp_cmpPktSelWithSelSet(
				SPDOutContainer_t *pContainer,
				struct sk_buff *skb)
{
	SASel_t *pSel;
	struct selNode_s *pSelNode;
	unsigned char ucMatchSrcSelFlag, ucMatchDstSelFlag;
	unsigned char protocol, tos;
	struct iphdr *iph = ip_hdr(skb);
	unsigned short int *ptrhdrOffset;
	unsigned short int sport, dport;
	bool bMatchFound = ASF_FALSE;
	SPDOutSALinkNode_t *pSALinkNode;
	outSA_t *pSA;
	int ii;
#ifdef ASF_IPV6_FP_SUPPORT
	struct ipv6hdr *ipv6h = (struct ipv6hdr *) iph;
	if (iph->version == 4) {
#endif
	ptrhdrOffset = (unsigned short int *) (&(skb->data[(iph->ihl*4)]));
		protocol = iph->protocol;
		tos = iph->tos;
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		ptrhdrOffset = (unsigned short int *)
			(&(skb->data[SECFP_IPV6_HDR_LEN]));
		protocol = ipv6h->nexthdr;
		ipv6_traffic_class(tos, ipv6h);
	}
#endif
	sport = *ptrhdrOffset;
	dport = *(ptrhdrOffset+1);

	for (pSALinkNode = pContainer->SAHolder.pSAList;
		pSALinkNode != NULL; pSALinkNode = pSALinkNode->pNext) {
		pSA = (outSA_t *) ptrIArray_getData(&secFP_OutSATable,
					pSALinkNode->ulSAIndex);
		if ((pSA) && (pSA->pSelList)) {
			ucMatchSrcSelFlag = ucMatchDstSelFlag = 0;

			for (pSel = &(pSA->pSelList->srcSel);
				pSel != NULL; pSel = pSel->pNext) {
				for (ii = 0; ii < pSel->ucNumSelectors; ii++) {
					pSelNode = &(pSel->selNodes[ii]);
					ucMatchSrcSelFlag = 0;

					if (pSA->pSelList->ucSelFlags & SECFP_SA_XPORT_SELECTOR) {
						if (protocol == pSelNode->proto)
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
#ifdef ASF_IPV6_FP_SUPPORT
						if (pSelNode->IP_Version == 4) {
#endif
							if (iph->version == 4 &&
								(iph->saddr >= pSelNode->ipAddrRange.v4.start) &&
								(iph->saddr <= pSelNode->ipAddrRange.v4.end)) {
							ucMatchSrcSelFlag |= SECFP_SA_SRCIPADDR_SELECTOR;
						} else
							continue;
#ifdef ASF_IPV6_FP_SUPPORT
						} else {
							if (iph->version == 6 &&
								(memcmp(ipv6h->saddr.s6_addr,
									pSelNode->ipAddrRange.v6.start.u.b_addr, 16) >= 0) &&
								(memcmp(ipv6h->saddr.s6_addr,
									pSelNode->ipAddrRange.v6.end.u.b_addr, 16) <= 0)) {
								ucMatchSrcSelFlag |= SECFP_SA_SRCIPADDR_SELECTOR;
							} else
								continue;
						}
#endif
					}
					bMatchFound = ASF_TRUE;
					break;
				}
				if (bMatchFound == ASF_TRUE)
					break;
			}
			bMatchFound = ASF_FALSE;
			for (pSel = &(pSA->pSelList->destSel);
				pSel != NULL; pSel = pSel->pNext) {
				for (ii = 0; ii < pSel->ucNumSelectors; ii++) {
					pSelNode = &(pSel->selNodes[ii]);
					ucMatchDstSelFlag = 0;

					if (pSA->pSelList->ucSelFlags & SECFP_SA_XPORT_SELECTOR) {
						if (protocol == pSelNode->proto)
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
#ifdef ASF_IPV6_FP_SUPPORT
						if (pSelNode->IP_Version == 4) {
#endif
							if (iph->version == 4 &&
								(iph->daddr >= pSelNode->ipAddrRange.v4.start) &&
								(iph->daddr <= pSelNode->ipAddrRange.v4.end)) {
								ucMatchDstSelFlag |= SECFP_SA_DESTIPADDR_SELECTOR;
							} else
								continue;
#ifdef ASF_IPV6_FP_SUPPORT
						} else {
							if (iph->version == 6 &&
								(memcmp(ipv6h->daddr.s6_addr,
									pSelNode->ipAddrRange.v6.start.u.b_addr, 16) >= 0) &&
								(memcmp(ipv6h->daddr.s6_addr,
									pSelNode->ipAddrRange.v6.end.u.b_addr, 16) <= 0)) {
								ucMatchDstSelFlag |= SECFP_SA_DESTIPADDR_SELECTOR;
							} else
								continue;
						}
#endif
					}

					bMatchFound = ASF_TRUE;
					break;
				}
				if (bMatchFound == ASF_TRUE)
					break;
			}
			if (pSA->pSelList->ucSelFlags & SECFP_SA_DSCP_SELECTOR) {
				if ((tos >= pSA->pSelList->usDscpStart) &&
					(tos <= pSA->pSelList->usDscpEnd))
					ucMatchSrcSelFlag |= SECFP_SA_DSCP_SELECTOR;
			}
			if ((ucMatchSrcSelFlag | ucMatchDstSelFlag)
				== pSA->pSelList->ucSelFlags)
					return pSALinkNode;
		}
	}
	return NULL;
}

/* Checks for SPI based matching entry */
inSA_t *secfp_findInv4SA(unsigned int ulVSGId,
		unsigned char ucProto,
		unsigned long int ulSPI,
		unsigned int daddr,
		unsigned int *pHashVal)
{
	inSA_t *pSA = NULL;

	if (*pHashVal == usMaxInSAHashTaleSize_g) {
		*pHashVal = secfp_compute_hash(ulSPI);
	}

	ASFIPSEC_DEBUG("findInv4SA hashVal = %d, ulSPI=0x%x, daddr=%x ",
			*pHashVal, (unsigned int) ulSPI, daddr);
	ASFIPSEC_DEBUG("ucProto = %d", ucProto);

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

#ifdef ASF_IPV6_FP_SUPPORT
inSA_t *secfp_findInv6SA(unsigned int ulVSGId,
		unsigned char ucProto,
		unsigned long int ulSPI,
		unsigned int *daddr,
		unsigned int *pHashVal)
{
	inSA_t *pSA = NULL;

	if (*pHashVal == usMaxInSAHashTaleSize_g)
		*pHashVal = secfp_compute_hash(ulSPI);

	ASFIPSEC_DEBUG("hashVal = %d, ulSPI=0x%x, daddr=%x:%x:%x:%x ",
		*pHashVal, (unsigned int) ulSPI,
		daddr[0], daddr[1], daddr[2], daddr[3]);
	ASFIPSEC_DEBUG("ucProto = %d", ucProto);

	for (pSA = secFP_SPIHashTable[*pHashVal].pHeadSA;
		pSA != NULL; pSA = pSA->pNext) {
		ASFIPSEC_DEBUG("findInv6SA SA in table ulSPI=0x%x, \
				daddr=%x:%x:%x:%x proto = %d",
				pSA->SAParams.ulSPI,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr[0],
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr[1],
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr[2],
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr[3],
				pSA->SAParams.ucProtocol);
		if ((ulSPI == pSA->SAParams.ulSPI)
				&& (ucProto == pSA->SAParams.ucProtocol)
				&& (!memcmp(daddr,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr,
				sizeof(struct in6_addr)))
			&& (ulVSGId == pSA->ulVSGId))
			break;
	}
	return pSA;
}
#endif

inSA_t *secfp_findInSA(unsigned int ulVSGId,
		unsigned char ucProto,
		unsigned long int ulSPI,
		ASF_IPAddr_t daddr, unsigned int *pHashVal)
{
#ifdef ASF_IPV6_FP_SUPPORT
	if (daddr.bIPv4OrIPv6)
		return secfp_findInv6SA(ulVSGId, ucProto, ulSPI,
				daddr.ipv6addr, pHashVal);
	else
#endif
		return secfp_findInv4SA(ulVSGId, ucProto, ulSPI,
				daddr.ipv4addr, pHashVal);
}

/*
 * Function finds the right SA for the given packet. Logic
 * already explained in the beginning of the file
 */
outSA_t *secfp_findOutSA(
		unsigned int ulVsgId,
		ASFFFPIpsecInfo_t *pSecInfo,
		struct sk_buff *skb,
		unsigned char tos,
		SPDOutContainer_t **ppContainer,
		ASF_boolean_t *pbRevalidate)
{

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
			*pbRevalidate = ASF_TRUE;
			return NULL;
		}
		pSecInfo->outContainerInfo.ulTimeStamp = ulTimeStamp_g;
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	*ppContainer = pContainer = (SPDOutContainer_t *)
		ptrIArray_getData(&(secfp_OutDB),
			pSecInfo->outContainerInfo.ulSPDContainerId);

	ASFIPSEC_DEBUG("Valid Container found pContainer = 0x%x",
			(unsigned int) pContainer);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	/* Check the container magic value */
	if (ptrIArray_getMagicNum(&(secfp_OutDB),
				pSecInfo->outContainerInfo.ulSPDContainerId) !=
		pSecInfo->outContainerInfo.ulSPDMagicNumber) {
		ASFIPSEC_WARN("SPD - Magic Number mismatch ");
		/* Send packet to control plane : SPD pointer Not Available */
		return NULL;
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/

	ASFIPSEC_DEBUG("SA within Container : Container Matched SA=%d ",
		pSecInfo->outSAInfo.ulSAIndex);
	if ((pSecInfo->outSAInfo.ulSAIndex == ulMaxSupportedIPSecSAs_g) ||
		(ptrIArray_getMagicNum(&secFP_OutSATable,
			pSecInfo->outSAInfo.ulSAIndex)
		!= pSecInfo->outSAInfo.ulSAMagicNumber)) {
		/* Either we don't have the SA or our magic nums are different*/
		if (pContainer->SPDParams.bOnlySaPerDSCP) {
			if (pContainer->SAHolder.ulSAIndex[tos] !=
					ulMaxSupportedIPSecSAs_g) {
				/* We don't have the SA yet,
				Get it from global table */
				pSecInfo->outSAInfo.ulSAIndex =
					pContainer->SAHolder.ulSAIndex[tos];

				ASFIPSEC_DEBUG("Found SA ");
			} else {
				ASFIPSEC_DEBUG("Matching DSCP Based SA"\
					"could not be found");
				return NULL;

			}
		} else {
			/* Handle SA Selector case */
			pOutSALinkNode = secfp_cmpPktSelWithSelSet(pContainer,
							skb);
			if (!pOutSALinkNode) {
				ASFIPSEC_DEBUG("Matching SelSet SA Notfound");
				ASFIPSEC_DEBUG("Send packet to CP ");
				return NULL;
			}
			ASFIPSEC_DEBUG("Got the SA = %d",
				pOutSALinkNode->ulSAIndex);
			/* We don't have the SA yet, Get it from global table */
			pSecInfo->outSAInfo.ulSAIndex =
					pOutSALinkNode->ulSAIndex;
		}

		/* Now update our magic number from Global table */
		pSecInfo->outSAInfo.ulSAMagicNumber =
		ptrIArray_getMagicNum(&secFP_OutSATable,
				pSecInfo->outSAInfo.ulSAIndex);
	}

	/* If we reached here, we have the SA in our cache */
	pSA = (outSA_t *) ptrIArray_getData(&secFP_OutSATable,
				pSecInfo->outSAInfo.ulSAIndex);

	ASFIPSEC_FEXIT;
	return pSA;
}


#ifndef CONFIG_ASF_SEC4x
/* update descriptor information within SA, that can be held permanantly */
static inline int secfp_updateInSA(inSA_t *pSA, SAParams_t *pSAParams)
{
	memcpy(&pSA->SAParams, pSAParams, sizeof(SAParams_t));
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
#else
static inline int secfp_updateInSA(inSA_t *pSA, SAParams_t *pSAParams)
{
	unsigned char mdpadlen[] = { 16, 20, 32, 32, 64, 64 };

	memcpy(&pSA->SAParams, pSAParams, sizeof(SAParams_t));
	if (pSA->SAParams.bAuth) {
		switch (pSA->SAParams.ucAuthAlgo) {
		case SECFP_HMAC_MD5:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_PCL_IPSEC_HMAC_MD5_96 |
						OP_TYPE_CLASS2_ALG;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);

			break;
		case SECFP_HMAC_SHA1:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA1 |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA1 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);

			break;
		case SECFP_HMAC_AES_XCBC_MAC:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
					OP_ALG_AAI_XCBC_MAC |
					OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_PCL_IPSEC_AES_XCBC_MAC_96 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		case SECFP_HMAC_SHA256:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA256 |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA256 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		case SECFP_HMAC_SHA384:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA384 |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA384 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		case SECFP_HMAC_SHA512:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA512|
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA512 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		default:
			ASFIPSEC_DEBUG("Invalid ucAuthAlgo");
			return -1;
		}
		pSA->ctx.class2_alg = pSA->SAParams.ucAuthAlgo;
	}

	if (pSA->SAParams.bEncrypt) {
		switch (pSA->SAParams.ucCipherAlgo) {
		case SECFP_DES:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_DES |
							OP_ALG_AAI_CBC;
			break;
		case SECFP_3DES:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_3DES |
							OP_ALG_AAI_CBC;
			break;

		case SECFP_AES:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_AES |
							OP_ALG_AAI_CBC;
			break;
		case SECFP_AESCTR:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_AES |
							OP_ALG_AAI_CTR_XCBCMAC;
			break;
		case SECFP_ESP_NULL:
			ASFIPSEC_DEBUG("NULL Encryption set");
			break;
		default:
			ASFIPSEC_WARN("Invalid ucEncryptAlgo");
			return -1;
		}
		pSA->ctx.class1_alg = pSA->SAParams.ucCipherAlgo;
	}

	return 0;
}
#endif

/* Internal routines to support Control Plane/Normal Path API */
#ifndef CONFIG_ASF_SEC4x
static inline int secfp_updateOutSA(outSA_t *pSA, void *buff)
{
	SAParams_t *pSAParams = (SAParams_t *)(buff);

	memcpy(&pSA->SAParams, pSAParams, sizeof(SAParams_t));
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
#else
static inline int secfp_updateOutSA(outSA_t *pSA, void *buff)
{
	SAParams_t *pSAParams = (SAParams_t *)(buff);
	unsigned char mdpadlen[] = { 16, 20, 32, 32, 64, 64 };

	memcpy(&pSA->SAParams, pSAParams, sizeof(SAParams_t));
	if (pSA->SAParams.bAuth) {
		switch (pSAParams->ucAuthAlgo) {
		case SECFP_HMAC_MD5:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_PCL_IPSEC_HMAC_MD5_96 |
						OP_TYPE_CLASS2_ALG;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);

			break;
		case SECFP_HMAC_SHA1:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA1 |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA1 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);

			break;
		case SECFP_HMAC_AES_XCBC_MAC:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_AAI_XCBC_MAC |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_PCL_IPSEC_AES_XCBC_MAC_96 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		case SECFP_HMAC_SHA256:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA256 |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA256 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		case SECFP_HMAC_SHA384:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA384 |
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA384 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		case SECFP_HMAC_SHA512:
			pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA512|
						OP_ALG_AAI_HMAC_PRECOMP;
			pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_SHA512 |
						OP_ALG_AAI_HMAC;
			pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
			pSA->ctx.split_key_pad_len =
					ALIGN(pSA->ctx.split_key_len, 16);
			break;
		default:
			ASFIPSEC_DEBUG("Invalid ucAuthAlgo");
			return -1;
		}
		pSA->ctx.class2_alg = pSA->SAParams.ucAuthAlgo;

	}
	if (pSA->SAParams.bEncrypt) {
		switch (pSAParams->ucCipherAlgo) {
		case SECFP_DES:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_DES |
							OP_ALG_AAI_CBC;
			break;
		case SECFP_3DES:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_3DES |
							OP_ALG_AAI_CBC;
			break;
		case SECFP_AES:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_AES |
							OP_ALG_AAI_CBC;
			break;
		case SECFP_AESCTR:
			pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
						OP_ALG_ALGSEL_AES |
						OP_ALG_AAI_CTR_XCBCMAC;
			break;
		case SECFP_ESP_NULL:
			ASFIPSEC_DEBUG("NULL Encryption set");
			break;
		default:
			ASFIPSEC_WARN("Invalid ucEncryptAlgo");
			return -1;
		}
		pSA->ctx.class1_alg = pSA->SAParams.ucCipherAlgo;
	}

	return 0;
}
#endif


/* To remove all container index nodes from the tunnel */
void secfp_removeAllCINodesFromTunnelList(unsigned int ulVSGId,
				unsigned int ulTunnelId, ASF_boolean_t bDir)
{
	ASFIPSEC_DEBUG("Stub function: Need to handle RCUs ");
}


SPDOutSALinkNode_t *secfp_allocOutSALinkNode(void)
{
	SPDOutSALinkNode_t *pOutSALinkNode;
	char			bHeap;
	pOutSALinkNode = (SPDOutSALinkNode_t *) asfGetNode(
			SPDOutSALinkNodePoolId_g, &bHeap);
	if (pOutSALinkNode && bHeap)
		pOutSALinkNode->bHeap = bHeap;

	return pOutSALinkNode;
}

void secfp_freeOutSALinkNode(struct rcu_head *rcu)
{
	SPDOutSALinkNode_t *pOutSALinkNode = (SPDOutSALinkNode_t *) rcu;
	asfReleaseNode(SPDOutSALinkNodePoolId_g,
		pOutSALinkNode, pOutSALinkNode->bHeap);
}

static void secfp_addOutSALinkNode(SPDOutContainer_t *pContainer,
	SPDOutSALinkNode_t *pOutSALinkNode)
{
	/* Adding new SAList to pContainer */
	spin_lock_bh(&pContainer->spinlock);
	pOutSALinkNode->pNext = pContainer->SAHolder.pSAList;
	pOutSALinkNode->pPrev = NULL;

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

	call_rcu((struct rcu_head *) pOutSALinkNode, secfp_freeOutSALinkNode);
	spin_unlock_bh(&pContainer->spinlock);

}


/*
 * Need to fill this with code to check if given packet selectors
 * match with SA selectors
 */
bool secfp_verifySASels(inSA_t *pSA, unsigned char protocol,
			unsigned short int sport,
			unsigned short int dport,
			ASF_IPAddr_t saddr,
			ASF_IPAddr_t daddr) {
	InSelList_t *pList;
	SASel_t *pSel;
	struct selNode_s *pSelNode;
	unsigned char ucMatchSrcSelFlag, ucMatchDstSelFlag;
	int ii;
	bool bMatchFound = ASF_FALSE;


	if (pSA->ulSPDSelSetIndexMagicNum == ptrIArray_getMagicNum(
				&secFP_InSelTable, pSA->ulSPDSelSetIndex)) {
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
#ifdef ASF_IPV6_FP_SUPPORT
						if (pSelNode->IP_Version == 4) {
#endif
							if (!saddr.bIPv4OrIPv6 &&
								(saddr.ipv4addr >= pSelNode->ipAddrRange.v4.start) &&
								(saddr.ipv4addr <= pSelNode->ipAddrRange.v4.end)) {
								ucMatchSrcSelFlag |= SECFP_SA_SRCIPADDR_SELECTOR;
							} else
								continue;
#ifdef ASF_IPV6_FP_SUPPORT
						} else {
							if (saddr.bIPv4OrIPv6 &&
								(memcmp(saddr.ipv6addr,
									pSelNode->ipAddrRange.v6.start.u.b_addr, 16) >= 0) &&
								(memcmp(saddr.ipv6addr,
									pSelNode->ipAddrRange.v6.end.u.b_addr, 16) <= 0)) {
								ucMatchSrcSelFlag |= SECFP_SA_SRCIPADDR_SELECTOR;
							} else
								continue;
						}
#endif
					}
					bMatchFound = ASF_TRUE;
					break;
				}
				if (bMatchFound == ASF_TRUE)
					break;
			}
			bMatchFound = ASF_FALSE;
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
#ifdef ASF_IPV6_FP_SUPPORT
						if (pSelNode->IP_Version == 4) {
#endif
							if (!daddr.bIPv4OrIPv6 &&
								(daddr.ipv4addr >= pSelNode->ipAddrRange.v4.start) &&
								(daddr.ipv4addr <= pSelNode->ipAddrRange.v4.end)) {
								ucMatchDstSelFlag |= SECFP_SA_DESTIPADDR_SELECTOR;
							} else
								continue;
#ifdef ASF_IPV6_FP_SUPPORT
						} else {
							if (daddr.bIPv4OrIPv6 &&
								(memcmp(daddr.ipv6addr,
									pSelNode->ipAddrRange.v6.start.u.b_addr, 16) >= 0) &&
								(memcmp(daddr.ipv6addr,
									pSelNode->ipAddrRange.v6.end.u.b_addr, 16) <= 0)) {
								ucMatchDstSelFlag |= SECFP_SA_DESTIPADDR_SELECTOR;
							} else
								continue;
						}
#endif
					}
					bMatchFound = ASF_TRUE;
					break;
				}
				if (bMatchFound == ASF_TRUE)
					break;
			}
			if ((ucMatchSrcSelFlag | ucMatchDstSelFlag) == pList->ucSelFlags) {
				return ASF_TRUE;
			}
		} else {
			ASFIPSEC_DEBUG("SelList not found in Ptr Array"
				"for comparison");
		}
	} else {
		ASFIPSEC_DEBUG("Sel Set (In) Magic number mismatch"
			"between SA and pointer array");
	}
	return ASF_FALSE;
}


/* API functions for Control Plane/Normal Path */

/* Append Container node to tunnel list -internal function */

void secfp_appendCINodeToTunnelList(unsigned int ulVSGId,
		unsigned int ulTunnelId,
		struct SPDCILinkNode_s *pCINode,
		ASF_boolean_t bDir)
{
	struct SPDCILinkNode_s *pTempCINode;
	struct SPDCILinkNode_s **pList;

	spin_lock(&secfp_TunnelIfaceCIIndexListLock);

	if (bDir == SECFP_OUT)
		pList = &secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	else /* for Inbound */
		pList = &secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;

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
		unsigned int ulTunnelId,
		struct SPDCILinkNode_s *pCINode,
		bool bDir)
{
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
	call_rcu((struct rcu_head *)pCINode, secfp_freeSDPCILinkNode);
	spin_unlock(&secfp_TunnelIfaceCIIndexListLock);
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
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	/* If tunnel interface not created, create the tunnel interface */
	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse = 1;
		ASFIPSEC_DEBUG("Tunnel Int is not in use.TunnelId=%u, VSGId=%u",
			ulTunnelId, ulVSGId);
	}

	pCINode = secfp_allocSPDCILinkNode();
	if (pCINode == NULL) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("Tunnel LinkNode creation failure:"
			"secfp_allocSPDCILinkNode returned null");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_RESOURCE_NOT_AVAILABLE;;
	}

	pContainer = secfp_allocSPDOutContainer();
	if (pContainer) {
		memcpy(&(pContainer->SPDParams),
			pSPDParams, sizeof(SPDOutParams_t));
		if (pContainer->SPDParams.bOnlySaPerDSCP) {
			for (ii = 0; ii < SECFP_MAX_DSCP_SA; ii++)
				pContainer->SAHolder.ulSAIndex[ii] =
					ulMaxSupportedIPSecSAs_g;

		}

		if (ptrIArray_addInGivenIndex(&(secfp_OutDB), pContainer,
					ulContainerIndex, ulMagicNum) != 0) {
			ASFIPSEC_DEBUG("ptrIArray_addInGivenIndex return null");
			secfp_freeSPDOutContainer(
					(struct rcu_head *)pContainer);
			secfp_freeSDPCILinkNode((struct rcu_head *)pCINode);
			GlobalErrors.ulOutSPDContainerAlreadyPresent++;
			if (!bVal)
				local_bh_enable();
			return ASF_IPSEC_INVALID_CONTAINER_ID;
		}

		pCINode->ulIndex = ulContainerIndex;

		/* Append it to the list */
		secfp_appendCINodeToTunnelList(ulVSGId, ulTunnelId,
				pCINode, SECFP_OUT);
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
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_DEBUG("Tunnel If is not in use. TunnelId=%u, VSGId=%u",
				ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}

	for (pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
		pCINode != NULL;
		pCINode = pCINode->pNext) {
		if (pCINode->ulIndex == ulContainerIndex)
			break;
	}

	if (!pCINode) {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("Could not find CI Link Node");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_OUTSPDCONTAINER_NOT_FOUND;
	}
	secfp_removeCINodeFromTunnelList(ulVSGId, ulTunnelId,
			pCINode, SECFP_OUT);
	ptrIArray_delete(&(secfp_OutDB), ulContainerIndex,
			secfp_freeSPDOutContainer);
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}


/* In container create function */
unsigned int secfp_SPDInContainerCreate(unsigned int ulVSGId,
					unsigned int ulTunnelId,
					unsigned int ulContainerIndex,
					unsigned int ulMagicNum,
					SPDInParams_t *pSPDParams)
{
	SPDInContainer_t *pContainer;
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	/* If tunnel interface not created, create the tunnel interface */
	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse = 1;
		ASFIPSEC_DEBUG("Tunnel Int is not in use.TunnelId=%u, VSGId=%u",
			ulTunnelId, ulVSGId);
	}

	pCINode = secfp_allocSPDCILinkNode();
	if (pCINode == NULL) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("Tunnel LinkNode creation failure:"
			"secfp_allocSPDCILinkNode returned null");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_RESOURCE_NOT_AVAILABLE;;
	}

	pContainer = secfp_allocSPDInContainer();
	if (pContainer) {
		memcpy(&pContainer->SPDParams, pSPDParams,
			sizeof(SPDInParams_t));
		if (ptrIArray_addInGivenIndex(&(secfp_InDB), pContainer,
				ulContainerIndex, ulMagicNum) != 0) {
			ASFIPSEC_DEBUG("ptrIArray_addInGivenIndex failure");
			secfp_freeSPDInContainer((struct rcu_head *)pContainer);
			secfp_freeSDPCILinkNode((struct rcu_head *) pCINode);
			GlobalErrors.ulInSPDContainerAlreadyPresent++;
			if (!bVal)
				local_bh_enable();
			return ASF_IPSEC_INVALID_CONTAINER_ID;
		}
		pCINode->ulIndex = ulContainerIndex;
		/* Append it to the list */
		secfp_appendCINodeToTunnelList(ulVSGId, ulTunnelId,
				pCINode, SECFP_IN);
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


/* In container delete function */
unsigned int secfp_SPDInContainerDelete(unsigned int ulVSGId,
					unsigned int ulTunnelId,
					unsigned int ulContainerIndex,
					unsigned int ulMagicNumber)
{
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_interrupt();

	/* Clean up the selector set SA Pointers and others */
	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_DEBUG("Tunnel Int is not in use.TunnelId=%u, VSGId=%u",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}


	for (pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
		pCINode != NULL;
		pCINode = pCINode->pNext) {
		if (pCINode->ulIndex == ulContainerIndex)
			break;
	}

	if (!pCINode) {
		GlobalErrors.ulSPDInContainerNotFound++;
		ASFIPSEC_DEBUG("Could not find CI Link Node");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_INSPDCONTAINER_NOT_FOUND;
	}
	secfp_removeCINodeFromTunnelList(ulVSGId, ulTunnelId, pCINode, SECFP_IN);
	ptrIArray_delete(&(secfp_InDB), ulContainerIndex,
				secfp_freeSPDInContainer);
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}

/* Out SA creation function */
unsigned int secfp_createOutSA(
			unsigned int ulVSGId,
			unsigned int ulTunnelId,
			unsigned int ulSPDContainerIndex,
			unsigned int ulMagicNumber,
			SASel_t	*pSrcSel,
			SASel_t	*pDstSel,
			unsigned char ucSelMask,
			SAParams_t	*SAParams,
			unsigned short usDscpStart,
			unsigned short usDscpEnd,
			unsigned int ulMtu)

{
	outSA_t *pSA;
	SPDOutContainer_t *pContainer;
	int ii;
	ASF_IPSecTunEndAddr_t TunAddress;
	unsigned int ulIndex;
	outSA_t *pOldSA;
	SPDOutSALinkNode_t *pOutSALinkNode;
	ASF_IPAddr_t daddr;
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	daddr.bIPv4OrIPv6 = SAParams->tunnelInfo.bIPv4OrIPv6;
	if (SAParams->tunnelInfo.bIPv4OrIPv6)
		memcpy(daddr.ipv6addr,
			SAParams->tunnelInfo.addr.iphv6.daddr, 16);
	else
		daddr.ipv4addr = SAParams->tunnelInfo.addr.iphv4.daddr;


	pContainer = (SPDOutContainer_t *)ptrIArray_getData(&(secfp_OutDB),
						ulSPDContainerIndex);
	if (!pContainer) {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("SPDContainer not found");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	if ((usDscpStart == 0) && (usDscpEnd == 0))
		usDscpEnd = 7;

	if (pContainer->SPDParams.bOnlySaPerDSCP) {
		for (ii = usDscpStart; ii < usDscpEnd; ii++) {
			if (pContainer->SAHolder.ulSAIndex[ii] !=
						ulMaxSupportedIPSecSAs_g) {
				/* DSCP Index has already an SA,
					so compare the SPI values */
				pOldSA = (outSA_t *)ptrIArray_getData(
					&secFP_OutSATable,
					pContainer->SAHolder.ulSAIndex[ii]);
				if (SAParams->ulSPI == pOldSA->SAParams.ulSPI) {
					ASFIPSEC_DEBUG("SA Already exists:"
						"Ignore the new one");
					if (!bVal)
						local_bh_enable();
					return SECFP_SUCCESS;
				} else {
					ASFIPSEC_DEBUG("Missed a delete,"
						"need to see how to handle");
					if (!bVal)
						local_bh_enable();
					return SECFP_FAILURE;
				}
			}
		}
	} else {
		pOutSALinkNode = secfp_findOutSALinkNode(pContainer, daddr,
					SAParams->ucProtocol, SAParams->ulSPI);
		if (pOutSALinkNode != NULL) {
			GlobalErrors.ulOutDuplicateSA++;
			ASFIPSEC_DEBUG("SA Already exists:Ignore the new one ");
			if (!bVal)
				local_bh_enable();
			return SECFP_SUCCESS;
		}
	}

	pSA = secfp_allocOutSA();
	if (unlikely(pSA == NULL)) {
		GlobalErrors.ulResourceNotAvailable++;
		ASFIPSEC_DEBUG("secfp_allocOutSA returned null");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}
	if (!pContainer->SPDParams.bOnlySaPerDSCP) {
		secfp_addOutSelSet(pSA, pSrcSel, pDstSel, ucSelMask,
				usDscpStart, usDscpEnd);
		if (!pSA->pSelList) {
			ASFIPSEC_DEBUG("secfp_addOutSelSet failure");
			if (!bVal)
				local_bh_enable();
			secfp_freeOutSA((struct rcu_head *)pSA);
			return SECFP_FAILURE;
		}
	}
	pSA->ulTunnelId = ulTunnelId;
	pSA->chan = ulLastOutSAChan_g;
	ulLastOutSAChan_g = (ulLastOutSAChan_g == 0) ? 1 : 0;
	memcpy(&(pSA->SPDParams), &(pContainer->SPDParams),
				sizeof(SPDOutParams_t));

	if (secfp_updateOutSA(pSA, SAParams)) {
		GlobalErrors.ulInvalidAuthEncAlgo++;
		ASFIPSEC_DEBUG("secfp_updateOutSA returned failure");
		secfp_freeOutSA((struct rcu_head *)pSA);
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	pSA->ipHdrInfo.bIpVersion =
			pSA->SAParams.tunnelInfo.bIPv4OrIPv6;
	/* Prepare the IP header and keep it for reuse */
	if (!pSA->ipHdrInfo.bIpVersion) { /* IPv4 */
		pSA->ipHdrInfo.hdrdata.iphv4.version = 4;
		pSA->ipHdrInfo.hdrdata.iphv4.ihl = 5;
		pSA->ipHdrInfo.hdrdata.iphv4.tos = 0;
		if (!pSA->SAParams.bCopyDscp)
			/* Revisit code */
			pSA->ipHdrInfo.hdrdata.iphv4.tos =
						pSA->SAParams.ucDscp;

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
			pSA->ipHdrInfo.hdrdata.iphv4.frag_off = 0;
			ASFIPSEC_DEBUG("DF Option not handled");
			break;
		}

		pSA->ipHdrInfo.hdrdata.iphv4.ttl = SECFP_IP_TTL;
		pSA->ipHdrInfo.hdrdata.iphv4.protocol = SECFP_PROTO_ESP;
		pSA->ipHdrInfo.hdrdata.iphv4.check = 0;
		pSA->ipHdrInfo.hdrdata.iphv4.saddr =
			pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		pSA->ipHdrInfo.hdrdata.iphv4.daddr =
			pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
		pSA->ulSecOverHead = SECFP_IPV4_HDR_LEN
			+ SECFP_ESP_HDR_LEN + SECFP_ESP_TRAILER_LEN
			+ pSA->SAParams.ulIvSize;
		pSA->ulPathMTU = ulMtu;
		pSA->ulSecLenIncrease = SECFP_IPV4_HDR_LEN;
	} else { /* Handle IPv6 case */
#ifdef ASF_IPV6_FP_SUPPORT
		pSA->ipHdrInfo.hdrdata.iphv6.version = 6;
		pSA->ipHdrInfo.hdrdata.iphv6.priority = 0;
		memset(pSA->ipHdrInfo.hdrdata.iphv6.flow_lbl , 0, 3);
		pSA->ipHdrInfo.hdrdata.iphv6.payload_len = 0;

		pSA->ipHdrInfo.hdrdata.iphv6.nexthdr = SECFP_PROTO_ESP;
		pSA->ipHdrInfo.hdrdata.iphv6.hop_limit = SECFP_IP_TTL;
		memcpy(pSA->ipHdrInfo.hdrdata.iphv6.saddr.s6_addr32,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
		memcpy(pSA->ipHdrInfo.hdrdata.iphv6.daddr.s6_addr32,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
		pSA->ulSecOverHead = SECFP_IPV6_HDR_LEN
			+ SECFP_ESP_HDR_LEN + SECFP_ESP_TRAILER_LEN
			+ pSA->SAParams.ulIvSize;
		pSA->ulPathMTU = ulMtu;
		pSA->ulSecLenIncrease = SECFP_IPV6_HDR_LEN;
#endif
	}
	pSA->prepareOutPktFnPtr = secfp_prepareOutPacket;
	pSA->finishOutPktFnPtr = secfp_finishOutPacket;
	/*
	* Get the NAT-T header packet
	*/
	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		pSA->usNatHdrSize = SECFP_MAX_UDP_HDR_LEN;
		if (pSA->SAParams.IPsecNatInfo.ulNATt
			== ASF_IPSEC_IKE_NATtV1)
			pSA->usNatHdrSize += 8;
		pSA->ulSecOverHead += pSA->usNatHdrSize;
	} else
		pSA->usNatHdrSize = 0;

	pSA->ulIvSizeInWords = pSA->SAParams.ulIvSize/4;
	pSA->ulSecHdrLen = SECFP_ESP_HDR_LEN + pSA->SAParams.ulIvSize;
	pSA->bSoftExpiry = 0;
	/* starting the seq number from 2 to avoid the conflict
	with the Networking Stack seq number */
	atomic_set(&pSA->ulLoSeqNum, 2);

	if (pSA->SAParams.bAuth) {
		pSA->ulSecOverHead += SECFP_ICV_LEN;
		pSA->ulSecLenIncrease += SECFP_ICV_LEN;
	}

	pSA->ulCompleteOverHead = pSA->ulSecOverHead;
	pSA->ulCompleteOverHead += pSA->SAParams.ulBlockSize;

	ASFIPSEC_DEBUG(" Overhead = %d", pSA->ulCompleteOverHead);
	/* revisit - usAuthKeyLen or usAuthKeySize */

#ifdef CONFIG_ASF_SEC4x
	pSA->option[1] = SECFP_NONE;
	pSA->bIVDataPresent = ASF_TRUE;
	if (pSA->SAParams.bEncrypt && pSA->SAParams.bAuth)
		pSA->option[0] = SECFP_BOTH;
	else if (pSA->SAParams.bEncrypt && (!pSA->SAParams.bAuth))
		pSA->option[0] = SECFP_CIPHER;
	else
		pSA->option[0] = SECFP_AUTH;
	pSA->ctx.class1_alg = pSA->SAParams.ucCipherAlgo;
	pSA->ctx.class2_alg = pSA->SAParams.ucAuthAlgo;

	if (pSA->SAParams.bEncrypt)
		if (secfp_createOutSACaamCtx(pSA)) {
			ASFIPSEC_DEBUG("secfp_createOutSACaamCtx"\
					"Failed");
			secfp_freeOutSA((struct rcu_head *)pSA);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}

	ASFIPSEC_FPRINT("authsize %d enckeylen %d authkeylen %d",
		pSA->ctx.authsize, pSA->SAParams.EncKeyLen,
		pSA->SAParams.AuthKeyLen);
	ASFIPSEC_FPRINT("split_key_len %d split_key_pad_len %d",
		pSA->ctx.split_key_len, pSA->ctx.split_key_pad_len);
	ASFIPSEC_HEXDUMP(pSA->ctx.key,
		pSA->SAParams.EncKeyLen + pSA->SAParams.AuthKeyLen);

#else /*CONFIG_ASF_SEC3x*/
	secfp_createOutSATalitosDesc(pSA);
#endif
	ulIndex = ptrIArray_add(&secFP_OutSATable, pSA);
	if (ulIndex != secFP_OutSATable.nr_entries) {
		if (pContainer->SPDParams.bOnlySaPerDSCP) {
			for (ii = usDscpStart; ii < usDscpEnd; ii++)
				pContainer->SAHolder.ulSAIndex[ii] = ulIndex;
		} else {
			pOutSALinkNode = secfp_allocOutSALinkNode();
			if (pOutSALinkNode == NULL) {
				GlobalErrors.ulResourceNotAvailable++;
				ASFIPSEC_DEBUG("secfp_allocOutSALinkNod"
					"returned null");
				secfp_freeOutSA((struct rcu_head *)pSA);
				if (!bVal)
					local_bh_enable();
				return SECFP_FAILURE;
			}
			pOutSALinkNode->ulSAIndex = ulIndex;
			secfp_addOutSALinkNode(pContainer,
				pOutSALinkNode);
		}
	} else {
		GlobalErrors.ulOutSAFull++;
		ASFIPSEC_DEBUG("Could not find index to hold SA:"
			"Maximum count reached ");
		secfp_freeOutSA((struct rcu_head *)pSA);
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}
	memset(&(pSA->l2blobConfig), 0, sizeof(ASFFFPL2blobConfig_t));
#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
	TunAddress.IP_Version = 4;
	TunAddress.dstIP.bIPv4OrIPv6 = 0;
	TunAddress.srcIP.bIPv4OrIPv6 = 0;
	TunAddress.dstIP.ipv4addr =
		pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
	TunAddress.srcIP.ipv4addr =
		pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		TunAddress.IP_Version = 6;
		TunAddress.dstIP.bIPv4OrIPv6 = 1;
		TunAddress.srcIP.bIPv4OrIPv6 = 1;
		memcpy(TunAddress.dstIP.ipv6addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
		memcpy(TunAddress.srcIP.ipv6addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
	}
#endif
	if (!bVal)
		local_bh_enable();
	if (ASFIPSecCbFn.pFnRefreshL2Blob)
		ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId, ulTunnelId,
			ulSPDContainerIndex, ulMagicNumber, &TunAddress,
			pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (ulL2BlobRefreshTimeInSec_g) {
		pSA->pL2blobTmr = asfTimerStart(
				ASF_SECFP_BLOB_TMR_ID, 0,
				ulL2BlobRefreshTimeInSec_g,
				ulVSGId, ulIndex,
				ptrIArray_getMagicNum(&secFP_OutSATable,
				ulIndex), ulSPDContainerIndex, 0);
		if (!pSA->pL2blobTmr)
			ASFIPSEC_WARN("asfTimerStart failed");
	}
#endif
	return SECFP_SUCCESS;
}

/* Out SA Modification function */
unsigned int secfp_ModifyOutSA(unsigned long int ulVSGId,
				ASFIPSecRuntimeModOutSAArgs_t *pModSA)
{
	outSA_t *pOutSA = NULL;
	SPDOutContainer_t *pOutContainer;
	SPDOutSALinkNode_t *pOutSALinkNode;
	unsigned short usDscpStart = 0;
	unsigned short usDscpEnd = SECFP_MAX_DSCP_SA - 1;
	int ii;
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
					pModSA->ulSPDContainerIndex));
	ASFIPSEC_DEBUG("Change Type = %d", pModSA->ucChangeType);
	if (unlikely(pOutContainer == NULL)) {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("OutContainer not found");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
		for (ii = usDscpStart; ii < usDscpEnd; ii++) {
			if (pOutContainer->SAHolder.ulSAIndex[ii] !=
					ulMaxSupportedIPSecSAs_g) {
				/* DSCP Index has already an SA,
					so compare the SPI values */
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
		pOutSALinkNode = secfp_findOutSALinkNode(
				pOutContainer, pModSA->DestAddr,
				pModSA->ucProtocol, pModSA->ulSPI);
		if (pOutSALinkNode) {
			pOutSA = (outSA_t *)ptrIArray_getData(
					&secFP_OutSATable,
					pOutSALinkNode->ulSAIndex);
		} else
			pOutSA = NULL;
	}
	if (pOutSA) {
		switch (pModSA->ucChangeType) {
		case ASFIPSEC_UPDATE_LOCAL_GW:
#ifdef ASF_IPV6_FP_SUPPORT
			if (pOutSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
				memcpy(pOutSA->SAParams.tunnelInfo.addr.iphv6.saddr,
					pModSA->u.addrInfo.IPAddr.ipv6addr, 16);
			} else
#endif
			{
			pOutSA->SAParams.tunnelInfo.addr.iphv4.saddr
				= pModSA->u.addrInfo.IPAddr.ipv4addr;
			}
			break;
		case ASFIPSEC_UPDATE_PEER_GW:
#ifdef ASF_IPV6_FP_SUPPORT
			if (pOutSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 0) {
				memcpy(pOutSA->SAParams.tunnelInfo.addr.iphv6.daddr,
					pModSA->u.addrInfo.IPAddr.ipv6addr, 16);
			} else
#endif
			{
			pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr
				= pModSA->u.addrInfo.IPAddr.ipv4addr;
			}
			break;
		case ASFIPSEC_UPDATE_MTU:
			pOutSA->ulPathMTU = pModSA->u.ulMtu;
			break;
		case ASFIPSEC_UPDATE_L2BLOB:
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
			pOutSA->bl2blob = ASF_TRUE;
			pOutSA->l2blobConfig.ulL2blobMagicNumber =
				pModSA->u.l2blob.ulL2blobMagicNumber;
			pOutSA->l2blobConfig.bl2blobRefreshSent = 0;
			break;
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

}
/* Out SA deletion function */
unsigned int secfp_DeleteOutSA(unsigned int	ulSPDContainerIndex,
				unsigned int	ulSPDMagicNumber,
				ASF_IPAddr_t	daddr,
				unsigned char	ucProtocol,
				unsigned int	ulSPI,
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

	if (unlikely(pContainer == NULL)) {
		GlobalErrors.ulSPDOutContainerNotFound++;
		ASFIPSEC_DEBUG("SPDOutContainer not found");
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_OUTSPDCONTAINER_NOT_FOUND;
	}

	if ((usDscpStart == 0) && (usDscpEnd == 0))
		usDscpEnd = 7;
	if (pContainer->SPDParams.bOnlySaPerDSCP) {
		ulSAIndex = pContainer->SAHolder.ulSAIndex[
					(unsigned int)usDscpStart];
		if (ulSAIndex == ulMaxSupportedIPSecSAs_g) {
			GlobalErrors.ulOutSANotFound++;
			ASFIPSEC_DEBUG("secfp_findOutSALinkNode null");
			if (!bVal)
				local_bh_enable();
			return ASF_IPSEC_OUTSA_NOT_FOUND;

		}
		pOutSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
							ulSAIndex);
		if (pOutSA) {
			for_each_possible_cpu(Index) {
				ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[0],
					pOutSA->PolicyPPStats[Index].NumInBoundInPkts);
				ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[1],
					pOutSA->PolicyPPStats[Index].NumInBoundOutPkts);
				ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[2],
					pOutSA->PolicyPPStats[Index].NumOutBoundInPkts);
				ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[3],
					pOutSA->PolicyPPStats[Index].NumOutBoundOutPkts);
			}
			for (Index = 0; Index < 4; Index++)
				ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(
					pContainer->PPStats.IPSecPolPPStats[Index + 4],
					pContainer->PPStats.IPSecPolPPStats[Index]);

			for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
				ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(
					pContainer->PPStats.IPSecPolPPStats[Index],
					pOutSA->PPStats.IPSecPolPPStats[Index]);
				ASF_IPSEC_ATOMIC_SET(pOutSA->PPStats.IPSecPolPPStats[Index], 0);
			}
			ptrIArray_delete(&secFP_OutSATable, ulSAIndex,
						secfp_freeOutSA);
			memset(&pOutSA->PolicyPPStats, 0x0,
				sizeof(pOutSA->PolicyPPStats));
		}
		for (ii = usDscpStart; ii < usDscpEnd; ii++)
			pContainer->SAHolder.ulSAIndex[ii] =
					ulMaxSupportedIPSecSAs_g;
	} else {
		ASFIPSEC_DEBUG("Delete - dest %x, proto = %d spi= %x ",
			daddr, ucProtocol, ulSPI);

		pOutSALinkNode = secfp_findOutSALinkNode(
				pContainer, daddr, ucProtocol, ulSPI);
		if (pOutSALinkNode) {
			pOutSA = (outSA_t *)ptrIArray_getData(
					&secFP_OutSATable,
					pOutSALinkNode->ulSAIndex);
			if (pOutSA) {
				for_each_possible_cpu(Index) {
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[0],
						pOutSA->PolicyPPStats[Index].NumInBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[1],
						pOutSA->PolicyPPStats[Index].NumInBoundOutPkts);
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[2],
						pOutSA->PolicyPPStats[Index].NumOutBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[3],
						pOutSA->PolicyPPStats[Index].NumOutBoundOutPkts);
				}
				for (Index = 0; Index < 4; Index++)
					ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(
						pContainer->PPStats.IPSecPolPPStats[Index + 4],
						pContainer->PPStats.IPSecPolPPStats[Index]);
				for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
					ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(
						pContainer->PPStats.IPSecPolPPStats[Index],
						pOutSA->PPStats.IPSecPolPPStats[Index]);
					ASF_IPSEC_ATOMIC_SET(pOutSA->PPStats.IPSecPolPPStats[Index], 0);
				}
				memset(&pOutSA->PolicyPPStats, 0x0,
					sizeof(pOutSA->PolicyPPStats));
			}
			ulSAIndex = pOutSALinkNode->ulSAIndex;
			secfp_delOutSALinkNode(pContainer,
					pOutSALinkNode);
			ptrIArray_delete(&secFP_OutSATable, ulSAIndex,
						secfp_freeOutSA);
		} else {
			GlobalErrors.ulOutSANotFound++;
			ASFIPSEC_DEBUG("secfp_findOutSALinkNode"
				"returned null");
			if (!bVal)
				local_bh_enable();
			return ASF_IPSEC_OUTSA_NOT_FOUND;
		}
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
			unsigned int ulOutSPI,
			unsigned int ulMtu)
{
	inSA_t *pSA;
	SPDInContainer_t *pContainer;
	SPDInSelTblIndexLinkNode_t *pNode;
	SPDInSPIValLinkNode_t *pSPINode;
	unsigned int iphdrlen;
	int bVal = in_interrupt();

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
		pSA->ulSPDOutContainerMagicNumber = ptrIArray_getMagicNum(
					&secfp_OutDB, ulSPDOutContainerIndex);
		pSA->ulOutSPI = ulOutSPI;
		pSA->ulTunnelId = ulTunnelId;

		memcpy(&(pSA->SPDParams), &(pContainer->SPDParams),
						sizeof(SPDInParams_t));
		if (secfp_updateInSA(pSA, pSAParams)) {
			GlobalErrors.ulInvalidAuthEncAlgo++;
			kfree(pSA);
			ASFIPSEC_DEBUG("secfp_updateInSA returned failure");
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
#ifdef ASF_IPV6_FP_SUPPORT
		if (pSAParams->tunnelInfo.bIPv4OrIPv6)
			iphdrlen = SECFP_IPV6_HDR_LEN;
		else
#endif
			iphdrlen = SECFP_IPV4_HDR_LEN;

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
		/*
		* Get the NAT-T header packet
		*/
		if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
			pSA->usNatHdrSize = SECFP_MAX_UDP_HDR_LEN;
			if (pSA->SAParams.IPsecNatInfo.ulNATt
					== ASF_IPSEC_IKE_NATtV1)
				pSA->usNatHdrSize += 8;
		} else
			pSA->usNatHdrSize = 0;

#ifdef CONFIG_ASF_SEC4x
		pSA->option[1] = SECFP_NONE;
		if (pSA->SAParams.bEncrypt && pSA->SAParams.bAuth)
			pSA->option[0] = SECFP_BOTH;
		else if (pSA->SAParams.bEncrypt && (!pSA->SAParams.bAuth))
			pSA->option[0] = SECFP_CIPHER;
		else
			pSA->option[0] = SECFP_AUTH;

		if (secfp_createInSACaamCtx(pSA)) {
			ASFIPSEC_DEBUG("secfp_createInSACaamCtx returnfailure");
			kfree(pSA);
			if (!bVal)
				local_bh_enable();

			return SECFP_FAILURE;
		}
#else
		secfp_createInSATalitosDesc(pSA);
#endif
		/* Need to create and append Selector Set */
		pNode = secfp_updateInSelSet(pContainer, pSrcSel,
						pDstSel, ucSelFlags);
		if (!pNode) {
			ASFIPSEC_DEBUG("secfp_updateInSelSet returned failure");
			kfree(pSA);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}

		/* Need to append SPI value to pSPIValList */
		if (!secfp_allocAndAppendSPIVal(pContainer, pSA)) {
			ASFIPSEC_DEBUG("secfp_allocAndAppendSPIVal failure");
			/* Remove from Selector List */
			secfp_deleteInContainerSelList(pContainer, pNode);
			kfree(pSA);
			if (!bVal)
				local_bh_enable();
			return SECFP_FAILURE;
		}
		pSA->bSoftExpiry = 0;
		pSA->ulRcvMTU = ulMtu;
		/* Update the magic number and index in SPI table for easy reference */
		pSA->ulSPDInContainerIndex = ulContainerIndex;
		pSA->ulSPDInMagicNum = ptrIArray_getMagicNum(&secfp_InDB,
							ulContainerIndex);
		pSA->ulSPDSelSetIndex = pNode->ulIndex;
		pSA->ulSPDSelSetIndexMagicNum = ptrIArray_getMagicNum(
					&secFP_InSelTable, pNode->ulIndex);
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

/* Setting DPD in IN SPD function */
unsigned int secfp_SetDPD(unsigned long int ulVSGId,
				ASFIPSecRuntimeSetDPDArgs_t *pSetDPD)
{
	SPDInContainer_t *pContainer;
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	pContainer = (SPDInContainer_t *)(ptrIArray_getData(&(secfp_InDB),
				pSetDPD->ulInSPDContainerIndex));
	if (pContainer) {
		pContainer->SPDParams.bDPDAlive = 1;
		if (!bVal)
			local_bh_enable();
		return SECFP_SUCCESS;
	}
	GlobalErrors.ulInvalidInSPDContainerId++;
	ASFIPSEC_DEBUG("InSPD not found");
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
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	pInSA = secfp_findInSA(ulVSGId, pModSA->ucProtocol, pModSA->ulSPI,
				pModSA->DestAddr, &hashVal);
	if (unlikely(pInSA == NULL)) {
		GlobalErrors.ulInSANotFound++;
		ASFIPSEC_PRINT("InSA not found");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}

	if (pInSA->ulSPDInContainerIndex == pModSA->ulSPDContainerIndex) {
		if (pModSA->ucChangeType == ASFIPSEC_UPDATE_LOCAL_GW) {
#ifdef ASF_IPV6_FP_SUPPORT
			if (pInSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
				memcpy(pInSA->SAParams.tunnelInfo.addr.iphv6.daddr,
					pModSA->IPAddr.ipv6addr, 16);
			} else
#endif
			{
			pInSA->SAParams.tunnelInfo.addr.iphv4.daddr
				= pModSA->IPAddr.ipv4addr;
			}
		} else { /*ASFIPSEC_UPDATE_PEER_GW */
#ifdef ASF_IPV6_FP_SUPPORT
			if (pInSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
				memcpy(pInSA->SAParams.tunnelInfo.addr.iphv6.saddr,
					pModSA->IPAddr.ipv6addr, 16);
			} else
#endif
			{
				pInSA->SAParams.tunnelInfo.addr.iphv4.saddr
					= pModSA->IPAddr.ipv4addr;
			}
		}
	} else {
		GlobalErrors.ulInSASPDContainerMisMatch++;
		ASFIPSEC_PRINT("SPD Container mismatch SA Container ="
			"%u, Passed Container = %u",
				pInSA->ulSPDInContainerIndex,
				pModSA->ulSPDContainerIndex);
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}

/* In SA deletion function */
unsigned int secfp_DeleteInSA(unsigned int ulVSGId,
				unsigned int ulContainerIndex,
				unsigned int ulMagicNumber,
				ASF_IPAddr_t daddr,
				unsigned char ucProtocol,
				unsigned int ulSPI)

{
	unsigned int hashVal = usMaxInSAHashTaleSize_g;
	unsigned int Index;
	SPDInContainer_t *pContainer;
	SPDInSelTblIndexLinkNode_t *pNode;
	SPDInSPIValLinkNode_t *pSPINode;
	bool bFound;
	inSA_t *pSA;
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	pSA = secfp_findInSA(ulVSGId, ucProtocol, ulSPI, daddr, &hashVal);
	if (unlikely(pSA == NULL)) {
		GlobalErrors.ulInSANotFound++;
		ASFIPSEC_PRINT("secfp_findInvSA returned NULL");
		if (!bVal)
			local_bh_enable();
		return SECFP_FAILURE;
	}
	pContainer = (SPDInContainer_t *)ptrIArray_getData(
			&(secfp_InDB), pSA->ulSPDInContainerIndex);
	bFound = ASF_FALSE;
	if (pContainer) {
		for (pNode = pContainer->pSelIndex; pNode != NULL;
			pNode = pNode->pNext) {
			if (pSA->ulSPDSelSetIndex == pNode->ulIndex) {
				bFound = ASF_TRUE;
				break;
			}
		}
		if (bFound == ASF_TRUE)
			secfp_deleteInContainerSelList(pContainer, pNode);
		else
			ASFIPSEC_WARN("CouldNotfind selectorlist node");

		pSPINode = secfp_findInSPINode(pContainer,
					pSA->SAParams.ulSPI);
		if (pSPINode)
			secfp_deleteInContainerSPIList(pContainer,
						pSPINode);
		else
			ASFIPSEC_WARN("Could not find SPI Link node");
	}
	if (pSA->ulSPDSelSetIndexMagicNum ==
		ptrIArray_getMagicNum(&secFP_InSelTable, pSA->ulSPDSelSetIndex)) {
		ptrIArray_delete(&secFP_InSelTable,
			pSA->ulSPDSelSetIndex, secfp_freeInSelSet);
	}

	for_each_possible_cpu(Index) {
		ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[0],
			pSA->PolicyPPStats[Index].NumInBoundInPkts);
		ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[1],
			pSA->PolicyPPStats[Index].NumInBoundOutPkts);
		ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[2],
			pSA->PolicyPPStats[Index].NumOutBoundInPkts);
		ASF_IPSEC_ATOMIC_ADD(pContainer->PPStats.IPSecPolPPStats[3],
			pSA->PolicyPPStats[Index].NumOutBoundOutPkts);
	}
	for (Index = 0; Index < 4; Index++)
		ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(
			pContainer->PPStats.IPSecPolPPStats[Index + 4],
			pContainer->PPStats.IPSecPolPPStats[Index]);

	for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
		ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(
			pContainer->PPStats.IPSecPolPPStats[Index],
			pSA->PPStats.IPSecPolPPStats[Index]);
		ASF_IPSEC_ATOMIC_SET(pSA->PPStats.IPSecPolPPStats[Index], 0);
	}
	memset(&pSA->PolicyPPStats, 0x0, sizeof(pSA->PolicyPPStats));
	secfp_deleteInSAFromSPIList(pSA);
	if (!bVal)
		local_bh_enable();
	return SECFP_SUCCESS;
}

void secfp_freeSelSet(SASel_t *pSel)
{
	SASel_t *pTempSel;
	while (pSel) {
		pTempSel = pSel->pNext;
		asfReleaseNode(SASelPoolId_g, pSel, pSel->bHeap);
		pSel = pTempSel;
	}
}
#ifdef ASF_IPV6_FP_SUPPORT
static inline void secfpv6_prefix_to_range(
	ASF_IPSecIPv6RangeAddr_t *range,
	ASF_IPv6Address_t *IPv6Addr,
	unsigned char plen)

{
	int bytes = plen >> 3;
	int bits = plen & 0x7;

	memset(range->start.u.b_addr, 0, sizeof(ASF_IPv6Address_t));
	memset(range->end.u.b_addr, 0xff, sizeof(ASF_IPv6Address_t));
	memcpy(range->start.u.b_addr, IPv6Addr->u.b_addr, bytes);
	memcpy(range->end.u.b_addr, IPv6Addr->u.b_addr, bytes);
	if (bits != 0) {
		range->start.u.b_addr[bytes] =
			IPv6Addr->u.b_addr[bytes] & (0xff00 >> bits);
		range->start.u.b_addr[bytes] =
			IPv6Addr->u.b_addr[bytes] | (0x00ff >> bits);
	}
}
#endif

unsigned int secfp_copySrcAndDestSelSet(
			SASel_t			**pSrcSel,
			SASel_t			**pDstSel,
			ASF_IPSecSASelector_t *pSASel,
			unsigned char		*pucSelFlags)
{
	SASel_t *pNewSel, *pPrevSel;
	int ii;
	unsigned char ucSelFlags, jj;
	char bHeap;

	ucSelFlags = SECFP_SA_XPORT_SELECTOR | SECFP_SA_SRCPORT_SELECTOR
		| SECFP_SA_SRCIPADDR_SELECTOR | SECFP_SA_DESTPORT_SELECTOR
		| SECFP_SA_DESTIPADDR_SELECTOR;

	pNewSel = *pSrcSel = (struct SASel_s *)asfGetNode(SASelPoolId_g,
							&bHeap);
	if (pNewSel && bHeap)
		pNewSel->bHeap = bHeap;

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
			pNewSel = (struct SASel_s *)asfGetNode(SASelPoolId_g,
								&bHeap);
			if (pNewSel && bHeap)
				pNewSel->bHeap = bHeap;

			if (pNewSel == NULL) {
				GlobalErrors.ulResourceNotAvailable++;
				ASFIPSEC_PRINT("Memory allocation failed"
					"for pNewSel#2");
				secfp_freeSelSet(*pSrcSel);
				return SECFP_FAILURE;
			}
			jj = 0;
		}

		pNewSel->selNodes[jj].proto = pSASel->srcSel[ii].protocol;
		if (pNewSel->selNodes[jj].proto == 0)
			ucSelFlags &= ~(SECFP_SA_XPORT_SELECTOR);

		pNewSel->selNodes[jj].prtStart = pSASel->srcSel[ii].port.start;
		pNewSel->selNodes[jj].prtEnd = pSASel->srcSel[ii].port.end;
		if (((pNewSel->selNodes[jj].prtStart == 0) &&
			((pNewSel->selNodes[jj].prtEnd == 0) ||
			(pNewSel->selNodes[jj].prtEnd == 0xffff)))) {
			ucSelFlags &= ~(SECFP_SA_SRCPORT_SELECTOR);
		}


		if (pSASel->srcSel[ii].IP_Version == 4) {
			pNewSel->selNodes[jj].IP_Version = 4;
			if (pSASel->srcSel[ii].addr.addrType ==
						ASF_IPSEC_ADDR_TYPE_RANGE) {
				pNewSel->selNodes[jj].ipAddrRange.v4.start =
				pSASel->srcSel[ii].addr.u.rangeAddr.v4.start;
				pNewSel->selNodes[jj].ipAddrRange.v4.end =
				pSASel->srcSel[ii].addr.u.rangeAddr.v4.end;
				pNewSel->selNodes[jj].ucMask = 32;
			} else {
				pNewSel->selNodes[jj].ucMask =
				pSASel->srcSel[ii].addr.u.prefixAddr.v4.IPv4Plen;
				pNewSel->selNodes[jj].ipAddrRange.v4.start =
				ASF_IPSEC4_GET_START_ADDR(\
					pSASel->srcSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
					pNewSel->selNodes[jj].ucMask);
				pNewSel->selNodes[jj].ipAddrRange.v4.end =
				ASF_IPSEC4_GET_END_ADDR(\
					pSASel->srcSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
					pNewSel->selNodes[jj].ucMask);

			}
			if ((pNewSel->selNodes[jj].ipAddrRange.v4.start == 0) &&
				(pNewSel->selNodes[jj].ipAddrRange.v4.end == 0xffffffff))
				ucSelFlags &= ~(SECFP_SA_SRCIPADDR_SELECTOR);

		}
#ifdef ASF_IPV6_FP_SUPPORT
		else if (pSASel->srcSel[ii].IP_Version == 6) {
			pNewSel->selNodes[jj].IP_Version = 6;
			if (pSASel->srcSel[ii].addr.addrType ==
					ASF_IPSEC_ADDR_TYPE_RANGE) {
				memcpy(&pNewSel->selNodes[jj].ipAddrRange,
					&pSASel->srcSel[ii].addr.u.rangeAddr,
					sizeof(ASF_IPSecRangeAddr_t));
				pNewSel->selNodes[jj].ucMask = 128;
			} else {
				pNewSel->selNodes[jj].ucMask =
					pSASel->srcSel[ii].addr.u.prefixAddr.v6.IPv6Plen;
				secfpv6_prefix_to_range(&pNewSel->selNodes[jj].ipAddrRange.v6,
					&pSASel->srcSel[ii].addr.u.prefixAddr.v6.IPv6Addr,
					pNewSel->selNodes[jj].ucMask);

			}
			/*
			if ((pNewSel->selNodes[jj].ipAddrStart == 0) &&
			(pNewSel->selNodes[jj].ipAddrEnd == 0xffffffff)) {
			ucSelFlags &= ~(SECFP_SA_SRCIPADDR_SELECTOR);
			}*/
		}
#endif

	}
	if (pPrevSel) {
		pPrevSel->pNext = pNewSel;
		pNewSel->pPrev = pPrevSel;
	}
	pNewSel->ucNumSelectors = jj;

	*pDstSel = pNewSel = (struct SASel_s *)asfGetNode(SASelPoolId_g,
							&bHeap);
	if (pNewSel && bHeap)
		pNewSel->bHeap = bHeap;

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
			pNewSel = (struct SASel_s *)asfGetNode(SASelPoolId_g,
								&bHeap);
			if (pNewSel && bHeap) {
				pNewSel->bHeap = bHeap;
			}
			if (pNewSel == NULL) {
				GlobalErrors.ulResourceNotAvailable++;
				ASFIPSEC_PRINT("Memory allocation failed"
					"for pNewSel#4");
				secfp_freeSelSet(*pSrcSel);
				secfp_freeSelSet(*pDstSel);
				return SECFP_FAILURE;
			}
			jj = 0;
		}

		pNewSel->selNodes[jj].proto = pSASel->dstSel[ii].protocol;
		if (pNewSel->selNodes[jj].proto == 0)
			ucSelFlags &= ~(SECFP_SA_XPORT_SELECTOR);

		pNewSel->selNodes[jj].prtStart = pSASel->dstSel[ii].port.start;
		pNewSel->selNodes[jj].prtEnd = pSASel->dstSel[ii].port.end;
		if ((pNewSel->selNodes[jj].prtStart == 0) &&
			((pNewSel->selNodes[jj].prtEnd == 0) ||
			(pNewSel->selNodes[jj].prtEnd == 0xffff)))
			ucSelFlags &= ~(SECFP_SA_DESTPORT_SELECTOR);


		if (pSASel->dstSel[ii].IP_Version == 4) {
			pNewSel->selNodes[jj].IP_Version = 4;
			if (pSASel->dstSel[ii].addr.addrType ==
					ASF_IPSEC_ADDR_TYPE_RANGE) {
				pNewSel->selNodes[jj].ipAddrRange.v4.start =
				pSASel->dstSel[ii].addr.u.rangeAddr.v4.start;
				pNewSel->selNodes[jj].ipAddrRange.v4.end =
				pSASel->dstSel[ii].addr.u.rangeAddr.v4.end;
				pNewSel->selNodes[jj].ucMask = 32;
			} else {
				pNewSel->selNodes[jj].ucMask =
				pSASel->dstSel[ii].addr.u.prefixAddr.v4.IPv4Plen;
				pNewSel->selNodes[jj].ipAddrRange.v4.start =
				ASF_IPSEC4_GET_START_ADDR(\
					pSASel->dstSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
					pNewSel->selNodes[jj].ucMask);
				pNewSel->selNodes[jj].ipAddrRange.v4.end =
				ASF_IPSEC4_GET_END_ADDR(\
					pSASel->dstSel[ii].addr.u.prefixAddr.v4.IPv4Addrs, \
					pNewSel->selNodes[jj].ucMask);

			}
			if ((pNewSel->selNodes[jj].ipAddrRange.v4.start == 0) &&
				(pNewSel->selNodes[jj].ipAddrRange.v4.end == 0xffffffff))
				ucSelFlags &= ~(SECFP_SA_SRCIPADDR_SELECTOR);
		}
#ifdef ASF_IPV6_FP_SUPPORT
		else if (pSASel->dstSel[ii].IP_Version == 6) {
			pNewSel->selNodes[jj].IP_Version = 6;
			if (pSASel->dstSel[ii].addr.addrType ==
					ASF_IPSEC_ADDR_TYPE_RANGE) {
				memcpy(&pNewSel->selNodes[jj].ipAddrRange,
					&pSASel->dstSel[ii].addr.u.rangeAddr,
					sizeof(ASF_IPSecRangeAddr_t));
				pNewSel->selNodes[jj].ucMask = 128;
			} else {
				pNewSel->selNodes[jj].ucMask =
				pSASel->dstSel[ii].addr.u.prefixAddr.v6.IPv6Plen;
				secfpv6_prefix_to_range(&pNewSel->selNodes[jj].ipAddrRange.v6,
					&pSASel->dstSel[ii].addr.u.prefixAddr.v6.IPv6Addr,
					pNewSel->selNodes[jj].ucMask);
			}

		}
#endif
	}
	if (pPrevSel) {
		pPrevSel->pNext = pNewSel;
		pNewSel->pPrev = pPrevSel;
	}
	pNewSel->ucNumSelectors = jj;

	*pucSelFlags = ucSelFlags;
	return SECFP_SUCCESS;
}

ASF_uint32_t asfFlushInSA(SPDInContainer_t *pInContainer,
			inSA_t *pInSA)
{
	SPDInSelTblIndexLinkNode_t *pNode;
	SPDInSPIValLinkNode_t *pSPINode;
	ASF_boolean_t bFound = ASF_FALSE;

	for (pNode = pInContainer->pSelIndex; pNode != NULL;
					pNode = pNode->pNext) {
		if (pInSA->ulSPDSelSetIndex == pNode->ulIndex) {
			bFound = ASF_TRUE;
			break;
		}
	}

	if (bFound == ASF_TRUE)
		secfp_deleteInContainerSelList(pInContainer, pNode);

	if (!pInSA)
		return SECFP_FAILURE;

	pSPINode = secfp_findInSPINode(pInContainer, pInSA->SAParams.ulSPI);

	if (pSPINode)
		secfp_deleteInContainerSPIList(pInContainer, pSPINode);


	if (pInSA->ulSPDSelSetIndexMagicNum == ptrIArray_getMagicNum(
		&secFP_InSelTable, pInSA->ulSPDSelSetIndex)) {
		ptrIArray_delete(&secFP_InSelTable,
			pInSA->ulSPDSelSetIndex, secfp_freeInSelSet);
	}
	secfp_deleteInSAFromSPIList(pInSA);
	return SECFP_SUCCESS;
}

ASF_uint32_t asfFlushAllOutSAs(ASF_uint32_t ulSPDOutContainerIndex)
{
	int ii, ulSAIndex, prevSAIndex = 0;
	SPDOutContainer_t *pOutContainer = NULL;
	SPDOutSALinkNode_t *pOutSALinkNode;

	pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
						ulSPDOutContainerIndex));
	if (!pOutContainer)
		return SECFP_FAILURE;

	if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
		for (ii = 0; ii < SECFP_MAX_DSCP_SA ; ii++) {
			if (pOutContainer->SAHolder.ulSAIndex[ii]
				!= ulMaxSupportedIPSecSAs_g) {
				ulSAIndex =
					pOutContainer->SAHolder.ulSAIndex[ii];
				pOutContainer->SAHolder.ulSAIndex[ii] =
					ulMaxSupportedIPSecSAs_g + 1;
				if (prevSAIndex == ulSAIndex)
					continue;
				prevSAIndex = ulSAIndex;
				ptrIArray_delete(&secFP_OutSATable,
					ulSAIndex, secfp_freeOutSA);
			}
		}
	} else {
		pOutSALinkNode = pOutContainer->SAHolder.pSAList;
		while (pOutSALinkNode != NULL) {
			ulSAIndex = pOutSALinkNode->ulSAIndex;
			secfp_delOutSALinkNode(pOutContainer, pOutSALinkNode);
			ptrIArray_delete(&secFP_OutSATable, ulSAIndex,
				secfp_freeOutSA);
			pOutSALinkNode = pOutContainer->SAHolder.pSAList;
		}
	}
	return SECFP_SUCCESS;
}

ASF_uint32_t asfFlushAllInSAs(ASF_uint32_t ulSPDInContainerIndex)
{
	SPDInContainer_t *pInContainer = NULL;
	SPDInSPIValLinkNode_t *pSPILinkNode;
	inSA_t *pInSA = NULL;
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

ASF_uint32_t ASFIPSecFlushContainers(ASF_uint32_t ulVSGId,
					ASF_uint32_t ulTunnelId)
{
	struct SPDCILinkNode_s *pCINode;
	int bVal = in_interrupt(), iRetVal;

	if (ulVSGId > ulMaxVSGs_g) {
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_WARN("Invalid VSG Id = %u", ulVSGId);
		return SECFP_FAILURE;
	}

	if (ulTunnelId > ulMaxTunnels_g) {
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_WARN("Invalid Tunnel Id = %u", ulTunnelId);
		return SECFP_FAILURE;
	}

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_PRINT("Tunnel Int is not in use.TunnelId=%u, VSGId=%u",
			ulTunnelId, ulVSGId);
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
	int bVal = in_interrupt(), iRetVal;

	if (ulVSGId > ulMaxVSGs_g) {
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_WARN("Invalid VSG Id = %u", ulVSGId);
		return SECFP_FAILURE;
	}

	if (ulTunnelId > ulMaxTunnels_g) {
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_WARN("Invalid Tunnel Id = %u", ulTunnelId);
		return SECFP_FAILURE;
	}

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_DEBUG("Tunnel Int is not in use.TunnelId=%u, VSGId=%u",
			ulTunnelId, ulVSGId);
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
	int bVal = in_interrupt();

	if (ulVSGId > ulMaxVSGs_g) {
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_WARN("Invalid VSG Id = %u", ulVSGId);
		return SECFP_FAILURE;
	}

	if (ulTunnelId > ulMaxTunnels_g) {
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_WARN("Invalid Tunnel Id = %u", ulTunnelId);
		return SECFP_FAILURE;
	}

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		GlobalErrors.ulTunnelIdNotInUse++;
		ASFIPSEC_PRINT("Tunnel Int is not in use.TunnelId=%u, VSGId=%u",
			ulTunnelId, ulVSGId);
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
