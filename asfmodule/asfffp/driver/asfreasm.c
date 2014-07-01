/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfreasm.c
 *
 * Description: Contains the reassembly/fragmentation routines for ASF
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/
#include <linux/version.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <8021q/vlan.h>
#include "asfparry.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfreasm.h"
#include "gplcode.h"
#include "asf.h"
#include "asfcmn.h"

/* #define ASF_REASM_DEBUG */

extern ASFFFPGlobalStats_t *asf_gstats;
#ifdef ASF_REASM_DEBUG
#define asf_reasm_debug(fmt, args...) printk("[CPU %d line %d %s] " fmt, smp_processor_id(), __LINE__, __FUNCTION__, ##args)
#else
#define asf_reasm_debug(fmt, args...)
#endif


#ifndef CONFIG_DPA
#define TRUE 1
#define FALSE 0
#endif


#ifdef ASF_REASM_USE_L2SRAM
#define ASF_REASM_BASE   (GFAR_SRAM_PBASE + GFAR_SRAM_SIZE  + SECFP_TOT_SRAM_SIZE)
#endif

unsigned long asf_reasm_num_cbs = ASF_REASM_MAX_NUM_CBS;
unsigned long asf_reasm_hash_list_size = ASF_REASM_MAX_HASH_LIST_SIZE;
#define ASF_REASM_NUM_CB_HASH_TBL_ENTRIES (asf_reasm_hash_list_size)
#define ASF_REASM_NUM_CBS		(asf_reasm_num_cbs)

#ifdef ASF_IPV6_FP_SUPPORT
unsigned long asf_ipv6_reasm_num_cbs = ASF_REASM_MAX_NUM_CBS;
unsigned long asf_ipv6_reasm_hash_list_size = ASF_REASM_MAX_HASH_LIST_SIZE;
#define ASF_IPV6_REASM_NUM_CB_HASH_TBL_ENTRIES (asf_ipv6_reasm_hash_list_size)
#define ASF_IPV6_REASM_NUM_CBS		(asf_ipv6_reasm_num_cbs)
#endif

#define ASF_NUM_FRAG_CBS_PER_REASM_CB	16
#define ASF_REASM_NUM_FRAG_CBS \
		(ASF_REASM_MAX_NUM_CBS * ASF_NUM_FRAG_CBS_PER_REASM_CB)
#define ASF_REASM_CB_PTRARRAY_SIZE \
	(NR_CPUS * sizeof(ptrIArry_nd_t *) * ASF_REASM_NUM_CBS)
#define ASF_REASM_TOT_SIZE \
	(ASF_REASM_HASH_TBL_SIZE + ASF_REASM_CB_PTRARRAY_SIZE)

#define ASF_REASM_NUM_TMR_BUCKETS ASF_REASM_MAX_NUM_CBS

#define ASF_REASM_NUM_APP_INFO_VARS	4

#define ASF_REASM_CB_POOL_ID_INDEX 0
#define ASF_REASM_FRAG_POOL_ID_INDEX 1
#define ASF_REASM_TIMER_POOL_ID_INDEX 2
#define ASF_REASM_IP_HDR_LEN 20

#define ASF_REASM_TIME_INTERVAL	10 /* 10 seconds */
#define ASF_REASM_NUM_RQ_ENTRIES 256  /* 256 per core */

#define ASF_REASM_IP_MAX_PKT_LEN 65535

#ifndef ASF_IPSEC_FP_SUPPORT
#define ASF_MAX_SKB_FRAGS MAX_SKB_FRAGS
#else
#define ASF_MAX_SKB_FRAGS 16
#endif

#ifdef CONFIG_DPA
#define ASF_EXTRA_TAIL_ROOM 128
#endif

/* Values taken from iGateway code */
extern int asf_reasm_timeout;
extern int asf_reasm_maxfrags;
extern int asf_reasm_min_fragsize;
#define ASF_MAX_FRAG_CNT	asf_reasm_maxfrags
#define ASF_MIN_FRAG_SIZE	asf_reasm_min_fragsize
#define ASF_MAX_REASM_TIMEOUT	asf_reasm_timeout

extern int asf_max_vsgs;

unsigned int asfReasmTmrCb(unsigned int ulVSGId,
			   unsigned int ulIndex, unsigned int ulMagicNum, unsigned int pCbArg4);

static int asfSkbCopyBits(const struct sk_buff *this_skb,
		int offset, void *to,
		int len);

struct asf_fragInfo_s {
	unsigned short int ulFragOffset;
	unsigned short int ulLen;
	unsigned short int ulSegMap;
	unsigned int ulCoreId;
	char bHeap;
	struct sk_buff *pHeadSkb;
	struct sk_buff *pTailSkb;
	struct asf_fragInfo_s *next;
	struct asf_fragInfo_s *prev;
} ;

struct asf_reasmCb_s {
	struct rcu_head rcu;
	char bHeap;
	struct asf_fragInfo_s frag;
	struct asf_fragInfo_s *fragList;
	unsigned int ulCoreId;
	union {
		unsigned int sip;
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t	ipv6sip;
#endif
	};
	union {
		unsigned int dip;
#ifdef ASF_IPV6_FP_SUPPORT
		ASF_IPv6Addr_t	ipv6dip;
#endif
	};
	unsigned int id;
	unsigned char proto;
	unsigned int ifIndex;
	unsigned int ulVSGId;
	unsigned int ulHashVal;
	unsigned int ulMagicNum;
	unsigned int ulPtrArrayIndex;
	int ulTotLen;
	int ulRecvLen;
	int ulNumFrags;
	int ulNumSkbs;
	int ulLastPktTime;
	asfTmr_t *ptmr;
	unsigned int ulAppInfo[ASF_REASM_NUM_APP_INFO_VARS];
	struct asf_reasmCb_s *pNext;
	struct asf_reasmCb_s *pPrev;
#ifdef ASF_REASM_NEED_INUSE
	atomic_t bInUse;
	spinlock_t lock;
	struct asf_fragInfo_s *queue;
#endif

} ;

#define ASF_REASM_HASH_TBL_SIZE \
	(NR_CPUS * ASF_REASM_NUM_CB_HASH_TBL_ENTRIES * sizeof(struct asf_reasmCb_s *))
struct asf_reasmList_s {
	struct asf_reasmCb_s *pReasmCbHead;
} ;

struct asf_reasmHashList_s {
	dma_addr_t paddr;
	unsigned long *vaddr;
	struct asf_reasmList_s *pHead;
} ;

struct asf_reasmCbPtrArray_s {
	struct {
		dma_addr_t paddr;
		unsigned long *vaddr;
		ptrIArry_tbl_t ptrArray;
	} ptrArrayInfo[ASF_MAX_VSGS];
};



/* Configuration data structure */
struct asf_reasmCfg_s {
	unsigned int ulMaxFragCnt;
	unsigned int ulMinFragSize;
	unsigned int ulMaxPktSize;
	unsigned int ulIpRsmTimeOutVal;
	unsigned int ulTimeOutInJiffies;
	bool bReasmEnabled;
} ;

struct asf_reasmHashList_s  *asf_ReasmCbHashList;

struct asf_reasmCbPtrArray_s *asf_ReasmCbPtrIndexArray;

#ifdef ASF_IPV6_FP_SUPPORT
struct asf_reasmHashList_s  *asf_ipv6_ReasmCbHashList;
struct asf_reasmCbPtrArray_s *asf_ipv6_ReasmCbPtrIndexArray;
#endif

struct asf_reasmCfg_s asf_reasmCfg[ASF_MAX_VSGS];

static unsigned int asf_reasmRandValue_g;

#ifdef ASF_IPV6_FP_SUPPORT
static unsigned int asf_ipv6_reasmRandValue_g;
#endif

#define ASF_MAX_REASM_POOLS 3
unsigned int asf_reasmPools[ASF_MAX_REASM_POOLS];

unsigned int asf_reasmIPv4_Id[NR_CPUS];

void asf_ip_options_fragment(struct sk_buff  *skb)
{
	skb = skb;
	return;
}


unsigned int asfReasmGetNextId(void)
{
	return asf_reasmIPv4_Id[smp_processor_id()]++;
}
void asfReasmInitConfig(void)
{
	int ii;
	for (ii = 0; ii < asf_max_vsgs; ii++) {
		asf_reasmCfg[ii].ulMaxFragCnt = ASF_MAX_FRAG_CNT;
		asf_reasmCfg[ii].ulMinFragSize = ASF_MIN_FRAG_SIZE;
		asf_reasmCfg[ii].ulMaxPktSize = ASF_REASM_IP_MAX_PKT_LEN;
		asf_reasmCfg[ii].ulIpRsmTimeOutVal = ASF_MAX_REASM_TIMEOUT;
		asf_reasmCfg[ii].ulTimeOutInJiffies = msecs_to_jiffies(1000 * asf_reasmCfg[ii].ulIpRsmTimeOutVal);
	}
}
int asfReasmInit(void)
{
	struct asf_reasmHashList_s *ptr;
	struct asf_reasmCbPtrArray_s *ptr1;
	int ii, numVSG;

	get_random_bytes(&asf_reasmRandValue_g, sizeof(asf_reasmRandValue_g));

	asf_ReasmCbHashList  = asfAllocPerCpu(sizeof(struct asf_reasmHashList_s));

	if (asf_ReasmCbHashList) {
		for_each_possible_cpu(ii)
		{
			ptr = asfPerCpuPtr(asf_ReasmCbHashList , ii);
#ifdef ASF_REASM_USE_L2SRAM
			asf_reasm_debug("ASF_REASM_BASE = 0x%x\r\n", ASF_REASM_BASE);
			ptr->paddr  = (unsigned long) (ASF_REASM_BASE) +
				      (ii * ASF_REASM_NUM_CB_HASH_TBL_ENTRIES *
				       sizeof(struct asf_reasmCb_s *));
			ptr->vaddr  = ioremap_flags(ptr->paddr,
						    (ASF_REASM_NUM_CB_HASH_TBL_ENTRIES *
						     sizeof(struct asf_reasmCb_s *)),
						    PAGE_KERNEL | _PAGE_COHERENT);
			asf_reasm_debug("ptr->paddr = 0x%x, ptr->vaddr = 0x%x, size = %d\r\n",
					ptr->paddr, ptr->vaddr, (ASF_REASM_NUM_CB_HASH_TBL_ENTRIES * sizeof(struct asf_reasmCb_s *)));

#else
			ptr->vaddr = kzalloc((sizeof(struct asf_reasmCb_s *) *
					      ASF_REASM_NUM_CB_HASH_TBL_ENTRIES), GFP_ATOMIC);
#endif
			if (!(ptr->vaddr)) {
				asf_reasm_debug("Could not allocate Reassembly context\
				 block Hash list for core = %d\r\n", ii);
				return 1;
			}
			ptr->pHead = (struct asf_reasmList_s *)  (ptr->vaddr);
			memset(ptr->pHead, 0, sizeof(struct asf_reasmCb_s *) *
			       ASF_REASM_NUM_CB_HASH_TBL_ENTRIES);
		}
	}

	asf_ReasmCbPtrIndexArray = asfAllocPerCpu(sizeof(struct asf_reasmCbPtrArray_s));

	if (asf_ReasmCbPtrIndexArray) {
		for_each_possible_cpu(ii)
		{
			ptr1 = asfPerCpuPtr(asf_ReasmCbPtrIndexArray, ii);
			for (numVSG = 0; numVSG < asf_max_vsgs; numVSG++) {
				ptr1->ptrArrayInfo[numVSG].vaddr =
				kzalloc((sizeof(ptrIArry_nd_t) *
					 ASF_REASM_NUM_CBS), GFP_KERNEL);

				if (!ptr1->ptrArrayInfo[numVSG].vaddr) {
					asf_reasm_debug("Memory allocation failed for\
					 Holding Reassembly context blocks CB\
					 Pointer Array, for VSG Id=%d, \
					core ID=%d\r\n", numVSG, ii);
					return 1;
				}

				ptrIArray_setup(
					       &(ptr1->ptrArrayInfo[numVSG].ptrArray),
					       (ptrIArry_nd_t *)  (ptr1->ptrArrayInfo[numVSG].vaddr),
					       ASF_REASM_NUM_CBS, 0);
			}
		}
	} else {
		asf_reasm_debug("Memory Allocation failed for holding Reassembly \
			context block array block's pointers \r\n");
		return 1;
	}
#ifdef ASF_IPV6_FP_SUPPORT
	get_random_bytes(&asf_ipv6_reasmRandValue_g, sizeof(asf_ipv6_reasmRandValue_g));

	asf_ipv6_ReasmCbHashList  = asfAllocPerCpu(sizeof(struct asf_reasmHashList_s));

	if (asf_ipv6_ReasmCbHashList) {
		for_each_possible_cpu(ii)
		{
			ptr = asfPerCpuPtr(asf_ipv6_ReasmCbHashList , ii);
			ptr->vaddr = kzalloc((sizeof(struct asf_reasmCb_s *) *
					      ASF_IPV6_REASM_NUM_CB_HASH_TBL_ENTRIES), GFP_ATOMIC);
			if (!(ptr->vaddr)) {
				asf_reasm_debug("Could not allocate Reassembly context\
				 block Hash list for core = %d\r\n", ii);
				return 1;
			}
			ptr->pHead = (struct asf_reasmList_s *)  (ptr->vaddr);
			memset(ptr->pHead, 0, sizeof(struct asf_reasmCb_s *) *
			       ASF_IPV6_REASM_NUM_CB_HASH_TBL_ENTRIES);
		}
	}

	asf_ipv6_ReasmCbPtrIndexArray = asfAllocPerCpu(sizeof(struct asf_reasmCbPtrArray_s));

	if (asf_ipv6_ReasmCbPtrIndexArray) {
		for_each_possible_cpu(ii)
		{
			ptr1 = asfPerCpuPtr(asf_ipv6_ReasmCbPtrIndexArray, ii);
			for (numVSG = 0; numVSG < asf_max_vsgs; numVSG++) {
				ptr1->ptrArrayInfo[numVSG].vaddr =
				kzalloc((sizeof(ptrIArry_nd_t) *
					 ASF_IPV6_REASM_NUM_CBS), GFP_KERNEL);

				if (!ptr1->ptrArrayInfo[numVSG].vaddr) {
					asf_reasm_debug("Memory allocation failed for\
					 Holding Reassembly context blocks CB\
					 Pointer Array, for VSG Id=%d, \
					core ID=%d\r\n", numVSG, ii);
					return 1;
				}

				ptrIArray_setup(
					       &(ptr1->ptrArrayInfo[numVSG].ptrArray),
					       (ptrIArry_nd_t *)  (ptr1->ptrArrayInfo[numVSG].vaddr),
					       ASF_IPV6_REASM_NUM_CBS, 0);
			}
		}
	} else {
		asf_reasm_debug("Memory Allocation failed for holding Reassembly \
			context block array block's pointers \r\n");
		return 1;
	}
#endif
	asfReasmInitConfig();

	asf_reasm_debug("Allocating pools\r\n");

	/* Pool allocations for Reassembly context blocks and Fragment context blocks, Timer blocks */
	if (asfCreatePool("ReassemCb",  ASF_REASM_NUM_CBS,
			  ASF_REASM_NUM_CBS, (ASF_REASM_NUM_CBS/2),
			  sizeof(struct asf_reasmCb_s),
			  &(asf_reasmPools[ASF_REASM_CB_POOL_ID_INDEX]))) {
		asf_reasm_debug("Error in creating pool \r\n");
		asfReasmDeInit();
		return 1;
	}
	asf_reasm_debug("ReassemCb: PoolId = %d\r\n", asf_reasmPools[ASF_REASM_CB_POOL_ID_INDEX]);

	if (asfCreatePool("TimerCb", ASF_REASM_NUM_CBS,
			  ASF_REASM_NUM_CBS, (ASF_REASM_NUM_CBS/2),
			  sizeof(asfTmr_t),
			  &(asf_reasmPools[ASF_REASM_TIMER_POOL_ID_INDEX]))) {
		asf_reasm_debug("Error in creating pool \r\n");
		asfReasmDeInit();
		return 1;
	}

	asf_reasm_debug("Timer : PoolId = %d\r\n", asf_reasmPools[ASF_REASM_TIMER_POOL_ID_INDEX]);

	if (asfCreatePool("FragCb", ASF_REASM_NUM_FRAG_CBS,
			  ASF_REASM_NUM_FRAG_CBS, (ASF_REASM_NUM_FRAG_CBS/2),
			  sizeof(struct asf_fragInfo_s),
			  &(asf_reasmPools[ASF_REASM_FRAG_POOL_ID_INDEX]))) {
		asf_reasm_debug("Error in creating pool\r\n");
		asfReasmDeInit();
		return 1;
	}
	asf_reasm_debug("FragCb: PoolId = %d\r\n", asf_reasmPools[ASF_REASM_FRAG_POOL_ID_INDEX]);

	/* Instantiate the timer wheel */
	asf_reasm_debug("Instantiating timer wheels\r\n");

	if (asfTimerWheelInit(ASF_REASM_TMR_ID, 0,
			      ASF_REASM_NUM_TMR_BUCKETS, ASF_TMR_TYPE_SEC_TMR,
			      ASF_REASM_TIME_INTERVAL, ASF_REASM_NUM_RQ_ENTRIES) == 1) {
		asf_reasm_debug("Error in initializing Timer wheel \r\n");
		asfReasmDeInit();
		return 1;
	}

	/* Register the callback function and timer pool Id */

	if (asfTimerAppRegister(ASF_REASM_TMR_ID, 0,
				(asfTmrCbFn) asfReasmTmrCb,
				(asf_reasmPools[ASF_REASM_TIMER_POOL_ID_INDEX]))) {
		asf_reasm_debug("Error in registering Cb Fn/Pool Id \r\n");
		asfReasmDeInit();
		return 1;
	}

	asf_reasm_debug("Reassembly module initialized.\n");
	return 0;
}


void asfReasmDeInit(void)
{
	asfTimerWheelDeInit(ASF_REASM_TMR_ID, 0);
	asf_reasm_debug("Not implemented!\n");
}


#define ASF_GET_VFRAGINFO(sip, dip, ports, proto, cb1, cb2, cb3, cb4, pReasmCb)	do { \
		sip = pReasmCb->sip;	\
		dip = pReasmCb->dip;	\
		ports = pReasmCb->ports;	\
		proto = pReasmCb->proto;	\
		cb1 = pReasmCb->cb1;	\
		cb2 = pReasmCb->cb2;	\
		cb3 = pReasmCb->cb3;	\
		cb4 = pReasmCb->cb4;	\
	} while (0)


void asfReasmCleanCb(struct rcu_head  *rcu)
{
	struct asf_reasmCb_s *pCb = (struct asf_reasmCb_s *)  rcu;
	struct asf_fragInfo_s *pFrag, *pNextFrag;
	struct sk_buff *skb, *pTempSkb;

#ifdef ASF_REASM_DEBUG
	asf_reasm_debug("asfReasmCleanCb called\r\n");
#endif
	for (pFrag = pCb->fragList; pFrag != NULL;  pFrag = pNextFrag) {
		for (skb = pFrag->pHeadSkb; skb != NULL; skb = pTempSkb) {
			pTempSkb = skb->next;
			ASF_gfar_kfree_skb(skb);
		}
		pNextFrag = pFrag->next;
		if (pFrag->bHeap != 2) /* part of Cb itself; so don't release it to mempool */
			asfReleaseNode(
				      asf_reasmPools[ASF_REASM_FRAG_POOL_ID_INDEX],
				      (void *)  pFrag, pFrag->bHeap);
	}
	/* Release the cb */
	asfReleaseNode(asf_reasmPools[ASF_REASM_CB_POOL_ID_INDEX],
		       (void *)  pCb, (pCb->bHeap));
}



static inline void asfReasmDeleteCb(struct asf_reasmCb_s *pCb)
{
#ifdef ASF_REASM_DEBUG
	asf_reasm_debug("asfReasmDeleteCb called\r\n");
#endif

	ptrIArray_delete(&(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
					smp_processor_id())->ptrArrayInfo[pCb->ulVSGId].ptrArray),
			 pCb->ulPtrArrayIndex, asfReasmCleanCb);


}

#ifdef ASF_IPV6_FP_SUPPORT
static inline void asfIPv6ReasmDeleteCb(struct asf_reasmCb_s *pCb)
{
#ifdef ASF_REASM_DEBUG
	asf_reasm_debug("asfReasmDeleteCb called\r\n");
#endif

	ptrIArray_delete(&(asfPerCpuPtr(asf_ipv6_ReasmCbPtrIndexArray,
					smp_processor_id())->ptrArrayInfo[pCb->ulVSGId].ptrArray),
			 pCb->ulPtrArrayIndex, asfReasmCleanCb);


}
#endif
#ifdef CONFIG_DPA
extern struct sk_buff *asf_alloc_buf_skb(struct net_device *dev);
extern int asf_free_buf_skb(struct net_device *dev, struct sk_buff *skb);
#endif

static inline unsigned int asfReasmComputeHash(unsigned int word_a, unsigned int word_b, unsigned int word_c)
{ /* Bob jenkins hash */
	unsigned int hash;

	register unsigned int temp_a, temp_b, temp_c;
	temp_a = temp_b = 0x9e3779b9;/* the golden ratio; an arbitrary value */
	temp_c = asf_reasmRandValue_g;/* random value*/

	temp_a += word_a;
	temp_b += word_b;
	temp_c += word_c;

	ASF_BJ3_MIX(temp_a, temp_b, temp_c);
	hash = temp_c & (ASF_REASM_NUM_CB_HASH_TBL_ENTRIES-1);
	return hash;
}


/*
 * Inline function to set up the fragment information CB
 * This is required for quick validation when other fragments are
 * received
 */

static inline void asfReasmUpdateFrag(struct asf_reasmCb_s *pCb,
					  unsigned int ulOffset, unsigned int flags, unsigned int ulSegLen)
{
	/* Create fragment holder to hold the rcvd fragment */
	/* We just received the first fragment	*/
	struct asf_fragInfo_s *frag;

	pCb->fragList = &(pCb->frag);
	frag = &(pCb->frag);
	frag->bHeap  = 2 ; /* Don't free this fragment */
	frag->ulFragOffset = ulOffset;
	frag->ulLen = ulSegLen;
	frag->ulSegMap = ulOffset + ulSegLen;
#ifdef ASF_REASM_DEBUG
	asf_reasm_debug("frag->ulSegMap =%d\r\n", frag->ulSegMap);
#endif

	if ((flags & IP_MF) == 0) {
		pCb->ulTotLen = ulOffset + ulSegLen;
	}
	pCb->ulRecvLen = ulSegLen;
	pCb->ulNumFrags++;

}


static inline void asfRemCbFromHashList(unsigned int hashVal,  struct asf_reasmCb_s *pCb)
{
	struct asf_reasmCb_s *pHead  =
	asfPerCpuPtr(asf_ReasmCbHashList,
		     smp_processor_id())->pHead[hashVal].pReasmCbHead;

	if (pCb == pHead) {
		pHead
		= asfPerCpuPtr(asf_ReasmCbHashList, smp_processor_id())->pHead[hashVal].pReasmCbHead
		  = pCb->pNext;

		if (pHead) {
			pHead->pPrev = NULL;
		}
	} else {
		if (pCb->pPrev)
			pCb->pPrev->pNext = pCb->pNext;
		if (pCb->pNext)
			pCb->pNext->pPrev = pCb->pPrev;
	}
	pCb->pPrev = NULL;
	pCb->pNext = NULL;
}


static inline void asfAddCbToHashList(unsigned int hashVal, struct asf_reasmCb_s *pCb)
{
	struct asf_reasmCb_s *pHead  = asfPerCpuPtr(asf_ReasmCbHashList,
						    smp_processor_id())->pHead[hashVal].pReasmCbHead;

	if (pHead) {
		pHead->pPrev = pCb;
	}
	pCb->pNext = pHead;
	pCb->pPrev = NULL;
	asfPerCpuPtr(asf_ReasmCbHashList,
		     smp_processor_id())->pHead[hashVal].pReasmCbHead = pCb;
}
#ifdef ASF_IPV6_FP_SUPPORT
static inline void asfIPv6RemCbFromHashList(unsigned int hashVal,  struct asf_reasmCb_s *pCb)
{
	struct asf_reasmCb_s *pHead  =
	asfPerCpuPtr(asf_ipv6_ReasmCbHashList,
		     smp_processor_id())->pHead[hashVal].pReasmCbHead;

	if (pCb == pHead) {
		pHead
		= asfPerCpuPtr(asf_ipv6_ReasmCbHashList, smp_processor_id())->pHead[hashVal].pReasmCbHead
		  = pCb->pNext;

		if (pHead) {
			pHead->pPrev = NULL;
		}
	} else {
		if (pCb->pPrev)
			pCb->pPrev->pNext = pCb->pNext;
		if (pCb->pNext)
			pCb->pNext->pPrev = pCb->pPrev;
	}
	pCb->pPrev = NULL;
	pCb->pNext = NULL;
}


static inline void asfIPv6AddCbToHashList(unsigned int hashVal, struct asf_reasmCb_s *pCb)
{
	struct asf_reasmCb_s *pHead  = asfPerCpuPtr(asf_ipv6_ReasmCbHashList,
						    smp_processor_id())->pHead[hashVal].pReasmCbHead;

	if (pHead) {
		pHead->pPrev = pCb;
	}
	pCb->pNext = pHead;
	pCb->pPrev = NULL;
	asfPerCpuPtr(asf_ipv6_ReasmCbHashList,
		     smp_processor_id())->pHead[hashVal].pReasmCbHead = pCb;
}
#endif
/*
 * Function Name: asf_ipv4ReasmFindOrCreateCb
 * Input: ulVSGId, to find out Configuration information
 *	skb - the buffer that was recieved
 *	hashVal - hash value already calculated
 * Return value - If there is a match, returns the matched Reassembly CB.
 *	      - If there is no match, if config permits and memory avail,
 *		creates CB with as much information, adds to list and
 *		returns
 */

static inline struct asf_reasmCb_s *asfIPv4ReasmFindOrCreateCb(
							      unsigned int ulVSGId, struct sk_buff *skb,
							      unsigned int  hashVal) {
	struct asf_reasmCb_s *pCb, *tpCb;
	char bHeap;
	struct iphdr *iph = ip_hdr(skb);
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());

	pCb = asfPerCpuPtr(asf_ReasmCbHashList,
			   smp_processor_id())->pHead[hashVal].pReasmCbHead;

	for (; pCb != NULL; pCb = pCb->pNext) {
		prefetchw(pCb->pNext);
		if ((iph->id == pCb->id) &&
		    (iph->protocol == pCb->proto) &&
		    (iph->saddr == pCb->sip) &&
		    (iph->daddr == pCb->dip) &&
		    (ulVSGId == pCb->ulVSGId)) {
			return pCb;
		}
	}
	pCb = (struct asf_reasmCb_s *)
	      asfGetNode(asf_reasmPools[ASF_REASM_CB_POOL_ID_INDEX], &bHeap);
	if (pCb) {
		/* Get an entry in the pointer array index */
		pCb->ulPtrArrayIndex  =  ptrIArray_add(
						      &(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
								     smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
						      pCb);

		if (pCb->ulPtrArrayIndex < ASF_REASM_NUM_CBS) {
			pCb->ulMagicNum = ptrIArray_getMagicNum(
							       &(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
									      smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
							       pCb->ulPtrArrayIndex);

			pCb->ulHashVal = hashVal;

			/* Now assign information and add it into list */
			pCb->id = iph->id;
			pCb->proto = iph->protocol;
			pCb->sip = iph->saddr;
			pCb->dip = iph->daddr;
#ifdef ASF_REASM_DEBUG
			asf_reasm_debug("Getting Reasm Cb from %d\r\n", bHeap);
#endif
			pCb->bHeap = bHeap;
			pCb->ifIndex = skb->dev->ifindex;
			pCb->ulVSGId = ulVSGId;
			pCb->ulLastPktTime = jiffies;


			/* Add into list */
			asfAddCbToHashList(hashVal, pCb);

			pCb->ptmr = asfTimerStart(ASF_REASM_TMR_ID, 0,
						asf_reasmCfg[pCb->ulVSGId].ulIpRsmTimeOutVal,
						pCb->ulVSGId,
						pCb->ulPtrArrayIndex,
						pCb->ulMagicNum, REASM_IPv4, 0);

			if (!(pCb->ptmr)) {
				asfRemCbFromHashList(hashVal, pCb);
				asf_reasm_debug("Timer start failed\r\n");
				asfReasmDeleteCb(pCb);
				return NULL;
			}

			return pCb;
		} else {
			int flushed_entries = 0;
			asf_reasm_debug("Out of context blocks in Index array \r\n");
			asfReleaseNode(asf_reasmPools[ASF_REASM_CB_POOL_ID_INDEX], pCb,
				       bHeap);
			gstats->ulMiscFailures++;
			for (hashVal = 0;
				hashVal < ASF_REASM_NUM_CB_HASH_TBL_ENTRIES - 1;
				hashVal++) {
					pCb = asfPerCpuPtr(asf_ReasmCbHashList,
					smp_processor_id())->pHead[hashVal].
						pReasmCbHead;
					for (; pCb != NULL; pCb = tpCb) {
						prefetchw(pCb->pNext);
						asfTimerStop(ASF_REASM_TMR_ID,
								0, pCb->ptmr);
						asfRemCbFromHashList(
							pCb->ulHashVal, pCb);
						tpCb = pCb->pNext;
						asfReasmDeleteCb(pCb);
						flushed_entries++;
						if (flushed_entries > 50)
							return NULL;
					}
			}
			return NULL;
		}
	}
	gstats->ulErrAllocFailures++;
	return NULL;
}


#ifdef ASF_IPV6_FP_SUPPORT
static inline struct asf_reasmCb_s *asfIPv6ReasmFindOrCreateCb(
							      unsigned int ulVSGId, struct sk_buff *skb,
							      unsigned int  hashVal) {
	struct asf_reasmCb_s *pCb, *tpCb;
	char bHeap;
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct frag_hdr *fhdr = (struct frag_hdr *)skb_transport_header(skb);
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());

	pCb = asfPerCpuPtr(asf_ipv6_ReasmCbHashList,
			   smp_processor_id())->pHead[hashVal].pReasmCbHead;

	for (; pCb != NULL; pCb = pCb->pNext) {
		prefetchw(pCb->pNext);
		if ((fhdr->identification == pCb->id) &&
		    (fhdr->nexthdr == pCb->proto)     &&
		    (!_ipv6_addr_cmp((struct in6_addr *)&(ip6h->saddr), (struct in6_addr *)&(pCb->ipv6sip))) &&
		    (!_ipv6_addr_cmp((struct in6_addr *)&(ip6h->daddr), (struct in6_addr *)&(pCb->ipv6dip))) &&
		    (ulVSGId == pCb->ulVSGId)) {
			return pCb;
		}
	}
	pCb = (struct asf_reasmCb_s *)
	      asfGetNode(asf_reasmPools[ASF_REASM_CB_POOL_ID_INDEX], &bHeap);
	if (pCb) {
		/* Get an entry in the pointer array index */
		pCb->ulPtrArrayIndex  =  ptrIArray_add(
						      &(asfPerCpuPtr(asf_ipv6_ReasmCbPtrIndexArray,
								     smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
						      pCb);

		if (pCb->ulPtrArrayIndex < ASF_REASM_NUM_CBS) {
			pCb->ulMagicNum = ptrIArray_getMagicNum(
							       &(asfPerCpuPtr(asf_ipv6_ReasmCbPtrIndexArray,
									      smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
							       pCb->ulPtrArrayIndex);

			pCb->ulHashVal = hashVal;

			/* Now assign information and add it into list */
			pCb->id = fhdr->identification;
			pCb->proto = fhdr->nexthdr;
			ipv6_addr_copy((struct in6_addr *)&(pCb->ipv6sip), (struct in6_addr *)&(ip6h->saddr));
			ipv6_addr_copy((struct in6_addr *)&(pCb->ipv6dip), (struct in6_addr *)&(ip6h->daddr));
#ifdef ASF_REASM_DEBUG
			asf_reasm_debug("Getting Reasm Cb from %d\r\n", bHeap);
#endif
			pCb->bHeap = bHeap;
			pCb->ifIndex = skb->dev->ifindex;
			pCb->ulVSGId = ulVSGId;
			pCb->ulLastPktTime = jiffies;


			/* Add into list */
			asfIPv6AddCbToHashList(hashVal, pCb);

			pCb->ptmr = asfTimerStart(ASF_REASM_TMR_ID, 0,
						asf_reasmCfg[pCb->ulVSGId].ulIpRsmTimeOutVal,
						pCb->ulVSGId,
						pCb->ulPtrArrayIndex,
						pCb->ulMagicNum, REASM_IPv6, 1);

			if (!(pCb->ptmr)) {
				asfIPv6RemCbFromHashList(hashVal, pCb);
				asf_reasm_debug("Timer start failed\r\n");
				asfIPv6ReasmDeleteCb(pCb);
				return NULL;
			}

			return pCb;
		} else {
			int flushed_entries = 0;
			asf_reasm_debug("Out of context blocks in Index array \r\n");
			asfReleaseNode(asf_reasmPools[ASF_REASM_CB_POOL_ID_INDEX], pCb,
				       bHeap);
			gstats->ulMiscFailures++;
			for (hashVal = 0;
				hashVal < ASF_REASM_NUM_CB_HASH_TBL_ENTRIES - 1;
				hashVal++) {
					pCb = asfPerCpuPtr(asf_ipv6_ReasmCbHashList,
					smp_processor_id())->pHead[hashVal].
						pReasmCbHead;
					for (; pCb != NULL; pCb = tpCb) {
						prefetchw(pCb->pNext);
						asfTimerStop(ASF_REASM_TMR_ID,
								0, pCb->ptmr);
						asfIPv6RemCbFromHashList(
							pCb->ulHashVal, pCb);
						tpCb = pCb->pNext;
						asfIPv6ReasmDeleteCb(pCb);
						flushed_entries++;
						if (flushed_entries > 50)
							return NULL;
					}
			}
			return NULL;
		}
	}
	gstats->ulErrAllocFailures++;
	return NULL;
}
#endif
static inline int asfIPv4CheckFragInfo(struct sk_buff *skb,
				       int *offset,  unsigned int *flags, unsigned int *ulSegLen,
				       int *pIhl, unsigned int ulVSGId)
{
	struct iphdr *iph;
	int ihl;
	unsigned short	host_ip_tot_len;
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());

	iph = ip_hdr(skb);
	host_ip_tot_len = ASF_NTOHS(iph->tot_len);
	*pIhl = ihl = iph->ihl * 4;

	if (unlikely((iph->ihl < 5) || (ihl >= skb->len)))
	{
		asf_reasm_debug("IP Header length is invalid \r\n");
		gstats->ulErrIpHdr++;
		return 1;
	}

	if (((iph->frag_off & (htons(IP_MF))))) {
		if (unlikely((host_ip_tot_len - (iph->ihl*4)) & 7)) {
			asf_reasm_debug("Invalid data length\r\n");
			gstats->ulErrIpHdr++;
			return 1;
		}
		if (unlikely(host_ip_tot_len < asf_reasmCfg[ulVSGId].ulMinFragSize)) {
			asf_reasm_debug("Length is smaller than min fragment size\r\n");
			gstats->ulErrIpHdr++;
			return 1;
		}
	}

	if (unlikely(skb->len < host_ip_tot_len)) {
		asf_reasm_debug(" Length is invalid\r\n");
		gstats->ulErrIpHdr++;
		return 1;
	}

	if (unlikely((host_ip_tot_len - ihl) == 0)) {
		asf_reasm_debug("Invalid data length \r\n");
		gstats->ulErrIpHdr++;
		return 1;
	}

	if (unlikely((host_ip_tot_len - ihl) > (skb->len  - ihl))) {
		asf_reasm_debug("Length is invalid \r\n");
		gstats->ulErrIpHdr++;
		return 1;
	}

	*offset = ASF_NTOHS(ip_hdr(skb)->frag_off);
	*flags = *offset & ~IP_OFFSET;
	*offset &= IP_OFFSET;
	asf_reasm_debug("*offset before shifting = %d\r\n", *offset);
	*offset <<= 3;
	asf_reasm_debug("*offset after shifting = %d\r\n", *offset);


	if (unlikely(host_ip_tot_len > (ASF_REASM_IP_MAX_PKT_LEN - *offset))) {
		asf_reasm_debug("Length is invalid \r\n");
		gstats->ulErrIpHdr++;
		return 1;
	}
	*ulSegLen = host_ip_tot_len - ihl;
	return 0;
}

static inline int asfIPv6CheckFragInfo(struct sk_buff *skb,
				       int *offset,  unsigned int *flags, unsigned int *ulSegLen,
				       int *pIhl, unsigned int ulVSGId)
{
	struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	struct frag_hdr *fhdr = (struct frag_hdr *)skb_transport_header(skb);
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	unsigned int frag_len = skb->len - ((uintptr_t)(fhdr + 1) - (uintptr_t)ipv6h);

	*pIhl = ((uintptr_t)(fhdr + 1) - (uintptr_t)ipv6h);

	if (unlikely(frag_len) <= 0) {
		asf_reasm_debug("Invalid data length\r\n");
		gstats->ulErrIpHdr++;
		return 1;
	}
	if (((fhdr->frag_off & (htons(IP_MF))))) {
		if (unlikely(frag_len & 7)) {
			asf_reasm_debug("Invalid data length\r\n");
			gstats->ulErrIpHdr++;
			return 1;
		}
		if (unlikely(frag_len < asf_reasmCfg[ulVSGId].ulMinFragSize)) {
			asf_reasm_debug("Length is smaller than min fragment size\r\n");
			gstats->ulErrIpHdr++;
			return 1;
		}
	}

	*offset = fhdr->frag_off;
	*flags = *offset & 0x1; /* Only MF bit is there */
	*flags = *flags << 13; /* Hack to convert IPV6 MF bit to IPv4 bit, this is done to make the rest of the processing work for both */
	*offset &= ~0x7; /*offset is in multiple of 8, already shited by 3 bits */

	if (unlikely(*offset + frag_len > (ASF_REASM_IP_MAX_PKT_LEN))) {
		asf_reasm_debug("Length is invalid \r\n");
		gstats->ulErrIpHdr++;
		return 1;
	}
	*ulSegLen = frag_len;
	return 0;
}

#define ASF_ADJUST_PREVFRAG 1
#define ASF_ADJUST_NEXTFRAG 2
#define ASF_ADJUST_NONE 3

static inline struct sk_buff  *asfFragHandle(struct asf_reasmCb_s *pCb,
						 struct sk_buff *skb, unsigned int *pOffset,
						 unsigned int flags, unsigned int *pLen, unsigned int ihl,
						 bool *bReasmDone, struct asf_fragInfo_s **frag, unsigned char *option) {
	struct asf_fragInfo_s *pFrag, *pFragPrev;
	unsigned int ulSegMap;
	unsigned int updateLen;
	struct asf_fragInfo_s *newFrag;
	char bHeap;
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());


	asf_reasm_debug("FragHandle: pCb->ulNumFrags=%d, pCb->fragList = 0x%x\r\n", pCb->ulNumFrags, pCb->fragList);
	if (pCb->ulNumFrags == 1) {
		pFrag = pCb->fragList;

		/* Only one fragment received so far, and let us test the best
		    case for 2 fragment cases and no overlap */

		if (likely((flags & IP_MF) == 0)) {
			asf_reasm_debug("Received 2nd fragment: checking for overlap\r\n");
			asf_reasm_debug("*pOffset=%d, pFrag->ulSegMap=%d, pFrag->ulLen=%d\r\n", *pOffset, pFrag->ulSegMap, pFrag->ulLen);

			/* We recieved 2nd fragments,let try for 2 overlap */
			/* Prev seg length + current segment length
				equals, expected total length (i.e offset
				+ ulSegLen, this being the last fragment
			*/
			if (likely((*pOffset == pFrag->ulSegMap) &&
				   (*pOffset == pFrag->ulLen))) {
				/* We got it all */
				*bReasmDone = TRUE;
				*frag = pFrag;
				*option = ASF_ADJUST_PREVFRAG;
				pCb->ulTotLen = *pOffset + *pLen;
				asf_reasm_debug("Returing skb from fragHandle\r\n");
				return skb;
			}
		}

		if (likely(pCb->ulTotLen)) {
			/* We recieved 2nd fragments,let try for 1 overlap */
			if (likely(((*pOffset + *pLen) == pFrag->ulFragOffset)
				   && ((*pLen + pFrag->ulLen) == pCb->ulTotLen))) {
				/* 2nd fragment came first */
				/* but we got it all */
				/* so let us go */
				*bReasmDone = TRUE;
				*frag = pFrag;
				*option = ASF_ADJUST_NEXTFRAG;
				return skb;
			}

		}
		/* Let it fall through and we can find the
			bad part along with
		    > 1 queued fragment cases */
	}


	/* Check if we have exceeded the max number of fragments */
	if (unlikely((pCb->ulNumFrags+1) >
		     asf_reasmCfg[pCb->ulVSGId].ulMaxFragCnt)) {
		asf_reasm_debug("Number of fragments exceeded\r\n");
		ASFSkbFree(skb);
		gstats->ulErrIpHdr++;
		return NULL;
	}

	/* Check if last fragment is repeated and if so
	the lengths are the same */
	if ((flags & IP_MF) == 0) {
		if (unlikely(pCb->ulTotLen)) {
			if (pCb->ulTotLen != (*pOffset + *pLen)) {
				asf_reasm_debug("Last fragment length different: pCb->ulTotalLen = %d, *pOffset =%d, *pLen = %d\r\n", pCb->ulTotLen, *pOffset, *pLen);
				ASFSkbFree(skb);
				gstats->ulErrIpHdr++;
				return NULL;
			}
		} else {
			pCb->ulTotLen = *pOffset + *pLen;
		}
	}

	/* Find the next fragment */
	*option = ASF_ADJUST_NONE;
	for (pFragPrev = NULL, pFrag = pCb->fragList;
	    pFrag != NULL;
	    pFrag = pFrag->next) {
		asf_reasm_debug("pFrag->ulFragOffset = 0x%x >"\
			" pOffset = 0x%x\n", pFrag->ulFragOffset, *pOffset);
		if (pFrag->ulFragOffset > *pOffset) {
			break;
		}
		pFragPrev = pFrag;
	}

	asf_reasm_debug("FragHandle: Prev fragment = 0x%x, next fragment = 0x%x\r\n", pFragPrev, pFrag);


	ulSegMap = *pLen + *pOffset;
	if (pFragPrev) {
		asf_reasm_debug("FragHandle:  ulSegMap = %d, pFragPrev->"\
			"ulSegMap = %d\n", ulSegMap, pFragPrev->ulSegMap);
		if (unlikely(((*pOffset >= pFragPrev->ulFragOffset)
			      && ((ulSegMap) <= (pFragPrev->ulSegMap))))) {
			asf_reasm_debug("IPREASM_SYSMSGID_OVERLAP_IPFRAG_8\r\n");
			ASFSkbFree(skb);
			gstats->ulErrIpHdr++;
			return NULL;
		} else if (unlikely((*pOffset <= pFragPrev->ulFragOffset) &&
				    (ulSegMap >= pFragPrev->ulSegMap) &&
				    (pFragPrev->next
				     ? pFragPrev->next->ulFragOffset > ulSegMap : TRUE) &&
				    (pFragPrev->prev ?
				     pFragPrev->prev->ulSegMap < *pOffset : TRUE))) {
			asf_reasm_debug("complete overlap over small packet\r\n");

			/* Trim the buffer */
			*pOffset += pFragPrev->ulSegMap;
			*pLen -= pFragPrev->ulLen;
			if (*pLen == 0) {
				ASFSkbFree(skb);
				return NULL;
			}
			ulSegMap = *pOffset + *pLen;
			/* Prepend buffer to previous fragment */
			/*
			 pFragPrev->ulLen += *pLen;
			 *pFrag = pFragPrev;
			return skb;
			*/

			*option = ASF_ADJUST_PREVFRAG;
		} else if ((*pOffset > pFragPrev->ulFragOffset) &&
			   (ulSegMap >= pFragPrev->ulSegMap) &&
			   (*pOffset <= pFragPrev->ulSegMap)) {
			if (pFrag ? (ulSegMap < pFrag->ulSegMap)
			    && (ulSegMap >= pFrag->ulFragOffset)
			    : *pOffset != pFragPrev->ulSegMap) {
				/* Post overlap */
				asf_reasm_debug("Overlapped IP frag rcvd\r\n");
				updateLen = pFragPrev->ulSegMap
					    - *pOffset;
				if (updateLen != 0) {
					asf_reasm_debug("Overlapped\r\n");
				}
				*pOffset += updateLen;
				*pLen -= updateLen;
				ulSegMap = *pOffset + *pLen;
				if (*pLen == 0) {
					ASFSkbFree(skb);
					return NULL;
				}
			}
			*option = ASF_ADJUST_PREVFRAG;
		} else if (((*pOffset > pFragPrev->ulFragOffset) &&
			     (*pOffset <= pFragPrev->ulSegMap) &&
			     (pFrag ? ulSegMap >= pFrag->ulSegMap : FALSE))
			    ||
			    ((*pOffset < pFragPrev->ulFragOffset) &&
			     (pFrag ? pFrag->ulFragOffset < ulSegMap : FALSE))
			    ||
			    ((*pOffset < pFragPrev->ulFragOffset) &&
			     (pFrag ? pFrag->next ?
			      (pFrag->next->ulSegMap < ulSegMap) :
			      (pFrag->ulSegMap < ulSegMap) : FALSE))) {
			asf_reasm_debug("Complete overlap over a set of fragments\r\n");
			ASFSkbFree(skb);
			return NULL;
		}

		if (pFrag ? (ulSegMap < pFrag->ulSegMap)
		    && (ulSegMap >= pFrag->ulFragOffset) : FALSE) {
			/* To be checked */
			updateLen =  ulSegMap - pFrag->ulFragOffset;
			if (updateLen) {
				asf_reasm_debug("Overlap with next segment\r\n");

			}
			*pLen -= updateLen;
			ulSegMap = *pOffset + *pLen;
			if (*pLen == 0) {
				ASFSkbFree(skb);
				return NULL;
			}
			*option = ASF_ADJUST_NEXTFRAG;
		}

	}

	if ((pFrag) && (pFrag->ulFragOffset < ulSegMap)) { /* Overlapping successive fragments */

		updateLen = ulSegMap - pFrag->ulFragOffset;
		if (updateLen) {
			asf_reasm_debug("Overlapped IP fragment received\r\n");
		}
		*pLen -= updateLen;
		ulSegMap = *pOffset + *pLen;
		if (*pLen == 0) {
			ASFSkbFree(skb);
			asf_reasm_debug("Dropping fragment \r\n");
			return NULL;
		}
		asf_reasm_debug("Setting Option = ASF_ADJUST_NEXT_FRAG\r\n");

		*option = ASF_ADJUST_NEXTFRAG;
	}

	if (*option == ASF_ADJUST_NONE) {
		if (pFragPrev) {
			if (pFragPrev->ulSegMap == *pOffset) {
				*option = ASF_ADJUST_PREVFRAG;
			}
		} else if (pFrag) {
			if (pFrag->ulFragOffset == ulSegMap) {
				*option = ASF_ADJUST_NEXTFRAG;
			} else {
				asf_reasm_debug("Not doing anything \r\n");
			}
		}
	}


	if (*option == ASF_ADJUST_PREVFRAG) {
		pFragPrev->ulLen += *pLen;
		asf_reasm_debug("ASF_ADJUST_PREVFRAG: ulSegMap = %d, "\
			"pFragPrev->ulSegMap = %d\r\n", pFragPrev->ulSegMap,
						pFragPrev->ulSegMap + *pLen);
		pFragPrev->ulSegMap += *pLen;
		pCb->ulRecvLen += *pLen;
		*frag = pFragPrev;

	} else if (*option == ASF_ADJUST_NEXTFRAG) {
		pFrag->ulFragOffset = *pOffset;

		pFrag->ulLen += *pLen;
		pCb->ulRecvLen += *pLen;
		asf_reasm_debug("ASF_ADJUST_NEXTFRAG: ulSegMap = %d, "\
			"pFrag->ulSegMap = %d\r\n", pFrag->ulSegMap,
						pFrag->ulSegMap + *pLen);
		/* Not required when handling Next Fragment
		   as it already have updated SegMap*/
		/* pFrag->ulSegMap += *pLen; */
		*frag = pFrag;
	} else {
		newFrag = asfGetNode(
				    asf_reasmPools[ASF_REASM_FRAG_POOL_ID_INDEX], &bHeap);
		if (newFrag) {
			asf_reasm_debug("asfGetNode Fragment Cb returned Cb from %d\r\n", bHeap);
			newFrag->bHeap = bHeap;
			newFrag->ulLen = *pLen;
			newFrag->ulFragOffset = *pOffset;
			newFrag->ulSegMap = *pOffset + *pLen;

			*frag = newFrag;
			pCb->ulRecvLen += *pLen;
			pCb->ulNumFrags++;

			/* Add fragment to the Reassembly Cb before pFragPrev or after pFrag */

			if (pFragPrev) {
				newFrag->next = pFragPrev->next;
				newFrag->prev = pFragPrev;

				if (pFragPrev->next) {
					pFragPrev->next->prev = newFrag;
				}
				pFragPrev->next = newFrag;
			} else if (pFrag) {
				newFrag->prev = NULL;
				newFrag->next = pFrag;

				pFrag->prev = newFrag;
				pCb->fragList = newFrag;
			}
			*option = ASF_ADJUST_NONE;
			asf_reasm_debug("Returning New fragment \r\n");
		} else {
			asf_reasm_debug("Allocation of new frag failed\r\n");
			ASF_gfar_kfree_skb(skb);
			return NULL;
		}
	}
	if ((pCb->ulTotLen != 0) && (pCb->ulRecvLen == pCb->ulTotLen)) {
		*bReasmDone = TRUE;
		asf_reasm_debug("Returning bReasmDone = TRUE \r\n");
	} else {
		*bReasmDone = FALSE;
		pCb->ulLastPktTime = jiffies;
		asf_reasm_debug("Returning bReasmDone = fALSE \r\n");
	}

	return skb;
}



/*
 * API: To get reasm Info
 */
static inline unsigned int asfReasmGetInfo(
					  unsigned int ulVSGId,  unsigned int ulIndex, unsigned int ulMagicNum,
					  unsigned int *ulStoredInfo1,
					  unsigned int *ulStoredInfo2,
					  unsigned int *ulStoredInfo3,
					  unsigned int *ulStoredInfo4)
{
	struct asf_reasmCb_s *pCb;
	if (ulMagicNum == ptrIArray_getMagicNum(
					       &(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
							      smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
					       ulIndex)) {
		pCb = ptrIArray_getData(&(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
						       smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray), ulIndex);
		if (ulStoredInfo1)
			*ulStoredInfo1 = pCb->ulAppInfo[0];
		if (ulStoredInfo2)
			*ulStoredInfo2 = pCb->ulAppInfo[1];
		if (ulStoredInfo3)
			*ulStoredInfo3 = pCb->ulAppInfo[2];
		if (ulStoredInfo4)
			*ulStoredInfo4 = pCb->ulAppInfo[3];

		return 0;
	}
	asf_reasm_debug("Cb magic number does not match with passed magic number\r\n");
	return 1;
}


/*
 * API to put some information in Reasembly context
 */
static inline unsigned int asfReasmPutInfo(
					  unsigned int ulVSGId, unsigned int ulIndex, unsigned int ulMagicNum,
					  unsigned int *ulStoredInfo1,
					  unsigned int *ulStoredInfo2,
					  unsigned int *ulStoredInfo3,
					  unsigned int *ulStoredInfo4)
{
	struct asf_reasmCb_s *pCb;
	if (ulMagicNum == ptrIArray_getMagicNum(
					       &(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
							      smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
					       ulIndex)) {
		pCb = ptrIArray_getData(&(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
						       smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray), ulIndex);
		if (ulStoredInfo1)
			pCb->ulAppInfo[0] = *ulStoredInfo1;
		if (ulStoredInfo2)
			pCb->ulAppInfo[1] = *ulStoredInfo2  ;
		if (ulStoredInfo3)
			pCb->ulAppInfo[2] = *ulStoredInfo3 ;
		if (ulStoredInfo4)
			pCb->ulAppInfo[3] = *ulStoredInfo4;

		return 0;
	}
	asf_reasm_debug("Cb magic number does not match with passed magic number\r\n");
	return 1;
}


/*
 * Assumption here is that the timer has to fire on the same core that
 * processes packets with respect to the Reassembly context block
 * In case of race condition between Timer expiry happening and
 * pkt arriving for reassembly completion, one of them will succeed.
 * i.e. they will be sequenced
 */
#define ASF_REASM_INT_MAX  0xffffffff
unsigned int asfReasmTmrCb(unsigned int ulVSGId,
			   unsigned int ulIndex, unsigned int ulMagicNum, unsigned int pCbArg4)
{
	struct asf_reasmCb_s *pCb;
	unsigned int ulTimeDiff;
	unsigned int mgnum;

#ifdef ASF_REASM_DEBUG
	asf_reasm_debug("Timer Cb called: ulIndex = %d, ulMagicNum = %d\r\n", ulIndex, ulMagicNum);
#endif
#ifdef ASF_IPV6_FP_SUPPORT
	if (pCbArg4 == REASM_IPv6) {
		mgnum = ptrIArray_getMagicNum(
					       &(asfPerCpuPtr(asf_ipv6_ReasmCbPtrIndexArray,
							      smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
					       ulIndex);

	} else
#endif
	{
		mgnum = ptrIArray_getMagicNum(
					       &(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
							      smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray),
					       ulIndex);

	}

	if (ulMagicNum == mgnum) {
#ifdef ASF_REASM_DEBUG
		asf_reasm_debug("Magic number matched\r\n");
#endif

#ifdef ASF_IPV6_FP_SUPPORT
		if (pCbArg4 == REASM_IPv6) {
			pCb = ptrIArray_getData(&(asfPerCpuPtr(asf_ipv6_ReasmCbPtrIndexArray,
						       smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray), ulIndex);
		} else
#endif
		{
			pCb = ptrIArray_getData(&(asfPerCpuPtr(asf_ReasmCbPtrIndexArray,
						       smp_processor_id())->ptrArrayInfo[ulVSGId].ptrArray), ulIndex);
		}

		asf_reasm_debug("pCb = 0x%x\r\n", pCb);
		if (jiffies > pCb->ulLastPktTime)
			ulTimeDiff = jiffies - pCb->ulLastPktTime;
		else
			ulTimeDiff = (ASF_REASM_INT_MAX - pCb->ulLastPktTime) + jiffies;

		if (ulTimeDiff  >= asf_reasmCfg[ulVSGId].ulTimeOutInJiffies) {
			asf_reasm_debug("Need to delete the Cb\r\n");
			/* Remove from hash list */
#ifdef ASF_IPV6_FP_SUPPORT
			if (pCbArg4 == 1) {
				asfIPv6RemCbFromHashList(pCb->ulHashVal,  pCb);
				asfIPv6ReasmDeleteCb(pCb);
			} else
#endif
			{
				asfRemCbFromHashList(pCb->ulHashVal,  pCb);
				asfReasmDeleteCb(pCb);
			}
			/* Stop the timer by returning 1 */
			return 1;
		} else {
			asf_reasm_debug("Timer will be restarted \r\n");
			asf_reasm_debug("ulTimeDiff = %d, ulTimeOutInJiffies = %d\r\n", ulTimeDiff, asf_reasmCfg[ulVSGId].ulTimeOutInJiffies);
			/* Continue the timer */
			return 0;
		}
	}
	return 1;
}


/*
 * Function Name : asf_ipv4Defrag
 * Inputs :
	ulVSGId, - VSG ID to enforce config params
	skb - recieved input buffer
	bFirstFragRcvd - Pointer to bool i/o value
	pReasmCb1, pReasmCb2 - I/O Pointers to Reasm Context block info
	   for further stashing by app, if desired
	*bReasmDone - I/o to indicate whether reasssembly was completed
  Description:
	Reassembly function called by Firewall, IPsec etc.
	Does: Context lookup/Context creation
	      Fragment integrity check
	      Returns NULL or completed fragment
 */

struct sk_buff  *asfIpv4Defrag(unsigned int ulVSGId,
			       struct sk_buff *skb , bool *bFirstFragRcvd,
			       unsigned int *pReasmCb1, unsigned int *pReasmCb2,
			       unsigned int *fragCnt) {
	struct iphdr *iph = ip_hdr(skb);
	struct asf_reasmCb_s *pCb;
	unsigned int hashVal;
	unsigned int ulOffset = 0;
	unsigned int flags = 0;
	unsigned int ulSegLen = 0;
	unsigned int ihl;
	struct asf_fragInfo_s *pFrag;
	struct sk_buff *pTempSkb;
	struct sk_buff *pHeadSkb;
	struct iphdr *pIpHdr;
	unsigned int *pSrc, *pTgt;
	char option;
	int ii;
	bool bReasmDone;
	unsigned int ret;
#ifdef ASF_IPV6_FP_SUPPORT
	struct ipv6hdr	*ip6h = (struct ipv6hdr  *)skb_network_header(skb);
	struct frag_hdr *fhdr = (struct frag_hdr *)skb_transport_header(skb);
	bool bIPv6 = ASFCB(skb)->Defrag.bIPv6;
#endif


	/* Calculate the hash value */
	/*
	   Since h/w has done checksum verification of IP packet, we can
	   go ahead with extraction and hash calculation
	*/
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true) {
		unsigned int src = 0;
		unsigned int dst = 0;
		unsigned int i;
		for (i = 0; i < 4; ++i)
			src += ip6h->saddr.s6_addr32[i];
		for (i = 0; i < 4; ++i)
			dst += ip6h->daddr.s6_addr32[i];
		hashVal = asfReasmComputeHash(src, dst, fhdr->identification);
		/* Prefetch the hash bucket collision element */
		prefetchw(asfPerCpuPtr(asf_ipv6_ReasmCbHashList,
				       smp_processor_id())->pHead[hashVal].pReasmCbHead);

		/* Go ahead and check the fragment, for various integrity checks*/
		ret = asfIPv6CheckFragInfo(skb, &ulOffset, &flags, &ulSegLen, &ihl, ulVSGId);
	} else
#endif
	{
		hashVal = asfReasmComputeHash(
					     (__force u32)(iph->id << 16 | iph->protocol),
					     (__force u32)(iph->saddr), (__force u32)iph->daddr);
		/* Prefetch the hash bucket collision element */
		prefetchw(asfPerCpuPtr(asf_ReasmCbHashList,
				       smp_processor_id())->pHead[hashVal].pReasmCbHead);
		/* Go ahead and check the fragment, for various integrity checks*/
		ret = asfIPv4CheckFragInfo(skb, &ulOffset, &flags, &ulSegLen,
						&ihl, ulVSGId);
	}


	if (ret) {
		asf_reasm_debug("Fragment Integrity check failed\r\n");
		/* Free the skb */
		ASFSkbFree(skb);
		return NULL;
	}

	asf_reasm_debug("asfDefrag: ulOffset=%d, flags=%x, ulSegLen=%d, ihl=%u\r\n", ulOffset, flags, ulSegLen, ihl);

	/* Find the Reassembly context block,
	   If not found, this function goes ahead and creates the
	   context block if memory is available && configuration
	   limits are not reached. If fragCnt in Cb is 0, that means
	   we created the cb just now
	*/

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true)
		pCb = asfIPv6ReasmFindOrCreateCb(ulVSGId, skb, hashVal);
	else
#endif
		pCb = asfIPv4ReasmFindOrCreateCb(ulVSGId, skb, hashVal);
	if (pCb) {
		if (pCb->ulNumFrags == 0) {
			asf_reasm_debug("Cb Created: fragment received\r\n");
			asfReasmUpdateFrag(pCb,  ulOffset, flags, ulSegLen);

			/* for the first fragment, don't update the skb->data,
			   skb->len fields. */
			if (ulOffset == 0) {
				if (bFirstFragRcvd)
					*bFirstFragRcvd = TRUE;
				*(uintptr_t *)  &(skb->cb[0]) = (uintptr_t)&(skb->data[0]); /* beginning of the IP header */
#ifdef ASF_IPV6_FP_SUPPORT
				*(uintptr_t *)  &(skb->cb[8]) = skb_transport_header(skb) - skb_network_header(skb);
				*(uintptr_t *)  &(skb->cb[16]) = fhdr->nexthdr;
#endif
			}

			asf_reasm_debug("First Packet skb = 0x%x, skb->data = 0x%x, skb->len = %d, *cb[0] 0x%x\r\n", skb, skb->data, skb->len, *(unsigned int *)  &(skb->cb[0]));
			/* Make skb->data point after the IP header */
			/* Update the length */
			skb->data += (ihl);
			skb->len -= (ihl);
			asf_reasm_debug("First Packet After update skb->data = 0x%x, skb->len = %d\r\n", skb->data, skb->len);

			if ((pReasmCb1) && (pReasmCb2)) {
				*pReasmCb1 =  pCb->ulPtrArrayIndex;
				*pReasmCb2 =  pCb->ulMagicNum;
			}

			/* Add skb into the fragment list */
			pCb->frag.pHeadSkb = pCb->frag.pTailSkb = skb;
			if (skb_shinfo(skb)->frag_list) {
				for (pCb->frag.pTailSkb = skb_shinfo(skb)->frag_list;
					pCb->frag.pTailSkb->next != NULL;
					pCb->frag.pTailSkb = pCb->frag.pTailSkb->next)
					; /* NULL statement */
			}
			return NULL;
		} else {
			asf_reasm_debug("ABC: 2 : *pHeadSkb->cb=0x%x\r\n", *(unsigned int *)  &(pCb->fragList->pHeadSkb->cb[0]));
			asf_reasm_debug("2nd packet of Reassembly cb received\r\n");
			asf_reasm_debug("Second fragment: skb->data = 0x%x, skb->len =%d\r\n", skb->data, skb->len);
			skb = asfFragHandle(pCb, skb, &ulOffset, flags,
						&ulSegLen, ihl, &bReasmDone, &pFrag, &option);
			if (skb) {
				asf_reasm_debug("IPv4Frag Handle completed with skb returned bReasmDone=%d\r\n", bReasmDone);
				if (ulOffset == 0) {
					if (bFirstFragRcvd)
						*bFirstFragRcvd = TRUE;
					*(uintptr_t *)  &(skb->cb[0]) = (uintptr_t)&(skb->data[0]); /* beginning of the IP header */
#ifdef ASF_IPV6_FP_SUPPORT
					*(uintptr_t *)  &(skb->cb[8]) = skb_transport_header(skb) - skb_network_header(skb);
					*(uintptr_t *)  &(skb->cb[16]) = fhdr->nexthdr;
#endif
				}

				asf_reasm_debug("before trimming : ulSegLen = %d, skb->len = %d\r\n", ulSegLen, skb->len);

				/* Trim the skbs*/
				skb->data += (skb->len - ulSegLen);
				skb->len = ulSegLen;

				asf_reasm_debug("After next fragment received: next frag: skb->data =0x%x, skb->len=%d\r\n",
						skb->data, skb->len);

				if (option == ASF_ADJUST_NEXTFRAG) {
					asf_reasm_debug("Option = ASF_ADJUST_NEXTFRAG\r\n");
					skb_shinfo(skb)->frag_list = pFrag->pHeadSkb;
					if (skb_shinfo(pFrag->pHeadSkb)->frag_list) {
						asf_reasm_debug("Fragment already has a frag list\r\n");
						/* Next fragment already has a frag list, so link the frag_list to the pNext */
						pFrag->pHeadSkb->next = skb_shinfo(pFrag->pHeadSkb)->frag_list;
						skb_shinfo(pFrag->pHeadSkb)->frag_list = NULL;
					}

					pFrag->pHeadSkb = skb;
					pCb->ulNumSkbs++;
				} else if (option == ASF_ADJUST_PREVFRAG) {
					asf_reasm_debug("Option = ASF_ADJUST_PREVFRAG\r\n");
					if (skb_shinfo(pFrag->pHeadSkb)->frag_list) {
						pFrag->pTailSkb->next = skb;
					} else {
						skb_shinfo(pFrag->pHeadSkb)->frag_list = skb;
					}
					pFrag->pTailSkb = skb;
					pCb->ulNumSkbs++;
				} else if (option == ASF_ADJUST_NONE) {
					/* Add skb into the fragment list */
					pFrag->pHeadSkb = pFrag->pTailSkb = skb;

				}

				if ((pReasmCb1) && (pReasmCb2)) {
					*pReasmCb1 =  pCb->ulPtrArrayIndex;
					*pReasmCb2 =  pCb->ulMagicNum;
				}
				if (bReasmDone) {
					asf_reasm_debug("Reassembly completed\r\n");

					if (unlikely(pCb->ulTotLen > asf_reasmCfg[ulVSGId].ulMaxPktSize)) {
						asf_reasm_debug("Total Length exceeded\r\n");
						/* Remove from hash list */
						asfRemCbFromHashList(pCb->ulHashVal,  pCb);
						/* Stop the timer */
						asfTimerStop(ASF_REASM_TMR_ID, 0, pCb->ptmr);
						asfReasmDeleteCb(pCb);
						return NULL;
					}

					pHeadSkb = pCb->fragList->pHeadSkb;
					asf_reasm_debug("pHeadSkb= 0x%x\r\n", pHeadSkb);
					asf_reasm_debug("ABC: 1 :  *pHeadSkb->cb=0x%x\r\n", *(unsigned int *)  (&pHeadSkb->cb[0]));

					if (pCb->fragList->next) {
						/* Link the remaining fragments other than the first fragment */
						pTempSkb = pCb->fragList->next->pHeadSkb;
						asf_reasm_debug("pTempSkb = 0x%x\r\n", pTempSkb);
						for (pFrag = pCb->fragList->next;
						    pFrag != NULL; pFrag = pFrag->next) {
							asf_reasm_debug("Looping \r\n");
							if (skb_shinfo(pFrag->pHeadSkb)->frag_list) {
								pFrag->pHeadSkb->next = skb_shinfo(pFrag->pHeadSkb)->frag_list;
								skb_shinfo(pFrag->pHeadSkb)->frag_list = NULL;
							}

							if (pFrag->next)
								pFrag->pTailSkb->next = pFrag->next->pHeadSkb;
							else
								pFrag->pTailSkb->next = NULL;

							pFrag->pHeadSkb = pFrag->pTailSkb = NULL;
						}

						/* If the first fragment has only one skb, then link the
						    chain of skbs created previously to the skb_shinfo(pHeadSkb),
						    otherwise, link it to the first fragment's tail skb
						   */
						asf_reasm_debug("Linking the remaining skbs to pHeadSkb\r\n");
						if (pCb->fragList->pHeadSkb == pCb->fragList->pTailSkb) {
							/* Link it in */
							skb_shinfo(pHeadSkb)->frag_list = pTempSkb;
						} else {
							pCb->fragList->pTailSkb->next = pTempSkb;
						}
					}
					pCb->fragList->pHeadSkb = pCb->fragList->pTailSkb = NULL;

#ifdef ASF_IPV6_FP_SUPPORT
					if (bIPv6 == true) {
						pHeadSkb->data -= *(uintptr_t *)&(pHeadSkb->cb[8]);;
						memmove(pHeadSkb->data, (void *)(*(uintptr_t *)&(pHeadSkb->cb[0])), *(uintptr_t *)&(pHeadSkb->cb[8]));
						ip6h = (struct ipv6hdr *)pHeadSkb->data;
						ip6h->payload_len = ASF_HTONS(pCb->ulTotLen + *(uintptr_t *)&(pHeadSkb->cb[8]));
						if (ip6h->nexthdr == NEXTHDR_HOP) {
							*(unsigned char *)(ip6h + 1) = *(uintptr_t *)&(pHeadSkb->cb[16]);;
						} else {
							ip6h->nexthdr = *(uintptr_t *)&(pHeadSkb->cb[16]);
						}
						pHeadSkb->len +=  *(uintptr_t *)&(pHeadSkb->cb[8]);
					} else
#endif
					{
					/* Update the ip header */
						asf_reasm_debug("pHeadSkb->cb = 0x%x, *pHeadSkb->cb=0x%x\r\n", pHeadSkb->cb, *(unsigned int *)  (&pHeadSkb->cb[0]));

						pIpHdr = (struct iphdr *)  (*(uintptr_t *)  &(pHeadSkb->cb[0]));
						asf_reasm_debug("Updating the IP header, pIpHdr = 0x%x, cb field \r\n", pIpHdr);
						pSrc = (unsigned int *)  pIpHdr;

						ihl = pIpHdr->ihl*4;
						if ((unsigned int *)  pHeadSkb->data - pIpHdr->ihl == (unsigned int *)  pIpHdr) {
							asf_reasm_debug("Stored ipheader = data-ihl\r\n");
							pHeadSkb->data -= ihl;
						} else {
							asf_reasm_debug("Stored ipheader != data-ihl\r\n");
							pHeadSkb->data -= ASF_REASM_IP_HDR_LEN;
							pTgt = (unsigned int *)  pHeadSkb->data;
							asf_reasm_debug("pSrc = 0x%x, pTgt = 0x%x\r\n", pSrc, pTgt);

							if ((unsigned int *)  pHeadSkb->data > (unsigned int *)  pIpHdr) {
								for (ii = 4; ii >= 0; ii--)
									pTgt[ii] =  pSrc[ii];
							} else {
								for (ii = 0; ii < 5; ii++)
									pTgt[ii] = pSrc[ii];
							}
							pIpHdr = (struct iphdr *)  (pHeadSkb->data);
						}
							pHeadSkb->len += ihl;
						skb_reset_network_header(pHeadSkb);

						pIpHdr->tot_len = ASF_HTONS(pCb->ulTotLen+ihl);
						pIpHdr->frag_off = 0;
						pIpHdr->ihl = (unsigned char)5;
						pIpHdr->id = asfReasmGetNextId();

						ip_send_check(pIpHdr);
						skb->ip_summed = CHECKSUM_UNNECESSARY;
					}
					*fragCnt = pCb->ulNumFrags + pCb->ulNumSkbs;
					asf_reasm_debug("returning skbs to caller\r\n");
					if ((pReasmCb1 == NULL) || (pReasmCb2 == NULL)) {
						/* Remove from hash list */
#ifdef ASF_IPV6_FP_SUPPORT
						if (bIPv6 == true)
							asfIPv6RemCbFromHashList(pCb->ulHashVal,  pCb);
						else
#endif
							asfRemCbFromHashList(pCb->ulHashVal,  pCb);
						/* Stop the timer */
						asfTimerStop(ASF_REASM_TMR_ID, 0, pCb->ptmr);
#ifdef ASF_IPV6_FP_SUPPORT
						if (bIPv6 == true)
							asfIPv6ReasmDeleteCb(pCb);
						else
#endif
							asfReasmDeleteCb(pCb);
					} else {
						/* Need to look at this */
#ifdef ASF_IPV6_FP_SUPPORT
						if (bIPv6 == true)
							asfIPv6RemCbFromHashList(hashVal, pCb);
						else
#endif
							asfRemCbFromHashList(hashVal, pCb);
						asfTimerStop(ASF_REASM_TMR_ID, 0, pCb->ptmr);
						/* Expecting application to call asfReasmDeleteCb */
					}

					return pHeadSkb;

				}
				return NULL;
			} else {
				asf_reasm_debug("Skb dropped\r\n");
				return NULL;
			}
		}
	} else {
		ASFSkbFree(skb);
		asf_reasm_debug("Out of memory \r\n");
		return NULL;
	}
}


/*
 * ulTotalLen = total length in ipheader of reassembled packet (including ip header)
 * ulExtraLen = VPN_PREOVERHEAD+32+VPN_POSTOVERHEAD
 *			32 bytes is for hardware header (eth/pppoe/8021q)
 * ulHeadRoom = (VPN_PREOVERHEAD+32)
 *
 * ex:
 *	asfReasmLinearize(&skb,ip_hdr(skb)->tot_len,VPN_PREOVERHEAD+32+VPN_POSTOVERHEAD,VPN_PREOVERHEAD+32);
 */

unsigned int asfReasmLinearize(struct sk_buff **pSkb,
			       unsigned int ulTotalLen,
			       unsigned int ulExtraLen,
			       unsigned int ulHeadRoom)
{
	struct sk_buff *skb, *frag, *frag1, *pTempSkb;
	bool bAlloc;
	bool bDone = 0;
	unsigned int ulBytesToCopy;
	char *ptr;
	struct iphdr *iph;

	pTempSkb = *pSkb;

	if (skb_shinfo(pTempSkb)->nr_frags) {
		asf_reasm_debug("Fragments with nr_frags not handled \r\n");
		return 1;
	}
	if (ulTotalLen <= (skb_end_pointer(pTempSkb) - pTempSkb->data)) {
		asf_reasm_debug("Total fragment can fit in first skb \r\n");
		skb = pTempSkb;
		bAlloc = 0;
	} else {
#ifdef ASF_TERM_FP_SUPPORT
		if (pTempSkb->mapped) {
			asf_reasm_debug("Total Len =%d, available = %d, "\
					"Don't expect to allocate new SKB\n",
					ulTotalLen,
					pTempSkb->end
					- (pTempSkb->data + pTempSkb->len));
			frag = skb_shinfo(pTempSkb)->frag_list;
			/* The Calling Function will free the First SKB */
			while (frag) {
				frag1 = frag;
				frag = frag->next;
				/* Free SKB using frag1 */
				frag1->next = NULL;
				packet_kfree_skb(frag1);
			}
			skb_shinfo(pTempSkb)->frag_list = NULL;
			return 1;
		}
#endif
		skb = ASFSkbAlloc((ulTotalLen+ulExtraLen), GFP_ATOMIC);
		if (skb) { /* We need a flat buffer, if not return an error*/
			if (skb_linearize(skb)) {
				dev_kfree_skb_any(skb);
				asf_reasm_debug("skb linearize failed ");
				return 1;
			}

			skb_reserve(skb, ulHeadRoom);
			memcpy(skb->data, pTempSkb->data, pTempSkb->len);
			memcpy(skb->cb, pTempSkb->cb, sizeof(skb->cb));
			skb->len = pTempSkb->len;
			bAlloc = 1;
		} else {
			asf_reasm_debug("Failed to allocate skb!\n");
			return 1;
		}
	}

	ulBytesToCopy = ulTotalLen - skb->len;
	ptr = skb->data + skb->len;
	frag = skb_shinfo(pTempSkb)->frag_list;
	while (1) {
		if ((frag) && (ulBytesToCopy > 0)) {
			memcpy(ptr, frag->data, frag->len);
			ptr  +=  frag->len;
			ulBytesToCopy -= frag->len;
			skb->len += frag->len;
			frag = frag->next;
		} else {
			if ((frag == NULL) && (ulBytesToCopy == 0)) {
				asf_reasm_debug("Exiting routine, ulBytesToCopy = %d skb->len = %d\r\n", ulBytesToCopy, skb->len);
				skb_set_tail_pointer(skb, skb->len);
				bDone = 1;
			} else {
				if (frag == NULL)
					asf_reasm_debug("Still need to copy: %d but frag is NULL\r\n", ulBytesToCopy);
				if (bAlloc)
					ASFSkbFree(skb);
				/* Nothing to be done to *pSkb */
			}
			break;
		}
	}
	if (bDone) {
		if (bAlloc) {
			*pSkb = skb;
			skb->dev = pTempSkb->dev;
			asf_reasm_debug("Alloced new buffer, so freeing up the old one\r\n");
			/* Ok we alloced a new skb */
			/* Go ahead adn free the passed one in pTempSkb*/
			ASFSkbFree(pTempSkb);
		} else {
			/* Need to free the old skb's fraglist */
			asf_reasm_debug("Freeing up pTempSkb->frag_list\r\n");
			for (frag = skb_shinfo(pTempSkb)->frag_list; frag != NULL; frag = frag1) {
				frag1 = frag->next;
				frag->next = NULL;
				ASFSkbFree(frag);
			}

			skb_shinfo(pTempSkb)->frag_list = NULL;
			asf_reasm_debug("pTempSkb->frag_list = 0x%x\r\n", skb_shinfo(pTempSkb)->frag_list);

			/* No need to set *pSkb as it is the same as passed one */
		}
		iph = (struct iphdr *)  skb->data;
		ip_send_check(iph);
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		return 0;
	}
	return 1;
}

/*
 * asfReasmPullBuf
 * Input: skb, len
 * Description : Pull len bytes from skb_shinfo(skb)->frag_list and make it available in the first skb
 * Returns the skb if this is possible, (meaning the first skb has that much room, otherwise NULL
 * It will not allocate a new skb for the first one, as the old skb may have information needed to
 * send the packet to the stack
 */

unsigned int asfReasmPullBuf(struct sk_buff *skb, unsigned int len, unsigned int *fragCnt)
{
	int ii;
	unsigned int *src, *tgt;
	/* Making len as 4 byte aligned */
	unsigned int temp_len = (len + 3) & 4;
	struct sk_buff *pTempSkb;

	if ((skb_tail_pointer(skb) - (skb->data + skb->len)) >= temp_len) {
		tgt = (unsigned int *)  (skb->data+skb->len);
		src = (unsigned int *)  (skb_shinfo(skb)->frag_list->data);
		for (ii = 0; ii < temp_len >> 2; ii++) {
			*tgt = *src;
			tgt++;
			src++;
		}

		skb_shinfo(skb)->frag_list->data += len;
		skb_shinfo(skb)->frag_list->len -= len;
		if (skb_shinfo(skb)->frag_list->len == 0) {
			pTempSkb = skb_shinfo(skb)->frag_list;
			skb_shinfo(skb)->frag_list = pTempSkb->next;
			pTempSkb->next = NULL;
			ASF_gfar_kfree_skb(pTempSkb);
			if (fragCnt)
				*fragCnt -= 1;
		}

		skb->len += len;
		return 0;
	} else {
		asf_reasm_debug("Skb does not have enough room\r\n");
		return 1;
	}
}



/* ulMTU - to be used for fragmentation
   ulDevXmitHdrLen : buffer space to be reserved for L2 header
   bDoChecksum : whether to do IP header checksum or not.
   For the cases where firewall returns packet to stack or when
   IPsec red side fragmentation is enabled, this will be set to TRUE
   dev - is used to allocate skb from (ASF_gfar_new_skb) (Optional,
   otherwise, allocated using alloc_skb
  **pOutSkb - chain of skb ip fragments
*/

int asfIpv4Fragment(struct sk_buff *skb,
			   unsigned int ulMTU, unsigned int ulDevXmitHdrLen,
			   unsigned int bDoChecksum,
			   struct net_device *dev,
			   struct sk_buff **pOutSkb)
{
	struct iphdr *iph = ip_hdr(skb);
	unsigned short ihl = iph->ihl*4;
	unsigned int ulReqHeadRoom = ulDevXmitHdrLen + ASF_REASM_IP_HDR_LEN;
	struct sk_buff *skb2, *pLastSkb;
	unsigned int bytesLeft, len, ii, ptr = 0;
	unsigned int *pSrc, *pTgt;
	unsigned int offset = (ASF_NTOHS(iph->frag_off) & IP_OFFSET) << 3;
	unsigned int flags = ASF_NTOHS(iph->frag_off) & IP_MF;
	unsigned int tot_len;
	bool bNewSkb = 1;
	struct sk_buff *pSkb, *frag;

	asf_reasm_debug("skb->len = %d, ulMTU=%d, ulDevXmitHdrLen = %d ip_tot_len =%d\r\n", skb->len,
			ulMTU, ulDevXmitHdrLen, ASF_NTOHS(iph->tot_len));
	if ((likely(ASF_NTOHS(iph->tot_len) > ulMTU)) || (skb_shinfo(skb)->frag_list)) {
		/* Fragmentation */
		if (((skb->len <= ulMTU) && (skb_headroom(skb) > ulDevXmitHdrLen))
			&& (!((skb->len - ihl) & 7))) {
			bNewSkb = 0;
			for (pSkb = skb->next;  pSkb != NULL; pSkb = pSkb->next) {
				if ((pSkb->len + ASF_REASM_IP_HDR_LEN > ulMTU) ||
				    ((pSkb->len & 7) && (pSkb->next)) ||
				    (skb_headroom(pSkb) < ulReqHeadRoom)) {
					/* If the length is > MTU or if there is not enough head room */
					bNewSkb =  1;
					break;
				}
			}
			if (!bNewSkb) {
				asf_reasm_debug("No new skb required \r\n");
				/* Adjust the fragments properly */
				offset = 0;
				frag = skb_shinfo(skb)->frag_list;
				asf_reasm_debug("skb_shinfo(skb)->frag_list = 0x%x\r\n", frag);


				iph->tot_len = htons(skb->len);
				iph->frag_off = htons(IP_MF);

				ip_send_check(iph);
				skb->ip_summed = CHECKSUM_UNNECESSARY;

				skb_set_transport_header(skb, ihl);
				skb_reset_network_header(skb);

				offset += skb->len - ihl;
				for (; frag != NULL; frag = frag->next) {
					if (frag) {

						__skb_push(frag, ihl);
						skb_reset_network_header(frag);


						for (pSrc = (unsigned int *)  iph,
						     pTgt = (unsigned int *)  (skb_network_header(frag)),
						     ii = 0; ii < 5; ii++) {
							pTgt[ii] = pSrc[ii];
						}
						iph = ip_hdr(frag);
						iph->tot_len = htons(frag->len);
						if (offset == 0)
							asf_ip_options_fragment(frag);
						iph->frag_off = htons(offset >> 3);
						if (frag->next != NULL)
							iph->frag_off |= htons(IP_MF);

						ip_send_check(iph);
						frag->ip_summed =
							CHECKSUM_UNNECESSARY;

						offset += frag->len - ihl;
					}
				}
				skb->next = skb_shinfo(skb)->frag_list;
				skb_shinfo(skb)->frag_list = NULL;
				*pOutSkb = skb;
				return 0;
			}
		}

		if (bNewSkb) {
			struct net_device *ndev;
			/* Special Handling for VLAN Interfaces.
			   All the SKBs must be allocated from parent
			   device pool only.
			 */
			if (skb->dev->priv_flags & IFF_802_1Q_VLAN) {

				ndev = vlan_dev_priv(skb->dev)->real_dev;
				/* Return Error if Parent device not found */
				if (!ndev)
					return 1;
			} else
				ndev = skb->dev;

			ulMTU -= ihl;
			asf_reasm_debug("Re-using incoming Skb"
						" as first fragment.\r\n");
			*pOutSkb = skb;
			pLastSkb = skb;
			/* adjust other skb pointers */
			len = (ulMTU & ~7);
			bytesLeft = (ASF_NTOHS(iph->tot_len) - ihl - len);

			tot_len = len+ihl;
			/* The first fragment will be created at the end */

#if 0
			/* Skb->len will be set at last as will be used
			  asfSkbCopyBits() */
			skb->tail = skb->data;
			skb->tail += tot_len;
			iph->frag_off |= htons(IP_MF);
			iph->tot_len = htons(len+ihl);

			if (!bDoChecksum)
				skb->ip_summed = CHECKSUM_PARTIAL;
			else {
				ip_send_check(iph);
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
			asf_ip_options_fragment(skb);
#endif

			offset += len;
			ptr += (ihl + len);
			asf_reasm_debug("bytesLeft %d, Offset %d, len %d \r\n",
					bytesLeft, offset, len);
			/* continue more more fragments with new allocations. */
			while (bytesLeft > 0) {
				asf_reasm_debug("New Skb required \r\n");
				asf_reasm_debug("bytesLeft = %d\r\n",
								bytesLeft);

				len = (bytesLeft > ulMTU) ?  ulMTU : bytesLeft;
				if (len < bytesLeft)
					len &= ~7;
#ifdef CONFIG_DPA
				skb2 = asf_alloc_buf_skb(ndev);
#else
				skb2 = gfar_new_skb(ndev);
#endif
				if (skb2) {
					asf_reasm_debug("Next skb\r\n");
#ifdef CONFIG_DPA
					skb_reserve(skb2, ulDevXmitHdrLen +
							dev->needed_headroom);
					skb2->protocol = ETH_P_IP;
#endif
					pLastSkb->next = skb2;
					pLastSkb = skb2;
					skb2->queue_mapping = skb->queue_mapping;

					skb2->tail += (len+ihl);
					skb2->len = (len+ihl);
					skb_reset_network_header(skb2);
					skb2->transport_header =
						skb2->network_header + ihl;

					/*
					 *	Copy the packet header
					 *	into the new buffer.
					 */
					pSrc = (unsigned int *) ip_hdr(skb);
					pTgt = (unsigned int *) ip_hdr(skb2);
					for (ii = 0; ii < 5; ii++)
						pTgt[ii] = pSrc[ii];

					asfSkbCopyBits(skb,
						ptr,
						skb_transport_header(skb2),
						len);

					bytesLeft -= len;

					/*
					  *	Fill in the new header fields.
					  */
					iph = ip_hdr(skb2);
					iph->frag_off = htons((offset >> 3));
					iph->tot_len = htons(len + ihl);
					iph->frag_off |= htons(IP_MF);
					if (bytesLeft == 0 && !flags)
						iph->frag_off &= htons(~IP_MF);

					ip_send_check(iph);
					skb2->ip_summed =
						CHECKSUM_UNNECESSARY;

					offset += len;
					ptr += len;
				} else {
					asf_reasm_debug("Skb allocation"
						" failed in fragmenation\r\n");
					skb2 = skb;
					while (skb2) {
						pLastSkb = skb2->next;
						ASFSkbFree(skb2);
						skb2 = pLastSkb;
					}
					return 1;
				}
			}
#ifdef CONFIG_DPA
			skb2 = asf_alloc_buf_skb(ndev);
#else
			skb2 = gfar_new_skb(ndev);
#endif
			if (!skb2)
				goto drop;

#ifdef CONFIG_DPA
			skb_reserve(skb2, ulDevXmitHdrLen +
					dev->needed_headroom);
			skb2->protocol = ETH_P_IP;
#endif
			skb_reset_network_header(skb2);
			skb2->transport_header =
				skb2->network_header + ihl;

			asfSkbCopyBits(skb, 0,
					skb_put(skb2, tot_len),
					tot_len);

			ip_hdr(skb2)->frag_off |= htons(IP_MF);
			ip_hdr(skb2)->tot_len = htons(tot_len);

			asf_ip_options_fragment(skb2);

			ip_send_check(ip_hdr(skb2));
			skb2->ip_summed = CHECKSUM_UNNECESSARY;


			*pOutSkb = skb2;
			skb2->next = skb->next;
			skb->next = NULL;
#ifdef CONFIG_DPA
			if (skb->cb[BPID_INDEX])
				asf_free_buf_skb(skb->dev, skb);
			else
#endif
				ASFSkbFree(skb);
			return 0;
		}
	}
drop:
	asf_reasm_debug("default error case!\n");
	skb2 = skb;
	while (skb2) {
		pLastSkb = skb2->next;
#ifdef CONFIG_DPA
		       if (skb2->cb[BPID_INDEX])
				asf_free_buf_skb(skb2->dev, skb2);
			else
#endif
				ASFSkbFree(skb2);
		skb2 = pLastSkb;
	}
	*pOutSkb = NULL;
	return 1;
}

#ifdef ASF_IPV6_FP_SUPPORT
int asfIpv6Fragment(struct sk_buff *skb,
			   unsigned int ulMTU,
			   struct net_device *dev,
			   struct sk_buff **pOutSkb)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct frag_hdr *fhdr;
	struct sk_buff *pLastSkb;
	unsigned int offset = 0;
	bool bNewSkb = 1;
	struct sk_buff *pSkb, *frag;
	unsigned int	ip6hpexh_len = 0;
	unsigned int ident = asfReasmGetNextId();
	unsigned int	bytesLeft, len, ptr;
	unsigned	char nexthdr;

	asf_reasm_debug("skb->len = %d, ulMTU=%d, ip_tot_len =%d\r\n", skb->len,
			ulMTU, , ip6h->payload_len);

	ip6hpexh_len = skb_transport_header(skb) - skb_network_header(skb);

	if (skb_shinfo(skb)->frag_list) {
		/* Fragmentation */
		if (((skb_pagelen(skb) + sizeof(struct frag_hdr)) <= ulMTU) && !((skb_pagelen(skb) - ip6hpexh_len) & 7)) {
			bNewSkb = 0;
			for (pSkb = skb_shinfo(skb)->frag_list;  pSkb != NULL; pSkb = pSkb->next) {
				if (((pSkb->len + ip6hpexh_len + sizeof(struct frag_hdr)) > ulMTU) ||
				    ((pSkb->next) && (pSkb->len & 7))) {
					bNewSkb =  1;
					break;
				}
			}
			if (!bNewSkb) {
				asfIpv6MakeFragment(skb, pOutSkb);
				return 0;
			}
		}
	}

	if (ip6h->nexthdr == NEXTHDR_HOP) {
		nexthdr = *((unsigned char *)(ip6h + 1));
		*((unsigned char *)(ip6h + 1)) = NEXTHDR_FRAGMENT;
	} else {
		nexthdr = ip6h->nexthdr;
		ip6h->nexthdr = NEXTHDR_FRAGMENT;
	}

	ulMTU -= (ip6hpexh_len + sizeof(struct frag_hdr));
	asf_reasm_debug("Re-using incoming Skb"
			" as first fragment.\r\n");

	pLastSkb = skb;

	bytesLeft = skb->len - ip6hpexh_len;

	offset = 0;
	ptr = ip6hpexh_len;
			asf_reasm_debug("bytesLeft %d, Offset %d, len %d \r\n",
					bytesLeft, offset, len);
	/* continue more more fragments with new allocations. */
	while (bytesLeft > 0) {
		asf_reasm_debug("bytesLeft %d, Offset %d, len %d \r\n",
					bytesLeft, offset, len);

		len = (bytesLeft > ulMTU) ?  (ulMTU & (~7)) : bytesLeft;


#ifdef CONFIG_DPA
		frag = alloc_skb(len+ip6hpexh_len+32, GFP_ATOMIC);
#else
		frag = gfar_new_skb(skb->dev);
#endif

		if (unlikely(!frag)) {
			asf_reasm_debug("Skb allocation"
					" failed in fragmenation\r\n");
			while (skb) {
				frag = skb;;
				skb = skb->next;
				frag->next = NULL;
				ASFSkbFree(frag);
			}
			return 1;
		}
		asf_reasm_debug("Next skb\r\n");
		pLastSkb->next = frag;
		pLastSkb = frag;
		frag->queue_mapping = skb->queue_mapping;

		skb_put(frag, ip6hpexh_len + sizeof(struct frag_hdr) + len);

		skb_reset_network_header(frag);

		skb_set_transport_header(frag, ip6hpexh_len + sizeof(struct frag_hdr));

		/*
		 *	Copy the packet header
		 *	into the new buffer.
		*/
		memcpy(skb_network_header(frag), skb_network_header(skb), ip6hpexh_len);

		asfSkbCopyBits(skb,
				ptr,
				skb_transport_header(frag),
				len);

		bytesLeft -= len;

		/*
		*	Fill in the new header fields.
		*/
		ip6h = ipv6_hdr(frag);
		ip6h->payload_len = htons(len + ip6hpexh_len + sizeof(struct frag_hdr));

		fhdr = (struct frag_hdr *)(skb_network_header(frag) + ip6hpexh_len);
		fhdr->nexthdr = nexthdr;
		fhdr->frag_off = ((offset >> 3) << 3);
		fhdr->frag_off |= (bytesLeft != 0);
		fhdr->identification = ident;

		offset += len;
		ptr += len;
	}
	*pOutSkb = skb->next;
	skb->next = NULL;
	ASFSkbFree(skb);
	return 0;
}
EXPORT_SYMBOL(asfIpv6Fragment);

int asfIpv6MakeFragment(struct sk_buff *skb,
				struct sk_buff **pOutSkb)
{
	struct ipv6hdr *ipv6h;
	struct frag_hdr *fhdr;
	unsigned int offset = 0;
	struct sk_buff *frag;
	unsigned int hdrtocpy = 0;
	unsigned int ident = asfReasmGetNextId();

	hdrtocpy = (uintptr_t)(skb_transport_header(skb)) - (uintptr_t)(skb_network_header(skb));

	skb->data -= sizeof(struct frag_hdr);
	memmove(skb->data, skb_network_header(skb), hdrtocpy);
	skb_reset_network_header(skb);

	ipv6h = ipv6_hdr(skb);

	fhdr = (struct frag_hdr *)(skb_network_header(skb) + hdrtocpy);

	if (ipv6h->nexthdr == NEXTHDR_HOP) {
		fhdr->nexthdr = *(skb_network_header(skb) + sizeof(struct ipv6hdr));
		*(skb_network_header(skb) + sizeof(struct ipv6hdr)) = NEXTHDR_FRAGMENT;
	} else {
		fhdr->nexthdr = ipv6h->nexthdr;
		ipv6h->nexthdr = NEXTHDR_FRAGMENT;
	}
	skb->len = skb_pagelen(skb);
	skb->len += sizeof(struct frag_hdr);

	ipv6h->payload_len = skb->len - sizeof(struct ipv6hdr);
	fhdr->identification = ident;
	fhdr->frag_off = 0x1; /* Zero offset , MF bit set */

	skb_set_transport_header(skb, hdrtocpy + sizeof(struct frag_hdr));

	/* Adjust the fragments properly */
	frag = skb_shinfo(skb)->frag_list;
	asf_reasm_debug("skb_shinfo(skb)->frag_list = 0x%x\r\n", frag);
	offset = skb->len - (hdrtocpy + sizeof(struct frag_hdr));
	for (; frag != NULL; frag = frag->next) {
		__skb_push(frag, hdrtocpy + sizeof(struct frag_hdr));
		skb_reset_network_header(frag);
		memcpy(skb_network_header(frag), skb_network_header(skb), hdrtocpy + sizeof(struct frag_hdr));

		ipv6h = ipv6_hdr(frag);
		ipv6h->payload_len = htons(frag->len - sizeof(struct ipv6hdr));

		fhdr = (struct frag_hdr *)(skb_network_header(frag) + hdrtocpy);
		fhdr->identification = ident;
		fhdr->frag_off = (offset >> 3) << 3;

		if (frag->next != NULL)
			fhdr->frag_off |= htons(0x1);
		offset += frag->len - (hdrtocpy + sizeof(struct frag_hdr));
	}
	skb->next = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = NULL;
	*pOutSkb = skb;
	return 0;
}
EXPORT_SYMBOL(asfIpv6MakeFragment);
#endif

/* Copy some data bits from skb to kernel buffer. */

static int asfSkbCopyBits(const struct sk_buff *this_skb,
			int offset,
			void *to,
			int len)
{
	unsigned char *dest = (unsigned char *) to, *src;
	const struct	sk_buff *skb = this_skb;
	int	nbytes, begin_skip, cur_off = 0, do_copy = 0;
	unsigned int src_len;
	unsigned int i;

	asf_reasm_debug("offset %d len %d (skb->len %u)!\n",
			offset, len, skb->len);



	while (skb) {

		src_len = skb->len;

		if (!do_copy && (offset >= cur_off) && (offset < (cur_off+src_len))) {
			do_copy = 1;
			begin_skip = offset-cur_off;
		} else {
			begin_skip = 0;
		}

		if (do_copy) {

			if (begin_skip <  skb_headlen(skb)) {
				nbytes = (len <= (skb_headlen(skb) - begin_skip)) ? len : (skb_headlen(skb) - begin_skip);
				src = skb->data;
				memcpy(dest, src + begin_skip, nbytes);
				len -= nbytes;
				dest += nbytes;
				if (len <= 0) {
					asf_reasm_debug("SkbCopyBits done!\n");
					return 0;
				}
				begin_skip = 0;
			}

			i = 0;

			if (begin_skip) {
				begin_skip -= skb_headlen(skb);
				for ( ; i < skb_shinfo(skb)->nr_frags; i++) {
					if (begin_skip < skb_shinfo(skb)->frags[i].size)
						break;
					begin_skip -= skb_shinfo(skb)->frags[i].size;
				}
				nbytes = (len <= (skb_shinfo(skb)->frags[i].size - begin_skip)) ? len : (skb_shinfo(skb)->frags[i].size - begin_skip);
				src = page_address((const struct page *)
					skb_shinfo(skb)->frags[i].page.p);
				memcpy(dest, src + begin_skip + skb_shinfo(skb)->frags[i].page_offset, nbytes);
				len -= nbytes;
				dest += nbytes;
				if (len <= 0) {
					asf_reasm_debug("SkbCopyBits done!\n");
					return 0;
				}
				++i;
			}

			for ( ; i < skb_shinfo(skb)->nr_frags; i++) {
				nbytes = (len <= skb_shinfo(skb)->frags[i].size) ? len : skb_shinfo(skb)->frags[i].size;
				src = page_address((const struct page *)
					skb_shinfo(skb)->frags[i].page.p);
				memcpy(dest, src + skb_shinfo(skb)->frags[i].page_offset, nbytes);
				len -= nbytes;
				dest += nbytes;
				if (len <= 0) {
					asf_reasm_debug("SkbCopyBits done!\n");
					return 0;
				}
			}
		}

		cur_off += src_len;

		if (skb == this_skb)
			skb = skb_shinfo(skb)->frag_list;
		else
			skb = skb->next;
	}
	return len;
}

/*
 * Callback from splice_to_pipe(), if we need to release some pages
 * at the end of the spd in case we error'ed out in filling the pipe.
 */


EXPORT_SYMBOL(asfIpv4Defrag);
EXPORT_SYMBOL(asfReasmLinearize);
EXPORT_SYMBOL(asfIpv4Fragment);
EXPORT_SYMBOL(asfReasmPullBuf);


