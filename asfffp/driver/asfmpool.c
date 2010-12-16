/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
 ***************************************************************************/
/*
 * File:	asfmpool.c
 *
 * Description: Memory Pools routines for ASF
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
#include <net/ip.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#include "gplcode.h"
#include "asfdeps.h"

/* #define ASF_DUMMY_MPOOL */
/* #define ASF_DUMMY_MPOOL_NOFREE */
#ifdef ASF_DUMMY_MPOOL
#define ASF_MPOOL_DEBUG
extern int asf_enable;
#define panic (fmt, args...) do { asf_mpool_debug("Forced Panic " fmt, ##args); asf_enable = 0; } while (0)
#endif

/* #define ASF_MPOOL_DEBUG */
#ifdef ASF_MPOOL_DEBUG
#define asf_mpool_debug(fmt, args...) printk("[CPU %d] asfmpool.c:%d %s] " fmt, smp_processor_id(), __LINE__, __FUNCTION__, ##args)
#else
#define asf_mpool_debug(fmt, args...)
#endif


#define ASF_MAX_POOLS 25
#define ASF_MAX_POOL_NAME_LEN 32
#define ASF_MAX_RETURNS 10

#define ASF_MIN_POOL_ENTRIES            (10)

struct asf_poolInfo_s {
	dma_addr_t paddr;
	unsigned long *vaddr;
	struct asf_pool_s  *pHead ____cacheline_aligned_in_smp;
} ;

struct asf_poolLinkNode_s {
	struct asf_poolLinkNode_s *pNext;
} ;

/*
#define GFAR_SRAM_PBASE 0xf0000000
*/


struct asf_pool_s {
	char name[ASF_MAX_POOL_NAME_LEN];
	char bInUse;
	spinlock_t lock;
	void	 *pMemory;
	struct asf_poolLinkNode_s  *head;
	unsigned int ulDataSize;
	unsigned int ulDataElemSize;
	unsigned int ulNumAllocs;
	unsigned int ulNumHeapAllocs;
	unsigned int ulNumFrees;
	unsigned int ulNumPerCoreStaticEntries;
	unsigned int ulNumPerCoreMaxEntries;
	unsigned int ulNumEntries;
	unsigned int ulNumMaxEntries;
} ;

#ifndef ASF_DUMMY_MPOOL

static struct asf_poolInfo_s *pools;
static struct asf_poolInfo_s *global_pools;

/*
 * This function initializes space to hold the pool information in L2 SRAM
 * Care is taken to ensure that the every per CPU pool is allocated at a
 * different cache line, so there is no cache thrashing when two cores
 * work simultaneously on their respective pools
 * Should be called to initialize the memory pool library
 */
int asfInitPools(void)
{
	int ii;
	struct asf_poolInfo_s *ptr;

	pools = asfAllocPerCpu(sizeof(struct asf_poolInfo_s));

	if (pools) {
		asf_mpool_debug("pools = 0x%x\n", pools);
		for_each_possible_cpu(ii)
		{
			asf_mpool_debug("foreach_cpu %d\n", ii);
			ptr = asfPerCpuPtr(pools, ii);
#ifdef ASF_MPOOL_USE_SRAM
			asf_mpool_debug("ii = %d ptr 0x%x\n", ii, ptr);
			ptr->paddr = (unsigned long)(ASF_MPOOL_SRAM_BASE +
						     (ii * ASF_MAX_POOLS * sizeof(struct asf_pool_s)));
			ptr->vaddr  = ioremap_flags(ptr->paddr,
						    (ASF_MAX_POOLS * sizeof(struct asf_pool_s)),
						    PAGE_KERNEL | _PAGE_COHERENT);
#else
			ptr->vaddr = kzalloc(ASF_MAX_POOLS * sizeof(struct asf_pool_s), GFP_KERNEL);
#endif
			asf_mpool_debug("CPU Id =%d, paddr = 0x%x , vaddr = 0x%x, size =%d\r\n", ii, ptr->paddr,
					ptr->vaddr,
					(ASF_MAX_POOLS * sizeof(struct asf_pool_s)));
			if (!ptr->vaddr) {
				asf_mpool_debug("asf_init_pools failed for core Id =%d\r\n", ii);
				return 1;
			}
			memset(ptr->vaddr, 0, ASF_MAX_POOLS * sizeof(struct asf_pool_s));
			ptr->pHead = (struct asf_pool_s *)  (ptr->vaddr);
			asf_mpool_debug("Per CPU Pools: ptr->vaddr = 0x%x, ptr-pHead = 0x%x\r\n", ptr->vaddr, ptr->pHead);
		}
	} else {
		asf_mpool_debug("Pool Init: alloc memory failed\r\n");
		return 1;
	}

	global_pools = kzalloc((ASF_MAX_POOLS * sizeof(struct asf_poolInfo_s)), GFP_KERNEL);
	if (global_pools) {
		for (ii = 0; ii < ASF_MAX_POOLS; ii++) {
			ptr = &(global_pools[ii]);
#ifdef ASF_MPOOL_USE_SRAM

			ptr->paddr = (unsigned long)(ASF_MPOOL_SRAM_BASE +
						     ((NR_CPUS * ASF_MAX_POOLS * sizeof(struct asf_pool_s))
						      + (ii*sizeof(struct asf_pool_s))));
			ptr->vaddr  = ioremap_flags(ptr->paddr,
						    (sizeof(struct asf_pool_s)),
						    PAGE_KERNEL | _PAGE_COHERENT);
#else
			ptr->vaddr = kzalloc(sizeof(struct asf_pool_s), GFP_KERNEL);
#endif
			if (!ptr->vaddr) {
				asf_mpool_debug("asf_init_pools  failed for global pool Id =%d\r\n", ii);
				return 1;
			}
			memset(ptr->vaddr, 0, sizeof(struct asf_pool_s));
			ptr->pHead = (struct asf_pool_s *)  (ptr->vaddr);
			asf_mpool_debug("Global Pools%d  : ptr->paddr = 0x%x, ptr->vaddr = 0x%x, ptr-pHead = 0x%x\r\n", ii, ptr->paddr, ptr->vaddr, ptr->pHead);
		}
	} else {
		asf_mpool_debug("Failed to allocate memory for global pools!\n");
		return 1;
	}
	return 0;

}

int asfDeInitPools(void)
{
	struct asf_poolInfo_s *ptr;
	int ii;

	for_each_possible_cpu(ii)
	{
		ptr = asfPerCpuPtr(pools, ii);
#ifdef ASF_MPOOL_USE_SRAM
		iounmap(ptr->vaddr);
#else
		kfree(ptr->vaddr);
#endif
	}
	asfFreePerCpu(pools);

	for (ii = 0; ii < ASF_MAX_POOLS; ii++) {
		ptr = &(global_pools[ii]);
#ifdef ASF_MPOOL_USE_SRAM
		iounmap(ptr->vaddr);
#else
		kfree(ptr->vaddr);
#endif
	}
	kfree(global_pools);
	return 0;
}



/* assumes that asf_create_pool will always be called during initialization only,
    single core context
    assumes that one pool
 * Arguments
	 name = pool name
	 ulNumGlobalPoolEntries = number of global pool entries
	 ulNumMaxEntries = number of max pool entries [TBD: To enfore this ]
	 ulNumPerCoreEntries = number of entries to keep per pool
	 ulDataSize = size in bytes of the data structure
	 numPoolId = Pointer that holds the allocated pool Id index
  Description
	Finds a pool which is not in use and returns the pool ID. It needs
	to set up per core pool as well as global pool
  */
int asfCreatePool(char *name, unsigned int ulNumGlobalPoolEntries,
		  unsigned int ulNumMaxEntries, unsigned int ulPerCoreEntries,
		  unsigned int ulDataSize, unsigned int *numPoolId)
{
	struct asf_poolInfo_s *ptr;
	struct asf_poolLinkNode_s *pLinkNode;
	struct asf_pool_s *poolPtr = NULL;
	int ii, numPool = 0, jj, poolAlloced = 0;
	unsigned char *cptr;

	asf_mpool_debug("%s - name %s NumGbl %d NumMax %d PerCpu %d DataSize %d\n",
			__FUNCTION__, name, ulNumGlobalPoolEntries, ulNumMaxEntries,
			ulPerCoreEntries, ulDataSize);


	ulNumGlobalPoolEntries = (ulNumGlobalPoolEntries < ASF_MIN_POOL_ENTRIES) ?
					ASF_MIN_POOL_ENTRIES :
					ulNumGlobalPoolEntries;

	ulNumMaxEntries = (ulNumMaxEntries < ASF_MIN_POOL_ENTRIES) ?
					ASF_MIN_POOL_ENTRIES :
					ulNumMaxEntries;

	ulPerCoreEntries = (ulPerCoreEntries < ASF_MIN_POOL_ENTRIES) ?
					ASF_MIN_POOL_ENTRIES :
					ulPerCoreEntries;

	for_each_possible_cpu(ii)
	{
		asf_mpool_debug("%s - ii = %d\n", __FUNCTION__, ii);
		ptr = per_cpu_ptr(pools, ii);
		if (poolAlloced == 0) {
			for (numPool = 0, poolPtr = ptr->pHead+numPool; numPool < ASF_MAX_POOLS; numPool++, poolPtr++) {
				asf_mpool_debug("CPU = %d ptr->pHead = 0x%x, poolPtr=0x%x\r\n", ii, ptr->pHead, poolPtr);
				if (!poolPtr->bInUse) {
					poolPtr->bInUse = 1;
					asf_mpool_debug("poolAlloced poolId=%d\r\n", numPool);
					poolAlloced = 1;
					strncpy(poolPtr->name, name, ASF_MAX_POOL_NAME_LEN);
					poolPtr->head =
					kzalloc((ulDataSize + sizeof(struct asf_poolLinkNode_s)) * ulPerCoreEntries, GFP_KERNEL);
					if (poolPtr->head == NULL) {
						asf_mpool_debug("asf_create_pool: core Id =%d, pool Id=%d allocation failed\r\n", ii, numPool);
						return 1;
					}
					poolPtr->pMemory = poolPtr->head;
					poolPtr->ulDataElemSize = sizeof(struct asf_poolLinkNode_s) + ulDataSize;
					asf_mpool_debug("ulDataElemSize = %d\r\n", poolPtr->ulDataElemSize);

					poolPtr->ulNumEntries = ulPerCoreEntries;
					poolPtr->ulNumPerCoreMaxEntries = ulPerCoreEntries;
					poolPtr->ulDataSize = ulDataSize;
					for (jj = 0, pLinkNode = (struct asf_poolLinkNode_s *)  (poolPtr->head) ;
					    jj < (ulPerCoreEntries-2); jj++) {
						cptr = (unsigned char *)  (pLinkNode) + poolPtr->ulDataElemSize;
						pLinkNode->pNext = (struct asf_poolLinkNode_s *)  cptr;
						pLinkNode = pLinkNode->pNext;
					}
					pLinkNode->pNext = NULL;
					break;
				}
			}
			if (numPool >= ASF_MAX_POOLS) {
				asf_mpool_debug("asf_create_pool: core Id =%d, pool Id=%d no free slot for new pool\n", ii, numPool);
				return 1;
			}
		} else {
			asf_mpool_debug("ii=%d ptr->pHead = 0x%x, numPool = %d\r\n", ii, ptr->pHead, numPool);
			poolPtr = ptr->pHead + numPool;
			asf_mpool_debug("poolPtr = 0x%x\r\n", poolPtr);
			if (!poolPtr->bInUse) {
				poolPtr->bInUse = 1;
				strncpy(poolPtr->name, name, ASF_MAX_POOL_NAME_LEN);
				poolPtr->head =
				kzalloc((ulDataSize + sizeof(struct asf_poolLinkNode_s)) * ulPerCoreEntries, GFP_KERNEL);
				if (poolPtr->head == NULL) {
					asf_mpool_debug("asf_create_pool: core Id =%d, pool Id=%d allocation failed\r\n", ii, numPool);
					return 1;
				}
				poolPtr->pMemory = poolPtr->head;
				poolPtr->ulDataElemSize = sizeof(struct asf_poolLinkNode_s) + ulDataSize;
				poolPtr->ulNumEntries = ulPerCoreEntries;
				poolPtr->ulNumPerCoreMaxEntries = ulPerCoreEntries;
				poolPtr->ulDataSize = ulDataSize;
				for (jj = 0, pLinkNode = (struct asf_poolLinkNode_s *)  (poolPtr->head) ; jj < (ulPerCoreEntries-2);
				    jj++) {
					cptr = (unsigned char *)  (pLinkNode) + poolPtr->ulDataElemSize;
					pLinkNode->pNext = (struct asf_poolLinkNode_s *)  cptr;
					pLinkNode = pLinkNode->pNext;
				}
				pLinkNode->pNext = NULL;
			} else {
				asf_mpool_debug("Should not happen, Pool in use in other core, core Id =%d, pool Id=%d\r\n",
						ii, numPool);
				return 1;
			}

		}
	}
	/* Get from the global pool */
	ptr = &(global_pools[numPool]);
	if (/*(numPool < ASF_MAX_POOLS) && */ !ptr->pHead->bInUse) {
		ptr->pHead->bInUse = 1;
		strncpy(ptr->pHead->name, name, ASF_MAX_POOL_NAME_LEN);
		ptr->pHead->head =
		kzalloc((ulDataSize + sizeof(struct asf_poolLinkNode_s)) * ulNumGlobalPoolEntries,
			GFP_KERNEL);
		if (ptr->pHead->head == NULL) {
			asf_mpool_debug("asf_create_pool: core Id =%d, pool Id=%d allocation failed\r\n", ii, numPool);
			return 1;
		}
		spin_lock_init(&(ptr->pHead->lock));
		ptr->pHead->pMemory = ptr->pHead->head;
		ptr->pHead->ulNumEntries = ulNumGlobalPoolEntries;
		ptr->pHead->ulDataSize = ulDataSize;
		for (jj = 0,
		     pLinkNode = (struct asf_poolLinkNode_s *)  (ptr->pHead->head) ;
		    jj < (ulNumGlobalPoolEntries-2); jj++) {
			cptr = (unsigned char *)  (pLinkNode) + poolPtr->ulDataElemSize;
			pLinkNode->pNext = (struct asf_poolLinkNode_s *)  cptr;
			pLinkNode = pLinkNode->pNext;
		}
		pLinkNode->pNext = NULL;
	} else {
		asf_mpool_debug("Should not happen, Global Pool in use in other core, , pool Id=%d\r\n",
				numPool);
		return 1;
	}
	*numPoolId = numPool;
	asf_mpool_debug("Allocated pool Id = %d\r\n", *numPoolId);
	return 0;
}

/* all heap allocated data items should have been released by the caller already */
int asfDestroyPool(unsigned int numPool)
{
	struct asf_poolInfo_s *ptr;
	struct asf_pool_s *poolPtr;
	int ii;

	ptr = &(global_pools[numPool]);
	/* printk("Freeing ID %d GblPool Ptr 0x%x\n", numPool, ptr->pHead->head); */
	kfree(ptr->pHead->pMemory);
	ptr->pHead->bInUse = 0;

	for_each_possible_cpu(ii)
	{
		ptr = per_cpu_ptr(pools, ii);
		poolPtr = ptr->pHead+numPool;

		if (poolPtr->bInUse) {
			/*printk("Freeing ID %d PerCpu[%d] Ptr 0x%x\n", numPool, ii, poolPtr->head);*/
			kfree(poolPtr->pMemory);
			poolPtr->bInUse = 0;
		}

	}

	return 0;
}


/*
 * Function : asfGetNode
 * Arguments
      ulNumPoolId : Pool Id to get the node from
      bHeap : Return variable, that holds information whether the element
	      was allocated from heap.
 * Description
      : try from its own core pool. If available, return the same
      : If not available, try the global pool using lock, If lock obtained,
	check in global pool, Gets as many entries as required, takes one
	and assigns remaining to the head
      : If lock is not available or global pool is empty, does kmalloc,
	assigns heap and returns
 */
void *asfGetNode(unsigned int ulNumPoolId,  char *bHeap)
{
	struct asf_pool_s *pool, *gl_pool;
	struct asf_poolLinkNode_s *pLinkNode, *pPrev, *node;
	int ii;

	pool = &(per_cpu_ptr(pools, smp_processor_id())->pHead[ulNumPoolId]);
	asf_mpool_debug("asfGetNode: CPU %d id %d pool 0x%x extd 0x%x\n", smp_processor_id(), ulNumPoolId,
			pool, per_cpu_ptr(pools, smp_processor_id()));

	node = (struct asf_poolLinkNode_s *)  pool->head;
	if (node) {
		asf_mpool_debug("Allocating from static per CPU pool\r\n");
		pool->head = pool->head->pNext;
		pool->ulNumAllocs++;
		pool->ulNumEntries--;
		*bHeap = 0;
		node->pNext = NULL;
		return node;
	} else {
		asf_mpool_debug("Allocating from Global pool\r\n");
		gl_pool = global_pools[ulNumPoolId].pHead;
		if ((gl_pool->head) &&
		    (spin_trylock(&(gl_pool->lock)))) {
			for (ii = 0, pPrev = NULL, node = pLinkNode = (struct asf_poolLinkNode_s *)  (gl_pool->head);
			    ((pLinkNode != NULL) && (ii < pool->ulNumPerCoreMaxEntries));
			    ii++, pLinkNode = pLinkNode->pNext) {
				pPrev = pLinkNode;
			}
			if (pPrev) {
				gl_pool->head = pPrev->pNext;
				pPrev->pNext  = NULL;
				gl_pool->ulNumEntries -= (ii-1);
			}
			spin_unlock(&(gl_pool->lock));
		}
		if (node) {
			pool->head = node->pNext;
			pool->ulNumEntries += ((ii > 2) ? (ii-2) : 0) ;
			node->pNext = NULL;
			pool->ulNumAllocs++;
			*bHeap = 0;
			return node;
		} else {
			asf_mpool_debug("Allocating from heap\r\n");
			node = kzalloc((pool->ulDataSize), GFP_ATOMIC);
			if (node) {
				*bHeap = 1;
				pool->ulNumHeapAllocs++;
			}
			return node;
		}
	}
	return NULL;
}


/*
 * Function name : asfReleaseNode
 * Input Args
		ulNumPoolId - Pool Id
		data - data to be released
		bHeap - whether data was allocated from heap or not
 * Description :
	If allocated from heap, returns to heap
	Tries to return to the current core's pool. If more than max per core
	entries, it returns to the global pool if global pool lock is available.
	If lock is not available, returns to heap again.
*/
void asfReleaseNode(unsigned int ulNumPoolId, void *data, char bHeap)
{
	struct asf_pool_s *pool, *globalPool;
	struct asf_poolLinkNode_s *pNode = (struct asf_poolLinkNode_s *)  (data);

	pool = &(per_cpu_ptr(pools, smp_processor_id())->pHead[ulNumPoolId]);

	asf_mpool_debug("asfReleaseNode: CPU %d id %d pool 0x%x extd 0x%x\n", smp_processor_id(), ulNumPoolId,
			pool, per_cpu_ptr(pools, smp_processor_id()));

	asf_mpool_debug("PoolID = %d: bHeap = %d asfReleaseNode called\r\n", ulNumPoolId, bHeap);
	if (!bHeap) {
		asf_mpool_debug("pool: num %u  pc-max %u\n", pool->ulNumEntries, pool->ulNumPerCoreMaxEntries);
		if ((pool->ulNumEntries + 1) <= (pool->ulNumPerCoreMaxEntries)) {
			asf_mpool_debug("Returning to per cpu pool\r\n");
#if 1
			memset(pNode, 0, pool->ulDataElemSize);
#else
			cacheable_memzero(pNode, pool->ulDataElemSize);
#endif

			/* simplest case, release and get out */
			pNode->pNext = pool->head;
			pool->head = pNode;

			pool->ulNumEntries++;
			pool->ulNumFrees++;
			asf_mpool_debug("Pool Stats: NumAlloced = %d, NumFree = %d\r\n", pool->ulNumAllocs, pool->ulNumFrees);
		} else {
			/* try to release to global pool */
			globalPool = global_pools[ulNumPoolId].pHead;

			asf_mpool_debug("gpool: num %u\n", globalPool->ulNumEntries);

#if 1
			memset(pNode, 0, pool->ulDataElemSize);
#else
			cacheable_memzero(pNode, pool->ulDataElemSize);
#endif
			spin_lock(&(globalPool->lock));
			pNode->pNext = globalPool->head;
			globalPool->head = pNode;
			globalPool->ulNumEntries++;
			globalPool->ulNumFrees++;
			spin_unlock(&(globalPool->lock));
			asf_mpool_debug("Returned to global pool\r\n");
		}
		return;
	}
	kfree(data);
	asf_mpool_debug("Returning to heap\r\n");
	pool->ulNumFrees++;
	return;
}

void dump_mpool_counters(void);
void dump_mpool_counters()
{
	int ii, jj;
	struct asf_pool_s *pool, *globalPool;
	for (ii = 0; ii < 3; ii++) {
		for (jj = 0; jj < NR_CPUS; jj++) {
			pool = &(per_cpu_ptr(pools, jj)->pHead[ii]);
			asf_mpool_debug("Pool Id = %d, CPU Id = %d, Num Allocs = %d, Num Frees = %d\r\n", ii, jj, pool->ulNumAllocs, pool->ulNumFrees);
		}
	}
	for (ii = 0; ii < 3; ii++) {

		globalPool = global_pools[ii].pHead;
		asf_mpool_debug("Pool Id = %d, CPU Id = %d, Num Allocs = %d, Num Frees = %d\r\n", ii, jj, globalPool->ulNumAllocs, globalPool->ulNumFrees);
	}
}

#else
/* Dummy Mpool Wrappers - For testing */
static struct asf_pool_s pools[ASF_MAX_POOLS];

int asfInitPools(void)
{
	asf_mpool_debug("dummy\n");
	memset(pools, 0, sizeof(pools));
	return 0;
}

int asfDeInitPools(void)
{
	asf_mpool_debug(" %s -- dummy\n", , __FUNCTION__);
	return 0;
}

int asfCreatePool(char *name, unsigned int ulNumGlobalPoolEntries,
		  unsigned int ulNumMaxEntries, unsigned int ulPerCoreEntries,
		  unsigned int ulDataSize, unsigned int *numPoolId)
{
	int i;
	asf_mpool_debug("dummy\n");
	for (i = 0; i < ASF_MAX_POOLS; i++) {
		if (!pools[i].bInUse) {
			pools[i].bInUse = 1;
			pools[i].ulDataSize = ulDataSize;
			*numPoolId = i;
			return 0;
		}
	}
	return 1;
}

int asfDestroyPool(unsigned int ulNumPoolId)
{
	asf_mpool_debug("not implemented\n");
	return 0;
}

#define VALID_HEAD_MARK	"C0DE"
#define VALID_TAIL_MARK	"CAFE"
#define INVALID_HEAD_MARK	"DEAD"
#define INVALID_TAIL_MARK	"FACE"

void *asfGetNode(unsigned int ulNumPoolId,  char *bHeap)
{

	struct asf_pool_s *pool;
	unsigned char *p;

	if (ulNumPoolId >= ASF_MAX_POOLS) {
		asf_mpool_debug("ERROR - Invalid pool id %d\n", ulNumPoolId);
		return NULL;
	}
	pool = &pools[ulNumPoolId];
	if (pool->bInUse) {
		if (bHeap)
			*bHeap = 1;
		p = (unsigned char *)   kzalloc(pool->ulDataSize + 8, GFP_ATOMIC);
		if (p) {
			/* have markers at head and tail for detection of memory corruption */
			memcpy(p, VALID_HEAD_MARK, 4);
			memcpy(p+pool->ulDataSize + 4, VALID_TAIL_MARK, 4);
			return p + 4;
		} else {
			asf_mpool_debug("Memory allocation failed for pool ID %d\n", ulNumPoolId);
		}
	} else {
		asf_mpool_debug("Pool ID %d is invalid as it is not allocated\n", ulNumPoolId);
	}
	return NULL;
}

#define _C(ch) ((ch >= 32) && (ch < 200)) ? ch : '.'

void asfReleaseNode(unsigned int ulNumPoolId, void *data, char bHeap)
{
	struct asf_pool_s *pool;
	unsigned char *p = (unsigned char *)  data;
	unsigned long ulDataSize;

	if (ulNumPoolId >= ASF_MAX_POOLS) {
		dump_stack();
		asf_mpool_debug("ERROR - Invalid pool id %d\n", ulNumPoolId);
		return;
	}

	pool = &pools[ulNumPoolId];
	if (pool->bInUse) {
		ulDataSize = pool->ulDataSize;
		if (bHeap != 1) {
			dump_stack();
			asf_mpool_debug("ERROR - bHeap is suppossed to be 1, pool_id = %d\n", ulNumPoolId);
			return;
		}
		/* verify the markers and reset them */
		if (p) {
			p = p-4;
			if (!memcmp(p, INVALID_HEAD_MARK, 4)) {
				dump_stack();
				asf_mpool_debug("ERROR - Possible double free detected using head mark, pool_id = %d (head %c%c%c%c)\n",
						ulNumPoolId,
						_C(p[0]), _C(p[1]), _C(p[2]), _C(p[3]));
#ifdef ASF_DUMMY_MPOOL_NOFREE
				if (ulDataSize >= 4) {
					/* don't free the memory and store curent cpu id towards tail */
					/* 4 bytes before tail */
					unsigned short *magic = (unsigned short *) (p+ulDataSize);
					asf_mpool_debug("This pointer was already freed by CPU %d in_softirq %d\n",
							magic[0], magic[1]);
					asf_mpool_debug("Current State: CPU %d in_softirq %d\n",
							smp_processor_id(), in_softirq());
				}
#endif
				panic("double free attempt (detected using head mark)!\n");
				return;
			}
			if (!memcmp(p+ulDataSize + 4, INVALID_TAIL_MARK, 4)) {
				unsigned char *t = p+ulDataSize + 4;
				dump_stack();
				asf_mpool_debug("ERROR - Possible double free detected using tail mark, pool_id = %d (tail %c%c%c%c)\n",
						ulNumPoolId,
						_C(t[0]), _C(t[1]), _C(t[2]), _C(t[3]));
#ifdef ASF_DUMMY_MPOOL_NOFREE
				if (ulDataSize >= 4) {
					/* don't free the memory and store curent cpu id towards tail */
					/* 4 bytes before tail */
					unsigned short *magic = (unsigned short *) (p+ulDataSize);
					asf_mpool_debug("This pointer was already freed by CPU %d in_softirq %d\n",
							magic[0], magic[1]);
					asf_mpool_debug("Current State: CPU %d in_softirq %d\n",
							smp_processor_id(), in_softirq());
				}
#endif
				panic("double free attempt (detected using tail mark)!\n");
				return;
			}
			if (memcmp(p, VALID_HEAD_MARK, 4)) {
				dump_stack();
				asf_mpool_debug("ERROR - HEAD marker corrupted, pool_id = %d (head %c%c%c%c)\n",
						ulNumPoolId,
						_C(p[0]), _C(p[1]), _C(p[2]), _C(p[3]));
				panic("memory corruption!\n");
				return;
			}
			if (memcmp(p+ulDataSize + 4, VALID_TAIL_MARK, 4)) {
				unsigned char *t = p+ulDataSize + 4;
				dump_stack();
				asf_mpool_debug("ERROR - TAIL marker corrupted, pool_id = %d (tail %c%c%c%c)\n",
						ulNumPoolId,
						_C(t[0]), _C(t[1]), _C(t[2]), _C(t[3]));
				panic("memory corruption!\n");
				return;
			}
			memcpy(p, INVALID_HEAD_MARK, 4);
			memcpy(p+ulDataSize + 4, INVALID_TAIL_MARK, 4);
#ifndef ASF_DUMMY_MPOOL_NOFREE
			kfree(p);
#else
			if (ulDataSize >= 4) {
				/* don't free the memory and store curent cpu id towards tail */
				/* 4 bytes before tail */
				unsigned short *magic = (unsigned short *) (p+ulDataSize);
				magic[0] = smp_processor_id();
				magic[1] = in_softirq();
			}
#endif
		} else {
			dump_stack();
			asf_mpool_debug("ERROR - NULL pointer given for free (pool_id %d)\n", ulNumPoolId);
		}
	} else {
		asf_mpool_debug("ERROR - Pool ID %d is invalid as it is not allocated\n", ulNumPoolId);
	}
}
#endif
EXPORT_SYMBOL(asfCreatePool);
EXPORT_SYMBOL(asfReleaseNode);
EXPORT_SYMBOL(asfDestroyPool);
EXPORT_SYMBOL(asfGetNode);
