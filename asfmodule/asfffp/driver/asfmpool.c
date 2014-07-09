/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
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

#ifdef ASF_MPOOL_DEBUG
#define asf_mpool_debug(fmt, args...) \
	pr_info("[CPU %d] asfmpool.c:%d %s] " fmt, smp_processor_id(), \
		__LINE__, __func__, ##args)
#else
#define asf_mpool_debug(fmt, args...)
#endif
/* #define ASF_DUMMY_MPOOL */
/* #define ASF_DUMMY_MPOOL_NOFREE */
#ifdef ASF_DUMMY_MPOOL
#define ASF_MPOOL_DEBUG
extern bool asf_enable;
#define panic (fmt, args...) do { asf_mpool_debug("Forced Panic " fmt, ##args); asf_enable = 0; } while (0)
#endif

/* #define ASF_MPOOL_DEBUG */


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
#ifdef ASF_MPOOL_USE_SRAM
			memset(ptr->vaddr, 0, ASF_MAX_POOLS * sizeof(struct asf_pool_s));
#endif
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
#ifdef ASF_MPOOL_USE_SRAM
			memset(ptr->vaddr, 0, sizeof(struct asf_pool_s));
#endif
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
	 ulNumMaxEntries = number of max pool entries
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

	asf_mpool_debug("name %s NumGbl %d NumMax %d PerCpu %d DataSize %d\n",
			name, ulNumGlobalPoolEntries, ulNumMaxEntries,
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
		asf_mpool_debug("ii = %d\n", ii);
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
					spin_lock_init(&poolPtr->lock);
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
				spin_lock_init(&poolPtr->lock);
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
		ptr->pHead->ulDataElemSize = sizeof(struct asf_poolLinkNode_s)
			+ ulDataSize;
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

	spin_lock_bh(&(pool->lock));
	node = (struct asf_poolLinkNode_s *)  pool->head;
	if (node) {
		asf_mpool_debug("Allocating from static per CPU pool\r\n");
		pool->head = pool->head->pNext;
		pool->ulNumAllocs++;
		pool->ulNumEntries--;
		spin_unlock_bh(&(pool->lock));
		*bHeap = 0;
		node->pNext = NULL;
		return node;
	} else {
		spin_unlock_bh(&(pool->lock));
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
			spin_lock_bh(&(pool->lock));
			pool->head = node->pNext;
			pool->ulNumEntries += ((ii > 2) ? (ii-2) : 0) ;
			node->pNext = NULL;
			pool->ulNumAllocs++;
			spin_unlock_bh(&(pool->lock));
			*bHeap = 0;
			return node;
		} else {
			asf_mpool_debug("Allocating from heap\r\n");
			node = kzalloc((pool->ulDataSize), GFP_ATOMIC);
			if (node) {
				*bHeap = 1;
				spin_lock_bh(&(pool->lock));
				pool->ulNumHeapAllocs++;
				spin_unlock_bh(&(pool->lock));
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
		spin_lock_bh(&(pool->lock));
		asf_mpool_debug("pool: num %u  pc-max %u\n", pool->ulNumEntries, pool->ulNumPerCoreMaxEntries);
		if ((pool->ulNumEntries + 1) <= (pool->ulNumPerCoreMaxEntries)) {
			asf_mpool_debug("Returning to per cpu pool\r\n");
			memset(pNode, 0, pool->ulDataElemSize);

			/* simplest case, release and get out */
			pNode->pNext = pool->head;
			pool->head = pNode;

			pool->ulNumEntries++;
			pool->ulNumFrees++;
			asf_mpool_debug("Pool Stats: NumAlloced = %d, NumFree = %d\r\n", pool->ulNumAllocs, pool->ulNumFrees);
			spin_unlock_bh(&(pool->lock));
		} else {
			spin_unlock_bh(&(pool->lock));
			/* try to release to global pool */
			globalPool = global_pools[ulNumPoolId].pHead;

			asf_mpool_debug("gpool: num %u\n", globalPool->ulNumEntries);

			memset(pNode, 0, pool->ulDataElemSize);
			spin_lock_bh(&(globalPool->lock));
			pNode->pNext = globalPool->head;
			globalPool->head = pNode;
			globalPool->ulNumEntries++;
			globalPool->ulNumFrees++;
			spin_unlock_bh(&(globalPool->lock));
			asf_mpool_debug("Returned to global pool\r\n");
		}
		return;
	}
	kfree(data);
	asf_mpool_debug("Returning to heap\r\n");
	spin_lock_bh(&(pool->lock));
	pool->ulNumFrees++;
	spin_unlock_bh(&(pool->lock));
	return;
}

void dump_mpool_counters(void)
{
	int ii, jj, out;
	struct asf_pool_s *pool, *globalPool;
	pr_info("name    id    cpuwise alloc/free            "
		"global alloc/free   outstanding\n");
	for (ii = 0; ii < ASF_MAX_POOLS; ii++) {
		pool = &(per_cpu_ptr(pools, 0)->pHead[ii]);
		if (pool->bInUse) {
			pr_info("%.10s %d:", pool->name, ii);
			out = 0;
			for_each_possible_cpu(jj) {
			pool = &(per_cpu_ptr(pools, jj)->pHead[ii]);
				pr_info(" %d:%d/%d,", jj, pool->ulNumAllocs,
					pool->ulNumFrees);
				out += (pool->ulNumAllocs
					- pool->ulNumFrees);
	}

		globalPool = global_pools[ii].pHead;
			out += (globalPool->ulNumAllocs - globalPool->ulNumFrees);
			pr_info("  %d/%d, %d\n", globalPool->ulNumAllocs,
				globalPool->ulNumFrees, out);
		}
	}
}

EXPORT_SYMBOL(asfCreatePool);
EXPORT_SYMBOL(asfReleaseNode);
EXPORT_SYMBOL(asfDestroyPool);
EXPORT_SYMBOL(asfGetNode);
