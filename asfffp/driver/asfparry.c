/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfparry.c
 * Description: Contains Array Management functions for ASF
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version		Date		Author		Change Description
 *
*/
/******************************************************************************/
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/in.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include "asf.h"

#include "asfparry.h"
/*
  * Library functions to hold pointer/magic number based arrays
  * Array setup
  * Get Node
  * Get Magic Number
  * delete
  * Array cleanup
  */
void ptrIArray_setup(ptrIArry_tbl_t *pTable,  ptrIArry_nd_t *pNode,
		     unsigned int nr_entries, bool b_lock)
{
	int ii;
	pTable->pHead = pTable->pBase = pNode;
	pTable->nr_entries = nr_entries;
	pTable->ulMagicNum = 1;

	/* Set up first node */
	pNode[0].pPrev = NULL;
	pNode[0].pNext = &(pNode[1]);
	for (ii = 1; ii < (nr_entries-1); ii++) {
		pNode[ii].pNext = &(pNode[ii+1]);
		pNode[ii+1].pPrev = &(pNode[ii]);
	}
	/* Set up Last node */
	pNode[ii].pNext = NULL;
	pNode[ii].pPrev = &(pNode[ii-1]);

	pTable->bLock = b_lock;
}

void ptrIArray_cleanup(ptrIArry_tbl_t *pTable)
{
	if (pTable->pBase)
		kfree(pTable->pBase);
}

unsigned int ptrIArray_addInGivenIndex(ptrIArry_tbl_t *pTable,
				       void *pData,
				       unsigned ulIndex,
				       unsigned ulMagicNumber)
{
	ptrIArry_nd_t *pNode;

	if (pTable->bLock)
		spin_lock_bh(&pTable->tblLock);
	pNode = &(pTable->pBase[ulIndex]);
	if (pNode->ulMagicNum == 0) {
		if (pNode == pTable->pHead) {
			pNode = pTable->pHead;
			pTable->pHead = pTable->pHead->pNext;
			if (pTable->pHead)
				pTable->pHead->pPrev = NULL;
		} else {
			if (pNode->pPrev)
				pNode->pPrev->pNext = pNode->pNext;
			if (pNode->pNext)
				pNode->pNext->pPrev = pNode->pPrev;
		}
		if (pTable->bLock)
			spin_unlock_bh(&pTable->tblLock);

		pNode->pNext = NULL;
		pNode->pPrev = NULL;
		pNode->pData = pData;
		pNode->ulMagicNum = ulMagicNumber;
		smp_wmb();
		return 0;
	}
	if (pTable->bLock)
		spin_unlock_bh(&pTable->tblLock);
	return 1;
}
EXPORT_SYMBOL(ptrIArray_setup);
EXPORT_SYMBOL(ptrIArray_cleanup);
EXPORT_SYMBOL(ptrIArray_addInGivenIndex);
