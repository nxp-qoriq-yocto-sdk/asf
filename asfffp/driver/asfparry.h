/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfparry.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the  GNU General Public License along
 * with this program; if not, write  to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
/*
 * History
 *
 */

 /*
 * TBD:
 *
 */
/******************************************************************************/


/******************************************************************************
 * File Name : asfParry.h
 * Description: Contains the macros, type defintions, exported and imported functions for
 * IPsec fast path
 * Version  : 0.1
 * Author : Subha
 * Date : October 2009
 ******************************************************************************/
/*******************Include files ************************************************/
#ifndef _ASF_PARRY_H
#define _ASF_PARRY_H




typedef struct ptrIArry_nd_s {
	void *pData;
	unsigned int ulMagicNum;
	struct ptrIArry_nd_s *pNext;
	struct ptrIArry_nd_s *pPrev;
} ptrIArry_nd_t;

typedef struct ptrIArry_tbl_s {
	ptrIArry_nd_t *pHead;
	ptrIArry_nd_t *pBase;
	unsigned int nr_entries;
	unsigned int ulMagicNum;
	spinlock_t  tblLock;
	bool bLock;
} ptrIArry_tbl_t;
void ptrIArray_setup(ptrIArry_tbl_t *,  ptrIArry_nd_t *, unsigned int, bool);
extern void ptrIArray_cleanup(ptrIArry_tbl_t *pTable);
unsigned int ptrIArray_addInGivenIndex(ptrIArry_tbl_t *pTable,
				       void *pData,
				       unsigned ulIndex,
				       unsigned ulMagicNumber);

static inline ptrIArry_nd_t *ptrIArray_getIndex(ptrIArry_tbl_t *pTable, void *pData, unsigned ulIndex)
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
	} else {
		pNode = NULL;
	}
	if (pTable->bLock)
		spin_unlock_bh(&pTable->tblLock);

	return pNode;
}
static inline unsigned int ptrIArray_add(ptrIArry_tbl_t *pTable,  void *pData)
{
	unsigned int ulIndex;
	ptrIArry_nd_t *pNode;

	if (pTable->bLock)
		spin_lock_bh(&pTable->tblLock);
	if (pTable->pHead == NULL) {
		pNode = NULL;
	} else {
		pNode = pTable->pHead;
		pTable->pHead = pTable->pHead->pNext;
		if (pTable->pHead)
			pTable->pHead->pPrev = NULL;

	}
	if (pTable->bLock)
		spin_unlock_bh(&pTable->tblLock);

	if (pNode) {
		pNode->pNext = NULL;
		pNode->pPrev = NULL;
		pNode->pData = pData;
		pTable->ulMagicNum = (pTable->ulMagicNum + 1) == 0 ? 1 :  pTable->ulMagicNum+1;
		pNode->ulMagicNum = pTable->ulMagicNum;
		ulIndex = pNode - pTable->pBase;
		smp_wmb();
	} else {
		ulIndex = pTable->nr_entries+1;
	}

#ifdef ASF_PARRY_DEBUG
	printk("ptrIArray_add : Index =%d, pNode = 0x%x, pTable->pBase = 0x%x\r\n", ulIndex, pNode, pTable->pBase);
#endif

	return ulIndex;
}


static inline void *ptrIArray_getData(ptrIArry_tbl_t *pTable, unsigned int ulIndex)
{
	return pTable->pBase[ulIndex].pData;
}

static inline unsigned int ptrIArray_getMagicNum(ptrIArry_tbl_t *pTable, unsigned int ulIndex)
{
	return pTable->pBase[ulIndex].ulMagicNum;
}
static inline void ptrIArray_delete(ptrIArry_tbl_t *pTable, unsigned int ulIndex,
				    void (*func)(struct rcu_head *rcu))
{
	ptrIArry_nd_t *pNode = &(pTable->pBase[ulIndex]);
	struct rcu_head *pData;


	pNode->ulMagicNum = 0;
	pData = pNode->pData;
	pNode->pData = NULL;

	smp_wmb();

	if (pTable->bLock)
		spin_lock_bh(&pTable->tblLock);
	if (pTable->pHead) {
		pNode->pNext = pTable->pHead;
		pTable->pHead->pPrev = pNode;
	}
	pTable->pHead = pNode;
	if (pTable->bLock)
		spin_unlock_bh(&pTable->tblLock);

	call_rcu(pData,  func);

}
#endif
