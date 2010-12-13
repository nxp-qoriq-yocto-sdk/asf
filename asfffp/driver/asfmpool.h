/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
 ***************************************************************************/
/*
 * File:	asfmpool.h
 *
 * Description: Memory Pools routine defination for ASF
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/
#ifndef _ASF_MPOOL_H
#define _ASF_MPOOL_H

int asfInitPools(void);
int asfDeInitPools(void);
int asfCreatePool(char *name, unsigned int ulNumGlobalPoolEntries,
	unsigned int ulNumMaxEntries, unsigned int ulPerCoreEntries,
	unsigned int ulDataSize, unsigned int *numPoolId);
int asfDestroyPool(unsigned int ulNumPoolId);
void *asfGetNode(unsigned int ulNumPoolId,  char *bHeap);
void asfReleaseNode(unsigned int ulNumPoolId, void *data, char bHeap);

#endif
