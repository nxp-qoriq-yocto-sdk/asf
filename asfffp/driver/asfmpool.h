/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfmpool.h
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
/******************************************************************************/


/******************************************************************************
 * File Name : asfmpool.h
 * Description: Contains the macros, type defintions, exported and imported functions for
 * IPsec fast path
 * Version  : 0.1
 * Author : Subha
 * Date : October 2009
 ******************************************************************************/
/*******************Include files ************************************************/
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
