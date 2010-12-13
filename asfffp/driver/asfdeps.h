/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
 ***************************************************************************/
/*
 * File:	asfdeps.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
*  Version	Date		Author		Change Description
*
*/
/******************************************************************************/

#ifndef __ASF_DEPS_H
#define __ASF_DEPS_H

#include <linux/kernel.h>
#include <linux/skbuff.h>

/** External Dependencies */
#ifdef CONFIG_GFAR_USE_L2SRAM
#define GFAR_SRAM_PBASE 0xf0000000

#define ASF_SRAM_BASE ((unsigned long)GFAR_SRAM_PBASE + (36*1024))

#define ASF_MPOOL_USE_SRAM
#define ASF_FFP_USE_SRAM


#define ASF_MPOOL_SRAM_BASE	(ASF_SRAM_BASE)
#define ASF_MPOOL_SRAM_SIZE	(1920)
#define ASF_FFP_SRAM_BASE	(ASF_MPOOL_SRAM_BASE+ASF_MPOOL_SRAM_SIZE)

#endif

#endif
