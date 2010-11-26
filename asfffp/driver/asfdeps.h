/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfdeps.h
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