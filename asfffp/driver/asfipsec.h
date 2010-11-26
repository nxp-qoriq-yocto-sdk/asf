/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfipsec.h
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


#ifndef __ASFIPSAPI_H
#define __ASFIPSAPI_H


typedef int (*ASFFFPIPSecInv4_f)(struct sk_buff *skb,
				 ASF_boolean_t bCheckLen, unsigned int ulVSGId , ASF_uint32_t ulCommonInterfaceId);

typedef int (*ASFFFPIPSecOutv4_f)(
				 unsigned int ulVSGId,
				 struct sk_buff *skb, ASFFFPIpsecInfo_t *pSecInfo);

typedef int (*ASFFFPIPSecInVerifyV4_f)(
				      unsigned int pVSGId,
				      struct sk_buff *skb, ASF_uint32_t ulCommonInterfaceId,  ASFFFPIpsecInfo_t *pSecInfo, void *pIpsecOpq);

typedef int (*ASFFFPIPSecProcessPkt_f)(
	ASF_uint32_t	ulVsgId,
	ASF_uint32_t	ulCommonInterfaceId,
	ASFBuffer_t	Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t	*freeArg
);

void ASFFFPRegisterIPSecFunctions(ASFFFPIPSecInv4_f   pIn,
				ASFFFPIPSecOutv4_f  pOut,
				ASFFFPIPSecInVerifyV4_f pIpsecInVerify,
				ASFFFPIPSecProcessPkt_f pIpsecProcess);
#endif
