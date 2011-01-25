/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfipsec.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
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
