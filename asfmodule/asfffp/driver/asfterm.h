/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfterm.h
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/* History
*  Version	Date		Author		Change Description
*
*/
/******************************************************************************/

#ifndef __ASFTERM_H
#define __ASFTERM_H

typedef void (*ASFTERMProcessPkt_f)(
	ASF_uint32_t	ulVsgId,
	ASF_uint32_t	ulCommonInterfaceId,
	ASFBuffer_t	Buffer,
	genericFreeFn_t	pFreeFn,
	ASF_void_t	*freeArg,
	ASF_void_t	*pIpsecOpaque,
	ASF_boolean_t	sendOut
);

typedef void (*ASFTERMCleanVsg_f)(
	ASF_uint32_t	ulVsgId
);

void ASFFFPRegisterTERMFunctions(
		ASFTERMProcessPkt_f pTermProcessPkt,
		ASFTERMCleanVsg_f pCleanVsg);

#endif
