/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwd.h
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/* History
*  Version	Date		Author		Change Description
*
*/
/******************************************************************************/

#ifndef __ASFFWD_H
#define __ASFFWD_H

typedef void (*ASFFWDProcessPkt_f)(
	ASF_uint32_t	ulVsgId,
	ASF_uint32_t	ulCommonInterfaceId,
	ASFBuffer_t	Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t	*freeArg
);
typedef void (*ASFFWDCleanVsg_f)(
	ASF_uint32_t	ulVsgId
);

void ASFFFPRegisterFWDFunctions(
		ASFFWDProcessPkt_f pFwdProcessPkt,
		ASFFWDCleanVsg_f pCleanVsg);

#endif
