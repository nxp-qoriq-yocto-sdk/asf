/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asffwd.h
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
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
