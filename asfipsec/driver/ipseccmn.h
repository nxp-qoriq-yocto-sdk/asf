/* Copyright (C) 2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	ipseccmn.h
 *
 * Authors:	Sandeep Malik <B02416@freescale.com>
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
/******************************************************************************
 * File Name : ipsecmn.h
 * Description: Contains the macros, type defintions, exported and imported
 * functions for IPsec fast path
 * Version  : 0.1
 * Author : Sandeep Malik
 * Date : October 2010
 ******************************************************************************/
/*******************Include files *********************************************/

#ifndef __IPSEC_CMN_H_
#define __IPSEC_CMN_H_
extern int secfp_talitos_submit(struct device *dev, struct talitos_desc *desc,
		 void (*callback)(struct device *dev, struct talitos_desc *desc,
		void *context, int err), void *context);

extern struct net_device  *ASFFFPGetDeviceInterface(ASF_uint32_t ulDeviceId);
extern int secfp_rng_read_data(unsigned int *ptr);
extern struct device *talitos_getdevice(void);

extern int ulMaxVSGs_g;
extern int ulMaxTunnels_g;
extern int ulMaxSPDContainers_g;
extern int ulMaxSupportedIPSecSAs_g ;
extern int usMaxInSAHashTaleSize_g;
extern int ulL2BlobRefreshPktCnt_g;
extern int ulL2BlobRefreshTimeInSec_g;
extern int bFirewallCoExistence_g;
extern int bTightlyIntegrated_g;
extern ASFIPSecGlobalErrorCounters_t  GlobalErrors;
extern AsfIPSecPPGlobalStats_t IPSecPPGlobalStats_g[NR_CPUS];

extern ASFIPSecCbFn_t	ASFIPSecCbFn;

extern SecTunnelIface_t **secFP_TunnelIfaces;
extern ptrIArry_tbl_t secfp_OutDB;
extern ptrIArry_tbl_t secfp_InDB;
extern ptrIArry_tbl_t secFP_OutSATable;
extern inSAList_t *secFP_SPIHashTable;

#endif
