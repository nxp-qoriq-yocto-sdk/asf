/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
 ***************************************************************************/
/*
 * File:	ipseccmn.h
 * Description: Contains the macros, type defintions and other common
 * functions for IPsec fast path
 * Authors:	Sandeep Malik <B02416@freescale.com>
 *
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

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
