/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
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

extern struct net_device *ASFFFPGetDeviceInterface(ASF_uint32_t ulDeviceId);

extern int ulMaxVSGs_g;
extern int ulMaxTunnels_g;
extern int ulMaxSPDContainers_g;
extern int ulMaxSupportedIPSecSAs_g ;
extern int usMaxInSAHashTaleSize_g;
extern int ulL2BlobRefreshPktCnt_g;
extern int ulL2BlobRefreshTimeInSec_g;
extern int bFirewallCoExistence_g;
extern int bTightlyIntegrated_g;
extern ASFIPSecGlobalErrorCounters_t GlobalErrors;
extern AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats_g;
extern AsfIPSec4GlobalPPStats_t IPSec4GblPPStats_g;
extern ASFIPSecCbFn_t	ASFIPSecCbFn;

extern SecTunnelIface_t **secFP_TunnelIfaces;
extern ptrIArry_tbl_t secfp_OutDB;
extern ptrIArry_tbl_t secfp_InDB;
extern ptrIArry_tbl_t secFP_OutSATable;
extern inSAList_t *secFP_SPIHashTable;
extern spinlock_t secfp_TunnelIfaceCIIndexListLock;

extern unsigned int *pulVSGMagicNumber;
extern unsigned int *pulVSGL2blobMagicNumber;
extern unsigned int **pulTunnelMagicNumber;
extern unsigned int ulTimeStamp_g;

#define ASFIPSEC_ERR	asf_err
#define ASFIPSEC_DPERR asf_dperr

/* use this to selectively enable debug prints */
#ifdef ASF_IPSEC_DEBUG
#define ASFIPSEC_PRINT	asf_print
#define ASFIPSEC_WARN	asf_warn
#define ASFIPSEC_DEBUG	asf_debug
#define ASFIPSEC_DBGL2	asf_debug_l2

#define ASFIPSEC_TRACE	asf_trace
#define ASFIPSEC_FENTRY	asf_fentry
#define ASFIPSEC_FEXIT	asf_fexit
#else

#define ASFIPSEC_PRINT(fmt, arg...)
#define ASFIPSEC_WARN(fmt, arg...)
#define ASFIPSEC_DEBUG(fmt, arg...)
#define ASFIPSEC_DBGL2(fmt, arg...)

#define ASFIPSEC_TRACE
#define ASFIPSEC_FENTRY
#define ASFIPSEC_FEXIT
#endif

#ifdef ASFIPSEC_DEBUG_FRAME
#define ASFIPSEC_FPRINT asf_print
#define ASFIPSEC_HEXDUMP(data, len) {hexdump(data, len); ASFIPSEC_DEBUG(""); }
#else
#define ASFIPSEC_HEXDUMP(data, len)
#define ASFIPSEC_FPRINT(fmt, arg...)
#endif
#ifdef CONFIG_ASF_SEC3x
#define DESC_HDR_LO_ICCR0_MASK cpu_to_be32(0x18000000)
#define DESC_HDR_LO_ICCR0_PASS cpu_to_be32(0x08000000)
#define DESC_HDR_LO_ICCR0_FAIL cpu_to_be32(0x10000000)
#define DESC_HDR_MODE0_AES_XCBC_MAC cpu_to_be32(0x08400000)
#define DESC_HDR_MODE0_AES_XCBC_CICV cpu_to_be32(0x02000000)
#define DESC_HDR_MODE0_AES_CTR cpu_to_be32(0x00600000)
#define DESC_HDR_MODE0_MDEU_CICV cpu_to_be32(0x04000000)
#define DESC_HDR_TYPE_AESU_CTR_HMAC cpu_to_be32(3 << 6)
#endif

#endif
