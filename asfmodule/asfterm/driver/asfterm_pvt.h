/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfterm_pvt.h
 *
 * Description: Header file for ASF IP Termination internel
 * structure Definations.
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/*
 * History
 * Version	Date		Author			Change Description
 * 1.0	        12 April 2011	Hemant Agarwal		Initial version
 *
 */
/****************************************************************************/

#ifndef __ASFTERM_PVT_H
#define __ASFTERM_PVT_H


#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfipsec.h"
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/asfpvt.h"
#include "../../asfffp/driver/asfterm.h"
#include "asftermapi.h"


#define TERM_HINDEX(hval) ASF_HINDEX(hval, term_hash_buckets)
#define ASF_TERM_FLUSH_TIMER_EXPIRE	jiffies

#define ASF_TERM_BLOB_TIME_INTERVAL 1	/* inter bucket gap */
#define ASF_TERM_BLOB_TIMER_BUCKT 500	/* Max L2blob refresh timer value */
#define ASF_TERM_EXPIRY_TIME_INTERVAL 1	/* inter bucket gap */
#define ASF_TERM_EXPIRY_TIMER_BUCKT 500	/* Max flow expiry timer value */
#define	ASF_TERM_NUM_RQ_ENTRIES	(256)
#define ASF_TERM_AUTOMODE_FLOW_INACTIME	(300)
#define ASF_TERM_MIN_PER_CORE_EXP_TIMER	4

typedef struct ASFTermCacheId_s {

	unsigned long ulArg1;	/* Flow Index */
	unsigned long ulArg2;	/* Flow Magic Number */

} ASFTermCacheId_t;

#define entry_list_for_each(pos, head) \
	for (pos = (head)->pNext; prefetch(pos->pNext), pos != (head); \
		pos = pos->pNext)



/************ Forwading Cache Table data structure *****/
typedef struct term_cache_s {
	/* Must be first entries in this structure to enable circular list */
	struct rcu_head		rcu;
	struct term_cache_s	*pPrev;
	struct term_cache_s	*pNext;

	ASF_uint32_t	ulVsgId;
	ASF_IPv4Addr_t	ulSrcIp; /* Source IP Address */
	ASF_IPv4Addr_t	ulDestIp; /* Destination IP Address */
	ASF_uint32_t	ulPorts; /* Source Port and Destination Port */
	ASF_uint8_t	ucProtocol; /* IP Protocol */
	ASF_uint8_t	ucSubProtocolOffset; /* SubProtocol Offset in Packet */
	ASF_uint16_t	ucSubProtocol; /*SubProtocol Id */

	ASF_void_t	*as_cache_info;

	void			*bkt; /* Bucket to which its belong */

	/* bDeleted ---  indicate cache entry marked to be deleted */
	/* bVLAN, bPPPoE ---  indicate VLAN & PPPoE typr entry */
	ASF_uint32_t		bVLAN:1, bPPPoE:1, bDeleted:1,
				bIPsecIn:1, bIPsecOut:1, bLocalTerm:1;
	ASFFFPConfigIdentity_t	configIdentity;
	ASFFFPIpsecInfo_t	ipsecInfo;
	unsigned char		bHeap;
	unsigned short		pmtu;
	struct net_device	*odev;
	unsigned char		l2blob[ASF_MAX_L2BLOB_LEN];
	unsigned short		l2blob_len;
	unsigned short		tx_vlan_id; /*valid if bVLAN is 1*/
	ASFTERMCacheEntryStats_t stats;
#ifdef ASF_TERM_XTRA_STATS
	ASFFFPXtraFlowStats_t	xstats;
#endif
	/* time in jiffies */
	unsigned long	ulInacTime;
	/* Jiffies at which last packet was seen */
	unsigned long	ulLastPktInAt;
	asfTmr_t	*pL2blobTmr;
	asfTmr_t	*pInacRefreshTmr;
	ASFFFPFlowId_t	id;
	ASFFFPFlowId_t	other_id;
} term_cache_t;


/* This structure is mapped to term_cache_t structure to maintain circular list.
 * So first two entries pPrev and pNext must be at the beginning
 * of both structures.
 */
typedef struct term_bucket_s {
	/* Must be first two entries in this structure
	to enable circular list */
	struct rcu_head	rcu;
	term_cache_t	*pPrev;
	term_cache_t	*pNext;
	spinlock_t	lock;
} term_bucket_t;


/* Extern declarations */
extern bool term_aging_enable;
extern int term_l2blob_refresh_npkts;
extern int term_l2blob_refresh_interval;
extern int term_max_entry;
extern term_bucket_t *term_cache_table;
extern int asf_term_register_proc(void);
extern int asf_term_unregister_proc(void);
extern int term_hash_buckets;
extern struct proc_dir_entry *asf_dir;
extern struct ctl_table_header *asf_proc_header;

#endif
