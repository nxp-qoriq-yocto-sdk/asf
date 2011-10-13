/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwd_pvt.h
 *
 * Description: Header file for ASF IPv4 Forwarding internel
 * structure Definations.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/*
 * History
 *  Version     Date         	Author			Change Description
 *  1.0 		10 Nov 2010	Sachin Saxena
 *
 */
/****************************************************************************/

#ifndef __ASFFWD_PVT_H
#define __ASFFWD_PVT_H


#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfipsec.h"
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/asfpvt.h"
#include "../../asfffp/driver/asffwd.h"
#include "asffwdapi.h"


#define FWD_HINDEX(hval) ASF_HINDEX(hval, fwd_hash_buckets)
#define ASF_FWD_FLUSH_TIMER_EXPIRE	jiffies

#define ASF_FWD_BLOB_TIME_INTERVAL 1	/* inter bucket gap */
#define ASF_FWD_EXPIRY_TIME_INTERVAL 1	/* inter bucket gap */
#define	ASF_FWD_NUM_RQ_ENTRIES	(256)
#define ASF_FWD_AUTOMODE_FLOW_INACTIME	(300)
#define ASF_FWD_MIN_PER_CORE_EXP_TIMER	4

#define entry_list_for_each(pos, head) \
	for (pos = (head)->pNext; prefetch(pos->pNext), pos != (head); \
		pos = pos->pNext)



/************ Forwading Cache Table data structure *****/
typedef struct fwd_cache_s {
	/* Must be first entries in this structure to enable circular list */
	struct rcu_head		rcu;
	struct fwd_cache_s	*pPrev;
	struct fwd_cache_s	*pNext;

	ASF_uint32_t	ulVsgId;
	ASF_IPv4Addr_t	ulSrcIp; /* Source IP Address */
	ASF_IPv4Addr_t	ulDestIp; /* Destination IP Address */
	ASF_uint8_t	ucDscp; /* DSCP Value */
	ASF_void_t	*as_cache_info;

	struct fwd_cache_s	*aPrev; /* Previous Node in Aging list */
	struct fwd_cache_s	*aNext; /* Next Node in Aging list */
	void			*bkt; /* Bucket to which its belong */

	/* bDeleted ---  indicate cache entry marked to be deleted */
	/* bVLAN, bPPPoE ---  indicate VLAN & PPPoE typr entry */
	unsigned short		bVLAN:1, bPPPoE:1, bDeleted:1;
	unsigned char		bHeap;
	unsigned short		pmtu;
	struct net_device       *odev;
	unsigned char		l2blob[ASF_MAX_L2BLOB_LEN];
	unsigned short		l2blob_len;
	unsigned short		tx_vlan_id; /*valid if bVLAN is 1*/
	ASFFWDCacheEntryStats_t stats;
#ifdef ASF_FFP_XTRA_STATS
	ASFFFPXtraFlowStats_t   xstats;
#endif
	/* time in jiffies */
	unsigned long	ulInacTime;
	/* Jiffies at which last packet was seen */
	unsigned long	ulLastPktInAt;
	asfTmr_t	*pL2blobTmr;
} fwd_cache_t;


/* This structure is mapped to fwd_cache_t structure to maintain circular list.
 * So first two entries pPrev and pNext must be at the beginning
 * of both structures.
 */
typedef struct fwd_bucket_s {
	/* Must be first two entries in this structure
	to enable circular list */
	struct rcu_head	rcu;
	fwd_cache_t	*pPrev;
	fwd_cache_t	*pNext;
	spinlock_t	lock;
} fwd_bucket_t;


typedef struct fwd_aging_s {
	/* First and Most Recently used Node in Aging list */
	struct fwd_cache_s	*pHead;
	/* Last and Least Recently used Node in Aging list */
	struct fwd_cache_s	*pTail;
	asfTmr_t		*pInacRefreshTmr;
	struct timer_list	flush_timer;
} fwd_aging_t;


/* Extern declarations */
extern bool fwd_aging_enable;
extern int fwd_expiry_timeout;
extern int fwd_l2blob_refresh_npkts;
extern int fwd_l2blob_refresh_interval;
extern int fwd_max_entry;
extern fwd_bucket_t *fwd_cache_table;
extern int asf_fwd_register_proc(void);
extern int asf_fwd_unregister_proc(void);
extern int fwd_hash_buckets;
extern fwd_bucket_t *fwd_cache_table;
extern struct proc_dir_entry *asf_dir;
extern struct ctl_table_header *asf_proc_header;

#endif
