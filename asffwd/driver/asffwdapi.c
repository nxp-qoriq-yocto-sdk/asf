/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwdapi.c
 *
 * Description: ASF Forwarding module for IPv4 forwarding
 * Initialization and Handling.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/*
 * History
 *  Version     Date         	Author			Change Description *
 *  1.0		22 Sep 2010   Sachin Saxena 	IPv4 forwarding Support Added
 */
 /****************************************************************************/

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <net/xfrm.h>
#include "asffwd_pvt.h"


#define ASF_FWD_VERSION	"1.0.0"
#define ASF_FWD_DESC 	"ASF Forwarding Component"
/** \brief	Driver's license
 *  \details	GPL
 *  \ingroup	Linux_module
 */
MODULE_LICENSE("GPL");
/** \brief	Module author
 *  \ingroup	Linux_module
 */
MODULE_AUTHOR("Freescale Semiconductor, Inc");
/** \brief	Module description
 *  \ingroup	Linux_module
 */
MODULE_DESCRIPTION(ASF_FWD_DESC);
char *asf_fwd_version = ASF_FWD_VERSION;

/* Initilization Parameters */
int fwd_aging_enable = 1; /* Enable */
int fwd_max_entry = 8*1024;
int fwd_expiry_timeout = 180; /* in sec */
int fwd_max_vsgs = ASF_MAX_VSGS;
int fwd_max_ifaces = ASF_MAX_IFACES;
int fwd_hash_buckets = 8*1024;
int fwd_l2blob_refresh_npkts = ASF_MAX_L2BLOB_REFRESH_PKT_CNT;
int fwd_l2blob_refresh_interval = ASF_MAX_L2BLOB_REFRESH_TIME;

module_param(fwd_aging_enable, int, 0644);
MODULE_PARM_DESC(fwd_aging_enable, "Enable / Disable Aging.");
module_param(fwd_expiry_timeout, int, 0644);
MODULE_PARM_DESC(fwd_expiry_timeout, "Expiry Timeout for Route Cache Entry");
module_param(fwd_l2blob_refresh_npkts, int, 0644);
MODULE_PARM_DESC(fwd_l2blob_refresh_npkts, "Number of packets after which"\
							"L2 blob required");
module_param(fwd_l2blob_refresh_interval, int, 0644);
MODULE_PARM_DESC(fwd_l2blob_refresh_interval, "Time interval after which"\
							"L2 blob required");
module_param(fwd_hash_buckets, int, 0444);
MODULE_PARM_DESC(fwd_hash_buckets, "Maximum number of buckets"\
						" in FWD Hash table");

module_param(fwd_max_entry, int, 0444);
MODULE_PARM_DESC(fwd_max_entry, "Maximum number of FWD flow entries");

static volatile unsigned int  fwd_cur_entry_count;
spinlock_t	fwd_entry_count_lock;
static unsigned int  fwd_cache_pool_id = -1;
static unsigned int  fwd_blob_timer_pool_id = -1;
static unsigned int  fwd_expiry_timer_pool_id = -1;

/* Forwarding table gobal pointer */
fwd_bucket_t	*fwd_cache_table;
fwd_aging_t	**fwd_aging_table;

/* Statistics */
ASFFFPGlobalStats_t	*asf_gstats; /* per cpu global stats */
ASFFFPVsgStats_t	*asf_vsg_stats; /* per cpu vsg stats */

ASF_boolean_t	asf_fwd_notify = ASF_FALSE;
static ASFFWDCallbackFns_t	fwdCbFns = {0};
unsigned long asf_fwd_hash_init_value;


/** Local functions */
static int fwd_cmd_create_entry(ASF_uint32_t  ulVsgId,
				ASFFWDCreateCacheEntry_t *p,
				fwd_cache_t **pFlow,
				unsigned long *pHashVal);
static int fwd_cmd_delete_entry(ASF_uint32_t  ulVsgId,
				ASFFWDDeleteCacheEntry_t *p,
				unsigned long *pHashVal,
				ASFFWDCacheEntryStats_t  *stats);
static int fwd_cmd_update_cache(ASF_uint32_t ulVsgId,
				ASFFWDUpdateCacheEntry_t *p);
static void ASFFWDCleanVsg(ASF_uint32_t ulVsgId);



static inline void fwd_copy_cache_stats(fwd_cache_t *cache,
					ASFFWDCacheEntryStats_t *stats)
{
	if (cache) {
		stats->ulInPkts = htonl(cache->stats.ulInPkts);
		stats->ulOutPkts = htonl(cache->stats.ulOutPkts);
		stats->ulInBytes = htonl(cache->stats.ulInBytes);
		stats->ulOutBytes = htonl(cache->stats.ulOutBytes);
	} else
		memset(stats, 0, sizeof(*stats));
}
static inline fwd_cache_t *fwd_cache_alloc(void)
{
	char		bHeap;
	fwd_cache_t	*Cache;
	ASFFFPGlobalStats_t *gstats;

	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());

	Cache = (fwd_cache_t *) asfGetNode(fwd_cache_pool_id, &bHeap);
	if (Cache) {
		gstats->ulFlowAllocs++;
		Cache->bHeap = bHeap;
	} else
		gstats->ulFlowAllocFailures++;

	return Cache;
}

static inline void fwd_cache_free(fwd_cache_t *Cache)
{
	ASFFFPGlobalStats_t	*gstats;

	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	asfReleaseNode(fwd_cache_pool_id, Cache, Cache->bHeap);
	gstats->ulFlowFrees++;
}

static inline void asf_fwd_cache_insert(fwd_cache_t *Cache, fwd_bucket_t *bkt)
{
	fwd_cache_t *head, *temp;

	head = (fwd_cache_t *) bkt;
	spin_lock_bh(&bkt->lock);
	temp = Cache->pNext = head->pNext;
	Cache->pPrev = head;
	rcu_assign_pointer(head->pNext, Cache);
	temp->pPrev = Cache;
	spin_unlock_bh(&bkt->lock);
}

static void fwd_cache_destroy(struct rcu_head *rcu)
{
	fwd_cache_t	*cache = (fwd_cache_t *)rcu;

	asfTimerFreeNodeMemory(cache->pL2blobTmr);
	if (cache->bHeap)
		kfree(cache);
}

static void fwd_cache_free_rcu(struct rcu_head *rcu)
{
	fwd_cache_free((fwd_cache_t *)rcu);
}

/* Note: Caller must hold the spin lock of the bucket */
static inline void __asf_fwd_cache_remove(fwd_cache_t *Cache, fwd_bucket_t *bkt)
{
	Cache->pNext->pPrev = Cache->pPrev;
	Cache->pPrev->pNext = Cache->pNext;
}

static inline fwd_bucket_t *asf_fwd_bucket_by_hash(unsigned long ulHashVal)
{
	return &fwd_cache_table[FWD_HINDEX(ulHashVal)];
}


static inline fwd_cache_t *asf_fwd_entry_lookup_in_bkt(
		unsigned long sip, unsigned long dip,
		unsigned char dscp, unsigned long vsg,
		fwd_cache_t *pHead)
{
	fwd_cache_t	*Cache;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	for (Cache = pHead->pNext; Cache != pHead; Cache = Cache->pNext) {
		if (
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			(Cache->ucDscp == dscp) &&
			(Cache->ulVsgId == vsg) &&
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			(Cache->ulSrcIp == sip) &&
			(Cache->ulDestIp == dip))
				return Cache;
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_print("Max (%u) scanned ... aborting search!\n",
							SEARCH_MAX_PER_BUCKET);
			return NULL;
		}
#endif
	}
	return NULL;
}

static inline fwd_cache_t *asf_fwd_entry_lookup_in_bkt_ex(
						ASFFWDCacheEntryTuple_t *tuple,
						unsigned long ulVsgId,
						fwd_cache_t *pHead)
{
	return asf_fwd_entry_lookup_in_bkt(tuple->ulSrcIp, tuple->ulDestIp,
					tuple->ucDscp, ulVsgId, pHead);
}

static __u32 rule_salt __read_mostly;

static inline unsigned long ASFFWDComputeFlowHash(
			unsigned long ulSrcIp,
			unsigned long ulDestIp,
			unsigned long ulDscp,
			unsigned long ulVsgId,
			unsigned long initval)
{
	ulSrcIp += rule_salt;
	ulDestIp += JHASH_GOLDEN_RATIO;
	ulDscp += initval;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulDscp);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ulSrcIp += ulVsgId;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulDscp);
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	return rule_salt + ulDscp;
}

/*
 * Lookups through the Caches to find matching entry.
 * The argument 'head' is head of circular list (actually bucket ponter).
 */
static inline fwd_cache_t *asf_fwd_entry_lookup(
	unsigned long sip, unsigned long dip, unsigned char dscp,
	unsigned long vsg, unsigned long *pHashVal)
{
	fwd_cache_t *Cache, *pHead;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	*pHashVal = ASFFWDComputeFlowHash(sip, dip, dscp, vsg,
					asf_fwd_hash_init_value);
	asf_print("ASF: Hash(0x%lx, 0x%lx, 0x%x, 0x%lx)"
			" = %lx \n", sip, dip, dscp, vsg, *pHashVal);

	pHead = (fwd_cache_t *) asf_fwd_bucket_by_hash(*pHashVal);

	for (Cache = pHead->pNext; Cache != pHead; Cache = Cache->pNext) {
		if (
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			(Cache->ucDscp == dscp) &&
			(Cache->ulVsgId == vsg) &&
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
			(Cache->ulSrcIp == sip) &&
			(Cache->ulDestIp == dip))
				return Cache;
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_print("Max (%d) scanned in bucket for"
					" hashVal(%ld) ... aborting search!\n",
					SEARCH_MAX_PER_BUCKET, *pHashVal);
			return NULL;
		}
#endif
	}
	return NULL;
}
static inline fwd_cache_t *asf_fwd_entry_lookup_by_tuple(
						ASFFWDCacheEntryTuple_t *tpl,
						unsigned long ulVsgId,
						unsigned long *pHashVal)
{
	return asf_fwd_entry_lookup(tpl->ulSrcIp, tpl->ulDestIp,
				(tpl->ucDscp & IPTOS_RT_MASK),
				ulVsgId, pHashVal);
}

static inline void asfFwdSendLogEx(fwd_cache_t *Cache,
				unsigned long ulMsgId,
				ASF_uchar8_t *aMsg,
				unsigned long ulHashVal)
{
	if (fwdCbFns.pFnAuditLog) {
		ASFLogInfo_t		li;
		li.ulVSGId = Cache->ulVsgId;
		li.ulMsgId = ulMsgId;
		li.aMsg = aMsg;
		li.u.fwdInfo.tuple.ulSrcIp = Cache->ulSrcIp;
		li.u.fwdInfo.tuple.ulDestIp = Cache->ulDestIp;
		/*--- Test next Two lines (for endianness also) ---*/
		li.u.fwdInfo.tuple.ucDscp = Cache->ucDscp;
		li.u.fwdInfo.ulHashVal = ulHashVal;
		fwdCbFns.pFnAuditLog(&li);
	}
}

static inline void asfFwdSendLog(fwd_cache_t *Cache,
				unsigned long ulMsgId,
				unsigned long ulHashVal)
{
	asfFwdSendLogEx(Cache, ulMsgId, (ASF_uchar8_t *)"", ulHashVal);
}

inline void asfFragmentAndSendPkt(fwd_cache_t	*Cache,
				struct sk_buff	*skb,
				struct iphdr	*iph,
				ASFFWDCacheEntryStats_t *cache_stats,
				ASFFFPGlobalStats_t *gstats,
				ASFFFPVsgStats_t *vstats)
{
	struct sk_buff *pSkb, *pTempSkb;
	/* Need to call fragmentation routine */
	asf_print("attempting to fragment and xmit\n");
	if (!asfIpv4Fragment(skb, (Cache->odev->mtu < Cache->pmtu ?
			skb->dev->mtu : Cache->pmtu),
			/*32*/ Cache->l2blob_len,
			0 /* FALSE */, Cache->odev, &pSkb)) {
		int ulFrags = 0;

		for (; pSkb != NULL; pSkb = pTempSkb) {
			ulFrags++;
			pTempSkb = pSkb->next;
			asf_print("Next skb = 0x%p\r\n", pTempSkb);
			pSkb->next = NULL;
			iph = ip_hdr(pSkb);

			pSkb->pkt_type = PACKET_FASTROUTE;
			pSkb->asf = 1;
			if (Cache->bVLAN)
				pSkb->vlan_tci = Cache->tx_vlan_id;

			ip_decrease_ttl(iph);

			pSkb->data -= Cache->l2blob_len;
			pSkb->len += Cache->l2blob_len;

			if (pSkb->data < pSkb->head) {
				asf_err("SKB's head > data ptr... PANIC !!\n");
				ASFSkbFree(pSkb);
				continue;
			}

			pSkb->dev = Cache->odev;
			asfCopyWords((unsigned int *)pSkb->data,
					(unsigned int *)Cache->l2blob,
					Cache->l2blob_len);
			if (Cache->bPPPoE) {
				/* PPPoE packet. Set Payload
				   length in PPPoE header */
				*((short *)&(pSkb->data[Cache->l2blob_len-4])) =
					htons(ntohs(iph->tot_len)+2);
			}

			asf_print("skb->network_header = 0x%p, "
				"skb->transport_header = 0x%p\r\n",
					skb_network_header(pSkb),
					skb_transport_header(pSkb));
			asf_print("Xmiting:  buffer = 0x%p dev->index = %d\r\n",
						pSkb, pSkb->dev->ifindex);
			gstats->ulOutBytes += pSkb->len;
			cache_stats->ulOutBytes += pSkb->len;
			vstats->ulOutBytes += pSkb->len;
			if (asfDevHardXmit(pSkb->dev, pSkb) != 0) {
				asf_warn("Error in Xmit: may happen\r\n");
				ASFSkbFree(pSkb);
			}

		}
		gstats->ulOutPkts += ulFrags;
		vstats->ulOutPkts += ulFrags;
		cache_stats->ulOutPkts += ulFrags;
	} else
		asf_print("asfIpv4Fragment returned NULL!!\n");

	return;
}

ASF_void_t ASFFWDProcessPkt(ASF_uint32_t	ulVsgId,
				ASF_uint32_t	ulCommonInterfaceId,
				ASFBuffer_t	Buffer,
				genericFreeFn_t	pFreeFn,
				ASF_void_t	*freeArg)
{
	fwd_cache_t		*Cache;
	unsigned long		ulHashVal;
	int			bL2blobRefresh = 0;
	struct sk_buff		*skb ;
	struct iphdr		*iph ;
	struct netdev_queue *txq = NULL;
	u16 q_idx = 0;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ASFFFPGlobalStats_t	*gstats;
	ASFFFPVsgStats_t	*vstats;
	ASFFWDCacheEntryStats_t	*cache_stats;


	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id())
							+ ulVsgId;
	vstats->ulInPkts++;
#endif

	skb = (struct sk_buff *) Buffer.nativeBuffer;
	iph = ip_hdr(skb);
	Cache = asf_fwd_entry_lookup(iph->saddr, iph->daddr,
					(iph->tos & IPTOS_RT_MASK),
					ulVsgId, &ulHashVal);
	asf_print("RX: %s SRC:%d.%d.%d.%d, DST:%d.%d.%d.%d, ToS:0x%x \n"
			"VsgId %d\n  Hash 0x%lx, (Cache= 0x%p) => %s\n",
		skb->dev->name, NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
			iph->tos, ulVsgId, ulHashVal, Cache, Cache ?
						"FOUND" : "NOT FOUND");
	if (unlikely(NULL == Cache)) {
		if (fwdCbFns.pFnCacheEntryNotFound) {
			ASFBuffer_t		abuf;
			ASFNetDevEntry_t	*anDev;

			anDev = ASFNetDev(skb->dev);
			abuf.nativeBuffer = skb;
			if (anDev)
				fwdCbFns.pFnCacheEntryNotFound(anDev->ulVSGId,
						anDev->ulCommonInterfaceId,
						abuf,
						ASF_SKB_FREE_FUNC, skb);
			goto exit;
		} else
			goto ret_pkt_to_stk;
	}

	if (likely(iph->ttl > 1)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulInPktFlowMatches++;
		vstats->ulInPktFlowMatches++;

		cache_stats = &Cache->stats;
		cache_stats->ulInPkts++;
		cache_stats->ulInBytes += (skb->mac_len + skb->len);
		/* Mark the Cache as most recently used in aging list */
		if (fwd_aging_enable) {
			int processor_id = smp_processor_id();
			/* Not already at Head and not being deleted */
			if (Cache->aPrev != Cache && !Cache->bDeleted) {
				asf_print("Last: Head[%p]. Next[%p] Tail[%p]\n",
					fwd_aging_table[processor_id]
							[ulVsgId].pHead,
					fwd_aging_table[processor_id]
							[ulVsgId].pHead->aNext,
					fwd_aging_table[processor_id]
							[ulVsgId].pTail);

				Cache->aPrev->aNext = Cache->aNext;
				if (Cache->aNext)
					Cache->aNext->aPrev = Cache->aPrev;
				else /* Last node, adjust Tail also */
					fwd_aging_table[processor_id]
						[ulVsgId].pTail = Cache->aPrev;
				Cache->aNext = fwd_aging_table[processor_id]
								[ulVsgId].pHead;
				Cache->aNext->aPrev = Cache;
				fwd_aging_table[processor_id]
						[ulVsgId].pHead = Cache;
				Cache->aPrev = fwd_aging_table[processor_id]
								[ulVsgId].pHead;

				asf_print("Now: Head[%p]. Next[%p] Tail[%p]\n",
					fwd_aging_table[processor_id]
							[ulVsgId].pHead,
					fwd_aging_table[processor_id]
							[ulVsgId].pHead->aNext,
					fwd_aging_table[processor_id]
							[ulVsgId].pTail);
			}
			Cache->ulLastPktInAt = jiffies;
		}
		/* Handle IP options */
		if (unlikely(iph->ihl > 5)) {
			if (asf_process_ip_options(skb, skb->dev, iph) < 0) {
				gstats->ulErrIpHdr++;
				XGSTATS_INC(IpOptProcFail);
				goto drop_pkt;
			}
		}
#endif
		if (Cache->l2blob_len == 0) {
			asf_print("Generating L2blob Indication"
					" as Blank L2blob found!\n");
			bL2blobRefresh = 1;
			goto gen_indications;
		}
		asf_print("L2blob Info found! out dev %p\n", Cache->odev);

		q_idx = skb_tx_hash(Cache->odev, skb);
		skb_set_queue_mapping(skb, q_idx);
		txq = netdev_get_tx_queue(Cache->odev, q_idx);
		if (0 == netif_tx_queue_stopped(txq)) {
			asf_print("attempting to xmit the packet\n");
			asf_print("----------------------------------------\n");
			asf_print("len = %d,  data_len = %d, mac_len = %d, "
				"hdr_len = %d\n", skb->len, skb->data_len,
						skb->mac_len, skb->hdr_len);
			asf_print("trans_hdr = 0x%p, nw_hdr = 0x%p, "
				"mac_hdr = 0x%p\n", skb->transport_header,
					skb->network_header, skb->mac_header);
			asf_print("head = %p,  data = %p, tail = 0x%p, "
				"end = 0x%p\n", skb->head, skb->data,
						skb->tail, skb->end);
			asf_print("----------------------------------------\n");

			/* Cache->l2blob_len > 0 && Cache->odev != NULL
			from this point onwards */
			if ((((skb->len > Cache->pmtu) &&
				(skb->len + Cache->l2blob_len) >
				(Cache->odev->mtu + ETH_HLEN))) ||
				(skb_shinfo(skb)->frag_list)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				if (iph->frag_off & IP_DF)
					goto ret_pkt_to_stk;

				/* Fragmentation Needed, so do it */
				asfFragmentAndSendPkt(Cache, skb, iph,
						cache_stats, gstats, vstats);
				txq->trans_start = jiffies;
#endif
				goto gen_indications;
			}

			asf_print("decreasing TTL\n");
			ip_decrease_ttl(iph);
			asf_print("attempting to xmit non fragment packet\n");
			skb->dev = Cache->odev;
			/* Ensure there's enough head room for l2blob_len */
			/* Update the MAC address information */
			skb->len += Cache->l2blob_len;
			skb->data -= Cache->l2blob_len;
			asf_print("copy l2blob to packet (blob_len %d)\n",
							Cache->l2blob_len);
			asfCopyWords((unsigned int *)skb->data,
					(unsigned int *)Cache->l2blob,
					Cache->l2blob_len);
			if (Cache->bVLAN)
				skb->vlan_tci = Cache->tx_vlan_id;
			skb->pkt_type = PACKET_FASTROUTE;
			skb->asf = 1;

			asf_print("invoke hard_start_xmit skb-packet"
					" (blob_len %d)\n", Cache->l2blob_len);
			txq->trans_start = jiffies;
			if (0 != asfDevHardXmit(skb->dev, skb)) {
				asf_err("Error in transmit: may happen as "
					"we don't check for gfar free desc\n");
				ASFSkbFree(skb);
			}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulOutBytes += skb->len;
			vstats->ulOutBytes += skb->len;
			cache_stats->ulOutBytes += skb->len;

			gstats->ulOutPkts++;
			vstats->ulOutPkts++;
			cache_stats->ulOutPkts++;
#endif

			return;

gen_indications:
			/* skip all other indications if cache_end indication
			is going to be sent */
			if (unlikely(bL2blobRefresh)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				if (!Cache->bDeleted &&
					fwdCbFns.pFnCacheEntryRefreshL2Blob) {
					ASFFWDCacheEntryL2BlobRefreshCbInfo_t
									ind;

					ind.packetTuple.ulSrcIp =
								Cache->ulSrcIp;
					ind.packetTuple.ulDestIp =
								Cache->ulDestIp;
					ind.packetTuple.ucDscp = Cache->ucDscp;

					ind.ulHashVal = ulHashVal;
					ind.ASFFwdInfo = (ASF_uint8_t *)
						Cache->as_cache_info;
					ind.Buffer.nativeBuffer = NULL;

					fwdCbFns.pFnCacheEntryRefreshL2Blob
								(ulVsgId, &ind);
				}
#endif
				goto ret_pkt_to_stk;
			}
			return;
		} else {
			/* drop the packet here */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			cache_stats->ulInPkts--;
#endif
			goto drop_pkt;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	} else
		gstats->ulErrTTL++;
#else
	} /* End of if (likely(iph->ttl > 1)) */
#endif

	/* Return to Slow path for further handling */
ret_pkt_to_stk:
	netif_receive_skb(skb);

exit:
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	return;

drop_pkt:
	asf_print("drop_pkt LABEL\n");
	dev_kfree_skb_any(skb);
	return;
}
EXPORT_SYMBOL(ASFFWDProcessPkt);

ASF_void_t  ASFFWDGetCapabilities(ASFFWDCap_t *pCap)
{
	pCap->ulMaxVSGs = fwd_max_vsgs;
	pCap->bBufferHomogenous = ASF_TRUE;
	pCap->bHomogenousHashAlgorithm = ASF_TRUE;
	pCap->ulHashAlgoInitVal = asf_fwd_hash_init_value;
	pCap->ulMaxCacheEntries = fwd_max_entry;
}
EXPORT_SYMBOL(ASFFWDGetCapabilities);


ASF_void_t  ASFFWDSetNotifyPreference(ASF_boolean_t bEnable)
{
	asf_fwd_notify = bEnable;
}
EXPORT_SYMBOL(ASFFWDSetNotifyPreference);


#ifdef ASF_DEBUG
static char *cmdStrs[10] = {
		/* 0 */ "DMY",
		/* 1 */ "CREATE_CACHE_ENTRY",
		/* 2 */ "UPDATE_CACHE_ENTRY",
		/* 3 */ "DELETE_CACHE_ENTRY",
		/* 4 */ "FLUSH_CACHE_TABLE"
	};
#define cmd2Str(cmd) ((cmd <= 4) ? cmdStrs[cmd] : "INVALID")
#endif

ASF_uint32_t ASFFWDRuntime(
			ASF_uint32_t  ulVsgId,
			ASF_uint32_t  cmd,
			ASF_void_t    *args,
			ASF_uint32_t  ulArgslen,
			ASF_void_t    *pReqIdentifier,
			ASF_uint32_t  ulReqIdentifierlen)
{
	int iResult = ASFFWD_RESPONSE_FAILURE;

	asf_print("vsg %u cmd %s (%u) arg_len %u reqid_len %u"
			" (notify %d) \n",
			ulVsgId, cmd2Str(cmd), cmd,
			ulArgslen, ulReqIdentifierlen,
			asf_fwd_notify);

	/* invalid mode - avoid creation of Caches */
	if (!ASFGetStatus()) {
		asf_print("ASF is DISABLED\n");
		return ASFFWD_RESPONSE_FAILURE;
	}
	if (!asf_ffp_check_vsg_mode(ulVsgId, fwdMode))
		return ASFFWD_RESPONSE_FAILURE;

	switch (cmd) {
	case ASF_FWD_CREATE_CACHE_ENTRY:
	{
		unsigned long ulHashVal = 0;
		ASFFWDCreateCacheEntryResp_t	resp;


		if (ulVsgId < fwd_max_vsgs)
			iResult = fwd_cmd_create_entry(ulVsgId,
					(ASFFWDCreateCacheEntry_t *)args,
					NULL, &ulHashVal);
		else
			iResult = ASFFWD_RESPONSE_FAILURE;

		if ((asf_fwd_notify == ASF_TRUE) && fwdCbFns.pFnRuntime) {
			memcpy(&resp.tuple, &((ASFFWDCreateCacheEntry_t *)
				args)->CacheEntry.tuple, sizeof(resp.tuple));

			resp.ulHashVal = ulHashVal;
			resp.iResult = iResult;
			fwdCbFns.pFnRuntime(ulVsgId, cmd, pReqIdentifier,
				ulReqIdentifierlen, &resp, sizeof(resp));
		}
	}
	break;

	case ASF_FWD_DELETE_CACHE_ENTRY:
	{
		unsigned long ulHashVal = 0;
		ASFFWDDeleteCacheEntryResp_t resp;

		if (ulVsgId < fwd_max_vsgs)
			iResult = fwd_cmd_delete_entry(ulVsgId,
				(ASFFWDDeleteCacheEntry_t *)args,
				&ulHashVal, &resp.stats);

		if ((asf_fwd_notify == ASF_TRUE)  && fwdCbFns.pFnRuntime) {
			memcpy(&resp.tuple,
				&((ASFFWDDeleteCacheEntry_t *)args)->tuple,
				sizeof(resp.tuple));

			resp.ulHashVal = ulHashVal;
			resp.iResult = (iResult == 0) ?
					ASFFWD_RESPONSE_SUCCESS :
					ASFFWD_RESPONSE_FAILURE;
			resp.ASFFwdInfo = NULL;

			fwdCbFns.pFnRuntime(ulVsgId, cmd, pReqIdentifier,
				ulReqIdentifierlen, &resp, sizeof(resp));
			}
	}
	break;

	case ASF_FWD_UPDATE_CACHE_ENTRY:
	{
		if (ulVsgId < fwd_max_vsgs)
			iResult = fwd_cmd_update_cache(ulVsgId,
				(ASFFWDUpdateCacheEntry_t *)args);

		asf_print("mod_entry iResult %d (vsg %d) "
			"max_vsg %d\n", iResult, ulVsgId, fwd_max_vsgs);
		/* No confirmation sent to AS ?? */
	}
	break;

	case ASF_FWD_FLUSH_CACHE_TABLE:
		ASFFWDCleanVsg(ulVsgId);
	break;

	default:
		return ASFFWD_RESPONSE_FAILURE;
	}
	asf_print("vsg %u cmd %s (%d)  - result %d\n", ulVsgId, cmd2Str(cmd),
								cmd, iResult);
	return iResult;
}
EXPORT_SYMBOL(ASFFWDRuntime);

ASF_void_t ASFFWDRegisterCallbackFns(ASFFWDCallbackFns_t *pFnList)
{
	fwdCbFns.pFnInterfaceNotFound = pFnList->pFnInterfaceNotFound;
	fwdCbFns.pFnVSGMappingNotFound = pFnList->pFnVSGMappingNotFound;
	fwdCbFns.pFnCacheEntryNotFound = pFnList->pFnCacheEntryNotFound;
	fwdCbFns.pFnRuntime = pFnList->pFnRuntime;
	fwdCbFns.pFnCacheEntryExpiry = pFnList->pFnCacheEntryExpiry;
	fwdCbFns.pFnCacheEntryRefreshL2Blob =
				pFnList->pFnCacheEntryRefreshL2Blob;
	fwdCbFns.pFnAuditLog = pFnList->pFnAuditLog;
	asf_print("Register AS response cbk 0x%p\n", fwdCbFns.pFnRuntime);
}
EXPORT_SYMBOL(ASFFWDRegisterCallbackFns);

ASF_uint32_t  ASFFWDSetCacheEntryExpiryParams(ASFFWDExpiryParams_t *pInfo)
{
	fwd_expiry_timeout = pInfo->ulExpiryInterval;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFFWDSetCacheEntryExpiryParams);


/* NEW API END */
static inline int fwd_entry_copy_info(ASFFWDCacheEntry_t *pInfo,
							fwd_cache_t *Cache)
{
	Cache->ulSrcIp = pInfo->tuple.ulSrcIp;
	Cache->ulDestIp = pInfo->tuple.ulDestIp;
	Cache->ucDscp = (pInfo->tuple.ucDscp & IPTOS_RT_MASK);
	Cache->ulInacTime = pInfo->ulExpTimeout;

	return ASFFWD_RESPONSE_SUCCESS;
}

/* Cache will be allocated in advance at init time
   & will be used during On Demand cleaning as a reserved
   Cache Memory */
fwd_cache_t	*resCache[2];
static int fwd_cmd_create_entry(ASF_uint32_t  ulVsgId,
				ASFFWDCreateCacheEntry_t *p,
				fwd_cache_t **pFlow,
				unsigned long *pHashVal)
{
	fwd_cache_t	*CacheEntry, *temp;
	unsigned long	hash;
	fwd_bucket_t	*bkt;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int processor_id = smp_processor_id();
#endif

	CacheEntry = asf_fwd_entry_lookup(p->CacheEntry.tuple.ulSrcIp,
			p->CacheEntry.tuple.ulDestIp,
			(p->CacheEntry.tuple.ucDscp & IPTOS_RT_MASK),
			ulVsgId, &hash);

	if (CacheEntry) {
		asf_print("Cache entry already exist!\n");
		return ASFFWD_RESPONSE_FAILURE;
	}

	spin_lock_bh(&fwd_entry_count_lock);
	if (fwd_cur_entry_count >= fwd_max_entry) {
		unsigned int	vsg = ulVsgId;

		spin_unlock_bh(&fwd_entry_count_lock);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		/* On demand Force cleaning of existing Cache entry*/
		asf_print("Doing On Demand force cleaning\n");
		CacheEntry = fwd_aging_table[processor_id][vsg].pTail;
		if (unlikely(!CacheEntry)) {
			/* Try to get Cache entry from any other VSG */
			asf_print("Trying to Get Cache"
				" Entry from other VSG's list.\n");
			for (vsg = 0; vsg < fwd_max_vsgs; vsg++) {
				if (fwd_aging_table[processor_id]
						[vsg].pTail) {
					CacheEntry = fwd_aging_table
						[processor_id][vsg].pTail;
					break;
				}
			}
			if (unlikely(!CacheEntry)) {
				/* Should not come Here */
				asf_warn("Surprised No VSG has Cache entry.\n");
				goto down;
			}
		}

		if (CacheEntry->aPrev != CacheEntry) {
			fwd_aging_table[processor_id]
						[vsg].pTail = CacheEntry->aPrev;
			CacheEntry->aPrev->aNext = NULL;
		} else {
			fwd_aging_table[processor_id][vsg].pHead = NULL;
			fwd_aging_table[processor_id][vsg].pTail = NULL;
			asfTimerStop(ASF_FWD_EXPIRY_TMR_ID,
					0,
					fwd_aging_table[processor_id]
						[vsg].pInacRefreshTmr);
		}

		/* Unattach the Cache from Bucket */
		bkt = (fwd_bucket_t *)CacheEntry->bkt;
		spin_lock_bh(&bkt->lock);
		__asf_fwd_cache_remove(CacheEntry, bkt);
		spin_unlock_bh(&bkt->lock);
		if (CacheEntry->pL2blobTmr)
			asfTimerStop(ASF_FWD_BLOB_TMR_ID,
					0, CacheEntry->pL2blobTmr);
		/* Now swap this with reserve Cache entry */
		temp = CacheEntry;
		CacheEntry = resCache[processor_id];
		resCache[processor_id] = temp;
#else
		asf_print("Cache entry table Full for vsg %d!\n", vsg);
		return ASFFWD_RESPONSE_FAILURE;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
	} else {
		CacheEntry = fwd_cache_alloc();
		/* Increment number of current cache count */
		fwd_cur_entry_count++;
		spin_unlock_bh(&fwd_entry_count_lock);
	}
	asf_print("Current FWD entries count [%d]\n", fwd_cur_entry_count);

	if (CacheEntry) {
		CacheEntry->ulVsgId = ulVsgId;
		if (fwd_entry_copy_info(&p->CacheEntry, CacheEntry) !=
						ASFFWD_RESPONSE_SUCCESS)
			goto down;

		CacheEntry->as_cache_info = p->ASFFwdInfo;
		CacheEntry->ulLastPktInAt = jiffies;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		asf_print("Creating l2blob timer (CacheEntry)\n");
		CacheEntry->pL2blobTmr = asfTimerStart(ASF_FWD_BLOB_TMR_ID, 0,
						fwd_l2blob_refresh_interval,
						ulVsgId,
						(unsigned int)CacheEntry,
						0, hash);
		if (!(CacheEntry->pL2blobTmr))
			goto down;
#endif
		/* insert in the table.. but l2blob_len is
		   zero meaning waiting for l2blob update */
		bkt = asf_fwd_bucket_by_hash(hash);
		CacheEntry->bkt = (void *)bkt;
		asf_fwd_cache_insert(CacheEntry, bkt);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		/* Insert Cache into Aging list.*/
		if (NULL == fwd_aging_table[processor_id][ulVsgId].pHead) {
			fwd_aging_table[processor_id]
					[ulVsgId].pHead = CacheEntry;
			fwd_aging_table[processor_id]
					[ulVsgId].pTail = CacheEntry;
			CacheEntry->aPrev = fwd_aging_table[processor_id]
								[ulVsgId].pHead;
			CacheEntry->aNext = NULL;
			asf_print("Creating: Head[%p]. Next[%p] Tail[%p]\n",
				fwd_aging_table[processor_id][ulVsgId].pHead,
				fwd_aging_table[processor_id][ulVsgId].
								pHead->aNext,
				fwd_aging_table[processor_id][ulVsgId].pTail);
			/*If First Cache in this VSG, start Aging timer*/
			if (fwd_aging_enable) {
				asf_print("Creating per VSG Expiry timer\n");
				fwd_aging_table[processor_id][ulVsgId].
					pInacRefreshTmr = asfTimerStart(
							ASF_FWD_EXPIRY_TMR_ID,
							0, fwd_expiry_timeout,
							ulVsgId, hash, 0, 0);
				if (!(fwd_aging_table[processor_id]
					[ulVsgId].pInacRefreshTmr))
					goto down2;
			} else
				asf_print("Aging disabled.\n");
		} else {
			CacheEntry->aNext = fwd_aging_table[processor_id]
								[ulVsgId].pHead;
			CacheEntry->aNext->aPrev = CacheEntry;
			fwd_aging_table[processor_id]
						[ulVsgId].pHead = CacheEntry;
			CacheEntry->aPrev = fwd_aging_table[processor_id]
								[ulVsgId].pHead;
			asf_print("Creating: Head[%p]. Next[%p] Tail[%p]\n",
				fwd_aging_table[processor_id][ulVsgId].pHead,
				fwd_aging_table[processor_id][ulVsgId].
								pHead->aNext,
				fwd_aging_table[processor_id][ulVsgId].pTail);
		}
#endif
		asf_print("Cache entry [%p], created with Hash [%lX]\n",
			CacheEntry, hash);
		if (pHashVal)
			*pHashVal = hash;
		if (pFlow)
			*pFlow = CacheEntry;

		return ASFFWD_RESPONSE_SUCCESS;
	}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
down2:
	asf_print("%s - timer allocation failed!\n", __func__);
	if (CacheEntry && CacheEntry->pL2blobTmr)
		asfTimerStop(ASF_FWD_BLOB_TMR_ID, 0, CacheEntry->pL2blobTmr);
#endif
down:
	spin_lock_bh(&fwd_entry_count_lock);
	fwd_cur_entry_count--;
	spin_unlock_bh(&fwd_entry_count_lock);

	if (CacheEntry)
		fwd_cache_free(CacheEntry);
	asf_print("%s - Cache creation failed!\n", __func__);
	if (pFlow)
		*pFlow = NULL;

	return ASFFWD_RESPONSE_FAILURE;
}


static int fwd_cmd_delete_entry(ASF_uint32_t  ulVsgId,
				ASFFWDDeleteCacheEntry_t *p,
				unsigned long *pHashVal,
				ASFFWDCacheEntryStats_t  *stats)
{
	fwd_cache_t	*CacheEntry;
	fwd_bucket_t	*bkt;
	unsigned long	hash;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int	processor_id = smp_processor_id();
#endif

	/* first detach the Caches */
	hash = ASFFWDComputeFlowHash(p->tuple.ulSrcIp, p->tuple.ulDestIp,
					(p->tuple.ucDscp & IPTOS_RT_MASK),
					ulVsgId, asf_fwd_hash_init_value);
	if (pHashVal)
		*pHashVal = hash;
	bkt = asf_fwd_bucket_by_hash(hash);

	spin_lock_bh(&bkt->lock);
	CacheEntry = asf_fwd_entry_lookup_in_bkt_ex(&p->tuple,
					ulVsgId, (fwd_cache_t *)bkt);
	if (CacheEntry) {
		if (unlikely(CacheEntry->bDeleted)) {
			spin_unlock_bh(&bkt->lock);
			return -1;
		}
		 __asf_fwd_cache_remove(CacheEntry, bkt);
		CacheEntry->bDeleted = 1;
		spin_unlock_bh(&bkt->lock);

		spin_lock_bh(&fwd_entry_count_lock);
		fwd_cur_entry_count--;
		spin_unlock_bh(&fwd_entry_count_lock);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (CacheEntry->pL2blobTmr)
			asfTimerStop(ASF_FWD_BLOB_TMR_ID,
					0,
					CacheEntry->pL2blobTmr);

		/* Delete Entry from Respective Core Aging List */
		if (fwd_aging_table[processor_id][ulVsgId].pHead != CacheEntry
				&& (num_online_cpus() == 2))
			processor_id = !processor_id;

		if (CacheEntry->aPrev == CacheEntry) {
			fwd_aging_table[processor_id][ulVsgId].pHead =
							CacheEntry->aNext;

			if (fwd_aging_enable && !fwd_aging_table[processor_id]
								[ulVsgId].pHead)
				/* Stop Aging Timer */
				asfTimerStop(ASF_FWD_EXPIRY_TMR_ID, 0,
					fwd_aging_table[processor_id][ulVsgId].
							pInacRefreshTmr);

		} else
			CacheEntry->aPrev->aNext = CacheEntry->aNext;

		if (CacheEntry->aNext)
			CacheEntry->aNext->aPrev = CacheEntry->aPrev;
		else {
			/* Adjust the Tail pointer */
			fwd_aging_table[processor_id][ulVsgId].pTail =
							CacheEntry->aPrev;
		}
#endif
		/* copy stats , required for delete response */
		fwd_copy_cache_stats(CacheEntry, stats);
		/* Free the cache entry */
		call_rcu((struct rcu_head *)CacheEntry,  fwd_cache_free_rcu);
		return 0;
	}
	spin_unlock_bh(&bkt->lock);
	return -1;
}

static int fwd_cmd_update_cache(ASF_uint32_t ulVsgId,
				ASFFWDUpdateCacheEntry_t *p)
{
	fwd_cache_t *Cache;
	unsigned long	hash;

	Cache = asf_fwd_entry_lookup_by_tuple(&p->tuple, ulVsgId, &hash);
	asf_print("Cache entry [%p] found at hash [%lx]... updating it\n",
								Cache, hash);
	if (Cache) {
		if (p->bL2blobUpdate) {
			ASFNetDevEntry_t  *dev;

			if (p->u.l2blob.ulDeviceId > fwd_max_ifaces) {
				asf_err("DeviceId %d > MAX %d\n",
					p->u.l2blob.ulDeviceId, fwd_max_ifaces);
				return ASFFWD_RESPONSE_FAILURE;
			}
			dev = ASFCiiToNetDev(p->u.l2blob.ulDeviceId);
			if (!dev) {
				asf_err("No matching iface mapping found for"
				" DeviceId %d\n", p->u.l2blob.ulDeviceId);
				return ASFFWD_RESPONSE_FAILURE;
			}

			if (dev->ulDevType != ASF_IFACE_TYPE_ETHER) {
				asf_err("tx iface must be of ETH type\n");
				return ASFFWD_RESPONSE_FAILURE;
			}

			Cache->odev = dev->ndev;

			if (p->u.l2blob.l2blobLen > ASF_MAX_L2BLOB_LEN) {
				asf_err("bloblen %d > MAX %d\n",
				p->u.l2blob.l2blobLen, ASF_MAX_L2BLOB_LEN);
				return ASFFWD_RESPONSE_FAILURE;
			}

			memcpy(&Cache->l2blob, p->u.l2blob.l2blob,
					p->u.l2blob.l2blobLen);
			Cache->l2blob_len = p->u.l2blob.l2blobLen;
			Cache->pmtu = p->u.l2blob.ulPathMTU;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			Cache->bVLAN = p->u.l2blob.bTxVlan;
			Cache->bPPPoE = p->u.l2blob.bUpdatePPPoELen;
			Cache->tx_vlan_id = p->u.l2blob.usTxVlanId;
#endif
			asf_print("L2Blob(%d) = %pM%pM...%02X%02X\n",
					Cache->l2blob_len,
					Cache->l2blob, Cache->l2blob+6,
					Cache->l2blob[Cache->l2blob_len-2],
					Cache->l2blob[Cache->l2blob_len-1]);
			return ASFFWD_RESPONSE_SUCCESS;
		}
	} else
		asf_print("Cache is not found!\n");

	return ASFFWD_RESPONSE_FAILURE;
}

int ASFFWDQueryCacheEntryStats(ASF_uint32_t ulVsgId,
				ASFFWDQueryCacheEntryStatsInfo_t *p)
{
	fwd_cache_t	*CacheEntry;
	int		bLockFlag, iResult;
	unsigned long	hash;

	if (!p)
		return ASFFWD_RESPONSE_FAILURE;

	ASF_RCU_READ_LOCK(bLockFlag);
	CacheEntry = asf_fwd_entry_lookup_by_tuple(&p->tuple, ulVsgId, &hash);
	if (CacheEntry) {
		fwd_copy_cache_stats(CacheEntry, &p->stats);
		iResult = ASFFWD_RESPONSE_SUCCESS;
	} else {
		memset(&p->stats, 0, sizeof(p->stats));
		iResult = ASFFWD_RESPONSE_FAILURE;
	}
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return iResult;
}
EXPORT_SYMBOL(ASFFWDQueryCacheEntryStats);

unsigned int asfFwdBlobTmrCb(unsigned int ulVsgId, unsigned int ulCacheEntryPtr,
				unsigned int ulArg2, unsigned int ulHashVal)
{
	fwd_cache_t *CacheEntry;

	asf_print("vsg %u hash %u CacheEntry 0x%X\n",
			ulVsgId, ulHashVal, ulCacheEntryPtr);

	if (ASFGetStatus()) {
		CacheEntry = (fwd_cache_t *)ulCacheEntryPtr;
		if (CacheEntry) {
			if (fwdCbFns.pFnCacheEntryRefreshL2Blob) {
				ASFFWDCacheEntryL2BlobRefreshCbInfo_t ind;

				ind.packetTuple.ulSrcIp = CacheEntry->ulSrcIp;
				ind.packetTuple.ulDestIp = CacheEntry->ulDestIp;
				ind.packetTuple.ucDscp = CacheEntry->ucDscp;
				ind.ulHashVal = ulHashVal;
				ind.Buffer.nativeBuffer = NULL;
				ind.ASFFwdInfo = (ASF_uint8_t *)
						CacheEntry->as_cache_info;

				fwdCbFns.pFnCacheEntryRefreshL2Blob
						(CacheEntry->ulVsgId, &ind);
			}
			return 0;
		}
		asf_print("Blob Tmr: CacheEntry not found {%p}.."
			" (might happen while Caches are being deleted)!!!\n",
							CacheEntry);
	}
	asf_print("asf not enabled: return 1.. REVIEW??\n");
	return 0;
}


unsigned int asfFwdExpiryTmrCb(unsigned int ulVsgId,
	unsigned int ulHash, unsigned int ularg2, unsigned int ularg3)
{
	fwd_cache_t *CacheEntry;
	int	processor_id = smp_processor_id();

	asf_print("Removing Aged out cache entires for vsgId %u\n", ulVsgId);
	CacheEntry = fwd_aging_table[processor_id][ulVsgId].pTail;
	if (CacheEntry) {
		unsigned long ulIdleTime;
		fwd_bucket_t	*bkt;
		int		last_entry = 0;
		while (!last_entry) {
			ulIdleTime =
				ASF_LAST_IN_TO_IDLE(CacheEntry->ulLastPktInAt);
			asf_print("Idle Time [%ld] MAX [%d]\n",
					ulIdleTime, fwd_expiry_timeout);
			if (ulIdleTime >= fwd_expiry_timeout) {
				if (CacheEntry == CacheEntry->aPrev)
					last_entry = 1;
				else
					fwd_aging_table[processor_id][ulVsgId].
						pTail = CacheEntry->aPrev;

				asf_print("Removing Cache[%p]\n", CacheEntry);
				CacheEntry->bDeleted = 1;
				/* Delete the entry */
				bkt = (fwd_bucket_t *)CacheEntry->bkt;
				spin_lock_bh(&bkt->lock);
				__asf_fwd_cache_remove(CacheEntry, bkt);
				spin_unlock_bh(&bkt->lock);

				spin_lock_bh(&fwd_entry_count_lock);
				fwd_cur_entry_count--;
				spin_unlock_bh(&fwd_entry_count_lock);

				if (CacheEntry->pL2blobTmr)
					asfTimerStop(ASF_FWD_BLOB_TMR_ID,
						0, CacheEntry->pL2blobTmr);
				/* Control layer callback */
				if (fwdCbFns.pFnCacheEntryExpiry) {
					ASFFWDCacheEntryExpiryCbInfo_t ind;

					ind.tuple.ulSrcIp = CacheEntry->ulSrcIp;
					ind.tuple.ulDestIp =
							CacheEntry->ulDestIp;
					ind.tuple.ucDscp = CacheEntry->ucDscp;
					ind.ulHashVal = ulHash;
					fwd_copy_cache_stats(CacheEntry,
								&ind.stats);
					ind.ASFFwdInfo = (ASF_uint8_t *)
						CacheEntry->as_cache_info;

					fwdCbFns.pFnCacheEntryExpiry(ulVsgId,
									&ind);
				}
				call_rcu((struct rcu_head *)CacheEntry,
					fwd_cache_free_rcu);
				/* Move to Next entry */
				CacheEntry = fwd_aging_table[processor_id]
								[ulVsgId].pTail;
				continue;
			}
			return 0;
		}
		/* All entries are aged out */
		fwd_aging_table[processor_id][ulVsgId].pHead = NULL;
		fwd_aging_table[processor_id][ulVsgId].pTail = NULL;

		goto stop_timer;

	}
	asf_print("Inac Tmr: Cache not found \n");
stop_timer:
	/* Stop the Timer */
	asf_print("No more entries , Stopping aging timer..\n");
	asfTimerStop(ASF_FWD_EXPIRY_TMR_ID, 0,
			fwd_aging_table[processor_id][ulVsgId].pInacRefreshTmr);
	return 0;
}

static void asf_fwd_destroy_all_caches(void)
{
	int i;
	fwd_cache_t	*head, *Cache, *temp;

	for (i = 0; i < fwd_hash_buckets; i++) {
		head = (fwd_cache_t *) &fwd_cache_table[i];
		Cache = head->pNext;
		while (Cache != head) {
			temp = Cache;
			Cache = Cache->pNext;
			call_rcu((struct rcu_head *)temp,
					fwd_cache_destroy);
		}
	}
	spin_lock_bh(&fwd_entry_count_lock);
	fwd_cur_entry_count = 0;
	spin_unlock_bh(&fwd_entry_count_lock);
}

static void fwd_cmd_flush_table(unsigned long ulVsgId)
{
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	fwd_bucket_t	*bkt;
#endif
	fwd_cache_t	*CacheEntry;
	int	processor_id = smp_processor_id();

	asf_print("SoftIRQ Context [%s]..at Jiffies[0x%lu]\n",
			in_softirq() ? "YES" : "NO", jiffies);

	if (!asf_ffp_check_vsg_mode(ulVsgId, fwdMode))
		return;

	asf_print("Flushing Core[%d]VSG [%lu] Cache Table\n",
					processor_id, ulVsgId);
	/* Check if already flushed */
	if (fwd_aging_table[processor_id][ulVsgId].pHead == NULL)
		return;

	if (fwd_aging_enable) {
		asf_print("Stopping Aging timer for Core[%d]VSG[%lu]..\n",
							processor_id, ulVsgId);
		asfTimerStop(ASF_FWD_EXPIRY_TMR_ID, 0,
			fwd_aging_table[processor_id][ulVsgId].pInacRefreshTmr);
	}
	CacheEntry = fwd_aging_table[processor_id][ulVsgId].pHead;
	fwd_aging_table[processor_id][ulVsgId].pHead = NULL;
	fwd_aging_table[processor_id][ulVsgId].pTail = NULL;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	while (CacheEntry) {
		/* Delete the entry */
		bkt = (fwd_bucket_t *)CacheEntry->bkt;
		spin_lock_bh(&bkt->lock);
		__asf_fwd_cache_remove(CacheEntry, bkt);
		spin_unlock_bh(&bkt->lock);
		if (CacheEntry->pL2blobTmr)
			asfTimerStop(ASF_FWD_BLOB_TMR_ID,
				0, CacheEntry->pL2blobTmr);

		call_rcu((struct rcu_head *)CacheEntry,  fwd_cache_free_rcu);
		/* Move to Next entry */
		CacheEntry = CacheEntry->aNext;
	}
	spin_lock_bh(&fwd_entry_count_lock);
	fwd_cur_entry_count = 0;
	spin_unlock_bh(&fwd_entry_count_lock);
#endif
	return;
}

void asfFwdAddTimerOn(void *tmr)
{
	struct timer_list *timer;

	timer = (struct timer_list *)tmr;
	mod_timer(timer, timer->expires);
}

static void ASFFWDCleanVsg(ASF_uint32_t ulVsgId)
{
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	struct timer_list *tmr_cpu1, *tmr_cpu2;
	int bInInterrupt = in_softirq();
	int processor_id = smp_processor_id();

	switch (num_online_cpus()) {
	case 1: /* NON-SMP */
	{
		if (bInInterrupt) {
			fwd_cmd_flush_table(ulVsgId);
			return;
		}

		tmr_cpu1 = &fwd_aging_table[processor_id][ulVsgId].flush_timer;
		tmr_cpu1->expires = ASF_FWD_FLUSH_TIMER_EXPIRE;
		setup_timer(tmr_cpu1, fwd_cmd_flush_table,
					(unsigned long)ulVsgId);
		/* Flushing on local core */
		mod_timer(tmr_cpu1, tmr_cpu1->expires);
		return;
	}

	default:
		asf_print("SMP Mode handling\n");
		/* fall through */
	}

	tmr_cpu1 = &fwd_aging_table[processor_id][ulVsgId].flush_timer;
	tmr_cpu2 = &fwd_aging_table[!processor_id][ulVsgId].flush_timer;

	if (!bInInterrupt) {
		/* Switch to IRQ context to make aging
		   list manupulation Lock free */
		asf_print("Not in SoftIRQ Context.."
			" Switching at Jiffies[0x%lu]\n", jiffies);
		tmr_cpu2->expires = ASF_FWD_FLUSH_TIMER_EXPIRE;
		tmr_cpu1->expires = ASF_FWD_FLUSH_TIMER_EXPIRE;
		setup_timer(tmr_cpu1, fwd_cmd_flush_table,
					(unsigned long)ulVsgId);
		setup_timer(tmr_cpu2, fwd_cmd_flush_table,
					(unsigned long)ulVsgId);
		/* Flushing on other core */
		smp_call_function_single(!processor_id, asfFwdAddTimerOn,
					tmr_cpu2, 0);
		/* Flushing on local core */
		mod_timer(tmr_cpu1, tmr_cpu1->expires);
	} else {
		asf_print("Already In SoftIRQ Context!\n");
		/* Flushing on other core */
		tmr_cpu2->expires = ASF_FWD_FLUSH_TIMER_EXPIRE;
		setup_timer(tmr_cpu2, fwd_cmd_flush_table,
					(unsigned long)ulVsgId);
		smp_call_function_single(!processor_id, asfFwdAddTimerOn,
					tmr_cpu2, 0);
		/* Flushing on local core */
		fwd_cmd_flush_table(ulVsgId);
	}
#else
	fwd_cmd_flush_table(ulVsgId);
#endif
}


/*
 * Initialization
 */
static int asf_fwd_init_cache_table(void)
{
	unsigned int	max_num;
#ifdef ASF_FFP_USE_SRAM
	dma_addr_t      addr;
#endif

	get_random_bytes(&asf_fwd_hash_init_value,
			sizeof(asf_fwd_hash_init_value));
	/* 10% of actual max value */
	max_num = fwd_max_entry/10;
	if (asfCreatePool("FwdCache", max_num,
			  max_num, (max_num/2),
			  sizeof(fwd_cache_t),
			  &fwd_cache_pool_id) != 0) {
		asf_err("failed to initialize fwd_cache_pool\n");
		return -ENOMEM;
	}

	if (asfCreatePool("FwdBlobTimers", max_num,
			max_num, (max_num/2), sizeof(asfTmr_t),
			&fwd_blob_timer_pool_id)) {
		asf_err("Error in creating pool for Blob Timers\n");
		goto err1;
	}
	/* Setting up max num of Expiray timer
	as per current num of VSG */
	if (fwd_max_vsgs < ASF_FWD_MIN_PER_CORE_EXP_TIMER)
		max_num = (num_online_cpus() * ASF_FWD_MIN_PER_CORE_EXP_TIMER);
	else if (0 != (fwd_max_vsgs % 2))
		max_num = (num_online_cpus() * (fwd_max_vsgs + 1));
	else
		max_num = (num_online_cpus() * fwd_max_vsgs);

	asf_print("FwdExpiryTimers count is [%d]\n", max_num);
	if (asfCreatePool("FwdExpiryTimers", max_num,
			max_num, (max_num/2), sizeof(asfTmr_t),
				&fwd_expiry_timer_pool_id)) {
		asf_err("Error in creating pool for Inac Timers\n");
		goto err2;
	}

	asf_print("Timer : BlobTmr_PoolId= %d ExpiryTimer_PoolId = %d\r\n",
			fwd_blob_timer_pool_id, fwd_expiry_timer_pool_id);

	asf_print("Instantiating blob timer wheels\n");

	if (asfTimerWheelInit(ASF_FWD_BLOB_TMR_ID, 0,
		fwd_hash_buckets, ASF_TMR_TYPE_SEC_TMR,
		ASF_FWD_BLOB_TIME_INTERVAL, ASF_FWD_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing L2blob Timer wheel\n");
		goto err3;
	}

	asf_print("Instantiating Cache Expiry Timer Wheels\n");

	if (asfTimerWheelInit(ASF_FWD_EXPIRY_TMR_ID, 0,
		fwd_hash_buckets, ASF_TMR_TYPE_SEC_TMR,
		ASF_FWD_EXPIRY_TIME_INTERVAL, fwd_max_vsgs) == 1) {
		asf_err("Error in initializing Cache Timer wheel\n");
		goto err4;
	}


	/* Register the callback function and timer pool Id */
	asf_print("Register Blob Timer App\n");
	if (asfTimerAppRegister(ASF_FWD_BLOB_TMR_ID, 0, asfFwdBlobTmrCb,
						fwd_blob_timer_pool_id)) {
		asf_err("Error in registering Cb Fn/Pool Id\n");
		goto err5;
	}

	asf_print("Register Cache Expiry Timer App\n");
	if (asfTimerAppRegister(ASF_FWD_EXPIRY_TMR_ID, 0,
			asfFwdExpiryTmrCb, fwd_expiry_timer_pool_id)) {
		asf_err("Error in registering Cb Fn/Pool Id\n");
		goto err5;
	}
	return 0;

err5:
	asfTimerWheelDeInit(ASF_FWD_EXPIRY_TMR_ID, 0);
err4:
	asfTimerWheelDeInit(ASF_FWD_BLOB_TMR_ID, 0);
err3:
	asfDestroyPool(fwd_expiry_timer_pool_id);
err2:
	asfDestroyPool(fwd_blob_timer_pool_id);
err1:
	asfDestroyPool(fwd_cache_pool_id);
	return -ENOMEM;
}

static void asf_fwd_destroy_cache_table(void)
{
	int i;

	for (i = 0; i < num_online_cpus(); i++)
		kfree(fwd_aging_table[i]);

	asf_fwd_destroy_all_caches();

	asf_print("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	asf_print("DeInit EXPIRY_TMR Wheel\n");
	asfTimerWheelDeInit(ASF_FWD_EXPIRY_TMR_ID, 0);
	asf_print("DeInit BLOB_TMR Wheel\n");
	asfTimerWheelDeInit(ASF_FWD_BLOB_TMR_ID, 0);

	asf_print("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	asf_print("DestroyPool ExpiryTimerPool\n");
	asfDestroyPool(fwd_expiry_timer_pool_id);

	asf_print("DestroyPool BlobTimerPool\n");
	asfDestroyPool(fwd_blob_timer_pool_id);

	asf_debug("DestroyPool FWDCachePool\n");
	asfDestroyPool(fwd_cache_pool_id);

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();
	/* Free the table bucket array */
#ifdef ASF_FFP_USE_SRAM
	iounmap((unsigned long *)(fwd_cache_table));
#else
	kfree(fwd_cache_table);
#endif
	asf_print("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();
}


static int __init asf_fwd_init(void)
{
	int		i, j, num_cpus, err = -EINVAL;
	ASFCap_t	asf_cap;
#ifdef ASF_FFP_USE_SRAM
	dma_addr_t	addr;
#endif
	get_random_bytes(&rule_salt, sizeof(rule_salt));

	/* Get ASF Capabilities and store them for future use. */
	ASFGetCapabilities(&asf_cap);
	if (!asf_cap.mode[fwdMode]) {
		asf_err("ASF not configured in FWD mode.... Exiting\n");
		return err;
	} else if (!asf_cap.bBufferHomogenous) {
		asf_err("No Support for Hetrogenous Buffer, ...Exiting\n");
		return err;
	}

	fwd_max_vsgs = asf_cap.ulNumVSGs;
	fwd_max_ifaces = asf_cap.ulNumIfaces;

	/* Memory Pools must have been initialized by FFP module */
	asf_print("Initializing FWD Cache & Timers Pools\n");
	err = asf_fwd_init_cache_table();
	if (err)
		return err;

	/* Allocate hash table */
#ifdef ASF_FFP_USE_SRAM
	addr = (unsigned long)(ASF_FFP_SRAM_BASE);
	fwd_cache_table = ioremap_flags(addr,
			(sizeof(fwd_bucket_t) * fwd_hash_buckets),
				PAGE_KERNEL | _PAGE_COHERENT);
#else
	fwd_cache_table = kzalloc((sizeof(fwd_bucket_t)
				* fwd_hash_buckets), GFP_KERNEL);
#endif

	if (fwd_cache_table == NULL) {
		asf_err("Memory allocatin for Hash table Failed...Exiting\n");
		return -ENOMEM;
	}
	for (i = 0; i < fwd_hash_buckets; i++) {
		spin_lock_init(&fwd_cache_table[i].lock);
		/* initialize circular list */
		fwd_cache_table[i].pPrev = fwd_cache_table[i].pNext
			= (fwd_cache_t *)&fwd_cache_table[i];
	}

	/* Allocate Aging table instance */
	num_cpus = num_online_cpus();
	fwd_aging_table = kzalloc(
		sizeof(fwd_aging_t *) * num_cpus, GFP_KERNEL);
	if (fwd_aging_table == NULL) {
		/* Need better cleanup and allocation */
		asf_err("Unable to allocate memory"
			" for per core fwd_aging_table\n");
		return -ENOMEM;
	}
	for (i = 0; i < num_cpus; i++) {
		fwd_aging_table[i] = kzalloc(
			sizeof(fwd_aging_t) * fwd_max_vsgs, GFP_KERNEL);
		for (j = 0; j < fwd_max_vsgs; j++)
			/* Initialize Flush timers required
			   for context switching */
			init_timer(&fwd_aging_table[i][j].flush_timer);
	}
	asf_print("Per Core Per VSG Aging List Initialized\n");
	asf_fwd_register_proc();
	asf_print("Registered PROC entries\n");

	/* Register function pointer with ASF Main module
	to receive packet. */
	ASFFFPRegisterFWDFunctions(ASFFWDProcessPkt, ASFFWDCleanVsg);
	/* Get Statistucs pointer */
	asf_vsg_stats = get_asf_vsg_stats();
	asf_gstats = get_asf_gstats();

	spin_lock_init(&fwd_entry_count_lock);
	/* Allocate the Reserved Cache Memory */
	resCache[0] = fwd_cache_alloc();
	resCache[1] = fwd_cache_alloc();

	return err;
}

static void __exit asf_fwd_exit(void)
{
	int		i, j, num_cpus;

	num_cpus = num_online_cpus();
	asf_print("Waiting for all CPUs to finish existing packets!\n");
	synchronize_rcu();

	/* De-Register function pointer with ASF Main module
	to receive packet. */
	ASFFFPRegisterFWDFunctions(NULL, NULL);
	asf_fwd_unregister_proc();
	/* Delete Flush timers */
	for (i = 0; i < num_cpus; i++) {
		for (j = 0; j < fwd_max_vsgs; j++)
			asfTimerFreeNodeMemory(
				fwd_aging_table[i][j].pInacRefreshTmr);
			/* Delete Flush timers required
			   for context switching */
			del_timer(&fwd_aging_table[i][j].flush_timer);
	}

	asf_print("Destroying existing Cache table!\n");
	fwd_cache_free(resCache[0]);
	fwd_cache_free(resCache[1]);
	asf_fwd_destroy_cache_table();

	asf_print("Waiting for all CPUs to finish existing packets!\n");
	synchronize_rcu();
}
module_init(asf_fwd_init);
module_exit(asf_fwd_exit);

