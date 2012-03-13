/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asftermapi.c
 *
 * Description: ASF Termination module for IPv4 forwarding
 * Initialization and Handling.
 *
 * Authors:
 *		Hemant Agrawal <hemant@freescale.com>
 */
/*
 * History
 * Version	Date		Author			Change Description *
 * 2.0		22 Feb 2011	Hemant Agrawal	IP Termination Support Added
 *
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
#include <linux/if_pmal.h>
#include <linux/ip.h>
#include <net/udp.h>
#include <net/xfrm.h>
#include "asfterm_pvt.h"

#define ASF_TERM_VERSION	"1.0.0"
#define ASF_TERM_DESC	"ASF Termination Component"
/** \brief	Driver's license
 * \details	GPL
 * \ingroup	Linux_module
 */
MODULE_LICENSE("GPL");
/** \brief	Module author
 * \ingroup	Linux_module
 */
MODULE_AUTHOR("Freescale Semiconductor, Inc");
/** \brief	Module description
 * \ingroup	Linux_module
 */
MODULE_DESCRIPTION(ASF_TERM_DESC);
char *asf_term_version = ASF_TERM_VERSION;

/* Initilization Parameters */
bool term_aging_enable = 1; /* Enable */
int term_max_entry = 1024;
int term_max_vsgs = ASF_MAX_VSGS;
int term_max_ifaces = ASF_MAX_IFACES;
int term_hash_buckets = 1024;
int term_l2blob_refresh_npkts = ASF_MAX_L2BLOB_REFRESH_PKT_CNT;
int term_l2blob_refresh_interval = ASF_MAX_L2BLOB_REFRESH_TIME;

bool term_l4_rx_csum;
bool term_l4_tx_csum;

module_param(term_aging_enable, bool, 0644);
MODULE_PARM_DESC(term_aging_enable, "Enable / Disable Aging.");
module_param(term_l2blob_refresh_interval, int, 0644);
MODULE_PARM_DESC(term_l2blob_refresh_interval,
	"Time interval after which L2 blob required");
module_param(term_hash_buckets, int, 0444);
MODULE_PARM_DESC(term_hash_buckets,
	"Maximum number of buckets in TERM Hash table");
module_param(term_max_entry, int, 0444);
MODULE_PARM_DESC(term_max_entry, "Maximum number of TERM entry entries");

module_param(term_l4_rx_csum, bool, 0644);
MODULE_PARM_DESC(term_l4_rx_csum, "Verify Layer 4 RX Checksum UDP & TCP");

module_param(term_l4_tx_csum, bool, 0644);
MODULE_PARM_DESC(term_l4_tx_csum, "Update Layer 4 TX Checksum UDP & TCP");

static unsigned int term_cache_pool_id = -1;
static unsigned int term_blob_timer_pool_id = -1;
static unsigned int term_expiry_timer_pool_id = -1;
ptrIArry_tbl_t term_ptrary;

/* Termination table gobal pointer */
term_bucket_t	*term_cache_table;
struct timer_list	term_flush_timer[NR_CPUS][ASF_MAX_VSGS];

/* Statistics */
ASFFFPGlobalStats_t	*asf_gstats; /* per cpu global stats */
ASFFFPVsgStats_t	*asf_vsg_stats; /* per cpu vsg stats */

ASF_boolean_t	asf_term_notify = ASF_FALSE;
static ASFTERMCallbackFns_t	termCbFns = {0};
unsigned long asf_term_hash_init_value;

#ifdef ASF_IPSEC_FP_SUPPORT
extern ASFFFPIPSecInv4_f	pFFPIPSecIn;
extern ASFFFPIPSecOutv4_f	pFFPIPSecOut;
extern ASFFFPIPSecInVerifyV4_f	pFFPIpsecInVerify;
extern ASFFFPIPSecProcessPkt_f	pFFPIpsecProcess;
#endif

/** Local functions */
static int term_cmd_create_entry(ASF_uint32_t ulVsgId,
				ASFTERMCreateCacheEntry_t *p,
				term_cache_t **pFlow1,
				term_cache_t **pFlow2,
				unsigned long *pHashVal);
static int term_cmd_delete_entry(ASF_uint32_t ulVsgId,
				ASFTERMDeleteCacheEntry_t *p,
				unsigned long *pHashVal,
				ASFTERMCacheEntryStats_t *stats);
static int term_cmd_update_cache(ASF_uint32_t ulVsgId,
				ASFTERMUpdateCacheEntry_t *p);
static void ASFTERMCleanVsg(ASF_uint32_t ulVsgId);

static inline void term_copy_cache_stats(
	term_cache_t *cache,
	ASFTERMCacheEntryStats_t *stats)
{
	if (cache) {
		stats->ulInPkts = htonl(cache->stats.ulInPkts);
		stats->ulOutPkts = htonl(cache->stats.ulOutPkts);
		stats->ulInBytes = htonl(cache->stats.ulInBytes);
		stats->ulOutBytes = htonl(cache->stats.ulOutBytes);
	} else
		memset(stats, 0, sizeof(*stats));
}
static inline term_cache_t *term_cache_alloc(void)
{
	char		bHeap;
	term_cache_t	*Cache;
	ASFFFPGlobalStats_t *gstats;

	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());

	Cache = (term_cache_t *) asfGetNode(term_cache_pool_id, &bHeap);
	if (Cache) {
		gstats->ulFlowAllocs++;
		Cache->bHeap = bHeap;
	} else
		gstats->ulFlowAllocFailures++;

	return Cache;
}

static inline void term_cache_free(term_cache_t *Cache)
{
	ASFFFPGlobalStats_t	*gstats;

	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	asfReleaseNode(term_cache_pool_id, Cache, Cache->bHeap);
	gstats->ulFlowFrees++;
}

static inline void asf_term_cache_insert(
	term_cache_t *Cache,
	term_bucket_t *bkt)
{
	term_cache_t *head, *temp;

	head = (term_cache_t *) bkt;
	spin_lock_bh(&bkt->lock);
	temp = Cache->pNext = head->pNext;
	Cache->pPrev = head;
	rcu_assign_pointer(head->pNext, Cache);
	temp->pPrev = Cache;
	spin_unlock_bh(&bkt->lock);
}

static void term_cache_destroy(struct rcu_head *rcu)
{
	term_cache_t	*cache = (term_cache_t *)rcu;

	asfTimerFreeNodeMemory(cache->pL2blobTmr);
	asfTimerFreeNodeMemory(cache->pInacRefreshTmr);
	if (cache->bHeap)
		kfree(cache);
}

static void term_cache_free_rcu(struct rcu_head *rcu)
{
	term_cache_free((term_cache_t *)rcu);
}

/* Note: Caller must hold the spin lock of the bucket */
static inline void __asf_term_cache_remove(
	term_cache_t *Cache,
	term_bucket_t *bkt)
{
	Cache->pNext->pPrev = Cache->pPrev;
	Cache->pPrev->pNext = Cache->pNext;
}

static inline term_bucket_t *asf_term_bucket_by_hash(unsigned long ulHashVal)
{
	return &term_cache_table[TERM_HINDEX(ulHashVal)];
}


static inline term_cache_t *asf_term_entry_lookup_in_bkt(
		unsigned long sip, unsigned long dip,
		unsigned long ports, unsigned char protocol,
		unsigned long vsg,
		term_cache_t *pHead)
{
	term_cache_t	*Cache;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	for (Cache = pHead->pNext; Cache != pHead; Cache = Cache->pNext) {
		if ((Cache->ulSrcIp == sip)
			&& (Cache->ulDestIp == dip)
			&& (Cache->ulPorts == ports)
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			&& (Cache->ucProtocol == protocol)
			&& (Cache->ulVsgId == vsg)
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
				) {
				return Cache;
		}
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_print("Max (%u) scanned ... aborting search!",
					SEARCH_MAX_PER_BUCKET);
			return NULL;
		}
#endif
	}
	return NULL;
}

static inline term_cache_t *asf_term_entry_lookup_in_bkt_ex(
		ASFTERMCacheEntryTuple_t *tuple,
		unsigned long ulVsgId,
		term_cache_t *pHead)
{
	return asf_term_entry_lookup_in_bkt(tuple->ulSrcIp, tuple->ulDestIp,
				(tuple->usSrcPort << 16)|tuple->usDestPort,
				tuple->ucProtocol, ulVsgId, pHead);
}

static __u32 rule_salt __read_mostly;

static inline unsigned long ASFTERMComputeFlowHash(
			unsigned long ulSrcIp,
			unsigned long ulDestIp,
			unsigned long ulPorts,
			unsigned long ulVsgId,
			unsigned long initval)
{
	ulSrcIp += rule_salt;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	ulDestIp += JHASH_GOLDEN_RATIO;
#else
	ulDestIp += JHASH_INITVAL;
#endif
	ulPorts += initval;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulPorts);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ulSrcIp += ulVsgId;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulPorts);
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	return rule_salt + ulPorts;
}

/*
 * Lookups through the Caches to find matching entry.
 * The argument 'head' is head of circular list (actually bucket ponter).
 */
static inline term_cache_t *asf_term_entry_lookup(
	unsigned long sip, unsigned long dip, unsigned long ports,
	unsigned long vsg, unsigned char protocol, unsigned long *pHashVal)
{
	term_cache_t *Cache, *pHead;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	*pHashVal = ASFTERMComputeFlowHash(sip, dip, ports, vsg,
					asf_term_hash_init_value);
	asf_print("ASF: Hash(0x%lx, 0x%lx, 0x%x, 0x%lx) = %lx",
		sip, dip, ports, vsg, *pHashVal);

	pHead = (term_cache_t *) asf_term_bucket_by_hash(*pHashVal);

	for (Cache = pHead->pNext; Cache != pHead; Cache = Cache->pNext) {
		if ((Cache->ulSrcIp == sip)
			&& (Cache->ulDestIp == dip)
			&& (Cache->ulPorts == ports)
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			&& (Cache->ucProtocol == protocol)
			&& (Cache->ulVsgId == vsg)
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			)
				return Cache;
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_print("Max (%d) scanned in bucket for"
					" hashVal(%ld) ... aborting search!",
					SEARCH_MAX_PER_BUCKET, *pHashVal);
			return NULL;
		}
#endif
	}
	return NULL;
}
static inline term_cache_t *asf_term_entry_lookup_by_tuple(
			ASFTERMCacheEntryTuple_t *tpl,
			unsigned long ulVsgId,
			unsigned long *pHashVal)
{
	return asf_term_entry_lookup(tpl->ulSrcIp, tpl->ulDestIp,
				(tpl->usSrcPort << 16)|tpl->usDestPort,
				ulVsgId, tpl->ucProtocol, pHashVal);
}

static inline term_cache_t *term_cache_by_id(ASFFFPFlowId_t *id)
{
	return (term_cache_t *)
		(term_ptrary.pBase[id->ulArg1].ulMagicNum == id->ulArg2) ?
			term_ptrary.pBase[id->ulArg1].pData : NULL;
}

static inline term_cache_t *term_cache_by_id_ex(unsigned int ulIndex,
			unsigned int ulMagicNum)
{
	return (term_cache_t *)
		(term_ptrary.pBase[ulIndex].ulMagicNum == ulMagicNum) ?
			term_ptrary.pBase[ulIndex].pData : NULL;
}

static inline void asfTermSendLogEx(term_cache_t *Cache,
				unsigned long ulMsgId,
				ASF_uchar8_t *aMsg,
				unsigned long ulHashVal)
{
	if (termCbFns.pFnAuditLog) {
		ASFLogInfo_t		li;
		li.ulVSGId = Cache->ulVsgId;
		li.ulMsgId = ulMsgId;
		li.aMsg = aMsg;
		li.u.termInfo.tuple.ulSrcIp = Cache->ulSrcIp;
		li.u.termInfo.tuple.ulDestIp = Cache->ulDestIp;
		/*--- Test next Two lines (for endianness also) ---*/
		li.u.termInfo.tuple.usSrcPort =
			*(ASF_uint16_t *) ((ASF_uchar8_t *) &Cache->ulPorts);
		li.u.termInfo.tuple.usDestPort = *(ASF_uint16_t *)
				 ((ASF_uchar8_t *) &Cache->ulPorts + 2);
		li.u.termInfo.tuple.ucProtocol = Cache->ucProtocol;
		li.u.termInfo.ulHashVal = ulHashVal;
		termCbFns.pFnAuditLog(&li);
	}
}

static inline void asfTermSendLog(term_cache_t *Cache,
				unsigned long ulMsgId,
				unsigned long ulHashVal)
{
	asfTermSendLogEx(Cache, ulMsgId, (ASF_uchar8_t *)"", ulHashVal);
}
#ifdef ASF_DEBUG
void asfterm_display_frags(struct sk_buff *skb, char *msg)
{
	struct iphdr *iph;
	int count = 1, data_len = 0;

	asf_debug("Fragment Information (%s):", msg);
	iph = ip_hdr(skb);
	asf_debug(" Frag %d (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
		"skb->len %d iph->tot_len %u frag_off %u (sum %u)",
		count, skb->dev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
		skb->len, iph->tot_len, iph->frag_off, data_len);
	asf_debug("	   [ip_ptr 0x%x skb->data 0x%x data[0] 0x%02x"\
	"data[1] 0x%02x ]", iph, skb->data, skb->data[0], skb->data[1]);

	data_len = iph->tot_len;
	skb = skb_shinfo(skb)->frag_list;
	while (skb) {
		iph = ip_hdr(skb);
		count++;
		data_len += iph->tot_len;
		asf_debug(" Frag %d (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
			"skb->len %d iph->tot_len %u frag_off %u (sum %u)",
			count, skb->dev->name,
			NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
			skb->len, iph->tot_len, iph->frag_off, data_len);
		asf_debug("	   [ip_ptr 0x%x skb->data 0x%x data[0]"\
			"0x%02x data[1] 0x%02x ]",
			iph, skb->data, skb->data[0], skb->data[1]);
		skb = skb->next;
	}
}

void asfterm_display_one_frag(struct sk_buff *skb)
{
	struct iphdr *iph;
	unsigned char *data;
	int count = 1, data_len = 0;

	iph = ip_hdr(skb);
	data = skb->data + iph->ihl*4;
	asf_debug(" Org Frag (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
		"skb->len %d iph->tot_len %u frag_off %u",
		skb->dev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
		skb->len, iph->tot_len, iph->frag_off);
	asf_debug("	   [ip_ptr 0x%x data 0x%x data[0] 0x%02x data[1]"\
		"0x%02x ]", iph, data, data[0], data[1]);
}

void asfterm_display_skb_list(struct sk_buff *skb, char *msg)
{
	struct iphdr *iph;
	int count = 0, data_len = 0;

	asf_debug("Skb List (Frag) Information (%s):", msg);
	while (skb) {
		iph = ip_hdr(skb);
		count++;
		data_len += iph->tot_len;
		asf_debug(" Frag %d (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
			"skb->len %d iph->tot_len %u frag_off %u (sum %u)",
			count, skb->dev->name,
			NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
			skb->len, iph->tot_len, iph->frag_off, data_len);
		asf_debug("	   [ip_ptr 0x%x skb->data 0x%x data[0]"\
			"0x%02x data[1] 0x%02x ]",
			iph, skb->data, skb->data[0], skb->data[1]);
		skb = skb->next;
	}

}
#else
#define asfterm_display_frags(skb, msg) do {} while (0)
#define asfterm_display_skb_list(skb, msg) do {} while (0)
#define asfterm_display_one_frag(skb) do {} while (0)
#endif


inline void asfFragmentAndSendPkt(term_cache_t	*Cache,
				struct sk_buff	*skb,
				struct iphdr	*iph,
				ASFTERMCacheEntryStats_t *term_stats,
				ASFFFPGlobalStats_t *gstats,
				ASFFFPVsgStats_t *vstats)
{
	struct sk_buff *pSkb, *pTempSkb;
	/* Need to call fragmentation routine */
	asf_print("attempting to fragment and xmit");
	if (!asfIpv4Fragment(skb, Cache->pmtu,
			/*32*/ Cache->l2blob_len,
			0 /* FALSE */, Cache->odev, &pSkb)) {
		int ulFrags = 0;

		for (; pSkb != NULL; pSkb = pTempSkb) {
			ulFrags++;
			pTempSkb = pSkb->next;
			asf_print("Next skb = 0x%p", pTempSkb);
			pSkb->next = NULL;
			iph = ip_hdr(pSkb);

			pSkb->pkt_type = PACKET_FASTROUTE;
			pSkb->asf = 1;
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
				"skb->transport_header = 0x%p",
					skb_network_header(pSkb),
					skb_transport_header(pSkb));
			asf_print("Xmiting: buffer = 0x%p dev->index = %d",
						pSkb, pSkb->dev->ifindex);
			gstats->ulOutBytes += pSkb->len;
			term_stats->ulOutBytes += pSkb->len;
			vstats->ulOutBytes += pSkb->len;
			/* TBD - why transmit out */
			if (asfDevHardXmit(pSkb->dev, pSkb) != 0) {
				asf_warn("Error in Xmit: may happen\n");
				ASFSkbFree(pSkb);
			}

		}
		gstats->ulOutPkts += ulFrags;
		vstats->ulOutPkts += ulFrags;
		term_stats->ulOutPkts += ulFrags;
	} else
		asf_print("asfIpv4Fragment returned NULL!!");

	return;
}

ASF_void_t ASFTERMProcessPkt(ASF_uint32_t	ulVsgId,
				ASF_uint32_t	ulCommonInterfaceId,
				ASFBuffer_t	Buffer,
				genericFreeFn_t	pFreeFn,
				ASF_void_t	*freeArg,
				ASF_void_t	*pIpsecOpaque
				/* Recvd from VPN In Hook */,
				ASF_boolean_t	sendOut)
{
	term_cache_t		*Cache;
	unsigned long		ulHashVal;
	int			L2blobRefresh = 0;
	struct sk_buff		*skb ;
	struct iphdr		*iph ;
	struct netdev_queue *txq = NULL;
	u16 q_idx		= 0;
	int			tot_len;
	unsigned short int	iphlen;
	unsigned short int	b_ipsec_done = 0;
	unsigned long int	*ptrhdrOffset;
	ASFNetDevEntry_t	*anDev;
	unsigned short int	*q;
	ASFTERMCacheEntryStats_t	*term_stats;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int			b_validate = 0;
	unsigned int		fragCnt;
	ASFFFPGlobalStats_t	*gstats;
	ASFFFPVsgStats_t	*vstats;
	asf_vsg_info_t		*vsgInfo;

	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id()) + ulVsgId;
	vstats->ulInPkts++;
#endif
	skb = (struct sk_buff *) Buffer.nativeBuffer;

	anDev = ASFCiiToNetDev(ulCommonInterfaceId);

	if (NULL == anDev) {
		asf_debug("CII %u doesn't appear to be valid",
			ulCommonInterfaceId);
		pFreeFn(skb);
		return;
	}

	iph = ip_hdr(skb);

	asf_print(" Pkt (%s) skb->len = %d, iph->tot_len = %d",
		sendOut ? "OUT" : "IN", skb->len, iph->tot_len);

#ifdef ASF_DEBUG_FRAME
	hexdump(skb->data - 14, skb->len + 14);
#endif

	/* If the packet is recevied from IPsec-after decryption
	Or, if the application has given it for sent out */
	if (pIpsecOpaque || sendOut) {
		if (unlikely(iph->ihl < 5)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			pFreeFn(skb);
			return;
		}

		if (unlikely(iph->version != 4)) {
			/*FIXME: call IPsec VPN IN hook so that it can submit
			the packet to AS -Currently only IPv4 Supported*/
			asf_err("Bad iph-version =%d", iph->version);
			goto drop_pkt;
		}

		tot_len = ntohs(iph->tot_len);
		if (unlikely((skb->len < tot_len)
			|| (tot_len < (iph->ihl*4)))) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			goto drop_pkt;
		}
	}

	if (sendOut) {
		if (unlikely(iph->ttl <= 1)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrTTL++;
#endif
			goto drop_pkt;
		}
	} else {
		if (unlikely(iph->ttl < 1)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrTTL++;
#endif
			goto drop_pkt;
		}
	}

	if (pIpsecOpaque) {
		asf_debug(" DECRYPTED PACKET");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		XGSTATS_INC(LocalCsumVerify);
		if (ip_fast_csum((u8 *)iph, iph->ihl)) {
			gstats->ulErrCsum++;
			XGSTATS_INC(LocalBadCsum);
			asf_debug("Decrypted Packet"\
				"Ip Checksum verification failed");
			goto drop_pkt;
		}
#endif
		if (unlikely(iph->protocol != IPPROTO_UDP)) {
			if (pFFPIpsecInVerify) {
				pFFPIpsecInVerify(ulVsgId, skb,
					anDev->ulCommonInterfaceId, NULL,
					pIpsecOpaque);
				return;
			}
			asf_err("Non supported Decrypted packet!!! ERROR!!!\n");
			goto drop_pkt;
		}
	}


#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	fragCnt = 1;
	asf_debug("SKB[0x%x] iph->frag_off[0x%x], SKBLEN[%d], TailRoom[%d]\n",
		skb, iph->frag_off, skb->len, skb->end - (skb->data+skb->len));
	asf_debug("Head_to_Tail[%d], Headroom[%d]\n",
		skb->end - skb->head, skb->data - skb->head);

	if (unlikely((iph->frag_off) & ASF_MF_OFFSET_FLAG_NET_ORDER)) {

		struct sk_buff *frag, *frag1;
		unsigned int ulBytesToCopy;
		char *ptr;

		asf_debug("Defrag Required!");
		asfterm_display_one_frag(skb);
#ifdef ASF_DEBUG
		hexdump(skb->data - 14, skb->len + 14);
#endif
		XGSTATS_INC(IpFragPkts);

		skb = asfIpv4Defrag(ulVsgId, skb, NULL, NULL, NULL, &fragCnt);
		if (!(skb)) {
			asf_debug("Skb absorbed for re-assembly ");
			return;
		}
		asfterm_display_frags(skb, "After Defrag");

		asf_debug("Defrag Completed... Now Linearizing the Fragments!");
		iph = ip_hdr(skb);
		ulBytesToCopy = iph->tot_len - skb->len;
		frag = skb_shinfo(skb)->frag_list;

#ifdef ASF_SG_SUPPORT
		 if (asfSkbFraglistToNRFrags(skb)) {
			asf_debug("asfSkbFraglistToNRFrags failed");
			goto drop_pkt;
		}
#else
		/* It has been assumed that the accumulated size of
		   all the fragments at any time will be < 1536 bytes.*/
		if (ulBytesToCopy > (skb->end - (skb->data + skb->len))) {
			asf_debug(" cann't Fit in First fragment.."\
					"Dropping all the fragments\n");
			while (frag) {
				frag1 = frag;
				frag = frag->next;
				/* Free SKB using frag1 */
				frag1->next = NULL;
				packet_kfree_skb(frag1);
			}
			goto drop_pkt;
		}
		ptr = skb->data + skb->len;
		/* Reset MF Bit */
		iph->frag_off = 0x0;
		asf_debug(" iph->tot_len %d Bytes_to_Copy %d frag_len %d",
			iph->tot_len, ulBytesToCopy, frag->len);
		while (1) {
			if ((frag) && (ulBytesToCopy > 0)) {
				frag1 = frag;
				memcpy(ptr, frag->data, frag->len);
				ptr  +=  frag->len;
				ulBytesToCopy -= frag->len;
				skb->len += frag->len;

				frag = frag->next;
				/* Free SKB using frag1 */
				frag1->next = NULL;
				packet_kfree_skb(frag1);
			} else {
				if ((frag == NULL) && (ulBytesToCopy == 0)) {
					asf_debug("Exiting routine," \
						"ulBytesToCopy = %d "\
						"skb->len= %d\n",
						ulBytesToCopy, skb->len);

					skb->tail = skb->data + skb->len;
				} else if (frag == NULL) {
					asf_err("Still need to copy: %d but " \
							"frag is NULL\r\n",
								ulBytesToCopy);
					/* TBD Do we need to free skb here?? */
					return;
				}
				break;
			}
		}
#endif
		skb_shinfo(skb)->frag_list = NULL;
		ip_send_check(iph);
		skb->ip_summed = CHECKSUM_UNNECESSARY;

		asfterm_display_frags(skb, "After Linearization");
#ifdef ASF_DEBUG
		hexdump(skb->data - 14, skb->len + 14);
#endif
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	iphlen = iph->ihl * 4;

	if (!sendOut  && (iph->protocol == IPPROTO_UDP)) {
		unsigned short int usSrcPrt;
		unsigned short int usDstPrt;

		usSrcPrt = BUFGET16((char *) (iph) + iphlen);
		usDstPrt = BUFGET16(((char *) (iph) + iphlen) + 2);

		if (usSrcPrt == ASF_IKE_SERVER_PORT
			|| usSrcPrt == ASF_IKE_NAT_FLOAT_PORT
			|| usDstPrt == ASF_IKE_SERVER_PORT
			|| usDstPrt == ASF_IKE_NAT_FLOAT_PORT) {
			if (pFFPIPSecIn &&
				pFFPIPSecIn(skb, 0, anDev->ulVSGId,
				anDev->ulCommonInterfaceId) == 0) {
				asf_debug("UDP encapsulated ESP packet"
					"(fraglist) absorbed by IPSEC-ASF\n");
				return;
			} else {
				asf_debug("Looks like IKE packet");
				goto ret_pkt_to_stk;
			}
		}
	}

	ptrhdrOffset = (unsigned long int *)(((unsigned char *) iph) + iphlen);

	Cache = asf_term_entry_lookup(iph->saddr, iph->daddr,
					*ptrhdrOffset/* ports*/, ulVsgId,
					iph->protocol, &ulHashVal);

	asf_debug("ASF: %s Hash(%d.%d.%d.%d, %d.%d.%d.%d, 0x%lx, %d, %d)"\
		" = %lx (hindex %lx) (hini 0x%lx) => %s",
		skb->dev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), *ptrhdrOffset,
		iph->protocol, ulVsgId, ulHashVal, TERM_HINDEX(ulHashVal),
		asf_term_hash_init_value, Cache ? "FOUND" : "NOT FOUND");

	if (unlikely(NULL == Cache)) {
		if (termCbFns.pFnCacheEntryNotFound) {
			ASFBuffer_t		abuf;

			abuf.nativeBuffer = skb;
			termCbFns.pFnCacheEntryNotFound(anDev->ulVSGId,
				anDev->ulCommonInterfaceId,
				abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC,
				skb, pIpsecOpaque, sendOut);
			goto exit;
		} else
			goto drop_pkt;
	}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulInPktFlowMatches++;
	vstats->ulInPktFlowMatches++;
#endif
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
	if (vsgInfo) {
		if (vsgInfo->configIdentity.ulConfigMagicNumber !=
			Cache->configIdentity.ulConfigMagicNumber) {
			asf_warn("Calling entry validate %x != %x",
			vsgInfo->configIdentity.ulConfigMagicNumber,
			Cache->configIdentity.ulConfigMagicNumber);
			b_validate = 1;
		}
		/* L2blob refersh handling for the possible change in the l2 */

		if ((!Cache->bIPsecOut || sendOut) &&
			(vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber !=
			Cache->configIdentity.l2blobConfig.ulL2blobMagicNumber)) {

			if (!Cache->configIdentity.l2blobConfig.bl2blobRefreshSent) {
				Cache->configIdentity.l2blobConfig.ulOldL2blobJiffies = jiffies;
				Cache->configIdentity.l2blobConfig.bl2blobRefreshSent = 1;
			}

			if (time_after(jiffies ,
				Cache->configIdentity.l2blobConfig.ulOldL2blobJiffies +
				ASF_MAX_OLD_L2BLOB_JIFFIES_TIMEOUT)) {
				L2blobRefresh = ASF_L2BLOB_REFRESH_DROP_PKT;
				goto gen_indications;
			}

			L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
		}
	}
#endif
#ifdef ASF_IPSEC_FP_SUPPORT
	if (pIpsecOpaque) {
		if (pFFPIpsecInVerify(ulVsgId, skb,
			anDev->ulCommonInterfaceId,
			Cache->bIPsecIn ? &Cache->ipsecInfo : NULL,
			pIpsecOpaque) != 0) {
			asf_warn("IPSEC In VerifySPD Failed");
			goto gen_indications;
		}
	}
#endif

	q = (unsigned short *) ptrhdrOffset;
	if (iph->protocol == IPPROTO_UDP) {
		XGSTATS_INC(UdpPkts);
		if (((iph->tot_len-iphlen) < 8) ||
			(ntohs(*(q + 2)) > (iph->tot_len-iphlen))) {
			/* Udp header length is invalid */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpProtoHdr++;
#endif
			asfTermSendLog(Cache, ASF_LOG_ID_INVALID_UDP_HDRLEN,
					ulHashVal);
			goto drop_pkt;
		}
	} else { /* Not a UDP packeet */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulMiscFailures++;
#endif
			goto drop_pkt;
	}

	term_stats = &Cache->stats;

	if (!sendOut/* && !Cache->bLocalTerm*/) {
		asf_debug(" SENDING PACKET UP (IPSEC=%d) Local=%d",
			pIpsecOpaque ? 1 : 0, Cache->bLocalTerm);
		if (termCbFns.pFnRcvPkt) {
			ASFBuffer_t	abuf;
			abuf.nativeBuffer = skb;

			if (term_l4_rx_csum) {
				struct udphdr	*uh;
				__sum16	check;

				skb->transport_header = skb->network_header
							+ iphlen;
				uh = (struct udphdr *)skb_transport_header(skb);
				check = uh->check;

				if (check == 0) {
					asf_debug(" UDP checksum fail =%x",
						check);
					goto drop_pkt;
				}


				uh->check = 0;
				uh->check = csum_tcpudp_magic(
						iph->saddr, iph->daddr,
						uh->len, IPPROTO_UDP,
						csum_partial((char *)uh,
						uh->len, 0));
				if (uh->check != check) {
					asf_debug(" UDP checksum fail =%x",
						check);
					goto drop_pkt;
				}
			}

			skb->pmal_ctxt = (ASF_uint32_t)Cache->as_cache_info;

			term_stats->ulInPkts++;
			term_stats->ulInBytes += (skb->mac_len + skb->len);
			/* Sending Packet to User Space */
			termCbFns.pFnRcvPkt(anDev->ulVSGId,
			anDev->ulCommonInterfaceId,
			abuf,
			(genericFreeFn_t)ASF_SKB_FREE_FUNC, skb);
			return;
		} else {
			goto ret_pkt_to_stk;
		}
	} else {
		if (term_l4_tx_csum) {
			struct udphdr	*uh;

			skb->transport_header = skb->network_header + iphlen;
			uh = (struct udphdr *)skb_transport_header(skb);

			uh->check = csum_tcpudp_magic(iph->saddr,
					iph->daddr,
					uh->len, IPPROTO_UDP,
					csum_partial((char *)uh,
					uh->len, 0));
			skb->ip_summed = CHECKSUM_COMPLETE;
		}
	}
	asf_debug_l2(" IPSEC_OUT = %d SPD=%d", Cache->bIPsecOut,
		Cache->ipsecInfo.outContainerInfo.ulSPDContainerId);

	Cache->ulLastPktInAt = jiffies;
#ifdef ASF_IPSEC_FP_SUPPORT
	if (Cache->bIPsecOut) {
		if (pFFPIPSecOut) {
			if (pFFPIPSecOut(ulVsgId,
				skb, &Cache->ipsecInfo) == 0) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				gstats->ulOutBytes += skb->len;
				vstats->ulOutBytes += skb->len;

				gstats->ulOutPkts++;
				vstats->ulOutPkts++;
#endif
				term_stats->ulOutBytes += skb->len;
				term_stats->ulOutPkts++;
				b_ipsec_done = 1;
				goto gen_indications;
			}
			asf_err("Error in IPSEC ");
		}
		goto drop_pkt;
	}
#endif /*ASF_IPSEC_FP_SUPPORT*/
	/* Else this is a non-ipsec normal packet */
	if (Cache->l2blob_len == 0) {
		asf_print("Generating L2blob Indication"
				" as Blank L2blob found!");
		L2blobRefresh = ASF_L2BLOB_REFRESH_RET_PKT_STK;
		goto gen_indications;
	}
	asf_print("L2blob Info found! out dev %p", Cache->odev);

	q_idx = skb_tx_hash(Cache->odev, skb);
	skb_set_queue_mapping(skb, q_idx);
	txq = netdev_get_tx_queue(Cache->odev, q_idx);
	if (0 == netif_tx_queue_stopped(txq)) {
		asf_print("attempting to xmit the packet");
		asf_print("----------------------------------------");
		asf_print("len = %d, data_len = %d, mac_len = %d, "
			"hdr_len = %d", skb->len, skb->data_len,
					skb->mac_len, skb->hdr_len);
		asf_print("trans_hdr = 0x%p, nw_hdr = 0x%p, "
			"mac_hdr = 0x%p", skb->transport_header,
				skb->network_header, skb->mac_header);
		asf_print("head = %p, data = %p, tail = 0x%p, "
			"end = 0x%p", skb->head, skb->data,
					skb->tail, skb->end);
		asf_print("----------------------------------------");

		/* Cache->l2blob_len > 0 && Cache->odev != NULL
		from this point onwards */
		if (((skb->len + Cache->l2blob_len) >
			(Cache->pmtu + ETH_HLEN)) ||
			(skb_shinfo(skb)->frag_list)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (iph->frag_off & IP_DF)
				goto ret_pkt_to_stk;

			/* Fragmentation Needed, so do it */
			asfFragmentAndSendPkt(Cache, skb, iph,
					term_stats, gstats, vstats);
			txq->trans_start = jiffies;
#endif
			goto gen_indications;
		}

		asf_print("decreasing TTL");
		ip_decrease_ttl(iph);
		asf_print("attempting to xmit non fragment packet");
		skb->dev = Cache->odev;
		/* Ensure there's enough head room for l2blob_len */
		/* Update the MAC address information */
		skb->len += Cache->l2blob_len;
		skb->data -= Cache->l2blob_len;
		asf_print("copy l2blob to packet (blob_len %d)",
						Cache->l2blob_len);
		asfCopyWords((unsigned int *)skb->data,
				(unsigned int *)Cache->l2blob,
				Cache->l2blob_len);
		if (Cache->bVLAN)
			skb->vlan_tci = Cache->tx_vlan_id;
		else
			skb->vlan_tci = 0;
		skb->pkt_type = PACKET_FASTROUTE;
		skb->asf = 1;

		asf_print("invoke hard_start_xmit skb-packet"
				" (blob_len %d)", Cache->l2blob_len);
		txq->trans_start = jiffies;
		if (0 != asfDevHardXmit(skb->dev, skb)) {
			asf_err("Error in transmit: may happen as "
				"we don't check for gfar free desc");
			ASFSkbFree(skb);
		}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulOutBytes += skb->len;
		vstats->ulOutBytes += skb->len;

		gstats->ulOutPkts++;
		vstats->ulOutPkts++;
#endif
		term_stats->ulOutBytes += skb->len;
		term_stats->ulOutPkts++;
	}
gen_indications:
	/* skip all other indications if entry_end indication is being sent */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	/* FlowValidate indicaion */
	if (b_validate) {
		if (!Cache->bDeleted && termCbFns.pFnValidate) {
			ASFTERMCacheValidateCbInfo_t ind;

			ind.tuple.ulSrcIp = Cache->ulSrcIp;
			ind.tuple.ulDestIp = Cache->ulDestIp;
			ind.tuple.usSrcPort = (Cache->ulPorts >> 16);
			ind.tuple.usDestPort = Cache->ulPorts&0xffff;
			ind.tuple.ucProtocol = Cache->ucProtocol;
			ind.ulHashVal = htonl(ulHashVal);
			ind.bLocalTerm = Cache->bLocalTerm;
			ind.ASTermInfo =
			(ASF_uint32_t *)Cache->as_cache_info;

			termCbFns.pFnValidate(ulVsgId, &ind);
		}
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	if (b_ipsec_done)
		return;

	/* skip all other indications if cache_end indication
	is going to be sent */
	if (unlikely(L2blobRefresh)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (!Cache->bDeleted &&
			termCbFns.pFnCacheEntryRefreshL2Blob) {
			ASFTERMCacheEntryL2BlobRefreshCbInfo_t ind;

			ind.packetTuple.ulSrcIp = Cache->ulSrcIp;
			ind.packetTuple.ulDestIp = Cache->ulDestIp;
			ind.packetTuple.usSrcPort = (Cache->ulPorts >> 16);
			ind.packetTuple.usDestPort = Cache->ulPorts&0xffff;
			ind.packetTuple.ucProtocol = Cache->ucProtocol;

			ind.ulHashVal = ulHashVal;
			ind.ASFTermInfo = (ASF_uint32_t *)Cache->as_cache_info;
			ind.Buffer.linearBuffer.buffer = NULL;
			ind.Buffer.nativeBuffer = NULL;

			termCbFns.pFnCacheEntryRefreshL2Blob(ulVsgId, &ind);
		}
		switch (L2blobRefresh) {
		case ASF_L2BLOB_REFRESH_RET_PKT_STK:
		case ASF_L2BLOB_REFRESH_DROP_PKT:
			goto drop_pkt;
			break;
		default:
			break;
		}
#endif
	}
	return;

/* Return to Slow path for further handling */
ret_pkt_to_stk:
	ASF_netif_receive_skb(skb);

exit:
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	return;

drop_pkt:
	asf_print("drop_pkt LABEL");
	ASFSkbFree(skb);
	return;
}
EXPORT_SYMBOL(ASFTERMProcessPkt);

ASF_void_t ASFTERMGetCapabilities(ASFTERMCap_t *pCap)
{
	pCap->ulMaxVSGs = term_max_vsgs;
	pCap->bBufferHomogenous = ASF_TRUE;
	pCap->bHomogenousHashAlgorithm = ASF_TRUE;
	pCap->ulHashAlgoInitVal = asf_term_hash_init_value;
	pCap->ulMaxCacheEntries = term_max_entry;
}
EXPORT_SYMBOL(ASFTERMGetCapabilities);


ASF_void_t ASFTERMSetNotifyPreference(ASF_boolean_t bEnable)
{
	asf_term_notify = bEnable;
}
EXPORT_SYMBOL(ASFTERMSetNotifyPreference);


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

ASF_uint32_t ASFTERMRuntime(
			ASF_uint32_t ulVsgId,
			ASF_uint32_t cmd,
			ASF_void_t *args,
			ASF_uint32_t ulArgslen,
			ASF_void_t *pReqIdentifier,
			ASF_uint32_t ulReqIdentifierlen)
{
	int iResult = ASFTERM_RESPONSE_FAILURE;

	asf_print("vsg %u cmd %s (%u) arg_len %u reqid_len %u (notify %d) ",
			ulVsgId, cmd2Str(cmd), cmd,
			ulArgslen, ulReqIdentifierlen,
			asf_term_notify);

	/* invalid mode - avoid creation of Caches */
	if (!ASFGetStatus()) {
		asf_print("ASF is DISABLED\n");
		return ASFTERM_RESPONSE_FAILURE;
	}
	if (!asf_ffp_check_vsg_mode(ulVsgId, termMode))
		return ASFTERM_RESPONSE_FAILURE;

	switch (cmd) {
	case ASF_TERM_CREATE_CACHE_ENTRY:
	{
		unsigned long ulHashVal = 0;
		ASFTERMCreateCacheEntryResp_t	resp;


		if (ulVsgId < term_max_vsgs)
			iResult = term_cmd_create_entry(ulVsgId,
					(ASFTERMCreateCacheEntry_t *)args,
					NULL, NULL, &ulHashVal);
		else
			iResult = ASFTERM_RESPONSE_FAILURE;

		if ((asf_term_notify == ASF_TRUE) && termCbFns.pFnRuntime) {
			memcpy(&resp.tuple, &((ASFTERMCreateCacheEntry_t *)
				args)->entry1.tuple, sizeof(resp.tuple));

			resp.ulHashVal = ulHashVal;
			resp.iResult = iResult;
			termCbFns.pFnRuntime(ulVsgId, cmd, pReqIdentifier,
				ulReqIdentifierlen, &resp, sizeof(resp));
		}
	}
	break;

	case ASF_TERM_DELETE_CACHE_ENTRY:
	{
		unsigned long ulHashVal = 0;
		ASFTERMDeleteCacheEntryResp_t resp;

		if (ulVsgId < term_max_vsgs)
			iResult = term_cmd_delete_entry(ulVsgId,
				(ASFTERMDeleteCacheEntry_t *)args,
				&ulHashVal, &resp.stats);

		if ((asf_term_notify == ASF_TRUE) && termCbFns.pFnRuntime) {
			memcpy(&resp.tuple,
				&((ASFTERMDeleteCacheEntry_t *)args)->tuple,
				sizeof(resp.tuple));

			resp.ulHashVal = ulHashVal;
			resp.iResult = (iResult == 0) ?
					ASFTERM_RESPONSE_SUCCESS :
					ASFTERM_RESPONSE_FAILURE;
			resp.ASFTermInfo = NULL;

			termCbFns.pFnRuntime(ulVsgId, cmd, pReqIdentifier,
				ulReqIdentifierlen, &resp, sizeof(resp));
			}
	}
	break;

	case ASF_TERM_UPDATE_CACHE_ENTRY:
	{
		if (ulVsgId < term_max_vsgs)
			iResult = term_cmd_update_cache(ulVsgId,
				(ASFTERMUpdateCacheEntry_t *)args);

		asf_print("mod_entry iResult %d (vsg %d) max_vsg %d",
			iResult, ulVsgId, term_max_vsgs);
		/* No confirmation sent to AS ?? */
	}
	break;

	case ASF_TERM_FLUSH_CACHE_TABLE:
		ASFTERMCleanVsg(ulVsgId);
	break;

	default:
		return ASFTERM_RESPONSE_FAILURE;
	}
	asf_print("vsg %u cmd %s (%d) - result %d", ulVsgId, cmd2Str(cmd),
								cmd, iResult);
	return iResult;
}
EXPORT_SYMBOL(ASFTERMRuntime);

ASF_void_t ASFTERMRegisterCallbackFns(ASFTERMCallbackFns_t *pFnList)
{
	termCbFns.pFnInterfaceNotFound = pFnList->pFnInterfaceNotFound;
	termCbFns.pFnVSGMappingNotFound = pFnList->pFnVSGMappingNotFound;
	termCbFns.pFnCacheEntryNotFound = pFnList->pFnCacheEntryNotFound;
	termCbFns.pFnRuntime = pFnList->pFnRuntime;
	termCbFns.pFnCacheEntryExpiry = pFnList->pFnCacheEntryExpiry;
	termCbFns.pFnCacheEntryRefreshL2Blob =
				pFnList->pFnCacheEntryRefreshL2Blob;
	termCbFns.pFnRcvPkt = pFnList->pFnRcvPkt;
	termCbFns.pFnValidate = pFnList->pFnValidate;
	termCbFns.pFnAuditLog = pFnList->pFnAuditLog;
	asf_print("Register AS response cbk 0x%p\n", termCbFns.pFnRuntime);
}
EXPORT_SYMBOL(ASFTERMRegisterCallbackFns);

/* NEW API END */
static inline int term_entry_copy_info(ASFTERMCacheEntry_t *pInfo,
							term_cache_t *Cache)
{
	Cache->ulSrcIp = pInfo->tuple.ulSrcIp;
	Cache->ulDestIp = pInfo->tuple.ulDestIp;
	Cache->ulPorts = (pInfo->tuple.usSrcPort << 16)|pInfo->tuple.usDestPort;
	Cache->ucProtocol = pInfo->tuple.ucProtocol;

	Cache->ulInacTime = pInfo->ulExpTimeout;
	Cache->bIPsecIn = pInfo->bIPsecIn;
	Cache->bIPsecOut = pInfo->bIPsecOut;
	Cache->bLocalTerm = pInfo->bLocalTerm;

	memcpy(&Cache->ipsecInfo, &pInfo->ipsecInInfo,
				sizeof(Cache->ipsecInfo));

	return ASFTERM_RESPONSE_SUCCESS;
}

/* Cache will be allocated in advance at init time
 & will be used during On Demand cleaning as a reserved
 Cache Memory */

term_cache_t	*resCache[2];
static int term_cmd_create_entry(ASF_uint32_t ulVsgId,
				ASFTERMCreateCacheEntry_t *p,
				term_cache_t **pFlow1,
				term_cache_t **pFlow2,
				unsigned long *pHashVal)
{
	term_cache_t	*entry1, *entry2;
	unsigned long	hash1, hash2;
	unsigned int  index1, index2;
	term_bucket_t	*bkt;

	entry1 = asf_term_entry_lookup(p->entry1.tuple.ulSrcIp,
		p->entry1.tuple.ulDestIp,
		(p->entry1.tuple.usSrcPort << 16) | p->entry1.tuple.usDestPort,
		ulVsgId, p->entry1.tuple.ucProtocol, &hash1);

	entry2 = asf_term_entry_lookup(p->entry2.tuple.ulSrcIp,
		p->entry2.tuple.ulDestIp,
		(p->entry2.tuple.usSrcPort << 16) | p->entry2.tuple.usDestPort,
		ulVsgId, p->entry2.tuple.ucProtocol, &hash2);

	if (entry2 || entry1) {
		asf_print("Cache entry already exist!");
		return ASFTERM_RESPONSE_FAILURE;
	}

	entry1 = term_cache_alloc();
	entry2 = term_cache_alloc();

	if (entry1 && entry2) {
		entry1->ulVsgId = ulVsgId;
		entry2->ulVsgId = ulVsgId;
		term_entry_copy_info(&p->entry1, entry1);
		term_entry_copy_info(&p->entry2, entry2);

		memcpy(&entry1->configIdentity, &p->configIdentity,
			sizeof(p->configIdentity));

		memcpy(&entry2->configIdentity, &p->configIdentity,
			sizeof(p->configIdentity));

		entry1->as_cache_info = entry2->as_cache_info = p->ASFTermInfo;
		entry1->ulLastPktInAt = entry2->ulLastPktInAt = jiffies;

		index1 = ptrIArray_add(&term_ptrary, entry1);
		if (index1 > term_ptrary.nr_entries)
			goto down;
		index2 = ptrIArray_add(&term_ptrary, entry2);
		if (index2 > term_ptrary.nr_entries)
			goto down1;

		entry1->id.ulArg1 = index1;
		entry1->id.ulArg2 = term_ptrary.pBase[index1].ulMagicNum;

		entry1->other_id.ulArg1 = index2;
		entry1->other_id.ulArg2 = term_ptrary.pBase[index2].ulMagicNum;

		memcpy(&entry2->id, &entry1->other_id, sizeof(ASFFFPFlowId_t));
		memcpy(&entry2->other_id, &entry1->id, sizeof(ASFFFPFlowId_t));

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (!entry1->bIPsecOut && !entry1->bIPsecIn
			&& !entry1->bLocalTerm) {
			asf_print("Creating l2blob timer (CacheEntry 1)");
			entry1->pL2blobTmr =
				asfTimerStart(ASF_TERM_BLOB_TMR_ID, 0,
						term_l2blob_refresh_interval,
						ulVsgId,
						entry1->id.ulArg1,
						entry1->id.ulArg2, hash1, 0);
			if (!(entry1->pL2blobTmr))
				goto down1;
		}
		if (!entry2->bIPsecOut && !entry2->bIPsecIn
			&& !entry2->bLocalTerm) {
			asf_print("Creating l2blob timer (CacheEntry 2)");
			entry1->pL2blobTmr =
				asfTimerStart(ASF_TERM_BLOB_TMR_ID, 0,
						term_l2blob_refresh_interval,
						ulVsgId,
						entry2->id.ulArg1,
						entry2->id.ulArg2, hash2, 0);
			if (!(entry1->pL2blobTmr))
				goto down2;
		}
		if (term_aging_enable && entry1->ulInacTime) {
			asf_debug_l2("creating inac timer (entry)");
			entry1->pInacRefreshTmr = asfTimerStart(
					ASF_TERM_EXPIRY_TMR_ID, 0,
					entry1->ulInacTime/4,
					entry1->ulVsgId,
					entry1->id.ulArg1,
					entry1->id.ulArg2, hash1, 0);
			if (!entry1->pInacRefreshTmr)
				goto down2;
		}
#endif
		/* insert in the table.. but l2blob_len is
		 zero meaning waiting for l2blob update */
		bkt = asf_term_bucket_by_hash(hash1);
		asf_term_cache_insert(entry1, bkt);
		entry1->bkt = bkt;
		if (pHashVal)
			*pHashVal = hash1;

		bkt = asf_term_bucket_by_hash(hash2);
		asf_term_cache_insert(entry2, bkt);
		entry2->bkt = bkt;
		asf_print("Cache entry [%p],[%p],  Hash [%lX], [%lX]",
			entry1, entry2, hash1, hash2);
		if (pHashVal)
			*pHashVal = hash1;
		if (pFlow1)
			*pFlow1 = entry1;
		if (pFlow2)
			*pFlow2 = entry2;

		return ASFTERM_RESPONSE_SUCCESS;
	}
down:

	if (entry1)
		term_cache_free(entry1);
	if (entry2)
		term_cache_free(entry2);

	asf_print("%s - Cache creation failed!");
	if (pFlow1)
		*pFlow1 = NULL;
	if (pFlow2)
		*pFlow2 = NULL;

	return ASFTERM_RESPONSE_FAILURE;
down1:
	asf_debug("entry creation failed!\n");
	ptrIArray_delete(&term_ptrary, index1, term_cache_free_rcu);
	if (entry2)
		term_cache_free(entry2);
	if (pFlow1)
		*pFlow1 = NULL;
	if (pFlow2)
		*pFlow2 = NULL;
	return ASFTERM_RESPONSE_FAILURE;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
down2:
	asf_print("%s - timer allocation failed!");
	if (entry1) {
		if (entry1->pL2blobTmr)
			asfTimerStop(ASF_TERM_BLOB_TMR_ID, 0,
					entry2->pL2blobTmr);
		if (entry1->pInacRefreshTmr)
			asfTimerStop(ASF_TERM_EXPIRY_TMR_ID, 0,
					entry1->pInacRefreshTmr);
	}

	if (entry2) {
		if (entry2->pL2blobTmr)
			asfTimerStop(ASF_TERM_BLOB_TMR_ID, 0,
					entry2->pL2blobTmr);
		if (entry2->pInacRefreshTmr)
			asfTimerStop(ASF_TERM_EXPIRY_TMR_ID, 0,
					entry2->pInacRefreshTmr);
	}

	asf_debug("entry creation failed!\n");
	ptrIArray_delete(&term_ptrary, index1, term_cache_free_rcu);
	ptrIArray_delete(&term_ptrary, index2, term_cache_free_rcu);
	return ASFTERM_RESPONSE_FAILURE;
#endif
}


static int term_cmd_delete_entry(ASF_uint32_t ulVsgId,
				ASFTERMDeleteCacheEntry_t *p,
				unsigned long *pHashVal,
				ASFTERMCacheEntryStats_t *stats)
{
	term_cache_t	*entry1, *entry2;
	term_bucket_t	*bkt1, *bkt2;
	unsigned long	hash1, hash2;
	int	rem_entry2_resources = 0;

	/* first detach the Caches */
	hash1 = ASFTERMComputeFlowHash(p->tuple.ulSrcIp, p->tuple.ulDestIp,
		(p->tuple.usSrcPort << 16) | p->tuple.usDestPort,
		ulVsgId, asf_term_hash_init_value);
	if (pHashVal)
		*pHashVal = hash1;
	bkt1 = asf_term_bucket_by_hash(hash1);

	spin_lock_bh(&bkt1->lock);
	entry1 = asf_term_entry_lookup_in_bkt_ex(&p->tuple,
					ulVsgId, (term_cache_t *)bkt1);
	if (entry1) {
		if (unlikely(entry1->bDeleted)) {
			spin_unlock_bh(&bkt1->lock);
			return ASFTERM_RESPONSE_FAILURE;
		}
		 __asf_term_cache_remove(entry1, bkt1);
		entry1->bDeleted = 1;
		spin_unlock_bh(&bkt1->lock);

		/* copy stats , required for delete response */
		term_copy_cache_stats(entry1, stats);
		entry2 = term_cache_by_id(&entry1->other_id);
		if (entry2) {
			hash2 =  ASFTERMComputeFlowHash(entry2->ulSrcIp,
					entry2->ulDestIp,
					entry2->ulPorts,
					ulVsgId, asf_term_hash_init_value);
			bkt2 = asf_term_bucket_by_hash(hash2);
			spin_lock_bh(&bkt2->lock);
			if (!entry2->bDeleted) {
				__asf_term_cache_remove(entry2, bkt2);
				entry2->bDeleted = 1;
				rem_entry2_resources = 1;
			}
			spin_unlock_bh(&bkt2->lock);
			if (rem_entry2_resources) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				if (entry2->pL2blobTmr) {
					asfTimerStop(ASF_TERM_BLOB_TMR_ID, 0,
						entry2->pL2blobTmr);
				}
				if (entry2->pInacRefreshTmr) {
					asfTimerStop(ASF_TERM_EXPIRY_TMR_ID, 0,
						entry2->pInacRefreshTmr);
				}
#endif
				ptrIArray_delete(&term_ptrary,
					entry2->id.ulArg1, term_cache_free_rcu);
			}
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (entry1->pL2blobTmr) {
			asfTimerStop(ASF_TERM_BLOB_TMR_ID, 0,
				entry1->pL2blobTmr);
		}
		if (entry1->pInacRefreshTmr) {
			asfTimerStop(ASF_TERM_EXPIRY_TMR_ID, 0,
				entry1->pInacRefreshTmr);
		}
#endif
		ptrIArray_delete(&term_ptrary, entry1->id.ulArg1,
			term_cache_free_rcu);

		return ASFTERM_RESPONSE_SUCCESS;
	}
	spin_unlock_bh(&bkt1->lock);
	return ASFTERM_RESPONSE_FAILURE;
}

static int term_cmd_update_cache(ASF_uint32_t ulVsgId,
				ASFTERMUpdateCacheEntry_t *p)
{
	term_cache_t *Cache;
	unsigned long	hash;

	Cache = asf_term_entry_lookup_by_tuple(&p->tuple, ulVsgId, &hash);
	asf_print("Cache entry [%p] found at hash [%lx]... updating it",
			Cache, hash);
	if (Cache) {
		if (p->bL2blobUpdate) {
			ASFNetDevEntry_t *dev;

			if (p->u.l2blob.ulDeviceId > term_max_ifaces) {
				asf_err("DeviceId %d > MAX %d",
					p->u.l2blob.ulDeviceId,
					term_max_ifaces);
				return ASFTERM_RESPONSE_FAILURE;
			}
			dev = ASFCiiToNetDev(p->u.l2blob.ulDeviceId);
			if (!dev) {
				asf_err("No matching iface mapping found for"
				" DeviceId %d", p->u.l2blob.ulDeviceId);
				return ASFTERM_RESPONSE_FAILURE;
			}

			if (dev->ulDevType != ASF_IFACE_TYPE_ETHER) {
				asf_err("tx iface must be of ETH type");
				return ASFTERM_RESPONSE_FAILURE;
			}

			Cache->odev = dev->ndev;

			if (p->u.l2blob.l2blobLen > ASF_MAX_L2BLOB_LEN) {
				asf_err("bloblen %d > MAX %d",
				p->u.l2blob.l2blobLen, ASF_MAX_L2BLOB_LEN);
				return ASFTERM_RESPONSE_FAILURE;
			}

			memcpy(&Cache->l2blob, p->u.l2blob.l2blob,
					p->u.l2blob.l2blobLen);
			Cache->l2blob_len = p->u.l2blob.l2blobLen;
			Cache->pmtu = (dev->ndev->mtu < p->u.l2blob.ulPathMTU) ?
					dev->ndev->mtu : p->u.l2blob.ulPathMTU;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			Cache->bVLAN = p->u.l2blob.bTxVlan;
			Cache->bPPPoE = p->u.l2blob.bUpdatePPPoELen;
			Cache->tx_vlan_id = p->u.l2blob.usTxVlanId;
			Cache->configIdentity.l2blobConfig.ulL2blobMagicNumber =
				p->u.l2blob.ulL2blobMagicNumber;
			Cache->configIdentity.l2blobConfig.bl2blobRefreshSent
								= 0;
#endif
			asf_print("L2Blob(%d) = %pM%pM...%02X%02X",
					Cache->l2blob_len,
					Cache->l2blob, Cache->l2blob+6,
					Cache->l2blob[Cache->l2blob_len-2],
					Cache->l2blob[Cache->l2blob_len-1]);
			return ASFTERM_RESPONSE_SUCCESS;
		} else if (p->bTERMConfigIdentityUpdate) {
			memcpy(&Cache->configIdentity, &p->u.termConfigIdentity,
				sizeof(Cache->configIdentity));
			return ASFTERM_RESPONSE_SUCCESS;
		} else if (p->bIPsecConfigIdentityUpdate) {
			if (p->u.ipsec.bOut) {
				memcpy(&Cache->ipsecInfo.outContainerInfo,
					&p->u.ipsec.ipsecInfo.outContainerInfo,
					sizeof(Cache->ipsecInfo.outContainerInfo));
				Cache->bIPsecOut = p->u.ipsec.bIPsecOut;
			}
			if (p->u.ipsec.bIn) {
				memcpy(&Cache->ipsecInfo.inContainerInfo,
					&p->u.ipsec.ipsecInfo.inContainerInfo,
					sizeof(Cache->ipsecInfo.inContainerInfo));
				Cache->bIPsecIn = p->u.ipsec.bIPsecIn;
			}
			return ASFTERM_RESPONSE_SUCCESS;
		}
	} else
		asf_print("Cache is not found!");

	return ASFTERM_RESPONSE_FAILURE;
}

int ASFTERMQueryCacheEntryStats(ASF_uint32_t ulVsgId,
				ASFTERMQueryCacheEntryStatsInfo_t *p)
{
	term_cache_t	*entry1, *entry2;
	int		bLockFlag, iResult;
	unsigned long	hash;

	if (!p)
		return ASFTERM_RESPONSE_FAILURE;

	ASF_RCU_READ_LOCK(bLockFlag);
	entry1 = asf_term_entry_lookup_by_tuple(&p->tuple, ulVsgId, &hash);
	if (entry1)
		entry2 = term_cache_by_id(&entry1->other_id);
	if (entry1 && entry2) {
		term_copy_cache_stats(entry1, &p->stats);
		term_copy_cache_stats(entry2, &p->other_stats);
		iResult = ASFTERM_RESPONSE_SUCCESS;
	} else {
		memset(&p->stats, 0, sizeof(p->stats));
		memset(&p->other_stats, 0, sizeof(p->other_stats));
		iResult = ASFTERM_RESPONSE_FAILURE;
	}
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return iResult;
}
EXPORT_SYMBOL(ASFTERMQueryCacheEntryStats);

unsigned int asfTermBlobTmrCb(unsigned int ulVsgId,
		unsigned int ulIndex, unsigned int ulMagicNum,
		unsigned int ulHashVal)
{
	term_cache_t *CacheEntry;

	asf_print("vsg %u hash %u CacheEntry index %d",
			ulVsgId, ulHashVal, ulIndex);

	if (ASFGetStatus()) {
		CacheEntry = term_cache_by_id_ex(ulIndex, ulMagicNum);
		if (CacheEntry) {
			if (termCbFns.pFnCacheEntryRefreshL2Blob) {
				ASFTERMCacheEntryL2BlobRefreshCbInfo_t ind;

				ind.packetTuple.ulSrcIp = CacheEntry->ulSrcIp;
				ind.packetTuple.ulDestIp = CacheEntry->ulDestIp;
				ind.packetTuple.usSrcPort =
					(CacheEntry->ulPorts >> 16);
				ind.packetTuple.usDestPort =
					CacheEntry->ulPorts & 0xffff;
				ind.packetTuple.ucProtocol =
					CacheEntry->ucProtocol;
				ind.ulHashVal = ulHashVal;
				ind.Buffer.nativeBuffer = NULL;
				ind.ASFTermInfo = (ASF_uint32_t *)
						CacheEntry->as_cache_info;

				termCbFns.pFnCacheEntryRefreshL2Blob
						(CacheEntry->ulVsgId, &ind);
			}
			return 0;
		}
		asf_print("Blob Tmr: CacheEntry not found {%p}.."
			" (might happen while Caches are being deleted)!!!",
							CacheEntry);
	} else {
		asf_print("asf not enabled: return 1.. REVIEW??");
	}
	return 0;
}


unsigned int asfTermExpiryTmrCb(unsigned int ulVSGId,
				unsigned int ulIndex,
				unsigned int ulMagicNum,
				unsigned int ulHashVal)
{
	term_cache_t *entry1, *entry2;
	term_bucket_t	*bkt;
	int	rem_entry2_resources = 0;

	asf_debug_l2("vsg %u idx %u magic %u hash %u", ulVSGId,
		ulIndex, ulMagicNum, ulHashVal);

	entry1 = term_cache_by_id_ex(ulIndex, ulMagicNum);
	if (entry1) {
		unsigned long entry1_idle, entry2_idle, ulIdleTime;

		entry2 = term_cache_by_id(&entry1->other_id);
		if (!entry2) {
			asf_debug("Other entry is not found.doing nothing!!");
			return 0;
			/*this may happen during entry deletion */
		}

		entry1_idle = ASF_LAST_IN_TO_IDLE(entry1->ulLastPktInAt);
		entry2_idle = ASF_LAST_IN_TO_IDLE(entry2->ulLastPktInAt);

		ulIdleTime = ASF_MIN(entry1_idle, entry2_idle);

		asf_print("Idle Time [%ld] MAX [%d]",
					ulIdleTime, entry1->ulInacTime);

		if (ulIdleTime >= entry1->ulInacTime) {
			asf_print("Removing Cache[%p]", entry1);
			entry1->bDeleted = 1;
			/* Delete the entry */
			bkt = (term_bucket_t *)entry1->bkt;
			spin_lock_bh(&bkt->lock);
			__asf_term_cache_remove(entry1, bkt);
			spin_unlock_bh(&bkt->lock);

			bkt = (term_bucket_t *)entry2->bkt;
			spin_lock_bh(&bkt->lock);
			if (!entry2->bDeleted) {
				__asf_term_cache_remove(entry2, bkt);
				entry2->bDeleted = 1;
				rem_entry2_resources = 1;
			}
			spin_unlock_bh(&bkt->lock);

			if (rem_entry2_resources) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				if (entry2->pL2blobTmr) {
					asfTimerStop(ASF_TERM_BLOB_TMR_ID, 0,
						entry2->pL2blobTmr);
				}
				if (entry2->pInacRefreshTmr) {
					asfTimerStop(ASF_TERM_EXPIRY_TMR_ID, 0,
						entry2->pInacRefreshTmr);
				}
#endif
				ptrIArray_delete(&term_ptrary,
					entry2->id.ulArg1, term_cache_free_rcu);
			}
			if (entry1->pL2blobTmr)
				asfTimerStop(ASF_TERM_BLOB_TMR_ID,
					0, entry1->pL2blobTmr);
			if (entry1->pInacRefreshTmr) {
				asfTimerStop(ASF_TERM_EXPIRY_TMR_ID, 0,
					entry1->pInacRefreshTmr);
			}
			/* Control layer callback */
			if (termCbFns.pFnCacheEntryExpiry) {
				ASFTERMCacheEntryExpiryCbInfo_t ind;

				ind.tuple.ulSrcIp = entry1->ulSrcIp;
				ind.tuple.ulDestIp =
						entry1->ulDestIp;
				ind.tuple.usSrcPort =
					(entry1->ulPorts >> 16);
				ind.tuple.usDestPort =
					entry1->ulPorts & 0xffff;
				ind.tuple.ucProtocol =
					entry1->ucProtocol;
				ind.ulHashVal = ulHashVal;
				term_copy_cache_stats(entry1,
							&ind.stats);
				ind.ASFTermInfo = (ASF_uint32_t *)
					entry1->as_cache_info;

				termCbFns.pFnCacheEntryExpiry(ulVSGId,
								&ind);
			}
			ptrIArray_delete(&term_ptrary, entry1->id.ulArg1,
				term_cache_free_rcu);
		}
	} else
		asf_debug("Inac Tmr: entry not found {%lu, %lu}\n",
		ulIndex, ulMagicNum);

	return 0;
}

static void asf_term_destroy_all_caches(void)
{
	int i;
	term_cache_t	*head, *Cache, *temp;

	for (i = 0; i < term_hash_buckets; i++) {
		head = (term_cache_t *) &term_cache_table[i];
		Cache = head->pNext;
		while (Cache != head) {
			temp = Cache;
			Cache = Cache->pNext;
			call_rcu((struct rcu_head *)temp,
					term_cache_destroy);
		}
	}
}

static void term_cmd_flush_table(unsigned long ulVsgId)
{
	term_bucket_t	*bkt;
	term_cache_t	*entry;
	term_cache_t *head, *temp;
	int i;

	asf_print("SoftIRQ Context [%s]..at Jiffies[0x%lu]\n",
			in_softirq() ? "YES" : "NO", jiffies);

	if (!asf_ffp_check_vsg_mode(ulVsgId, termMode))
		return;

	asf_print("Flushing VSG [%lu] Cache Table", ulVsgId);
	/* Flush only non-static entries for required VSG*/
	for (i = 0; i < term_hash_buckets; i++) {
		bkt = &term_cache_table[i];
		head = (term_cache_t *) bkt;
		spin_lock_bh(&bkt->lock);
		entry = head->pNext;
		while (entry != head) {
			temp = entry;
			entry = entry->pNext;
			if (temp->ulVsgId != ulVsgId || !temp->ulInacTime)
				continue;
			__asf_term_cache_remove(temp, bkt);
			if (temp->pL2blobTmr)
				asfTimerStop(ASF_TERM_BLOB_TMR_ID, 0,
					temp->pL2blobTmr);
			if (temp->pInacRefreshTmr)
				asfTimerStop(ASF_TERM_EXPIRY_TMR_ID, 0,
					temp->pInacRefreshTmr);
			ptrIArray_delete(&term_ptrary, temp->id.ulArg1,
				term_cache_free_rcu);
		}
		spin_unlock_bh(&bkt->lock);
	}
	return;
}

void asfTermAddTimerOn(void *tmr)
{
	struct timer_list *timer;

	timer = (struct timer_list *)tmr;
	mod_timer(timer, timer->expires);
}

static void ASFTERMCleanVsg(ASF_uint32_t ulVsgId)
{
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	struct timer_list *tmr_cpu1, *tmr_cpu2;
	int bInInterrupt = in_softirq();
	int processor_id = smp_processor_id();

	switch (num_online_cpus()) {
	case 1: /* NON-SMP */
	{
		if (bInInterrupt) {
			term_cmd_flush_table(ulVsgId);
			return;
		}

		tmr_cpu1 = &term_flush_timer[processor_id][ulVsgId];
		tmr_cpu1->expires = ASF_TERM_FLUSH_TIMER_EXPIRE;
		setup_timer(tmr_cpu1, term_cmd_flush_table,
					(unsigned long)ulVsgId);
		/* Flushing on local core */
		mod_timer(tmr_cpu1, tmr_cpu1->expires);
		return;
	}

	default:
		asf_print("SMP Mode handling\n");
		/* fall through */
	}

	tmr_cpu1 = &term_flush_timer[processor_id][ulVsgId];
	tmr_cpu2 = &term_flush_timer[!processor_id][ulVsgId];

	if (!bInInterrupt) {
		/* Switch to IRQ context to make aging
		 list manupulation Lock free */
		asf_print("Not in SoftIRQ Context.."
			" Switching at Jiffies[0x%lu]\n", jiffies);
		tmr_cpu2->expires = ASF_TERM_FLUSH_TIMER_EXPIRE;
		tmr_cpu1->expires = ASF_TERM_FLUSH_TIMER_EXPIRE;
		setup_timer(tmr_cpu1, term_cmd_flush_table,
					(unsigned long)ulVsgId);
		setup_timer(tmr_cpu2, term_cmd_flush_table,
					(unsigned long)ulVsgId);
		/* Flushing on other core */
		smp_call_function_single(!processor_id, asfTermAddTimerOn,
					tmr_cpu2, 0);
		/* Flushing on local core */
		mod_timer(tmr_cpu1, tmr_cpu1->expires);
	} else {
		asf_print("Already In SoftIRQ Context!\n");
		/* Flushing on other core */
		tmr_cpu2->expires = ASF_TERM_FLUSH_TIMER_EXPIRE;
		setup_timer(tmr_cpu2, term_cmd_flush_table,
					(unsigned long)ulVsgId);
		smp_call_function_single(!processor_id, asfTermAddTimerOn,
					tmr_cpu2, 0);
		/* Flushing on local core */
		term_cmd_flush_table(ulVsgId);
	}
#else
	term_cmd_flush_table(ulVsgId);
#endif
}

/*
 * Initialization
 */
static int asf_term_init_cache_table(void)
{
	unsigned int	max_num;
	ptrIArry_nd_t	*node;
#ifdef ASF_FFP_USE_SRAM
	dma_addr_t addr;
#endif

	get_random_bytes(&asf_term_hash_init_value,
			sizeof(asf_term_hash_init_value));
	/* 10% of actual max value */
	max_num = term_max_entry/10;
	if (asfCreatePool("TermCache", max_num,
			 max_num, (max_num/2),
			 sizeof(term_cache_t),
			 &term_cache_pool_id) != 0) {
		asf_err("failed to initialize term_cache_pool\n");
		return -ENOMEM;
	}

	if (asfCreatePool("TermBlobTimers", max_num,
			max_num, (max_num/2), sizeof(asfTmr_t),
			&term_blob_timer_pool_id)) {
		asf_err("Error in creating pool for Blob Timers\n");
		goto err1;
	}
	/* Setting up max num of Expiray timer
	as per current num of VSG */
	if (term_max_vsgs < ASF_TERM_MIN_PER_CORE_EXP_TIMER)
		max_num = (num_online_cpus() * ASF_TERM_MIN_PER_CORE_EXP_TIMER);
	else if (0 != (term_max_vsgs % 2))
		max_num = (num_online_cpus() * (term_max_vsgs + 1));
	else
		max_num = (num_online_cpus() * term_max_vsgs);

	asf_print("TermExpiryTimers count is [%d]\n", max_num);
	if (asfCreatePool("TermExpiryTimers", max_num,
			max_num, (max_num/2), sizeof(asfTmr_t),
				&term_expiry_timer_pool_id)) {
		asf_err("Error in creating pool for Inac Timers\n");
		goto err2;
	}

	asf_print("Timer : BlobTmr_PoolId= %d ExpiryTimer_PoolId = %d\r\n",
			term_blob_timer_pool_id, term_expiry_timer_pool_id);

	asf_print("Instantiating blob timer wheels\n");

	if (asfTimerWheelInit(ASF_TERM_BLOB_TMR_ID, 0,
		ASF_TERM_BLOB_TIMER_BUCKT, ASF_TMR_TYPE_SEC_TMR,
		ASF_TERM_BLOB_TIME_INTERVAL, ASF_TERM_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing L2blob Timer wheel\n");
		goto err3;
	}

	asf_print("Instantiating Cache Expiry Timer Wheels\n");

	if (asfTimerWheelInit(ASF_TERM_EXPIRY_TMR_ID, 0,
		ASF_TERM_EXPIRY_TIMER_BUCKT, ASF_TMR_TYPE_SEC_TMR,
		ASF_TERM_EXPIRY_TIME_INTERVAL, term_max_vsgs) == 1) {
		asf_err("Error in initializing Cache Timer wheel\n");
		goto err4;
	}


	/* Register the callback function and timer pool Id */
	asf_print("Register Blob Timer App\n");
	if (asfTimerAppRegister(ASF_TERM_BLOB_TMR_ID, 0, asfTermBlobTmrCb,
						term_blob_timer_pool_id)) {
		asf_err("Error in registering Cb Fn/Pool Id\n");
		goto err5;
	}

	asf_print("Register Cache Expiry Timer App\n");
	if (asfTimerAppRegister(ASF_TERM_EXPIRY_TMR_ID, 0,
			asfTermExpiryTmrCb, term_expiry_timer_pool_id)) {
		asf_err("Error in registering Cb Fn/Pool Id\n");
		goto err5;
	}
	asf_print("Initializing pointer array!\n");
	/* initialize pointer array */
	node = kzalloc((sizeof(ptrIArry_nd_t)*term_max_entry), GFP_KERNEL);

	if (NULL == node)
		goto err5;

	ptrIArray_setup(&term_ptrary, node, term_max_entry, 1);
	return 0;

err5:
	asfTimerWheelDeInit(ASF_TERM_EXPIRY_TMR_ID, 0);
err4:
	asfTimerWheelDeInit(ASF_TERM_BLOB_TMR_ID, 0);
err3:
	asfDestroyPool(term_expiry_timer_pool_id);
err2:
	asfDestroyPool(term_blob_timer_pool_id);
err1:
	asfDestroyPool(term_cache_pool_id);
	return -ENOMEM;
}

static void asf_term_destroy_cache_table(void)
{
	asf_term_destroy_all_caches();

	asf_print("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	asf_print("DeInit EXPIRY_TMR Wheel\n");
	asfTimerWheelDeInit(ASF_TERM_EXPIRY_TMR_ID, 0);
	asf_print("DeInit BLOB_TMR Wheel\n");
	asfTimerWheelDeInit(ASF_TERM_BLOB_TMR_ID, 0);

	asf_print("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	asf_print("DestroyPool ExpiryTimerPool\n");
	asfDestroyPool(term_expiry_timer_pool_id);

	asf_print("DestroyPool BlobTimerPool\n");
	asfDestroyPool(term_blob_timer_pool_id);

	asf_debug("DestroyPool TERMCachePool\n");
	asfDestroyPool(term_cache_pool_id);

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();
	/* Free the table bucket array */
#ifdef ASF_FFP_USE_SRAM
	iounmap((unsigned long *)(term_cache_table));
#else
	kfree(term_cache_table);
#endif
	/* destroy the pointer array */
	ptrIArray_cleanup(&term_ptrary);

	asf_print("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();
}


static int __init asf_term_init(void)
{
	int		i, j, num_cpus, err = -EINVAL;
	ASFCap_t	asf_cap;
#ifdef ASF_FFP_USE_SRAM
	dma_addr_t	addr;
#endif

	get_random_bytes(&rule_salt, sizeof(rule_salt));

	/* Get ASF Capabilities and store them for future use. */
	ASFGetCapabilities(&asf_cap);
	if (!(asf_cap.mode & termMode)) {
		asf_err("ASF not configured in TERM mode.... Exiting\n");
		return err;
	} else if (!asf_cap.bBufferHomogenous) {
		asf_err("No Support for Hetrogenous Buffer, ...Exiting\n");
		return err;
	}

	term_max_vsgs = asf_cap.ulNumVSGs;
	term_max_ifaces = asf_cap.ulNumIfaces;

	/* Memory Pools must have been initialized by FFP module */
	asf_print("Initializing TERM Cache & Timers Pools\n");
	err = asf_term_init_cache_table();
	if (err)
		return err;

	/* Allocate hash table */
#ifdef ASF_FFP_USE_SRAM
	addr = (unsigned long)(ASF_FFP_SRAM_BASE);
	term_cache_table = ioremap_flags(addr,
			(sizeof(term_bucket_t) * term_hash_buckets),
				PAGE_KERNEL | _PAGE_COHERENT);
#else
	term_cache_table = kzalloc((sizeof(term_bucket_t)
				* term_hash_buckets), GFP_KERNEL);
#endif

	if (term_cache_table == NULL) {
		asf_err("Memory allocatin for Hash table Failed...Exiting\n");
		return -ENOMEM;
	}
	for (i = 0; i < term_hash_buckets; i++) {
		spin_lock_init(&term_cache_table[i].lock);
		/* initialize circular list */
		term_cache_table[i].pPrev = term_cache_table[i].pNext
			= (term_cache_t *)&term_cache_table[i];
	}

	/* Allocate Aging table instance */
	num_cpus = num_online_cpus();
	for (i = 0; i < num_cpus; i++) {
		for (j = 0; j < term_max_vsgs; j++)
			/* Initialize Flush timers required
			 for context switching */
			init_timer(&term_flush_timer[i][j]);
	}
	asf_print("Per Core Per VSG Aging List Initialized\n");
	asf_term_register_proc();
	asf_print("Registered PROC entries\n");

	/* Register function pointer with ASF Main module
	to receive packet. */
	ASFFFPRegisterTERMFunctions(ASFTERMProcessPkt, ASFTERMCleanVsg);
	/* Get Statistucs pointer */
	asf_vsg_stats = get_asf_vsg_stats();
	asf_gstats = get_asf_gstats();

	/* Allocate the Reserved Cache Memory */
	resCache[0] = term_cache_alloc();
	resCache[1] = term_cache_alloc();

	return err;
}

static void __exit asf_term_exit(void)
{
	int		i, j, num_cpus;

	num_cpus = num_online_cpus();
	asf_print("Waiting for all CPUs to finish existing packets!\n");
	synchronize_rcu();

	/* De-Register function pointer with ASF Main module
	to receive packet. */
	ASFFFPRegisterTERMFunctions(NULL, NULL);
	asf_term_unregister_proc();
	/* Delete Flush timers */
	for (i = 0; i < num_cpus; i++) {
		for (j = 0; j < term_max_vsgs; j++)
			/* Delete Flush timers required for context switching */
			del_timer(&term_flush_timer[i][j]);
	}

	asf_print("Destroying existing Cache table!\n");
	term_cache_free(resCache[0]);
	term_cache_free(resCache[1]);
	asf_term_destroy_cache_table();

	asf_print("Waiting for all CPUs to finish existing packets!\n");
	synchronize_rcu();
}
module_init(asf_term_init);
module_exit(asf_term_exit);

