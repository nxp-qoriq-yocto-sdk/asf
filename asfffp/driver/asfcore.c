/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfcore.c
 *
 * Main module for ASF Core initialization and Firewall Handling.
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 * Modifier:	Sachin saxena <sachin.saxena@freescale.com>
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
 * 22 Sep 2010 - Sachin Saxena - Integrating code for IPv4 Forwarding support.
 * 30 Sep 2010 - Sachin Saxena - Changes for Per VSG flow table support.
 *
 */
/******************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/if_arp.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/crc32.h>
#include <linux/mii.h>
#include <linux/phy.h>
#include <linux/phy_fixed.h>
#include <net/xfrm.h>
#include <linux/sysctl.h>
#include <gianfar.h>

#include "gplcode.h"
#include "asf.h"
#include "asfcmn.h"
#include "asffwd.h"
#include "asfipsec.h"
#include "asfparry.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfreasm.h"
#include "asfpvt.h"
#include "asftcp.h"

MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION("Application Specific FastPath");
MODULE_LICENSE("GPL");


char *asf_version = "asf-rel-0.1.0";
/* Initilization Parameters */
int asf_enable;
int ffp_max_flows = 64*1024;
int asf_max_vsgs = ASF_MAX_VSGS;
int asf_max_ifaces = ASF_MAX_IFACES;
int ffp_hash_buckets = 8*1024;
int asf_inac_divisor = 4;
#if 0
int asf_tcp_fin_timeout = 20;
int asf_tcp_rst_timeout = 20;
#endif
int asf_l2blob_refresh_npkts = ASF_MAX_L2BLOB_REFRESH_PKT_CNT;
int asf_l2blob_refresh_interval = ASF_MAX_L2BLOB_REFRESH_TIME;
int asf_reasm_timeout = 60; /* in seconds ? */
int asf_reasm_maxfrags = 47;
int asf_reasm_min_fragsize = 28;
int asf_tcp_drop_oos;
int asf_default_mode = fwMode;
int asf_fwd_func_on;
int asf_ipsec_func_on;
extern unsigned long asf_reasm_hash_list_size;
extern unsigned long asf_reasm_num_cbs;

module_param(asf_enable, bool, 0644);
MODULE_PARM_DESC(asf_enable, "Enable or disable ASF upon loading");
module_param(ffp_max_flows, int, 0644);
MODULE_PARM_DESC(ffp_max_flows, "Maximum number of FFP flows");
module_param(asf_max_vsgs, int, 0644);
MODULE_PARM_DESC(asf_max_vsgs, "Maximum number of VSGs");
module_param(asf_max_ifaces, int, 0644);
MODULE_PARM_DESC(asf_max_ifaces, "Maximum number of interfaces");
module_param(ffp_hash_buckets, int, 0644);
MODULE_PARM_DESC(ffp_hash_buckets,
			"Number of hash buckets in FFP flow hash table");
module_param(asf_l2blob_refresh_interval, int, 0644);
MODULE_PARM_DESC(asf_l2blob_refresh_interval,
	"Periodic interval at which L2 blob refresh indication to be generated");
#if 0
module_param(asf_tcp_fin_timeout, int, 0644);
MODULE_PARM_DESC(asf_tcp_fin_timeout,
			"Inactivity timeout for a TCP flow after receiving FIN packet");
module_param(asf_tcp_rst_timeout, int, 0644);
MODULE_PARM_DESC(asf_tcp_rst_timeout,
				"Inactivity timeout for a TCP flow after receiving RST packet");
#endif
module_param(asf_tcp_drop_oos, bool, 0644);
MODULE_PARM_DESC(asf_tcp_drop_oos, "Drop TCP out of sequence packets");
#if 0
module_param(asf_l2blob_refresh_npkts, int, 0644);
MODULE_PARM_DESC(asf_l2blob_refresh_npkts, "Number of packets to be processed"
		" before generating L2 blob refresh indication");
module_param(asf_l2blob_refresh_interval, int, 0644);
MODULE_PARM_DESC(asf_l2blob_refresh_interval,
	"Periodic interval at which L2 blob refresh indication to be generated");
#endif
module_param(asf_reasm_hash_list_size, int, 0644);
MODULE_PARM_DESC(asf_reasm_hash_list_size, "Size of reassembly hash table");
module_param(asf_reasm_num_cbs, int, 0644);
MODULE_PARM_DESC(asf_reasm_num_cbs,
				"Maximum number of Reassembly context blocks per VSG");


ptrIArry_tbl_t ffp_ptrary;
ffp_bucket_t *ffp_flow_table;
spinlock_t		asf_iface_lock;
/* array of strcuture pointers indexed by common interface id */
ASFNetDevEntry_t	**asf_ifaces;
ASFFFPGlobalStats_t *asf_gstats; /* per cpu global stats */
#ifdef ASF_FFP_XTRA_STATS
ASFFFPXtraGlobalStats_t *asf_xgstats;
#endif
asf_vsg_info_t  **asf_vsg_info;
ASFFFPVsgStats_t *asf_vsg_stats; /* per cpu vsg stats */
#if 0
static unsigned long l2fw_validation_time;
#endif
static unsigned int  ffp_flow_pool_id = -1;
static unsigned int  ffp_blob_timer_pool_id = -1;
static unsigned int  ffp_inac_timer_pool_id = -1;

ASF_boolean_t   asf_ffp_notify = ASF_FALSE;
static ASFFFPCallbackFns_t      ffpCbFns = {0};

unsigned long asf_ffp_hash_init_value;

extern struct net_device *__find_vlan_dev(struct net_device *real_dev,
			u16 vlan_id);

EXPORT_SYMBOL(asf_ffp_hash_init_value);


static int asf_ffp_init_flow_table(void);
static void asf_ffp_destroy_flow_table(void);
void asf_ffp_cleanup_all_flows(void);

static int asf_ffp_devfp_rx(struct sk_buff *skb, struct net_device *dev);

#define ASF_FFP_BLOB_TIME_INTERVAL 1	/* inter bucket gap */
#define ASF_FFP_INAC_TIME_INTERVAL 1	/* inter bucket gap */
#define	ASF_FFP_NUM_RQ_ENTRIES	(256)
#define ASF_FFP_AUTOMODE_FLOW_INACTIME	(300)

#define FFP_HINDEX(hval) ASF_HINDEX(hval, ffp_hash_buckets)

/** Local functions */
static int ffp_cmd_create_flows(ASF_uint32_t  ulVsgId,
		ASFFFPCreateFlowsInfo_t *p,
		ffp_flow_t **pFlow1,
		ffp_flow_t **pFlow2,
		unsigned long *pHashVal);
static int ffp_cmd_delete_flows(ASF_uint32_t  ulVsgId,
			ASFFFPDeleteFlowsInfo_t *p,
			unsigned long *pHashVal);
static int ffp_cmd_update_flow(ASF_uint32_t ulVsgId,
			ASFFFPUpdateFlowParams_t *p);

inline ASFFFPVsgStats_t *get_asf_vsg_stats()
{
	return asf_vsg_stats;
}
EXPORT_SYMBOL(get_asf_vsg_stats);

inline ASFFFPGlobalStats_t *get_asf_gstats() /* per cpu global stats */
{
	return asf_gstats;
}
EXPORT_SYMBOL(get_asf_gstats);

#ifdef ASF_IPSEC_FP_SUPPORT
ASFFFPIPSecInv4_f   pFFPIPSecInv4;
ASFFFPIPSecOutv4_f  pFFPIPSecOutv4;
ASFFFPIPSecInVerifyV4_f  pFFPIpsecInVerifyV4;
ASFFFPIPSecProcessPkt_f pFFPIpsecProcess;

void ASFFFPRegisterIPSecFunctions(ASFFFPIPSecInv4_f   pIn,
				ASFFFPIPSecOutv4_f  pOut,
				ASFFFPIPSecInVerifyV4_f pIpsecInVerify,
				ASFFFPIPSecProcessPkt_f pIpsecProcess)
{
	pFFPIPSecInv4 = pIn;
	pFFPIPSecOutv4 = pOut;
	pFFPIpsecInVerifyV4 = pIpsecInVerify;
	pFFPIpsecProcess = pIpsecProcess;

	if (pFFPIPSecInv4 && pFFPIPSecOutv4)
		asf_ipsec_func_on = ASF_TRUE;
	else
		asf_ipsec_func_on = ASF_FALSE;
}
EXPORT_SYMBOL(ASFFFPRegisterIPSecFunctions);
#endif

#ifdef ASF_FWD_FP_SUPPORT

ASFFWDProcessPkt_f	pFwdProcessPkt;
ASFFWDCleanVsg_f	pFwdCleanVsg;

void ASFFFPRegisterFWDFunctions(
		ASFFWDProcessPkt_f pFwd,
		ASFFWDCleanVsg_f pCleanVsg)
{
	pFwdCleanVsg = pCleanVsg;

	pFwdProcessPkt = pFwd;
	if (pFwdProcessPkt)
		asf_fwd_func_on = ASF_TRUE;
	else
		asf_fwd_func_on = ASF_FALSE;
}
EXPORT_SYMBOL(ASFFFPRegisterFWDFunctions);
#endif

static __u32 rule_salt __read_mostly;

static inline unsigned long ASFFFPComputeFlowHash1(
				unsigned long ulSrcIp,
				unsigned long ulDestIp,
				unsigned long ulPorts,
				unsigned long ulVsgId,
				unsigned long ulZoneId,
				unsigned long initval)
{
	ulSrcIp += rule_salt;
	ulDestIp += JHASH_GOLDEN_RATIO;
	ulPorts += initval;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulPorts);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ulSrcIp += ulVsgId;
	ulDestIp += ulZoneId;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulPorts);
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	return rule_salt + ulPorts;
}

static inline unsigned long ASFFFPComputeFlowHashEx(
				ASFFFPFlowTuple_t *tuple,
				unsigned long ulVsgId,
				unsigned long ulZoneId,
				unsigned long initval)
{
	return ASFFFPComputeFlowHash1(tuple->ulSrcIp, tuple->ulDestIp,
		(tuple->usSrcPort << 16)|tuple->usDestPort,
		ulVsgId, ulZoneId, initval);
}


#define flow_list_for_each(pos, head) \
	for (pos = (head)->pNext; prefetch(pos->pNext), pos != (head); \
					pos = pos->pNext)

static inline ffp_bucket_t *asf_ffp_bucket_by_hash(unsigned long ulHashVal)
{
	return &ffp_flow_table[FFP_HINDEX(ulHashVal)];
}


static inline ffp_flow_t *asf_ffp_flow_lookup_in_bkt(
				unsigned long sip, unsigned long dip,
				unsigned long ports, unsigned char protocol,
				unsigned long vsg, unsigned long szone,
				ffp_flow_t *pHead)
{
	ffp_flow_t      *flow;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	for (flow = pHead->pNext; flow != pHead; flow = flow->pNext) {
		if ((flow->ulSrcIp == sip)
		&& (flow->ulDestIp == dip)
		&& (flow->ulPorts == ports)
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		&& (flow->ucProtocol == protocol)
		&& (flow->ulZoneId == szone)
		&& (flow->ulVsgId == vsg)
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			) {
			return flow;
		}
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_debug("Max (%u) scanned ... aborting search!\n", SEARCH_MAX_PER_BUCKET);
			return NULL;
		}
#endif
	}
	return NULL;
}

static inline ffp_flow_t *asf_ffp_flow_lookup_in_bkt_ex(ASFFFPFlowTuple_t *tuple,
				unsigned long ulVsgId,
				unsigned long ulZoneId,
				ffp_flow_t *pHead)
{
	return asf_ffp_flow_lookup_in_bkt(tuple->ulSrcIp, tuple->ulDestIp,
					(tuple->usSrcPort << 16)|tuple->usDestPort,
					tuple->ucProtocol,
					ulVsgId, ulZoneId, pHead);
}

/*
 * Lookups through the flows to find matching entry.
 * The argument 'head' is head of circular list (actually bucket ponter).
 */
static inline ffp_flow_t  *asf_ffp_flow_lookup(
					unsigned long sip, unsigned long dip, unsigned long ports,
					unsigned long vsg, unsigned long szone, unsigned char protocol, unsigned long *pHashVal)
{
	ffp_flow_t *flow, *pHead;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	*pHashVal = ASFFFPComputeFlowHash1(sip, dip, ports, vsg,
					szone, asf_ffp_hash_init_value);
#if 0
	printk("ASF: Hash(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)  = %lx (masked %lx) (hini 0x%lx)\n",
	       iph->saddr, iph->daddr, ports, ulVsgId, ulZoneId,
	       ulHashVal, FFP_HINDEX(ulHashVal), asf_ffp_hash_init_value);
#endif

	pHead = (ffp_flow_t *) asf_ffp_bucket_by_hash(*pHashVal);

	/*todo - check rcu flow_list_for_each(flow, pHead)
for (flow = pHead->pNext; flow != pHead; flow = rcu_deference(flow->pNext)) */
	for (flow = pHead->pNext; flow != pHead; flow = flow->pNext) {
		if ((flow->ulSrcIp == sip)
		&& (flow->ulDestIp == dip)
		&& (flow->ulPorts == ports)
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		&& (flow->ucProtocol == protocol)
		&& (flow->ulZoneId == szone)
		&& (flow->ulVsgId == vsg)
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
		) {
			return flow;
		}
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_debug("Max (%u) scanned in bucket (%d)"\
			"... aborting search!\n",
			SEARCH_MAX_PER_BUCKET, FFP_HINDEX(*pHashVal));
			return NULL;
		}
#endif
	}
	return NULL;
}

static inline ffp_flow_t *asf_ffp_flow_lookup_by_tuple(ASFFFPFlowTuple_t *tpl,
			unsigned long ulVsgId,
			unsigned long ulZoneId,
			unsigned long *pHashVal)
{
	return asf_ffp_flow_lookup(tpl->ulSrcIp, tpl->ulDestIp,
				(tpl->usSrcPort << 16)|tpl->usDestPort,
				ulVsgId, ulZoneId, tpl->ucProtocol, pHashVal);
}

static inline ffp_flow_t *ffp_flow_alloc(void)
{
	char bHeap;
	ffp_flow_t	*flow;
	ASFFFPGlobalStats_t	*gstats = asfPerCpuPtr(asf_gstats,
						smp_processor_id());

	flow = (ffp_flow_t *)  asfGetNode(ffp_flow_pool_id, &bHeap);
	if (flow) {
		/*memset(flow, 0, sizeof(*flow)); */
		gstats->ulFlowAllocs++;
		flow->bHeap = bHeap;
	} else
		gstats->ulFlowAllocFailures++;

	return flow;
}

static inline void ffp_flow_free(ffp_flow_t *flow)
{
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats,
					smp_processor_id());
	asfReleaseNode(ffp_flow_pool_id, flow, flow->bHeap);
	gstats->ulFlowFrees++;
}

static inline void __asf_ffp_flow_insert(ffp_flow_t *flow, ffp_bucket_t *bkt)
{
	ffp_flow_t *head, *temp;

	head = (ffp_flow_t *) bkt;
	temp = flow->pNext = head->pNext;
	flow->pPrev = head;
	rcu_assign_pointer(head->pNext, flow);
	temp->pPrev = flow;
}


static inline void asf_ffp_flow_insert(ffp_flow_t *flow, ffp_bucket_t *bkt)
{
	ffp_flow_t *head, *temp;

	head = (ffp_flow_t *) bkt;
	spin_lock_bh(&bkt->lock);
	temp = flow->pNext = head->pNext;
	flow->pPrev = head;
	rcu_assign_pointer(head->pNext, flow);
	temp->pPrev = flow;
	spin_unlock_bh(&bkt->lock);
}

static void ffp_flow_free_rcu(struct rcu_head *rcu)
{
	ffp_flow_t *flow = (ffp_flow_t *) rcu;
	ffp_flow_free(flow);
}

/*caller must hold the spin lock of the bucket */
static inline void __asf_ffp_flow_remove(ffp_flow_t *flow, ffp_bucket_t *bkt)
{
	flow->pNext->pPrev = flow->pPrev;
	flow->pPrev->pNext = flow->pNext;
}


static void asfNetDevFreeRcu(struct rcu_head *rcu)
{
	ASFNetDevEntry_t *iface = (ASFNetDevEntry_t *) rcu;
	if (iface->pVlanDevArray)
		kfree(iface->pVlanDevArray);
	kfree(iface);
}

ASFNetDevEntry_t *ASFCiiToNetDev(ASF_uint32_t ulCommonInterfaceId)
{
	if (ulCommonInterfaceId >= asf_max_ifaces) {
		asf_debug("CII %u is greater than MAX %u\n",
			ulCommonInterfaceId, asf_max_ifaces);
		return NULL;
	}
	return asf_ifaces[ulCommonInterfaceId];
}
EXPORT_SYMBOL(ASFCiiToNetDev);
ASFNetDevEntry_t *ASFNetDev(struct net_device *dev)
{
	ASF_uint32_t cii;
	cii = asf_cii_cache(dev);
	if (cii < asf_max_ifaces)
		return asf_ifaces[cii];
	return NULL;
}
EXPORT_SYMBOL(ASFNetDev);

#if 0
static inline void asf_ffp_flow_remove(ffp_flow_t *flow, ffp_bucket_t *bkt)
{
	spin_lock_bh(&bkt->lock);
	__asf_ffp_flow_remove(flow, bkt);
	spin_unlock_bh(&bkt->lock);
	call_rcu((struct rcu_head *)flow, ffp_flow_free_rcu);
}
#endif

static inline void ffp_copy_flow_stats(ffp_flow_t *flow, ASFFFPFlowStats_t *stats)
{
	if (flow) {
		stats->ulInPkts = htonl(flow->stats.ulInPkts);
		stats->ulOutPkts = htonl(flow->stats.ulOutPkts);
		stats->ulInBytes = htonl(flow->stats.ulInBytes);
		stats->ulOutBytes = htonl(flow->stats.ulOutBytes);
	} else
		memset(stats, 0, sizeof(*stats));
}



/*
 * skb->dev points to either ethernet device or VLAN device
 * Expect skb->data to point to start of (inner) IP header. This will be start of inner IP header in case of tunnelled packet
 * Expect skb->mac_header point to start of eth header
 * Expect skb->mac_len to include (outer_ip_hdr_ptr-eth_hdr_ptr)
 *	i.e  skb->mac_len-ETH_HLEN gives you the x_hh_len (typically PPPoE + PPP header)
 *		this should be copied to each fragment before giving it to stack
 *
 */
int asfAdjustFragAndSendToStack(struct sk_buff *skb, ASFNetDevEntry_t *anDev)
{
	struct sk_buff *pSkb, *pTempSkb;
	struct net_device *dev = skb->dev;
	unsigned char	   bPPPoE = 0;
	unsigned short	  usEthType;
	unsigned char ucL2blob[ASF_MAX_L2BLOB_LEN];
	int	     x_hh_len;

	asf_debug(" send fraglist up!\n");
	x_hh_len = skb->mac_len-ETH_HLEN;

	if (x_hh_len > 0) {
		asfCopyWords((unsigned int *) ucL2blob, (unsigned int *)(skb->mac_header + ETH_HLEN), x_hh_len);
		/* Possible combinations for PPPoE
		 *    | MAC HDR | PPPoE | PPP | IP | TCP | DATA .... |
		 *    | MAC HDR | VLAN | PPPoE | PPP | IP | TCP | DATA .... |
		 */
		usEthType = skb->protocol;
		if (usEthType == __constant_htons(ETH_P_8021Q))
			usEthType = *(unsigned short *) (ucL2blob + 2);
		if (usEthType == __constant_htons(ETH_P_PPP_SES))
			bPPPoE = 1;
	}

	/* TODO: x_hh_len can be zero meaning we are not interestd in attaching extra hardware header (i.e 802.1Q/PPPOE) */
	if (!asfIpv4Fragment(skb, anDev->ulMTU, x_hh_len, 1 /* TRUE */, dev, &pSkb)) {
		for (; pSkb != NULL; pSkb = pTempSkb) {
			int offset;

			asf_debug("For Loop: skb->len %d (x_hh_len %d)\n", pSkb->len, x_hh_len);
			pTempSkb = pSkb->next;
			asf_debug("Next skb = 0x%x\r\n", (unsigned int) pTempSkb);
			pSkb->next = NULL;

			if (x_hh_len > 0) {
				pSkb->data -= x_hh_len;
				asfCopyWords((unsigned int *) pSkb->data, (unsigned int *) ucL2blob, x_hh_len);

				pSkb->len += x_hh_len;
				if (bPPPoE) {
					struct iphdr *iph;
					iph = (struct iphdr *) (pSkb->data + x_hh_len);
					/* PPPoE packet.. Set Payload length in PPPoE header */
					*((short *)&(pSkb->data[x_hh_len-4])) = htons(ntohs(iph->tot_len) + 2);
				}
			}
			pSkb->dev = dev;
			asf_debug("For Loop (@2): skb->len %d (x_hh_len %d)\n", pSkb->len, x_hh_len);

			asf_debug("pSkb->len = 0x%x, pSkb->data = 0x%x\r\n", pSkb->len, pSkb->data);
			asf_debug("pskb->network_header = 0x%x, pskb->transport_header = 0x%x\r\n", pSkb->network_header, pSkb->transport_header);
			asf_debug("skb->ip_summed = 0x%x\r\n", pSkb->ip_summed);

			/*if (pSkb->len < 60) pSkb->len = 60;
			pSkb->protocol = eth_type_trans(pSkb, dev); */
			offset = (ntohs(((struct iphdr *) (pSkb->data))->frag_off) & IP_OFFSET) << 3;
			asf_debug("Call netif_receive_skb (frag) : skb->len %d offset %d skb->pkt_type %d skb->protocol 0x%04x data[0] = 0x%02x\n", pSkb->len, offset, pSkb->pkt_type, pSkb->protocol, pSkb->data[0]);
			if (netif_receive_skb(pSkb) == NET_RX_DROP) {
				asf_debug("Error in Submitting to NetRx: Should not happen\r\n");
			}
		}
		return 1;
	}
	return 1;
}
EXPORT_SYMBOL(asfAdjustFragAndSendToStack);

static inline int asfAdjustFragAndSendUp(struct sk_buff *skb, ASFNetDevEntry_t *anDev)
{
	struct sk_buff *pSkb, *pTempSkb;
	struct net_device *dev = skb->dev;
	ASFBuffer_t	     abuf;

	if (ffpCbFns.pFnNoFlowFound) {
		if (!asfIpv4Fragment(skb, anDev->ulMTU, 32 /* extraLen */ , 1 /* TRUE */, dev, &pSkb)) {
			for (; pSkb != NULL; pSkb = pTempSkb) {
				asf_debug("For Loop: skb->len %d\n", pSkb->len);
				pTempSkb = pSkb->next;
				pSkb->next = NULL;
				pSkb->dev = dev;
				abuf.nativeBuffer = pSkb;
				ffpCbFns.pFnNoFlowFound(anDev->ulVSGId, anDev->ulCommonInterfaceId, anDev->ulZoneId,
							abuf, ASF_SKB_FREE_FUNC, pSkb);
			}
		}
	} else {
		return asfAdjustFragAndSendToStack(skb, anDev);
	}
	return 1;
}

static inline ffp_flow_t *ffp_flow_by_id(ASFFFPFlowId_t *id)
{
	return (ffp_flow_t *) (ffp_ptrary.pBase[id->ulArg1].ulMagicNum == id->ulArg2) ? ffp_ptrary.pBase[id->ulArg1].pData : NULL;
}

static inline ffp_flow_t *ffp_flow_by_id_ex(unsigned int ulIndex, unsigned int ulMagicNum)
{
	return (ffp_flow_t *) (ffp_ptrary.pBase[ulIndex].ulMagicNum == ulMagicNum) ? ffp_ptrary.pBase[ulIndex].pData : NULL;
}

static inline void asfFfpSendLogEx(ffp_flow_t *flow, unsigned long ulMsgId, ASF_uchar8_t *aMsg, unsigned long ulHashVal)
{
	if (ffpCbFns.pFnAuditLog) {
		ASFLogInfo_t	    li;
		li.ulVSGId = flow->ulVsgId;
		li.ulMsgId = ulMsgId;
		li.aMsg = aMsg;
		li.u.fwInfo.tuple.ulSrcIp = flow->ulSrcIp;
		li.u.fwInfo.tuple.ulDestIp = flow->ulDestIp;
		/*--- Test next Two lines (for endianness also) ---*/
		li.u.fwInfo.tuple.usSrcPort = *(ASF_uint16_t *) ((ASF_uchar8_t *) &flow->ulPorts);
		li.u.fwInfo.tuple.usDestPort = *(ASF_uint16_t *) ((ASF_uchar8_t *) &flow->ulPorts + 2);
		li.u.fwInfo.tuple.ucProtocol = flow->ucProtocol;
		li.u.fwInfo.ulZoneId = flow->ulZoneId;
		li.u.fwInfo.ulHashVal = ulHashVal;
		ffpCbFns.pFnAuditLog(&li);
	}
}

static inline void asfFfpSendLog(ffp_flow_t *flow, unsigned long ulMsgId, unsigned long ulHashVal)
{
	return asfFfpSendLogEx(flow, ulMsgId, (ASF_uchar8_t *) "", ulHashVal);
}


int asf_process_ip_options(struct sk_buff *skb, struct net_device *dev, struct iphdr *iph)
{
	struct ip_options *opt;

	skb->protocol = eth_type_trans(skb, skb->dev);

	if (skb_cow(skb, skb_headroom(skb))) {
		asf_debug("IPOPT -- skb_cow failed -- drop packet\n");
		return -1;
	}

	if (skb_dst(skb) == NULL) {
		int err = ip_route_input(skb, iph->daddr, iph->saddr, iph->tos, dev);
		if (unlikely(err))
			return -1;
	}

	opt = &(IPCB(skb)->opt);
	opt->optlen = (unsigned char)(iph->ihl*4 - sizeof(struct iphdr));
	asf_debug("calling asf_ip_options_compile: skb->cb 0x%x opt 0x%x optlen %d tot_len %d\n",
		  skb->cb, opt, opt->optlen, ntohs(iph->tot_len));

	if (asf_ip_options_compile(dev_net(dev), opt, skb, iph)) {
		asf_debug("IPOPT -- options_compile failed -- drop packet\n");
		return -1;
	}
	return 0;
}
EXPORT_SYMBOL(asf_process_ip_options);
#ifdef ASF_DEBUG
void asf_display_frags(struct sk_buff *skb, char *msg)
{
	struct iphdr *iph;
	int count = 1, data_len = 0;

	asf_debug("Fragment Information (%s):\n", msg);
	iph = ip_hdr(skb);
	asf_debug(" Frag %d (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
		"skb->len %d iph->tot_len %u frag_off %u (sum %u)\n",
		count, skb->dev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
		skb->len, iph->tot_len, iph->frag_off, data_len);
	asf_debug("	   [ip_ptr 0x%x skb->data 0x%x data[0] 0x%02x"\
	"data[1] 0x%02x ]\n", iph, skb->data, skb->data[0], skb->data[1]);

	data_len = iph->tot_len;
	skb = skb_shinfo(skb)->frag_list;
	while (skb) {
		iph = ip_hdr(skb);
		count++;
		data_len += iph->tot_len;
		asf_debug(" Frag %d (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
			"skb->len %d iph->tot_len %u frag_off %u (sum %u)\n",
			count, skb->dev->name,
			NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
			skb->len, iph->tot_len, iph->frag_off, data_len);
		asf_debug("	   [ip_ptr 0x%x skb->data 0x%x data[0]"\
			"0x%02x data[1] 0x%02x ]\n",
			iph, skb->data, skb->data[0], skb->data[1]);
		skb = skb->next;
	}

}

void asf_display_one_frag(struct sk_buff *skb)
{
	struct iphdr *iph;
	unsigned char *data;
	int count = 1, data_len = 0;

	iph = ip_hdr(skb);
	data = skb->data + iph->ihl*4;
	asf_debug(" Org Frag (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
		"skb->len %d iph->tot_len %u frag_off %u\n",
		skb->dev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
		skb->len, iph->tot_len, iph->frag_off);
	asf_debug("	   [ip_ptr 0x%x data 0x%x data[0] 0x%02x data[1]"\
		"0x%02x ]\n", iph, data, data[0], data[1]);
}

void asf_display_skb_list(struct sk_buff *skb, char *msg)
{
	struct iphdr *iph;
	int count = 0, data_len = 0;

	asf_debug("Skb List (Frag) Information (%s):\n", msg);
	while (skb) {
		iph = ip_hdr(skb);
		count++;
		data_len += iph->tot_len;
		asf_debug(" Frag %d (rx %s %u.%u.%u.%u <-> %u.%u.%u.%u):"\
			"skb->len %d iph->tot_len %u frag_off %u (sum %u)\n",
			count, skb->dev->name,
			NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
			skb->len, iph->tot_len, iph->frag_off, data_len);
		asf_debug("	   [ip_ptr 0x%x skb->data 0x%x data[0]"\
			"0x%02x data[1] 0x%02x ]\n",
			iph, skb->data, skb->data[0], skb->data[1]);
		skb = skb->next;
	}

}

#else
#define asf_display_frags(skb, msg) do {} while (0)
#define asf_display_skb_list(skb, msg) do {} while (0)
#define asf_display_one_frag(skb) do {} while (0)
#endif

static int asf_ffp_devfp_rx(struct sk_buff *skb, struct net_device *real_dev)
{
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ASFFFPGlobalStats_t     *gstats;
	ASFFFPVsgStats_t	*vstats;
	int			bCsumVerify = 0;
#endif
	int			bLockFlag;
	/*struct net_device	*logical_dev;*/
	/*x_hh_len = extra hardware-header length (data b/w end
		of ETH_H to IPH) */
	int			x_hh_len, len;
	ASFNetDevEntry_t	*anDev;
	ASF_uint16_t		usEthType;
	struct iphdr		*iph;
	ASFBuffer_t		abuf;

	if (0 == asf_enable)
		return AS_FP_PROCEED;

	ASF_RCU_READ_LOCK(bLockFlag);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	ACCESS_XGSTATS();

	gstats->ulInPkts++;
#endif

	/*skb->protocol = eth_type_trans(skb, real_dev);*/

	/*This function resets skb->dev (affects VLAN device) */
	skb->protocol = eth_type_trans(skb, skb->dev);

	skb->mac_len = ETH_HLEN;
	usEthType = skb->protocol; /* *(short *)(skb->data + 12); */
	x_hh_len = 0;

	if (skb->pkt_type != PACKET_HOST) {
		/* multicast or broadcast or a packet
			received in promiscous mode */
		asf_debug("packet type (%d) is not PACKET_HOST"\
			"(skb->dev %s real_dev %s vlan_tci %u) .. return\n",
			skb->pkt_type, skb->dev->name,
			real_dev->name, skb->vlan_tci);
		goto ret_pkt;
	}

	anDev = ASFNetDev(real_dev);
	if (NULL == anDev)
		goto iface_not_found;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (real_dev != skb->dev)
		anDev = ASFGetVlanDev(anDev, skb->vlan_tci & VLAN_VID_MASK);
	if (NULL == anDev)
		goto iface_not_found;
	if (unlikely(anDev->ulVSGId == ASF_INVALID_VSG)) {
		abuf.nativeBuffer = skb;
		ffpCbFns.pFnVSGMappingNotFound(anDev->ulCommonInterfaceId, abuf, ASF_SKB_FREE_FUNC, skb);
		ASF_RCU_READ_UNLOCK(bLockFlag);
		return AS_FP_STOLEN;
	}

	/* Check if ethernet device / VLAN device is attached to a Bridge */
	if (anDev->pBridgeDev)
		anDev = anDev->pBridgeDev;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */


#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (unlikely(usEthType == __constant_htons(ETH_P_8021Q))) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *) (skb->data + x_hh_len);
		unsigned short usVlanId;

		XGSTATS_INC(VlanPkts);

		usVlanId = ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
		if (anDev->pVlanDevArray) {
			anDev = ASFGetVlanDev(anDev, usVlanId);
			if (anDev == NULL) {
				asf_debug("VLAN dev entry not found (usVlanId %u)\n", usVlanId);
				goto iface_not_found;
			}
		} else {
			asf_debug("NULL VlanDevArray (cii %u) (usVlanId %u)\n", anDev->ulCommonInterfaceId, usVlanId);
			goto iface_not_found;
		}
		/*if (anDev->pBridgeDev) anDev = anDev->pBridgeDev; */

		usEthType = vhdr->h_vlan_encapsulated_proto;
		x_hh_len += VLAN_HLEN; /* 4 bytes */
		bCsumVerify = 1;
	}

	if (unlikely(usEthType == __constant_htons(ETH_P_PPP_SES))) {

		unsigned char *poe_hdr = skb->data + x_hh_len;
		unsigned short ppp_proto, pppoe_session_id;

		XGSTATS_INC(PPPoEPkts);

		ppp_proto = *(unsigned short *) (poe_hdr + 6);
		/* PPPoE header is of 6 bytes */
		/* PPPOE: VER = 1, TYPE = 1, CODE = 0 and  PPP:_PROTO = 0x0021 (IP) */
		if ((poe_hdr[0] != 0x11) || (poe_hdr[1] != 0) ||
		    (ppp_proto != __constant_htons(0x0021))) {
			asf_debug("PPPoE traffic but not interested %02x%02x %04x\n", poe_hdr[0], poe_hdr[1], ppp_proto);
			XGSTATS_INC(PPPoEUnkPkts);
			goto ret_pkt;
		}

		pppoe_session_id = *(unsigned short *) (poe_hdr + 2);
		anDev = ASFGetPPPoEDev(anDev, pppoe_session_id);
		if (anDev == NULL) {
			asf_debug("PPPoE dev entry not found (SessId %u)\n", pppoe_session_id);
			goto iface_not_found;
		}
		asf_debug_l2("PPPoE dev entry FOUND! (SessId %u)\n", pppoe_session_id);

		x_hh_len += (8); /* 6+2 -- pppoe + ppp headers */
		usEthType = __constant_htons(ETH_P_IP);
		bCsumVerify = 1;
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	/* By now anDev, usEthType and hh_len will have proper values */
	if ((usEthType != __constant_htons(ETH_P_IP))) {
		XGSTATS_INC(NonIpPkts);
		asf_debug_l2("Non IP traffic. EthType = 0x%x\n", usEthType);
		goto ret_pkt;
	}

	skb->mac_len += x_hh_len;
	skb_set_network_header(skb, x_hh_len);
	iph = ip_hdr(skb);

	if (unlikely(iph->version != 4)) {
		goto ret_pkt;
	}

	if (unlikely(iph->ihl != 5)) {
		if (likely(iph->ihl > 5)) {
			XGSTATS_INC(IpOptPkts);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (asf_process_ip_options(skb, skb->dev, iph) < 0) {
				gstats->ulErrIpHdr++;
				XGSTATS_INC(IpOptProcFail);
				goto drop_pkt;
			}
#endif
		} else {
		/* IP Header Length is < 5... PKT HDR ERROR */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			/*asfFfpSendLog(flow,
			  ASF_LOG_ID_SHORT_IP_HDR,ulHashVal);
			TODO: there's no flow pointer */
			goto drop_pkt;
		}
	}

	len = ntohs(iph->tot_len);
	if (unlikely((skb->len < (len + x_hh_len)) || (len < (iph->ihl*4)))) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulErrIpHdr++;
#endif
		goto drop_pkt;
	}

#ifdef ASF_FWD_FP_SUPPORT
	/* If in Forwarding Mode , send packet to
	   FWD module for further processing */
	if (asf_fwd_func_on &&
		(asf_vsg_info[anDev->ulVSGId]->curMode == fwdMode)) {

		/* Checksum verification will be done by eTSEC.*/
		abuf.nativeBuffer = skb;
		pFwdProcessPkt(anDev->ulVSGId, anDev->ulCommonInterfaceId,
				abuf, ASF_SKB_FREE_FUNC, skb);
		ASF_RCU_READ_UNLOCK(bLockFlag);
		return AS_FP_STOLEN;
	}
#endif
	if (unlikely((iph->protocol != IPPROTO_TCP)
		&& (iph->protocol != IPPROTO_UDP)
#ifdef ASF_IPSEC_FP_SUPPORT
		&& (iph->protocol != IPPROTO_ESP)
#endif
		)) {
		XGSTATS_INC(NonTcpUdpPkts);
		asf_debug_l2("Non IP traffic. EthType = 0x%x\n", usEthType);
		goto ret_pkt;
	}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (unlikely(anDev->ulZoneId == ASF_INVALID_ZONE)) {
		abuf.nativeBuffer = skb;
		ffpCbFns.pFnZoneMappingNotFound(anDev->ulVSGId,
			anDev->ulCommonInterfaceId, abuf,
			ASF_SKB_FREE_FUNC, skb);
		ASF_RCU_READ_UNLOCK(bLockFlag);
		return AS_FP_STOLEN;
	}

	if (unlikely(skb->ip_summed != CHECKSUM_UNNECESSARY)) {
		if ((iph->frag_off) & ASF_MF_OFFSET_FLAG_NET_ORDER)
			bCsumVerify  = 1;
		/*
		 *  TODO: check the capability of the underlying ethernet driver
		 *  for RX checksum verification. ASF may drop all packets here
		 *  if ethernet driver other than eTSEC is used.
		 *  Or to make this generic, we can blindly go for local
		 *  checksum verification here.
		 */
		if (unlikely(bCsumVerify || (iph->ihl > 5)
			|| (iph->protocol == IPPROTO_ESP)
			|| (iph->protocol == IPPROTO_AH))) {
			XGSTATS_INC(LocalCsumVerify);
			if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl))) {
				gstats->ulErrCsum++;
				XGSTATS_INC(LocalBadCsum);
				asf_debug("Ip Checksum verification failed \n");
				goto drop_pkt;
			}
		} else {
			/* allow UDP packets with zero in checksum field */
			if (likely((iph->protocol == IPPROTO_UDP)
				&& (*(unsigned short *) (skb->data
					+ x_hh_len + iph->ihl*4 + 6) == 0))) {
				XGSTATS_INC(UdpBlankCsum);
			} else {
				XGSTATS_INC(InvalidCsum);
				gstats->ulErrCsum++;
				asf_debug("checksum error, ip->summed=%d",
					skb->ip_summed);
				goto drop_pkt;
			}
		}
	}

	if (ip_fast_csum((u8 *)iph, iph->ihl)) {
		gstats->ulErrCsum++;
		XGSTATS_INC(LocalBadCsum);
		asf_debug("Ip Checksum verification failed \r\n");
		goto drop_pkt;
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	skb->protocol = usEthType;
	/*skb->pkt_type = ?? */
	skb->data += x_hh_len;
	/* skb->len -= x_hh_len; */
	skb->len = iph->tot_len;
	skb_set_transport_header(skb, iph->ihl*4);

#ifdef ASF_IPSEC_FP_SUPPORT

	/* IPSEC IN PROCESS function call for any of following conditions
	 *   iph->protocol == ESP
	 *   udph->dport == 500 or 4500
	 *   udph->sport == 500 or 4500
	 */
/*Derive Src and Dst Ports*/

#define BUFGET16(cp)	(*(unsigned short *) (cp))

	if (iph->protocol == IPPROTO_ESP) {
		if (pFFPIPSecInv4) {
			if (pFFPIPSecInv4(skb, 0, anDev->ulVSGId,
				anDev->ulCommonInterfaceId) != 0) {
				ASF_RCU_READ_UNLOCK(bLockFlag);
				return AS_FP_STOLEN;
			}
		} else {
			XGSTATS_INC(NonTcpUdpPkts);
			asf_debug("Non IP traffic. EthType = 0x%x", usEthType);
			goto ret_pkt;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	} else if (iph->protocol == IPPROTO_UDP) {
		unsigned short int usSrcPrt;
		unsigned short int usDstPrt;

		usSrcPrt = BUFGET16((char *) (iph) + iph->ihl*4);
		usDstPrt = BUFGET16(((char *) (iph) + iph->ihl*4) + 2);

		if (usSrcPrt  ==  500 || usSrcPrt  ==  4500 ||
			usDstPrt  ==  500 || usDstPrt  ==  4500) {
			if (pFFPIPSecInv4 &&
				pFFPIPSecInv4(skb, 0, anDev->ulVSGId,
					anDev->ulCommonInterfaceId) != 0) {
				ASF_RCU_READ_UNLOCK(bLockFlag);
				return AS_FP_STOLEN;
			}
		}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	}
#endif /*ASF_IPSEC_FP_SUPPORT*/

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id()) + anDev->ulVSGId;
#endif

	abuf.nativeBuffer = skb;
	ASFFFPProcessAndSendPkt(anDev->ulVSGId,
			anDev->ulCommonInterfaceId,
			abuf, ASF_SKB_FREE_FUNC, skb, NULL);

	ASF_RCU_READ_UNLOCK(bLockFlag);
	asf_debug_l2("returning STOLEN!\n");
	return AS_FP_STOLEN;

iface_not_found:
	ASF_RCU_READ_UNLOCK(bLockFlag);
	abuf.nativeBuffer = skb;
	ffpCbFns.pFnInterfaceNotFound(abuf, ASF_SKB_FREE_FUNC, skb);
	return AS_FP_STOLEN;

ret_pkt:
	/* no frag list expected */
	netif_receive_skb(skb);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return AS_FP_STOLEN;

drop_pkt:
	kfree_skb(skb);
	asf_debug("drop_pkt LABEL\n");
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return AS_FP_STOLEN;

/*ipsec_in_proc:

	TODO--- Invoke IPsec In process function
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return AS_FP_STOLEN;
*/
}

ASF_void_t    ASFFFPProcessAndSendPkt(
				     ASF_uint32_t    ulVsgId,
				     ASF_uint32_t    ulCommonInterfaceId,
				     ASFBuffer_t     Buffer,
				     genericFreeFn_t pFreeFn,
				     ASF_void_t      *freeArg,
				     ASF_void_t      *pIpsecOpaque
				     /* pass this to VPN In Hook */
				   )
{
	struct iphdr		*iph;
	ffp_flow_t		*flow;
	unsigned long		ulHashVal;
	unsigned int		trhlen;
	unsigned int		iphlen;
	unsigned short int      *q;
	int			bL2blobRefresh = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int			bSpecialIndication = 0,
				bFlowValidate = 0;
	unsigned int		ulTcpState;
	unsigned int		fragCnt;
	asf_vsg_info_t		*vsgInfo;
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	ASFFFPVsgStats_t	*vstats;
	ASFFFPFlowStats_t	*flow_stats;
	unsigned long		ulOrgSeqNum, ulOrgAckNum, ulLogId;
	int			iRetVal;
	struct tcphdr		*ptcph;
#endif
	int			tot_len;
	unsigned long int       *ptrhdrOffset;
	unsigned long		ulZoneId;
	struct sk_buff		*skb;
	ASFNetDevEntry_t	*anDev;
	ACCESS_XGSTATS();

	skb = (struct sk_buff *) Buffer.nativeBuffer;

	anDev = ASFCiiToNetDev(ulCommonInterfaceId);

	if (NULL == anDev) {
		asf_debug("CII %u doesn't appear to be valid\n", ulCommonInterfaceId);
		dev_kfree_skb_any(skb);	/* FIXME: Use pFreeFn function ? */
		return;
	}

	ulZoneId = anDev->ulZoneId;

	/* TODO: review check for skb->len before directly accessing data */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id()) + ulVsgId;
	vstats->ulInPkts++;
#endif
	iph = ip_hdr(skb);


#ifdef ASF_IPSEC_FP_SUPPORT

	/* If the packet is recevied from IPsec-ASF, IPSEC-ASF it self will take care of
	 * submitting the packet to AS */
	/* Needed to verify checksum of the packet recieved in tunnel */
	if (pIpsecOpaque) {
		if (unlikely(iph->ihl < 5)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			dev_kfree_skb_any(skb);	/* FIXME: Use pFreeFn function ? */
			return;
		}

		/* TODO: use vpn hook to submit this packet to AS */
		if (unlikely(iph->version != 4)) {
			/*FIXME: call IPsec VPN IN hook so that it can submit
			the packet to AS */
			goto ret_pkt;
		}

		/* Do ip header length checks if the packet is received thru IPsec */
		tot_len = ntohs(iph->tot_len);
		if (unlikely((skb->len < tot_len) || (tot_len < (iph->ihl*4)))) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			goto drop_pkt;
		}

		XGSTATS_INC(LocalCsumVerify);
		if (ip_fast_csum((u8 *)iph, iph->ihl)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrCsum++;
#endif
			XGSTATS_INC(LocalBadCsum);
			asf_debug("Ip Checksum verification failed \r\n");
			goto drop_pkt;
		}

#if 0 /* todo - how to get logical incoming device ? */
		if (unlikely(iph->ihl > 5)) {
			XGSTATS_INC(IpOptPkts);
			if (asf_process_ip_options(skb, skb->dev, iph) < 0) {
				gstats->ulErrIpHdr++;
				XGSTATS_INC(IpOptProcFail);
				goto drop_pkt;
			}
		}
#endif

		if (unlikely((iph->protocol != IPPROTO_TCP)
			&& (iph->protocol != IPPROTO_UDP))) {
			if (pFFPIpsecInVerifyV4(ulVsgId, skb,
				anDev->ulCommonInterfaceId, NULL,
				pIpsecOpaque) == 0) {
				asf_debug("IPSEC must consume non UDP&TCP"\
					" packet!!!! ERROR!!!\n");
			}
			return;	/* FIXME: review! */
		}
	}
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	/* TODO: how to handle fragments received on PPPoE iface and how
	 * to remember logical device and hh_len */
	fragCnt = 1;
	if (unlikely((iph->frag_off) & ASF_MF_OFFSET_FLAG_NET_ORDER)) {
		asf_display_one_frag(skb);
		XGSTATS_INC(IpFragPkts);

		skb = asfIpv4Defrag(ulVsgId, skb, NULL, NULL, NULL, &fragCnt);
		if (!(skb)) {
			asf_debug("Skb absorbed for re-assembly \r\n");
			return;
		}
		asf_display_frags(skb, "After Defrag");

		asf_debug("Defrag Completed!\n");

		/* TODO: need to verify if all fragments belong to same security zone */

		iph = ip_hdr(skb);
		if (unlikely(skb->len < ((iph->ihl*4) + 8))) {
			/* Need to have the transport headers ready */
			asf_debug("First fragment does not have transport headers ready\n");
			if (iph->protocol == IPPROTO_UDP)
				iRetVal = asfReasmPullBuf(skb, 8, &fragCnt);
			else
				iRetVal	= asfReasmPullBuf(skb, 28, &fragCnt);

			if (iRetVal) {
				/* Failure */
				asf_debug("Could not pull in the UDP or TCP header\r\n");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				gstats->ulErrIpProtoHdr++;
#endif
				goto drop_pkt;
			}
			/* TBD */
		}
		asf_debug("DeFrag & Pull done .. proceed!! skb->len %d iph->tot_len %d fragCnt %d\n",
			  skb->len, iph->tot_len, fragCnt);
		asf_display_frags(skb, "After Pull");
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	iphlen = iph->ihl * 4;
	ptrhdrOffset = (unsigned long int *)(((unsigned char *) iph) + iphlen);

	flow = asf_ffp_flow_lookup(iph->saddr, iph->daddr,
					*ptrhdrOffset/* ports*/, ulVsgId,
					ulZoneId, iph->protocol, &ulHashVal);
#ifdef ASF_DEBUG
	asf_debug("ASF: %s Hash(%d.%d.%d.%d, %d.%d.%d.%d, 0x%lx, %d, %d)"\
		" = %lx (hindex %lx) (hini 0x%lx) => %s\n",
		skb->dev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), *ptrhdrOffset,
		ulVsgId, ulZoneId, ulHashVal, FFP_HINDEX(ulHashVal),
		asf_ffp_hash_init_value, flow ? "FOUND" : "NOT FOUND");
#endif

#ifdef ASF_IPSEC_FP_SUPPORT
	if (pIpsecOpaque /*&& pFFPIpsecInVerifyV4 */) {
		if (pFFPIpsecInVerifyV4(ulVsgId, skb,
			anDev->ulCommonInterfaceId,
			(flow && flow->bIPsecIn) ? &flow->ipsecInfo : NULL,
			pIpsecOpaque) != 0) {
			return;	/* FIXME: review! */
		}
	}
#endif

	if (flow && (iph->ttl > 1)) {

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulInPktFlowMatches++;
		vstats->ulInPktFlowMatches++;
		XGSTATS_INC(Condition1);

		flow_stats = &flow->stats;
#endif
		/* general purpose flag. This gets set when TCP connection is
		 * completed and we are waiting for FNP to delete flows. The
		 * same can be used by L2 firewall later */
		if (flow->bDrop) {
			XGSTATS_INC(bDropPkts);
			asf_debug("dropping packet as bDrop is set\n");
			goto drop_pkt;
		}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
		if (vsgInfo) {
			if (vsgInfo->configIdentity.ulConfigMagicNumber > flow->configIdentity.ulConfigMagicNumber)
				bFlowValidate = 1;
		}
#endif
		q = (unsigned short *)  ptrhdrOffset;
		if (iph->protocol == IPPROTO_UDP) {
			XGSTATS_INC(UdpPkts);
			/*TODO: review this condition
			printk("UDP: skb->len %d iph->tot_len %u iphlen %d" \
				"udph->len %d\n", skb->len, iph->tot_len,
				iphlen, ntohs(*(q + 2))); */
			if (((iph->tot_len-iphlen) < 8) ||
				(ntohs(*(q + 2)) > (iph->tot_len-iphlen))) {
				/* Udp header length is invalid */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				gstats->ulErrIpProtoHdr++;
#endif
				asfFfpSendLog(flow, ASF_LOG_ID_INVALID_UDP_HDRLEN, ulHashVal);
				goto drop_pkt;
			}
		} else if (iph->protocol == IPPROTO_TCP) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			int     optlen, tcp_data_len;
			ffp_flow_t      *oth_flow;
#endif

			XGSTATS_INC(TcpPkts);
			trhlen = ((*(ptrhdrOffset + 3) & 0xf0000000) >> 28) * 4;
			/* Invalid length check
			   Length indicated in IPhdr - header length < expected transport header length
			   Length as indicated in skb - ip hder - ethernet header < expected transport header length
			*/
			if (((ntohs(iph->tot_len)-iphlen) < trhlen) || ((iph->tot_len-iphlen) < trhlen)) {
				/* Need to add code for TCP */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				gstats->ulErrIpProtoHdr++;
#endif
				XGSTATS_INC(TcpHdrLenErr);
				asfFfpSendLog(flow, ASF_LOG_ID_INVALID_TCP_HDRLEN, ulHashVal);
				goto drop_pkt;
			}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			ptcph = (struct tcphdr *) ptrhdrOffset;
			/*optlen = ptcph->doff*4-20; */

			/* if (flow->bTcpTimeStamp && ((optlen = ptcph->doff*4-20) > 0)) */
			optlen = trhlen - 20;
			if (flow->bTcpTimeStampCheck && (optlen > 0)) {
				unsigned char *tcpopt;
				tcpopt = ((unsigned char *) (ptcph)) + 20;
				iRetVal = asfTcpProcessOptions(flow, tcpopt, optlen);
				if (iRetVal < 0) {
					asf_debug("invalid timestamp\n");
					gstats->ulErrIpProtoHdr++;
					XGSTATS_INC(TcpTimeStampErr);
					goto drop_pkt;
				}
			}

			oth_flow = ffp_flow_by_id(&flow->other_id);
			if (!oth_flow) {
				asf_debug("other flow is not found!! strange!!\n");
				goto drop_pkt;
			}

			/* TODO: consider data in fragments also */
			tcp_data_len = ntohs(iph->tot_len)-iphlen-trhlen;
			asf_debug_l2("TCP_STATE_PROC: tcp_data_len = %d\n", tcp_data_len);

			if (flow->bTcpOutOfSeqCheck) {
				ulLogId = asfTcpCheckForOutOfSeq(flow, oth_flow, ptcph, tcp_data_len);
				if (unlikely(ulLogId != ASF_LOG_ID_DUMMY)) {
					asf_debug("out of seq check failed!\n");
					asfFfpSendLog(flow, ulLogId, ulHashVal);
					gstats->ulErrIpProtoHdr++;
					XGSTATS_INC(TcpOutOfSequenceErr);
					if (asf_tcp_drop_oos)
						goto drop_pkt;
				}
			}
			asf_debug_l2("TCP_STATE_PROC: out of sequence checks finished!\n");

			ulOrgSeqNum = ntohl(ptcph->seq);
			ulOrgAckNum = ntohl(ptcph->ack_seq);
			asfTcpApplyDelta(flow, oth_flow, ptcph, ulOrgSeqNum, ulOrgAckNum);
			asf_debug_l2("TCP_STATE_PROC: applied delta to the packet\n");

			asfTcpUpdateState(flow, ulOrgSeqNum, ulOrgAckNum, ptcph, tcp_data_len);
			asf_debug_l2("TCP_STATE_PROC: updated current TCP state in the flow\n");
			iRetVal = asfTcpProcess(flow, oth_flow, ptcph);
			if (iRetVal < 0) {
				asf_debug("asfTcpProcess returned failure!\n");
				gstats->ulErrIpProtoHdr++;
				XGSTATS_INC(TcpProcessErr);
				goto drop_pkt;
			} else if (iRetVal == 1) {
				asf_debug("TCP_STATE_PROC: %s packet .. send InacRefresh indication\n",
					  ptcph->fin ? "FIN" : "RST");
				ulTcpState = (ptcph->fin) ? ASF_FFP_TCP_STATE_FIN_RCVD : ASF_FFP_TCP_STATE_RST_RCVD;
				bSpecialIndication = 1;
			} else if (iRetVal == 2) {
				ulTcpState = ASF_FFP_TCP_STATE_FIN_COMP;
				bSpecialIndication = 1;
			}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			asf_debug_l2("TCP state processing is done!\n");
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		flow_stats->ulInPkts++;
/* Only timer based L2 blob refresh  is supported in current release */
		if (asf_l2blob_refresh_npkts &&
			(flow_stats->ulInPkts % asf_l2blob_refresh_npkts) == 0) {
			asf_debug_l2("Decided to send L2Blob refresh ind based on npkts\n");
			bL2blobRefresh = 1;
		}
		flow->ulLastPktInAt = jiffies;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

#ifdef ASF_IPSEC_FP_SUPPORT
		if (pFFPIPSecOutv4) {
			if (flow->bIPsecOut) {
				if (pFFPIPSecOutv4(ulVsgId, skb, &flow->ipsecInfo) != 0) {
					goto gen_indications;
				}
			}
		}
#endif /*ASF_IPSEC_FP_SUPPORT*/

		if ((flow->l2blob_len == 0)) {
			asf_debug("Generating L2blob Indication as Blank L2blob found!\n");
			bL2blobRefresh = 1;
			goto gen_indications;
		}

		if (0 == netif_queue_stopped(flow->odev)) {
			asf_debug_l2("attempting to xmit the packet\n");
			/*skb_set_network_header(skb, hh_len); */

			if (flow->bNat) {
				XGSTATS_INC(NatPkts);
				asf_debug_l2("applying NAT\n");
				/* Update IP Checksum also */
				if (iph->saddr != flow->ulSrcNATIp) {
#ifdef ASF_DO_INC_CHECKSUM
					csum_replace4(&iph->check, iph->saddr, flow->ulSrcNATIp);
#endif
					iph->saddr = flow->ulSrcNATIp;
				}
				if (iph->daddr != flow->ulDestNATIp) {
#ifdef ASF_DO_INC_CHECKSUM
					csum_replace4(&iph->check, iph->daddr, flow->ulDestNATIp);
#endif
					iph->daddr = flow->ulDestNATIp;
				}

				*ptrhdrOffset = flow->ulNATPorts;
				skb_set_transport_header(skb, iphlen);

#if 0

				/* apply nat to all fragments */
				if (skb_shinfo(skb)->frag_list) {
					struct sk_buff *pSkb;
					struct iphdr  *pIph;
					pSkb = skb_shinfo(skb)->frag_list;

					for (; pSkb; pSkb = pSkb->next) {
						pIph = ip_hdr(pSkb);
						if (pIph->saddr != flow->ulSrcNATIp) {
							csum_replace4(&pIph->check, pIph->saddr, flow->ulSrcNATIp);
							pIph->saddr = flow->ulSrcNATIp;
						}
						if (pIph->daddr != flow->ulDestNATIp) {
							csum_replace4(&pIph->check, pIph->daddr, flow->ulDestNATIp);
							pIph->daddr = flow->ulDestNATIp;
						}
					}
				}
#endif


#ifndef ASF_DO_INC_CHECKSUM
				if (iph->ihl != 5) /* Options */
#endif
				{
					/* Hardware does not handle this, so we do incremental checksum */
					if (iph->protocol == IPPROTO_UDP) {
						q = ((unsigned short int *) ptrhdrOffset) + 3;
					} else { /*if (iph->protocol == IPPROTO_TCP) */
						q = ((unsigned short int *) ptrhdrOffset) + 8;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
						if (ulOrgSeqNum != ntohl(ptcph->seq))
							inet_proto_csum_replace4(q, skb,
										 htonl(ulOrgSeqNum), ptcph->seq, 1);

						if (ulOrgAckNum != ntohl(ptcph->ack_seq))
							inet_proto_csum_replace4(q, skb,
										 htonl(ulOrgAckNum), ptcph->ack_seq, 1);
#endif
					}

					inet_proto_csum_replace4(q, skb, flow->ulSrcIp, flow->ulSrcNATIp, 1);
					inet_proto_csum_replace4(q, skb, flow->ulDestIp, flow->ulDestNATIp, 1);
					inet_proto_csum_replace4(q, skb, flow->ulPorts, flow->ulNATPorts, 0);
				}
#ifndef ASF_DO_INC_CHECKSUM
				else {
					skb->ip_summed = CHECKSUM_PARTIAL;
				}
#endif
			} else {

#ifndef ASF_DO_INC_CHECKSUM
				if (iph->ihl != 5) /* Options */
#endif
				{
					if (iph->protocol == IPPROTO_TCP) {
						skb_set_transport_header(skb, iphlen);
						q = (unsigned short int *) ptrhdrOffset;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
						if (ulOrgSeqNum != ntohl(ptcph->seq))
							inet_proto_csum_replace4(q + 8, skb, htonl(ulOrgSeqNum), ptcph->seq, 1);
						if (ulOrgAckNum != ntohl(ptcph->ack_seq))
							inet_proto_csum_replace4(q + 8, skb, htonl(ulOrgAckNum), ptcph->ack_seq, 1);
#endif
					}
				}
			}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			/* flow->l2blob_len > 0 && flow->odev != NULL
			from this point onwards */
			if (((((skb->len + flow->l2blob_len) >
				(flow->odev->mtu + ETH_HLEN))
				&& (skb->len > flow->pmtu))) ||
				(skb_shinfo(skb)->frag_list)) {
				struct sk_buff *pSkb, *pTempSkb;

				XGSTATS_INC(FragAndXmit);

				if (iph->frag_off & IP_DF)
					goto ret_pkt_to_stk;

				/* Need to call fragmentation routine */
				asf_debug("attempting to fragment and xmit\n");

				if (!asfIpv4Fragment(skb,
						     (flow->odev->mtu < flow->pmtu ?
						      skb->dev->mtu : flow->pmtu), /*32*/ flow->l2blob_len,
						     0 /* FALSE */, flow->odev, &pSkb)) {
					int ulFrags = 0;
					/* asf_display_frags(pSkb, "Before Xmit");*/
					asf_display_skb_list(pSkb, "Before Xmit");
					for (; pSkb != NULL; pSkb = pTempSkb) {
						ulFrags++;
						pTempSkb = pSkb->next;
						asf_debug("Next skb = 0x%x\r\n", pTempSkb);
						pSkb->next = NULL;
						iph = ip_hdr(pSkb);

						pSkb->pkt_type = PACKET_FASTROUTE;

						/* make following unconditional*/
						if (flow->bVLAN)
							pSkb->vlan_tci = flow->tx_vlan_id;
						else
							pSkb->vlan_tci = 0;

						/* TODO: No need to call ip_decrease_ttl? why? */
						ip_decrease_ttl(iph);

						pSkb->data -= flow->l2blob_len;
						pSkb->len += flow->l2blob_len;
#if 1

						if (pSkb->data < pSkb->head) {
							printk("SKB's head > data ptr .. UNDER PANIC!!!\n");
							kfree_skb(pSkb);
							continue;
						}
#endif

						pSkb->dev = flow->odev;

						asfCopyWords((unsigned int *)pSkb->data, (unsigned int *)flow->l2blob, flow->l2blob_len);
						if (flow->bPPPoE) {
							/* PPPoE packet.. Set Payload length in PPPoE header */
							*((short *)&(pSkb->data[flow->l2blob_len-4])) = htons(ntohs(iph->tot_len) + 2);
						}

						asf_debug("skb->network_header = 0x%x, skb->transport_header = 0x%x\r\n",
							  skb_network_header(pSkb), skb_transport_header(pSkb));
						asf_debug("Transmitting  buffer = 0x%x dev->index = %d\r\n",
							  pSkb, pSkb->dev->ifindex);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
						gstats->ulOutBytes += pSkb->len;
						flow_stats->ulOutBytes += pSkb->len;
						vstats->ulOutBytes += pSkb->len;
#endif
						if (asfDevHardXmit(pSkb->dev, pSkb) != 0) {
							asf_debug("Error in transmit: Should not happen\r\n");
							kfree_skb(pSkb);
						}

					}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
					gstats->ulOutPkts += ulFrags;
					vstats->ulOutPkts += ulFrags;
					flow_stats->ulOutPkts += ulFrags;
#endif
				} else {
					printk("asfcore.c:%d - asfIpv4Fragment returned NULL!!\n", __LINE__);
				}
				goto gen_indications;
			}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			XGSTATS_INC(NormalXmit);
			asf_debug_l2("decreasing TTL\n");
			ip_decrease_ttl(iph);

			asf_debug_l2("attempting to xmit non"
						" fragment packet\n");
			skb->dev = flow->odev;
			/* FIXME: ensure there's enough head room for flow->l2blob_len */
			/* Update the MAC address information */
			skb->len += flow->l2blob_len;
			skb->data -= flow->l2blob_len;
			asf_debug_l2("copy l2blob to packet (blob_len %d)\n",
				flow->l2blob_len);
			asfCopyWords((unsigned int *)skb->data,
				(unsigned int *)flow->l2blob, flow->l2blob_len);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (flow->bPPPoE) {
				/* PPPoE packet..
				 * Set Payload length in PPPoE header */
				*((short *)&(skb->data[flow->l2blob_len-4])) =
				htons(ntohs(iph->tot_len) + 2);
			}
#endif  /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			skb->pkt_type = PACKET_FASTROUTE;
			skb->asf = 1;
			if (flow->bVLAN)
				skb->vlan_tci = flow->tx_vlan_id;
			else
				skb->vlan_tci = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulOutBytes += skb->len;
			flow_stats->ulOutBytes += skb->len;
			vstats->ulOutBytes += skb->len;
#endif

			asf_debug_l2("invoke hard_start_xmit skb-packet (blob_len %d)\n", flow->l2blob_len);
			if (asfDevHardXmit(skb->dev, skb)) {
				XGSTATS_INC(DevXmitErr);
				asf_debug("Error in transmit: may happen as we don't check for gfar free desc\n");
				kfree_skb(skb);
			}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulOutPkts++;
			vstats->ulOutPkts++;
			flow_stats->ulOutPkts++;
#endif

gen_indications:
			/* skip all other indications if flow_end indication is going to be sent */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (bSpecialIndication) {
				/*XGSTATS_INC(FlowSpecialInd);*/
				 /* TODO: must always be present? */
				if (ffpCbFns.pFnFlowTcpSpecialPkts) {
					ASFFFPFlowSpecialPacketsInfo_t  ind;
					ffp_flow_t		      *oth_flow;

					ind.tuple.ulSrcIp = flow->ulSrcIp;
					ind.tuple.ulDestIp = flow->ulDestIp;
					ind.tuple.usSrcPort = (flow->ulPorts >> 16);
					ind.tuple.usDestPort = flow->ulPorts&0xffff;
					ind.tuple.ucProtocol = flow->ucProtocol;
					ind.ulZoneId = flow->ulZoneId;
					ind.ulHashVal = htonl(ulHashVal);

					/* TODO: what about ASFwInfo */
					ind.ASFwInfo = (ASF_uint8_t *)flow->as_flow_info;
					ind.ulTcpState = ulTcpState;

					oth_flow = ffp_flow_by_id(&flow->other_id);

					ffp_copy_flow_stats(flow, &ind.flow_stats);
					if (oth_flow)
						ffp_copy_flow_stats(oth_flow, &ind.other_stats);
					else
						memset(&ind.other_stats, 0, sizeof(ind.other_stats));

					if (flow->pInacRefreshTmr)
						asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID,
								0, flow->pInacRefreshTmr);

					if (oth_flow && oth_flow->pInacRefreshTmr)
						asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID,
								0, oth_flow->pInacRefreshTmr);

					ffpCbFns.pFnFlowTcpSpecialPkts(ulVsgId, &ind);
				}
			}
			/* TODO: FlowValidate indicaion? */
			if (bFlowValidate) {
				if (!flow->bDeleted && ffpCbFns.pFnFlowValidate) {
					ASFFFPFlowValidateCbInfo_t  ind;

					ind.tuple.ulSrcIp = flow->ulSrcIp;
					ind.tuple.ulDestIp = flow->ulDestIp;
					ind.tuple.usSrcPort = (flow->ulPorts >> 16);
					ind.tuple.usDestPort = flow->ulPorts&0xffff;
					ind.tuple.ucProtocol = flow->ucProtocol;
					ind.ulZoneId = flow->ulZoneId;
					ind.ulHashVal = htonl(ulHashVal);

					/* TODO: what about ASFwInfo */
					ind.ASFwInfo =
					(ASF_uint8_t *)flow->as_flow_info;

					ffpCbFns.pFnFlowValidate(ulVsgId, &ind);
				}
			}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

			if (bL2blobRefresh) {
				if (!flow->bDeleted && ffpCbFns.pFnFlowRefreshL2Blob) {
					ASFFFPFlowL2BlobRefreshCbInfo_t  ind;

					ind.flowTuple.ulSrcIp = flow->ulSrcIp;
					ind.flowTuple.ulDestIp = flow->ulDestIp;
					ind.flowTuple.usSrcPort = (flow->ulPorts >> 16);
					ind.flowTuple.usDestPort = flow->ulPorts&0xffff;
					ind.flowTuple.ucProtocol = flow->ucProtocol;

					if (flow->bNat) {
						ind.packetTuple.ulSrcIp = flow->ulSrcNATIp;
						ind.packetTuple.ulDestIp = flow->ulDestNATIp;
						ind.packetTuple.usSrcPort = (flow->ulNATPorts >> 16);
						ind.packetTuple.usDestPort = flow->ulNATPorts&0xffff;
						ind.packetTuple.ucProtocol = flow->ucProtocol;
					} else
						ind.packetTuple	= ind.flowTuple;

					ind.ulZoneId = flow->ulZoneId;

					ind.ulHashVal = ulHashVal;

					ind.Buffer.linearBuffer.buffer = NULL;
					ind.Buffer.linearBuffer.ulBufLen = 0;
					ind.Buffer.nativeBuffer = NULL;

					/* TODO: what to do with ASFwInfo field */
					ind.ASFwInfo = NULL;

					XGSTATS_INC(PktCtxL2blobInd);
					ffpCbFns.pFnFlowRefreshL2Blob(ulVsgId, &ind);
				}
				goto ret_pkt_to_stk;
			}
			return;
		} else {
			XGSTATS_INC(NetIfQStopped);
			/* drop the packet here */
			/* TODO: incr some error counter */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			flow_stats->ulInPkts--;
#endif
			goto drop_pkt;
		}
	} else {
		XGSTATS_INC(Condition2);
		asf_debug("ELSE case: flow = 0x%x iph->ver %d h_dest[0]&0x01 ="\
			"%d iph->ttl %d\n",
			flow, iph->version, skb->data[0] & 0x01, iph->ttl);

		if (flow) {
			/* If Flow exist then only case left is TTL <= 1,
			So not check is required */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrTTL++;
#endif
			goto drop_pkt;
		} /* Else continue with return packet to stack */
		asf_debug_l2("defaulting to ret_pkt_to_stk code in else case");
	}
	/* continue with ret_pkt_to_stk labelled code */

ret_pkt_to_stk:
	asf_debug_l2("ret_pkt_to_stk LABEL\n");
	if (skb_shinfo(skb)->frag_list) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulPktsToFNP++;
#endif
		/*TODO: count frags */
		asfAdjustFragAndSendUp(skb, anDev);
		return;
	}
	/* proceed with ret_pkt labelled code for non-frag pkt */

ret_pkt:
	if (ffpCbFns.pFnNoFlowFound) {
		ASFBuffer_t	abuf;

		abuf.nativeBuffer = skb;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulPktsToFNP++;
#endif
		ffpCbFns.pFnNoFlowFound(anDev->ulVSGId,
			anDev->ulCommonInterfaceId, anDev->ulZoneId,
			abuf, ASF_SKB_FREE_FUNC, skb);
		return;
	}
	/* no frag list expected */
	asf_debug_l2("ret_pkt LABEL\n");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (skb->mac_len != ETH_HLEN) {
		/*
		 * This should not happen in general.. might happen if this packet is de-tunnelled.
		 * However asf-IPsec takes care of pushing de-tunnelled packet to AS on its own.
		 */
		int x_hh_len;
		ASF_uint16_t    usEthType;

		asf_debug_l2("   ret_pkt LABEL : need to adjust! (ethType 0x%04x)\n", skb->protocol);

		/* TODO: Adjust PPPoE len if necessary */
		skb->protocol = *(unsigned short *) (skb->mac_header + 12);
		usEthType = skb->protocol;
		if (usEthType == __constant_htons(ETH_P_8021Q))
			usEthType = *(unsigned short *) (skb->mac_header + ETH_HLEN + 2);

		x_hh_len = skb->mac_len-ETH_HLEN;
		asf_debug_l2("   ret_pkt LABEL : adjust using x_hh_len %d! (ethType 0x%04x\n", x_hh_len, usEthType);
		if ((x_hh_len < 0) || (x_hh_len > (ASF_MAX_L2BLOB_LEN-ETH_HLEN))) {
			asf_debug("   ret_pkt LABEL : invalid x_hh_len... drop the packet!\n");
			goto drop_pkt;
		}
		skb->data -= x_hh_len;
		skb->len += x_hh_len;

		if (skb->data != (skb->mac_header + ETH_HLEN))
			memcpy(skb->data, skb->mac_header + ETH_HLEN, x_hh_len);

		if (usEthType == __constant_htons(ETH_P_PPP_SES)) {
			struct iphdr *iph;
			iph = (struct iphdr *) (skb->data + x_hh_len);
			/* PPPoE packet.. Set Payload length in PPPoE header */
			asf_debug_l2("   Adjust PPPOE len (old %u) to %u\n", *((short *)  &(skb->data[x_hh_len-4])),  htons(ntohs(iph->tot_len) + 2));

			*((short *)  &(skb->data[x_hh_len-4])) = htons(ntohs(iph->tot_len) + 2);
		}
		skb_set_mac_header(skb, -ETH_HLEN);
		skb->mac_len = ETH_HLEN;
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	asf_debug_l2("  ret_pkt LABEL -- calling netif_receive_skb!\n");
	netif_receive_skb(skb);
	asf_debug_l2("  ret_pkt LABEL -- returning from function!\n");
	return;


drop_pkt:
	asf_debug_l2("drop_pkt LABEL\n");
	/* TODO: we may have to iterate through frag_list and free all of them*/
	/* TODO: ensure all fragments are also dropped. and return STOLEN
	 always return stolen?? */
	dev_kfree_skb_any(skb);	/*FIXME: what about pFreeFn ? */
	return;
}
EXPORT_SYMBOL(ASFFFPProcessAndSendPkt);


unsigned int asf_ffp_check_vsg_mode(ASF_uint32_t ulVSGId, ASF_Modes_t mode)
{
	if (ulVSGId >= asf_max_vsgs)
		return ASF_FALSE;

	if (asf_vsg_info[ulVSGId]) {
		if (asf_vsg_info[ulVSGId]->curMode == mode)
			return ASF_TRUE;
		else
			return ASF_FALSE;
	}

	/*if default mdoe is also same than is also ok. as it will create new
	vsg entry with default mode. */
	if (asf_default_mode == mode)
		return ASF_TRUE;

	return ASF_FALSE;
}
EXPORT_SYMBOL(asf_ffp_check_vsg_mode);

asf_vsg_info_t *asf_ffp_get_vsg_info_node(ASF_uint32_t ulVSGId)
{
	asf_vsg_info_t  *vsg;

	if (ulVSGId >= asf_max_vsgs)
		return NULL;
	if (asf_vsg_info[ulVSGId])
		return asf_vsg_info[ulVSGId];
	vsg = kzalloc(sizeof(asf_vsg_info_t), GFP_KERNEL);
	if (!vsg)
		return NULL;

	/* fill defaults */
	vsg->ulReasmMaxFrags = asf_reasm_maxfrags;
	vsg->ulReasmMinFragSize = asf_reasm_min_fragsize;
	vsg->ulReasmTimeout = asf_reasm_timeout;
	vsg->bDropOutOfSeq = asf_tcp_drop_oos;
	vsg->curMode = asf_default_mode;
	vsg->bIPsec = 0;
	asf_vsg_info[ulVSGId] = vsg;
	return vsg;
}

ASF_void_t  ASFGetCapabilities(ASFCap_t *pCap)
{
	pCap->ulNumVSGs = asf_max_vsgs;
	pCap->ulNumIfaces = asf_max_ifaces;
	pCap->bBufferHomogenous = 1;
	pCap->mode[fwMode] = 1;
	pCap->mode[fwdMode] = 1;
	pCap->func.bIPsec = 1;
}
EXPORT_SYMBOL(ASFGetCapabilities);

struct net_device *ASFFFPGetDeviceInterface(ASF_uint32_t ulDeviceId)
{
	ASFNetDevEntry_t  *dev;
	dev = asf_ifaces[ulDeviceId];
	if (!dev) {
		return NULL;
	}
	return  dev->ndev;
}
EXPORT_SYMBOL(ASFFFPGetDeviceInterface);

ASF_uint32_t ASFMapInterface (ASF_uint32_t ulCommonInterfaceId, ASFInterfaceInfo_t *asfInterface)
{
	ASFInterfaceInfo_t      *info = asfInterface;
	ASFNetDevEntry_t	*dev;

	asf_debug(" begin cii %u type %u\n", ulCommonInterfaceId, info->ulDevType);

	if (ulCommonInterfaceId >= asf_max_ifaces) {
		asf_debug("CII %u is greater than MAX %u\n", ulCommonInterfaceId, asf_max_ifaces);
		return ASF_FAILURE;
	}

	if (info->ulDevType >= ASF_IFACE_TYPE_MAX) {
		asf_debug("DevType %u is invalid\n", info->ulDevType);
		return ASF_FAILURE;
	}

	if (asf_ifaces[ulCommonInterfaceId]) {
		asf_debug("CII %d (type %d) is already present (should we update??)\n",
			  ulCommonInterfaceId,
			  asf_ifaces[ulCommonInterfaceId]->ulDevType);

		return ASF_FAILURE;
	}

	dev = (ASFNetDevEntry_t *)  kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		asf_debug("failed allocate memory for ASFNetDevEntry_t\n");
		return ASF_FAILURE;
	}

	spin_lock_bh(&asf_iface_lock);
	dev->ulCommonInterfaceId = ulCommonInterfaceId;
	dev->ulDevType = info->ulDevType;
	dev->ulMTU = info->ulMTU;
	dev->ulVSGId = ASF_INVALID_VSG;
	dev->ulZoneId = ASF_INVALID_ZONE;
	switch (dev->ulDevType) {
	case ASF_IFACE_TYPE_ETHER:
		{
			struct net_device  *ndev;
			int found = 0;
			asf_debug("MAP REQ ETHER cii %u mac %pM ptr 0x%x\n",
				  ulCommonInterfaceId, info->ucDevIdentifierInPkt, info->ucDevIdentifierInPkt);
			/*
			 * Device identifier must have ethernet port number.
			 * eg: 0 for eth0, 1 for eth1 etc.
			 */
			if (info->ulDevIdentiferInPktLen != 6) {
				asf_debug("Invalid DevIdLen %d for ETHER iface type\n", info->ulDevIdentiferInPktLen);
				goto free_and_ret_err;
			}
			read_lock_bh(&dev_base_lock);
			for_each_netdev(&init_net, ndev) {
				/*FIXME: avoid alias interfaces here */
				if ((ndev->type == ARPHRD_ETHER) && (info->ulDevIdentiferInPktLen == ndev->addr_len)) {
					if (!memcmp(ndev->dev_addr, info->ucDevIdentifierInPkt, ndev->addr_len)) {
						asf_debug("ETHER iface found %s with mac %pM req-mac %pM\n",
							  ndev->name,
							  ndev->dev_addr, info->ucDevIdentifierInPkt);
						found = 1;
						break;
					}
				}
			}
			read_unlock_bh(&dev_base_lock);
			if (!found) {
				asf_debug("Ethernet device with hwaddr %pM not found\n", info->ucDevIdentifierInPkt);
				goto free_and_ret_err;
			}

			/* Cache common interface ID in net_device pointer for ETHER interfaces
			 * FIXME: avoid using atalk_ptr in net_device.
			 */
			asf_cii_set_cache(ndev, dev->ulCommonInterfaceId);

			dev_hold(ndev);
			dev->ndev = ndev;
			/* dev->usId = port_num; ?? */
			asf_ifaces[dev->ulCommonInterfaceId] = dev;
		}
		break;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	case ASF_IFACE_TYPE_BRIDGE:
		{
			/*
			 * ucRelatedIDs must have list of common interface IDs of
			 * attached interfaces.
			 */
			ASFNetDevEntry_t	*attached_dev;
			int		     num, cii;

			for (num = 0; num < info->ulNumRelatedIDs; num++) {
				cii = info->ulRelatedIDs[num];

				if (cii >= asf_max_ifaces) {
					asf_debug("Related CII (%u @ index %d) of Bridge iface is out of bounds (max %u)\n",
						  cii, num, asf_max_ifaces);
					/* FIXME: detach from previous entries */
					goto free_and_ret_err;
				}

				attached_dev = asf_ifaces[cii];
				if (!attached_dev) {
					asf_debug("Attached iface of Bridge iface not found (CII %u)\n", cii);
					/* FIXME: detach from previous entries */
					goto free_and_ret_err;
				}

				if ((attached_dev->ulDevType != ASF_IFACE_TYPE_ETHER)
				    && (attached_dev->ulDevType != ASF_IFACE_TYPE_VLAN)) {
					asf_debug("Attached iface (type %u) is not suitable for Bridge iface.\n",
						  attached_dev->ulDevType);
					/* FIXME: detach from previous entries */
					goto free_and_ret_err;
				}
				attached_dev->pBrIfaceNext = dev->pBrIfaceNext;
				attached_dev->pBridgeDev = dev;
				/*
				 * FIXME: we should use call_rcu to free this node as
				 *  reader might start accessing bridge entry
				 */
				dev->pBrIfaceNext = attached_dev;
			}
			asf_ifaces[dev->ulCommonInterfaceId] = dev;
		}
		break;

	case ASF_IFACE_TYPE_VLAN:
		{
			/*
			 * ucDevIdentifierInPkt must have VLAN ID
			 * ucRelatedIDs must have common interface ID of parent interface
			 */
			ASFNetDevEntry_t	*parent_dev;
			ASF_uint16_t	    usVlanId;

			if ((info->ulDevIdentiferInPktLen != 2) || (info->ulNumRelatedIDs != 1)) {
				asf_debug("Bad DevIdLen %d (must be 2) or NumRelIDs %d (must be 1) for VLAN Map\n",
					  info->ulDevIdentiferInPktLen, info->ulNumRelatedIDs);
				goto free_and_ret_err;
			}

			if (info->ulRelatedIDs[0] >= asf_max_ifaces) {
				asf_debug("Parent CII (%u) of VLAN iface is out of bounds (max %u)\n",
					  info->ulRelatedIDs[0], asf_max_ifaces);
				goto free_and_ret_err;
			}

			parent_dev = asf_ifaces[info->ulRelatedIDs[0]];
			if (!parent_dev) {
				asf_debug("Parent iface of VLAN iface not found (CII %u)\n", info->ulRelatedIDs[0]);
				goto free_and_ret_err;
			}

			if ((parent_dev->ulDevType != ASF_IFACE_TYPE_ETHER) /* || (parent_dev->ulDevType != ASF_IFACE_TYPE_BRIDGE)*/) {
				asf_debug("Parent iface (type %u) is not suitable for VLAN iface.\n",
					  parent_dev->ulDevType);
				goto free_and_ret_err;
			}

			usVlanId = *(ASF_uint16_t *) info->ucDevIdentifierInPkt;
			if (usVlanId >= ASF_VLAN_ARY_LEN) {
				asf_debug("VLAN Id (%u) is invalid (must be less than %u)\n",
					  usVlanId, ASF_VLAN_ARY_LEN);
				goto free_and_ret_err;
			}

			if (parent_dev->pVlanDevArray) {
				if (ASFGetVlanDev(parent_dev, usVlanId)) {
					asf_debug("Map already present with VLAN ID %u\n", usVlanId);
					goto free_and_ret_err;
				}
			} else {
				parent_dev->pVlanDevArray = (ASFVlanDevArray_t *)  kzalloc(sizeof(ASFVlanDevArray_t), GFP_KERNEL);
				if (!parent_dev->pVlanDevArray) {
					asf_debug("Failed alloc VLAN Dev array!\n");
					goto free_and_ret_err;
				}
			}

			/* Copy VLAN ID */
			dev->usId = usVlanId;
			dev->pParentDev = parent_dev;
			ASFInsertVlanDev(parent_dev, usVlanId, dev);

			/* FIXME: use rcu assign operation??!! */
			asf_ifaces[dev->ulCommonInterfaceId] = dev;
		}
		break;

	case ASF_IFACE_TYPE_PPPOE:
		{
			/*
			 * ucRelatedIDs must have common interface ID of parent interface
			 */
			ASFNetDevEntry_t	*parent_dev;

			if ((info->ulDevIdentiferInPktLen != 2) || (info->ulNumRelatedIDs != 1)) {
				asf_debug("Bad DevIdLen %d (must be 2) or NumRelIDs %d (must be 1) for PPPoE Map\n",
					  info->ulDevIdentiferInPktLen, info->ulNumRelatedIDs);
				goto free_and_ret_err;
			}

			if (info->ulRelatedIDs[0] >= asf_max_ifaces) {
				asf_debug("Parent CII (%u) of PPPoE iface is out of bounds (max %u)\n",
					  info->ulRelatedIDs[0], asf_max_ifaces);
				goto free_and_ret_err;
			}

			parent_dev = asf_ifaces[info->ulRelatedIDs[0]];
			if (!parent_dev) {
				asf_debug("Parent iface of PPPoE iface not found (CII %u)\n", info->ulRelatedIDs[0]);
				goto free_and_ret_err;
			}

			if ((parent_dev->ulDevType != ASF_IFACE_TYPE_ETHER)
			    && (parent_dev->ulDevType != ASF_IFACE_TYPE_VLAN)) {
				asf_debug("Parent iface (type %u) is not suitable for PPPoE iface.\n",
					  parent_dev->ulDevType);
				goto free_and_ret_err;
			}


			/* Copy PPPoE session ID */
			dev->usId = *(ASF_uint16_t *) info->ucDevIdentifierInPkt;
			dev->pParentDev = parent_dev;
			dev->pPPPoENext = parent_dev->pPPPoENext;
			parent_dev->pPPPoENext = dev;

			/* FIXME: use rcu assign operation??!! */
			asf_ifaces[dev->ulCommonInterfaceId] = dev;

		}
		break;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */

	}

	asf_debug(" exit .. success .. cii %u type %u\n", ulCommonInterfaceId, info->ulDevType);

	spin_unlock_bh(&asf_iface_lock);
	return ASF_SUCCESS;

free_and_ret_err:
	spin_unlock_bh(&asf_iface_lock);
	kfree(dev);
	return ASF_FAILURE;
}
EXPORT_SYMBOL(ASFMapInterface);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
/* Must be called with spin lock held */
ASF_void_t  asfDetachFromParentBridge(ASFNetDevEntry_t *dev)
{
	ASFNetDevEntry_t *bdev, *tdev;
	bdev = dev->pBridgeDev;
	tdev = bdev->pBrIfaceNext;
	if (dev == tdev) {
		rcu_assign_pointer(bdev->pBrIfaceNext, dev->pBrIfaceNext);
	} else {
		while (tdev) {
			if (dev == tdev->pBrIfaceNext) {
				rcu_assign_pointer(tdev->pBrIfaceNext, dev->pBrIfaceNext);
				break;
			}
			tdev = tdev->pBrIfaceNext;
		}
	}
}



/* Must be called with spin lock held */
ASF_void_t  asfDestoryAllPPPoEChildren(ASFNetDevEntry_t *dev)
{
	ASFNetDevEntry_t *tdev, *t1dev;
	tdev = dev->pPPPoENext;
	do {
		t1dev = tdev->pPPPoENext;
		asf_ifaces[dev->ulCommonInterfaceId] = NULL;
		call_rcu((struct rcu_head *)  tdev, asfNetDevFreeRcu);
		tdev = t1dev;
	} while (tdev);
}

/* Must be called with spin lock held */
ASF_void_t  asfDestoryAllVlanChildren(ASFNetDevEntry_t *dev)
{
	ASFNetDevEntry_t *tdev;
	ASF_uint16_t    usVlanId;
	ASF_uint32_t    count;

	/* TODO: crude way.. may be maintain a list as well.
	 * However must be fast enough as long as VLAN IDs are
	 * not scattered.
	 */
	count = dev->pVlanDevArray->ulNumVlans;
	for (usVlanId = 0; usVlanId < ASF_VLAN_ARY_LEN; usVlanId++) {
		if (dev->pVlanDevArray->pArray[usVlanId]) {
			tdev = dev->pVlanDevArray->pArray[usVlanId];
			dev->pVlanDevArray->pArray[usVlanId] = NULL;

			if (tdev->pBridgeDev)
				asfDetachFromParentBridge(tdev);
			if (tdev->pPPPoENext)
				asfDestoryAllPPPoEChildren(tdev);

			asf_ifaces[tdev->ulCommonInterfaceId] = NULL;
			call_rcu((struct rcu_head *)  tdev, asfNetDevFreeRcu);

			count--;
		}
	}

}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */

ASF_uint32_t ASFUnMapInterface (ASF_uint32_t ulCommonInterfaceId)
{
	ASFNetDevEntry_t	*dev;

	asf_debug(" begin cii %u\n", ulCommonInterfaceId);

	if (ulCommonInterfaceId >= asf_max_ifaces) {
		asf_debug("CII %u is greater than MAX %u\n", ulCommonInterfaceId, asf_max_ifaces);
		return ASF_FAILURE;
	}

	dev = asf_ifaces[ulCommonInterfaceId];
	if (!dev) {
		asf_debug("CII %d is not present\n", ulCommonInterfaceId);
		return ASF_FAILURE;
	}

	spin_lock_bh(&asf_iface_lock);
	switch (dev->ulDevType) {
	case ASF_IFACE_TYPE_ETHER:
		{
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			/* Remove this interface and all dependent interfaces like VLAN, PPPOE */
			if (dev->pVlanDevArray)
				asfDestoryAllVlanChildren(dev);
			if (dev->pBridgeDev)
				asfDetachFromParentBridge(dev);
			if (dev->pPPPoENext)
				asfDestoryAllPPPoEChildren(dev);
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
			dev_put(dev->ndev);
		}
		break;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	case ASF_IFACE_TYPE_BRIDGE:
		{
			/* reset pBridgeDev of attached interfaces and
			 * remove them from the pBrIfaceNext chain
			 */
			ASFNetDevEntry_t	*tdev, *t1dev;

			tdev = dev->pBrIfaceNext;
			while (tdev) {
				t1dev = tdev->pBrIfaceNext;
				rcu_assign_pointer(tdev->pBridgeDev, NULL);
				rcu_assign_pointer(tdev->pBrIfaceNext, NULL);
				tdev = t1dev;
			}
		}
		break;
	case ASF_IFACE_TYPE_VLAN:
		{
			/* remove from from pVlanDevArray of pParentDev
			 * detach from pBrIfaceNext chain of pBridgeDev if any.
			 */
			ASFRemoveVlanDev(dev->pParentDev, dev->usId);

			if (dev->pBridgeDev)
				asfDetachFromParentBridge(dev);
			if (dev->pPPPoENext)
				asfDestoryAllPPPoEChildren(dev);
		}
		break;
	case ASF_IFACE_TYPE_PPPOE:
		{
			ASFNetDevEntry_t	*tdev;

			tdev = dev->pParentDev->pPPPoENext;

			/* detach from parent PPPoE list */
			if (dev == tdev) {
				rcu_assign_pointer(dev->pParentDev->pPPPoENext, dev->pPPPoENext);
			} else {
				while (tdev) {
					if (dev == tdev->pPPPoENext) {
						rcu_assign_pointer(tdev->pPPPoENext, dev->pPPPoENext);
						break;
					}
					tdev = tdev->pPPPoENext;
				}
			}

		}
		break;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	default:
		asf_debug("Invalid iface entry with devtype %d found. (shouldn't happen!\n", dev->ulDevType);
	}
	asf_debug(" exit .. success cii %u\n", ulCommonInterfaceId);
	asf_ifaces[ulCommonInterfaceId] = NULL;
	call_rcu((struct rcu_head *)  dev, asfNetDevFreeRcu);
	spin_unlock_bh(&asf_iface_lock);
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFUnMapInterface);


ASF_uint32_t ASFBindDeviceToVSG(ASF_uint32_t ulVSGId, ASF_uint32_t ulCommonInterfaceId)
{
	asf_debug(" begin cii %u vsg %u\n", ulCommonInterfaceId, ulVSGId);
	if ((ulCommonInterfaceId < asf_max_ifaces) && asf_ifaces[ulCommonInterfaceId]) {
		asf_ifaces[ulCommonInterfaceId]->ulVSGId = ulVSGId;
		asf_debug(" exit ... success .. cii %u vsg %u\n", ulCommonInterfaceId, ulVSGId);
		return ASF_SUCCESS;
	}
	return ASF_FAILURE;
}
EXPORT_SYMBOL(ASFBindDeviceToVSG);

ASF_uint32_t ASFUnBindDeviceToVSG(ASF_uint32_t ulVSGId, ASF_uint32_t ulCommonInterfaceId)
{
	asf_debug(" begin cii %u vsg %u\n", ulCommonInterfaceId, ulVSGId);
	if ((ulCommonInterfaceId < asf_max_ifaces) && asf_ifaces[ulCommonInterfaceId]) {
		asf_ifaces[ulCommonInterfaceId]->ulVSGId = ASF_INVALID_VSG;
		asf_debug(" exit ... success .. cii %u vsg %u\n", ulCommonInterfaceId, ulVSGId);
		return ASF_SUCCESS;
	}
	return ASF_FAILURE;
}
EXPORT_SYMBOL(ASFUnBindDeviceToVSG);


ASF_uint32_t ASFRemove(ASF_void_t)
{
	/* TBD: Implement this function */

	/* it should cleanup the  forwarding flows as well.*/
	asf_ffp_cleanup_all_flows();

	asf_enable = 0;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFRemove);

ASF_uint32_t ASFDeploy(ASF_void_t)
{
	/* TBD: Implement this function */
	asf_enable = 1;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFDeploy);

ASF_uint32_t ASFSetReasmParams(ASF_uint32_t ulVSGId, ASFReasmParams_t *p)
{
	asf_vsg_info_t  *vsg = NULL;

	vsg = asf_ffp_get_vsg_info_node(ulVSGId);
	if (vsg == NULL)
		return ASF_FAILURE;
	vsg->ulReasmTimeout = p->ulReasmTimeout;
	vsg->ulReasmMaxFrags = p->ulReasmMaxFrags;
	vsg->ulReasmMinFragSize = p->ulReasmMinFragSize;

/* TODO: make this VSG specific --	asfReasmInitConfig(); */
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFSetReasmParams);



ASF_void_t  ASFFFPGetCapabilities(ASFFFPCap_t *pCap)
{
	pCap->ulMaxVSGs = asf_max_vsgs;
	pCap->bBufferHomogenous = ASF_TRUE;
	pCap->ulMaxFlows = ffp_max_flows;
	pCap->bHomogenousHashAlgorithm = ASF_TRUE;
	pCap->ulHashAlgoInitVal = asf_ffp_hash_init_value;
}
EXPORT_SYMBOL(ASFFFPGetCapabilities);


ASF_void_t  ASFFFPSetNotifyPreference(ASF_boolean_t bEnable)
{
	asf_ffp_notify = bEnable;
}
EXPORT_SYMBOL(ASFFFPSetNotifyPreference);


#ifdef ASF_DEBUG
static char *cmdStrs[10] = {
	/* 0 */ "DMY",
	/* 1 */ "CREATE_FLOWS",
	/* 2 */ "DELETE_FLOWS",
	/* 3 */ "MODIFY_FLOWS"
} ;
#define cmd2Str(cmd) ((cmd <= 3) ? cmdStrs[cmd] : "INVALID")
#endif


ASF_uint32_t ASFFFPRuntime (
			   ASF_uint32_t  ulVSGId,
			   ASF_uint32_t  cmd,
			   ASF_void_t    *args,
			   ASF_uint32_t  ulArgslen,
			   ASF_void_t    *pReqIdentifier,
			   ASF_uint32_t  ulReqIdentifierlen)
{
	int iResult;
	ACCESS_XGSTATS();

	asf_debug("vsg %u cmd %s (%u) arg_len %u reqid_len %u (notify %d) (respCbk 0x%x)\n",
		  ulVSGId, cmd2Str(cmd), cmd, ulArgslen, ulReqIdentifierlen,
		  asf_ffp_notify, ffpCbFns.pFnRuntime);
	/* invalid mode - avoid creation of flows */
	if (!asf_ffp_check_vsg_mode(ulVSGId, fwMode))
		return ASFFFP_RESPONSE_FAILURE;

	switch (cmd) {
	case ASF_FFP_CREATE_FLOWS:
		{
			unsigned long ulHashVal = 0;
			ASFFFPCreateFlowsResp_t resp;

			XGSTATS_INC(CreateFlowsCmd);

			if (ulVSGId < asf_max_vsgs)
				iResult = ffp_cmd_create_flows(ulVSGId, (ASFFFPCreateFlowsInfo_t *) args, NULL, NULL, &ulHashVal);
			else {
				XGSTATS_INC(CreateFlowsCmdVsgErr);
				iResult = ASFFFP_RESPONSE_FAILURE;
			}

#ifdef ASF_FFP_XTRA_STATS
			if (iResult != ASFFFP_RESPONSE_SUCCESS)
				XGSTATS_INC(CreateFlowsCmdFailures);
#endif

			if ((asf_ffp_notify == ASF_TRUE) && ffpCbFns.pFnRuntime) {
				memcpy(&resp.tuple, &((ASFFFPCreateFlowsInfo_t *) args)->flow1.tuple, sizeof(resp.tuple));
				resp.ulZoneId = ((ASFFFPCreateFlowsInfo_t *) args)->flow1.ulZoneId;
				resp.ulHashVal = ulHashVal;
				resp.iResult = iResult;
				ffpCbFns.pFnRuntime(ulVSGId, cmd, pReqIdentifier, ulReqIdentifierlen,
						    &resp, sizeof(resp));
			}
		}

		break;

	case ASF_FFP_DELETE_FLOWS:
		{
			unsigned long ulHashVal = 0;
			ASFFFPDeleteFlowsResp_t resp;

			XGSTATS_INC(DeleteFlowsCmd);
			if (ulVSGId < asf_max_vsgs)
				iResult = ffp_cmd_delete_flows(ulVSGId, (ASFFFPDeleteFlowsInfo_t *) args, &ulHashVal);
			else
				iResult	= ASFFFP_RESPONSE_FAILURE;

#ifdef ASF_FFP_XTRA_STATS
			if (iResult != ASFFFP_RESPONSE_SUCCESS)
				XGSTATS_INC(DeleteFlowsCmdFailures);
#endif
			if ((asf_ffp_notify == ASF_TRUE)  && ffpCbFns.pFnRuntime) {
				memset(&resp, 0, sizeof(resp));
				memcpy(&resp.tuple, &((ASFFFPDeleteFlowsInfo_t *) args)->tuple, sizeof(resp.tuple));
				resp.ulZoneId = ((ASFFFPDeleteFlowsInfo_t *) args)->ulZoneId;
				resp.ulHashVal = ulHashVal;
				resp.iResult = (iResult == 0) ? ASFFFP_RESPONSE_SUCCESS : ASFFFP_RESPONSE_FAILURE;

				/* FIXME: flow1Stats and flow2Stats */

				ffpCbFns.pFnRuntime(ulVSGId, cmd, pReqIdentifier, ulReqIdentifierlen,
						    &resp, sizeof(resp));
			}
		}

		break;

	case ASF_FFP_MODIFY_FLOWS:
		{
			XGSTATS_INC(ModifyFlowsCmd);
			if (ulVSGId < asf_max_vsgs) {
				iResult = ffp_cmd_update_flow(ulVSGId, (ASFFFPUpdateFlowParams_t *) args);
			} else
				iResult	= ASFFFP_RESPONSE_FAILURE;
#ifdef ASF_FFP_XTRA_STATS
			if (iResult != ASFFFP_RESPONSE_SUCCESS)
				XGSTATS_INC(ModifyFlowsCmdFailures);
#endif
			asf_debug("mod_flows iResult %d (vsg %d) max_vsg %d\n", iResult, ulVSGId, asf_max_vsgs);
			/* No confirmation sent to AS ?? */
		}
		break;

	default:
		return ASFFFP_RESPONSE_FAILURE;
	}
	asf_debug("vsg %u cmd %s (%d)  - result %d\n", ulVSGId, cmd2Str(cmd), cmd, iResult);
	return iResult;
}
EXPORT_SYMBOL(ASFFFPRuntime);


ASF_void_t ASFFFPRegisterCallbackFns(ASFFFPCallbackFns_t *pFnList)
{
	ffpCbFns.pFnInterfaceNotFound = pFnList->pFnInterfaceNotFound;
	ffpCbFns.pFnVSGMappingNotFound = pFnList->pFnVSGMappingNotFound;
	ffpCbFns.pFnZoneMappingNotFound = pFnList->pFnZoneMappingNotFound;
	ffpCbFns.pFnNoFlowFound = pFnList->pFnNoFlowFound;
	ffpCbFns.pFnRuntime = pFnList->pFnRuntime;
	ffpCbFns.pFnFlowRefreshL2Blob = pFnList->pFnFlowRefreshL2Blob;
	ffpCbFns.pFnFlowActivityRefresh = pFnList->pFnFlowActivityRefresh;
	ffpCbFns.pFnFlowTcpSpecialPkts = pFnList->pFnFlowTcpSpecialPkts;
	ffpCbFns.pFnFlowValidate = pFnList->pFnFlowValidate;
	ffpCbFns.pFnAuditLog = pFnList->pFnAuditLog;
	asf_debug("Register AS response cbk 0x%x\n", ffpCbFns.pFnRuntime);
}
EXPORT_SYMBOL(ASFFFPRegisterCallbackFns);


ASF_void_t ASFFFPUpdateConfigIdentity(ASF_uint32_t ulVSGId, ASFFFPConfigIdentity_t configIdentity)
{
	asf_vsg_info_t  *vsg;

	vsg = asf_ffp_get_vsg_info_node(ulVSGId);
	if (!vsg)
		return;
	vsg->configIdentity = configIdentity;
}
EXPORT_SYMBOL(ASFFFPUpdateConfigIdentity);


ASF_uint32_t ASFFFPBindInterfaceToZone(ASF_uint32_t ulVSGId, ASF_uint32_t ulCommonInterfaceId, ASF_uint32_t ulZoneId)
{
	if ((ulCommonInterfaceId < asf_max_ifaces) && asf_ifaces[ulCommonInterfaceId]) {
		asf_ifaces[ulCommonInterfaceId]->ulZoneId = ulZoneId;
		return ASF_SUCCESS;
	}
	return ASF_FAILURE;
}
EXPORT_SYMBOL(ASFFFPBindInterfaceToZone);

ASF_uint32_t ASFFFPUnBindInterfaceToZone(ASF_uint32_t ulVSGId,  ASF_uint32_t ulCommonInterfaceId, ASF_uint32_t ulZoneId)
{
	if ((ulCommonInterfaceId < asf_max_ifaces) && asf_ifaces[ulCommonInterfaceId]) {
		asf_ifaces[ulCommonInterfaceId]->ulZoneId = ASF_INVALID_ZONE;
		return ASF_SUCCESS;
	}
	return ASF_FAILURE;
}
EXPORT_SYMBOL(ASFFFPUnBindInterfaceToZone);


ASF_uint32_t ASFFFPSetL2blobParams(ASFFFPL2blobParams_t *p)
{
	asf_l2blob_refresh_npkts = p->ulL2blobNumPkts;
	asf_l2blob_refresh_interval = p->ulL2blobInterval;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFFFPSetL2blobParams);


ASF_uint32_t  ASFFFPSetInacRefreshParams(ASFFFPInacRefreshParams_t *pInfo)
{
	asf_inac_divisor = pInfo->ulDivisor;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFFFPSetInacRefreshParams);



ASF_uint32_t ASFFFPSetTcpCtrlParams(ASF_uint32_t  ulVSGId, ASFFFPTcpCtrlParams_t *pInfo)
{
	asf_vsg_info_t  *vsg;

	vsg = asf_ffp_get_vsg_info_node(ulVSGId);
	if (!vsg)
		return ASF_FAILURE;
	vsg->bDropOutOfSeq = pInfo->bDropOutOfSeq;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFFFPSetTcpCtrlParams);

static inline int ffp_flow_copy_info(ASFFFPFlowInfo_t *pInfo, ffp_flow_t *flow)
{
	/* TODO:
	 * pInfo->tuple.ucprotocol
	 * protocol should be either TCP or UDP */

	flow->ulSrcIp = pInfo->tuple.ulSrcIp;
	flow->ulDestIp = pInfo->tuple.ulDestIp;
	flow->ulPorts = (pInfo->tuple.usSrcPort << 16)|pInfo->tuple.usDestPort;
	flow->ucProtocol = pInfo->tuple.ucProtocol;

	flow->ulZoneId = pInfo->ulZoneId;

	flow->ulInacTime = pInfo->ulInacTimeout;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (flow->ucProtocol == IPPROTO_TCP) {
		flow->bTcpOutOfSeqCheck = pInfo->bTcpOutOfSeqCheck;
		flow->bTcpTimeStampCheck = pInfo->bTcpTimeStampCheck;
		flow->ulTcpTimeStamp = ntohl(pInfo->ulTcpTimeStamp);
		flow->tcpState.ulHighSeqNum = ntohl(pInfo->tcpState.ulHighSeqNum);
		flow->tcpState.ulSeqDelta = ntohl(pInfo->tcpState.ulSeqDelta);
		flow->tcpState.bPositiveDelta = pInfo->tcpState.bPositiveDelta;
		flow->tcpState.ucWinScaleFactor = pInfo->tcpState.ucWinScaleFactor;
		flow->tcpState.ulRcvNext = ntohl(pInfo->tcpState.ulRcvNext);
		flow->tcpState.ulRcvWin = ntohl(pInfo->tcpState.ulRcvWin);
		flow->tcpState.ulMaxRcvWin = ntohl(pInfo->tcpState.ulMaxRcvWin);
	}
#endif  /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	flow->bNat = pInfo->bNAT;
	flow->bIPsecIn = pInfo->bIPsecIn;
	flow->bIPsecOut = pInfo->bIPsecOut;
	flow->bNat = pInfo->bNAT;

	if (flow->bNat) {
		flow->ulSrcNATIp = pInfo->natInfo.ulSrcNATIp;
		flow->ulDestNATIp = pInfo->natInfo.ulDestNATIp;
		flow->ulNATPorts = (pInfo->natInfo.usSrcNATPort << 16)|pInfo->natInfo.usDestNATPort;
	}

	memcpy(&flow->ipsecInfo, &pInfo->ipsecInInfo, sizeof(flow->ipsecInfo));

	return ASFFFP_RESPONSE_SUCCESS;
}

static inline unsigned long asfSwapShorts(unsigned long ulPorts)
{
	unsigned char *p = (unsigned char *)  &ulPorts, temp;

	temp = p[0]; p[0] = p[2]; p[2] = temp;
	temp = p[1]; p[1] = p[3]; p[3] = temp;
	return ulPorts;
}

static int ffp_cmd_create_flows(ASF_uint32_t  ulVsgId, ASFFFPCreateFlowsInfo_t *p,
				ffp_flow_t **pFlow1, ffp_flow_t **pFlow2, unsigned long *pHashVal)
{
	ffp_flow_t    *flow1, *flow2;
	unsigned int  index1, index2;
	unsigned long hash1, hash2;
	ffp_bucket_t  *bkt;
	ACCESS_XGSTATS();

	/* invalid mode - avoid creation of flows */
	if (!asf_enable)
		return ASFFFP_RESPONSE_FAILURE;
	/*
	 * ptrary allocations and free should be streamlined for two at a time.!!?
	 */
	if (ulVsgId >= asf_max_vsgs) {
		asf_debug("VSG (%d) > MAX (%d)\n", ulVsgId, asf_max_vsgs);
		return ASFFFP_RESPONSE_FAILURE;
	}

	flow1 = ffp_flow_alloc();
	flow2 = ffp_flow_alloc();
	if (flow1 && flow2) {
		flow1->ulVsgId = flow2->ulVsgId = ulVsgId;
		flow1->as_flow_info = flow2->as_flow_info = p->ASFWInfo;
		if (ffp_flow_copy_info(&p->flow1, flow1) != ASFFFP_RESPONSE_SUCCESS)
			goto down;
		if (ffp_flow_copy_info(&p->flow2, flow2) != ASFFFP_RESPONSE_SUCCESS)
			goto down;

		memcpy(&flow1->configIdentity, &p->configIdentity, sizeof(flow1->configIdentity));
		memcpy(&flow2->configIdentity, &p->configIdentity, sizeof(flow2->configIdentity));

		flow1->ulLastPktInAt = flow2->ulLastPktInAt = jiffies;

		/* TODO: what to do with ASFWInfo field */

		index1 = ptrIArray_add(&ffp_ptrary, flow1);
		if (index1 > ffp_ptrary.nr_entries)
			goto down;
		index2 = ptrIArray_add(&ffp_ptrary, flow2);
		if (index2 > ffp_ptrary.nr_entries)
			goto down1;

		flow1->id.ulArg1 = index1;
		flow1->id.ulArg2 = ffp_ptrary.pBase[index1].ulMagicNum;

		flow1->other_id.ulArg1 = index2;
		flow1->other_id.ulArg2 = ffp_ptrary.pBase[index2].ulMagicNum;

		memcpy(&flow2->id, &flow1->other_id, sizeof(ASFFFPFlowId_t));
		memcpy(&flow2->other_id, &flow1->id, sizeof(ASFFFPFlowId_t));


		hash1 = ASFFFPComputeFlowHash1(flow1->ulSrcIp, flow1->ulDestIp, flow1->ulPorts,
					       ulVsgId, flow1->ulZoneId, asf_ffp_hash_init_value);
		hash2 = ASFFFPComputeFlowHash1(flow2->ulSrcIp, flow2->ulDestIp, flow2->ulPorts,
					       ulVsgId, flow2->ulZoneId, asf_ffp_hash_init_value);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		asf_debug_l2("creating l2blob timer (flow1)\n");
		flow1->pL2blobTmr = asfTimerStart(ASF_FFP_BLOB_TMR_ID, 0,
							asf_l2blob_refresh_interval,
							flow1->ulVsgId,
							flow1->id.ulArg1,
							flow1->id.ulArg2, hash1);
		if (!flow1->pL2blobTmr)
			goto down2;

		asf_debug_l2("creating inac timer (flow1)\n");
		flow1->pInacRefreshTmr = asfTimerStart(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
							     flow1->ulInacTime/asf_inac_divisor,
							     flow1->ulVsgId,
							     flow1->id.ulArg1,
							     flow1->id.ulArg2, hash1);
		if (!flow1->pInacRefreshTmr)
			goto down2;

		asf_debug_l2("creating l2blob timer (flow2)\n");
		flow2->pL2blobTmr = asfTimerStart(ASF_FFP_BLOB_TMR_ID, 0,
							asf_l2blob_refresh_interval,
							flow2->ulVsgId,
							flow2->id.ulArg1,
							flow2->id.ulArg2, hash2);
		if (!flow2->pL2blobTmr)
			goto down2;

		asf_debug_l2("creating inac timer (flow2)\n");
		flow2->pInacRefreshTmr = asfTimerStart(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
							     flow2->ulInacTime/asf_inac_divisor,
							     flow2->ulVsgId,
							     flow2->id.ulArg1,
							     flow2->id.ulArg2, hash2);
		if (!flow2->pInacRefreshTmr)
			goto down2;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		/* insert in the table.. but l2blob_len is zero meaning waiting for l2blob update */
		bkt = asf_ffp_bucket_by_hash(hash1);
		asf_ffp_flow_insert(flow1, bkt);
		if (pHashVal)
			*pHashVal = hash1;

		bkt = asf_ffp_bucket_by_hash(hash2);
		asf_ffp_flow_insert(flow2, bkt);

		if (pFlow1)
			*pFlow1 = flow1;
		if (pFlow2)
			*pFlow2 = flow2;

		return ASFFFP_RESPONSE_SUCCESS;
	}
down:
	XGSTATS_INC(CreateFlowsCmdErrDown);
	if (flow1)
		ffp_flow_free(flow1);
	if (flow2)
		ffp_flow_free(flow2);
	asf_debug("flow creation failed!\n");
	if (pFlow1)
		*pFlow1 = NULL;
	if (pFlow2)
		*pFlow2 = NULL;
	return ASFFFP_RESPONSE_FAILURE;
down1:
	XGSTATS_INC(CreateFlowsCmdErrDown1);
	asf_debug("flow creation failed!\n");
	ptrIArray_delete(&ffp_ptrary, index1, ffp_flow_free_rcu);
	if (flow2)
		ffp_flow_free(flow2);
	if (pFlow1)
		*pFlow1 = NULL;
	if (pFlow2)
		*pFlow2 = NULL;
	return ASFFFP_RESPONSE_FAILURE;
down2:
	XGSTATS_INC(CreateFlowsCmdErrDown2);
	asf_debug("timer allocation failed!\n");
	if (flow1->pL2blobTmr)
		asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, flow1->pL2blobTmr);
	if (flow1->pInacRefreshTmr)
		asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, flow1->pInacRefreshTmr);
	if (flow2->pL2blobTmr)
		asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, flow2->pL2blobTmr);
	if (flow2->pInacRefreshTmr)
		asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, flow2->pInacRefreshTmr);
	ptrIArray_delete(&ffp_ptrary, index1, ffp_flow_free_rcu);
	ptrIArray_delete(&ffp_ptrary, index2, ffp_flow_free_rcu);
	return ASFFFP_RESPONSE_FAILURE;
}


static int ffp_cmd_delete_flows(ASF_uint32_t  ulVsgId, ASFFFPDeleteFlowsInfo_t *p, unsigned long *pHashVal)
{
	ffp_flow_t      *flow1, *flow2;
	ffp_bucket_t    *bkt1, *bkt2;
	unsigned long   hash1, hash2;
	int	     rem_flow2_resources = 0;

	/* first detach the flows */
	hash1 = ASFFFPComputeFlowHashEx(&p->tuple, ulVsgId, p->ulZoneId, asf_ffp_hash_init_value);
	if (pHashVal)
		*pHashVal = hash1;
	bkt1 = asf_ffp_bucket_by_hash(hash1);

	spin_lock_bh(&bkt1->lock);
	flow1 = asf_ffp_flow_lookup_in_bkt_ex(&p->tuple, ulVsgId, p->ulZoneId, (ffp_flow_t *)  bkt1);
	if (flow1) {
		if (unlikely(flow1->bDeleted)) {
			spin_unlock_bh(&bkt1->lock);
			return -1;
		}
		__asf_ffp_flow_remove(flow1, bkt1);
		flow1->bDeleted = 1;
		spin_unlock_bh(&bkt1->lock);

		flow2 = ffp_flow_by_id(&flow1->other_id);
		if (flow2) {
			hash2 = ASFFFPComputeFlowHash1(flow2->ulSrcIp, flow2->ulDestIp, flow2->ulPorts,
						       ulVsgId, flow2->ulZoneId, asf_ffp_hash_init_value);
			bkt2 = asf_ffp_bucket_by_hash(hash2);
			spin_lock_bh(&bkt2->lock);
			if (!flow2->bDeleted) {
				__asf_ffp_flow_remove(flow2, bkt2);
				flow2->bDeleted = 1;
				rem_flow2_resources = 1;
			}
			spin_unlock_bh(&bkt2->lock);
			if (rem_flow2_resources) {
				if (flow2->pL2blobTmr) {
					asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, flow2->pL2blobTmr);
				}
				if (flow2->pInacRefreshTmr) {
					asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, flow2->pInacRefreshTmr);
				}
				ptrIArray_delete(&ffp_ptrary, flow2->id.ulArg1, ffp_flow_free_rcu);
			}
		}
		if (flow1->pL2blobTmr) {
			asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, flow1->pL2blobTmr);
		}
		if (flow1->pInacRefreshTmr) {
			asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, flow1->pInacRefreshTmr);
		}
		ptrIArray_delete(&ffp_ptrary, flow1->id.ulArg1, ffp_flow_free_rcu);
		return 0;
	}
	spin_unlock_bh(&bkt1->lock);
	return -1;
}

static int ffp_cmd_update_flow(ASF_uint32_t ulVsgId, ASFFFPUpdateFlowParams_t *p)
{
	ffp_flow_t *flow;
	unsigned long   hash;

	flow = asf_ffp_flow_lookup_by_tuple(&p->tuple, ulVsgId, p->ulZoneId, &hash);
	if (flow) {
		if (p->bL2blobUpdate) {
			ASFNetDevEntry_t  *dev;

			if (p->u.l2blob.ulDeviceId > asf_max_ifaces) {
				asf_debug("DeviceId %d > MAX %d\n", p->u.l2blob.ulDeviceId, asf_max_ifaces);
				return ASFFFP_RESPONSE_FAILURE;
			}
			dev = asf_ifaces[p->u.l2blob.ulDeviceId];
			if (!dev) {
				asf_debug("No matching iface mapping found for DeviceId %d\n", p->u.l2blob.ulDeviceId);
				return ASFFFP_RESPONSE_FAILURE;
			}

			if (dev->ulDevType != ASF_IFACE_TYPE_ETHER) {
				asf_debug("tx iface must be of ETH type\n");
				return ASFFFP_RESPONSE_FAILURE;
			}

			flow->odev = dev->ndev;

			/* TODO: Find outDev ???  */
			if (p->u.l2blob.l2blobLen > ASF_MAX_L2BLOB_LEN) {
				asf_debug_l2("bloblen %d > MAX %d\n", p->u.l2blob.l2blobLen, ASF_MAX_L2BLOB_LEN);
				return ASFFFP_RESPONSE_FAILURE;
			}

			memcpy(&flow->l2blob, p->u.l2blob.l2blob, p->u.l2blob.l2blobLen);
			flow->l2blob_len = p->u.l2blob.l2blobLen;
			flow->pmtu = p->u.l2blob.ulPathMTU;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			flow->bVLAN = p->u.l2blob.bTxVlan;
			flow->bPPPoE = p->u.l2blob.bUpdatePPPoELen;
			flow->tx_vlan_id = p->u.l2blob.usTxVlanId;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			asf_debug("{%u, %u} blob(%d) = %pM%pM...%02X%02X\n",
				  flow->id.ulArg1, flow->id.ulArg2,
				  flow->l2blob_len,
				  flow->l2blob, flow->l2blob + 6,
				  flow->l2blob[flow->l2blob_len-2],
				  flow->l2blob[flow->l2blob_len-1]);
			return ASFFFP_RESPONSE_SUCCESS;
		} else if (p->bFFPConfigIdentityUpdate) {
			memcpy(&flow->configIdentity, &p->u.fwConfigIdentity, sizeof(flow->configIdentity));
			return ASFFFP_RESPONSE_SUCCESS;
		} else if (p->bIPsecConfigIdentityUpdate) {
			if (p->u.ipsec.bOut) {
				memcpy(&flow->ipsecInfo.outContainerInfo, &p->u.ipsec.ipsecInfo.outContainerInfo, sizeof(flow->ipsecInfo.outContainerInfo));
				flow->bIPsecOut = p->u.ipsec.bIPsecOut;
			}
			if (p->u.ipsec.bIn) {
				memcpy(&flow->ipsecInfo.inContainerInfo, &p->u.ipsec.ipsecInfo.inContainerInfo, sizeof(flow->ipsecInfo.inContainerInfo));
				flow->bIPsecIn = p->u.ipsec.bIPsecIn;
			}

			return ASFFFP_RESPONSE_SUCCESS;
		}
	} else
		asf_debug("flow is not found!\n");

	return ASFFFP_RESPONSE_FAILURE;
}

int ASFFFPQueryFlowStats(ASF_uint32_t ulVsgId, ASFFFPQueryFlowStatsInfo_t *p)
{
	ffp_flow_t      *flow1, *flow2;
	int	     bLockFlag, iResult;
	unsigned long   hash;

	ASF_RCU_READ_LOCK(bLockFlag);
	flow1 = asf_ffp_flow_lookup_by_tuple(&p->tuple, ulVsgId, p->ulZoneId, &hash);
	if (flow1)
		flow2 = ffp_flow_by_id(&flow1->other_id);
	if (flow1 && flow2) {
		ffp_copy_flow_stats(flow1, &p->stats);
		ffp_copy_flow_stats(flow2, &p->other_stats);
		iResult = ASFFFP_RESPONSE_SUCCESS;
	} else {
		memset(&p->stats, 0, sizeof(p->stats));
		memset(&p->other_stats, 0, sizeof(p->other_stats));
		iResult = ASFFFP_RESPONSE_FAILURE;
	}
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return iResult;
}
EXPORT_SYMBOL(ASFFFPQueryFlowStats);


int ASFFFPQueryVsgStats(ASF_uint32_t ulVsgId, ASFFFPVsgStats_t *pStats)
{
	int cpu;

	if (ulVsgId >= asf_max_vsgs) {
		asf_debug("Invalid VSG ID %u given to extract VSG stats\n", ulVsgId);
		return ASFFFP_RESPONSE_FAILURE;
	}

	memset(pStats, 0, sizeof(*pStats));
	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		ASFFFPVsgStats_t	*vstats;

		vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id()) + ulVsgId;
		pStats->ulInPkts += vstats->ulInPkts;
		pStats->ulOutPkts += vstats->ulOutPkts;
		pStats->ulOutBytes += vstats->ulOutBytes;
	}
	return ASFFFP_RESPONSE_SUCCESS;
}
EXPORT_SYMBOL(ASFFFPQueryVsgStats);


int ASFFFPQueryGlobalStats(ASFFFPGlobalStats_t *pStats)
{
	int cpu;
	ASFFFPGlobalStats_t     *stats, *t_stats;

	t_stats = pStats;
	memset(t_stats, 0, sizeof(*t_stats));
	for_each_online_cpu(cpu)
	{
		stats = asfPerCpuPtr(asf_gstats, cpu);
#define ASF_GSTATS_SUM_FIELD(f) (t_stats->ul##f += stats->ul##f)

		/*t_stats->ulInPkts += stats->ulInPkts;*/
		ASF_GSTATS_SUM_FIELD(InPkts);
		ASF_GSTATS_SUM_FIELD(OutPkts);
		ASF_GSTATS_SUM_FIELD(OutBytes);
		ASF_GSTATS_SUM_FIELD(FlowAllocs);
		ASF_GSTATS_SUM_FIELD(FlowFrees);
		ASF_GSTATS_SUM_FIELD(FlowAllocFailures);
		ASF_GSTATS_SUM_FIELD(FlowFreeFailures);
		ASF_GSTATS_SUM_FIELD(ErrCsum);
		ASF_GSTATS_SUM_FIELD(ErrIpHdr);
		ASF_GSTATS_SUM_FIELD(ErrIpProtoHdr);
		ASF_GSTATS_SUM_FIELD(ErrAllocFailures);
		ASF_GSTATS_SUM_FIELD(MiscFailures);
		ASF_GSTATS_SUM_FIELD(ErrTTL);
		ASF_GSTATS_SUM_FIELD(PktsToFNP);

	}
	return ASFFFP_RESPONSE_SUCCESS;
}
EXPORT_SYMBOL(ASFFFPQueryGlobalStats);



int ASFGetStatus()
{
	return asf_enable;
}
EXPORT_SYMBOL(ASFGetStatus);

unsigned int asfFfpBlobTmrCb(unsigned int ulVSGId,
			     unsigned int ulIndex, unsigned int ulMagicNum, unsigned int ulHashVal)
{
	ffp_flow_t *flow;
	ACCESS_XGSTATS();

	asf_debug_l2("vsg %u idx %u magic %u hash %u\n", ulVSGId, ulIndex, ulMagicNum, ulHashVal);
	XGSTATS_INC(BlobTmrCalls);

	if (asf_enable) {
		flow = ffp_flow_by_id_ex(ulIndex, ulMagicNum);
		if (flow) {
			if (ffpCbFns.pFnFlowRefreshL2Blob) {
				ASFFFPFlowL2BlobRefreshCbInfo_t ind;

				ind.flowTuple.ulSrcIp = flow->ulSrcIp;
				ind.flowTuple.ulDestIp = flow->ulDestIp;
				ind.flowTuple.usSrcPort = (flow->ulPorts >> 16);
				ind.flowTuple.usDestPort = flow->ulPorts&0xffff;
				ind.flowTuple.ucProtocol = flow->ucProtocol;

				if (flow->bNat) {
					ind.packetTuple.ulSrcIp = flow->ulSrcNATIp;
					ind.packetTuple.ulDestIp = flow->ulDestNATIp;
					ind.packetTuple.usSrcPort = (flow->ulNATPorts >> 16);
					ind.packetTuple.usDestPort = flow->ulNATPorts&0xffff;
					ind.packetTuple.ucProtocol = flow->ucProtocol;
				} else
					ind.packetTuple	= ind.flowTuple;

				ind.ulZoneId = flow->ulZoneId;

				ind.ulHashVal = ulHashVal;

				ind.Buffer.linearBuffer.buffer = NULL;
				ind.Buffer.linearBuffer.ulBufLen = 0;
				ind.Buffer.nativeBuffer = NULL;


				/* TODO: what to do with ASFwInfo field */

				XGSTATS_INC(TmrCtxL2blobInd);
				ffpCbFns.pFnFlowRefreshL2Blob(flow->ulVsgId, &ind);
				/*TODO: what's the use of ret val */
			}
			return 0;
		}
		XGSTATS_INC(BlobTmrCtxBadFlow);
		asf_debug("Blob Tmr: flow not found {%lu, %lu}.. (might happen while flows are being deleted)!!!\n",
			  ulIndex, ulMagicNum);
	}
	asf_debug_l2("asf not enabled: {%lu, %lu} return 1.. REVIEW??\n",  ulIndex, ulMagicNum);
	return 0;
}


unsigned int asfFfpInacRefreshTmrCb(unsigned int ulVSGId,
				    unsigned int ulIndex, unsigned int ulMagicNum, unsigned int ulHashVal)
{
	ffp_flow_t *flow1, *flow2;
	ACCESS_XGSTATS();

	asf_debug_l2("vsg %u idx %u magic %u hash %u\n", ulVSGId, ulIndex, ulMagicNum, ulHashVal);
	XGSTATS_INC(InacTmrCalls);

	flow1 = ffp_flow_by_id_ex(ulIndex, ulMagicNum);
	if (flow1) {
		unsigned long flow1_idle, flow2_idle, ulIdleTime;

		flow2 = ffp_flow_by_id(&flow1->other_id);
		if (!flow2) {
			asf_debug("Other flow is not found.. doing nothing!!\n");
			XGSTATS_INC(InacTmrCtxBadFlow2);
			return 0;
			/*this may happen during flow deletion */
		}

		flow1_idle = ASF_LAST_IN_TO_IDLE(flow1->ulLastPktInAt);
		flow2_idle = ASF_LAST_IN_TO_IDLE(flow2->ulLastPktInAt);

		ulIdleTime = ASF_MIN(flow1_idle, flow2_idle);

		if (ffpCbFns.pFnFlowActivityRefresh) {
			ASFFFPFlowRefreshInfo_t ind;

			ind.tuple.ulSrcIp = flow1->ulSrcIp;
			ind.tuple.ulDestIp = flow1->ulDestIp;
			ind.tuple.usSrcPort = (flow1->ulPorts >> 16);
			ind.tuple.usDestPort = flow1->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow1->ucProtocol;
			ind.ulZoneId = flow1->ulZoneId;

			ind.ulInactiveTime = htonl(ulIdleTime);
			ind.ulHashVal = htonl(ulHashVal);
			ffp_copy_flow_stats(flow1, &ind.flow_stats);
			/* TODO: what to do with ASFwInfo */
			ind.ASFwInfo = (ASF_uint8_t *)flow1->as_flow_info;
			XGSTATS_INC(TmrCtxInacInd);
			ffpCbFns.pFnFlowActivityRefresh(flow1->ulVsgId, &ind);

			flow1->pInacRefreshTmr->ulTmOutVal =
				flow1->ulInacTime/asf_inac_divisor;

		}
		return 0;
	}
	XGSTATS_INC(InacTmrCtxBadFlow1);
	asf_debug("Inac Tmr: flow not found {%lu, %lu}\n", ulIndex, ulMagicNum);
	return 0;
}


/*
 * Initialization
 */
static int asf_ffp_init_flow_table()
{
	ptrIArry_nd_t   *node;
#ifdef ASF_FFP_USE_SRAM
	dma_addr_t      addr;
#endif
	int		i;
	unsigned int	max_num;

	/* TODO: handle error conditions properly to cleanup
		allocated memory */

	/* 10% of actual max value */
	max_num = ffp_max_flows/10;
	get_random_bytes(&asf_ffp_hash_init_value, sizeof(asf_ffp_hash_init_value));

	/* TODO: how do we calculate various limits based on ffp_max_flows ? */
	if (asfCreatePool("FfpFlow", max_num,
			  max_num, (max_num/2),
			  sizeof(ffp_flow_t),
			  &ffp_flow_pool_id) != 0) {
		asf_err("failed to initialize ffp_flow_pool\n");
		return -ENOMEM;
	}

	if (asfCreatePool("FfpBlobTimers", max_num,
			  max_num, (max_num/2),
			  sizeof(asfTmr_t),
			  &ffp_blob_timer_pool_id)) {
		asf_err("Error in creating pool for Blob Timers\n");
		return -ENOMEM;
	}

	if (asfCreatePool("FfpInacTimers", max_num,
			  max_num, (max_num/2),
			  sizeof(asfTmr_t),
			  &ffp_inac_timer_pool_id)) {
		asf_err("Error in creating pool for Inac Timers\n");
		return -ENOMEM;
	}

	asf_debug("Timer : BlobTmr_PoolId = %d InacTimer_PoolId = %d\r\n",
		ffp_blob_timer_pool_id, ffp_inac_timer_pool_id);

	asf_print("Instantiating blob timer wheels\n");

	/* TODO: check interBucketGap value */
	if (asfTimerWheelInit(ASF_FFP_BLOB_TMR_ID, 0,
			      ffp_hash_buckets, ASF_TMR_TYPE_SEC_TMR,
			      ASF_FFP_BLOB_TIME_INTERVAL, ASF_FFP_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing L2blob Timer wheel\n");
		return -ENOMEM;
	}

	asf_print("Instantiating inac timer wheels\n");

	if (asfTimerWheelInit(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
			      ffp_hash_buckets, ASF_TMR_TYPE_SEC_TMR,
			      ASF_FFP_INAC_TIME_INTERVAL, ASF_FFP_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing Inac Timer wheel\n");
		return -ENOMEM;
	}


	/* Register the callback function and timer pool Id */
	asf_print("Register Blob Timer App\n");

	if (asfTimerAppRegister(ASF_FFP_BLOB_TMR_ID, 0,
				asfFfpBlobTmrCb,
				ffp_blob_timer_pool_id)) {
		asf_debug("Error in registering Cb Fn/Pool Id\n");
		return -ENOMEM;
	}

	asf_print("Register Inac Timer App\n");
	if (asfTimerAppRegister(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
				asfFfpInacRefreshTmrCb,
				ffp_inac_timer_pool_id)) {
		asf_debug("Error in registering Cb Fn/Pool Id\n");
		return -ENOMEM;
	}
	asf_print("Initializing pointer array!\n");
	/* initialize pointer array */
#if 0  /*def ASF_FFP_USE_SRAM */
	addr = (unsigned long)(ASF_FFP_SRAM_BASE);
	node = ioremap_flags(addr,
			     (sizeof(ptrIArry_nd_t)*ffp_max_flows),
			     PAGE_KERNEL | _PAGE_COHERENT);
#else
	node = kzalloc((sizeof(ptrIArry_nd_t)*ffp_max_flows), GFP_KERNEL);
#endif
	if (NULL == node) {
		return -ENOMEM;
	}
	ptrIArray_setup(&ffp_ptrary, node, ffp_max_flows, 1);

	/* allocate hash table */
#ifdef ASF_FFP_USE_SRAM
	addr = (unsigned long)(ASF_FFP_SRAM_BASE);
	ffp_flow_table = (ffp_bucket_t *) ioremap_flags(addr,
			(sizeof(ffp_bucket_t) * ffp_hash_buckets),
			PAGE_KERNEL | _PAGE_COHERENT);
#else
	ffp_flow_table = kzalloc((sizeof(ffp_bucket_t) * ffp_hash_buckets),
					GFP_KERNEL);
#endif
	if (NULL == ffp_flow_table) {
		asf_err("Unable to allocate memory for ffp_flow_table");
		/*tbd - need better cleanup and allocation */
		ptrIArray_cleanup(&ffp_ptrary);
		return -ENOMEM;
	}

	for (i = 0; i < ffp_hash_buckets; i++) {
		spin_lock_init(&ffp_flow_table[i].lock);
		/* initialize circular list */
		ffp_flow_table[i].pNext = (ffp_flow_t *) &ffp_flow_table[i];
		ffp_flow_table[i].pPrev = ffp_flow_table[i].pNext;
	}
	return 0;
}

void asf_ffp_cleanup_all_flows(void)
{
	int i;
	ffp_bucket_t    *bkt;
	ffp_flow_t      *head, *flow, *temp;

	for (i = 0; i < ffp_hash_buckets; i++) {
		bkt = &ffp_flow_table[i];
		head = (ffp_flow_t *)  bkt;
		spin_lock_bh(&bkt->lock);
		flow = head->pNext;
		rcu_assign_pointer(head->pNext, head);
		rcu_assign_pointer(head->pPrev, head);
		spin_unlock_bh(&bkt->lock);

		/* Now the list is detached from the bucket */
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
			if (temp->pL2blobTmr) {
				asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, temp->pL2blobTmr);
			}
			if (temp->pInacRefreshTmr) {
				asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, temp->pInacRefreshTmr);
			}
			ptrIArray_delete(&ffp_ptrary, temp->id.ulArg1, ffp_flow_free_rcu);
		}
	}
}
static void asf_ffp_destroy_all_flows(void)
{
	int i;
	ffp_flow_t	*head, *flow, *temp;

	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *) &ffp_flow_table[i];
		flow = head->pNext;
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
			asfTimerFreeNodeMemory(temp->pL2blobTmr);
			asfTimerFreeNodeMemory(temp->pInacRefreshTmr);
			if (temp->bHeap)
				kfree(temp);
		}
	}
}
static void asf_ffp_destroy_flow_table()
{
	/*asf_ffp_cleanup_all_flows(); */
	asf_ffp_destroy_all_flows();

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	asf_debug("DeInit INAC_REFRESH_TMR Wheel\n");
	asfTimerWheelDeInit(ASF_FFP_INAC_REFRESH_TMR_ID, 0);
	asf_debug("DeInit BLOB_TMR Wheel\n");
	asfTimerWheelDeInit(ASF_FFP_BLOB_TMR_ID, 0);

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	asf_debug("DestroyPool InacTimerPool\n");
	if (asfDestroyPool(ffp_inac_timer_pool_id) != 0)
		asf_debug("failed to destroy inac timer mpool\n");

	asf_debug("DestroyPool BlobTimerPool\n");
	if (asfDestroyPool(ffp_blob_timer_pool_id) != 0)
		asf_debug("failed to destroy blob timer mpool\n");

	asf_debug("DestroyPool FlowPool\n");
	if (asfDestroyPool(ffp_flow_pool_id) != 0)
		asf_debug("failed to destroy flow mpool\n");

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	/* free the table bucket array */
#ifdef ASF_FFP_USE_SRAM
		iounmap((unsigned long *)(ffp_flow_table));
#else
		kfree(ffp_flow_table);
#endif

	/* destroy the pointer array */
	ptrIArray_cleanup(&ffp_ptrary);

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();
}


void asfDestroyNetDevEntries(void)
{
	int i;
	ASFNetDevEntry_t *dev;

	for (i = 0; i < asf_max_ifaces; i++) {
		if (asf_ifaces[i]) {
			dev = asf_ifaces[i];
			call_rcu((struct rcu_head *)  dev, asfNetDevFreeRcu);
		}
	}
}
ASF_uint32_t ASFSetVSGMode(ASF_uint32_t ulVSGId, ASF_Modes_t  mode)
{
	asf_vsg_info_t *vsg_info = NULL;

	asf_fentry;

	vsg_info = asf_ffp_get_vsg_info_node(ulVSGId);
	if (vsg_info == NULL) {
		asf_err("VSGId[=%d] Not Valid", ulVSGId);
		return ASF_FAILURE;
	}

	if (vsg_info->curMode == mode)
		return ASF_SUCCESS;

	if (!asf_fwd_func_on && (mode == fwdMode)) {
		asf_err(" Forwarding Mode Not Available");
		return ASF_FAILURE;
	}

	if (mode == fwdMode) {
		/*tbd take a lock */
		asf_print("Setting FWD Mode for VSG [%d]\n", ulVSGId);
		vsg_info->curMode = fwdMode;

	} else {
		/* cleanup all fwd flows */
#ifdef ASF_FWD_FP_SUPPORT
		if (vsg_info->curMode == fwdMode)
			if (pFwdCleanVsg)
				pFwdCleanVsg(ulVSGId);
#endif
		vsg_info->curMode = fwMode;
	}

	asf_fexit;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFSetVSGMode);

ASF_uint32_t ASFGetVSGMode(ASF_uint32_t ulVSGId , ASF_Modes_t *mode)
{
	asf_vsg_info_t *vsg_info = NULL;

	asf_fentry;

	vsg_info = asf_ffp_get_vsg_info_node(ulVSGId);
	if (vsg_info == NULL) {
		asf_err("VSGId[=%d] Not Valid", ulVSGId);
		return ASF_FAILURE;
	}

	*mode = vsg_info->curMode;

	asf_fexit;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFGetVSGMode);

ASF_uint32_t ASFEnableVSGFunctions(ASF_uint32_t ulVSGId, ASF_Functions_t funcs)
{
	asf_vsg_info_t *vsg_info = NULL;

	vsg_info = asf_ffp_get_vsg_info_node(ulVSGId);
	if (vsg_info == NULL) {
		asf_err("VSGId[=%d] Not Valid", ulVSGId);
		return ASF_FAILURE;
	}
	if (!asf_ipsec_func_on && funcs.bIPsec) {
		asf_err("VSGId[=%d] IPSEC Function Not Available", ulVSGId);
		return  ASF_FAILURE;
	}
	/* tbd take a RCU Lock
	enable IPSEC functionality */
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFEnableVSGFunctions);

ASF_uint32_t ASFDisableVSGFunctions(ASF_uint32_t ulVSGId, ASF_Functions_t funcs)
{
	asf_vsg_info_t *vsg_info = NULL;

	vsg_info = asf_ffp_get_vsg_info_node(ulVSGId);
	if (vsg_info == NULL) {
		asf_err("VSGId[=%d] Not Valid", ulVSGId);
		return ASF_FAILURE;
	}
	if (!(vsg_info->bIPsec) && (funcs.bIPsec)) {
		asf_err("VSGId[=%d] IPSEC Function Not Enabled", ulVSGId);
		return  ASF_FAILURE;
	}
	/*tbd take a RCU Lock
	disable IPSEC functionality
	cleanup the IPSEC database */
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFDisableVSGFunctions);

ASF_uint32_t ASFGetVSGFunctions(ASF_uint32_t ulVSGId , ASF_Functions_t *funcs)
{
	asf_vsg_info_t *vsg_info = NULL;
	asf_fentry;

	vsg_info = asf_ffp_get_vsg_info_node(ulVSGId);
	if (vsg_info == NULL) {
		asf_err("VSGId[=%d] Not Valid", ulVSGId);
		return ASF_FAILURE;
	}
	if (vsg_info->bIPsec)
		funcs->bIPsec = ASF_TRUE;
	asf_fexit;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFGetVSGFunctions);

ASF_uint32_t ASFGetAPIVersion(ASF_uint8_t Ver[])
{
	strcpy(Ver, asf_version);
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFGetAPIVersion);

void asf_register_devfp(void)
{
	devfp_register_rx_hook(&asf_ffp_devfp_rx);
}

void asf_unregister_devfp(void)
{
	devfp_register_rx_hook(NULL);
}

static int __init asf_init(void)
{
	int err;

	get_random_bytes(&rule_salt, sizeof(rule_salt));

	if (asf_max_vsgs > ASF_MAX_VSGS) {
		asf_err("Number of VSG exceeded the Max Limit =%d",
			ASF_MAX_VSGS);
		return -1;
	}

	/* FIXME: free allocated memory on error conditions during initialization */

	asfTimerInit(ASF_NUM_OF_TIMERS, 1);
	asf_debug("Initializing mpool module\n");
	if (asfInitPools() != 0) {
		return -1;
	}
	if (asfReasmInit() != 0) {
		return -1;
	}

	spin_lock_init(&asf_iface_lock);
	asf_ifaces = kzalloc(sizeof(ASFNetDevEntry_t *) * asf_max_ifaces, GFP_KERNEL);
	if (!asf_ifaces) {
		asf_err("Failed to allocate memory for asf interface array\n");
		return -ENOMEM;
	}

	asf_vsg_info = kzalloc(sizeof(asf_vsg_info_t *) * asf_max_vsgs, GFP_KERNEL);
	if (!asf_vsg_info) {
		asf_err("Failed to allocate memory for vsg specific info array\n");
		return -ENOMEM;
	}

	asf_debug("Allocating perCpu memory for global stats\n");
	asf_gstats = asfAllocPerCpu(sizeof(ASFFFPGlobalStats_t));
	if (!asf_gstats) {
		asf_err("Failed to allocate per-cpu memory for global statistics\n");
		return -ENOMEM;
	}

#ifdef ASF_FFP_XTRA_STATS
	asf_debug("Allocating perCpu memory for xtra global stats\n");
	asf_xgstats = asfAllocPerCpu(sizeof(ASFFFPXtraGlobalStats_t));
	if (!asf_xgstats) {
		asf_err("Failed to allocate per-cpu memory for xtra global statistics\n");
		return -ENOMEM;
	}
#endif


	asf_debug("Allocating perCpu memory for VSG stats\n");
	asf_vsg_stats = asfAllocPerCpu(sizeof(ASFFFPVsgStats_t)*asf_max_vsgs);
	if (!asf_vsg_stats) {
		asf_err("Failed to allocate per-cpu memory for VSG statistics\n");
		return -ENOMEM;
	}
#if 0
	l2fw_validation_time = jiffies;
#endif


	asf_debug("Registering PROC entries\n");
	asf_register_proc();

	asf_print("Initializing Flow Table\n");
	err = asf_ffp_init_flow_table();
	if (err) {
		asf_ffp_destroy_flow_table();
		return err;
	}
	asf_debug("Registering hooks to DevFP\n");
	err = devfp_register_rx_hook(&asf_ffp_devfp_rx);
	return err;
}

static void __exit asf_exit(void)
{
/*	wait_queue_head_t dummyWq; */

	asf_debug("Unregister DevFP RX Hooks!\n");
	devfp_register_rx_hook(NULL);

	asfTimerDisableKernelTimers();
	asf_enable = 0;

	asf_debug("Waiting for all CPUs to finish existing packets!\n");
	synchronize_rcu();

	asf_debug("Unregister PROC entries\n");
	asf_unregister_proc();

#if 0
	init_waitqueue_head(&dummyWq);
	printk("Sleeping for 5 seconds to be safe from pending timer callabcks & DevFP callbacks!\n");
	sleep_on_timeout(&dummyWq, 5*HZ);
#endif

	asf_print("Destroying existing flow table!\n");
	asf_ffp_destroy_flow_table();

	asf_debug("Waiting for all CPUs to finish existing packets!\n");
	synchronize_rcu();

	asf_debug("Free PerCpu memory of Vsg Stats\n");
	asfFreePerCpu(asf_vsg_stats);
	asf_debug("Free PerCpu memory of Global Stats\n");
	asfFreePerCpu(asf_gstats);

#ifdef ASF_FFP_XTRA_STATS
	asf_debug("Free PerCpu memory of Xtra Global Stats\n");
	asfFreePerCpu(asf_xgstats);
#endif

	asf_debug("DeInit Reassembly Module\n");
	asfReasmDeInit();

	asf_debug("DeInit MemPool Module\n");
	if (asfDeInitPools() != 0) {
		asf_debug("failed to deinit pools!\n");
	}

	asf_debug("DeInit Timer Module\n");
	asfTimerDeInit();

	asf_debug("Destroy ASF interface entries\n");
	asfDestroyNetDevEntries();

	asf_debug("Waiting for all RCU callbacks to finish\n");
	synchronize_rcu();

	asf_debug("Freeing ASF interface index\n");
	kfree(asf_ifaces);

	asf_debug("Freeing VSG specific info array\n");
	kfree(asf_vsg_info);

	asf_debug("Unregister DevFP TX Hooks at Last!\n");
	devfp_register_tx_hook(NULL);
}
module_init(asf_init);
module_exit(asf_exit);
