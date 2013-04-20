/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfcore.c
 *
 * Description: Main module for ASF Core initialization and Firewall Handling.
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 * Modifier:	Sachin saxena <sachin.saxena@freescale.com>
 *
 */
/*
 * History
 * 22 Sep 2010 - Sachin Saxena - Integrating code for IPv4 Forwarding support.
 * 30 Sep 2010 - Sachin Saxena - Changes for Per VSG flow table support.
 * 22 Jul 2011 - Sachin Saxena - Adding support for ASF tool Kit.
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
#include <linux/ipv6.h>
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
#ifdef CONFIG_DPA
#include <dpa/dpaa_eth.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#else
#include <gianfar.h>
#endif
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include "gplcode.h"
#include "asf.h"
#include "asfcmn.h"
#include "asffwd.h"
#include "asfterm.h"
#include "asfipsec.h"
#include "asfparry.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfreasm.h"
#include "asfpvt.h"
#include "asftcp.h"
#ifdef	ASF_IPV6_FP_SUPPORT
#include "asfipv6pvt.h"
#endif

MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION("Application Specific FastPath");
MODULE_LICENSE("GPL");

#ifdef ASF_TOOLKIT_SUPPORT
/*! \brief Index used by Linux to register driver */
#define ASF_HLD_MAJORNUMBER (100)
/*! \brief Name used when mounting path */
#define ASF_HLD_DEVICE_NAME "asf_hld"
#endif

char *periodic_errmsg[] = PERIODIC_ERRMSGS;
char *asf_version = "asf-rel-0.2.0";
/* Initilization Parameters */
int asf_enable;
int ffp_max_flows = ASF_FFP_MAX_FLOWS;
int asf_max_vsgs = ASF_MAX_VSGS;
int asf_max_ifaces = ASF_MAX_IFACES;
int ffp_hash_buckets = ASF_FFP_MAX_HASH_BKT;
int asf_inac_divisor = ASF_FFP_FLOW_INAC_DIVISOR;
int asf_l2blob_refresh_npkts = ASF_MAX_L2BLOB_REFRESH_PKT_CNT;
int asf_l2blob_refresh_interval = ASF_MAX_L2BLOB_REFRESH_TIME;
int asf_reasm_timeout = ASF_REASM_REASM_TIMEOUT; /* in seconds ? */
int asf_reasm_maxfrags = ASF_REASM_MAX_NUM_FRAGS;
int asf_reasm_min_fragsize = ASF_REASM_MIN_FRAGSIZE;
int asf_tcp_drop_oos;
#ifdef ASF_TERM_FP_SUPPORT
int asf_default_mode = fwMode | termMode;
#else
int asf_default_mode = fwMode;
#endif
ASF_boolean_t asf_fwd_func_on;
ASF_boolean_t asf_term_func_on;
ASF_boolean_t asf_ipsec_func_on;
extern unsigned long asf_reasm_hash_list_size;
extern unsigned long asf_reasm_num_cbs;
#ifdef ASF_IPV6_FP_SUPPORT
extern unsigned long asf_ipv6_reasm_hash_list_size;
extern unsigned long asf_ipv6_reasm_num_cbs;
extern int ffp_ipv6_max_flows;
extern int ffp_ipv6_hash_buckets;

#endif
#ifdef ASF_QOS
int asf_qos_enable;
EXPORT_SYMBOL(asf_qos_enable);

module_param(asf_qos_enable, bool, 0644);
MODULE_PARM_DESC(asf_qos_enable, "Enable or disable ASF QoS Functionality");
#endif
module_param(asf_enable, bool, 0644);
MODULE_PARM_DESC(asf_enable, "Enable or disable ASF upon loading");
module_param(ffp_max_flows, int, 0444);
MODULE_PARM_DESC(ffp_max_flows, "Maximum number of FFP flows");
module_param(asf_max_vsgs, int, 0444);
MODULE_PARM_DESC(asf_max_vsgs, "Maximum number of VSGs");
module_param(asf_max_ifaces, int, 0444);
MODULE_PARM_DESC(asf_max_ifaces, "Maximum number of interfaces");
module_param(ffp_hash_buckets, int, 0444);
MODULE_PARM_DESC(ffp_hash_buckets,
			"Number of hash buckets in FFP flow hash table");
module_param(asf_l2blob_refresh_interval, int, 0644);
MODULE_PARM_DESC(asf_l2blob_refresh_interval,
	"Periodic interval at which L2 blob refresh indication to be generated");
module_param(asf_tcp_drop_oos, bool, 0644);
MODULE_PARM_DESC(asf_tcp_drop_oos, "Drop TCP out of sequence packets");
module_param(asf_reasm_hash_list_size, ulong, 0444);
MODULE_PARM_DESC(asf_reasm_hash_list_size, "Size of reassembly hash table");
module_param(asf_reasm_num_cbs, ulong, 0444);
MODULE_PARM_DESC(asf_reasm_num_cbs,
				"Maximum number of Reassembly context blocks per VSG");
#ifdef ASF_IPV6_FP_SUPPORT
module_param(asf_ipv6_reasm_num_cbs, ulong, 0444);
MODULE_PARM_DESC(asf_reasm_num_cbs,
				"Maximum number of IPv6 Reassembly context blocks per VSG");
module_param(ffp_ipv6_max_flows, int, 0444);
MODULE_PARM_DESC(ffp_ipv6_max_flows, "Maximum number of FFP IPv6 flows");
module_param(ffp_ipv6_hash_buckets, int, 0444);
MODULE_PARM_DESC(ffp_ipv6_hash_buckets,
			"Number of hash buckets in FFP IPv6 flow hash table");
#endif

#define ASF_DO_INC_CHECKSUM

/* DPAA has Error Queue Handling .. so not required.
#define TRAP_UNEXP_CONDITION
*/
#ifdef CONFIG_DPA
	#define DPAA_PARSE_L2_ETH		0x8000
	#define DPAA_PARSE_L2_VLAN		0x4000
	#define DPAA_PARSE_L2_PPPOE		0x0800
	#define DPAA_PARSE_L2_TYPES		(DPAA_PARSE_L2_ETH |	\
						DPAA_PARSE_L2_VLAN	\
						| DPAA_PARSE_L2_PPPOE)
	#define DPAA_PARSE_L2_BMCAST		0x0060
	#define DPAA_PARSE_L2_ERROR		0x001F

	#define DPAA_PARSE_L3_ERROR		0x0200
	#define DPAA_PARSE_L3_TYPE_MASK		0xFC00
	#define DPAA_PARSE_L3_FIRST_IPHDR_V4	0x8000
	#define DPAA_PARSE_L3_FIRST_IPHDR_V6	0x4000
	#define DPAA_PARSE_L3_FIRST_IPHDR_UNK_PROTO	0x0080
	#define DPAA_PARSE_L3_FIRST_IPHDR_FRAG	0x0040
	#define DPAA_PARSE_L3_PKT_TYPE	        0x0030
	#define DPAA_PARSE_L4_ERROR		0x10
	#define DPAA_PARSE_L4_CKSUM_DONE	0x01
	#define DPAA_PARSE_L4_NONZERO_CKSUM	0x08
	#define DPAA_PARSE_L4_OTHER_PROTO	0x80
	#define DPAA_PARSE_L4_PROTO_MASK	0xE0
	#define DPAA_PARSE_L4_PROTO_TCP		0x20
	#define DPAA_PARSE_L4_PROTO_UDP		0x40
	#define DPAA_PARSE_L4_PROTO_IPSEC	0x60
	#define DPAA_PARSE_L4_IPSEC_MASK	0x6C
	#define DPAA_PARSE_L4_IPSEC_ESP		0x68
	#define DPAA_PARSE_L4_IPSEC_AH		0x64

	#define FM_FD_STAT_L4CV			0x00000004
#endif

#ifdef CONFIG_DPA
#define PER_CPU_BP_COUNT(bp) \
	(*(per_cpu_ptr((bp)->percpu_count, smp_processor_id())))
#endif
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
static unsigned int  ffp_flow_pool_id = -1;
static unsigned int  ffp_blob_timer_pool_id = -1;
static unsigned int  ffp_inac_timer_pool_id = -1;

ASF_boolean_t   asf_ffp_notify = ASF_FALSE;
ASFFFPCallbackFns_t      ffpCbFns = {0};

unsigned long asf_ffp_hash_init_value;

extern struct net_device *__find_vlan_dev(struct net_device *real_dev,
			u16 vlan_id);

EXPORT_SYMBOL(asf_ffp_hash_init_value);


static int asf_ffp_init_flow_table(void);
static void asf_ffp_destroy_flow_table(void);
void asf_ffp_cleanup_all_flows(void);

#define ASF_FFP_BLOB_TIME_INTERVAL 1    /* inter bucket gap */
#define ASF_FFP_BLOB_TIMER_BUCKT 512    /* Max L2blob timer value */
#define ASF_FFP_INAC_TIME_INTERVAL 1    /* inter bucket gap */
#define ASF_FFP_INAC_TIMER_BUCKT 2048    /* Max inactity timer value  */
#define ASF_FFP_NUM_RQ_ENTRIES  (256)
#define ASF_FFP_AUTOMODE_FLOW_INACTIME  (300)

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

ASFFFPVsgStats_t *get_asf_vsg_stats()
{
	return asf_vsg_stats;
}
EXPORT_SYMBOL(get_asf_vsg_stats);

ASFFFPGlobalStats_t *get_asf_gstats() /* per cpu global stats */
{
	return asf_gstats;
}
EXPORT_SYMBOL(get_asf_gstats);

#ifdef ASF_INGRESS_MARKER
pASFCbFnQosMarker_f pASFCbFnQosMarker_p;
EXPORT_SYMBOL(pASFCbFnQosMarker_p);
pASFQOSCbFnSkbMark_f	pSkbMarkfn;
EXPORT_SYMBOL(pSkbMarkfn);

ASF_void_t ASFRegisterQosMarkerFn(pASFCbFnQosMarker_f pFn1,
						pASFQOSCbFnSkbMark_f pFn2)
{
	pASFCbFnQosMarker_p = pFn1;
	pSkbMarkfn = pFn2;
}
EXPORT_SYMBOL(ASFRegisterQosMarkerFn);
#endif

#ifdef ASF_IPSEC_FP_SUPPORT
ASFFFPIPSecInv4_f pFFPIPSecIn;
EXPORT_SYMBOL(pFFPIPSecIn);

ASFFFPIPSecOutv4_f pFFPIPSecOut;
EXPORT_SYMBOL(pFFPIPSecOut);

ASFFFPIPSecInVerifyV4_f pFFPIpsecInVerify;
EXPORT_SYMBOL(pFFPIpsecInVerify);

ASFFFPIPSecProcessPkt_f pFFPIpsecProcess;
EXPORT_SYMBOL(pFFPIpsecProcess);

void ASFFFPRegisterIPSecFunctions(ASFFFPIPSecInv4_f pIn,
				ASFFFPIPSecOutv4_f pOut,
				ASFFFPIPSecInVerifyV4_f pIpsecInVerify,
				ASFFFPIPSecProcessPkt_f pIpsecProcess)
{
	pFFPIPSecIn = pIn;
	pFFPIPSecOut = pOut;
	pFFPIpsecInVerify = pIpsecInVerify;
	pFFPIpsecProcess = pIpsecProcess;

	if (pFFPIPSecIn && pFFPIPSecOut)
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

#ifdef ASF_TERM_FP_SUPPORT

ASFTERMCleanVsg_f	pTermCleanVsg;
ASFTERMProcessPkt_f	pTermProcessPkt;
EXPORT_SYMBOL(pTermProcessPkt);

void ASFFFPRegisterTERMFunctions(
		ASFTERMProcessPkt_f pTerm,
		ASFTERMCleanVsg_f pCleanVsg)
{
	pTermCleanVsg = pCleanVsg;

	pTermProcessPkt = pTerm;
	if (pTermProcessPkt)
		asf_term_func_on = ASF_TRUE;
	else
		asf_term_func_on = ASF_FALSE;
}
EXPORT_SYMBOL(ASFFFPRegisterTERMFunctions);
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
#ifdef CONFIG_DPA
return ASFFFPComputeFlowHash1_DPAA(ulSrcIp, ulDestIp, ulPorts);
#else
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
	ulDestIp += ulZoneId;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulPorts);
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	return rule_salt + ulPorts;
#endif
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
				uint32_t ports, unsigned char protocol,
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
#ifdef CONFIG_DPA
static inline ffp_flow_t  *asf_ffp_flow_lookup_DPAA(
					unsigned long sip,
					unsigned long dip,
					uint32_t ports,
					unsigned long vsg,
					unsigned long szone,
					unsigned char protocol,
					unsigned long HashVal)
{
	ffp_bucket_t *pHead;
#ifdef USE_SRCIP_AS_HASH
	HashVal = sip;
#endif
	pHead = asf_ffp_bucket_by_hash(HashVal);
	return asf_ffp_flow_lookup_in_bkt(sip, dip, ports,
					protocol, vsg, szone,
					(ffp_flow_t *)pHead);
}
struct sk_buff *asf_alloc_buf_skb(struct net_device *dev)
{
	struct dpa_priv_s *priv = netdev_priv(dev);
	struct dpa_bp *bp;
	struct bm_buffer bmb[8];
	struct sk_buff **skbh;
	struct sk_buff *skb;
	dma_addr_t addr;
	int n;

	/* choose to use the last bpid to get buffers */
	bp = priv->dpa_bp;
	n = bman_acquire(bp->pool, bmb, 1, 0);
	if (unlikely(n <= 0))
		return NULL;

	addr = bm_buf_addr(&bmb[0]);
	skbh = (struct sk_buff **)phys_to_virt(addr);
	skb = *skbh;

	dma_unmap_single(bp->dev, addr, bp->size, DMA_FROM_DEVICE);

	skb->cb[BPID_INDEX] = bp->bpid;

	skb->data = ((u8 *)skbh + DPA_BP_HEAD);
	skb_reset_tail_pointer(skb);

	return skb;
}
int asf_free_buf_skb(struct net_device *dev, struct sk_buff *skb)
{
	struct dpa_priv_s *priv = netdev_priv(dev);
	struct dpa_bp *bp;
	struct bm_buffer bmb;
	dma_addr_t addr;
	int ret;
	struct sk_buff **skbh;
	int pad;

	bp = priv->dpa_bp;
	pad = round_down(((uintptr_t)skb_end_pointer(skb) - (uintptr_t)skb->head) -
			(bp->size + NET_SKB_PAD), L1_CACHE_BYTES);
	skbh = (struct sk_buff **)(skb->head + pad);
	addr = dma_map_single(bp->dev, skbh,
				bp->size, DMA_FROM_DEVICE);
	/* Recycle the SKB */
	skb_recycle(skb);

	*skbh = skb;

	bm_buffer_set64(&bmb, addr);
	ret = bman_release(bp->pool, &bmb, 1, 0);

	if (unlikely(ret < 0)) {
		pr_err(KBUILD_MODNAME ": dpa_free_buf_skb() "
				"failed for bman_release error: %d\n", ret);
		return ret;
	}

	return 0;
}
/* deducts skb accounting from common pool */
void asf_dec_skb_buf_count(struct sk_buff *skb)
{
	struct dpa_bp *bp;
	struct sk_buff *skb_temp;
	int i;
	struct dpa_priv_s *priv = netdev_priv(skb->dev);

	/* If first SKB doen't have bpid, then frag_list shouldn'y have bpid */
	if (!(skb->cb[BPID_INDEX]))
		return;

	bp = priv->dpa_bp;
	for (i = 0; (skb->cb[BPID_INDEX] == (&bp[i])->bpid); i++) {
		bp = &bp[i];
		break;
	}

	PER_CPU_BP_COUNT(bp)--;
	skb->cb[BPID_INDEX] = 0;

	for (skb_temp = skb_shinfo(skb)->frag_list;
		skb_temp != NULL; skb_temp = skb_temp->next) {
		/* we can have mix bpids */
		if (skb_temp->cb[BPID_INDEX]) {
			bp = priv->dpa_bp;
			for (i = 0; (skb_temp->cb[BPID_INDEX] == (&bp[i])->bpid); i++) {
				bp = &bp[i];
				break;
			}

			PER_CPU_BP_COUNT(bp)--;
			skb_temp->cb[BPID_INDEX] = 0;
		}
	}
	return;
}
EXPORT_SYMBOL(asf_dec_skb_buf_count);
#endif
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

	pHead = (ffp_flow_t *) asf_ffp_bucket_by_hash(*pHashVal);

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
		asfCopyWords((unsigned int *) ucL2blob, (unsigned int *)(skb_mac_header(skb) + ETH_HLEN), x_hh_len);
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
			if (ASF_netif_receive_skb(pSkb) == NET_RX_DROP)
				asf_debug("Error in Submitting to NetRx: Should not happen\r\n");
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
#ifdef CONFIG_DPA
				asf_dec_skb_buf_count(pSkb);
#endif
				abuf.nativeBuffer = pSkb;
				ffpCbFns.pFnNoFlowFound(anDev->ulVSGId,
					anDev->ulCommonInterfaceId,
					anDev->ulZoneId, abuf,
					(genericFreeFn_t)ASF_SKB_FREE_FUNC,
					pSkb);
			}
		}
	} else {
		return asfAdjustFragAndSendToStack(skb, anDev);
	}
	return 1;
}

static inline ffp_flow_t *ffp_flow_by_id(ASFFFPFlowId_t *id)
{
	return (ffp_flow_t *) ((ffp_ptrary.pBase[id->ulArg1].ulMagicNum == id->ulArg2) ? ffp_ptrary.pBase[id->ulArg1].pData : NULL);
}

static inline ffp_flow_t *ffp_flow_by_id_ex(unsigned int ulIndex, unsigned int ulMagicNum)
{
	return (ffp_flow_t *) ((ffp_ptrary.pBase[ulIndex].ulMagicNum == ulMagicNum) ? ffp_ptrary.pBase[ulIndex].pData : NULL);
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
	if (skb_dst(skb) == NULL) {
		int err = ip_route_input(skb, iph->daddr, iph->saddr,
					 iph->tos, dev);
		if (unlikely(err))
			return -1;
	}

	if (ip_rcv_options(skb))
		return -1;

	ip_forward_options(skb);

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

#ifdef CONFIG_DPA
/* do all skb setup that happens in DPAA ethernet driver after
	devfp_rx_hook and before netif_receive_skb */
ASF_void_t *asf_abuf_to_skb(ASFBuffer_t *pAbuf)
{
	struct sk_buff *skb = pAbuf->pAnnot->skbh;
	t_FmPrsResult *pParse = &pAbuf->pAnnot->parse_result;
	int cache_fudge;
	struct dpa_priv_s		*priv;
	struct dpa_percpu_priv_s	*percpu_priv;

	if (NULL != pAbuf->nativeBuffer)
		return skb;
	/* we do not try to return this frame back
		to ingress iface bp any more */
	if (unlikely(!(pAbuf->bbuffInDomain))) {
		priv = netdev_priv(pAbuf->ndev);
		percpu_priv = per_cpu_ptr(priv->percpu_priv,
					smp_processor_id());

		(*percpu_priv->dpa_bp_count)--;
	} else {
		skb->cb[BPID_INDEX] = pAbuf->pAnnot->fd->bpid;
	}

	/* set data/length from eth hdr */
	cache_fudge = (unsigned char *)pAbuf->ethh - skb->head - NET_SKB_PAD;
	skb->mac_len = pParse->ip_off[0];
	skb->dev = pAbuf->ndev;
	skb->data += cache_fudge;
	skb_reset_mac_header(skb);
	skb->data += skb->mac_len;
	skb->tail += pAbuf->pAnnot->fd->length20 + cache_fudge;
	skb->len  = (pAbuf->pAnnot->fd->length20 - skb->mac_len);
	/* To handle - PPPoE, Now we are at ip hdr */
	skb->protocol = htons(*(u16 *)(skb->data - 2));
	asf_debug("pAbuf->pAnnot->fd->length20 %d, pAbuf->ethh 0x%X,"
			" pParse->ip_off[0] 0x%X, pParse->l4_off 0x%X\n",
			pAbuf->pAnnot->fd->length20, pAbuf->ethh,
			pParse->ip_off[0], pParse->l4_off);

	/* fill in some skb fields */
	skb_reset_network_header(skb);
	skb_set_transport_header(skb, (pParse->l4_off - pParse->ip_off[0]));

	skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* update pointer */
	pAbuf->nativeBuffer = skb;
	/* Will be helpful in Defrag */
	memcpy(&(skb->cb[ANNOTATION_ADDR_INDEX]), &(pAbuf->pAnnot), 4)
	asf_debug("skb 0x%p, skb->head 0x%p, skb->data 0x%p, skb->tail 0x%p"
		" skb->len 0x%x skb->mac_header 0x%p\n\n",
	       skb, skb->head, skb->data, skb->tail,
	       skb->len, skb->mac_header);

	return skb;
}
EXPORT_SYMBOL(asf_abuf_to_skb);
/* setup abuf for skb head; skb frags are left as is  */
ASF_void_t asf_skb_to_abuf(ASFBuffer_t *pAbuf,
					ASFNetDevEntry_t *pNdev)
{
	struct sk_buff *skb = pAbuf->nativeBuffer;
	unsigned long	ulPorts;
	struct iphdr	*iph;
	t_FmPrsResult	*pParse;
	u8 *ptr;
	/* locate a cache aligned annotation start */
	memcpy(&ptr, &(skb->cb[ANNOTATION_ADDR_INDEX]), 4);
	if (unlikely(ptr < skb->head)) {
		asf_debug("%s: no headroom; dropping pkt\n", __func__);
		asf_dperr("%s", periodic_errmsg[PERR_REASM_NO_HDROOM]);
		ASF_SKB_FREE_FUNC(skb);
		pAbuf->nativeBuffer = NULL;
		return;
	}
	/* fill in known values */
	pAbuf->pAnnot = (struct annotations_t *)ptr;
	pAbuf->pAnnot->skbh = skb;
	pAbuf->iph = (struct iphdr *)skb->data;
	/* pAbuf->nativeBuffer is already set */
	pAbuf->ethh = (struct ethhdr *)skb_mac_header(skb);
	/*pAbuf->pAnnot->fd->length20 = skb->len +
			((u32)pAbuf->iph - (u32)pAbuf->ethh); */
	asf_debug("RES: skb 0x%p, skb->head 0x%p, skb->data 0x%p, "
			"skb->tail 0x%p skb->len 0x%x skb->mac_header 0x%p\n\n",
			skb, skb->head, skb->data, skb->tail,
			skb->len, skb->mac_header);

	pParse = &pAbuf->pAnnot->parse_result;
	if (pAbuf->iph->version != 4)
		return;	/* HW Hash not used in IPv6 */

	iph = pAbuf->iph;
	/* Setting the required L4 Fields */
	switch (iph->protocol) {
	case IPPROTO_UDP:
	{
		struct udphdr *udph;
		udph = (struct udphdr *)((unsigned char *)iph
					+ (4 * iph->ihl));
		ulPorts = (udph->source << 16) | udph->dest;
		pAbuf->pAnnot->hr_hilo.loHash =
			ASFFFPComputeFlowHash1_DPAA(iph->saddr,
					iph->daddr, ulPorts);
		pParse->l4r = DPAA_PARSE_L4_PROTO_UDP;
		break;
	}
	case IPPROTO_TCP:
	{
		struct tcphdr *tcph;
		tcph = (struct tcphdr *)((unsigned char *)iph
					+ (4 * iph->ihl));
		ulPorts = (tcph->source << 16) | tcph->dest;
		pAbuf->pAnnot->hr_hilo.loHash =
			ASFFFPComputeFlowHash1_DPAA(iph->saddr,
						iph->daddr, ulPorts);
		pParse->l4r = DPAA_PARSE_L4_PROTO_TCP;
		break;
	}
	case IPPROTO_ESP:
		pParse->l4r = DPAA_PARSE_L4_IPSEC_ESP;
		break;
	default:
		pParse->l4r = DPAA_PARSE_L4_OTHER_PROTO;
	}

}
#endif

#ifdef CONFIG_DPA
int asf_ffp_devfp_rx(void *ptr, struct net_device *real_dev,
							unsigned int  fqid)
{
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ASFFFPGlobalStats_t	*gstats;
#endif
	struct qm_fd		*fd  = (struct qm_fd *)ptr;
	int			bLockFlag;
	/*struct net_device	*logical_dev;*/
	/*x_hh_len = extra hardware-header length (data b/w end
		of ETH_H to IPH) */
	ASFNetDevEntry_t	*anDev = NULL;
	struct iphdr		*iph;
	ASFBuffer_t		abuf;
	t_FmPrsResult		*pParse;
	if (unlikely(0 == asf_enable))
		return AS_FP_PROCEED;

	ASF_RCU_READ_LOCK(bLockFlag);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	ACCESS_XGSTATS();
	gstats->ulInPkts++;
#endif

	/* gather all pointers used often */
	abuf.pAnnot = phys_to_virt(qm_fd_addr(fd));
	abuf.ethh = (struct ethhdr *)((void *)abuf.pAnnot + fd->offset);
	pParse = &abuf.pAnnot->parse_result;
	abuf.ndev = real_dev;
	/* overwrite physical addr with virt addr */
	abuf.pAnnot->fd = fd;
	abuf.nativeBuffer = NULL;
	abuf.frag_list = 0;
	abuf.bbuffInDomain = ASF_FALSE;
	/* L2 header related checks */
	if (unlikely(!(pParse->l2r & DPAA_PARSE_L2_TYPES))) {
		asf_debug("unhandled L2 type 0x%04X\n", pParse->l2r);
		XGSTATS_INC(L2Unknown);
		goto ret_pkt;
	}
#ifdef TRAP_UNEXP_CONDITION
	/* If pkts with L2 error always goto error que,
	then this check can be removed */
	if (unlikely(pParse->l2r & DPAA_PARSE_L2_ERROR)) {
		asf_err("error indicated in L2 parse result 0x%04X\n",
			pParse->l2r);
		XGSTATS_INC(L2ParseErr);
		goto drop_pkt;
	}
#endif

	/* make sure the pkt is on a mapped device */
	anDev = ASFNetDev(real_dev);
	if (unlikely(NULL == anDev))
		goto iface_not_found;


#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	/* identify VLAN device if it is VLAN pkt */
	if (unlikely(pParse->l2r & DPAA_PARSE_L2_VLAN)) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *)((void *)abuf.ethh
				+ pParse->vlan_off[0]);
		unsigned short usVlanId;

		XGSTATS_INC(VlanPkts);

		usVlanId = ntohs(vhdr->h_vlan_TCI) & VLAN_VID_MASK;
		if (likely(anDev->pVlanDevArray)) {
			anDev = ASFGetVlanDev(anDev, usVlanId);
			if (unlikely(anDev == NULL)) {
				asf_debug("VLAN dev entry not"
					"found (usVlanId %u)\n",
					usVlanId);
				XGSTATS_INC(InvalidVlanDev);
				goto iface_not_found;
			}
		} else {
			asf_debug("NULL VlanDevArray (cii %u) (usVlanId %u)\n",
				anDev->ulCommonInterfaceId, usVlanId);
			goto iface_not_found;
		}
		asf_debug("vlan dev %p on real dev %s\n", anDev->ndev,
			real_dev->name);
	}
	/* identify PPPoE device if it is PPPoE pkt */
	if (unlikely(pParse->l2r & DPAA_PARSE_L2_PPPOE)) {
		unsigned char *poe_hdr = (unsigned char *)((void *)abuf.ethh
				+ pParse->pppoe_off);
		unsigned short ppp_proto, pppoe_session_id;

		XGSTATS_INC(PPPoEPkts);

		ppp_proto = *(unsigned short *) (poe_hdr + 6);
		/* PPPoE header is of 6 bytes */
		/* PPPOE: VER = 1, TYPE = 1, CODE = 0 and
			PPP:_PROTO = 0x0021 (IP) */
		if ((poe_hdr[0] != 0x11) || (poe_hdr[1] != 0) ||
			(ppp_proto != __constant_htons(0x0021))) {
			asf_debug("PPPoE traffic but not interested"
				"%02x%02x %04x\n",
				poe_hdr[0], poe_hdr[1], ppp_proto);
			XGSTATS_INC(PPPoEUnkPkts);
			goto ret_pkt;
		}

		pppoe_session_id = *(unsigned short *) (poe_hdr + 2);
		anDev = ASFGetPPPoEDev(anDev, pppoe_session_id);
		if (unlikely(anDev == NULL)) {
			asf_debug("PPPoE dev entry not found (SessId %u)\n",
				pppoe_session_id);
			XGSTATS_INC(InvalidPPPoEDev);
			goto iface_not_found;
		}
		asf_debug("PPPoE sessId %u dev %p on real dev %s\n",
				pppoe_session_id,
				anDev->ndev, real_dev->name);

	}

	/* Check if ethernet device / VLAN device is attached to a Bridge */
	if (unlikely(anDev->pBridgeDev)) {
		asf_debug(" bridged port: anDev=%p netdev=%s anDev->br=%p "
				"br->netdev=%p\n", anDev, real_dev->name,
				anDev->pBridgeDev, anDev->pBridgeDev->ndev);
		anDev = anDev->pBridgeDev;
		/* TODO: if pppoe/VLAN interfaces are bridged, then anDev->ndev
			should be correctly set */
		real_dev = anDev->ndev;
	}
	if (!real_dev) {
		asf_err("logical dev NULL for pkt from %s\n", abuf.ndev->name);
		goto ret_pkt;
	}
	if (unlikely(is_multicast_ether_addr(abuf.ethh->h_dest))) {
		asf_debug_l2("Multicast or Broadcast on iface %s\n",
				real_dev->name);
		XGSTATS_INC(BMCastPkts);
		goto ret_pkt;
	}
	/* see if it is destined to us; may be pkts
		received in promiscuous mode */
	if (unlikely(!(ether_addr_equal_64bits(abuf.ethh->h_dest,
			real_dev->dev_addr)))) {
		asf_debug_l2("PACKET_OTHERHOST on iface %s\n",
				real_dev->name);
		XGSTATS_INC(OtherHost);
		goto ret_pkt;
	}
	XGSTATS_INC(ThisHost);

	if (unlikely(anDev->ulVSGId == ASF_INVALID_VSG)) {
		asf_abuf_to_skb(&abuf);
		XGSTATS_INC(VsgUnknown);
		ffpCbFns.pFnVSGMappingNotFound(anDev->ulCommonInterfaceId,
			abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC, abuf.nativeBuffer);
		ASF_RCU_READ_UNLOCK(bLockFlag);
		return AS_FP_STOLEN;
	}
	if (unlikely(anDev->ulZoneId == ASF_INVALID_ZONE)) {
		asf_abuf_to_skb(&abuf);
		XGSTATS_INC(ZoneUnknown);
		ffpCbFns.pFnZoneMappingNotFound(anDev->ulVSGId,
			anDev->ulCommonInterfaceId, abuf,
			(genericFreeFn_t)ASF_SKB_FREE_FUNC, abuf.nativeBuffer);
		ASF_RCU_READ_UNLOCK(bLockFlag);
		return AS_FP_STOLEN;
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	if (!(pParse->l3r & (
#ifdef ASF_IPV6_FP_SUPPORT
			DPAA_PARSE_L3_FIRST_IPHDR_V6 |
#endif
			DPAA_PARSE_L3_FIRST_IPHDR_V4))) {
#ifdef ASF_FFP_XTRA_STATS
		XGSTATS_INC(NonIpPkts);
#endif
		asf_debug_l2("Non IP traffic. EthType = 0x%x\n",
		*(u16 *)((void *)abuf.ethh + pParse->etype_off));
		goto ret_pkt;
	}

	/* no need for explicit ip hdr length and ip checksum errors */

	abuf.iph = (struct iphdr *)((void *)abuf.ethh +
			pParse->ip_off[0]);
#ifdef ASF_IPV6_FP_SUPPORT
	/* first check IPv6 case */
	if (likely((pParse->l3r & DPAA_PARSE_L3_FIRST_IPHDR_V6)
			== DPAA_PARSE_L3_FIRST_IPHDR_V6)) {
		ASF_uint32_t	ret;
		struct ipv6hdr *ipv6h;

		ipv6h = (struct ipv6hdr *)abuf.iph;

		/*Send packet to IPv6 layer*/
		if (ipv6h->nexthdr != IPPROTO_IPIP) {
			ret = ASFFFPIPv6ProcessAndSendFD(anDev, abuf);
			switch (ret) {
			case ASF_DONE:
				goto stole_pkt;
			case ASF_RTS:
				goto ret_pkt;
			default:
				BUG();
			}
		} else {

			abuf.iph = (struct iphdr *)(ipv6h + 1);
			/* Facing problem of getting wrong hash value because
			 of which filling the coorect hash value itself */
			abuf.pAnnot->hr_hilo.loHash =
				ASFFFPComputeFlowHash1(abuf.iph->saddr,
					abuf.iph->daddr,
					*((unsigned int *)(abuf.iph + 1)),
					anDev->ulVSGId,
					anDev->ulZoneId,
					asf_ffp_ipv6_hash_init_value);
		}
	}
#endif	/* ASF_IPV6_FP_SUPPORT */

	/* do reassembly only for ipv4 */
	if (abuf.iph->frag_off & htons(IP_MF|IP_OFFSET)) {
		int fragCnt;

		/* reassemble anyway */
		XGSTATS_INC(IpFragPkts);
		abuf.bbuffInDomain = ASF_TRUE;
		asf_abuf_to_skb(&abuf);

		/* For IP4inIP6 handling */
		skb_pull(abuf.nativeBuffer,
				(unsigned char *)abuf.iph -
		(unsigned char *)(skb_network_header(abuf.nativeBuffer)));
		skb_reset_network_header(abuf.nativeBuffer);
		ASFCB((struct sk_buff *)abuf.nativeBuffer)->Defrag.bIPv6 = 0;
		abuf.nativeBuffer = asfIpv4Defrag(anDev->ulVSGId,
					abuf.nativeBuffer,
					NULL, NULL, NULL, &fragCnt);
		if (!abuf.nativeBuffer) {
			asf_debug("Skb absorbed for re-assembly\n");
			goto stole_pkt;
		}
		asf_display_frags(abuf.nativeBuffer, "re-assembled");
		/* make an abuf out of head skb; this buffer should not
		   go through another asf_abuf_to_skb - ok because
		   abuf.nativebuffer is already populated */
		asf_skb_to_abuf(&abuf, anDev);
		asf_debug("pAnnot 0x%p\n", abuf.pAnnot);
		/* TODO: when sending out the head abuf, remember to
		   credit appropriate the bman buffer pool */
		XGSTATS_INC(IpReasmPkts);
		/* Update pParse pointer to HEAD aBuf */
		pParse = &abuf.pAnnot->parse_result;
		/* Assuming that Transport Header is
		   included in Head Fragment */
		abuf.frag_list = 1;
	}

	iph = abuf.iph;

#ifdef ASF_IPV6_FP_SUPPORT
	/* XXX - Does here it mean that IPv6-in-IPv4 encapsulation? */
	if (abuf.iph->protocol ==  IPPROTO_IPV6) {
		ASF_uint32_t	ret;

		/* XXX - if IPIP, return to Linux stack */
		asf_debug("IPv6 over IPv4 on ASF DPAA\n");
		/* Need to update ip Offset to IPv6 Header */
		pParse->ip_off[0] += (4 * abuf.iph->ihl);
		abuf.iph = (void *)((unsigned char *)abuf.iph
					+ (4 * abuf.iph->ihl));
		ret = ASFFFPIPv6ProcessAndSendFD(anDev, abuf);
		switch (ret) {
		case ASF_DONE:
			goto stole_pkt;
		case ASF_RTS:
			goto ret_pkt;
		default:
			BUG();
		}
	}
#endif
	/* L4 header related checks for non-fragmented packets */
	/* debug trap for L4 error; also skip some uninteresting protocols */
#ifdef TRAP_UNEXP_CONDITION
	if (unlikely(pParse->l4r &
		(DPAA_PARSE_L4_ERROR |
		DPAA_PARSE_L4_OTHER_PROTO))) {
#endif
		if (likely(pParse->l4r &
			DPAA_PARSE_L4_OTHER_PROTO)) {
non_tudp:
			XGSTATS_INC(NonTcpUdpPkts);
			asf_debug("Non TCP/UDP/ESP traffic."
				"ip proto = %d\n", iph->protocol);
			goto ret_pkt;
		}
#ifdef TRAP_UNEXP_CONDITION
		/* TODO: invalid tcp flags -> syslog? */
		asf_err("error in L4 parse result 0x%02X\n",
				pParse->l4r);
		XGSTATS_INC(L4ParseErr);
		goto drop_pkt;
	}
#endif
	/* TODO: is it more efficient to switch on iph->protocol?
	another possible improvement is to lookup session
	and pass pkt to stack if not offloaded */
	switch (pParse->l4r & DPAA_PARSE_L4_PROTO_MASK) {
	case DPAA_PARSE_L4_PROTO_TCP:
		/* HW don't validate the L4 checksum
		   when packet is fragmented */
		if (!abuf.frag_list &&
			(pParse->l4r & DPAA_PARSE_L4_CKSUM_DONE) == 0)
			asf_dperr("%s", periodic_errmsg[PERR_HWTCP_CKSUM]);
			break;
	case DPAA_PARSE_L4_PROTO_UDP:
		/* HW don't validate the checksum when UDP csum is 0 */
		if (!abuf.frag_list &&
			((pParse->l4r & (DPAA_PARSE_L4_CKSUM_DONE |
				DPAA_PARSE_L4_NONZERO_CKSUM))
				== DPAA_PARSE_L4_NONZERO_CKSUM))
			asf_dperr("%s", periodic_errmsg[PERR_HWUDP_CKSUM]);
			break;
#ifdef ASF_IPSEC_FP_SUPPORT
	case DPAA_PARSE_L4_PROTO_IPSEC:
		if ((pParse->l4r & DPAA_PARSE_L4_IPSEC_MASK)
			== DPAA_PARSE_L4_IPSEC_ESP)
			break;
			/* else, fall thru, not interested in this pkt */
#endif
	default:
		goto non_tudp;
	}


	/* from here, abuf could be one of:
		1. single buffer: abuf is the buffer & abuf.nativebuffer
		   is NULL; annotation area contains info about original packet
		2. re-assembled buffer: abuf is the head buffer &
		   abuf.nativebuffer is the skb head (holding IP and transport
		   headers) and skb frag list holding rest of data fragments;
		   annotation area contains junk
		so, drop_pkt and stolen are valid return conditions, but not
		ret_pkt; to be corrected by processing fragments using
		ASFFFPProcessAndSendPkt */
#ifdef ASF_IPSEC_FP_SUPPORT

	/* IPSEC IN PROCESS function call for any of following conditions
	 *   iph->protocol == ESP
	 *   udph->dport == 500 or 4500
	 *   udph->sport == 500 or 4500
	 */

	/* IpSecIn for ESP pkts */
	if (unlikely(iph->protocol == IPPROTO_ESP)) {
		XGSTATS_INC(ESPPkts);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
ipsecin:
#endif
		if (pFFPIPSecIn) {
			abuf.bbuffInDomain = ASF_TRUE;
			asf_abuf_to_skb(&abuf);
			if (pFFPIPSecIn(abuf.nativeBuffer, 0, anDev->ulVSGId,
				anDev->ulCommonInterfaceId) == 0) {
				ASF_RCU_READ_UNLOCK(bLockFlag);
				return AS_FP_STOLEN;
			} else {
				/* Most Likely UDP encap - IKE packets*/
				/* because asf_abuf_to_skb has already been done, we cannot
				    return this packet to driver; so steal it by netif_rx */
				asf_dec_skb_buf_count(abuf.nativeBuffer);
				asf_debug("pFFPIPSecIn returned the packet");
				goto rcv_pkt;
			}
		} else
			asf_debug("No IPSec processing hook.");

		goto ret_pkt;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	} else if (unlikely(iph->protocol == IPPROTO_UDP)
		&& !((iph->frag_off) & ASF_MF_OFFSET_FLAG_NET_ORDER)) {
		/* Don't submit individual fragments here as UDP header is
		 * available in first fragment only.
		 */
		struct udphdr *udph = (struct udphdr *)((void *)abuf.ethh
					+ pParse->l4_off);

		u16 usSrcPrt = udph->source;
		u16 usDstPrt = udph->dest;

		if (usSrcPrt == ASF_IKE_NAT_FLOAT_PORT
			|| usSrcPrt == ASF_IKE_SERVER_PORT
			|| usDstPrt == ASF_IKE_SERVER_PORT
			|| usDstPrt == ASF_IKE_NAT_FLOAT_PORT) {
			XGSTATS_INC(IKEPkts);
			goto ipsecin;
		}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	}

#endif /*ASF_IPSEC_FP_SUPPORT*/
#ifdef ASF_TERM_FP_SUPPORT
	/* If in Termination Mode , send packet to
	   TERM module for further processing */
	/*	if (skb->mapped) {	*/
	if (abuf.pAnnot->flag & AS_FLAG_TERM_MAPPED) {
		if (asf_term_func_on &&
		(asf_vsg_info[anDev->ulVSGId]->curMode & termMode)) {

			/* Checksum verification will be done by eTSEC.*/
			asf_abuf_to_skb(&abuf);
			pTermProcessPkt(anDev->ulVSGId,
					anDev->ulCommonInterfaceId, abuf,
					(genericFreeFn_t)ASF_SKB_FREE_FUNC,
					abuf.nativeBuffer, NULL, ASF_FALSE);
			ASF_RCU_READ_UNLOCK(bLockFlag);
			return AS_FP_STOLEN;
		} else
			goto drop_pkt;
	}
#endif
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (!(asf_vsg_info[anDev->ulVSGId]->curMode & fwMode))
		goto ret_pkt;
	else
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
		ASFFFPProcessAndSendFD(anDev, abuf);
	XGSTATS_INC(SentPkts);
stole_pkt:
	ASF_RCU_READ_UNLOCK(bLockFlag);
	asf_debug("returning STOLEN!\n");
	return AS_FP_STOLEN;

iface_not_found:
	if (ffpCbFns.pFnInterfaceNotFound) {
		asf_abuf_to_skb(&abuf);
		XGSTATS_INC(IfNotFound);
		ffpCbFns.pFnInterfaceNotFound(abuf,
			(genericFreeFn_t)ASF_SKB_FREE_FUNC,
			abuf.nativeBuffer);
		ASF_RCU_READ_UNLOCK(bLockFlag);
		return AS_FP_STOLEN;
	}

ret_pkt:

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	XGSTATS_INC(RetPkts);
	if (abuf.frag_list && anDev) {
		asfAdjustFragAndSendUp(
			(struct sk_buff *)abuf.nativeBuffer, anDev);

		ASF_RCU_READ_UNLOCK(bLockFlag);
		return AS_FP_STOLEN;
	}

	ASF_RCU_READ_UNLOCK(bLockFlag);
	return AS_FP_PROCEED;

	/* pkts to be returned to stack after doing asf_abuf_to_skb */
rcv_pkt:
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	XGSTATS_INC(RetPkts);
	if (unlikely(((struct sk_buff *)abuf.nativeBuffer)->mac_len > ETH_HLEN)) {
		struct sk_buff *skb = (struct sk_buff *)abuf.nativeBuffer;
		skb_push(skb, skb->mac_len - ETH_HLEN);
		skb->mac_len = ETH_HLEN;
	}
	ASF_RCU_READ_UNLOCK(bLockFlag);
	if (abuf.frag_list) {
		asfAdjustFragAndSendUp(
			(struct sk_buff *)abuf.nativeBuffer, anDev);
	} else
		ASF_netif_receive_skb(abuf.nativeBuffer);
	return AS_FP_STOLEN;
#if defined(ASF_TERM_FP_SUPPORT) || defined(TRAP_UNEXP_CONDITION)
drop_pkt:
	asf_debug("drop_pkt LABEL\n");
	XGSTATS_INC(DropPkts);
	ASF_RCU_READ_UNLOCK(bLockFlag);
	if (abuf.frag_list) {
		ASF_SKB_FREE_FUNC((struct sk_buff *)abuf.nativeBuffer);
		return AS_FP_STOLEN;
	}
	return AS_FP_DROP;
#endif
}
#else
int asf_ffp_devfp_rx(struct sk_buff *skb, struct net_device *real_dev)
{
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ASFFFPGlobalStats_t	*gstats;
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
#ifndef CONFIG_DPA
	/*skb->protocol = eth_type_trans(skb, real_dev);*/

	/*This function resets skb->dev (affects VLAN device) */
	skb->protocol = eth_type_trans(skb, skb->dev);
#endif
	skb->mac_len = ETH_HLEN;
	usEthType = skb->protocol; /* *(short *)(skb->data + 12); */
	x_hh_len = 0;

	if (skb->pkt_type != PACKET_HOST) {
		/* multicast or broadcast or a packet
			received in promiscous mode */
		asf_debug_l2("packet type (%d) is not PACKET_HOST"\
			"(skb->dev %s real_dev %s vlan_tci %u) .. return\n",
			skb->pkt_type, skb->dev->name,
			real_dev->name, skb->vlan_tci);
		goto ret_pkt;
	}

	anDev = ASFNetDev(real_dev);
	if (NULL == anDev)
		goto iface_not_found;
	abuf.nativeBuffer = skb;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (real_dev != skb->dev)
		anDev = ASFGetVlanDev(anDev, skb->vlan_tci & VLAN_VID_MASK);
	if (NULL == anDev)
		goto iface_not_found;
	if (unlikely(anDev->ulVSGId == ASF_INVALID_VSG) ||
		unlikely(anDev->ulZoneId == ASF_INVALID_ZONE)) {
		ffpCbFns.pFnVSGMappingNotFound(anDev->ulCommonInterfaceId,
			abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC, skb);
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
	if ((usEthType != __constant_htons(ETH_P_IP))
#ifdef ASF_IPV6_FP_SUPPORT
		 && (usEthType != __constant_htons(ETH_P_IPV6))
#endif
								) {
		XGSTATS_INC(NonIpPkts);
		asf_debug_l2("Non IP traffic. EthType = 0x%x\n", usEthType);
		goto ret_pkt;
	}

	skb->mac_len += x_hh_len;
	skb_set_network_header(skb, x_hh_len);

#ifdef ASF_IPV6_FP_SUPPORT
	if (usEthType == __constant_htons(ETH_P_IPV6)) {
		ASF_uint32_t	ret;
		struct ipv6hdr *ipv6h = (struct ipv6hdr *)skb_network_header(skb);
		/*Send packet to IPv6 layer*/
		if (ipv6h->nexthdr != IPPROTO_IPIP) {
			skb_pull(skb, x_hh_len);
			ret = ASFFFPIPv6ProcessAndSendPkt(anDev->ulVSGId,
					anDev->ulCommonInterfaceId,
					abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC, skb, NULL);
			if (ret == ASF_DONE) {
				ASF_RCU_READ_UNLOCK(bLockFlag);
				return AS_FP_STOLEN;
			} else {
				skb_push(skb, x_hh_len);
				goto ret_pkt;
			}
		} else {
			x_hh_len += sizeof(struct ipv6hdr);
			skb_set_network_header(skb, x_hh_len);
		}
		/* need to take care the IPV4 in IPV6 case */
	}
#endif

	iph = ip_hdr(skb);

	if (unlikely(iph->version != 4)) {
		asf_debug("Non IPv4 traffic. ver = 0x%x\n", iph->version);
		goto ret_pkt;
	}

	if (unlikely(iph->ihl < 5)) {
		/* IP Header Length is < 5... PKT HDR ERROR */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			goto drop_pkt;
	}

	len = ntohs(iph->tot_len);
	if (unlikely((skb->len < (len + x_hh_len)) || (len < (iph->ihl*4)))) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulErrIpHdr++;
#endif
		goto drop_pkt;
	}

#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->protocol ==  IPPROTO_IPV6) {
		ASF_uint32_t	ret;
		skb_pull(skb, x_hh_len + sizeof(struct iphdr));
		skb_reset_network_header(skb);
		ret = ASFFFPIPv6ProcessAndSendPkt(anDev->ulVSGId,
				anDev->ulCommonInterfaceId,
				abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC, skb, NULL);

		if (ret == ASF_DONE) {
			ASF_RCU_READ_UNLOCK(bLockFlag);
			return AS_FP_STOLEN;
		} else {
			skb_push(skb, x_hh_len + sizeof(struct iphdr));
			skb_set_network_header(skb, -sizeof(struct iphdr));
			goto ret_pkt;
		}
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

	if (unlikely(skb->ip_summed != CHECKSUM_UNNECESSARY)) {
		if ((iph->frag_off) & ASF_MF_OFFSET_FLAG_NET_ORDER)
			bCsumVerify  = 1;
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
	if (anDev->ndev)
		skb->dev = anDev->ndev;
	skb->len = iph->tot_len;
	skb_set_transport_header(skb, iph->ihl*4);

#ifdef ASF_IPSEC_FP_SUPPORT

	/* IPSEC IN PROCESS function call for any of following conditions
	 *   iph->protocol == ESP
	 *   udph->dport == 500 or 4500
	 *   udph->sport == 500 or 4500
	 */

	if (iph->protocol == IPPROTO_ESP) {
		if (pFFPIPSecIn) {
			if (pFFPIPSecIn(skb, 0, anDev->ulVSGId,
				anDev->ulCommonInterfaceId) == 0) {
				ASF_RCU_READ_UNLOCK(bLockFlag);
				return AS_FP_STOLEN;
			}
		} else {
			XGSTATS_INC(NonTcpUdpPkts);
			asf_debug("Non IP traffic. EthType = 0x%x", usEthType);
			goto ret_pkt;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	} else if ((iph->protocol == IPPROTO_UDP)
		&& !((iph->frag_off) & ASF_MF_OFFSET_FLAG_NET_ORDER)) {
		/* Don't submit individual fragments here as UDP header is
		 * available in first fragment only.
		 */
		unsigned short int usSrcPrt;
		unsigned short int usDstPrt;

		usSrcPrt = BUFGET16((char *) (iph) + iph->ihl*4);
		usDstPrt = BUFGET16(((char *) (iph) + iph->ihl*4) + 2);

		if (usSrcPrt  ==  ASF_IKE_NAT_FLOAT_PORT
			|| usSrcPrt  ==  ASF_IKE_SERVER_PORT
			|| usDstPrt  ==  ASF_IKE_SERVER_PORT
			|| usDstPrt  ==  ASF_IKE_NAT_FLOAT_PORT) {
			if (pFFPIPSecIn &&
				pFFPIPSecIn(skb, 0, anDev->ulVSGId,
					anDev->ulCommonInterfaceId) == 0) {
				ASF_RCU_READ_UNLOCK(bLockFlag);
				return AS_FP_STOLEN;
			}
		}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	}
#endif /*ASF_IPSEC_FP_SUPPORT*/
#ifdef ASF_TERM_FP_SUPPORT
	/* If in Termination Mode , send packet to
	   TERM module for further processing */
	if (skb->mapped) {
		if (asf_term_func_on &&
		(asf_vsg_info[anDev->ulVSGId]->curMode & termMode)) {

			/* Checksum verification will be done by eTSEC.*/
			abuf.nativeBuffer = skb;
			pTermProcessPkt(anDev->ulVSGId,
					anDev->ulCommonInterfaceId, abuf,
					(genericFreeFn_t)ASF_SKB_FREE_FUNC,
					skb, NULL, ASF_FALSE);
			ASF_RCU_READ_UNLOCK(bLockFlag);
			return AS_FP_STOLEN;
		} else
			goto drop_pkt;
	}
#endif
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (!(asf_vsg_info[anDev->ulVSGId]->curMode & fwMode))
		goto ret_pkt;
	else
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
		ASFFFPProcessAndSendPkt(anDev->ulVSGId,
			anDev->ulCommonInterfaceId,
			abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC, skb, NULL);

	ASF_RCU_READ_UNLOCK(bLockFlag);
	asf_debug_l2("returning STOLEN!\n");
	return AS_FP_STOLEN;

iface_not_found:
	ASF_RCU_READ_UNLOCK(bLockFlag);
	if (ffpCbFns.pFnInterfaceNotFound) {
		abuf.nativeBuffer = skb;
		ffpCbFns.pFnInterfaceNotFound(abuf,
			(genericFreeFn_t)ASF_SKB_FREE_FUNC, skb);
		return AS_FP_STOLEN;
	}

ret_pkt:
	/* no frag list expected */
	ASF_netif_receive_skb(skb);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return AS_FP_STOLEN;

drop_pkt:
	ASFSkbFree(skb);
	asf_debug("drop_pkt LABEL\n");
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return AS_FP_STOLEN;
}
#endif
EXPORT_SYMBOL(asf_ffp_devfp_rx);

/* the input FD is handled as follows:
	- if it can be forwarded, then it is enqued to egress iface FQ,
	  but freed to ingress iface bp; in all other cases, the FD is
	  converted to skb and the ingress iface bp count is
	  decremented by 1;
	further FD handling is done as follows:
	- processing by IPSec - the skb is passed to IPSec module
	- drop - the skb is released
	- pass to net stack - via netif_receive_skb() */
#ifdef CONFIG_DPA
ASF_void_t ASFFFPProcessAndSendFD(
			ASFNetDevEntry_t *anDev,
			ASFBuffer_t abuf)
{
	struct iphdr		*iph;
	ffp_flow_t		*flow;
	unsigned long		ulHashVal;
	unsigned short int	iphlen;
	int			L2blobRefresh = 0;
	unsigned int            retryCount = 0, err = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	unsigned short int	trhlen;
	int			bSpecialIndication = 0,
				bFlowValidate = 0;
	unsigned int		ulTcpState = 0;
	asf_vsg_info_t		*vsgInfo;
	ASFFFPGlobalStats_t     *gstats;
	ASFFFPVsgStats_t	*vstats;
	ASFFFPFlowStats_t	*flow_stats;
	unsigned long		ulOrgSeqNum = 0, ulOrgAckNum = 0;
	unsigned long           ulLogId;
	int			iRetVal;
	struct tcphdr		*ptcph = NULL;
	int			mtu;
	u32			tunnel_hdr_len = 0;
#endif
	uint32_t		*ptrhdrOffset;
	struct qm_fd		*tx_fd;
	u8			*txdata;
	dma_addr_t		addr;
	struct dpa_priv_s	*priv;
	struct dpa_bp		*dpa_bp;
	u32			data_len;
	unsigned char		bSendOut  = 0;

	ACCESS_XGSTATS();
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id())
			+ anDev->ulVSGId;
	vstats->ulInPkts++;
#endif
	iph = abuf.iph;
	ulHashVal = abuf.pAnnot->hr_hilo.loHash;
	data_len = abuf.pAnnot->fd->length20;
	abuf.pCsum = NULL;

#ifdef ASF_DEBUG_FRAME /* TODO: modify */
	asf_print("iph->tot_len = %d\n", iph->tot_len);
	hexdump(abuf.iph, data_len - abuf.pAnnot->parse_result.ip_off[0]);
#endif

	iphlen = iph->ihl * 4;
	ptrhdrOffset = (uint32_t *)(((unsigned char *) iph) + iphlen);
	flow = asf_ffp_flow_lookup_DPAA(iph->saddr, iph->daddr,
					*ptrhdrOffset/* ports*/, anDev->ulVSGId,
					anDev->ulZoneId, iph->protocol,
					ulHashVal);
	asf_debug("ASF: %s Hash(%d.%d.%d.%d, %d.%d.%d.%d, 0x%lx, %d, %d)"\
		" = %llx (hindex %lx) (hini 0x%lx) => %s\n",
		anDev->ndev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), *ptrhdrOffset,
		iph->protocol, anDev->ulVSGId, abuf.pAnnot->hash_result,
		FFP_HINDEX(ulHashVal),
		asf_ffp_hash_init_value, flow ? "FOUND" : "NOT FOUND");

	if (unlikely(!flow)) {
		asf_debug_l2("ret_pkt_to_stk in no flow case");
		XGSTATS_INC(NoFlow);
		goto ret_pkt_to_stk;
	}
	if (unlikely(iph->ttl <= 1)) {
		asf_debug("flow = 0x%p iph->ver %d iph->ttl %d\n",
			flow, iph->version, iph->ttl);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		XGSTATS_INC(TTLExpire);
		gstats->ulErrTTL++;
#endif
		goto drop_pkt;
	}

	/* both flow and TTL are valid */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulInPktFlowMatches++;
	vstats->ulInPktFlowMatches++;
	XGSTATS_INC(Condition1);
	flow_stats = &flow->stats;

	vsgInfo = asf_ffp_get_vsg_info_node(anDev->ulVSGId);
	if (likely(vsgInfo)) {
		if (unlikely(vsgInfo->configIdentity.ulConfigMagicNumber !=
				    flow->configIdentity.ulConfigMagicNumber)) {
			asf_print("Calling flow validate %d != %d",
			vsgInfo->configIdentity.ulConfigMagicNumber,
			flow->configIdentity.ulConfigMagicNumber);
			bFlowValidate = 1;
		}

		/* L2blob refersh handling for the possible
		   change in the l2blob */
		if (unlikely((vsgInfo->configIdentity.
			l2blobConfig.ulL2blobMagicNumber !=
			flow->configIdentity.l2blobConfig.ulL2blobMagicNumber)
					&& (!flow->bIPsecOut))) {
			if (unlikely(!flow->configIdentity.
					l2blobConfig.bl2blobRefreshSent)) {
				flow->configIdentity.l2blobConfig.
					ulOldL2blobJiffies = jiffies;
				flow->configIdentity.l2blobConfig.
					bl2blobRefreshSent = 1;
			}
			if (unlikely(time_after(jiffies, flow->configIdentity.
					l2blobConfig.ulOldL2blobJiffies +
					ASF_MAX_OLD_L2BLOB_JIFFIES_TIMEOUT))) {
				L2blobRefresh = ASF_L2BLOB_REFRESH_DROP_PKT;
				goto gen_indications;
			}
			L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
		}
	}

	/* TODO: Handle IP options */
	if (unlikely(iph->ihl > 5)) {
	#if 0 /* TODO : emulate it on FD */
		if (asf_process_ip_options(skb, tmpDev->ndev, abuf.iph) < 0) {
			gstats->ulErrIpHdr++;
			XGSTATS_INC(IpOptProcFail);
			goto drop_pkt;
		}
	#endif
	}
#endif /* ASF_FEATURE_OPTION > ASF_MINIMUM */

	/* general purpose flag. This gets set when TCP connection is
	 * completed and we are waiting for FNP to delete flows. The
	 * same can be used by L2 firewall later */
	if (unlikely(flow->bDrop)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (bFlowValidate)
			goto gen_indications;
#endif
		XGSTATS_INC(bDropPkts);
		asf_debug("dropping packet as bDrop is set\n");
		goto drop_pkt;
	}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (abuf.iph->protocol == IPPROTO_UDP) {
		XGSTATS_INC(UdpPkts);
	} else if (abuf.iph->protocol == IPPROTO_TCP) {
		int		optlen;
		unsigned short  tcp_data_len;
		ffp_flow_t      *oth_flow;

		XGSTATS_INC(TcpPkts);
		trhlen = (unsigned short)((*(ptrhdrOffset + 3) &
						0xf0000000) >> 28) * 4;
		ptcph = (struct tcphdr *) ptrhdrOffset;
		/*optlen = ptcph->doff*4-20; */

		/* if (flow->bTcpTimeStamp &&
		   ((optlen = ptcph->doff*4-20) > 0)) */
		optlen = trhlen - 20;
		if (unlikely(flow->bTcpTimeStampCheck && (optlen > 0))) {
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
		/* this check is necessary as their creation may not be atomic*/
		if (unlikely(!oth_flow)) {
			asf_debug("other flow is not found!\n");
			goto drop_pkt;
		}

		tcp_data_len = ntohs(iph->tot_len)-iphlen-trhlen;
		asf_debug_l2("TCP_STATE_PROC: tcp_data_len = %d\n",
							tcp_data_len);

		if (flow->bTcpOutOfSeqCheck) {
			ulLogId = asfTcpCheckForOutOfSeq(flow, oth_flow, ptcph,
						tcp_data_len, vsgInfo);
			if (unlikely(ulLogId != ASF_LOG_ID_DUMMY)) {
				asf_debug("out of seq check failed!\n");
				asfFfpSendLog(flow, ulLogId,
						abuf.pAnnot->hr_hilo.loHash);
				gstats->ulErrIpProtoHdr++;
				XGSTATS_INC(TcpOutOfSequenceErr);
				if (vsgInfo->bDropOutOfSeq)
					goto drop_pkt;
			}
		}
		asf_debug_l2("TCP_STATE_PROC: out of "
				"sequence checks finished!\n");

		ulOrgSeqNum = ntohl(ptcph->seq);
		ulOrgAckNum = ntohl(ptcph->ack_seq);
		asfTcpApplyDelta(flow, oth_flow, ptcph,
				ulOrgSeqNum, ulOrgAckNum);
		asf_debug_l2("TCP_STATE_PROC: applied delta to the packet\n");

		asfTcpUpdateState(flow, ulOrgSeqNum, ulOrgAckNum,
						ptcph, tcp_data_len);
		asf_debug_l2("TCP_STATE_PROC: updated current"
					" TCP state in the flow\n");
		iRetVal = asfTcpProcess(flow, oth_flow, ptcph);
		if (iRetVal < 0) {
			asf_debug("asfTcpProcess returned failure!\n");
			gstats->ulErrIpProtoHdr++;
			XGSTATS_INC(TcpProcessErr);
			goto drop_pkt;
		} else if (iRetVal == 1) {
			asf_debug("TCP_STATE_PROC: %s packet .. "
				"send InacRefresh indication\n",
					ptcph->fin ? "FIN" : "RST");
			ulTcpState = (ptcph->fin) ?
				ASF_FFP_TCP_STATE_FIN_RCVD :
				ASF_FFP_TCP_STATE_RST_RCVD;
			bSpecialIndication = 1;
		} else if (iRetVal == 2) {
			ulTcpState = ASF_FFP_TCP_STATE_FIN_COMP;
			bSpecialIndication = 1;
		}
		asf_debug_l2("TCP state processing is done!\n");
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	flow_stats->ulInPkts++;
	/* Only timer based L2 blob refresh  is supported in current release */
	/* TODO: avoid division here */
	if (asf_l2blob_refresh_npkts &&
		(flow_stats->ulInPkts % asf_l2blob_refresh_npkts) == 0) {
		asf_debug_l2("Decided to send L2Blob refresh "
					"ind based on npkts\n");
		if (!L2blobRefresh)
			L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
	}
	flow->ulLastPktInAt = jiffies;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	if (!flow->bIPsecOut &&
		(flow->l2blob_len == 0)) {
		asf_debug("Generating L2blob"
				" Indication as L2blob Not found!\n");
		L2blobRefresh = ASF_L2BLOB_REFRESH_RET_PKT_STK;
		XGSTATS_INC(BlankL2blobInd);
		goto gen_indications;
	}
	if (flow->bNat) {
		XGSTATS_INC(NatPkts);
		asf_debug_l2("applying NAT\n");
		/* Update IP Checksum  */
		if (iph->saddr != flow->ulSrcNATIp) {
#ifdef ASF_DO_INC_CHECKSUM
			csum_replace4(&iph->check,
				iph->saddr, flow->ulSrcNATIp);
#endif
			iph->saddr = flow->ulSrcNATIp;
		}
		if (iph->daddr != flow->ulDestNATIp) {
#ifdef ASF_DO_INC_CHECKSUM
			csum_replace4(&iph->check,
				iph->daddr, flow->ulDestNATIp);
#endif
			iph->daddr = flow->ulDestNATIp;
		}
		*ptrhdrOffset = flow->ulNATPorts;

		/* if hardware does not update checksum,
		   do incremental checksum */
#ifdef ASF_DO_INC_CHECKSUM
		if (iph->protocol == IPPROTO_UDP) {
			abuf.pCsum = ((unsigned short int *) ptrhdrOffset) + 3;
		} else { /*if (abuf.iph->protocol == IPPROTO_TCP) */
			abuf.pCsum = ((unsigned short int *) ptrhdrOffset) + 8;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (ulOrgSeqNum != ntohl(ptcph->seq))
				asf_proto_csum_replace4(abuf.pCsum,
					htonl(ulOrgSeqNum),
					ptcph->seq);

			if (ulOrgAckNum != ntohl(ptcph->ack_seq))
				asf_proto_csum_replace4(abuf.pCsum,
					htonl(ulOrgAckNum),
					ptcph->ack_seq);
#endif
		}
		asf_proto_csum_replace4(abuf.pCsum,
			flow->ulSrcIp, flow->ulSrcNATIp);
		asf_proto_csum_replace4(abuf.pCsum,
			flow->ulDestIp, flow->ulDestNATIp);
		asf_proto_csum_replace4(abuf.pCsum,
			flow->ulPorts, flow->ulNATPorts);
#else
		/* tweaked for UDP perf */
		if (likely(iph->protocol == IPPROTO_UDP))
			abuf.pCsum = ((u16 *)ptrhdrOffset) + 3;
		else /*if (abuf.iph->protocol == IPPROTO_TCP)*/
			abuf.pCsum = ((u16 *)ptrhdrOffset) + 8;
#endif /* ASF_DO_INC_CHECKSUM */
	} else {
#ifdef ASF_DO_INC_CHECKSUM
		if (iph->protocol == IPPROTO_TCP) {
			abuf.pCsum = ((u16 *)ptrhdrOffset) + 8;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (ulOrgSeqNum != ntohl(ptcph->seq))
				asf_proto_csum_replace4(abuf.pCsum,
					htonl(ulOrgSeqNum),
					ptcph->seq);
			if (ulOrgAckNum != ntohl(ptcph->ack_seq))
				asf_proto_csum_replace4(abuf.pCsum,
					htonl(ulOrgAckNum),
					ptcph->ack_seq);
#endif
		}
#else
		/* TODO: chksum update not necessary if seq/ack
		   nums are not changed */
		if (iph->protocol == IPPROTO_TCP)
			abuf.pCsum = ((u16 *)ptrhdrOffset) + 8;
#endif /* ASF_DO_INC_CHECKSUM */
	}
#ifdef ASF_INGRESS_MARKER
		if (ASF_QM_NULL_DSCP != flow->mkinfo.uciDscp) {
		#ifdef ASF_DO_INC_CHECKSUM
			csum_replace4(&iph->check, iph->tos,
					flow->mkinfo.uciDscp);
		#endif
			iph->tos = flow->mkinfo.uciDscp;
		}
#endif
#ifdef ASF_IPSEC_FP_SUPPORT
	if (flow->bIPsecOut) {
		abuf.bbuffInDomain = ASF_TRUE;
		asf_abuf_to_skb(&abuf);
		if (pFFPIPSecOut) {
			if (pFFPIPSecOut(anDev->ulVSGId,
				abuf.nativeBuffer, &flow->ipsecInfo) == 0) {
				goto gen_indications;
			}
		}
		goto drop_pkt_1;
	}
#endif /*ASF_IPSEC_FP_SUPPORT*/
	asf_debug_l2("attempting to xmit the packet\n");
	/* flow->l2blob_len > 0 && flow->odev != NULL
	from this point onwards */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	mtu = ASF_MIN(flow->pmtu, flow->odev->mtu) + ETH_HLEN - flow->l2blob_len;
#endif
	asf_debug_l2("attempting to xmit the packet\n");
	if (unlikely(abuf.frag_list
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	|| (iph->tot_len > mtu)
#endif
	)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		struct sk_buff *pSkb, *pTempSkb;
		struct sk_buff *skb;

		XGSTATS_INC(FragAndXmit);
		if (iph->frag_off & IP_DF)
			goto ret_pkt_to_stk;

		skb = (struct sk_buff *)asf_abuf_to_skb(&abuf);

		/* Need to call fragmentation routine */
		asf_debug("attempting to fragment and xmit\n");

		if (!asfIpv4Fragment(skb, mtu, flow->l2blob_len,
						1 /* TRUE */, flow->odev,
						&pSkb)) {
			int ulFrags = 0;
			struct iphdr *iph;
			/* asf_display_frags(pSkb, "Before Xmit");*/
			asf_display_skb_list(pSkb, "Before Xmit");
			for (; pSkb != NULL; pSkb = pTempSkb) {
				ulFrags++;
				pTempSkb = pSkb->next;
				asf_debug("Next skb = 0x%x\r\n", pTempSkb);
				pSkb->next = NULL;
				iph = ip_hdr(pSkb);

				pSkb->pkt_type = PACKET_FASTROUTE;
				/* pSkb->asf = 1; - field not
				   defined in p4080 bsp */
				asf_set_queue_mapping(pSkb,
							iph->tos);
				ip_decrease_ttl(iph);

				pSkb->data -= flow->l2blob_len;
				pSkb->len += flow->l2blob_len;

				if (pSkb->data < pSkb->head) {
					asf_debug("SKB's head > data ptr .. "
							"UNDER PANIC!!!\n");
					asf_free_buf_skb(pSkb->dev, pSkb);
					continue;
				}

				pSkb->dev = flow->odev;

				asfCopyWords((unsigned int *)pSkb->data,
						(unsigned int *)flow->l2blob,
						flow->l2blob_len);
#ifdef ASF_IPV6_FP_SUPPORT
				if (flow->bIP4IP6Out) {
					/* IPv4 in IPv6 */
					struct ipv6hdr *ipv6h;
					ipv6h = (struct ipv6hdr *)iph;
					ipv6h -= 1;
					ipv6h->payload_len = iph->tot_len;
					tunnel_hdr_len = sizeof(struct ipv6hdr);
				}
#endif
				if (flow->bPPPoE) {
					/* PPPoE packet.. Set Payload length in
					   PPPoE header */
					*((short *)&(pSkb->data[flow->l2blob_len
									- 4])) =
						htons(ntohs(iph->tot_len) + 2);
				}

				asf_debug("skb->network_header = 0x%x,"
					" skb->transport_header = 0x%x\r\n",
					  skb_network_header(pSkb),
					  skb_transport_header(pSkb));
				asf_debug("Transmitting  buffer = 0x%x "
						"dev->index = %d\r\n",
						pSkb, pSkb->dev->ifindex);

				gstats->ulOutBytes += pSkb->len;
				flow_stats->ulOutBytes += pSkb->len;
				vstats->ulOutBytes += pSkb->len;
#ifdef ASF_QOS
				/* Enqueue the packet in Linux QoS framework */
				asf_qos_handling(pSkb, &flow->tc_filter_res);
#else
				if (asfDevHardXmit(pSkb->dev, pSkb) != 0) {
					asf_debug("Error in transmit: "
						"Should not happen\r\n");
					asf_free_buf_skb(pSkb->dev, pSkb);
				}
#endif
				bSendOut = 1;
			}
			gstats->ulOutPkts += ulFrags;
			vstats->ulOutPkts += ulFrags;
			flow_stats->ulOutPkts += ulFrags;
		} else {
			asf_err(KERN_INFO "asfcore.c:%d - asfIpv4Fragment "
					"returned NULL!!\n", __LINE__);
		}
		goto gen_indications;
#else /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
		/* Fragmentation in case of ASF_MINIMUM */
		goto ret_pkt_to_stk;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	}

	XGSTATS_INC(NonFragXmit);
	asf_debug_l2("attempting to xmit non"
				" fragment packet\n");
	ip_decrease_ttl(iph);

	txdata = (u8 *)iph - flow->l2blob_len;

	asfCopyWords((unsigned int *)txdata,
		(unsigned int *)flow->l2blob, flow->l2blob_len);
#ifdef ASF_IPV6_FP_SUPPORT
	if (flow->bIP4IP6Out) {
		/* TODO - here we have issues for IPoverIP cases */
		struct ipv6hdr *ipv6h;
		ipv6h = (struct ipv6hdr *)iph;
		ipv6h -= 1;
		ipv6h->payload_len = iph->tot_len;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		tunnel_hdr_len = sizeof(struct ipv6hdr);
#endif
	}
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (flow->bPPPoE) {
		/* PPPoE packet..
		 * Set Payload length in PPPoE header */
		*((short *)&(txdata[(flow->l2blob_len - tunnel_hdr_len)-4])) =
			htons(ntohs(iph->tot_len + tunnel_hdr_len) + 2);
	}
#endif  /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	asf_debug_l2("invoke FD transmission (L2blob_len %d)\n",
							flow->l2blob_len);
	/* dma map data buffer */
	/*TODO: check if flow->odev is set correctly for VLANs or PPPoE*/
	priv = netdev_priv(flow->odev);
	dpa_bp = priv->dpa_bp;
	addr = dma_map_single(dpa_bp->dev, abuf.pAnnot,
				dpa_bp->size, DMA_TO_DEVICE);
	if (unlikely(addr == 0)) {
		asf_debug("xmit dma_map Error\n");
		goto drop_pkt;
	}

	/*Reusing unused annotation's (reserved ) area as TX_FD
	As per current implementation, parse result is not in use for TX_FD
	but in future if parse results need to be placed in TX_FD then TX_FD
	will be written at some other memory location*/
	tx_fd  = (struct qm_fd *)&(abuf.pAnnot->reserved[1]);

	*(u32 *)tx_fd = 0; /* Resetting the unused area */
	tx_fd->bpid = dpa_bp->bpid;
	tx_fd->addr_hi = upper_32_bits(addr);
	tx_fd->addr_lo = lower_32_bits(addr);
	/* Only Contiguous Frame Handling for now */
	tx_fd->format = qm_fd_contig;
	/* if L2 header on egress is make sure that enough
	   headroom exists.
	 */
	tx_fd->offset = (uintptr_t)iph - (uintptr_t)abuf.pAnnot - flow->l2blob_len;
	if (txdata >= (u8 *)abuf.ethh)
		tx_fd->length20 = data_len -
			((txdata - (u8 *)abuf.ethh) & 0xfffff);
	else
		tx_fd->length20 = data_len +
			(((u8 *)abuf.ethh - txdata) & 0xfffff);

	/* Indicate to Recycle Buffer */
	tx_fd->cmd = FM_FD_CMD_FCO;

	asf_debug_l2("copy l2blob to packet (blob_len %d)\n",
		flow->l2blob_len);

	asf_debug("tx on fqid %d\n",
			priv->egress_fqs[smp_processor_id()]->fqid);
	do {
#ifdef ASF_QOS
		err = asf_qos_fd_handling(&abuf, flow->odev,
					iph->tos, &flow->tc_filter_res);
#else
		err = qman_enqueue(priv->egress_fqs[smp_processor_id()],
								tx_fd, 0);
#endif
		if (err == 0)
			break;
		if (++retryCount == ASF_MAX_TX_RETRY_CNT) {
			XGSTATS_INC(DevXmitErr);
			asf_debug("qman_enque Error\n");
			goto drop_pkt;
		}
		__delay(50);
	} while (1);
	bSendOut = 1;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulOutBytes += tx_fd->length20;
	flow_stats->ulOutBytes += tx_fd->length20;
	vstats->ulOutBytes += tx_fd->length20;
	gstats->ulOutPkts++;
	vstats->ulOutPkts++;
	flow_stats->ulOutPkts++;
#endif

	/* if we enter gen_indications from here, the exit point from this
	   function should not be ret_pkt_to_stk or drop_pkt because
	   pkt is qued for xmit */
gen_indications:
	/* skip all other indications if flow_end
	   indication is going to be sent */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (unlikely(bSpecialIndication)) {
		if (ffpCbFns.pFnFlowTcpSpecialPkts) {
			ASFFFPFlowSpecialPacketsInfo_t  ind;
			ffp_flow_t		      *oth_flow;
			XGSTATS_INC(FlowSpecialInd);

			ind.tuple.bIPv4OrIPv6 = 0;
			ind.tuple.ulSrcIp = flow->ulSrcIp;
			ind.tuple.ulDestIp = flow->ulDestIp;
			ind.tuple.usSrcPort = (flow->ulPorts >> 16);
			ind.tuple.usDestPort = flow->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow->ucProtocol;
			ind.ulZoneId = flow->ulZoneId;
			ind.ulHashVal = htonl(ulHashVal);

			ind.ASFwInfo = (ASF_uint8_t *)flow->as_flow_info;
			ind.ulTcpState = ulTcpState;

			oth_flow = ffp_flow_by_id(&flow->other_id);

			ffp_copy_flow_stats(flow, &ind.flow_stats);
			if (oth_flow)
				ffp_copy_flow_stats(oth_flow, &ind.other_stats);
			else
				memset(&ind.other_stats, 0,
						sizeof(ind.other_stats));

			ffpCbFns.pFnFlowTcpSpecialPkts(anDev->ulVSGId, &ind);
		}
	}

	/* FlowValidate indicaion */
	if (unlikely(bFlowValidate)) {
		if (!flow->bDeleted && ffpCbFns.pFnFlowValidate) {
			ASFFFPFlowValidateCbInfo_t  ind;

			ind.tuple.bIPv4OrIPv6 = 0;
			ind.tuple.ulSrcIp = flow->ulSrcIp;
			ind.tuple.ulDestIp = flow->ulDestIp;
			ind.tuple.usSrcPort = (flow->ulPorts >> 16);
			ind.tuple.usDestPort = flow->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow->ucProtocol;
			ind.ulZoneId = flow->ulZoneId;
			ind.ulHashVal = htonl(ulHashVal);

			ind.ASFwInfo =
			(ASF_uint8_t *)flow->as_flow_info;

			ffpCbFns.pFnFlowValidate(anDev->ulVSGId, &ind);
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (flow->bDrop && !bSendOut) {
			XGSTATS_INC(bDropPkts);
			asf_debug("dropping packet as"\
					"bDrop is set\n");
			goto drop_pkt;
		}
#endif
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	if (unlikely(L2blobRefresh)) {
		if (!flow->bDeleted && ffpCbFns.pFnFlowRefreshL2Blob) {
			ASFFFPFlowL2BlobRefreshCbInfo_t  ind;
			ind.flowTuple.bIPv4OrIPv6 = 0;
			ind.flowTuple.ulSrcIp = flow->ulSrcIp;
			ind.flowTuple.ulDestIp = flow->ulDestIp;
			ind.flowTuple.usSrcPort = (flow->ulPorts >> 16);
			ind.flowTuple.usDestPort = flow->ulPorts&0xffff;
			ind.flowTuple.ucProtocol = flow->ucProtocol;

			if (flow->bNat) {
				ind.packetTuple.ulSrcIp = flow->ulSrcNATIp;
				ind.packetTuple.ulDestIp = flow->ulDestNATIp;
				ind.packetTuple.usSrcPort =
					(flow->ulNATPorts >> 16);
				ind.packetTuple.usDestPort =
					flow->ulNATPorts&0xffff;
				ind.packetTuple.ucProtocol = flow->ucProtocol;
			} else
				ind.packetTuple	= ind.flowTuple;

			ind.ulZoneId = flow->ulZoneId;

			ind.ulHashVal = ulHashVal;
			XGSTATS_INC(PktCtxL2blobInd);
			ffpCbFns.pFnFlowRefreshL2Blob(anDev->ulVSGId, &ind);
		}
		switch (L2blobRefresh) {
		case ASF_L2BLOB_REFRESH_RET_PKT_STK:
				goto ret_pkt_to_stk;
				break;
		case ASF_L2BLOB_REFRESH_DROP_PKT:
				goto drop_pkt;
				break;
		default:
				break;
		}
	}
	return;

ret_pkt_to_stk:
	asf_debug_l2("ret_pkt_to_stk LABEL\n");
	if (abuf.frag_list) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulPktsToFNP++;
#endif
		asfAdjustFragAndSendUp(
			(struct sk_buff *)abuf.nativeBuffer, anDev);
		return;
	}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	asf_abuf_to_skb(&abuf);
	if (ffpCbFns.pFnNoFlowFound) {
		asf_debug("NoFlow: andev %p dev %s ciid %d\n", anDev,
				abuf.ndev->name, anDev->ulCommonInterfaceId);
		ffpCbFns.pFnNoFlowFound(anDev->ulVSGId,
			anDev->ulCommonInterfaceId, anDev->ulZoneId,
			abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC,
			abuf.nativeBuffer);
		return;
	}

	asf_dperr("%s", periodic_errmsg[PERR_NO_FW]);
	if (unlikely(((struct sk_buff *)abuf.nativeBuffer)->
				mac_len > ETH_HLEN)) {
		struct sk_buff *skb = (struct sk_buff *)abuf.nativeBuffer;
		skb_push(skb, skb->mac_len - ETH_HLEN);
		skb->mac_len = ETH_HLEN;
	}
	asf_debug_l2("  ret_pkt LABEL -- calling netif_receive_skb!\n");
	ASF_netif_receive_skb(abuf.nativeBuffer);
	asf_debug_l2("  ret_pkt LABEL -- returning from function!\n");
	return;

drop_pkt:
	asf_debug_l2("drop_pkt LABEL\n");
	XGSTATS_INC(SendDrop);
	/* TODO: we may have to iterate through frag_list and free all of them*/
	/* TODO: ensure all fragments are also dropped. and return STOLEN
	 always return stolen?? */
	if (unlikely(abuf.frag_list))
		ASF_SKB_FREE_FUNC(abuf.nativeBuffer);
	else
		dpa_fd_release(abuf.ndev, (struct qm_fd *)abuf.pAnnot->fd);

	return;
drop_pkt_1:

	asf_free_buf_skb(abuf.ndev, (struct sk_buff *)abuf.nativeBuffer);
	return;
}
#endif

ASF_void_t ASFFFPProcessAndSendPkt(
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
	unsigned short int	trhlen;
	unsigned short int	iphlen;
	unsigned short int      *q;
	int			L2blobRefresh = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int			bSpecialIndication = 0,
				FlowValidate = 0;
	unsigned int		ulTcpState = 0;
	unsigned int		fragCnt;
	asf_vsg_info_t		*vsgInfo;
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	ASFFFPVsgStats_t	*vstats;
	ASFFFPFlowStats_t	*flow_stats;
	unsigned long		ulOrgSeqNum = 0, ulOrgAckNum = 0, ulLogId;
	int			iRetVal;
	struct tcphdr		*ptcph = NULL;
#endif
	int			tot_len;
	unsigned long int       *ptrhdrOffset;
	unsigned long		ulZoneId;
	struct sk_buff		*skb;
	ASFNetDevEntry_t	*anDev;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	unsigned int		tunnel_hdr_len = 0;
#endif
	ACCESS_XGSTATS();

	skb = (struct sk_buff *) Buffer.nativeBuffer;

	anDev = ASFCiiToNetDev(ulCommonInterfaceId);

	if (unlikely(!anDev)) {
		asf_debug("CII %u doesn't appear to be valid\n",
			ulCommonInterfaceId);
		pFreeFn(skb);
		return;
	}

	ulZoneId = anDev->ulZoneId;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id()) + ulVsgId;
	vstats->ulInPkts++;
#endif
	iph = ip_hdr(skb);

#ifdef ASF_DEBUG_FRAME
	asf_print(" Pkt (%x) skb->len = %d, iph->tot_len = %d",
		pIpsecOpaque, skb->len, iph->tot_len);
	hexdump(skb->data - 14, skb->len + 14);
#endif

#ifdef ASF_IPSEC_FP_SUPPORT

	/* If the packet is recevied from IPsec-ASF, IPSEC-ASF it self will take care of
	 * submitting the packet to AS */
	/* Needed to verify checksum of the packet recieved in tunnel */
	if (pIpsecOpaque) {
		asf_debug(" DECRYPTED PACKET");
		if (unlikely(iph->ihl < 5)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			pFreeFn(skb);
			return;
		}

		if (unlikely(iph->version != 4)) {
			asf_debug("Bad iph-version =%d", iph->version);
			goto drop_pkt;
		}

		/* Do ip header length checks if the packet is received thru IPsec */
		tot_len = ntohs(iph->tot_len);
		if (unlikely(((skb->len < tot_len) &&
			skb_shinfo(skb)->frag_list == NULL)
				|| (tot_len < (iph->ihl*4)))) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpHdr++;
#endif
			goto drop_pkt;
		}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		XGSTATS_INC(LocalCsumVerify);
		if (ip_fast_csum((u8 *)iph, iph->ihl)) {
			gstats->ulErrCsum++;
			XGSTATS_INC(LocalBadCsum);
			asf_debug("Decrypted Packet"\
				"Ip Checksum verification failed\n");
			goto drop_pkt;
		}
#endif
		if (unlikely((iph->protocol != IPPROTO_TCP)
			&& (iph->protocol != IPPROTO_UDP))) {
			if (pFFPIpsecInVerify) {
				pFFPIpsecInVerify(ulVsgId, skb,
				anDev->ulCommonInterfaceId, NULL, pIpsecOpaque);
				return;
			}
			asf_err("Non supported Decrypted packet!!! ERROR!!!\n");
			goto drop_pkt;
		}
	}
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	/* TODO: how to handle fragments received on PPPoE iface and how to remember
	 * logical device and hh_len */
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
		}
		asf_debug("DeFrag & Pull done .. proceed!! skb->len %d iph->tot_len %d fragCnt %d\n",
			  skb->len, iph->tot_len, fragCnt);
		asf_display_frags(skb, "After Pull");
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	if (iph->protocol == IPPROTO_UDP) {
		unsigned short int usSrcPrt;
		unsigned short int usDstPrt;

		usSrcPrt = BUFGET16((char *) (iph) + iph->ihl*4);
		usDstPrt = BUFGET16(((char *) (iph) + iph->ihl*4) + 2);

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
			} else
				asf_debug("Looks like IKE packet");
		}
	}
	iphlen = iph->ihl * 4;
	ptrhdrOffset = (unsigned long int *)(((unsigned char *) iph) + iphlen);

	flow = asf_ffp_flow_lookup(iph->saddr, iph->daddr,
					*ptrhdrOffset/* ports*/, ulVsgId,
					ulZoneId, iph->protocol, &ulHashVal);

	asf_debug("ASF: %s Hash(%d.%d.%d.%d, %d.%d.%d.%d, 0x%lx, %d, %d)"\
		" = %lx (hindex %lx) (hini 0x%lx) => %s\n",
		skb->dev->name,
		NIPQUAD(iph->saddr), NIPQUAD(iph->daddr), *ptrhdrOffset,
		iph->protocol, ulVsgId, ulHashVal, FFP_HINDEX(ulHashVal),
		asf_ffp_hash_init_value, flow ? "FOUND" : "NOT FOUND");

#ifdef ASF_IPSEC_FP_SUPPORT
	if (pIpsecOpaque) {
		if (pFFPIpsecInVerify(ulVsgId, skb,
			anDev->ulCommonInterfaceId,
			(flow && flow->bIPsecIn) ? &flow->ipsecInfo : NULL,
			pIpsecOpaque) != 0) {
			asf_warn("IPSEC InVerify Failed\n");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (flow)
				FlowValidate = ASF_FLOWVALIDATE_NORAMAL;
#endif
			goto gen_indications;
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

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
		if (vsgInfo) {
			if (vsgInfo->configIdentity.ulConfigMagicNumber !=
				flow->configIdentity.ulConfigMagicNumber) {
				asf_print("Calling flow validate %d != %d",
				vsgInfo->configIdentity.ulConfigMagicNumber,

				flow->configIdentity.ulConfigMagicNumber);
				FlowValidate = ASF_FLOWVALIDATE_NORAMAL;
			}
			/* L2blob refersh handling for the possible change in the l2blob */

			if ((!flow->bIPsecOut) &&
				(vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber !=
				flow->configIdentity.l2blobConfig.ulL2blobMagicNumber)) {

				if (!flow->configIdentity.l2blobConfig.bl2blobRefreshSent) {
					flow->configIdentity.l2blobConfig.ulOldL2blobJiffies = jiffies;
					flow->configIdentity.l2blobConfig.bl2blobRefreshSent = 1;
				}

				if (time_after(jiffies ,
					flow->configIdentity.l2blobConfig.ulOldL2blobJiffies +
					ASF_MAX_OLD_L2BLOB_JIFFIES_TIMEOUT)) {
					L2blobRefresh = ASF_L2BLOB_REFRESH_DROP_PKT;
					goto gen_indications;
				}

				L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
			}
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
		/* general purpose flag. This gets set when TCP connection is
		 * completed and we are waiting for FNP to delete flows. This
		 * flag is also used in firewall case*/
		if (flow->bDrop) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (FlowValidate) {
				FlowValidate = ASF_FLOWVALIDATE_INVALIDFLOW;
				goto gen_indications;
			}
#endif
			XGSTATS_INC(bDropPkts);
			asf_debug("dropping packet as bDrop is set\n");
			goto drop_pkt;
		}

		q = (unsigned short *)  ptrhdrOffset;
		if (iph->protocol == IPPROTO_UDP) {
			XGSTATS_INC(UdpPkts);
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
			int     optlen;
			unsigned short  tcp_data_len;
			ffp_flow_t      *oth_flow;
#endif

			XGSTATS_INC(TcpPkts);
			trhlen = (unsigned short)((*(ptrhdrOffset + 3) &
							0xf0000000) >> 28) * 4;
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

			tcp_data_len = ntohs(iph->tot_len)-iphlen-trhlen;
			asf_debug_l2("TCP_STATE_PROC: tcp_data_len = %d\n", tcp_data_len);

			if (flow->bTcpOutOfSeqCheck) {
				ulLogId = asfTcpCheckForOutOfSeq(flow, oth_flow, ptcph,
							tcp_data_len, vsgInfo);
				if (unlikely(ulLogId != ASF_LOG_ID_DUMMY)) {
					asf_debug("out of seq check failed!\n");
					asfFfpSendLog(flow, ulLogId, ulHashVal);
					gstats->ulErrIpProtoHdr++;
					XGSTATS_INC(TcpOutOfSequenceErr);
					if (vsgInfo->bDropOutOfSeq)
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
			if (!L2blobRefresh)
				L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
		}
		flow->ulLastPktInAt = jiffies;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

		if (!flow->bIPsecOut &&
			(flow->l2blob_len == 0)) {
			asf_debug("Generating L2blob Indication as L2blob Not found!\n");
			L2blobRefresh = ASF_L2BLOB_REFRESH_RET_PKT_STK;
			goto gen_indications;
		}

		if (flow->bNat) {
			XGSTATS_INC(NatPkts);
			asf_debug_l2("applying NAT\n");
			/* Update IP Checksum also */
			if (iph->saddr != flow->ulSrcNATIp) {
#ifdef ASF_DO_INC_CHECKSUM
				csum_replace4(&iph->check,
					iph->saddr, flow->ulSrcNATIp);
#endif
				iph->saddr = flow->ulSrcNATIp;
			}
			if (iph->daddr != flow->ulDestNATIp) {
#ifdef ASF_DO_INC_CHECKSUM
				csum_replace4(&iph->check,
					iph->daddr, flow->ulDestNATIp);
#endif
				iph->daddr = flow->ulDestNATIp;
			}

			*ptrhdrOffset = flow->ulNATPorts;
			skb_set_transport_header(skb, iphlen);

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
							htonl(ulOrgSeqNum),
							ptcph->seq, 1);

					if (ulOrgAckNum != ntohl(ptcph->ack_seq))
						inet_proto_csum_replace4(q, skb,
							htonl(ulOrgAckNum),
							ptcph->ack_seq, 1);
#endif
				}

				inet_proto_csum_replace4(q, skb,
					flow->ulSrcIp, flow->ulSrcNATIp, 1);
				inet_proto_csum_replace4(q, skb,
					flow->ulDestIp, flow->ulDestNATIp, 1);
				inet_proto_csum_replace4(q, skb,
					flow->ulPorts, flow->ulNATPorts, 0);
			}
#ifndef ASF_DO_INC_CHECKSUM
			else {
				skb->ip_summed = CHECKSUM_PARTIAL;

				if (iph->protocol == IPPROTO_TCP)
					tcp_hdr(skb)->check = 0;
				else if (iph->protocol == IPPROTO_UDP)
					udp_hdr(skb)->check = 0;
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
						inet_proto_csum_replace4(q + 8, skb,
							htonl(ulOrgSeqNum),
							ptcph->seq, 1);
					if (ulOrgAckNum != ntohl(ptcph->ack_seq))
						inet_proto_csum_replace4(q + 8, skb,
							htonl(ulOrgAckNum),
							ptcph->ack_seq, 1);
#endif
				}
			}
		}

#ifdef ASF_INGRESS_MARKER
		if (ASF_QM_NULL_DSCP != flow->mkinfo.uciDscp) {
		#ifdef ASF_DO_INC_CHECKSUM
			csum_replace4(&iph->check, iph->tos,
					flow->mkinfo.uciDscp);
		#endif
			iph->tos = flow->mkinfo.uciDscp;
		}
#endif

#ifdef ASF_IPSEC_FP_SUPPORT
		if (flow->bIPsecOut) {
			if (pFFPIPSecOut) {
				if (pFFPIPSecOut(ulVsgId,
					skb, &flow->ipsecInfo) == 0) {
					goto gen_indications;
				}
			}
			goto drop_pkt;

		}
#endif /*ASF_IPSEC_FP_SUPPORT*/
			asf_debug_l2("attempting to xmit the packet\n");
			/*skb_set_network_header(skb, hh_len); */

			/* flow->l2blob_len > 0 && flow->odev != NULL
			from this point onwards */
			if (((skb->len + flow->l2blob_len) >
				(flow->pmtu + ETH_HLEN)) ||
				(skb_shinfo(skb)->frag_list)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				struct sk_buff *pSkb, *pTempSkb;

				XGSTATS_INC(FragAndXmit);

				if (iph->frag_off & IP_DF)
					goto ret_pkt_to_stk;

				/* Need to call fragmentation routine */
				asf_debug("attempting to fragment and xmit\n");

				if (!asfIpv4Fragment(skb, flow->pmtu,
						/*32*/ flow->l2blob_len,
						0 /* FALSE */, flow->odev,
						&pSkb)) {
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
						asf_set_queue_mapping(pSkb,
								iph->tos);

						/* make following unconditional*/
						if (flow->bVLAN)
							pSkb->vlan_tci = flow->tx_vlan_id;
						else
							pSkb->vlan_tci = 0;

						ip_decrease_ttl(iph);

						pSkb->data -= flow->l2blob_len;
						pSkb->len += flow->l2blob_len;

						if (pSkb->data < pSkb->head) {
							asf_debug("SKB's head > data ptr .. UNDER PANIC!!!\n");
							ASFSkbFree(pSkb);
							continue;
						}

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
#ifdef ASF_QOS
						/* Enqueue the packet in Linux
						QoS framework */
						asf_qos_handling(pSkb, &flow->tc_filter_res);
#else
						if (asfDevHardXmit(pSkb->dev, pSkb) != 0) {
							asf_debug("Error in transmit: Should not happen\r\n");
							ASFSkbFree(pSkb);
						}
#endif
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
#else /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
				/* Fragmentation in case of ASF_MINIMUM */
				goto ret_pkt_to_stk;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			}
			XGSTATS_INC(NormalXmit);
			asf_debug_l2("decreasing TTL\n");
			ip_decrease_ttl(iph);

			asf_debug_l2("attempting to xmit non"
						" fragment packet\n");
			skb->dev = flow->odev;
			/* Update the MAC address information */
			skb->len += flow->l2blob_len;
			skb->data -= flow->l2blob_len;
			asf_debug_l2("copy l2blob to packet (blob_len %d)\n",
				flow->l2blob_len);
			asfCopyWords((unsigned int *)skb->data,
				(unsigned int *)flow->l2blob, flow->l2blob_len);
#ifdef ASF_IPV6_FP_SUPPORT
			if (flow->bIP4IP6Out) {
				struct ipv6hdr *ipv6h = (struct ipv6hdr *)skb_network_header(skb);
				ipv6h -= 1;
				ipv6h->payload_len = iph->tot_len;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				tunnel_hdr_len = sizeof(struct ipv6hdr);
#endif
			}
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (flow->bPPPoE) {
				/* PPPoE packet..
				 * Set Payload length in PPPoE header */
				*((short *)&(skb->data[(flow->l2blob_len - tunnel_hdr_len)-4])) =
				htons(ntohs(iph->tot_len + tunnel_hdr_len) + 2);
			}
#endif  /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			skb->pkt_type = PACKET_FASTROUTE;
			asf_set_queue_mapping(skb, iph->tos);

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
#ifdef ASF_QOS
			/* Enqueue the packet in Linux QoS framework */
			asf_qos_handling(skb, &flow->tc_filter_res);
#else
			if (asfDevHardXmit(skb->dev, skb)) {
				XGSTATS_INC(DevXmitErr);
				asf_debug("Error in transmit: may happen as we don't check for gfar free desc\n");
				ASFSkbFree(skb);
			}
#endif
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
				if (ffpCbFns.pFnFlowTcpSpecialPkts) {
					ASFFFPFlowSpecialPacketsInfo_t  ind;
					ffp_flow_t		      *oth_flow;

					ind.tuple.bIPv4OrIPv6 = 0;
					ind.tuple.ulSrcIp = flow->ulSrcIp;
					ind.tuple.ulDestIp = flow->ulDestIp;
					ind.tuple.usSrcPort = (flow->ulPorts >> 16);
					ind.tuple.usDestPort = flow->ulPorts&0xffff;
					ind.tuple.ucProtocol = flow->ucProtocol;
					ind.ulZoneId = flow->ulZoneId;
					ind.ulHashVal = htonl(ulHashVal);

					ind.ASFwInfo = (ASF_uint8_t *)flow->as_flow_info;
					ind.ulTcpState = ulTcpState;

					oth_flow = ffp_flow_by_id(&flow->other_id);

					ffp_copy_flow_stats(flow, &ind.flow_stats);
					if (oth_flow)
						ffp_copy_flow_stats(oth_flow, &ind.other_stats);
					else
						memset(&ind.other_stats, 0, sizeof(ind.other_stats));

					ffpCbFns.pFnFlowTcpSpecialPkts(ulVsgId, &ind);
				}
			}
			/* FlowValidate indicaion */
			if (FlowValidate) {
				if (!flow->bDeleted && ffpCbFns.pFnFlowValidate) {
					ASFFFPFlowValidateCbInfo_t  ind;

					ind.tuple.bIPv4OrIPv6 = 0;
					ind.tuple.ulSrcIp = flow->ulSrcIp;
					ind.tuple.ulDestIp = flow->ulDestIp;
					ind.tuple.usSrcPort = (flow->ulPorts >> 16);
					ind.tuple.usDestPort = flow->ulPorts&0xffff;
					ind.tuple.ucProtocol = flow->ucProtocol;
					ind.ulZoneId = flow->ulZoneId;
					ind.ulHashVal = htonl(ulHashVal);

					ind.ASFwInfo =
					(ASF_uint8_t *)flow->as_flow_info;

					ffpCbFns.pFnFlowValidate(ulVsgId, &ind);
				}
				switch (FlowValidate) {
				case ASF_FLOWVALIDATE_NORAMAL:
					break;
				case ASF_FLOWVALIDATE_INVALIDFLOW:
					XGSTATS_INC(bDropPkts);
					asf_debug("dropping packet as"\
						"bDrop is set\n");
					goto drop_pkt;
				default:
					break;
				}
			}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

			if (L2blobRefresh) {
				if (!flow->bDeleted && ffpCbFns.pFnFlowRefreshL2Blob) {
					ASFFFPFlowL2BlobRefreshCbInfo_t  ind;

					memset(&ind, 0, sizeof(ind));
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

					ind.ASFwInfo = NULL;

					XGSTATS_INC(PktCtxL2blobInd);
					ffpCbFns.pFnFlowRefreshL2Blob(ulVsgId, &ind);
				}
				switch (L2blobRefresh) {
				case ASF_L2BLOB_REFRESH_RET_PKT_STK:
						goto ret_pkt_to_stk;
						break;
				case ASF_L2BLOB_REFRESH_DROP_PKT:
						goto drop_pkt;
						break;
				default:
						break;
				}

			}
			return;
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
		asfAdjustFragAndSendUp(skb, anDev);
		return;
	}
	/* proceed with ret_pkt labelled code for non-frag pkt */

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulPktsToFNP++;
#endif
	if (ffpCbFns.pFnNoFlowFound) {
		ASFBuffer_t	abuf;
#ifdef ASF_IPV6_FP_SUPPORT
		if (skb->protocol == __constant_htons(ETH_P_IPV6))
			skb_push(skb, sizeof(struct ipv6hdr));
#endif
		abuf.nativeBuffer = skb;
		ffpCbFns.pFnNoFlowFound(anDev->ulVSGId,
			anDev->ulCommonInterfaceId, anDev->ulZoneId,
			abuf, (genericFreeFn_t)ASF_SKB_FREE_FUNC, skb);
		return;
	}
#if 0
/*TBD - This code is not used anywhere.
	when this code will be called?*/
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
#endif

#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
	asf_debug_l2("  ret_pkt LABEL -- calling netif_receive_skb!\n");
	ASF_netif_receive_skb(skb);
	asf_debug_l2("  ret_pkt LABEL -- returning from function!\n");
	return;


drop_pkt:
	asf_debug_l2("drop_pkt LABEL\n");
	/* TODO: we may have to iterate through frag_list and free all of them*/
	/* TODO: ensure all fragments are also dropped. and return STOLEN
	 always return stolen?? */
	pFreeFn(skb);
	return;
}
EXPORT_SYMBOL(ASFFFPProcessAndSendPkt);

ASF_void_t ASFProcessNonTermPkt(
		ASF_uint32_t	ulVsgId,
		ASF_uint32_t	ulCommonInterfaceId,
		ASFBuffer_t	Buffer,
		genericFreeFn_t	pFreeFn,
		ASF_void_t	*freeArg,
		ASF_void_t	*pIpsecOpaque)
{
	ASF_Modes_t mode;
	struct sk_buff *skb = (struct sk_buff *) Buffer.nativeBuffer;

	ASFGetVSGMode(ulVsgId, &mode);

	if (mode & fwMode) {
		ASFFFPProcessAndSendPkt(ulVsgId, ulCommonInterfaceId,
			Buffer, pFreeFn, freeArg, pIpsecOpaque);
	} else
#ifdef ASF_FWD_FP_SUPPORT
	if ((mode & fwdMode) && pFwdProcessPkt) {
		pFwdProcessPkt(ulVsgId, ulCommonInterfaceId,
			Buffer, pFreeFn, freeArg);
	} else
#endif
		ASF_netif_receive_skb(skb);
}
EXPORT_SYMBOL(ASFProcessNonTermPkt);

unsigned int asf_ffp_check_vsg_mode(ASF_uint32_t ulVSGId, ASF_Modes_t mode)
{
	if (ulVSGId >= asf_max_vsgs)
		return ASF_FALSE;

	if (asf_vsg_info[ulVSGId]) {
		if (asf_vsg_info[ulVSGId]->curMode & mode)
			return ASF_TRUE;
		else
			return ASF_FALSE;
	}

	/*if default mdoe is also same than is also ok. as it will create new
	vsg entry with default mode. */
	if (asf_default_mode & mode)
		return ASF_TRUE;

	return ASF_FALSE;
}
EXPORT_SYMBOL(asf_ffp_check_vsg_mode);

asf_vsg_info_t *asf_ffp_get_vsg_info_node(ASF_uint32_t ulVSGId)
{
	asf_vsg_info_t *vsg;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	if (ulVSGId >= asf_max_vsgs)
		return NULL;
	if (asf_vsg_info[ulVSGId])
		return asf_vsg_info[ulVSGId];
	vsg = kzalloc(sizeof(asf_vsg_info_t), flags);
	if (!vsg)
		return NULL;

	/* fill defaults */
	vsg->ulReasmMaxFrags = asf_reasm_maxfrags;
	vsg->ulReasmMinFragSize = asf_reasm_min_fragsize;
	vsg->ulReasmTimeout = asf_reasm_timeout;
	vsg->bDropOutOfSeq = asf_tcp_drop_oos;
	vsg->ulTcpSeqNumRange = ASF_TCP_MAX_SEQNUM;
	vsg->ulTcpRstSeqNumRange = ASF_TCP_MAX_SEQNUM;
	vsg->curMode = asf_default_mode;
	vsg->bIPsec = 0;
	asf_vsg_info[ulVSGId] = vsg;
	return vsg;
}
EXPORT_SYMBOL(asf_ffp_get_vsg_info_node);

ASF_void_t ASFGetCapabilities(ASFCap_t *pCap)
{
	pCap->ulNumVSGs = asf_max_vsgs;
	pCap->ulNumIfaces = asf_max_ifaces;
	pCap->bBufferHomogenous = 1;
	pCap->mode = fwMode;

#ifdef ASF_FWD_FP_SUPPORT
	pCap->mode |= fwdMode;
#endif

#ifdef ASF_TERM_FP_SUPPORT
	pCap->mode |= termMode;
#endif
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
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

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

	dev = kzalloc(sizeof(*dev), flags);
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
			asf_debug("MAP REQ ETHER cii %u ptr 0x%x\n",
				ulCommonInterfaceId,
				info->ucDevIdentifierInPkt);
			/*
			 * Device identifier must have ethernet port number.
			 * eg: 0 for eth0, 1 for eth1 etc.
			 */
			if ((info->ucDevIdentifierType == ASF_IFACE_MAC_IDENTIFIER) &&
				(info->ulDevIdentiferInPktLen != 6)) {
				asf_debug("Invalid DevIdLen %d for ETHER iface type\n",
					info->ulDevIdentiferInPktLen);
				goto free_and_ret_err;
			}
			read_lock_bh(&dev_base_lock);
			for_each_netdev(&init_net, ndev) {
				if ((ndev->type == ARPHRD_ETHER) &&
				(((info->ucDevIdentifierType == ASF_IFACE_MAC_IDENTIFIER) &&
				(info->ulDevIdentiferInPktLen == ndev->addr_len) &&
				(!memcmp(ndev->dev_addr, info->ucDevIdentifierInPkt, ndev->addr_len))) ||
				((info->ucDevIdentifierType == ASF_IFACE_NAME_IDENTIFIER) &&
				(!memcmp(ndev->name, info->ucDevIdentifierInPkt, info->ulDevIdentiferInPktLen))))) {
						asf_debug("ETHER iface found %s with mac %pM\n",
							ndev->name, ndev->dev_addr);
						found = 1;
						break;
					}
				}
			read_unlock_bh(&dev_base_lock);
			if (!found) {
				if (info->ucDevIdentifierType == ASF_IFACE_MAC_IDENTIFIER)
					asf_debug("Ethernet device with hwaddr %pM not found\n",
						info->ucDevIdentifierInPkt);
				else
					asf_debug("Ethernet device with name %s not found\n",
						info->ucDevIdentifierInPkt);
				goto free_and_ret_err;
			}

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
					goto free_and_ret_err;
				}

				attached_dev = asf_ifaces[cii];
				if (!attached_dev) {
					asf_debug("Attached iface of Bridge iface not found (CII %u)\n", cii);
					goto free_and_ret_err;
				}

				if ((attached_dev->ulDevType != ASF_IFACE_TYPE_ETHER)
				    && (attached_dev->ulDevType != ASF_IFACE_TYPE_VLAN)) {
					asf_debug("Attached iface (type %u) is not suitable for Bridge iface.\n",
						  attached_dev->ulDevType);
					goto free_and_ret_err;
				}
				attached_dev->pBrIfaceNext = dev->pBrIfaceNext;
				attached_dev->pBridgeDev = dev;
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
				parent_dev->pVlanDevArray =
					kzalloc(sizeof(ASFVlanDevArray_t), flags);
				if (!parent_dev->pVlanDevArray) {
					asf_debug("Failed alloc VLAN Dev array!\n");
					goto free_and_ret_err;
				}
			}

			/* Copy VLAN ID */
			dev->usId = usVlanId;
			dev->pParentDev = parent_dev;
			ASFInsertVlanDev(parent_dev, usVlanId, dev);

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
			dev->ndev = (void *) info->ulRelatedIDs[1];

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
	spin_unlock_bh(&asf_iface_lock);
	call_rcu((struct rcu_head *)  dev, asfNetDevFreeRcu);
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFUnMapInterface);


ASF_uint32_t ASFBindDeviceToVSG(ASF_uint32_t ulVSGId, ASF_uint32_t ulCommonInterfaceId)
{
	asf_debug(" begin cii %u vsg %u\n", ulCommonInterfaceId, ulVSGId);
	if ((ulVSGId < asf_max_vsgs)
		&& (ulCommonInterfaceId < asf_max_ifaces)
		&& asf_ifaces[ulCommonInterfaceId]) {

		asf_ifaces[ulCommonInterfaceId]->ulVSGId = ulVSGId;

		/* create vsg specific node if not allocated yet! */
		asf_ffp_get_vsg_info_node(ulVSGId);

		asf_debug(" exit ... success .. cii %u vsg %u\n",
			ulCommonInterfaceId, ulVSGId);
		return ASF_SUCCESS;
	}
	return ASF_FAILURE;
}
EXPORT_SYMBOL(ASFBindDeviceToVSG);

ASF_uint32_t ASFUnBindDeviceToVSG(ASF_uint32_t ulVSGId, ASF_uint32_t ulCommonInterfaceId)
{
	asf_debug(" begin cii %u vsg %u\n", ulCommonInterfaceId, ulVSGId);
	if ((ulVSGId < asf_max_vsgs)
		&& (ulCommonInterfaceId < asf_max_ifaces)
		&& asf_ifaces[ulCommonInterfaceId]) {

		asf_ifaces[ulCommonInterfaceId]->ulVSGId = ASF_INVALID_VSG;
		asf_debug(" exit ... success .. cii %u vsg %u\n",
			ulCommonInterfaceId, ulVSGId);
		return ASF_SUCCESS;
	}
	return ASF_FAILURE;
}
EXPORT_SYMBOL(ASFUnBindDeviceToVSG);


ASF_uint32_t ASFRemove(ASF_void_t)
{
	asf_enable = 0;

	/* it should cleanup the  forwarding flows as well.*/
	asf_ffp_cleanup_all_flows();

	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFRemove);

ASF_uint32_t ASFDeploy(ASF_void_t)
{
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

	if (configIdentity.bL2blobMagicNumber) {
		vsg->configIdentity.l2blobConfig.ulL2blobMagicNumber =
			configIdentity.l2blobConfig.ulL2blobMagicNumber;
	} else {
		vsg->configIdentity.ulConfigMagicNumber =
				configIdentity.ulConfigMagicNumber;
	}
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


ASF_uint32_t ASFSetTcpCtrlParams(ASF_uint32_t ulVSGId,
				ASFTcpCtrlParams_t *pInfo)
{
	asf_vsg_info_t  *vsg;

	if (ulVSGId >= asf_max_vsgs)
		return ASF_FAILURE;
	vsg = asf_ffp_get_vsg_info_node(ulVSGId);
	if (!vsg)
		return ASF_FAILURE;
	vsg->bDropOutOfSeq = pInfo->bDropOutOfSeq;
	vsg->ulTcpSeqNumRange = pInfo->ulTcpSeqNumRange;
	vsg->ulTcpRstSeqNumRange = pInfo->ulTcpRstSeqNumRange;
	return ASF_SUCCESS;
}
EXPORT_SYMBOL(ASFSetTcpCtrlParams);

static inline int ffp_flow_copy_info(ASFFFPFlowInfo_t *pInfo, ffp_flow_t *flow)
{
	bool	bIPv6;

	bIPv6 = pInfo->tuple.bIPv4OrIPv6 ? true : false;
#ifdef	ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true) {
		ipv6_addr_copy((struct in6_addr *)&(flow->ipv6SrcIp),
					(struct in6_addr *)(pInfo->tuple.ipv6SrcIp));
		ipv6_addr_copy((struct in6_addr *)&(flow->ipv6DestIp),
					(struct in6_addr *)(pInfo->tuple.ipv6DestIp));
	} else
#endif
	{
		flow->ulSrcIp = pInfo->tuple.ulSrcIp;
		flow->ulDestIp = pInfo->tuple.ulDestIp;
	}
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
#ifdef	ASF_IPV6_FP_SUPPORT
		if (bIPv6 == true) {
			ipv6_addr_copy((struct in6_addr *)&(flow->ipv6SrcNATIp),
						(struct in6_addr *)(pInfo->natInfo.ipv6SrcNATIp));
			ipv6_addr_copy((struct in6_addr *)&(flow->ipv6DestNATIp),
						(struct in6_addr *)(pInfo->natInfo.ipv6DestNATIp));
		} else
#endif
		{
			flow->ulSrcNATIp = pInfo->natInfo.ulSrcNATIp;
			flow->ulDestNATIp = pInfo->natInfo.ulDestNATIp;
		}
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
	bool		bIPv6_flow1, bIPv6_flow2;
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

	bIPv6_flow1 = p->flow1.tuple.bIPv4OrIPv6 ? true : false;
	bIPv6_flow2 = p->flow2.tuple.bIPv4OrIPv6 ? true : false;

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6_flow1 == true)
		flow1 = ffp_ipv6_flow_alloc();
	else
#endif
		flow1 = ffp_flow_alloc();

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6_flow2 == true)
		flow2 = ffp_ipv6_flow_alloc();
	else
#endif
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

#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow1 == true) {
			index1 = ptrIArray_add(&ffp_ipv6_ptrary, flow1);
			if (index1 > ffp_ptrary.nr_entries)
				goto down;
		} else
#endif
		{
			index1 = ptrIArray_add(&ffp_ptrary, flow1);
			if (index1 > ffp_ptrary.nr_entries)
				goto down;
		}

#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow2 == true) {
			index2 = ptrIArray_add(&ffp_ipv6_ptrary, flow2);
			if (index2 > ffp_ptrary.nr_entries)
				goto down1;
		} else
#endif
		{
			index2 = ptrIArray_add(&ffp_ptrary, flow2);
			if (index2 > ffp_ptrary.nr_entries)
				goto down1;
		}

		/* Need consideration for NAT PT */
		flow1->id.ulArg1 = index1;
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow1 == true)
			flow1->id.ulArg2 = ffp_ipv6_ptrary.pBase[index1].ulMagicNum;
		else
#endif
			flow1->id.ulArg2 = ffp_ptrary.pBase[index1].ulMagicNum;

		flow1->other_id.ulArg1 = index2;
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow2 == true)
			flow1->other_id.ulArg2 = ffp_ipv6_ptrary.pBase[index2].ulMagicNum;
		else
#endif
			flow1->other_id.ulArg2 = ffp_ptrary.pBase[index2].ulMagicNum;

		memcpy(&flow2->id, &flow1->other_id, sizeof(ASFFFPFlowId_t));
		memcpy(&flow2->other_id, &flow1->id, sizeof(ASFFFPFlowId_t));
#ifdef ASF_QOS
#ifdef ASF_INGRESS_MARKER
		/* Copying DSCP Mark info */
		flow1->mkinfo.uciDscp = p->flow1.mkinfo.uciDscp;
		flow2->mkinfo.uciDscp = p->flow2.mkinfo.uciDscp;
#endif
		flow1->tc_filter_res = TC_FILTER_RES_INVALID;
		flow2->tc_filter_res = TC_FILTER_RES_INVALID;
#endif

#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow1 == true) {
			hash1 = ASFFFPIPv6ComputeFlowHash1(&(flow1->ipv6SrcIp), &(flow1->ipv6DestIp), flow1->ulPorts,
						       ulVsgId, flow1->ulZoneId, asf_ffp_ipv6_hash_init_value);
		} else
#endif
		{
			hash1 = ASFFFPComputeFlowHash1(flow1->ulSrcIp, flow1->ulDestIp, flow1->ulPorts,
						       ulVsgId, flow1->ulZoneId, asf_ffp_hash_init_value);
		}
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow2 == true) {
			hash2 = ASFFFPIPv6ComputeFlowHash1(&(flow2->ipv6SrcIp), &(flow2->ipv6DestIp), flow2->ulPorts,
						       ulVsgId, flow2->ulZoneId, asf_ffp_ipv6_hash_init_value);
		} else
#endif
		{
			hash2 = ASFFFPComputeFlowHash1(flow2->ulSrcIp, flow2->ulDestIp, flow2->ulPorts,
						       ulVsgId, flow2->ulZoneId, asf_ffp_hash_init_value);
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (!flow1->bIPsecOut) {
			asf_debug_l2("creating l2blob timer (flow1)\n");
			flow1->pL2blobTmr = asfTimerStart(
						ASF_FFP_BLOB_TMR_ID, 0,
						asf_l2blob_refresh_interval,
						flow1->ulVsgId,
						flow1->id.ulArg1,
						flow1->id.ulArg2,
						hash1, bIPv6_flow1);
			if (!flow1->pL2blobTmr)
				goto down2;
		}
		asf_debug_l2("creating inac timer (flow1)\n");
		flow1->pInacRefreshTmr = asfTimerStart(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
							     flow1->ulInacTime/asf_inac_divisor,
							     flow1->ulVsgId,
							     flow1->id.ulArg1,
							     flow1->id.ulArg2, hash1, bIPv6_flow1);
		if (!flow1->pInacRefreshTmr)
			goto down2;

		if (!flow2->bIPsecOut) {
			asf_debug_l2("creating l2blob timer (flow2)\n");
			flow2->pL2blobTmr = asfTimerStart(
					ASF_FFP_BLOB_TMR_ID, 0,
					asf_l2blob_refresh_interval,
					flow2->ulVsgId,
					flow2->id.ulArg1,
					flow2->id.ulArg2,
					hash2, bIPv6_flow2);
			if (!flow2->pL2blobTmr)
				goto down2;
		}
		asf_debug_l2("creating inac timer (flow2)\n");
		flow2->pInacRefreshTmr = asfTimerStart(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
							     flow2->ulInacTime/asf_inac_divisor,
							     flow2->ulVsgId,
							     flow2->id.ulArg1,
							     flow2->id.ulArg2, hash2, bIPv6_flow2);
		if (!flow2->pInacRefreshTmr)
			goto down2;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		/* insert in the table.. but l2blob_len is zero meaning waiting for l2blob update */
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow1 == true)
			bkt = asf_ffp_ipv6_bucket_by_hash(hash1);
		else
#endif
			bkt = asf_ffp_bucket_by_hash(hash1);
		asf_ffp_flow_insert(flow1, bkt);
		if (pHashVal)
			*pHashVal = hash1;

#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow2 == true)
			bkt = asf_ffp_ipv6_bucket_by_hash(hash2);
		else
#endif
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
	if (flow1) {
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow1 == true)
			ffp_ipv6_flow_free(flow1);
		else
#endif
			ffp_flow_free(flow1);
	}
	if (flow2) {
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow2 == true)
			ffp_ipv6_flow_free(flow2);
		else
#endif
			ffp_flow_free(flow2);
	}
	asf_debug("flow creation failed!\n");
	if (pFlow1)
		*pFlow1 = NULL;
	if (pFlow2)
		*pFlow2 = NULL;
	return ASFFFP_RESPONSE_FAILURE;
down1:
	XGSTATS_INC(CreateFlowsCmdErrDown1);
	asf_debug("flow creation failed!\n");
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6_flow1 == true)
		ptrIArray_delete(&ffp_ipv6_ptrary, index1, ffp_ipv6_flow_free_rcu);
	else
#endif
		ptrIArray_delete(&ffp_ptrary, index1, ffp_flow_free_rcu);
	if (flow2) {
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6_flow2 == true)
			ffp_ipv6_flow_free(flow2);
		else
#endif
			ffp_flow_free(flow2);
	}
	if (pFlow1)
		*pFlow1 = NULL;
	if (pFlow2)
		*pFlow2 = NULL;
	return ASFFFP_RESPONSE_FAILURE;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
down2:
#endif
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
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6_flow1 == true)
		ptrIArray_delete(&ffp_ipv6_ptrary, index1, ffp_ipv6_flow_free_rcu);
	else
#endif
		ptrIArray_delete(&ffp_ptrary, index1, ffp_flow_free_rcu);
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6_flow2 == true)
		ptrIArray_delete(&ffp_ipv6_ptrary, index2, ffp_ipv6_flow_free_rcu);
	else
#endif
		ptrIArray_delete(&ffp_ptrary, index1, ffp_flow_free_rcu);
	return ASFFFP_RESPONSE_FAILURE;
}


static int ffp_cmd_delete_flows(ASF_uint32_t  ulVsgId, ASFFFPDeleteFlowsInfo_t *p, unsigned long *pHashVal)
{
	ffp_flow_t      *flow1, *flow2;
	ffp_bucket_t    *bkt1, *bkt2;
	unsigned long   hash1, hash2;
	int	     rem_flow2_resources = 0;
	bool		bIPv6;
	/* first detach the flows */
	bIPv6 = p->tuple.bIPv4OrIPv6 ? true : false;

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true)
		hash1 = ASFFFPIPv6ComputeFlowHashEx(&p->tuple, ulVsgId, p->ulZoneId, asf_ffp_ipv6_hash_init_value);
	else
#endif
		hash1 = ASFFFPComputeFlowHashEx(&p->tuple, ulVsgId, p->ulZoneId, asf_ffp_hash_init_value);
	if (pHashVal)
		*pHashVal = hash1;

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true)
		bkt1 = asf_ffp_ipv6_bucket_by_hash(hash1);
	else
#endif
		bkt1 = asf_ffp_bucket_by_hash(hash1);
	spin_lock_bh(&bkt1->lock);
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true)
		flow1 = asf_ffp_ipv6_flow_lookup_in_bkt_ex(&p->tuple, ulVsgId, p->ulZoneId, (ffp_flow_t *)  bkt1);
	else
#endif
		flow1 = asf_ffp_flow_lookup_in_bkt_ex(&p->tuple, ulVsgId, p->ulZoneId, (ffp_flow_t *)  bkt1);
	if (flow1) {
		if (unlikely(flow1->bDeleted)) {
			spin_unlock_bh(&bkt1->lock);
			return -1;
		}
		__asf_ffp_flow_remove(flow1, bkt1);
		flow1->bDeleted = 1;
		spin_unlock_bh(&bkt1->lock);

		/* Need consideration for NAT-PT */
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6 == true)
			flow2 = ffp_ipv6_flow_by_id(&flow1->other_id);
		else
#endif
			flow2 = ffp_flow_by_id(&flow1->other_id);
		if (flow2) {
#ifdef ASF_IPV6_FP_SUPPORT
			if (bIPv6 == true) {
				hash2 = ASFFFPIPv6ComputeFlowHash1(&flow2->ipv6SrcIp, &flow2->ipv6DestIp, flow2->ulPorts,
							       ulVsgId, flow2->ulZoneId, asf_ffp_ipv6_hash_init_value);
				bkt2 = asf_ffp_ipv6_bucket_by_hash(hash2);
			} else
#endif
			{
				hash2 = ASFFFPComputeFlowHash1(flow2->ulSrcIp, flow2->ulDestIp, flow2->ulPorts,
							       ulVsgId, flow2->ulZoneId, asf_ffp_hash_init_value);
				bkt2 = asf_ffp_bucket_by_hash(hash2);
			}
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
				/* Need consideration for NAT-PT */
#ifdef ASF_IPV6_FP_SUPPORT
				if (bIPv6 == true)
					ptrIArray_delete(&ffp_ipv6_ptrary, flow2->id.ulArg1, ffp_ipv6_flow_free_rcu);
				else
#endif
					ptrIArray_delete(&ffp_ptrary, flow2->id.ulArg1, ffp_flow_free_rcu);
			}
		}
		if (flow1->pL2blobTmr) {
			asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, flow1->pL2blobTmr);
		}
		if (flow1->pInacRefreshTmr) {
			asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, flow1->pInacRefreshTmr);
		}
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6 == true)
			ptrIArray_delete(&ffp_ipv6_ptrary, flow1->id.ulArg1, ffp_ipv6_flow_free_rcu);
		else
#endif
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
	bool		bIPv6;

	bIPv6 = p->tuple.bIPv4OrIPv6 ? true : false;

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true)
		flow = asf_ffp_ipv6_flow_lookup_by_tuple(&p->tuple, ulVsgId, p->ulZoneId, &hash);
	else
#endif
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

			if (p->u.l2blob.l2blobLen > ASF_MAX_L2BLOB_LEN) {
				asf_debug_l2("bloblen %d > MAX %d\n", p->u.l2blob.l2blobLen, ASF_MAX_L2BLOB_LEN);
				return ASFFFP_RESPONSE_FAILURE;
			}


			memcpy(&flow->l2blob, p->u.l2blob.l2blob, p->u.l2blob.l2blobLen);
			flow->l2blob_len = p->u.l2blob.l2blobLen;
			flow->pmtu = (dev->ndev->mtu < p->u.l2blob.ulPathMTU) ?
					dev->ndev->mtu : p->u.l2blob.ulPathMTU;
#ifdef ASF_IPV6_FP_SUPPORT
			flow->bIP6IP4Out = p->u.l2blob.tunnel.bIP6IP4Out;
			flow->bIP6IP4In = p->u.l2blob.tunnel.bIP6IP4In;
			flow->bIP4IP6Out = p->u.l2blob.tunnel.bIP4IP6Out;
			flow->bIP4IP6In = p->u.l2blob.tunnel.bIP4IP6In;
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			flow->bVLAN = p->u.l2blob.bTxVlan;
			flow->bPPPoE = p->u.l2blob.bUpdatePPPoELen;
			flow->tx_vlan_id = p->u.l2blob.usTxVlanId;

			flow->configIdentity.l2blobConfig.ulL2blobMagicNumber =
				p->u.l2blob.ulL2blobMagicNumber;
			flow->configIdentity.l2blobConfig.bl2blobRefreshSent = 0;

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
#ifdef ASF_QOS
#ifdef ASF_INGRESS_MARKER
			/* Copying DSCP Mark info */
			flow->mkinfo.uciDscp = p->mkinfo.uciDscp;
#endif
			flow->tc_filter_res = TC_FILTER_RES_INVALID;
#endif
			flow->bDrop = p->bDrop;
			if (flow->bDrop) {
				if (flow->pL2blobTmr) {
					asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, flow->pL2blobTmr);
					flow->pL2blobTmr = NULL;
				}
				if (flow->pInacRefreshTmr) {
					asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID,
							0, flow->pInacRefreshTmr);
					flow->pInacRefreshTmr = NULL;
				}
			} else {
				if (!flow->pL2blobTmr && !flow->bIPsecOut) {
					flow->pL2blobTmr = asfTimerStart(ASF_FFP_BLOB_TMR_ID, 0,
							asf_l2blob_refresh_interval,
							flow->ulVsgId,
							flow->id.ulArg1,
							flow->id.ulArg2, hash, bIPv6);
					if (!flow->pL2blobTmr) {
						flow->bDrop = 0;
						return ASFFFP_RESPONSE_FAILURE;
					}
				}
				if (!flow->pInacRefreshTmr) {
					flow->pInacRefreshTmr = asfTimerStart(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
							flow->ulInacTime/asf_inac_divisor,
							flow->ulVsgId,
							flow->id.ulArg1,
							flow->id.ulArg2, hash, bIPv6);
					if (!flow->pInacRefreshTmr) {
						flow->bDrop = 0;
						asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, flow->pL2blobTmr);
						flow->pL2blobTmr = NULL;
						return ASFFFP_RESPONSE_FAILURE;
					}
					if (ffpCbFns.pFnFlowActivityRefresh) {
						ASFFFPFlowRefreshInfo_t ind;

						ind.tuple.bIPv4OrIPv6 = 0;
						ind.tuple.ulSrcIp = flow->ulSrcIp;
						ind.tuple.ulDestIp = flow->ulDestIp;
						ind.tuple.usSrcPort = (flow->ulPorts >> 16);
						ind.tuple.usDestPort = flow->ulPorts&0xffff;
						ind.tuple.ucProtocol = flow->ucProtocol;
						ind.ulZoneId = flow->ulZoneId;

						/*ind.ulInactiveTime = htonl(ulIdleTime);*/
						ind.ulHashVal = htonl(hash);
						ffp_copy_flow_stats(flow, &ind.flow_stats);
						ind.ASFwInfo = (ASF_uint8_t *)flow->as_flow_info;
						XGSTATS_INC(TmrCtxInacInd);
						ffpCbFns.pFnFlowActivityRefresh(flow->ulVsgId, &ind);

						flow->pInacRefreshTmr->ulTmOutVal =
							flow->ulInacTime/asf_inac_divisor;

					}
				}
			}
			return ASFFFP_RESPONSE_SUCCESS;
		} else if (p->bIPsecConfigIdentityUpdate) {
			if (p->u.ipsec.bOut) {
				asf_debug("IPSEC status old=%d,"
					"new = %d timer=%x",
					flow->bIPsecOut,
					p->u.ipsec.bIPsecOut,
					flow->pL2blobTmr);
				memcpy(&flow->ipsecInfo.outContainerInfo,
					&p->u.ipsec.ipsecInfo.outContainerInfo,
					sizeof(flow->ipsecInfo.outContainerInfo));
				if (flow->bIPsecOut && !p->u.ipsec.bIPsecOut &&
					!flow->pL2blobTmr) {
					flow->pL2blobTmr = asfTimerStart(
							ASF_FFP_BLOB_TMR_ID, 0,
							asf_l2blob_refresh_interval,
							flow->ulVsgId,
							flow->id.ulArg1,
							flow->id.ulArg2, hash, bIPv6);
					if (!flow->pL2blobTmr)
						return ASFFFP_RESPONSE_FAILURE;
				} else if (!flow->bIPsecOut &&
					p->u.ipsec.bIPsecOut &&
					flow->pL2blobTmr) {

					asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0,
						flow->pL2blobTmr);
					flow->pL2blobTmr = NULL;
				}
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
			     unsigned int ulIndex, unsigned int ulMagicNum, unsigned int ulHashVal, bool bIPv6)
{
	ffp_flow_t *flow;
	ACCESS_XGSTATS();

	asf_debug_l2("vsg %u idx %u magic %u hash %u\n", ulVSGId, ulIndex, ulMagicNum, ulHashVal);
	XGSTATS_INC(BlobTmrCalls);

	if (asf_enable) {
#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6 == true)
			flow = ffp_ipv6_flow_by_id_ex(ulIndex, ulMagicNum);
		else
#endif
			flow = ffp_flow_by_id_ex(ulIndex, ulMagicNum);

		if (flow) {
			if (!flow->bIPsecOut && ffpCbFns.pFnFlowRefreshL2Blob) {
				ASFFFPFlowL2BlobRefreshCbInfo_t ind;

				memset(&ind, 0, sizeof(ind));
#ifdef ASF_IPV6_FP_SUPPORT
				if (bIPv6 == true) {
					ipv6_addr_copy((struct in6_addr *)&ind.flowTuple.ipv6SrcIp, (struct in6_addr *)&flow->ipv6SrcIp);
					ipv6_addr_copy((struct in6_addr *)&ind.flowTuple.ipv6DestIp, (struct in6_addr *)&flow->ipv6DestIp);
				} else
#endif

				{
					ind.flowTuple.ulSrcIp = flow->ulSrcIp;
					ind.flowTuple.ulDestIp = flow->ulDestIp;
				}

				ind.flowTuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;

				ind.flowTuple.usSrcPort = (flow->ulPorts >> 16);
				ind.flowTuple.usDestPort = flow->ulPorts&0xffff;
				ind.flowTuple.ucProtocol = flow->ucProtocol;

				if (flow->bNat) {
#ifdef ASF_IPV6_FP_SUPPORT
					if (bIPv6 == true) {
						ipv6_addr_copy((struct in6_addr *)&ind.packetTuple.ipv6SrcIp, (struct in6_addr *)&flow->ipv6SrcNATIp);
						ipv6_addr_copy((struct in6_addr *)&ind.packetTuple.ipv6DestIp, (struct in6_addr *)&flow->ipv6DestNATIp);
					} else
#endif
					{
						ind.packetTuple.ulSrcIp = flow->ulSrcNATIp;
						ind.packetTuple.ulDestIp = flow->ulDestNATIp;
					}
					ind.packetTuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;
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

				XGSTATS_INC(TmrCtxL2blobInd);
				ffpCbFns.pFnFlowRefreshL2Blob(flow->ulVsgId, &ind);
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
				    unsigned int ulIndex, unsigned int ulMagicNum, unsigned int ulHashVal, bool bIPv6)
{
	ffp_flow_t *flow1, *flow2;
	ACCESS_XGSTATS();


	asf_debug_l2("vsg %u idx %u magic %u hash %u\n", ulVSGId, ulIndex, ulMagicNum, ulHashVal);
	XGSTATS_INC(InacTmrCalls);

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true)
		flow1 = ffp_ipv6_flow_by_id_ex(ulIndex, ulMagicNum);
	else
#endif
		flow1 = ffp_flow_by_id_ex(ulIndex, ulMagicNum);
	if (flow1) {
		unsigned long flow1_idle, flow2_idle, ulIdleTime;

#ifdef ASF_IPV6_FP_SUPPORT
		if (bIPv6 == true)
			flow2 = ffp_ipv6_flow_by_id(&flow1->other_id);
		else
#endif
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

#ifdef ASF_IPV6_FP_SUPPORT
			if (bIPv6 == true) {
				ipv6_addr_copy((struct in6_addr *)&ind.tuple.ipv6SrcIp, (struct in6_addr *)&flow1->ipv6SrcIp);
				ipv6_addr_copy((struct in6_addr *)&ind.tuple.ipv6DestIp, (struct in6_addr *)&flow1->ipv6DestIp);
			} else
#endif
			{
				ind.tuple.ulSrcIp = flow1->ulSrcIp;
				ind.tuple.ulDestIp = flow1->ulDestIp;
			}

			ind.tuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;

			ind.tuple.usSrcPort = (flow1->ulPorts >> 16);
			ind.tuple.usDestPort = flow1->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow1->ucProtocol;
			ind.ulZoneId = flow1->ulZoneId;

			ind.ulInactiveTime = htonl(ulIdleTime);
			ind.ulHashVal = htonl(ulHashVal);
			ffp_copy_flow_stats(flow1, &ind.flow_stats);
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

	/* 10% of actual max value */
	max_num = ffp_max_flows/20;
	get_random_bytes(&asf_ffp_hash_init_value, sizeof(asf_ffp_hash_init_value));

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

	if (asfTimerWheelInit(ASF_FFP_BLOB_TMR_ID, 0,
			      ASF_FFP_BLOB_TIMER_BUCKT, ASF_TMR_TYPE_SEC_TMR,
			      ASF_FFP_BLOB_TIME_INTERVAL, ASF_FFP_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing L2blob Timer wheel\n");
		return -ENOMEM;
	}

	asf_print("Instantiating inac timer wheels\n");

	if (asfTimerWheelInit(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
			      ASF_FFP_INAC_TIMER_BUCKT, ASF_TMR_TYPE_SEC_TMR,
			      ASF_FFP_INAC_TIME_INTERVAL, ASF_FFP_NUM_RQ_ENTRIES) == 1) {
		asf_err("Error in initializing Inac Timer wheel\n");
		return -ENOMEM;
	}


	/* Register the callback function and timer pool Id */
	asf_print("Register Blob Timer App\n");

	if (asfTimerAppRegister(ASF_FFP_BLOB_TMR_ID, 0,
				(asfTmrCbFn) asfFfpBlobTmrCb,
				ffp_blob_timer_pool_id)) {
		asf_debug("Error in registering Cb Fn/Pool Id\n");
		return -ENOMEM;
	}

	asf_print("Register Inac Timer App\n");
	if (asfTimerAppRegister(ASF_FFP_INAC_REFRESH_TMR_ID, 0,
				(asfTmrCbFn) asfFfpInacRefreshTmrCb,
				ffp_inac_timer_pool_id)) {
		asf_debug("Error in registering Cb Fn/Pool Id\n");
		return -ENOMEM;
	}
	asf_print("Initializing pointer array!\n");
	/* initialize pointer array */
	node = kzalloc((sizeof(ptrIArry_nd_t)*ffp_max_flows), GFP_KERNEL);

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

#ifdef ASF_QOS
static inline void direct_xmit(struct sk_buff *skb)
{
#ifndef ASF_HW_SCH
	/* Reset the SKB Queue mapping, which is already
	set as per DSCP value */
	skb->queue_mapping = 0;
#endif
	if (asfDevHardXmit(skb->dev, skb) != 0) {
		asf_warn("Error in Xmit: may happen\r\n");
		ASFSkbFree(skb);
	}
}

void asf_qos_handling(struct sk_buff *skb, u32 *tc_filter_res)
{
	if (asf_qos_enable) {
#ifdef ASF_TC_QOS
		if (dev_queue_xmit(skb) != 0) {
			asf_warn("Error in Xmit: may happen\r\n");
			ASFSkbFree(skb);
		}

#else /* ASF_EGRESS_QOS */
		struct  asf_qdisc *root =
			((struct net_device *)skb->dev)->asf_qdisc;

		if (root) {
			root->enqueue(skb, root, tc_filter_res);
#ifndef CONFIG_DPA
			/* Now dequeue the packets */
			root->dequeue(root);
#endif
		} else
			direct_xmit(skb);
#endif
	} else
		direct_xmit(skb);
}
EXPORT_SYMBOL(asf_qos_handling);

#ifdef CONFIG_DPA
int asf_qos_fd_handling(ASFBuffer_t *abuf,
				struct net_device *dev,
				ASF_uint8_t dscp,
				u32 *tc_filter_res
)
{
	if (asf_qos_enable) {
		struct  asf_qdisc *root = dev->asf_qdisc;

		if (root)
			return root->enqueue_fd(abuf, root,
					dscp, tc_filter_res);
		/* else fall down */
	}
	{
		struct dpa_priv_s *priv = netdev_priv(dev);

		return qman_enqueue(priv->egress_fqs[smp_processor_id()],
					(struct	qm_fd *)&(abuf->pAnnot->timestamp), 0);
	}
}
EXPORT_SYMBOL(asf_qos_fd_handling);
#endif
#endif /*ASF_QOS*/

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
static inline void asf_clean_vsg(ASF_uint32_t ulVSGId, ASF_Modes_t mode)
{
	if (mode & fwMode)
		asf_ffp_cleanup_all_flows();

#ifdef ASF_FWD_FP_SUPPORT
	else if (mode & fwdMode)
		if (pFwdCleanVsg)
			pFwdCleanVsg(ulVSGId);
#endif

#ifdef ASF_TERM_FP_SUPPORT
	if (mode & termMode)
		if (pTermCleanVsg)
			pTermCleanVsg(ulVSGId);
#endif

	return;
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

	switch (mode & 0x3) {
#ifdef ASF_FWD_FP_SUPPORT
	case fwdMode:
		if (!asf_fwd_func_on) {
			asf_err(" Forwarding Mode Not Available");
			return ASF_FAILURE;
		}
		asf_print("Setting FWD Mode for VSG [%d]\n", ulVSGId);
		break;
#endif
	case fwMode:
		asf_print("Setting FFP Mode for VSG [%d]\n", ulVSGId);
		break;

	/* Termination Only Case*/
	case 0:
		break;

	/* FWD and FW mode are not supported simultaneously*/
	default:
		asf_err(" Not Supported Mode");
		return ASF_FAILURE;
	}

#ifdef ASF_TERM_FP_SUPPORT
	if (mode & termMode) {
		if (!asf_term_func_on) {
			asf_err(" Termination Mode Not Available");
			return ASF_FAILURE;
		}
		asf_print("Setting TERM Mode for VSG [%d]\n", ulVSGId);
	}
#endif

/* TBD- at present on mode set, ASF flows in all modules are being reset,
we may be able to selectively reset the flows in respective modules */

	asf_clean_vsg(ulVSGId, vsg_info->curMode);
	vsg_info->curMode = mode;

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
	asf_debug("VSGId[=%d] mode %d=%d ", ulVSGId, *mode, vsg_info->curMode);
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

static int __init asf_init(void)
{
	int err;

#ifdef ASF_TOOLKIT_SUPPORT
	/* Registering the character device */
	if (register_chrdev(ASF_HLD_MAJORNUMBER,
			ASF_HLD_DEVICE_NAME,
			&asf_interface_fops) < 0) {
		asf_err(" %s : %s : Unable to get the "\
			"major number %d\n", __FILE__,
					__func__, ASF_HLD_MAJORNUMBER);
		return -1;
	}
	spin_lock_init(&asf_app_lock);
#endif

#ifdef CONFIG_DPA
	/*Check to prevent the asf initialization
	with minimum headroom size*/
	if (CONFIG_FSL_FM_RX_EXTRA_HEADROOM < 16) {
		asf_err("rx_extra_headroom_size (%d) is not sufficient. ASF is not initialized.\n",
			CONFIG_FSL_FM_RX_EXTRA_HEADROOM);
		return -1;
	}
#endif
	get_random_bytes(&rule_salt, sizeof(rule_salt));

	if (asf_max_vsgs > ASF_MAX_VSGS) {
		asf_err("Number of VSG exceeded the Max Limit =%d",
			ASF_MAX_VSGS);
		return -1;
	}
	/*Checks are intoduced to prevent the asf initialization
	with negative parameter*/
	if (ffp_max_flows < 0) {
		asf_err("invalid number of flows (%d).ASF is not initialized.\n",
			ffp_max_flows);
		return -1;
	}
	if (ffp_hash_buckets < 0) {
		asf_err("invalid bucket size(%d).ASF is not initialized.\n",
			ffp_hash_buckets);
		return -1;
	}

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
	asf_ffp_get_vsg_info_node(0); /* create first vsg */

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

	asf_debug("Registering PROC entries\n");
	asf_register_proc();

	asf_print("Initializing Flow Table\n");
	err = asf_ffp_init_flow_table();
	if (err) {
		asf_ffp_destroy_flow_table();
		return err;
	}

#ifdef ASF_IPV6_FP_SUPPORT
	err = asf_ffp_ipv6_init();
	if (err) {
		printk(KERN_INFO"IPV6 initialization failed\n");
		return err;
	}
#endif
	return err;
}

static void __exit asf_exit(void)
{
/*	wait_queue_head_t dummyWq; */

#ifdef ASF_TOOLKIT_SUPPORT
	/* Unregister the character device from the kernel.*/
	unregister_chrdev(ASF_HLD_MAJORNUMBER, ASF_HLD_DEVICE_NAME);
#endif
	asf_debug("Unregister DevFP RX Hooks!\n");

	asfTimerDisableKernelTimers();
	asf_enable = 0;

	asf_debug("Waiting for all CPUs to finish existing packets!\n");
	synchronize_rcu();

	asf_debug("Unregister PROC entries\n");
	asf_unregister_proc();

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

#ifdef ASF_IPV6_FP_SUPPORT
	asf_ffp_ipv6_exit();
#endif

	asf_debug("Unregister DevFP TX Hooks at Last!\n");
}
module_init(asf_init);
module_exit(asf_exit);
