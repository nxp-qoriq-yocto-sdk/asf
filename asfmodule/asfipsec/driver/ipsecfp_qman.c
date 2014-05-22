/**************************************************************************
 * Copyright 2011-2012, Freescale Semiconductor, Inc. All rights reserved.
 * File:	ipsecfp_qman.c
 * Description: Contains the routines for ipsec fast path at the
 * device driver level
 * Authors:	Denis Crasta <b22176@freescale.com>
 *		Hemant Agrawal <hemant@freescale.com>
 *		Yashpal Dutta <b05456@freescale.com>
 * History
 * Version	Date		Author		Change Description
 ****************************************************************************/

#ifdef ASF_QMAN_IPSEC
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#include <linux/delay.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <linux/version.h>
#include <net/dst.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfterm.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include "ipseccmn.h"
#include "ipseccaam.h"
#include <linux/fsl_qman.h>

/*
** SEC_CONGESTION_CONTROL compile time flag will
** control the enable/disable the CONGESTION CONTROL
** feature on SEC and FRAGMENTATION Qs
*/
#ifdef SEC_CONGESTION_CONTROL
struct qman_cgr sec_qi_cgr, sec_frag_qi_cgr;
#define ASF_CGR_THRESHOLD 256
/* Hard Coding till better way is found */
#define SEC_QI_CGRID 23
#define SEC_QI_FRAG_CGRID 24
#endif

/* todo why hardcoding */
#define MAX_POOL_CHANNELS 15
#define MAX_PINFO 128
DEFINE_PER_CPU_ALIGNED(int32_t, smp_counter);
/* per-cpu tasklet for SEC processing */
struct tasklet_struct *percpu_tasklet;

spinlock_t secFP_OutQmanFqLock;
spinlock_t secFP_InQmanFqLock;

/*todo - we need to drive the base FQs from DTS - need to create
a node/section in DTS*/
#define IPSEC_ASF_FQID_BASE 2000
#define IPSEC_ASF_MAX_FQ_NUM 4000
#define SECFP_ASF_SECOUT_FQS	(NR_CPUS*4)

/* start outSA enq fq */
#define ASF_BASE_OUT_SEC_NUM IPSEC_ASF_FQID_BASE
/* start outSA recv fq */
#define ASF_BASE_OUT_RECV_NUM (ASF_BASE_OUT_SEC_NUM + SECFP_MAX_SAS)
/* start inSA enq fq */
#define ASF_BASE_IN_SEC_NUM (ASF_BASE_OUT_RECV_NUM + SECFP_ASF_SECOUT_FQS)
/* start inSA recv fq */
#define ASF_BASE_IN_RECV_NUM (ASF_BASE_IN_SEC_NUM + SECFP_MAX_SAS)
/* start fragmentation fqs*/
#define ASF_BASE_OUT_FRAG_RECV_NUM (ASF_BASE_IN_RECV_NUM + SECFP_ASF_SECOUT_FQS)

#define ASF_MAX_IPSEC_FQ_NUM (ASF_BASE_OUT_FRAG_RECV_NUM + NR_CPUS)

#if (IPSEC_ASF_MAX_FQ_NUM < (ASF_MAX_IPSEC_FQ_NUM - IPSEC_ASF_FQID_BASE))
	#error "IPSec ASF FQ Range overflow"
#endif

#define ASF_QMAN_MAX_OUT_FQS	SECFP_MAX_SAS
#define ASF_QMAN_MAX_IN_FQS	SECFP_MAX_SAS
#define ASF_IPSEC_SEC_SA_SHDESC_SIZE (64 * sizeof(u32))

struct secfp_fq_link_node_s *out_rcvfrag_percpu_fq[NR_CPUS];

struct secfp_fq_link_node_s *out_secfq_start, *out_secfq_end;
struct secfp_fq_link_node_s *out_recvfq_start, *out_recvfq_cur;
struct secfp_fq_link_node_s *in_secfq_start, *in_secfq_end;
struct secfp_fq_link_node_s *in_recvfq_start, *in_recvfq_cur;
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
struct secfp_fq_link_node_s *out_recvfragfq_start, *out_recvfragfq_end;
#endif
static inline struct secfp_fq_link_node_s *secfp_qman_alloc_fq(
	asf_qman_sec_fq_t queue_flag);

static inline void secfp_qman_release_out_fq(struct caam_ctx *ctx);
static inline void secfp_qman_release_in_fq(struct caam_ctx *ctx);

static inline void qman_ern_callback(struct qman_portal *qm,
		struct qman_fq *fq, const struct qm_mr_entry *msg);

static inline void qman_fqstate_change_callback(struct qman_portal *qm,
		struct qman_fq *fq, const struct qm_mr_entry *msg);

#ifdef SEC_CONGESTION_CONTROL
static inline int qm_cgr_cs_thres_set64(struct qm_cgr_cs_thres *th, u64 val,
				int roundup)
{
	u32 e = 0;
	int oddbit = 0;
	while (val > 0xff) {
		oddbit = val & 1;
		val >>= 1;
		e++;
		if (roundup && oddbit)
			val++;
	}
	th->Tn = e;
	th->TA = val;
	return 0;
}
#endif

/* Tasklet handler to get upto budget number of frames */
static void secfp_poll(unsigned long budget)
{
#define SECFP_BUDGET 64
	qman_poll_dqrr(SECFP_BUDGET);

	qman_irqsource_add(QM_PIRQ_DQRI);
}

static inline int secfp_build_qman_desc(struct caam_ctx *ctx)
{
	u32 ulqmflags = 0;
	u32 ulRecvFQID = 0, ulSecFQID = 0;
	int iretval = 0;
	struct qm_mcc_initfq opts;

	ulRecvFQID = ctx->RecvFq->qman_fq.fqid;

	/* Create a QMAN FQ to queue packets to SEC */
	ulqmflags = QMAN_INITFQ_FLAG_SCHED;

	ctx->SecFq->qman_fq.cb.ern = qman_ern_callback;
	ctx->SecFq->qman_fq.cb.fqs = qman_fqstate_change_callback;

	/* Enqueuing packets to SEC */
	ulSecFQID = ctx->SecFq->qman_fq.fqid;

	memset(&opts, 0, sizeof(struct qm_mcc_initfq));
	opts.fqid = ulSecFQID;
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA
			| QM_INITFQ_WE_CONTEXTB | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.channel = qm_channel_caam; /* dedicated channel */
	/* Code is not 64-bit safe */
	opts.fqd.context_a.hi = 0;
	/* Cntxt_A_lo contains shared descriptor pointer */
	opts.fqd.context_a.lo = (u32) ctx->shared_desc_phys;
	opts.fqd.context_b = ulRecvFQID;
	opts.fqd.fq_ctrl = QM_FQCTRL_CPCSTASH
				| QM_FQCTRL_PREFERINCACHE;
#ifdef SEC_CONGESTION_CONTROL
	opts.we_mask |= QM_INITFQ_WE_CGID;
	opts.fqd.cgid = SEC_QI_CGRID;
	opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif

	iretval = qman_init_fq(&(ctx->SecFq->qman_fq), ulqmflags, &opts);
	if (iretval) {
		ASFIPSEC_ERR("failed to init secFQ\n");
		return iretval;
	}

	ASFIPSEC_DEBUG("allocated 2 FQs %d %d", ulRecvFQID, ulSecFQID);
	return iretval;
}

int secfp_buildAHProtocolDesc(struct caam_ctx *ctx, void *pSA, int dir)
{
	u32 *sh_desc;
	struct preheader_t *prehdr;
	int ret = 0;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	/* build shared descriptor for this session */
	ctx->sh_desc_mem = kzalloc(
			ASF_IPSEC_SEC_SA_SHDESC_SIZE + L1_CACHE_BYTES - 1,
			GFP_DMA | flags);
	if (!ctx->sh_desc_mem) {
		ASFIPSEC_DPERR("Could not allocate shared descriptor");
		return -ENOMEM;
	}
	sh_desc = (u32 *)(((dma_addr_t)ctx->sh_desc_mem
			+ (L1_CACHE_BYTES - 1)) & ~(L1_CACHE_BYTES - 1));

	ctx->sh_desc = sh_desc;
	/* Leaving space for Pre header*/
	sh_desc += (sizeof(struct preheader_t)/sizeof(*sh_desc));

	/* Shared Descriptor Creation */
	if (dir == SECFP_AH_DIR_OUT) {
		spin_lock(&secFP_OutQmanFqLock);
		ctx->RecvFq = secfp_qman_alloc_fq(ASF_QMAN_OUT_RECV_FQ);
		ctx->SecFq = secfp_qman_alloc_fq(ASF_QMAN_OUT_SEC_FQ);
		spin_unlock(&secFP_OutQmanFqLock);

		if (!ctx->SecFq) {
			kfree(ctx->sh_desc_mem);
			ASFIPSEC_DPERR("No Sec FQ available, just return\n");
			return -ENOMEM;
		}
		ret = secfp_buildAHQMANSharedDesc(ctx, sh_desc,
					(outSA_t *)pSA, SECFP_AH_DIR_IN);
		if (ret) {
			ASFIPSEC_DPERR("prepareEncapShareDesc-ret=%d", ret);
			secfp_qman_release_out_fq(ctx);
			kfree(ctx->sh_desc_mem);
			return ret;
		}
	} else {
		spin_lock(&secFP_InQmanFqLock);
		ctx->RecvFq = secfp_qman_alloc_fq(ASF_QMAN_IN_RECV_FQ);
		ctx->SecFq = secfp_qman_alloc_fq(ASF_QMAN_IN_SEC_FQ);
		spin_unlock(&secFP_InQmanFqLock);
		if (!ctx->SecFq) {
			kfree(ctx->sh_desc_mem);
			ASFIPSEC_ERR("No Sec FQ available, just return\n");
			return -ENOMEM;
		}
		ret = secfp_buildAHQMANSharedDesc(ctx, sh_desc,
					(inSA_t *)pSA, SECFP_AH_DIR_OUT);
		if (ret) {
			ASFIPSEC_DPERR("prepareEncapShareDesc-ret=%d", ret);
			secfp_qman_release_in_fq(ctx);
			kfree(ctx->sh_desc_mem);
			return ret;
		}
	}

	prehdr = (struct preheader_t *)ctx->sh_desc;
	prehdr->hi.field.idlen = (*(ctx->sh_desc + 2) & 0x3F);
	prehdr->lo.field.pool_buffer_size = 256;

	ASFIPSEC_FPRINT("Dir=%d - Shared Descriptor===>\n", dir);
	ASFIPSEC_HEXDUMP(ctx->sh_desc, desc_bytes(ctx->sh_desc));

	/* End of Shared Descriptor Creation */
	ret = secfp_build_qman_desc(ctx);
	if (ret) {
		ASFIPSEC_DPERR("error in secfp_build_qman_desc");
		kfree(ctx->sh_desc_mem);
	}
	return ret;


}
int secfp_buildProtocolDesc(struct caam_ctx *ctx, void *pSA, int dir)
{
	u32 *sh_desc;
	struct preheader_t *prehdr;
	int ret = 0;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	/* build shared descriptor for this session */
	ctx->sh_desc_mem = kzalloc(
			ASF_IPSEC_SEC_SA_SHDESC_SIZE + L1_CACHE_BYTES - 1,
			GFP_DMA | flags);
	if (!ctx->sh_desc_mem) {
		ASFIPSEC_DPERR("Could not allocate shared descriptor");
		return -ENOMEM;
	}
	sh_desc = (u32 *)(((dma_addr_t)ctx->sh_desc_mem
			+ (L1_CACHE_BYTES - 1)) & ~(L1_CACHE_BYTES - 1));

	ctx->sh_desc = sh_desc;
	/* Leaving space for Pre header*/
	sh_desc += (sizeof(struct preheader_t)/sizeof(*sh_desc));

	/* Shared Descriptor Creation */
	if (dir == SECFP_OUT) {
		spin_lock(&secFP_OutQmanFqLock);
		ctx->RecvFq = secfp_qman_alloc_fq(ASF_QMAN_OUT_RECV_FQ);
		ctx->SecFq = secfp_qman_alloc_fq(ASF_QMAN_OUT_SEC_FQ);
		spin_unlock(&secFP_OutQmanFqLock);

		if (!ctx->SecFq) {
			kfree(ctx->sh_desc_mem);
			ASFIPSEC_DPERR("No Sec FQ available, just return\n");
			return -ENOMEM;
		}
		ret = secfp_prepareEncapShareDesc(ctx, sh_desc,
							(outSA_t *)pSA, 0);
		if (ret) {
			ASFIPSEC_DPERR("prepareEncapShareDesc-ret=%d", ret);
			secfp_qman_release_out_fq(ctx);
			kfree(ctx->sh_desc_mem);
			return ret;
		}
	} else {
		spin_lock(&secFP_InQmanFqLock);
		ctx->RecvFq = secfp_qman_alloc_fq(ASF_QMAN_IN_RECV_FQ);
		ctx->SecFq = secfp_qman_alloc_fq(ASF_QMAN_IN_SEC_FQ);
		spin_unlock(&secFP_InQmanFqLock);
		if (!ctx->SecFq) {
			kfree(ctx->sh_desc_mem);
			ASFIPSEC_ERR("No Sec FQ available, just return\n");
			return -ENOMEM;
		}
		ret = secfp_prepareDecapShareDesc(ctx, sh_desc,
					(inSA_t *)pSA, 0);
		if (ret) {
			ASFIPSEC_DPERR("prepareEncapShareDesc-ret=%d", ret);
			secfp_qman_release_in_fq(ctx);
			kfree(ctx->sh_desc_mem);
			return ret;
		}
	}

	prehdr = (struct preheader_t *)ctx->sh_desc;
	prehdr->hi.field.idlen = (*(ctx->sh_desc + 2) & 0x3F);
	prehdr->lo.field.pool_buffer_size = 256;

	ASFIPSEC_FPRINT("Dir=%d - Shared Descriptor===>\n", dir);
	ASFIPSEC_HEXDUMP(ctx->sh_desc, desc_bytes(ctx->sh_desc));

	/* End of Shared Descriptor Creation */
	ret = secfp_build_qman_desc(ctx);
	if (ret) {
		ASFIPSEC_DPERR("error in secfp_build_qman_desc");
		kfree(ctx->sh_desc_mem);
	}
	return ret;
}

void clearICVMutable(struct sk_buff *skb, struct ses_pkt_info *pInfo, inSA_t *pSA)
{
	struct iphdr *iph;
	int ii;

	pInfo->in_icv = kzalloc(pSA->ctx.split_key_len, GFP_ATOMIC | GFP_DMA);
	if (pInfo->in_icv == NULL) {
		ASFIPSEC_ERR("Unable to allocate memory for IN ICV");
		return;
	}
#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			pInfo->in_icv[ii] = skb->data[SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii];

		/*setting icv to zero before computing new ICV*/
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii] = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			pInfo->in_icv[ii] = skb->data[SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii];

		/*setting icv to zero before computing new ICV*/
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii] = 0;
	}
#endif
	/*setting mutable fields to zero */
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		iph = (struct iphdr *)skb->data;
		iph->frag_off = 0;
		iph->ttl = 0;
		iph->tos = 0;
		iph->check = 0;
	} else {
		struct ipv6hdr *ipv6h;
		ipv6h = (struct ipv6hdr *)skb->data;
		ipv6h->hop_limit = 0;
		ipv6h->priority = 0;
		memset(ipv6h->flow_lbl, 0, 3);
	}
}
int secfp_qman_in_submit(inSA_t *pSA, void *context)
{
	int	iRetVal;
	unsigned int	retryCount = 0;
	struct	qm_fd qmfd = {};
	struct sk_buff *skb1, *skb = (struct sk_buff *) context;
	struct scatter_gather_entry_s *sgt = NULL;
	struct device *pDev = pSA->ctx.jrdev;
	struct ses_pkt_info *pInfo;
	scatter_gather_entry_t *pSG;
	dma_addr_t pInmap, addr;
	unsigned int ulHdrLen = 0, i = 1;

	ASFIPSEC_DEBUG("QMAN enqueue submit\n");


	pInfo = kzalloc(sizeof(struct ses_pkt_info),
			GFP_ATOMIC | GFP_DMA);
	if (!pInfo) {
		ASFIPSEC_DPERR("Unable to allocate pInfo\n");
		return -ENOMEM;
	}
#ifdef ASF_IPV6_FP_SUPPORT
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
		ulHdrLen = pSA->ulSecHdrLen + SECFP_IPV6_HDR_LEN;
	else
#endif
		ulHdrLen = pSA->ulSecHdrLen + SECFP_IPV4_HDR_LEN;
	/* todo NAT-T header removal offload
	+ pSA->usNatHdrSize;
	skb->cb[SECFP_4X_NAT_HDR_SIZE] = pSA->usNatHdrSize;*/

	pSG = pInfo->cb_SG;
	pInfo->cb_skb = skb;
	pInfo->dir = SECFP_IN;
	pInfo->proto = pSA->SAParams.ucProtocol;
	ASFIPSEC_DEBUG("skb->len= %d headlen=%d\n", skb->len, skb_headlen(skb));
	/* ToDo: We shouldn't work with jrdev anymore */
	if (pSA->SAParams.ucProtocol == SECFP_PROTO_ESP) {
	if (skb_shinfo(skb)->frag_list) {
		struct scatter_gather_entry_s *sgt1;
		unsigned int total_frags;
		unsigned int ulFragpadlen = 0;
		unsigned int len_to_caam = 0;
		if (ulHdrLen % 8)
			ulFragpadlen = 8 - (ulHdrLen % 8);
		ulHdrLen += ulFragpadlen;
		for (total_frags = 1, skb1 = skb_shinfo(skb)->frag_list;
			skb1->next != NULL; total_frags++, skb1 = skb1->next)
			;
		sgt = kzalloc((2 * (total_frags + 1)) *
			sizeof(struct scatter_gather_entry_s),
			GFP_ATOMIC | GFP_DMA);
		sgt[0].offset = 0;
		sgt[0].length = skb_headlen(skb);
		addr = dma_map_single(pSA->ctx.jrdev,
				skb->data, skb_headlen(skb), DMA_BIDIRECTIONAL);
		sgt[0].addr_lo = (uint32_t) (addr);
		sgt[0].addr_hi = (uint32_t) (addr>>32);
		len_to_caam = skb_headlen(skb);
		skb1 = skb_shinfo(skb)->frag_list;
		while (1) {
			sgt[i].offset = 0;
			sgt[i].length = skb1->len;
			addr = dma_map_single(pSA->ctx.jrdev,
				skb1->data, skb1->len, DMA_BIDIRECTIONAL);
			len_to_caam += skb1->len;
			sgt[i].addr_lo = (uint32_t) (addr);
			sgt[i].addr_hi = (uint32_t) (addr>>32);
			i++;
			if (skb1->next == NULL)
				break;
			skb1 = skb1->next;
		}
		ASFIPSEC_DEBUG("len_to_caam%d total_frags %d\n",
			len_to_caam, total_frags);
		sgt[i - 1].final = 1;
		pInmap = dma_map_single(pSA->ctx.jrdev,
				sgt, (total_frags + 1)
			* sizeof(struct scatter_gather_entry_s),
			DMA_BIDIRECTIONAL);
		pSG[1].extension = 1;
		pSG[1].addr_lo = (uint32_t) pInmap;
		pSG[1].addr_hi = (uint32_t) (pInmap>>32);
		pSG[1].length = len_to_caam;
		sgt1 = &sgt[i];
		memcpy(sgt1, sgt, (total_frags + 1) *
			sizeof(struct scatter_gather_entry_s));
		addr = dma_map_single(pSA->ctx.jrdev,
				skb->data, skb_headlen(skb), DMA_BIDIRECTIONAL);
		sgt1[0].addr_lo = (uint32_t) (addr + ulHdrLen);
		sgt1[0].addr_hi = (uint32_t) ((addr + ulHdrLen)>>32);
		sgt1[0].length = skb_headlen(skb) - ulHdrLen;
		sgt[i - 1].length += ulFragpadlen;
		skb1->len += ulFragpadlen;
		ASFIPSEC_DEBUG("len_from_caam%d total_frags %d\n",
			 len_to_caam - ulHdrLen, total_frags);
		pInmap = dma_map_single(pSA->ctx.jrdev,
				sgt1, (total_frags + 1)
			* sizeof(struct scatter_gather_entry_s),
			DMA_BIDIRECTIONAL);
		pSG->length = len_to_caam - ulHdrLen;
		pSG->extension = 1;
		pSG->addr_lo = (uint32_t) (pInmap);
		pSG->addr_hi = (uint32_t) (pInmap >> 32);
	} else {
		pInmap = dma_map_single(pSA->ctx.jrdev,
			skb->data, skb->len, DMA_BIDIRECTIONAL);
		pSG->addr_lo = (uint32_t) (pInmap + ulHdrLen);
		pSG->addr_hi = (uint32_t) ((pInmap + ulHdrLen)>>32);
		pSG->length = skb->len;
		pSG[1].addr_lo = (uint32_t) pInmap;
		pSG[1].addr_hi = (uint32_t) (pInmap>>32);
		pSG[1].length = skb->len;
	}
	} else {
		clearICVMutable(skb, pInfo, pSA);
		pInmap = dma_map_single(pSA->ctx.jrdev,
			skb->data - pSA->ctx.split_key_len,
			skb->len + pSA->ctx.split_key_len,
			DMA_BIDIRECTIONAL);
		pInfo->dynamic = pSA->ctx.split_key_len;
		/* filling compound frame */
		pSG->addr_lo = (uint32_t) pInmap;
		pSG->addr_hi = (uint32_t) (pInmap >> 32);
		pSG->length = skb->len;
		pSG[1].addr_lo = (uint32_t) (pInmap + pSA->ctx.split_key_len);
		pSG[1].addr_hi = (uint32_t)
				((pInmap + pSA->ctx.split_key_len) >> 32);
		pSG[1].length = skb->len;
	}
	pSG[1].final = 1;


	qmfd._format2 = qm_fd_compound;
	qmfd.addr_lo = dma_map_single(pDev, pSG,
		2*sizeof(scatter_gather_entry_t), DMA_BIDIRECTIONAL);
	qmfd.length29 = 2*sizeof(scatter_gather_entry_t);

	ASFIPSEC_DEBUG("out_len=%d :: in_len=%d\n", pSG->length, pSG[1].length);

	do {
		iRetVal = qman_enqueue(&(pSA->ctx.SecFq->qman_fq),
				&qmfd, 0);
		if (iRetVal == 0)
			break;
		else
			__delay(50);
		if (++retryCount == ASF_MAX_TX_RETRY_CNT) {
			if (sgt)
				kfree(sgt);
			kfree(pInfo);
			return iRetVal;
		}
	} while (1);
	return iRetVal;
}

int secfp_qman_out_submit(outSA_t *pSA, void *context)
{
	int	iRetVal;
	struct	qm_fd qmfd = {};
	scatter_gather_entry_t *pSG;
	struct sk_buff *skb = (struct sk_buff *) context;
	struct device *pDev = pSA->ctx.jrdev;
	struct ses_pkt_info *pInfo;
	dma_addr_t pInmap;
	struct iphdr *iph;
	unsigned int		retryCount = 0;

	ASFIPSEC_DEBUG("QMAN enqueue submit\n");


	pInfo = kzalloc(sizeof(struct ses_pkt_info),
			GFP_ATOMIC | GFP_DMA);
	if (!pInfo) {
		ASFIPSEC_DPERR("Unable to allocate pInfo\n");
		return -ENOMEM;
	}

	iph = (struct iphdr *)skb->data;
	if (pSA->SAParams.ucProtocol == SECFP_PROTO_ESP) {
#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6) {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *) iph;
		ipv6h->hop_limit--;
	} else
#endif
		ip_decrease_ttl(iph);
	}

	pSG = pInfo->cb_SG;
	pInfo->cb_skb = skb;
	pInfo->dir = SECFP_OUT;
	pInfo->proto = pSA->SAParams.ucProtocol;
	if (pSA->SAParams.ucProtocol == SECFP_PROTO_ESP) {
	pInmap = dma_map_single(pSA->ctx.jrdev, (skb->data),
		skb->len + SECFP_APPEND_BUF_LEN_FIELD + SECFP_NOUNCE_IV_LEN,
		DMA_BIDIRECTIONAL);

	/* filling compound frame */
	pSG->addr_lo = (uint32_t) (pInmap - pSA->ulXmitHdrLen);
	pSG->addr_hi = (uint32_t) ((pInmap - pSA->ulXmitHdrLen)>>32);
	pSG->length = skb->len + pSA->ulCompleteOverHead;

	pSG[1].addr_lo = (uint32_t) (pInmap);
	pSG[1].addr_hi = (uint32_t) (pInmap>>32);
	} else {
		pInmap = dma_map_single(pSA->ctx.jrdev,
				(skb->data - pSA->ctx.split_key_len),
				skb->len + pSA->ctx.split_key_len,
				DMA_BIDIRECTIONAL);
		/* filling compound frame */
		pInfo->dynamic = pSA->ctx.split_key_len;
		pSG->addr_lo = (uint32_t) (pInmap);
		pSG->addr_hi = (uint32_t) (pInmap >> 32);
		pSG->length = skb->len;
		pSG[1].addr_lo = (uint32_t) ((pInmap) + pSA->ctx.split_key_len);
		pSG[1].addr_hi = (uint32_t)
				((pInmap + pSA->ctx.split_key_len) >> 32);
	}

	ASFIPSEC_DEBUG("QMAN enqueue submit pSA->ulCompleteOverHead %d\n",
				pSA->ulCompleteOverHead);

	pSG[1].length = (skb->len);
	pSG[1].final = 1;

	qmfd._format2 = qm_fd_compound;
	qmfd.addr_lo = (u32)dma_map_single(pDev, pSG,
		2*sizeof(scatter_gather_entry_t), DMA_BIDIRECTIONAL);
	qmfd.length29 = 2*sizeof(scatter_gather_entry_t);

	do {
			iRetVal = qman_enqueue(&(pSA->ctx.SecFq->qman_fq),
					&qmfd, 0);

		if (iRetVal == 0)
			break;
		else
			__delay(50);

		if (++retryCount == ASF_MAX_TX_RETRY_CNT)
			kfree(pInfo);
	} while (1);
	return iRetVal;
}

enum qman_cb_dqrr_result espDQRRCallback(struct qman_portal *qm,
	struct qman_fq *fq, const struct qm_dqrr_entry *dqrr)
{
	scatter_gather_entry_t *pSG;
	struct ses_pkt_info *pInfo;
	u32 err_val = 0;
	unsigned int retryCount = 0;
	dma_addr_t addr;

	if (unlikely(in_irq())) {
		/* Disable QMan IRQ and invoke NAPI */
		int ret = qman_irqsource_remove(QM_PIRQ_DQRI);
		if (likely(!ret)) {
			tasklet_schedule(&percpu_tasklet[smp_processor_id()]);
			return qman_cb_dqrr_stop;
		}
	}

	/* ToDo: We set dma_map_single, so, should use dma_umap_single here */
	pSG = (scatter_gather_entry_t *)phys_to_virt(dqrr->fd.addr_lo);
	if (!pSG) {
		ASFIPSEC_DPERR("NULL pSG buffer\n");
		return qman_cb_dqrr_consume;
	}

	pInfo = container_of(pSG, struct ses_pkt_info, cb_SG[0]);

	if (dqrr->fd.status) {
		char err[256];
		err_val = dqrr->fd.status;
		caam_jr_strstatus(err, dqrr->fd.status);
		if ((err_val & 0xF00000FF) == 0x40000084) {
			ASFIPSEC_DEBUG("ANTI-REPLAY-ERR FD status = %#x "
			"Err = %s\n", dqrr->fd.status, err);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
				IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
		} else if ((err_val & 0xF00000FF) == 0x40000083) {
			ASFIPSEC_DEBUG("LATE-PACKET-ERR FD status = %#x "
			"Err = %s\n", dqrr->fd.status, err);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
				IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT19]);
		} else {
			ASFIPSEC_DEBUG("FD status = %#x Err = %s\n",
			err_val, err);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
				IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
		}
		ASFSkbFree(pInfo->cb_skb);
		goto out;
	}

	addr = ((dma_addr_t)(pSG->addr_hi)<<32) + pSG->addr_lo;
	if (!pSG->extension)
		pInfo->cb_skb->data = (u8 *)phys_to_virt(addr);
	else {
		struct scatter_gather_entry_s *sgt =
		(struct scatter_gather_entry_s *)phys_to_virt(addr);
		addr = ((dma_addr_t)(sgt[0].addr_hi)<<32) + pSG->addr_lo;
		pInfo->cb_skb->data = (u8 *)phys_to_virt(addr);
		pInfo->cb_skb->len = sgt[0].length;
		kfree(sgt);
	}
	if (pInfo->proto != SECFP_PROTO_ESP)
		pInfo->cb_skb->data += pInfo->dynamic;
	if (pInfo->dir == SECFP_OUT) {
		if (pInfo->proto == SECFP_PROTO_ESP)
			pInfo->cb_skb->len = pSG->length;
		if (pInfo->proto == SECFP_PROTO_ESP)
			secfp_outComplete(pInfo->cb_pDev, NULL, 0, pInfo->cb_skb);
		else
			secfp_outAHComplete(pInfo->cb_pDev, NULL, 0, pInfo->cb_skb);
	} else {
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
		int hashval = 0, frag_cpu;
		struct iphdr *iph = (struct iphdr *)(pInfo->cb_skb->data);
		struct ipv6hdr *ip6h = (struct ipv6hdr *)(pInfo->cb_skb->data);

		/* determining the inner fragmented packet and hashing it on
		the basis of source ip and frag-id (for IPv4 only).
		*/
		if ((iph->version == 4) &&
				(iph->frag_off & htons(IP_MF|IP_OFFSET))) {
			hashval = iph->id + iph->saddr;
			frag_cpu = hashval % num_online_cpus();
		} else if ((iph->version == 6) &&
				(ip6h->nexthdr == NEXTHDR_FRAGMENT)) {
			hashval = ip6h->saddr.s6_addr32[0]
				+ ip6h->saddr.s6_addr32[1]
				+ ip6h->saddr.s6_addr32[2]
				+ ip6h->saddr.s6_addr32[3];
			frag_cpu = hashval % num_online_cpus();
		}

		if (hashval && (frag_cpu != smp_processor_id())) {
			ASFIPSEC_DEBUG("frag_pkt on other core=%d",
				smp_processor_id());
			do {
				err_val = qman_enqueue(&out_rcvfrag_percpu_fq
							[frag_cpu]->qman_fq,
						&dqrr->fd, 0);
				if (err_val == 0)
					break;
				else
					__delay(50);
				if (++retryCount == ASF_MAX_TX_RETRY_CNT) {
					asf_skb_free_func(pInfo->cb_skb);
					goto out;
				}
			} while (1);
			return qman_cb_dqrr_consume;
		} else
#endif
		if (pInfo->proto == SECFP_PROTO_ESP)
			if (skb_shinfo(pInfo->cb_skb)->frag_list)
				secfp_inCompleteWithFrags(pInfo->cb_pDev,
					NULL, 0, pInfo->cb_skb);
			else
				secfp_inComplete(pInfo->cb_pDev,
					NULL, 0, pInfo->cb_skb);
		else
			secfp_inAHComplete(pInfo->cb_pDev,
				(u32 *)pInfo, 0, pInfo->cb_skb);
	}
out:
	kfree(pInfo);
	return qman_cb_dqrr_consume;
}

/*
 * FunctionName : qman_ern_callback
 * Description : This function is a callback function to frame queues
 */
static inline void qman_ern_callback(struct qman_portal *qm,
		struct qman_fq *fq, const struct qm_mr_entry *msg)
{
	scatter_gather_entry_t *pSG;
	struct ses_pkt_info *pInfo;

	ASFIPSEC_DPERR("Unable to process the packet\n");
	pSG = (scatter_gather_entry_t *)phys_to_virt(msg->ern.fd.addr_lo);
	if (!pSG) {
		ASFIPSEC_DPERR("NULL pSG buffer\n");
		return;
	}
	pInfo = container_of(pSG, struct ses_pkt_info, cb_SG[0]);
	asf_skb_free_func(pInfo->cb_skb);
	kfree(pInfo);
	return;
}

/**
 * FunctionName : qman_fqstate_change_callback
 * Description : This function is a callback function to frame queues
 */
static inline void qman_fqstate_change_callback(struct qman_portal *qm,
			 struct qman_fq *fq, const struct qm_mr_entry *msg)
{
	ASFIPSEC_WARN("fqid %d status %x\n", msg->fq.fqid, msg->fq.fqs);
}

static inline void secfp_qman_release_out_fq(struct caam_ctx *ctx)
{
	spin_lock(&secFP_OutQmanFqLock);

	ctx->SecFq->fq_uses = 0;
	/*Put the fq back to the tail of empty queue*/
	ctx->SecFq->pPrev = out_secfq_end;
	ctx->SecFq->pNext = NULL;
	out_secfq_end->pNext = ctx->SecFq;
	out_secfq_end = ctx->SecFq;
	ASFIPSEC_DEBUG("Released Sec FQ:fqid = %d", ctx->SecFq->qman_fq.fqid);

	ctx->RecvFq->fq_uses--;
	ASFIPSEC_DEBUG("Released Recv FQ:fqid = %d, usages =%d",
		ctx->RecvFq->qman_fq.fqid, ctx->RecvFq->fq_uses);
	spin_unlock(&secFP_OutQmanFqLock);
}

static inline void secfp_qman_release_in_fq(struct caam_ctx *ctx)
{
	spin_lock(&secFP_InQmanFqLock);
	ctx->SecFq->fq_uses = 0;
	/*Put the fq back to the tail of empty queue*/
	ctx->SecFq->pPrev = in_secfq_end;
	ctx->SecFq->pNext = NULL;
	in_secfq_end->pNext = ctx->SecFq;
	in_secfq_end = ctx->SecFq;

	ASFIPSEC_DEBUG("Released Sec FQ:fqid = %d", ctx->SecFq->qman_fq.fqid);

	ctx->RecvFq->fq_uses--;
	ASFIPSEC_DEBUG("Released Recv FQ:fqid = %d, usages =%d",
		ctx->RecvFq->qman_fq.fqid, ctx->RecvFq->fq_uses);
	spin_unlock(&secFP_InQmanFqLock);
}

void secfp_qman_release_fq(struct caam_ctx *ctx, int dir)
{
	u32 flags = 0;

	if (ctx->SecFq == NULL) {
		ASFIPSEC_ERR("SecFq NULL ?\n");
		return;
	}

	if (dir == SECFP_OUT)
		secfp_qman_release_out_fq(ctx);
	else
		secfp_qman_release_in_fq(ctx);

	/*Handle SEC FQ*/
	if (qman_retire_fq(&(ctx->SecFq->qman_fq), &flags))
		ASFIPSEC_ERR("qman_retire_fq failed\n");

	/* Flags from qman_fq_state():
		QMAN_FQ_STATE_BLOCKOOS : if any are set, no OOS */
	else if (!(flags & QMAN_FQ_STATE_BLOCKOOS)) {
		struct qm_mcc_initfq initfq = {};
		/**
		* qman_query_fq - Queries FQD fields (via h/w query command)
		* @fq: the frame queue object to be queried
		* @fqd: storage for the queried FQD fields
		*/
		if (qman_query_fq(&(ctx->SecFq->qman_fq), &initfq.fqd))
			ASFIPSEC_ERR("qman_query_fq failed\n");

		/* qman_oos_fq - Puts a FQ "out of service"
		put out-of-service, must be 'retired' */
		else if (qman_oos_fq(&(ctx->SecFq->qman_fq)))
			ASFIPSEC_ERR(" qman_oos_fq failed\n");

	} else
		ASFIPSEC_ERR("(flags & QMAN_FQ_STATE_BLOCKOOS)\n");

	return;
}

static inline struct secfp_fq_link_node_s *secfp_qman_alloc_fq(
	asf_qman_sec_fq_t queue_flag)
{
	struct secfp_fq_link_node_s *qman_fq_node1,
		*qman_fq_node2, *qman_fq_node3;

	switch (queue_flag) {
	case ASF_QMAN_OUT_SEC_FQ:
		qman_fq_node1 = out_secfq_start->pNext;
		break;
	case ASF_QMAN_OUT_RECV_FQ:
		qman_fq_node1 = out_recvfq_cur;
		out_recvfq_cur = out_recvfq_cur->pNext;
		if (out_recvfq_cur == NULL)
			out_recvfq_cur = out_recvfq_start;
		qman_fq_node1->fq_uses++;
		return qman_fq_node1;
	case ASF_QMAN_IN_SEC_FQ:
		qman_fq_node1 = in_secfq_start->pNext;
		break;
	case ASF_QMAN_IN_RECV_FQ:
		qman_fq_node1 = in_recvfq_cur;
		in_recvfq_cur = in_recvfq_cur->pNext;
		if (in_recvfq_cur == NULL)
			in_recvfq_cur = in_recvfq_start;
		qman_fq_node1->fq_uses++;
		return qman_fq_node1;
	default:
		return NULL;
	}

	while (qman_fq_node1) {
		if ((qman_fq_node1->qman_fq.fqid != 0)
		&& (qman_fq_node1->fq_uses == 0)
		&& (qman_fq_node1->qman_fq.state == qman_fq_state_oos)) {
			ASFIPSEC_DEBUG("Hit FQ: fqid = %d",
				qman_fq_node1->qman_fq.fqid);

			qman_fq_node2 = qman_fq_node1->pPrev;
			qman_fq_node3 = qman_fq_node1->pNext;

			qman_fq_node2->pNext = qman_fq_node1->pNext;
			if (qman_fq_node3)
				qman_fq_node3->pPrev = qman_fq_node1->pPrev;
			else { /*in case of all fq being used up*/
				if (queue_flag == ASF_QMAN_OUT_SEC_FQ)
					out_secfq_end = out_secfq_start;
				else
					in_secfq_end = in_secfq_start;
			}
			qman_fq_node1->fq_uses = 1;
			return qman_fq_node1;
		}
		qman_fq_node1 = qman_fq_node1->pNext;
	}
	return NULL;
}

static inline int secfp_init_rcv_fq(struct qman_fq *fq,
		qman_cb_dqrr dqrr, int cpu, bool sec_hw_rcv_fq)
{
	struct qm_mcc_initfq opts;

	/* SEC can't generate ERN or can't even generate DCERN */
	fq->cb.dqrr = dqrr;
	fq->cb.ern = qman_ern_callback;
	fq->cb.fqs = qman_fqstate_change_callback;

	memset(&opts, 0, sizeof(struct qm_mcc_initfq));
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
	if (sec_hw_rcv_fq == ASF_TRUE) {
		opts.fqd.dest.channel = qm_channel_pool1;
		opts.fqd.fq_ctrl |= QM_FQCTRL_HOLDACTIVE;
	} else
#endif
	{
		opts.fqd.dest.channel = qman_affine_channel(cpu);
#ifdef SEC_CONGESTION_CONTROL
		opts.we_mask |= QM_INITFQ_WE_CGID;
		opts.fqd.cgid = SEC_QI_FRAG_CGRID;
		opts.fqd.fq_ctrl |= QM_FQCTRL_CGE;
#endif
	}

	opts.fqd.fq_ctrl |= QM_FQCTRL_CTXASTASHING | QM_FQCTRL_PREFERINCACHE |
			QM_FQCTRL_FORCESFDR | QM_FQCTRL_CPCSTASH;
	opts.fqid = fq->fqid;
	opts.we_mask |= QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_CONTEXTA
			| QM_INITFQ_WE_FQCTRL;
	opts.fqd.context_a.stashing.data_cl = 1;
	opts.fqd.context_a.stashing.annotation_cl = 1;

	return qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
}

static int secfp_qman_fq_init(void)
{
	struct secfp_fq_link_node_s *qman_fq_node, *qman_fq_node1;
	int i, j, num_fqs;
	u32 recv_fq_flags, sec_fq_flags, qman_fq_flag, fq_base_num;
	int iretval = 0;

	spin_lock_init(&secFP_OutQmanFqLock);
	spin_lock_init(&secFP_InQmanFqLock);

	sec_fq_flags = QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_NO_MODIFY;
	recv_fq_flags = QMAN_FQ_FLAG_NO_MODIFY;

	for (j = ASF_QMAN_MIN_SEC_FQ; j <= ASF_QMAN_MAX_SEC_FQ; j++) {
		switch (j) {
		case ASF_QMAN_OUT_SEC_FQ:
			out_secfq_start = kzalloc(
					sizeof(struct secfp_fq_link_node_s),
					GFP_KERNEL | GFP_DMA);
			qman_fq_node = out_secfq_start;
			qman_fq_flag = sec_fq_flags;
			fq_base_num = ASF_BASE_OUT_SEC_NUM;
			break;

		case ASF_QMAN_OUT_RECV_FQ:
			out_recvfq_start = kzalloc(
					sizeof(struct secfp_fq_link_node_s),
					GFP_KERNEL | GFP_DMA);
			qman_fq_node = out_recvfq_start;
			qman_fq_flag = recv_fq_flags;
			fq_base_num = ASF_BASE_OUT_RECV_NUM;
			break;

		case ASF_QMAN_IN_SEC_FQ:
			in_secfq_start = kzalloc(sizeof(
					struct secfp_fq_link_node_s),
					GFP_KERNEL | GFP_DMA);
			qman_fq_node = in_secfq_start;
			qman_fq_flag = sec_fq_flags;
			fq_base_num = ASF_BASE_IN_SEC_NUM;
			break;

		case ASF_QMAN_IN_RECV_FQ:
			in_recvfq_start = kzalloc(
					sizeof(struct secfp_fq_link_node_s),
					GFP_KERNEL | GFP_DMA);
			qman_fq_node = in_recvfq_start;
			qman_fq_flag = recv_fq_flags;
			fq_base_num = ASF_BASE_IN_RECV_NUM;
			break;
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
		case ASF_QMAN_OUT_FRAG_RECV_FQ:
			out_recvfragfq_start = kzalloc(
					sizeof(struct secfp_fq_link_node_s),
					GFP_KERNEL | GFP_DMA);
			qman_fq_node = out_recvfragfq_start;
			qman_fq_flag = recv_fq_flags;
			fq_base_num = ASF_BASE_OUT_FRAG_RECV_NUM;
			break;
#endif
		default:
			continue;
		}

		if ((j == ASF_QMAN_OUT_RECV_FQ) || (j == ASF_QMAN_IN_RECV_FQ))
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
			num_fqs = SECFP_ASF_SECOUT_FQS;
#else
			num_fqs = num_online_cpus();
#endif
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
		else if (j == ASF_QMAN_OUT_FRAG_RECV_FQ)
			num_fqs = num_online_cpus();
#endif
		else	/* or ASF_QMAN_MAX_OUT_FQS */
			num_fqs = ASF_QMAN_MAX_OUT_FQS;

		for (i = 0; i < num_fqs; i++) {
			qman_fq_node1 = qman_fq_node;
			iretval = qman_create_fq(fq_base_num + i,
				qman_fq_flag, &(qman_fq_node->qman_fq));
			if (iretval) {
				/*todo cleanup */
				ASFIPSEC_ERR("qman_create_fq ret=%d", iretval);
				return iretval;
			}
			if (i < (num_fqs - 1)) {
				qman_fq_node->pNext = kzalloc(
					sizeof(struct secfp_fq_link_node_s),
					GFP_KERNEL | GFP_DMA);
				/*Link to the start node*/
				qman_fq_node = qman_fq_node->pNext;
				qman_fq_node->pPrev = qman_fq_node1;
				qman_fq_node->pNext = NULL;
			}
		}

		switch (j) {
		case ASF_QMAN_OUT_SEC_FQ:
			out_secfq_end = qman_fq_node;
			break;

		case ASF_QMAN_OUT_RECV_FQ:
			out_recvfq_cur = out_recvfq_start;
			qman_fq_node = out_recvfq_start;
			for (i = 0; i < num_fqs; i++) {
				iretval = secfp_init_rcv_fq(
						&qman_fq_node->qman_fq,
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
						espDQRRCallback, i, ASF_TRUE);
#else
						espDQRRCallback, i, ASF_FALSE);
#endif
				if (iretval) {
					/*todo cleanup */
					ASFIPSEC_ERR("secfp_init_rcv_fq ret=%d",
							iretval);
					return iretval;
				}
				qman_fq_node = qman_fq_node->pNext;
			}
			break;

		case ASF_QMAN_IN_SEC_FQ:
			in_secfq_end = qman_fq_node;
			break;

		case ASF_QMAN_IN_RECV_FQ:
			in_recvfq_cur = in_recvfq_start;
			qman_fq_node = in_recvfq_start;
			for (i = 0; i < num_fqs; i++) {
				iretval = secfp_init_rcv_fq(
					&qman_fq_node->qman_fq,
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
					espDQRRCallback, i, ASF_TRUE);
#else
					espDQRRCallback, i, ASF_FALSE);
#endif
				if (iretval) {
					/*todo cleanup */
					ASFIPSEC_ERR("secfp_init_rcv_fq ret=%d",
							iretval);
					return iretval;
				}
				qman_fq_node = qman_fq_node->pNext;
			}
			break;
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
		case ASF_QMAN_OUT_FRAG_RECV_FQ:
			out_recvfragfq_end = qman_fq_node;
			qman_fq_node = out_recvfragfq_start;
			for (i = 0; i < num_fqs; i++) {
				out_rcvfrag_percpu_fq[i] = qman_fq_node;
				iretval = secfp_init_rcv_fq(
						&qman_fq_node->qman_fq,
						espDQRRCallback, i, ASF_FALSE);
				if (iretval) {
					/*todo cleanup */
					ASFIPSEC_ERR("secfp_init_rcv_fq ret=%d",
							iretval);
					return iretval;
				}
				qman_fq_node->fq_uses = 1;
				qman_fq_node = qman_fq_node->pNext;
			}
			break;
#endif
		default:
			break;
		}

#ifdef ASF_QMAN_IPSEC_DEBUG
		while (qman_fq_node->pPrev) {
			printk(KERN_INFO"fq_uses = %d\n",
				qman_fq_node->fq_uses);
			printk(KERN_INFO"FQ: fqid = %d\n",
				qman_fq_node->qman_fq.fqid);
			qman_fq_node = qman_fq_node->pPrev;
		}
#endif
	}
	return iretval;
}
static void teardown_fq(struct qman_fq *fq)
{
	u32 flags;
	int s = qman_retire_fq(fq, &flags);
	/* Retire is non-blocking, poll for completion */
	enum qman_fq_state state;
	if (s == 1) {
		do {
			qman_poll();
			qman_fq_state(fq, &state, &flags);
		} while (state != qman_fq_state_retired);
		if (flags & QMAN_FQ_STATE_NE) {
			/* FQ isn't empty, drain it */
			s = qman_volatile_dequeue(fq, 0,
				QM_VDQCR_NUMFRAMES_TILLEMPTY);
			if (s) {
				printk(KERN_ERR "Failed "
					"qman_volatile_dequeue() %d\n", s);
				return;
			}
			/* Poll for completion */
			do {
				qman_poll();
				qman_fq_state(fq, &state, &flags);
			} while (flags & QMAN_FQ_STATE_VDQCR);
		}
	}
	qman_fq_state(fq, &state, &flags);
	if (state != qman_fq_state_oos)
		qman_oos_fq(fq);

	qman_destroy_fq(fq, 0);
}

static int secfp_qman_fq_deinit(void)
{
	int i;
	struct secfp_fq_link_node_s *qman_fq_node, *qman_fq_node1;

	for (i = ASF_QMAN_MIN_SEC_FQ; i <= ASF_QMAN_MAX_SEC_FQ; i++) {
		switch (i) {
		case ASF_QMAN_OUT_SEC_FQ:
			qman_fq_node = out_secfq_start;
			break;
		case ASF_QMAN_OUT_RECV_FQ:
			qman_fq_node = out_recvfq_start;
			break;
		case ASF_QMAN_IN_SEC_FQ:
			qman_fq_node = in_secfq_start;
			break;
		case ASF_QMAN_IN_RECV_FQ:
			qman_fq_node = in_recvfq_start;
			break;
#ifndef ASF_DEDICTD_CHAN_SEC_OUT
		case ASF_QMAN_OUT_FRAG_RECV_FQ:
			qman_fq_node = out_recvfragfq_start;
			break;
#endif
		}
		while (qman_fq_node) {
			qman_fq_node1 = qman_fq_node;
			teardown_fq(&(qman_fq_node->qman_fq));
			qman_fq_node = qman_fq_node->pNext;
			kfree(qman_fq_node1);
		}
	}
	return 0;
}


#ifdef SEC_CONGESTION_CONTROL
int sec_qi_cgr_init(void)
{
	struct qm_mcc_initcgr opts = {
		.we_mask = QM_CGR_WE_CS_THRES |
			QM_CGR_WE_CSTD_EN |
			QM_CGR_WE_MODE,
		.cgr = {
			.cstd_en = QM_CGR_EN,
			.mode = QMAN_CGR_MODE_FRAME
		}
	};
	qm_cgr_cs_thres_set64(&opts.cgr.cs_thres,
		ASF_CGR_THRESHOLD, 0);
	sec_qi_cgr.cgrid = SEC_QI_CGRID;
	if (qman_create_cgr(&sec_qi_cgr,
		QMAN_CGR_FLAG_USE_INIT, &opts)) {
		ASFIPSEC_ERR("rx CGR init, continuing\n");
		return -EINVAL;
	}

	sec_frag_qi_cgr.cgrid = SEC_QI_FRAG_CGRID;
	if (qman_create_cgr(&sec_frag_qi_cgr,
		QMAN_CGR_FLAG_USE_INIT, &opts)) {
		qman_delete_cgr(&sec_qi_cgr);
		ASFIPSEC_ERR(" Frag CGR init, continuing\n");
		return -EINVAL;
	}
	return 0;
}

int sec_qi_cgr_deinit(void)
{
	qman_delete_cgr(&sec_qi_cgr);
	qman_delete_cgr(&sec_frag_qi_cgr);
	return 0;
}
#endif

int secfp_qman_init(void)
{
	int err = -ENOMEM, ii;

#ifdef SEC_CONGESTION_CONTROL
	if (sec_qi_cgr_init()) {
		ASFIPSEC_ERR("CGR Init Failure\n");
		err = -EINVAL;
		goto cgr_init_failure;
	}
#endif

	err = secfp_qman_fq_init();
	if (err) {
		ASFIPSEC_ERR("Unable to create FQs\n");
		goto qm_init_failure;
	}

	percpu_tasklet = kzalloc(NR_CPUS * sizeof(struct tasklet_struct), GFP_KERNEL);
	if (!percpu_tasklet) {
		ASFIPSEC_ERR("allocate per-cpu memory for ASF IPsec tasklet\n");
		goto tsklet_alloc_failure;
	}

	for_each_possible_cpu(ii)
		tasklet_init(&percpu_tasklet[ii], secfp_poll, 0);

	return 0;

tsklet_alloc_failure:
	secfp_qman_fq_deinit();
qm_init_failure:
#ifdef SEC_CONGESTION_CONTROL
	sec_qi_cgr_deinit();
cgr_init_failure:
#endif
	return err;
}

/* SEC QI cleanup */
void secfp_qman_deinit(void)
{
	int ii;

	secfp_qman_fq_deinit();

	flush_scheduled_work();

	if (percpu_tasklet)
		for_each_possible_cpu(ii)
			tasklet_kill(&percpu_tasklet[ii]);
	kfree(percpu_tasklet);

#ifdef SEC_CONGESTION_CONTROL
	sec_qi_cgr_deinit();
#endif
}

#endif /*ASF_QMAN_IPSEC */
