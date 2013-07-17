/**************************************************************************
 * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfqosapi_dpa.c
 *
 * Description: ASF Quality Of Service module for DPAA
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/*
 * History
 *  Version     Date        Author			Change Description *
 */
 /****************************************************************************/

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
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
#include <net/pkt_sched.h>
#include <linux/hrtimer.h>
#include <dpa/dpaa_eth.h>
#include <dpa/dpaa_eth-common.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfctrl/linux/ffp/asfctrl.h"
#include "asfqosapi.h"
#include "asfqos_pvt.h"
#include <linux/fsl_qman.h>

#define ASF_QOS_VERSION	"1.1.0"
#define ASF_QOS_DESC	"ASF Quality Of Service Component"
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
MODULE_DESCRIPTION(ASF_QOS_DESC);

int non_asf_priority = NON_ASF_PRIO;
module_param(non_asf_priority, int, 0644);
MODULE_PARM_DESC(non_asf_priority, "Default Priority Level for"
		" NON-ASF Traffic\n\t\t\tRange: 0-7, where '0' is"
		" the Highest Priority");

char *asf_qos_version = ASF_QOS_VERSION;
struct asf_qdisc *qdisc_in_use[ASF_MAX_IFACES] = {NULL};
/* FOllowing mapping will be used to indicate shaper configured or not for a device */
struct dev_fm_port_map {
	struct net_device	*dev;
	struct fm_port		*txport;
	uint32_t		rate;
} shaper[ASF_MAX_IFACES] = {};

uint8_t qdisc_cnt;
spinlock_t cnt_lock;

#define MAX_NUM_PRIO_WQ_IDX	3
#define MAX_NUM_DRR_WQ_IDX	0
#define MAX_NUM_WRR_WQ_IDX	2

#define NUM_FQ_PER_WQ		8

/* FMAN DCP ENUM values used by QMAN */
#define WQ_CS_CFG_FMAN0		2
#define WQ_CS_CFG_FMAN1		3

static ASFQOSCallbackFns_t	qosCbFns = {0};

static void egress_ern(struct qman_portal	*portal,
		       struct qman_fq		*fq,
		       const struct qm_mr_entry	*msg)
{
	struct qm_fd fd = msg->ern.fd;
	dma_addr_t addr = qm_fd_addr(&fd);
	struct sk_buff *skb = NULL;
	struct sk_buff **skbh;
	struct asf_qos_fq *asf_fq;

	asf_fq = (struct asf_qos_fq *)fq;
	/* Updates STATS */
	queue_lock(&(asf_fq->lock));
	asf_fq->ulDroppedPkts++;
	queue_unlock(&(asf_fq->lock));

	if (fd.cmd & FM_FD_CMD_FCO) {
		dpa_fd_release(asf_fq->net_dev, &fd);
		return;
	}

	asf_debug("Egress ERN .!\n");
	if (unlikely(!addr))
		return;

	skbh = (struct sk_buff **)phys_to_virt(addr);

	if (fd.format == qm_fd_contig) {
		/* Retrieve the skb backpointer */
		skb = *skbh;
	} else {
		asf_err("SG Buffer..?\n");
		/* Retrieve the skb backpointer */
		skb = *skbh;
		/* Free first buffer (which was allocated on Tx) */
		kfree((void *) skbh);

	}
	dev_kfree_skb_any(skb);
}


static const struct qman_fq priv_egress_fq = {
	.cb = { .ern = egress_ern }
};


static int qos_add_shaper(ASF_uint32_t  ulVsgId,
			ASFQOSCreateQdisc_t *qdisc)
{
	struct dpa_priv_s *priv;
	struct mac_device *mac_dev;
	struct fm_port *txport = NULL;
	int	i, err = 0;

	priv = netdev_priv(qdisc->dev);
	mac_dev = priv->mac_dev;
	txport = mac_dev->port_dev[TX];
	/* Adjust Values as per HW requirements */
	qdisc->u.tbf.rate = (qdisc->u.tbf.rate * 8)/1000; /* Kbits/sec */
	qdisc->u.tbf.maxBurst = 1024; /*KB*/

	/* Convert Shaper Rate into Bits/Sec */
	err = fm_port_set_rate_limit(txport,
				qdisc->u.tbf.maxBurst,
				qdisc->u.tbf.rate);
	if (err) {
		asf_err("Shaper Configuration Failed on dev %s\n",
				qdisc->dev->name);
		return ASF_FAILURE;
	}
	asf_debug("Rate limiting configured: Rate %d & Burst_Size %d\n",
				qdisc->u.tbf.rate, qdisc->u.tbf.maxBurst);

	for (i = 0; i < ASF_MAX_IFACES; i++) {
		if (shaper[i].dev == NULL) {
			/* Add to list */
			spin_lock(&cnt_lock);
			shaper[i].dev = qdisc->dev;
			shaper[i].txport = txport;
			shaper[i].rate = qdisc->u.tbf.rate;
			spin_unlock(&cnt_lock);
			break;
		} else if (shaper[i].dev == qdisc->dev) {
			/* update rate */
			spin_lock(&cnt_lock);
			shaper[i].rate = qdisc->u.tbf.rate;
			spin_unlock(&cnt_lock);
			break;
		}
	}
	if (i == ASF_MAX_IFACES)
		asf_err("Shaper mapping table full.. should not happen!\n");

	return ASF_SUCCESS;
}

static int qos_del_shaper(ASF_uint32_t  ulVsgId,
			ASFQOSDeleteQdisc_t *qdisc)
{
	int	err = 0, i;

	for (i = 0; i < ASF_MAX_IFACES; i++) {
		if (shaper[i].dev == qdisc->dev) {
			err = fm_port_del_rate_limit(shaper[i].txport);
			if (err) {
				asf_err("Shaper Deletion Failed on dev %s\n",
							qdisc->dev->name);
				return ASF_FAILURE;
			}
			printk(KERN_INFO "Rate limiting Disabled on %s\n",
							qdisc->dev->name);
			/* update table */
			spin_lock(&cnt_lock);
			shaper[i].dev = NULL;
			shaper[i].txport = NULL;
			shaper[i].rate = 0;
			spin_unlock(&cnt_lock);
			return ASF_SUCCESS;
		}
	}
	asf_err("Shaper not found on dev %s\n", qdisc->dev->name);
	return ASF_FAILURE;
}

/* Totoal DPA Buffer Count must be >= 2048 as for 64 byte traffic,
   a High Priority FQ will hold around 68 buffer & Low priority
   FQ will hold 35 buffers.
*/
/* Will use 4096 byte Threshold for FQs which concerns to First
   two Highest Priority WQs & a Threshold of 2048 will be used
   for last 2 prioity WQ's FQ. */
#define TAILDROP_THRESHOLD	4096

int prio_alloc_fqs(struct  asf_qdisc *sch)
{
	struct dpa_priv_s	*priv;
	struct qman_fq		*fq;
	struct qm_mcc_initfq	 initfq;
	struct asf_qos_fq	*asf_fq;
	u32			i, j, flags;
	int			_errno;
	struct mac_device	*mac_dev;
	struct fm_port		*txport = NULL;

	priv = netdev_priv(sch->dev);
	mac_dev = priv->mac_dev;
	txport = mac_dev->port_dev[TX];

	memset(&initfq, 0, sizeof(struct qm_mcc_initfq));

	flags = QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_DYNAMIC_FQID;

	for (i = 0; i <= MAX_NUM_PRIO_WQ_IDX; i++) {
		for (j = 0; j < NUM_FQ_PER_WQ; j++) {

			asf_fq = (struct  asf_qos_fq *)
				kzalloc(sizeof(struct  asf_qos_fq),
					GFP_KERNEL);
			if (!asf_fq) {
				asf_err("OHHHH..NO Memory for QMAN_FQ\n");
				return -ENOMEM;
			}
			asf_fq->egress_fq = priv_egress_fq;

			_errno = qman_create_fq(0 , flags, &asf_fq->egress_fq);
			if (_errno) {
				asf_err("qman_create_fq() failed\n");
				kfree(asf_fq);
				return _errno;
			}
			/* Initialize FQ */
			fq = &asf_fq->egress_fq;
			initfq.we_mask = QM_INITFQ_WE_DESTWQ;
			initfq.fqd.dest.channel	=
				fm_get_tx_port_channel(txport);
			/* We will use WQ 0 1 2 & 5 */
			if (i == 3)
				initfq.fqd.dest.wq = i + 2;
			else
				initfq.fqd.dest.wq = i;
			initfq.we_mask |= QM_INITFQ_WE_TDTHRESH | QM_INITFQ_WE_FQCTRL;
			if (i < 2)
				qm_fqd_taildrop_set(&initfq.fqd.td,
						TAILDROP_THRESHOLD, 1);
			else
				qm_fqd_taildrop_set(&initfq.fqd.td,
						TAILDROP_THRESHOLD/2, 1);
			initfq.fqd.fq_ctrl = QM_FQCTRL_TDE | QM_FQCTRL_PREFERINCACHE;

			_errno = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
			if (_errno < 0) {
				asf_err("qman_init_fq(%u) = %d\n",
						qman_fq_fqid(fq), _errno);
				qman_destroy_fq(fq, 0);
				kfree(asf_fq);
				return _errno;
			}
			asf_debug("#### CH: %d Created FQ_FQID %d on WQ %d\n",
						initfq.fqd.dest.channel,
						fq->fqid,
						initfq.fqd.dest.wq);

			asf_fq->net_dev = sch->dev;
			sch->asf_fq[i][j] = asf_fq;
		}
	}
	return ASF_SUCCESS;
}

int drr_alloc_fq(struct  asf_qdisc *sch, ASFQOSCreateQdisc_t *qdisc)
{
	struct dpa_priv_s	*priv;
	struct qman_fq		*fq;
	struct qm_mcc_initfq	initfq;
	struct asf_qos_fq	*asf_fq;
	u32			j, flags;
	int			_errno;
	struct mac_device	*mac_dev;
	struct fm_port		*txport = NULL;

	priv = netdev_priv(sch->dev);
	mac_dev = priv->mac_dev;
	txport = mac_dev->port_dev[TX];

	flags = QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_DYNAMIC_FQID;

	for (j = 0; j < NUM_FQ_PER_WQ; j++) {
		if (sch->asf_fq[MAX_NUM_DRR_WQ_IDX][j] == NULL)
			break;
	}
	if (j == NUM_FQ_PER_WQ) {
		asf_err("MAX %d Classes allowed per DRR Qdisc\n",
							NUM_FQ_PER_WQ);
		return -ENOMEM;
	}

	asf_fq = (struct  asf_qos_fq *) kzalloc(sizeof(struct  asf_qos_fq),
								GFP_KERNEL);
	if (!asf_fq) {
		asf_err("OHHHH..NO Memory for QMAN_FQ\n");
		return -ENOMEM;
	}
	asf_fq->egress_fq = priv_egress_fq;

	_errno = qman_create_fq(0 , flags, &asf_fq->egress_fq);
	if (_errno) {
		asf_err("qman_create_fq() failed\n");
		kfree(asf_fq);
		return _errno;
	}
	spin_lock_init(&(asf_fq->lock));
	/* Initialize FQ */
	fq = &asf_fq->egress_fq;
	initfq.we_mask = QM_INITFQ_WE_DESTWQ;
	initfq.fqd.dest.channel	=
		fm_get_tx_port_channel(txport);
	/* Using WQ = 1 for DRR flows */
	initfq.fqd.dest.wq = 1;
	initfq.we_mask |= QM_INITFQ_WE_TDTHRESH |
				QM_INITFQ_WE_FQCTRL | QM_INITFQ_WE_ICSCRED;
	qm_fqd_taildrop_set(&initfq.fqd.td, TAILDROP_THRESHOLD, 1);
	/* Set FQs credits */
	initfq.fqd.ics_cred = asf_fq->quantum =
				qdisc->u.drr.quantum;
	asf_debug("Setting ics %d on FQ %d\n", initfq.fqd.ics_cred, fq->fqid);

	initfq.fqd.fq_ctrl = QM_FQCTRL_TDE | QM_FQCTRL_PREFERINCACHE;

	_errno = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
	if (_errno < 0) {
		asf_err("qman_init_fq(%u) = %d\n", qman_fq_fqid(fq), _errno);
		qman_destroy_fq(fq, 0);
		kfree(asf_fq);
		return _errno;
	}
	asf_debug("#### CH: %d Created FQ_FQID %d on WQ %d\n",
					initfq.fqd.dest.channel,
					fq->fqid,
					initfq.fqd.dest.wq);

	asf_fq->net_dev = sch->dev;
	asf_fq->classid = qdisc->handle;
	sch->asf_fq[MAX_NUM_DRR_WQ_IDX][j] = asf_fq;

	return ASFQOS_SUCCESS;
}

int wrr_alloc_fqs(struct  asf_qdisc *sch, ASFQOSCreateQdisc_t *qdisc)
{
	struct dpa_priv_s	*priv;
	struct qman_fq		*fq;
	struct qm_mcc_initfq	 initfq;
	struct asf_qos_fq	*asf_fq;
	u32			i, j, flags;
	int			_errno;
	struct mac_device	*mac_dev;
	struct fm_port		*txport = NULL;

	priv = netdev_priv(sch->dev);
	mac_dev = priv->mac_dev;
	txport = mac_dev->port_dev[TX];

	flags = QMAN_FQ_FLAG_TO_DCPORTAL | QMAN_FQ_FLAG_DYNAMIC_FQID;

	for (i = 0; i <= MAX_NUM_WRR_WQ_IDX; i++) {
		for (j = 0; j < NUM_FQ_PER_WQ; j++) {

			asf_fq = (struct  asf_qos_fq *)
				kzalloc(sizeof(struct  asf_qos_fq),
					GFP_KERNEL);
			if (!asf_fq) {
				asf_err("OHHHH..NO Memory for QMAN_FQ\n");
				return -ENOMEM;
			}
			asf_fq->egress_fq = priv_egress_fq;

			_errno = qman_create_fq(0 , flags, &asf_fq->egress_fq);
			if (_errno) {
				asf_err("qman_create_fq() failed\n");
				kfree(asf_fq);
				return _errno;
			}
			/* Initialize FQ */
			fq = &asf_fq->egress_fq;
			initfq.we_mask = QM_INITFQ_WE_DESTWQ;
			initfq.fqd.dest.channel	=
				fm_get_tx_port_channel(txport);
			/* Using WQ = 2, 3 & 4 for WRR flows */
			initfq.fqd.dest.wq = i + 2;
			initfq.we_mask |= QM_INITFQ_WE_TDTHRESH | QM_INITFQ_WE_FQCTRL ;
			if (i < 2)
				qm_fqd_taildrop_set(&initfq.fqd.td,
						TAILDROP_THRESHOLD, 1);
			else
				qm_fqd_taildrop_set(&initfq.fqd.td,
						TAILDROP_THRESHOLD/2, 1);

			initfq.fqd.fq_ctrl = QM_FQCTRL_TDE | QM_FQCTRL_PREFERINCACHE;

			_errno = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &initfq);
			if (_errno < 0) {
				asf_err("qman_init_fq(%u) = %d\n",
						qman_fq_fqid(fq), _errno);
				qman_destroy_fq(fq, 0);
				kfree(asf_fq);
				return _errno;
			}
			asf_debug("#### CH: %d Created FQ_FQID %d on WQ %d\n",
						initfq.fqd.dest.channel,
						fq->fqid,
						initfq.fqd.dest.wq);

			asf_fq->net_dev = sch->dev;
			asf_fq->quantum = qdisc->u.wrr.weight[i];
			sch->asf_fq[i][j] = asf_fq;
		}
	}
	return ASF_SUCCESS;
}

int qdisc_cleanup_fqs(struct  asf_qdisc *sch)
{
	struct qman_fq		*fq;
	struct asf_qos_fq	*asf_fq;
	u32			i, j;

	for (i = 0; i <= MAX_NUM_PRIO_WQ_IDX; i++) {
		for (j = 0; j < NUM_FQ_PER_WQ; j++) {

			asf_fq =  sch->asf_fq[i][j];
			if (!asf_fq)
				return ASF_SUCCESS;

			/* Initialize FQ */
			fq = &asf_fq->egress_fq;
			qman_destroy_fq(fq, 0);
			kfree(asf_fq);
		}
	}
	return ASF_SUCCESS;
}

struct	qman_fq	*qos_get_fq(u8 is_abuf, void *buf, ASF_uint8_t prio,
			struct  asf_qdisc *sch, u32 *tc_filter_res)
{
	struct asf_qos_fq	*asf_fq;

	switch (sch->qdisc_type) {
	case ASF_QDISC_PRIO:
		/* We can have at max 4 PRIO Queues */
		if (prio > MAX_NUM_PRIO_WQ_IDX)
			prio = MAX_NUM_PRIO_WQ_IDX;
		asf_fq =  sch->asf_fq[prio][smp_processor_id()];
		asf_fq->ulEnqueuePkts++;
		return &asf_fq->egress_fq;

	case ASF_QDISC_DRR:
		switch (*tc_filter_res) {
		case TC_FILTER_RES_INVALID:
		{
			struct sk_buff *skb;
			u32 classid, i;

			if (is_abuf) {
				skb = (struct sk_buff *)
					asf_abuf_to_skb((ASFBuffer_t *)buf);
			} else
				skb = (struct sk_buff *) buf;
			/* Checkout Filter table */
			if (sch->parent != ROOT_ID) {
				/* find actual qdisc and the root
				   must be TBF only */
				struct Qdisc *q =
					tbf_get_inner_qdisc(sch->dev->qdisc);

				classid = drr_filter_lookup(skb, q);
			} else
				classid = drr_filter_lookup(skb, sch->dev->qdisc);

			asf_debug("Got CLASS_ID 0x%X\n", classid);
			if (!classid) {
				asf_debug("Matching Class[0x%X]"
					" not found, DROP PKT!\n", classid);
				return NULL;
			}
			/* convert classid to Fq index */
			for (i = 0; i < NUM_FQ_PER_WQ; i++) {
				asf_fq =  sch->asf_fq[MAX_NUM_DRR_WQ_IDX][i];
				if (asf_fq && (asf_fq->classid == classid)) {
					*tc_filter_res = i;
					asf_debug("Matching class[0x%x] found"
							" at FQ %d\n", classid , i);
					queue_lock(&(asf_fq->lock));
					asf_fq->ulEnqueuePkts++;
					queue_unlock(&(asf_fq->lock));
					return &asf_fq->egress_fq;
				}
			}
			if (i == NUM_FQ_PER_WQ) {
				asf_err("Matching Class[0x%X] not configured,"
					" should not happen!\n", classid);
				return NULL;
			}

		}
		break;
		default:
			/* 8 DRR Queues Supported but 1 WQ '0' only */
			asf_fq =  sch->asf_fq[MAX_NUM_DRR_WQ_IDX][*tc_filter_res];
			if (!asf_fq)
				return NULL;
			queue_lock(&(asf_fq->lock));
			asf_fq->ulEnqueuePkts++;
			queue_unlock(&(asf_fq->lock));
			return &asf_fq->egress_fq;
		}

	case ASF_QDISC_WRR:
		/* We can have at max 3 WRR Queues */
		if (prio > MAX_NUM_WRR_WQ_IDX)
			prio = MAX_NUM_WRR_WQ_IDX;
		asf_fq =  sch->asf_fq[prio][smp_processor_id()];
		asf_fq->ulEnqueuePkts++;
		return &asf_fq->egress_fq;

	default:
		asf_err("Invalid Qdisc Type %d\n", sch->qdisc_type);
	}

	return NULL;
}

int qos_enqueue_fd(ASFBuffer_t *abuf,
		struct  asf_qdisc *sch,
		ASF_uint8_t dscp,
		u32 *tc_filter_res)
{

	ASF_uint8_t prio = 7 - (dscp >> 5);
	struct	qman_fq	*tx_fq;
	struct qm_fd *tx_fd;

	tx_fq = qos_get_fq(1, (void *)abuf, prio, sch, tc_filter_res);
	if (!tx_fq) {
		asf_debug("FQ not found!, Dropping FD\n");

		if (unlikely(abuf->frag_list))
			ASF_SKB_FREE_FUNC(abuf->nativeBuffer);
		else
			dpa_fd_release(abuf->ndev,
				(struct qm_fd *)abuf->pAnnot->fd);
		return ASF_SUCCESS;
	}

	tx_fd  = (struct qm_fd *)&(abuf->pAnnot->reserved[1]);
	asf_debug("Enqueuing in fqid %d\n", tx_fq->fqid);

	if (unlikely(qman_enqueue(tx_fq, tx_fd, 0) < 0)) {
		struct asf_qos_fq *asf_fq;

		asf_fq = (struct asf_qos_fq *) tx_fq;
		if (sch->qdisc_type == ASF_QDISC_DRR) {
			queue_lock(&(asf_fq->lock));
			asf_fq->ulDroppedPkts++;
			queue_unlock(&(asf_fq->lock));
		} else
			asf_fq->ulDroppedPkts++;

		return ASF_FAILURE;
	} else
		return ASF_SUCCESS;
}

int qos_enqueue_skb(struct sk_buff *skb,
			struct  asf_qdisc *sch,
			u32 *tc_filter_res)
{
	struct qm_fd		*tx_fd, fd;
	struct qman_fq		*tx_fq;
	struct dpa_priv_s	*priv;
	struct dpa_bp		*dpa_bp;
	struct dpa_percpu_priv_s *percpu_priv;
	struct sk_buff		**skbh;
	dma_addr_t		addr;
	enum dma_data_direction dma_dir = DMA_TO_DEVICE;
	bool	can_recycle = false;
	int	offset, extra_offset;

	priv = netdev_priv(skb->dev);
	percpu_priv = per_cpu_ptr(priv->percpu_priv, smp_processor_id());
	dpa_bp = priv->dpa_bp;

	/* In case, packet is recieved from Linux,
	   Head room may not be sufficient */
	if (skb_headroom(skb) < priv->tx_headroom) {
		struct sk_buff *skb_new;

		skb_new = skb_realloc_headroom(skb, priv->tx_headroom);
		if (unlikely(!skb_new)) {
			/* Increment Error Stat */
			asf_err("Headroom Allocation error.\n");
			ASFSkbFree(skb);
			return ASF_SUCCESS;
		}
		ASFSkbFree(skb);
		skb = skb_new;
	}

	/* TODO, if SKB is cloned & require SG support*/
	skb = skb_unshare(skb, GFP_ATOMIC);
	if (!skb)
		return ASF_SUCCESS;

	tx_fq = qos_get_fq(0, (void *)skb, skb->queue_mapping, sch, tc_filter_res);
	if (!tx_fq) {
		asf_debug("TX FQ not found\n");
		ASFSkbFree(skb);
		return ASF_SUCCESS;
	}
	asf_debug("Will enqueuing in fqid %d, prio = %d\n",
				tx_fq->fqid, skb->queue_mapping);

	tx_fd = &fd;
	/* Clear Required field in FD */
	tx_fd->opaque_addr = 0;
	tx_fd->opaque = 0;
	tx_fd->cmd = 0;
#define RECYCLE_EXTRA_SIZE	256
/* Maximum offset value for a contig or sg FD (represented on 9bits) */
#define MAX_FD_OFFSET	((1 << 9) - 1)
	/* Now Convert SKB to Tx_FD */
	if (likely(skb_is_recycleable(skb, dpa_bp->size) &&
		   (skb_end_pointer(skb) - skb->head <=
				dpa_bp->size + RECYCLE_EXTRA_SIZE) &&
		   (*percpu_priv->dpa_bp_count < dpa_bp->target_count))) {
		/* Compute the minimum necessary fd offset */
		offset = dpa_bp->size - skb->len - skb_tailroom(skb);

		/*
		 * And make sure the offset is no lower than DPA_BP_HEAD,
		 * as required by FMan
		 */
		offset = max(offset, (int)priv->tx_headroom);

		/*
		 * We also need to align the buffer address to 16, such that
		 * Fman will be able to reuse it on Rx.
		 */
		extra_offset = (unsigned long)(skb->data - offset) & 0xF;
		if (likely((offset + extra_offset) <= skb_headroom(skb) &&
			   (offset + extra_offset) <= MAX_FD_OFFSET)) {
			/* We're good to go for recycling*/
			offset += extra_offset;
			can_recycle = true;
		}
	}
	if (can_recycle) {
		/* Buffer will get recycled, setup fd accordingly */
		tx_fd->cmd = FM_FD_CMD_FCO;
		tx_fd->bpid = dpa_bp->bpid;
		dma_dir = DMA_BIDIRECTIONAL;
	} else {
		offset = priv->tx_headroom;
	}

	skbh = (struct sk_buff **)(skb->data - offset);
	*skbh = skb;

	tx_fd->format = qm_fd_contig;
	tx_fd->length20 = skb->len;
	tx_fd->offset = offset;

	/* TODO Does Linux will use DPAA HW Checksum */
	if (!priv->mac_dev || skb->ip_summed != CHECKSUM_PARTIAL) {
		/* Reaching Here means HW Checksum offloading not required.
		   We are not implementing this as linux packet
		   don't use this feature but still putting this
		   check to catch if any packet comes */
	} else
		asf_err("HW CHECKSUM Offload handling required..!\n");

	addr = dma_map_single(dpa_bp->dev, skbh, dpa_bp->size, dma_dir);
	if (unlikely(addr == 0)) {
		struct asf_qos_fq *asf_fq;

		asf_fq = (struct asf_qos_fq *) tx_fq;
		if (sch->qdisc_type == ASF_QDISC_DRR) {
			queue_lock(&(asf_fq->lock));
			asf_fq->ulDroppedPkts++;
			queue_unlock(&(asf_fq->lock));
		} else
			asf_fq->ulDroppedPkts++;

		(*percpu_priv->dpa_bp_count)--;
		ASFSkbFree(skb);
		asf_debug("xmit dma_map Error\n");

		return ASF_FAILURE;
	}

	tx_fd->addr_hi = upper_32_bits(addr);
	tx_fd->addr_lo = lower_32_bits(addr);

	if (can_recycle) {
		/* Recycle SKB */
		(*percpu_priv->dpa_bp_count)++;
		skb_recycle(skb);
		skb = NULL;
		percpu_priv->tx_returned++;
	}
	if (unlikely(qman_enqueue(tx_fq, tx_fd, 0) < 0)) {
		struct asf_qos_fq *asf_fq;

		asf_fq = (struct asf_qos_fq *) tx_fq;
		if (sch->qdisc_type == ASF_QDISC_DRR) {
			queue_lock(&(asf_fq->lock));
			asf_fq->ulDroppedPkts++;
			queue_unlock(&(asf_fq->lock));
		} else
			asf_fq->ulDroppedPkts++;

		if (tx_fd->cmd & FM_FD_CMD_FCO) {
			(*percpu_priv->dpa_bp_count)--;
			percpu_priv->tx_returned--;
		}
		if (skb)
			ASFSkbFree(skb);
	}

	return ASF_SUCCESS;
}


static int qos_create_sch(ASF_uint32_t  ulVsgId,
			ASFQOSCreateQdisc_t *qdisc)
{
	struct  asf_qdisc *root;
	int	err, i;

	if (qdisc->dev->asf_qdisc) {
		asf_err("Root Qdisc already exists on dev %s\n",
						qdisc->dev->name);
		return ASFQOS_FAILURE;
	}

	if (qdisc_cnt  >= ASF_MAX_IFACES) {
		asf_err("NO more Qdisc supported: limit[%d] reached\n",
							ASF_MAX_IFACES);
		return ASFQOS_FAILURE;
	}
	/* Now allocate Root Qdisc  */
	root = (struct asf_qdisc *)
		kzalloc(sizeof(struct  asf_qdisc), GFP_KERNEL);
	if (NULL == root) {
		asf_err("OHHHH   NO Memory for Root Qdisc\n");
		return ASFQOS_FAILURE;
	}
	/* fill up the structure data */
	root->enqueue = qos_enqueue_skb;
	root->enqueue_fd = qos_enqueue_fd;
	root->qdisc_type = qdisc->qdisc_type;
	root->handle = qdisc->handle;
	root->parent = qdisc->parent;
	root->state = SCH_READY;
	root->dev = qdisc->dev;

	switch (qdisc->qdisc_type) {
	case ASF_QDISC_PRIO:
	{
		/* Create & initialize Tx FQs for QoS */
		err = prio_alloc_fqs(root);
		if (err) {
			qdisc_cleanup_fqs(root);
			kfree(root);
			return ASFQOS_FAILURE;
		}

	}
	break;
	case ASF_QDISC_DRR:
	break;
	case ASF_QDISC_WRR:
	{
		/* Create & initialize Tx FQs for QoS */
		err = wrr_alloc_fqs(root, qdisc);
		if (err) {
			qdisc_cleanup_fqs(root);
			kfree(root);
			return ASFQOS_FAILURE;
		}

	}
	break;
	default:
		asf_err("OHHHH, INVALID Scheduler Qdisc Type\n");
		kfree(root);
		return ASFQOS_FAILURE;
	}

	/* Telling net_device to use this root qdisc */
	root->dev->asf_qdisc = root;

	for (i = 0; i < ASF_MAX_IFACES; i++) {
		if (qdisc_in_use[i] == NULL) {
			spin_lock(&cnt_lock);
			qdisc_in_use[i] = root;
			qdisc_cnt++;
			spin_unlock(&cnt_lock);
			break;
		}
	}
	asf_debug("CPU [%d]:ASF QDISC[%d][%s]: handle = 0x%X\n\n",
			smp_processor_id(), qdisc->qdisc_type,
			qdisc->dev->name, qdisc->handle);

	return 0;
}
static int qos_flush_qdisc(ASF_uint32_t  ulVsgId,
			ASFQOSDeleteQdisc_t *qdisc)
{
	struct  asf_qdisc *root;
	uint32_t	i;
	int	bLockFlag;

	root = qdisc->dev->asf_qdisc;
	if (!root) {
		asf_err("Qdisc not exists.\n");
		return ASFQOS_FAILURE;
	}

	ASF_RCU_READ_LOCK(bLockFlag);
	switch (root->qdisc_type) {
	case ASF_QDISC_PRIO:
	case ASF_QDISC_DRR:
	case ASF_QDISC_WRR:
	{
		qdisc_cleanup_fqs(root);
		root->dev->asf_qdisc = NULL;
		kfree(root);
	}
	break;
	case ASF_QDISC_TBF:
	{
		root->dev->asf_qdisc = NULL;
	}
	break;
	default:
		asf_err("Ohh.., Unsupported Parent Qdisc\n");
	}

	for (i = 0; i < ASF_MAX_IFACES; i++) {
		if (qdisc_in_use[i] == root) {
			spin_lock(&cnt_lock);
			qdisc_in_use[i] = NULL;
			qdisc_cnt--;
			spin_unlock(&cnt_lock);
			asf_debug("Deleted Qdisc at index %d, qdisc_cnt %d\n",
					i, qdisc_cnt);
			break;
		}
	}

	kfree(root);
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return ASFQOS_SUCCESS;
}


ASF_uint32_t ASFQOSRuntime(
			ASF_uint32_t  ulVsgId,
			ASF_uint32_t  cmd,
			ASF_void_t    *args)
{
	int iResult = ASFQOS_FAILURE;

	asf_debug("vsg %u cmd (%u)\n", ulVsgId, cmd);

	/* invalid mode - avoid creation of Caches */
	if (!ASFGetStatus()) {
		asf_debug("ASF is DISABLED\n");
		return ASFQOS_FAILURE;
	}

	switch (cmd) {
	case ASF_QOS_CREATE_QDISC:
	{
		ASFQOSCreateQdisc_t *qdisc;

		qdisc = (ASFQOSCreateQdisc_t *)args;
		iResult = qos_create_sch(ulVsgId, qdisc);
	}
	break;

	case ASF_QOS_FLUSH:
	{
		ASFQOSDeleteQdisc_t *qdisc;

		qdisc = (ASFQOSDeleteQdisc_t *)args;
		asf_debug("Flushing all QDISC on %s\n", qdisc->dev->name);

		iResult = qos_flush_qdisc(ulVsgId, qdisc);

	}
	break;

	case ASF_QOS_ADD_QDISC:
	{
		ASFQOSCreateQdisc_t *qdisc;

		qdisc = (ASFQOSCreateQdisc_t *)args;
		switch (qdisc->qdisc_type) {
		case ASF_QDISC_TBF:
		{
			asf_debug("Creating TBF QDISC\n");
			iResult = qos_add_shaper(ulVsgId, qdisc);
		}
		break;
		case ASF_QDISC_DRR:
		{
			struct  asf_qdisc *root;

			root = qdisc->dev->asf_qdisc;

			if (qdisc->parent != root->handle) {
				asf_err("INVALID Parent[0x%X] for class[0x%X]\n",
						qdisc->parent, qdisc->handle);
				return ASFQOS_FAILURE;
			}
			/* Create & initialize Tx FQ for each DRR class */
			iResult = drr_alloc_fq(root, qdisc);
			if (iResult) {
				qdisc_cleanup_fqs(root);
				kfree(root);
				return ASFQOS_FAILURE;
			}
		}
		break;
		default:
			asf_err("INVALID QDISC ADD CMD\n");
		}
	}
	break;

	case ASF_QOS_DELETE_QDISC:
	{
		ASFQOSDeleteQdisc_t *qdisc;

		qdisc = (ASFQOSDeleteQdisc_t *)args;
		switch (qdisc->qdisc_type) {
		case ASF_QDISC_TBF:
			asf_debug("Deleting TBF QDISC\n");
			iResult = qos_del_shaper(ulVsgId, qdisc);
		break;

		default:
			asf_err("INVALID QDISC DELETE CMD\n");
		}

	}
	break;

	default:
		return ASFQOS_FAILURE;
	}

	return iResult;
}
EXPORT_SYMBOL(ASFQOSRuntime);


ASF_void_t ASFQOSRegisterCallbackFns(ASFQOSCallbackFns_t *pFnList)
{
	qosCbFns.pFnInterfaceNotFound = pFnList->pFnInterfaceNotFound;
	qosCbFns.pFnQdiscNotFound = pFnList->pFnQdiscNotFound;
	qosCbFns.pFnRuntime = pFnList->pFnRuntime;
	asf_print("Registered AS QoS response cbk 0x%p\n", qosCbFns.pFnRuntime);
}
EXPORT_SYMBOL(ASFQOSRegisterCallbackFns);

ASF_int32_t ASFQOSQueryConfig(ASF_uint32_t ulVsgId,
				ASFQOSQueryConfig_t *p)
{
	struct  asf_qdisc	*qdisc;
	struct asf_qos_fq	*asf_fq;
	u32			i;

	if (!p->dev) {
		asf_err("Invalid Device pointer\n");
		return ASFQOS_FAILURE;
	}
	qdisc = p->dev->asf_qdisc;
	if (!qdisc) {
		asf_err("Root Qdisc doesn't exist on dev %s\n",
						p->dev->name);
		return ASFQOS_FAILURE;
	}

	p->sch_type = qdisc->qdisc_type;
	p->handle = qdisc->handle;

	switch (qdisc->qdisc_type) {
	case ASF_QDISC_PRIO:
	break;

	case ASF_QDISC_DRR:
	{
		for (i = 0; i < NUM_FQ_PER_WQ; i++) {
			asf_fq =  qdisc->asf_fq[MAX_NUM_DRR_WQ_IDX][i];
			if (asf_fq)
				p->quantum[i] = asf_fq->quantum;
			else
				p->quantum[i] = 0;
		}
	}
	break;
	case ASF_QDISC_WRR:
	{
		for (i = 0; i < DPA_MAX_WRR_QUEUES; i++) {
			/* Read only one FQ quantum for each WQ */
			asf_fq =  qdisc->asf_fq[i][0];
			p->quantum[i] = asf_fq->quantum;
		}
	}
	break;
	default:
		asf_err("OHHHH, INVALID Scheduler Qdisc Type\n");
		return ASFQOS_FAILURE;
	}

	for (i = 0; i < ASF_MAX_IFACES; i++) {
		if (shaper[i].dev == p->dev) {
			p->pShaper_rate = shaper[i].rate;
			p->b_port_shaper = 1;

			return ASF_SUCCESS;
		}
	}
	p->b_port_shaper = 0;

	return ASFQOS_SUCCESS;
}
EXPORT_SYMBOL(ASFQOSQueryConfig);

/* NEW API END */

static int process_lnx_pkt(struct sk_buff *skb)
{
	u32	tc_filter_res = 1;
	struct net_device *dev = skb->dev;

	/* Checkthat Xmit function pointer is not null */
	if (dev->netdev_ops->ndo_start_xmit == NULL)
		return ASF_FAILURE;
	/* If recevied DUMMY L2-blob packet, do not handle it */
	if (asfctrl_skb_is_dummy(skb))
		return ASF_FAILURE;

	if (skb->queue_mapping == 0) {
		/* Check if Callback to set skb Queue Mapping */
		if (pSkbMarkfn)
			skb->queue_mapping = pSkbMarkfn((void *)skb);
		else
			skb->queue_mapping = non_asf_priority;
	}
	asf_debug("Queue Mapping = %d\n", skb->queue_mapping);
	/* Apply QoS */
	asf_qos_handling(skb, &tc_filter_res);
	return ASF_SUCCESS;
}

/*
 * Initialization
 */
static int __init asf_qos_init(void)
{
	/* Verify & update the module parameters */
	if (non_asf_priority > 7 || non_asf_priority < 0) {
		asf_err("Invalid Priority: Range: "
			"0-7, where '0' is the Highest Priority\n");
		return -1;
	}
	/* Register Linux QoS Hook for receiving the packets */
	asf_qos_fn_register(&process_lnx_pkt);
	/* Init SYS Interface */
	asfqos_sysfs_init();

	spin_lock_init(&cnt_lock);
	asf_debug("ASF_QOS: Initalized: non_asf_priority [%d]\n",
						non_asf_priority);
	return 0;
}

static void __exit asf_qos_exit(void)
{
	int i;
	struct asf_qdisc *root;
	int bLockFlag;

	asf_qos_fn_register(NULL);
	asfqos_sysfs_exit();

	ASF_RCU_READ_LOCK(bLockFlag);
	for (i = 0; i < ASF_MAX_IFACES; i++) {
		root = qdisc_in_use[i];
		if (root) {
			qdisc_cleanup_fqs(root);
			kfree(root);
			root->dev->asf_qdisc = NULL;
		}
		if (shaper[i].dev)
			fm_port_del_rate_limit(shaper[i].txport);
	}
	ASF_RCU_READ_UNLOCK(bLockFlag);
}
module_init(asf_qos_init);
module_exit(asf_qos_exit);
