/**************************************************************************
 * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfqosapi.c
 *
 * Description: ASF Quality Of Service module
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
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfctrl/linux/ffp/asfctrl.h"
#include "asfqosapi.h"
#include "asfqos_pvt.h"


#define ASF_QOS_VERSION	"1.0.0"
#define ASF_QOS_DESC	"ASF Quality Of Service Component"
/** \brief	Driver's license
 *  \details	Dual BSD/GPL
 *  \ingroup	Linux_module
 */
MODULE_LICENSE("Dual BSD/GPL");
/** \brief	Module author
 *  \ingroup	Linux_module
 */
MODULE_AUTHOR("Freescale Semiconductor, Inc");
/** \brief	Module description
 *  \ingroup	Linux_module
 */
MODULE_DESCRIPTION(ASF_QOS_DESC);

int qos_budget = ASF_QOS_NAPI_WEIGHT;
int queue_len = SCH_QUEUE_LEN;
int non_asf_priority = NON_ASF_PRIO;
int shaping_level = ASF_SHAPE_AT_L1;
int layer_overhead;

module_param(shaping_level, int, 0644);
MODULE_PARM_DESC(shaping_level, "Define Shaping at Layer L1 or L2:\n"
				"\t\t\t1 = L1 Rate, 2 = L2 Rate,\n"
				"\t\t\t0 = To remove IPsec overhead,"
				" For Testing");
module_param(qos_budget, int, 0644);
MODULE_PARM_DESC(qos_budget, "QoS TX Budget");
module_param(queue_len, int, 0644);
MODULE_PARM_DESC(queue_len, "Queue Buffer Length (Number of packets)");
module_param(non_asf_priority, int, 0644);
MODULE_PARM_DESC(non_asf_priority, "Default Priority Level for"
		" NON-ASF Traffic\n\t\t\tRange: 0-7, where '0' is"
		" the Highest Priority");

char *asf_qos_version = ASF_QOS_VERSION;
struct asf_qdisc *qdisc_in_use[ASF_MAX_IFACES] = {NULL};
uint8_t qdisc_cnt;
spinlock_t cnt_lock;

static ASFQOSCallbackFns_t	qosCbFns = {0};
static int qos_flush_qdisc(ASF_uint32_t  ulVsgId,
			ASFQOSDeleteQdisc_t *qdisc);

static inline struct net_queue *qos_classify(struct sk_buff *skb,
						struct  asf_qdisc *sch,
						u32 *tc_filter_res)
{
	struct  asf_prio_sched_data *prio_priv =
		(struct  asf_prio_sched_data *)sch->priv;
	struct net_queue *queue;

	switch (sch->qdisc_type) {
	case ASF_QDISC_TBF:
		queue = &(prio_priv->q[0]);
		break;

	case ASF_QDISC_PRIO:
		queue = &(prio_priv->q[skb->queue_mapping]);
		break;

	case ASF_QDISC_PRIO_DRR:
	case ASF_QDISC_DRR:
	{
		switch (*tc_filter_res) {
		case TC_FILTER_RES_INVALID:
		{
			u32 classid, i;

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
			/* Convert classid to Queue index */
			for (i = 0; i < prio_priv->bands; i++) {
				queue = &(prio_priv->q[i]);
				if (queue->classid == classid) {
					*tc_filter_res = i;
					asf_debug("Matching class[0x%x] found"
							" at FQ %d\n", classid , i);
					break;
				}
			}
			if (i == prio_priv->bands) {
				asf_err("Matching Class[0x%X] not configured,"
					" should not happen!\n", classid);
				return NULL;
			}

		}
		break;
		default:
			queue = &(prio_priv->q[*tc_filter_res]);
		}
	}
	break;
	default:
		asf_err("Invalid Qdisc Type %d\n", sch->qdisc_type);
		return NULL;
	}
#ifndef ASF_HW_SCH
	/* Reset the SKB Queue mapping, which is already
	   set as per DSCP value */
	skb->queue_mapping = 0;
#endif
	queue->ulEnqueuePkts++;

	if (queue->queue_size > queue->max_queue_size) {
		queue->ulDroppedPkts++;
		return NULL;
	} else
		return	queue;

}


int qos_enqueue(struct sk_buff *skb,
		struct  asf_qdisc *sch,
		u32 *tc_filter_res)
{
	struct net_queue *queue;

	queue = qos_classify(skb, sch, tc_filter_res);
	if (NULL == queue) {

		asf_debug("QUEUE FULL:  skb->queue_mapping %d\n",
						skb->queue_mapping);
		/* Free the SKB in calling function */
		ASFSkbFree(skb);
		return -1;
	}

	skb->next = NULL;

	queue_lock(&(queue->lock));
	if (!queue->head) {
		queue->head = skb;
		queue->tail = skb;
	} else {
		queue->tail->next = skb;
		queue->tail = skb;
	}
	queue->queue_size++;
	queue_unlock(&(queue->lock));

	return 0;
}

static int prio_dequeue(struct asf_qdisc *sch, u32 *add_wait)
{
	struct asf_prio_sched_data *priv =
			(struct  asf_prio_sched_data *)sch->priv;
	struct net_queue *queue;
	struct sk_buff *skb = NULL;
	int i;
	struct netdev_queue *txq;
	struct net_device       *netdev;

	for (i = 0; i < priv->bands; i++) {

		queue = &(priv->q[i]);
		if (queue->head == NULL)
			continue;

		skb = queue->head;
#if 0/* Queue Shaper shall be added in next Release */
		/* If required, Shape the output traffic */
		if (queue->shaper) {
			u32 len = skb->len + layer_overhead;

			if (queue->shaper->toks >= len) {
				queue->shaper->toks -= len;
			} else {
				unsigned long c_j = jiffies;

				if (time_after(c_j, queue->shaper->l_j)) {

					uint32_t wait =
						queue->shaper->jiffies_to_wait;

					asf_debug("last_j %lu c_j %lu\n",
						queue->shaper->l_j, c_j);

					queue->shaper->toks +=
						queue->shaper->buffer ;
					if (queue->shaper->toks >
							queue->shaper->b_depth)
						queue->shaper->toks =
							queue->shaper->b_depth;

					queue->shaper->l_j = c_j + wait;
					/* See if we have Enough Tokens */
					if (queue->shaper->toks >= len) {
						queue->shaper->toks -= len;
					} else {

						if ((*add_wait == 0) ||
							(*add_wait > wait))
							*add_wait = wait + 1;

						/* Check Next Priority Queue */
						continue;
					}
				} else {
					unsigned long wait;

					wait = (unsigned long)queue->shaper->l_j
						- (unsigned long)c_j;

					if ((*add_wait == 0) ||
							(*add_wait > wait))
						*add_wait = wait + 1;

					/* Check Next Priority Queue */
					continue;
				}
			}
		}
#endif /* SHAPER */
#ifdef ASF_EGRESS_SHAPER
	/* If required, Shape the Port traffic */
	if (sch->pShaper) {
		struct asf_tbf_data *shaper = sch->pShaper;
		uint32_t len = skb->len + layer_overhead;

		if (shaper->toks >= len) {
			shaper->toks -= len;
		} else {
			unsigned long c_j = jiffies;
			if (time_after(c_j, shaper->l_j)) {

				uint32_t wait =
				shaper->jiffies_to_wait;

				asf_debug("last_j %lu c_j %lu\n",
						shaper->l_j, c_j);

				shaper->toks += shaper->buffer;
				if (shaper->toks >
						shaper->b_depth)
					shaper->toks =
						shaper->b_depth;

				shaper->l_j = c_j + wait;
				/* See if we have Enough Tokens */
				if (shaper->toks >= len) {
					shaper->toks -= len;
				} else {
					if ((*add_wait == 0) ||
							(*add_wait > wait))
						*add_wait = wait + 1;
						/* Can't send packet further */
						return 0;
					}
			} else {
				unsigned long wait;

				wait = (unsigned long)shaper->l_j
						- (unsigned long)c_j;

				if ((*add_wait == 0) || (*add_wait > wait))
						*add_wait = wait + 1;

				/* Can't send packet further */
				return 0;
			}
		}
	}
#endif /* SHAPER */
		queue_lock(&(queue->lock));
		queue->head = skb->next;
		queue->queue_size--;
		queue->ulDequeuePkts++;
		queue_unlock(&(queue->lock));
		txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
		netdev = skb->dev;
		if (unlikely(0 != asfDevHardXmit(skb->dev, skb))) {
			queue->ulTxErrorPkts++;
			ASFSkbFree(skb);
		} else
			netdev->trans_start = txq->trans_start = jiffies;
		return 1;
	} /* For Loop */

	return 0;
}



void qos_dequeue(struct  asf_qdisc *sch)
{
	if (sch->state != SCH_BUSY) {
		if (sch->state == SCH_TIMER_PENDING)
			del_timer(&sch->timer);

		if (napi_schedule_prep(&(sch->qos_napi))) {
			sch->state = SCH_BUSY;
			__napi_schedule(&(sch->qos_napi));
		}
	}
}



static void timer_handler(unsigned long data)
{
	struct asf_qdisc *sch = (struct asf_qdisc *)data;

	if (napi_schedule_prep(&(sch->qos_napi))) {
		sch->state = SCH_BUSY;
		__napi_schedule(&(sch->qos_napi));
	}
}

static int prio_tx_napi(struct napi_struct *napi, int budget)
{
	struct asf_qdisc *sch = (struct asf_qdisc *)napi->dev->asf_qdisc;
	unsigned long start_time = jiffies;
	unsigned int i = 0;
	u32 add_wait = 0;

	while (prio_dequeue(sch, &add_wait)) {
		i++;

		/* Note: In future , may need to check for
		   need_resched() too. No need appear for now */
		if (i >= budget || jiffies != start_time)
			break;

		add_wait = 0;
	}

	napi_complete(napi);
	if (add_wait || (i == budget)) {
		/* TODO can we use schedule() , for explicit Pre-emption ? */
		asf_debug("PKT_LEFT: processed %d : start_time %lu : NEXT %u\n",
						i, start_time, add_wait);
		mod_timer(&sch->timer, (jiffies + add_wait));
		sch->state = SCH_TIMER_PENDING;
		return 1;
	}

	sch->state = SCH_READY;
	return 1;
}

static int prio_drr_dequeue(struct asf_qdisc *sch, u32 *add_wait)
{
	struct asf_prio_drr_sched_data *priv =
			(struct  asf_prio_drr_sched_data *)sch->priv;
	int i, any_q_has_pkt = 0;
	struct net_queue *queue;
	struct sk_buff *skb = NULL;
	struct netdev_queue *txq;
	struct net_device       *netdev;

	/* First look for packets in Priority Queues */
	for (i = 0; i < priv->num_prio_bands; i++) {

		queue = &(priv->q[i]);
		if (queue->head == NULL)
			continue;

		skb = queue->head;
		/* Packet found, check for shaping */
		goto shape;
	}
	/* Check If All Queues are priority based, i.e.
	   No DRR Queue exists */
	if (i == priv->bands)
		return 0;

	/* No packet in Priority Queues, Now Check
	   for the DRR Queues */
	i = priv->last_drr_inuse;
	while (1) {
		queue = &(priv->q[i]);
		if (queue->head == NULL)
			goto check_n_loop;

		skb = queue->head;
		if (skb->len > queue->deficit) {
			queue->deficit += queue->quantum;
			/* Indicate that packet is left */
			any_q_has_pkt = 1;
		} else {
			queue->deficit -= skb->len;
			priv->last_drr_inuse = i;
			/* Exit Loop & try to send the packet */
			break;
		}

check_n_loop:
		if (i == priv->max_drr_idx)
			i = priv->num_prio_bands;
		else
			i++;

		if (i == priv->last_drr_inuse)
			return any_q_has_pkt;
	} /* End of WHILE Loop */

shape:
#ifdef ASF_EGRESS_SHAPER
	/* If required, Shape the Port traffic */
	if (sch->pShaper) {
		struct asf_tbf_data *shaper = sch->pShaper;
		uint32_t len = skb->len + layer_overhead;

		if (shaper->toks >= len) {
			shaper->toks -= len;
		} else {
			unsigned long c_j = jiffies;
			if (time_after(c_j, shaper->l_j)) {

				uint32_t wait =
				shaper->jiffies_to_wait;

				asf_debug("last_j %lu c_j %lu\n",
						shaper->l_j, c_j);

				shaper->toks += shaper->buffer;
				if (shaper->toks >
						shaper->b_depth)
					shaper->toks =
						shaper->b_depth;

				shaper->l_j = c_j + wait;
				/* See if we have Enough Tokens */
				if (shaper->toks >= len) {
					shaper->toks -= len;
				} else {
					if ((*add_wait == 0) ||
							(*add_wait > wait))
						*add_wait = wait + 1;
						/* Can't send packet further */
						return 0;
					}
			} else {
				unsigned long wait;

				wait = (unsigned long)shaper->l_j
						- (unsigned long)c_j;

				if ((*add_wait == 0) || (*add_wait > wait))
						*add_wait = wait + 1;

				/* Can't send packet further */
				return 0;
			}
		}
	}
#endif /* SHAPER */

	queue_lock(&(queue->lock));
	queue->head = skb->next;
	queue->queue_size--;
	queue->ulDequeuePkts++;
	queue_unlock(&(queue->lock));
	txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
	netdev = skb->dev;
	if (unlikely(0 != asfDevHardXmit(skb->dev, skb))) {
		queue->ulTxErrorPkts++;
		ASFSkbFree(skb);
	} else
		netdev->trans_start = txq->trans_start = jiffies;
	return 1;
}


static int prio_drr_tx_napi(struct napi_struct *napi, int budget)
{
	struct asf_qdisc *sch = (struct asf_qdisc *)napi->dev->asf_qdisc;
	unsigned long start_time = jiffies;
	unsigned int i = 0;
	u32 add_wait = 0;

	while (prio_drr_dequeue(sch, &add_wait)) {
		i++;

		/* Note: In future , may need to check for
		   need_resched() too. No need appear for now */
		if (i >= budget || jiffies != start_time)
			break;

		add_wait = 0;
	}

	napi_complete(napi);
	if (add_wait || (i == budget)) {
		/* TODO can we use schedule() , for explicit Pre-emption ? */
		asf_debug("PKT_LEFT: processed %d : start_time %lu : NEXT %u\n",
						i, start_time, add_wait);
		mod_timer(&sch->timer, (jiffies + add_wait));
		sch->state = SCH_TIMER_PENDING;
		return 1;
	}

	sch->state = SCH_READY;
	return 1;
}


static int qos_create_sch(ASF_uint32_t  ulVsgId,
			ASFQOSCreateQdisc_t *qdisc)
{
	struct  asf_qdisc *prio_root, *root =
			qdisc->dev->asf_qdisc;
	int i, replace_qdisc = 0;

	if (root) {
		if ((qdisc->parent == ROOT_ID) ||
			(root->qdisc_type != ASF_QDISC_TBF)) {
			asf_err("Root Qdisc already exists on dev %s\n",
						qdisc->dev->name);
			return ASFQOS_FAILURE;
		} else
			replace_qdisc = 1;
	}
	if (qdisc_cnt  >= ASF_MAX_IFACES) {
		asf_err("NO more Qdisc supported: limit[%d] reached\n",
							ASF_MAX_IFACES);
		return ASFQOS_FAILURE;
	}
	/* Now allocate Root Qdisc  */
	prio_root = (struct asf_qdisc *)
		kzalloc(sizeof(struct  asf_qdisc), GFP_KERNEL);
	if (NULL == prio_root) {
		asf_err("OHHHH   NO Memory for Root Qdisc\n");
		return ASFQOS_FAILURE;
	}
	/* fill up the structure data */
	prio_root->enqueue = qos_enqueue;
	prio_root->dequeue = qos_dequeue;
	prio_root->qdisc_type = qdisc->qdisc_type;
	prio_root->handle = qdisc->handle;
	prio_root->parent = qdisc->parent;
	prio_root->state = SCH_READY;
	prio_root->dev = qdisc->dev;
	prio_root->pShaper = NULL;

	switch (qdisc->qdisc_type) {
	case ASF_QDISC_PRIO:
	{
		struct  asf_prio_sched_data *prio_priv;

		prio_priv = (struct  asf_prio_sched_data *)
				kzalloc(sizeof(struct  asf_prio_sched_data),
				GFP_KERNEL);
		if (NULL == prio_priv) {
			asf_err("OHHHH   NO Memory for PRIV\n");
			kfree(prio_root);
			return ASFQOS_FAILURE;
		}

		prio_priv->bands = qdisc->u.prio.bands;
		for (i = 0; i < ASF_PRIO_MAX; i++) {
			prio_priv->q[i].head = NULL;
			prio_priv->q[i].tail = NULL;
			prio_priv->q[i].queue_size = 0;
			prio_priv->q[i].max_queue_size = queue_len;
			prio_priv->q[i].shaper = NULL;


			spin_lock_init(&(prio_priv->q[i].lock));
		}
		prio_root->priv = prio_priv;

		/* Configure De-queue NAPI */
		netif_napi_add(qdisc->dev, &(prio_root->qos_napi),
					prio_tx_napi, qos_budget);
		napi_enable(&(prio_root->qos_napi));

		setup_timer(&prio_root->timer, timer_handler,
					(unsigned long)prio_root);
	}
	break;

	case ASF_QDISC_PRIO_DRR:
	case ASF_QDISC_DRR:
	{
		struct  asf_prio_drr_sched_data *prio_priv;

		prio_priv = (struct  asf_prio_drr_sched_data *)
				kzalloc(sizeof(struct  asf_prio_drr_sched_data),
				GFP_KERNEL);
		if (NULL == prio_priv) {
			asf_err("OHHHH   NO Memory for PRIV\n");
			kfree(prio_root);
			return ASFQOS_FAILURE;
		}

		prio_priv->bands = 0;
		for (i = 0; i < ASF_PRIO_MAX; i++) {
			prio_priv->q[i].head = NULL;
			prio_priv->q[i].tail = NULL;
			prio_priv->q[i].queue_size = 0;
			prio_priv->q[i].max_queue_size = queue_len;
			prio_priv->q[i].shaper = NULL;
			prio_priv->q[i].classid = 0;
			spin_lock_init(&(prio_priv->q[i].lock));
		}
		prio_root->priv = prio_priv;
		/* Configure De-queue NAPI */
		netif_napi_add(qdisc->dev, &(prio_root->qos_napi),
					prio_drr_tx_napi, qos_budget);
		napi_enable(&(prio_root->qos_napi));

		setup_timer(&prio_root->timer, timer_handler,
					(unsigned long)prio_root);
	}
	break;
	default:
		asf_err("OHHHH, INVALID Scheduler Qdisc Type\n");
		kfree(prio_root);
		return ASFQOS_FAILURE;
	}

	/* Telling net_device to use this root qdisc */
	if (replace_qdisc) {
		prio_root->pShaper = root->pShaper;
		del_timer(&(root->timer));
		/* NAPI */
		napi_disable(&(root->qos_napi));
		netif_napi_del(&(root->qos_napi));
	}
	prio_root->dev->asf_qdisc = prio_root;

	for (i = 0; i < ASF_MAX_IFACES; i++) {
		if (qdisc_in_use[i] == NULL) {
			spin_lock(&cnt_lock);
			qdisc_in_use[i] = prio_root;
			qdisc_cnt++;
			spin_unlock(&cnt_lock);
			break;
		}
	}
	asf_debug("CPU [%d]:ASF PRIO[%d][%s]: handle = 0x%X\n parent = 0x%X,"
			" bands = %d\n", smp_processor_id(), qdisc->qdisc_type,
			qdisc->dev->name, qdisc->handle,
			qdisc->parent, qdisc->u.prio.bands);

	return 0;
}

static int qos_add_shaper(ASF_uint32_t  ulVsgId,
			ASFQOSCreateQdisc_t *qdisc)
{
	struct  asf_qdisc	*root = NULL;
	struct	asf_tbf_data	*shaper;
	uint32_t		i;

	if (qdisc->parent == ROOT_ID) {
		struct  asf_prio_sched_data *tbf_priv;
		/* Create Shaper Qdisc */
		root = (struct asf_qdisc *)
			kzalloc(sizeof(struct  asf_qdisc), GFP_KERNEL);
		if (NULL == root) {
			asf_err("Ohhh...NO Memory for Root Qdisc\n");
			return ASFQOS_FAILURE;
		}
		/* fill up the structure data */
		root->enqueue = qos_enqueue;
		root->dequeue = qos_dequeue;
		root->qdisc_type = qdisc->qdisc_type;
		root->handle = qdisc->handle;
		root->parent = qdisc->parent;
		root->state = SCH_READY; /* Not Ready to use */
		root->dev = qdisc->dev;
		root->pShaper = NULL;

		tbf_priv = (struct  asf_prio_sched_data *)
				kzalloc(sizeof(struct  asf_prio_sched_data),
				GFP_KERNEL);
		if (NULL == tbf_priv) {
			asf_err("OHHHH   NO Memory for TBF PRIV\n");
			kfree(root);
			return ASFQOS_FAILURE;
		}

		tbf_priv->bands = 1;
		/* Using only 1 queue but must initialize all to
		avoid any run time issues */
		for (i = 0; i < ASF_PRIO_MAX; i++) {
			tbf_priv->q[i].head = NULL;
			tbf_priv->q[i].tail = NULL;
			tbf_priv->q[i].queue_size = 0;
			tbf_priv->q[i].max_queue_size = queue_len;
			tbf_priv->q[i].shaper = NULL;
			spin_lock_init(&(tbf_priv->q[i].lock));
		}
		root->priv = tbf_priv;
		/* Configure De-queue NAPI */
		netif_napi_add(qdisc->dev, &(root->qos_napi),
					prio_tx_napi, qos_budget);
		napi_enable(&(root->qos_napi));
		setup_timer(&root->timer, timer_handler,
					(unsigned long)root);
	} else {
		root = qdisc->dev->asf_qdisc;
		if (!root) {
			asf_err(" NO Parent Qdisc Exists on dev %s\n",
							qdisc->dev->name);
			return ASFQOS_FAILURE;
		}
	}

	asf_debug("Parent found with handle 0x%X " "on dev %s\n",
				root->handle, root->dev->name);

	/* Allocate Shaper instance */
	shaper = (struct asf_tbf_data *)
			kzalloc(sizeof(struct  asf_tbf_data), GFP_KERNEL);
	if (!shaper) {
		asf_err("OHHHH:  NO Memory!!\n");
		if (qdisc->parent == ROOT_ID)
			kfree(root);

		return ASFQOS_FAILURE;
	}
	/* RATE Per Jiffy */
	shaper->b_depth = qdisc->u.tbf.rate; /* in Bytes */
	shaper->buffer = qdisc->u.tbf.rate / HZ; /* in Bytes */

	asf_debug("MTU  %d \n", root->dev->mtu);
	/* Need to handle dynamic MTU change */
	if (shaper->buffer < root->dev->mtu) {
		int num;

		num = (root->dev->mtu/shaper->buffer - 1);
		if (num)
			shaper->buffer = root->dev->mtu;

		shaper->jiffies_to_wait = num;

	} else
		shaper->jiffies_to_wait = 0;

	shaper->toks = shaper->buffer; /* Intial tokens */
	shaper->l_j = jiffies;


	switch (root->qdisc_type) {
	case ASF_QDISC_TBF:
	{
		if (root->pShaper) {
			asf_err("Shaper already attached.\n");
			kfree(shaper);
			return ASFQOS_FAILURE;
		} else
			root->pShaper = shaper;
		/* This qdisc will be deleted when actual
		scheduler will be attched */
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
	}
	break;
	case ASF_QDISC_PRIO_DRR:
	case ASF_QDISC_DRR:
	case ASF_QDISC_PRIO:
	{
		struct  asf_prio_sched_data *priv;

		priv = (struct  asf_prio_sched_data *) root->priv;
		/* Find out the Queue, to which shaper need to apply */
		i = qdisc->parent & MINOR_ID;
		if (i > priv->bands) {
			asf_err(" Invalid Parent Qdisc on dev %s\n",
							qdisc->dev->name);
			kfree(shaper);
			return ASFQOS_FAILURE;
		}
		i--; /* Index value */

		if (priv->q[i].shaper) {
			asf_err("Shaper already attached to Queue %d\n", i);
			kfree(shaper);
			return ASFQOS_FAILURE;
		} else
			priv->q[i].shaper = shaper;

		asf_debug("TBF[%s]q[%d]: handle = 0x%X parent = 0x%X,\n",
			qdisc->dev->name, i, qdisc->handle, qdisc->parent);

	}
	break;
	default:
		asf_err("OHHHH, Unsupported Parent Qdisc\n");
		kfree(shaper);
		if (qdisc->parent == ROOT_ID)
			kfree(root);
		return ASFQOS_FAILURE;
	}

	asf_debug("IN: Rate[%d] Depth[%d]\n ",
		qdisc->u.tbf.rate * 8, shaper->b_depth);
	asf_debug("CAL: Toks[%d] \n\n ", shaper->toks);

	return 0;
}

static int qos_del_qdisc(ASF_uint32_t  ulVsgId,
			ASFQOSDeleteQdisc_t *qdisc)
{
	struct  asf_qdisc *root;
	uint32_t i;
	int	bLockFlag;

	root = qdisc->dev->asf_qdisc;
	if (!root) {
		asf_err("Qdisc not exists.\n");
		return ASFQOS_FAILURE;
	}

	if (qdisc->qdisc_type != ASF_QDISC_TBF) {
		asf_err("Unsupported Qdisc Delete Command.\n");
		return ASFQOS_SUCCESS;
	}
	ASF_RCU_READ_LOCK(bLockFlag);
	/* If root Qdisc is TBF then simply delete Shaper */
	if (root->qdisc_type == ASF_QDISC_TBF) {
		root->dev->asf_qdisc = NULL;
		kfree(root->priv);
		del_timer(&(root->timer));
		/* NAPI */
		napi_disable(&(root->qos_napi));
		netif_napi_del(&(root->qos_napi));

		if (root->pShaper)
			kfree(root->pShaper);
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
	} else {
		/* If Root is not TBF , it means we have
		configured any SCHEDULER over SHAPER */
		if (qdisc->parent != ROOT_ID) {
			/* Should be Queue Level Shaper */
			switch (root->qdisc_type) {
			case ASF_QDISC_PRIO:
			case ASF_QDISC_PRIO_DRR:
			case ASF_QDISC_DRR:
			{
				struct  asf_prio_sched_data *root_priv;
				/* Find out the Queue, to which shaper need to apply */
				i = qdisc->parent & MINOR_ID;
				i--; /* Index value */

				/* Deleting Per Queue Shaper */
				root_priv = root->priv;
				if (root_priv->q[i].shaper) {
					root_priv->q[i].shaper =  NULL;
					kfree(root_priv->q[i].shaper);
				}

			}
			break;
			default:
				asf_err("Ohh.., Unsupported Parent Qdisc\n");
			}

			ASF_RCU_READ_UNLOCK(bLockFlag);
			return ASFQOS_SUCCESS;
		}
		/* ELSE Request for Deleting Root TBF Shaper */
		/* Delete Inactive Shaper Qdisc */
		for (i = 0; i < ASF_MAX_IFACES; i++) {
			struct  asf_qdisc *x = qdisc_in_use[i];
			if (!x)
				continue;
			if ((x->handle == qdisc->handle) &&
					(x->dev == qdisc->dev)) {
				spin_lock(&cnt_lock);
				qdisc_in_use[i] = NULL;
				qdisc_cnt--;
				spin_unlock(&cnt_lock);
				asf_debug("Deleted Qdisc at index %d, qdisc_cnt %d\n",
					i, qdisc_cnt);
				kfree(x);
				break;
			}
		}
		/* Now delete Child Qdisc */
		qos_flush_qdisc(ulVsgId, qdisc);
	}
	ASF_RCU_READ_UNLOCK(bLockFlag);
	return ASFQOS_SUCCESS;
}



static int qos_flush_qdisc(ASF_uint32_t  ulVsgId,
			ASFQOSDeleteQdisc_t *qdisc)
{
	struct  asf_qdisc *root;
	int	i;
	int	bLockFlag;

	/* Root Qdisc  */
	root = qdisc->dev->asf_qdisc;
	if (!root) {
		asf_err("Qdisc not exists.\n");
		return ASFQOS_SUCCESS;
	}

	ASF_RCU_READ_LOCK(bLockFlag);

	qdisc->dev->asf_qdisc = NULL;

	/* Destroying Shaper */
	switch (root->qdisc_type) {
	case ASF_QDISC_PRIO_DRR:
	case ASF_QDISC_DRR:
	case ASF_QDISC_PRIO:
	{
		struct  asf_prio_sched_data *root_priv;

		root_priv = root->priv;
		for (i = 0; i < ASF_PRIO_MAX; i++) {
			if (root_priv->q[i].shaper)
				kfree(root_priv->q[i].shaper);
		}

	}
	break;
	default:
		asf_err("Ohh.., Unsupported Parent Qdisc\n");
	}

	kfree(root->priv);
	del_timer(&(root->timer));
	/* NAPI */
	napi_disable(&(root->qos_napi));
	netif_napi_del(&(root->qos_napi));

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
	/* IF Port Shaper exists, Set it as Root Qdisc */
	for (i = 0; i < ASF_MAX_IFACES; i++) {
		struct  asf_qdisc *x = qdisc_in_use[i];
		if (x && (x->dev == qdisc->dev)) {
			/* Configure De-queue NAPI */
			netif_napi_add(x->dev, &(x->qos_napi),
					prio_tx_napi, qos_budget);
			napi_enable(&(x->qos_napi));

			setup_timer(&x->timer, timer_handler,
					(unsigned long)x);
			qdisc->dev->asf_qdisc = x;
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

	asf_debug("vsg %u cmd (%u) \n",
			ulVsgId, cmd);

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
			asf_debug("Creating TBF QDISC\n");
			iResult = qos_add_shaper(ulVsgId, qdisc);
		break;
		case ASF_QDISC_DRR:
		case ASF_QDISC_PRIO_DRR:
		{
			struct  asf_qdisc *root;
			struct  asf_prio_drr_sched_data *drr_priv;
			int	i;

			root = qdisc->dev->asf_qdisc;

			if (qdisc->parent != root->handle) {
				asf_err("INVALID Parent[0x%X] for class[0x%X]\n",
						qdisc->parent, qdisc->handle);
				return ASFQOS_FAILURE;
			}
			/* initialize Tx Queus for each DRR class */
			drr_priv =
				(struct  asf_prio_drr_sched_data *)root->priv;

			if ((drr_priv->bands + 1) > ASF_PRIO_MAX) {
				asf_err("AT MAX [%d] DRR Classes allowed\n",
								ASF_PRIO_MAX);
				return ASFQOS_FAILURE;
			}
			i = drr_priv->bands;
			drr_priv->q[i].quantum = qdisc->u.drr.quantum;
			drr_priv->q[i].deficit = drr_priv->q[i].quantum;
			drr_priv->q[i].classid = qdisc->handle;
			if (drr_priv->q[i].quantum == 0) {
				if ((i > 0) &&
					(drr_priv->q[i - 1].quantum != 0)) {
					asf_err("ERROR: All PRIO Queues"
						" must be contiguous\n");
					return ASFQOS_FAILURE;
				}
				drr_priv->num_prio_bands++;
			}

			asf_debug("CPU [%d]:ASF PRIO-DRR: Q[%d] quantum =%d\n",
					smp_processor_id(), i,
					drr_priv->q[i].quantum);
			drr_priv->max_drr_idx = drr_priv->bands;
			/* First DRR Queue index = Max Prio Queue idx + 1 =
						num of prio queues */
			drr_priv->last_drr_inuse = drr_priv->num_prio_bands;
			drr_priv->bands++;

			asf_debug("ASF PRIO_bands[%d] DRR_bands: [%d]\n",
					drr_priv->num_prio_bands,
					drr_priv->bands);
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
		asf_debug("Deleting QDISC on %s\n", qdisc->dev->name);
		iResult = qos_del_qdisc(ulVsgId, qdisc);
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

ASF_int32_t ASFQOSQueryQueueStats(ASF_uint32_t ulVsgId,
				ASFQOSQueryStatsInfo_t *p)
{
	struct  asf_qdisc	*qdisc;
	struct net_queue	*q;
	u32			i, num_queue;

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

	switch (qdisc->qdisc_type) {
	case ASF_QDISC_PRIO:
	{
		struct  asf_prio_sched_data *prio_priv;

		prio_priv = qdisc->priv;
		q = &prio_priv->q[0];
		num_queue = prio_priv->bands;
	}
	break;
	case ASF_QDISC_PRIO_DRR:
	case ASF_QDISC_DRR:
	{
		struct  asf_prio_drr_sched_data *prio_drr_priv;

		prio_drr_priv = qdisc->priv;
		q = &prio_drr_priv->q[0];
		num_queue = prio_drr_priv->bands;

	}
	break;
	default:
		asf_err("OHHHH, INVALID Scheduler Qdisc Type\n");
		return ASFQOS_FAILURE;
	}

	for (i = 0; i < num_queue; i++) {
		if (p->b_reset) {
			queue_lock(&(q[i].lock));
			q[i].ulEnqueuePkts = 0;
			q[i].ulDroppedPkts = 0;
			q[i].ulDequeuePkts = 0;
			q[i].ulTxErrorPkts = 0;
			queue_unlock(&(q[i].lock));
		} else {
			p->stats[i].ulEnqueuePkts = q[i].ulEnqueuePkts;
			p->stats[i].ulDroppedPkts = q[i].ulDroppedPkts;
			p->stats[i].ulDequeuePkts = q[i].ulDequeuePkts;
			p->stats[i].ulTxErrorPkts = q[i].ulTxErrorPkts;
		}
	}

	return ASFQOS_SUCCESS;
}
EXPORT_SYMBOL(ASFQOSQueryQueueStats);

ASF_int32_t ASFQOSQueryConfig(ASF_uint32_t ulVsgId,
				ASFQOSQueryConfig_t *p)
{
	struct  asf_qdisc	*qdisc;
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
	p->queue_max_size = queue_len;

	switch (qdisc->qdisc_type) {
	case ASF_QDISC_PRIO:
	{
		struct  asf_prio_sched_data *priv;

		priv = qdisc->priv;
		p->bands = priv->bands;
		p->b_port_shaper = 0;
		for (i = 0; i < priv->bands; i++) {
			if (priv->q[i].shaper) {
				p->b_queue_shaper[i] = 1;
				p->qShaper_rate[i] =
					priv->q[i].shaper->b_depth * 8;
			} else
				p->b_queue_shaper[i] = 0;
		}
	}
	break;
	case ASF_QDISC_PRIO_DRR:
	case ASF_QDISC_DRR:
	{
		struct  asf_prio_drr_sched_data *priv;

		priv = qdisc->priv;
		p->bands = priv->bands;
		for (i = 0; i < priv->bands; i++) {
			p->quantum[i] = priv->q[i].quantum;
			if (priv->q[i].shaper) {
				p->b_queue_shaper[i] = 1;
				p->qShaper_rate[i] =
					priv->q[i].shaper->b_depth * 8;
			} else
				p->b_queue_shaper[i] = 0;
		}

	}
	break;
	default:
		asf_err("OHHHH, INVALID Scheduler Qdisc Type\n");
		return ASFQOS_FAILURE;

	}
	if (qdisc->pShaper) {
		p->b_port_shaper = 1;
		p->pShaper_rate = qdisc->pShaper->b_depth * 8;
	} else
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

	/* Check if Callback to set skb Queue Mapping */
	if (pSkbMarkfn)
		skb->queue_mapping = pSkbMarkfn((void *)skb);
	else
		/* Use the initialization value */
		skb->queue_mapping = non_asf_priority;

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
	/* Adjust Shaping Level */
	if (shaping_level == 1)
		layer_overhead = 24;	/* 20 byte(L1) + 4 byte FCS (L2) */
	else if (shaping_level == 2)
		layer_overhead = 4;	/* 4 byte FCS (L2) */
	else if (shaping_level == 0) {
		layer_overhead = -26;
		asf_err("L1 Rate w/o IPSEC Overhead"
				 "---> for testing ONLY\n");
	} else {
		asf_err("Invalid Shaping Level: %d\n", shaping_level);
		return -1;
	}

	/* Register Linux QoS Hook for receiving the packets */
	asf_qos_fn_register(&process_lnx_pkt);
	/* Init SYS Interface */
	asfqos_sysfs_init();

	spin_lock_init(&cnt_lock);
	asf_debug("ASF_QOS: qos_budget %d, queue_len %d, shape Level: %d, \n",
					qos_budget, queue_len, shaping_level);
	return 0;
}

static void __exit asf_qos_exit(void)
{
	int i, j;
	struct asf_qdisc *root;
	int bLockFlag;

	asf_qos_fn_register(NULL);
	asfqos_sysfs_exit();

	ASF_RCU_READ_LOCK(bLockFlag);
	for (i = 0; i < ASF_MAX_IFACES; i++) {
		root = qdisc_in_use[i];
		if (root) {
			root->dev->asf_qdisc = NULL;
			/* NAPI */
			napi_disable(&(root->qos_napi));
			netif_napi_del(&(root->qos_napi));
			/* TImer */
			del_timer(&(root->timer));

			switch (root->qdisc_type) {
			case ASF_QDISC_PRIO_DRR:
			case ASF_QDISC_PRIO:
			case ASF_QDISC_DRR:
			{
				struct  asf_prio_sched_data *root_priv;

				root_priv = root->priv;
				for (j = 0; j < ASF_PRIO_MAX; j++) {
					if (root_priv->q[j].shaper)
						kfree(root_priv->q[j].shaper);
				}

			}
			break;
			case ASF_QDISC_TBF:
			break;
			default:
				asf_warn("Ohh.., Unsupported Parent Qdisc\n");
			}

			if (root->pShaper)
				kfree(root->pShaper);

			kfree(root->priv);
			kfree(root);
		}
	}
	ASF_RCU_READ_UNLOCK(bLockFlag);
}
module_init(asf_qos_init);
module_exit(asf_qos_exit);
