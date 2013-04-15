/**************************************************************************
 * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfqos_pvt.h
 *
 * Description: Header file for ASF QoS internel
 *		structure Definations.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/*
 * History
 *  Version     Date		Author			Change Description
 *  1.0		20 Jul 2012	Sachin Saxena
 *
 */
/****************************************************************************/

#ifndef __ASFQOS_PVT_H
#define __ASFQOS_PVT_H



/* Initilization Parameters */
#define		SCH_READY		0
#define		SCH_BUSY		1
#define		SCH_TIMER_PENDING	2
#define		SCH_QUEUE_LEN		100
#define		ASF_QOS_NAPI_WEIGHT	100
#define		ASF_SHAPE_AT_L1		1
#define		NON_ASF_PRIO		2

#ifdef CONFIG_SMP
#define queue_lock(x)		spin_lock(x)
#define queue_unlock(x)		spin_unlock(x)
#else
#define queue_lock(x)
#define queue_unlock(x)
#endif

struct asf_tbf_data {
/* Parameters */
	u32		b_depth;	/* Token bucket depth in Bytes*/
	u32		buffer;		/* Number to Tokens(Bytes) to fill
					at times MUST BE >= MTU*/
	u32		jiffies_to_wait; /* Waiting time to
						re-schedule NAPI */
/* Variables */
	u32		toks;		/* Current number of Bytes tokens */
	unsigned long	l_j;		/* Last Time check-point in Jiffies */
};

/* Scheduler queue profile */
struct net_queue {
	struct sk_buff			*head;
	struct sk_buff			*tail;
	/* Shaping Qualities */
	struct asf_tbf_data		*shaper;
	uint32_t			queue_size;	/* In bytes */
	uint32_t			max_queue_size; /* In bytes */
	uint32_t			deficit; /* DRR: Left Bytes */
	uint32_t			quantum; /* DRR: Total Weight
							in Bytes */
	/* Queue Statistics */
	uint32_t    ulEnqueuePkts;	/* Total number of packets received */
	uint32_t    ulDroppedPkts;	/* Total number of packets dropped
						due to Buffer overflow */
	uint32_t    ulDequeuePkts;	/* Total number of Dequeued packets */
	uint32_t    ulTxErrorPkts;	/* Total number of packets dropped
						due to TX Error */
	/** Others **/
	spinlock_t			lock;
};


struct  asf_prio_sched_data {
	uint32_t		bands; /* Number of Priority queues */
	struct net_queue	q[ASF_PRIO_MAX]; /* 8 priority FIFO queues */
};

struct  asf_prio_drr_sched_data {
	uint32_t		bands; /* Number of Scheduler queues */
	struct net_queue	q[ASF_PRIO_MAX]; /* Priority FIFO queues */
	/* Port Shaper */
	struct asf_tbf_data	*pShaper;
	/* Last DRR Queue in Use */
	uint8_t		last_drr_inuse;
	/* Index of last DRR Queue */
	uint8_t		max_drr_idx;
	/* Number of Priority queues */
	uint8_t		num_prio_bands;
};

extern int asf_qos_enable;
extern int asfqos_sysfs_init(void);
extern int asfqos_sysfs_exit(void);

#endif
