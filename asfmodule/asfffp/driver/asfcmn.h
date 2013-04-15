/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfcmn.h
 *
 * Description: Common Debugging, Flow, interface related functions
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#ifndef __ASF_CMN_H
#define __ASF_CMN_H

#define PERIODIC_ERRMSGS { \
       "misconfig: HW UDP checksum disabled", \
       "misconfig: HW TCP checksum disabled", \
       "misconfig: ASF FW present, but callbacks not registered", \
       "misconfig: encrypted pkt, IPsec present, callbacks not registered", \
       "error: no headroom for L2 header", \
       "error: no headroom for annotation after reassembly", \
       "info: anti-replay REPLAY", \
       "info: anti-replay LATE", \
       "SEC error", \
       "warning: duplicate flow push - ignored", \
       "misconfig: invalid errnum to PERIODIC_ERRMSGS" }

#define PERR_HWUDP_CKSUM       0
#define PERR_HWTCP_CKSUM       1
#define PERR_NO_FW             2
#define PERR_NO_IPSEC          3
#define PERR_NO_L2_HDROOM      4
#define PERR_REASM_NO_HDROOM   5
#define PERR_REPLAY_ERROR      6
#define PERR_LATE_ERROR                7
#define PERR_SEC_ERROR         8
#define PERR_DUP_FLOW_PUSH     9
#define MAX_PERIODIC_ERRS      10

extern char *periodic_errmsg[];

#define asf_err(fmt, arg...)  \
	printk(KERN_ERR"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
	__LINE__, __func__, ##arg)

#define asf_dperr(fmt, arg...) do { \
	if (net_ratelimit()) \
		printk(KERN_ERR"[CPU %d ln %d fn %s] - " fmt,\
		smp_processor_id(), __LINE__, __func__, ##arg); \
	} while (0)

#ifdef ASF_DEBUG
#define asf_warn(fmt, arg...)  \
	printk(KERN_WARNING"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
	__LINE__, __func__, ##arg)

#define asf_print(fmt, arg...) \
	printk(KERN_INFO"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
	__LINE__, __func__, ##arg)

#define asf_debug(fmt, arg...)  \
	printk(KERN_INFO"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
	__LINE__, __func__, ##arg)
#define asf_trace	asf_debug(" trace\n")
#define asf_fentry	asf_debug(" ENTRY\n")
#define asf_fexit	asf_debug(" EXIT\n")
#else
#define asf_warn(fmt, arg...)
#define asf_print(fmt, arg...)
#define asf_debug(fmt, arg...)
#define asf_trace	asf_debug(" trace\n")
#define asf_fentry	asf_debug(" ENTRY\n")
#define asf_fexit	asf_debug(" EXIT\n")
#endif

#ifdef ASF_DEBUG_L2
#define asf_debug_l2	asf_debug
#else
#define asf_debug_l2(fmt, arg...)
#endif

#define isprint(c)      ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || \
		(c >= '0' && c <= '9'))

static inline void hexdump(const unsigned char *buf, unsigned short len)
{
	char str[80], octet[10];
	int ofs, i, l;

	for (ofs = 0; ofs < len; ofs += 16) {
		sprintf(str, "%03x ", ofs);

		for (i = 0; i < 16; i++) {
			if ((i + ofs) < len)
				sprintf(octet, "%02x ", buf[ofs + i]);
			else
				strcpy(octet, "   ");

			strcat(str, octet);
		}
		strcat(str, "  ");
		l = strlen(str);

		for (i = 0; (i < 16) && ((i + ofs) < len); i++)
			str[l++] = isprint(buf[ofs + i]) ? buf[ofs + i] : '.';

		str[l] = '\0';
		printk(KERN_INFO "%s\n", str);
	}
}


/* Initialization Parameters */
#define ASF_FFP_BLOB_TMR_ID	(0)
#define ASF_REASM_TMR_ID 	(1)
#define ASF_FFP_INAC_REFRESH_TMR_ID	(2)
#define ASF_SECFP_BLOB_TMR_ID   (3)
#define ASF_FWD_BLOB_TMR_ID	(4)
#define ASF_FWD_EXPIRY_TMR_ID	(5)
#define ASF_TERM_BLOB_TMR_ID	(6)
#define ASF_TERM_EXPIRY_TMR_ID	(7)

#define ASF_NUM_OF_TIMERS (ASF_TERM_EXPIRY_TMR_ID + 1)

/* ASF Proc interface */
#define CTL_ASF 9999
#define ASF_FWD 1
/* Need for IPSEC too */

/* common buffer alloc and free functions */
#define ASFKernelSkbAlloc	alloc_skb
#define ASFSkbAlloc	alloc_skb

#define ASFKernelSkbFree(freeArg) kfree_skb((struct sk_buff *)freeArg)
#ifdef ASF_TERM_FP_SUPPORT
#ifdef CONFIG_DPA
#define ASFSkbFree(freeArg) \
{\
	asf_dec_skb_buf_count((struct sk_buff *)freeArg);\
	if (((struct sk_buff *)freeArg)->mapped) \
		packet_kfree_skb((struct sk_buff *)freeArg);\
	else\
		kfree_skb((struct sk_buff *)freeArg);\
}
#else /*CONFIG_DPA*/
#define ASFSkbFree(freeArg) \
{\
	if (((struct sk_buff *)freeArg)->mapped) \
		packet_kfree_skb((struct sk_buff *)freeArg);\
	else\
		kfree_skb((struct sk_buff *)freeArg);\
}
#endif
#else
#define ASFSkbFree(freeArg) kfree_skb((struct sk_buff *)freeArg)
#endif

#ifdef ASF_TERM_FP_SUPPORT
#define ASF_netif_receive_skb	pmal_netif_receive_skb
#else
#define ASF_netif_receive_skb	netif_receive_skb
#endif

#define ASF_gfar_kfree_skb	ASFSkbFree

static inline void asf_skb_free_func(void *obj)
{
#ifdef CONFIG_DPA
	asf_dec_skb_buf_count((struct sk_buff *)obj);
#endif
#ifdef ASF_TERM_FP_SUPPORT
	if (((struct sk_buff *)obj)->mapped)
		packet_kfree_skb((struct sk_buff *)obj);
	else
#endif
	dev_kfree_skb_any((struct sk_buff *)obj);
}
#define ASF_SKB_FREE_FUNC	asf_skb_free_func

#define ASF_MF_OFFSET_FLAG_NET_ORDER  __constant_htons(IP_MF|IP_OFFSET)
#define ASF_MIN(a, b) (((a) < (b)) ? (a) : (b))
#define ASF_LAST_IN_TO_IDLE(LastIn) \
	(((jiffies > LastIn) ? (jiffies - LastIn) \
			: (((2^32) - 1) - (LastIn) + jiffies)) / HZ)

/*
 * consider moving spinlock in ffp_bucket_s to another independent structure
 * so that spinlock may not consume l2 cache as add/delete are not so frequent.
 */

#define ASF_VALIDATE_IP(ip) ((ip && ip < 0xE0000000) ? 0 : -1)

#define ASF_RCU_READ_LOCK(bLockFlag) do { \
		bLockFlag = in_softirq(); \
		if (bLockFlag) { \
			rcu_read_lock(); \
		} else { \
			rcu_read_lock_bh(); \
		} \
	} while (0)

#define ASF_RCU_READ_UNLOCK(bLockFlag) do { \
		if (bLockFlag) { \
			rcu_read_unlock(); \
		} else { \
			rcu_read_unlock_bh(); \
		} \
	} while (0)
struct _Defrag {
	bool	bIPv6;
	void	*iph;
	unsigned int	fraghdr_len;
	unsigned char	fraghdr_nexthdr;
};
struct ASFSkbCB {
	struct _Defrag Defrag;
};
#define	ASFCB(skb) ((struct ASFSkbCB *)((skb)->cb))
struct ASFNetDevEntry_s;

#define ASF_VLAN_ARY_LEN	(4096)
typedef struct ASFVlanDevArray_s {
	unsigned long	   ulNumVlans;
	struct ASFNetDevEntry_s *pArray[ASF_VLAN_ARY_LEN];
} ASFVlanDevArray_t;

#define ASF_INVALID_VSG		0xFFFFFFFF
#define ASF_INVALID_ZONE	0xFFFFFFFF

typedef struct ASFNetDevEntry_s {
	struct rcu_head	 rcu;
	 /* common interface id between AS and ASF */
	ASF_uint32_t	    ulCommonInterfaceId;
	ASF_uint32_t	    ulDevType;	/* type of interface */
	/* underlying device (valid for VLAN & PPPOE) */
	struct ASFNetDevEntry_s *pParentDev;
	/* bridge device pointer if this iface is attached to bridge */
	struct ASFNetDevEntry_s *pBridgeDev;

	ASF_uint32_t	    ulVSGId;
	ASF_uint32_t	    ulZoneId;	/* firewall security zone id */
	ASF_uint32_t	    ulMTU;

	/*
	 * Port Number (0 - eth0, 1 for eth1 etc) for DevType == ETHER
	 * VLAN ID for devType == VLAN
	 * PPPOE_SESSION_ID if DevType == PPPOE
	 * Unused if DevType == BRIDGE
	 */
	ASF_uint16_t	    usId;

	/*
	 * This points to first interface attached to the bridge if this
	 * DevType == BRIDGE Otherwise points to next interface attached
	 * to the parent bridge device.
	 */
	struct ASFNetDevEntry_s *pBrIfaceNext;

	/*
	 * This contains array of attached VLAN devices
	 */
	ASFVlanDevArray_t       *pVlanDevArray;

	/*
	 * This points to first VLAN interface based on this device
	 * if DevType == ETHER
	 * This points to next VLAN interface on the parent device
	 * if DevType == VLAN
	 */
	struct ASFNetDevEntry_s *pPPPoENext;

	struct net_device       *ndev; /* valid only for ETHER device */

} ASFNetDevEntry_t;

static inline void ASFInsertVlanDev(ASFNetDevEntry_t *pRealDev,
	ASF_uint16_t usVlanId, ASFNetDevEntry_t *pThisDev)
{
	pRealDev->pVlanDevArray->pArray[usVlanId] = pThisDev;
	pRealDev->pVlanDevArray->ulNumVlans++;
}

static inline void ASFRemoveVlanDev(ASFNetDevEntry_t *pRealDev,
	ASF_uint16_t usVlanId)
{
	pRealDev->pVlanDevArray->pArray[usVlanId] = NULL;
	pRealDev->pVlanDevArray->ulNumVlans--;
}

static inline ASFNetDevEntry_t *ASFGetVlanDev(ASFNetDevEntry_t *pRealDev,
	ASF_uint16_t usVlanId)
{
	return (pRealDev->pVlanDevArray) ?
		pRealDev->pVlanDevArray->pArray[usVlanId] : NULL;
}

static inline ASFNetDevEntry_t *ASFGetPPPoEDev(ASFNetDevEntry_t *pParentDev,
	ASF_uint16_t usSessId)
{
	ASFNetDevEntry_t	*pDev;

	pDev = pParentDev->pPPPoENext;
	while (pDev) {
		if (usSessId == pDev->usId)
			return pDev;
		pDev = pDev->pPPPoENext;
	}
	return NULL;
}

/* This function implementation is driven
   from function "inet_proto_csum_replace4()".
 */
#ifdef CONFIG_DPA
static inline void asf_proto_csum_replace4(__sum16 *sum,
					__be32 from,
					__be32 to)
{
	__be32 diff[] = { ~from, to };

	*sum = csum_fold(csum_partial(diff, sizeof(diff),
				~csum_unfold(*sum)));
}
#endif

/* Always use interface index as CII for ethernet interfaces */
#define asf_cii_set_cache(dev, cii) do {} while (0)
#define asf_cii_reset_cache(dev) do {} while (0)
#define asf_cii_cache(dev)   (dev->ifindex)

static inline void asfCopyWords(unsigned int *dst, unsigned int *src, int len)
{
	if (ETH_HLEN == len) {
		dst[0] = src[0];
		dst[1] = src[1];
		dst[2] = src[2];
		/* Copy last 2 bytes */
		dst[3] = (dst[3] & 0x0000FFFF) | (src[3] & 0xFFFF0000);
	} else {
		while (len >= sizeof(unsigned int)) {
			*dst = *src;
			dst++;
			src++;
			len -= sizeof(unsigned int);
		}
		if (len)
			memcpy(dst, src, len);
	}
}

#ifdef ASF_EGRESS_QOS
/* We are interested in DSCP precedence field */
/* Get Priority and Invert */
#define asf_set_queue_mapping(skb_p, val) \
				(skb_p->queue_mapping = 7 - (val >> 5))
#else

#ifdef CONFIG_DPA
	/* Every thing to TX queue '0' only */
	#define asf_set_queue_mapping(skb_p, val)	\
			(skb_p->queue_mapping = smp_processor_id())
#else
	/* Every thing to TX queue '0' only */
	#define asf_set_queue_mapping(skb_p, val) (skb_p->queue_mapping = 0)
#endif
#endif

#ifdef ASF_QOS
#ifdef CONFIG_DPA
struct asf_qos_fq {
	struct qman_fq		egress_fq;
	/* Related Device structure */
	struct net_device	*net_dev;
	/* Queue Statistics */
	uint32_t    ulEnqueuePkts;	/* Total number of packets received */
	uint32_t    ulDroppedPkts;	/* Total number of packets dropped
						due to Buffer overflow */
	uint32_t    quantum;		/* reuired for DRR/WRR weight */
	/** Others **/
	spinlock_t	lock;
};
#endif

struct  asf_qdisc {
	/*	 Frequently used	*/
	int			(*enqueue)(struct sk_buff *skb,
						struct  asf_qdisc *sch);
#ifdef CONFIG_DPA
	int			(*enqueue_fd)(struct qm_fd *tx_fd,
						struct  asf_qdisc *sch,
						ASF_uint8_t dscp);
	struct asf_qos_fq	*asf_fq[DPAA_ETH_TX_QUEUES][NR_CPUS];
#else
	void			(*dequeue)(struct  asf_qdisc *);
	void			*priv;  /* Private scheduler data will point
					   to “asf_prio_sched_data” */
	struct napi_struct	qos_napi;
	struct timer_list	timer;
#endif
	uint32_t		handle;
	uint32_t		parent; /* Parent ID */
	u8			state;
	struct net_device	*dev;
	uint8_t			qdisc_type;
};

inline void asf_qos_handling(struct sk_buff *);
#ifdef CONFIG_DPA
inline int asf_qos_fd_handling(struct qm_fd *fd,
				struct net_device *dev,
				ASF_uint8_t dscp
				);
#endif

#endif

#define UCHAR(x) ((unsigned char) (x))

#define BUFGET16(cp)	\
	(((u16)(*(u8 *)(cp)) << 8 & 0xFF00) | (*((u8 *)(cp) + 1) & 0xFF))

#define BUFPUT16(cp, val)				\
{							\
	*((u8 *) (cp)) = (u8) (val >> 8) & 0xFF;	\
	*((u8 *) (cp) + 1) = (u8) val & 0xFF;		\
}

#define BUFGET32(cp)		(*(unsigned int *) (cp))
#define BUFPUT32(cp, val) (*((unsigned int *) (cp)) = (unsigned int) (val))

extern ASFNetDevEntry_t *ASFCiiToNetDev(ASF_uint32_t ulCommonInterfaceId);
extern ASFNetDevEntry_t *ASFNetDev(struct net_device *dev);
extern ASFFFPVsgStats_t *get_asf_vsg_stats(void);
extern ASFFFPGlobalStats_t *get_asf_gstats(void);

#ifdef CONFIG_DPA
/*int asf_ffp_devfp_rx(struct sk_buff *skb, struct net_device *real_dev,
							unsigned int fqid);*/
int asf_ffp_devfp_rx(void *ptr, struct net_device *real_dev,
							unsigned int fqid);
ASF_void_t ASFFFPProcessAndSendFD(ASFNetDevEntry_t *anDev,
							ASFBuffer_t abuf);
ASF_void_t *asf_abuf_to_skb(ASFBuffer_t *pAbuf);
extern ASF_void_t asf_skb_to_abuf(ASFBuffer_t *pAbuf, ASFNetDevEntry_t *pNdev);
#else
int asf_ffp_devfp_rx(struct sk_buff *skb, struct net_device *real_dev);
#endif

extern struct sk_buff  *asfIpv4Defrag(unsigned int ulVSGId,
			       struct sk_buff *skb , bool *bFirstFragRcvd,
			       unsigned int *pReasmCb1, unsigned int *pReasmCb2,
			       unsigned int *fragCnt);
extern int asfIpv6MakeFragment(struct sk_buff *skb,
				struct sk_buff **pOutSkb);
extern int asfIpv6Fragment(struct sk_buff *skb,
	unsigned int ulMTU,
	struct net_device *dev,
	struct sk_buff **pOutSkb);


extern int asfIpv4Fragment(struct sk_buff *skb,
	unsigned int ulMTU, unsigned int ulDevXmitHdrLen,
	unsigned int bDoChecksum,
	struct net_device *dev,
	struct sk_buff **pOutSkb);

extern unsigned int asfReasmLinearize(struct sk_buff **pSkb,
	unsigned int ulTotalLen,
	unsigned int ulExtraLen,
	unsigned int ulHeadRoom);

extern unsigned int asf_ffp_check_vsg_mode(
	ASF_uint32_t ulVSGId,
	ASF_Modes_t mode);

extern int asfAdjustFragAndSendToStack(
	struct sk_buff *skb,
	ASFNetDevEntry_t *anDev);

extern int asf_process_ip_options(
	struct sk_buff *skb,
	struct net_device *dev,
	struct iphdr *iph);

extern  unsigned int asfReasmPullBuf(struct sk_buff *skb,
	unsigned int len,
	unsigned int *fragCnt);
#endif
