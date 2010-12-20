/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
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

#define asf_err(fmt, arg...)  \
	printk(KERN_ERR"[CPU %d ln %d fn %s] - " fmt, smp_processor_id(), \
	__LINE__, __func__, ##arg)

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
#define asf_trace 	asf_debug("-trace\n")
#define asf_fentry 	asf_debug("-ENTRY\n")
#define asf_fexit 	asf_debug("-EXIT\n")
#else
#define asf_warn(fmt, arg...)
#define asf_print(fmt, arg...)
#define asf_debug(fmt, arg...)
#define asf_trace 	asf_debug("-trace\n")
#define asf_fentry 	asf_debug("-ENTRY\n")
#define asf_fexit 	asf_debug("-EXIT\n")
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
#define ASF_INVALID_VSG	(~0)
#define ASF_INVALID_ZONE	(~0)

#define ASF_NUM_OF_TIMERS  6

#define ASF_FFP_BLOB_TMR_ID	(0)
#define ASF_REASM_TMR_ID 	(1)
#define ASF_FFP_INAC_REFRESH_TMR_ID	(2)
#define ASF_SECFP_BLOB_TMR_ID   (3)
#define ASF_FWD_BLOB_TMR_ID	(4)
#define ASF_FWD_EXPIRY_TMR_ID	(5)

/* ASF Proc interface */
#define CTL_ASF 9999
#define ASF_FWD 1
/* Need for IPSEC too */

/*tbd #define ASF_SKB_FREE_FUNC	gfar_kfree_skb*/
static inline void asf_skb_free_func(void *obj)
{
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


#if 0
#define ASF_CII_CACHE_VALID_BIT	(0x80000000)
static inline void asf_cii_set_cache(struct net_device *dev,
	ASF_uint32_t ulCommonInterfaceId)
{
	/* Cache common interface ID in net_device pointer for ETHER interfaces
	 * FIXME: avoid using atalk_ptr in net_device.
	 */
	dev->atalk_ptr =
		(void *) (ASF_CII_CACHE_VALID_BIT | ulCommonInterfaceId);
}

static inline void asf_cii_reset_cache(struct net_device *dev)
{
	dev->atalk_ptr = NULL;
}


static inline ASF_uint32_t asf_cii_cache(struct net_device *dev)
{
	if (((ASF_uint32_t)dev->atalk_ptr) & ASF_CII_CACHE_VALID_BIT)
		return (ASF_uint32_t)
			(dev->atalk_ptr) & (~ASF_CII_CACHE_VALID_BIT) ;
	return asf_max_ifaces;
}

#else
/* Always use interface index as CII for ethernet interfaces */
#define asf_cii_set_cache(dev, cii) do {} while (0)
#define asf_cii_reset_cache(dev) do {} while (0)
#define asf_cii_cache(dev)   (dev->ifindex)
#endif

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

extern ASFNetDevEntry_t *ASFCiiToNetDev(ASF_uint32_t ulCommonInterfaceId);
extern ASFNetDevEntry_t *ASFNetDev(struct net_device *dev);
extern ASFFFPVsgStats_t *get_asf_vsg_stats(void);
extern ASFFFPGlobalStats_t *get_asf_gstats(void);

extern struct sk_buff  *asfIpv4Defrag(unsigned int ulVSGId,
			       struct sk_buff *skb , bool *bFirstFragRcvd,
			       unsigned int *pReasmCb1, unsigned int *pReasmCb2,
			       unsigned int *fragCnt);

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
