/**************************************************************************
 * Copyright 2015, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asficmpsend.c
 *
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/


#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <linux/version.h>
#include "asf.h"
#include "asfcmn.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfpvt.h"
#include "asftcp.h"

static __be16 asffp_IPv4_IDs[NR_CPUS];
static inline __be16 asf_getNextId(void)
{
	/* Stub : To be filled */
	return asffp_IPv4_IDs[smp_processor_id()]++;
}

static inline unsigned short ASFIpEac(unsigned int sum) /* Carries in high order 16 bits */{
	unsigned short csum;

	while ((csum = ((sum >> 16)&0xffffl)) != 0)
		sum = csum + (sum & 0xffffL);

	return (unsigned short) (sum & 0xffffl); /* Chops to 16 bits */
}

static unsigned short ASFascksum(unsigned short *pusData, unsigned short usLen)
{
	unsigned int sum = 0;
	unsigned short csum1, csum2;
	char *pSum;

	for (; usLen; usLen--)
		sum += *pusData++;

	csum1 = ASFIpEac(sum) & 0xffffl;

	pSum = (char *)&csum1;
	csum2 = csum1;

	BUFPUT16(pSum, csum2);
	return csum1;
}

static unsigned short ASFIPCkSum(char *data, unsigned short cnt)
{
	unsigned short cnt1;
	unsigned int sum = 0, csum;
	unsigned short csum1;
	char	*pUp;
	bool swap = ASF_FALSE;

	cnt1 = cnt;
	pUp = (char *)data;
	csum = csum1 = 0;

	if (((uintptr_t)pUp) & 1) {
	/* Handle odd leading byte */
		csum = ((unsigned short)UCHAR(*pUp++) << 8);
		cnt1--;
		swap = !swap;
	}

	if (cnt1 > 1) {
		csum1 = ASFascksum((unsigned short *)pUp, (cnt1 >> 1));
		if (swap)
			csum1 = (csum1 << 8) | (csum1 >> 8);
		csum += csum1;
	}

	if (cnt1 & 1) {
		if (swap)
			csum += UCHAR(pUp[--cnt1]);
		else
			csum += ((unsigned short)UCHAR(pUp[--cnt1]) << 8);
	}
	sum += csum;

	/* Do final end-around carry, complement and return */

	return (unsigned short)(~(ASFIpEac (sum)) & 0xffff);
}

int ASFSendIcmpErrMsg (unsigned char *pOrgData,
				unsigned char ucType,
				unsigned char ucCode,
				unsigned int ulUnused,
				unsigned int ulSNetId)
{
	unsigned char *pData;
	struct rtable *pRt = NULL;
	struct iphdr *iph;
	struct sk_buff *pSkb;
	unsigned char iplen;
	struct flowi fl = {};
	struct in_device *in_dev;
	struct dst_entry *dst;
	struct neighbour *neigh;

	pSkb = ASFKernelSkbAlloc(1024, GFP_ATOMIC);

	if (pSkb) {
		pSkb->data += 128; /* Reserve space to avoid reallocation */
		pSkb->data += ASF_IPLEN + ASF_ICMPLEN;
		iplen = ((*(unsigned char *)(pOrgData) & 0xf) << 2);
		memcpy(pSkb->data, pOrgData, iplen + 8);

		/* Fill Icmp Hdr */
		pSkb->data -= ASF_ICMPLEN;
		pData = pSkb->data;
		pData[0] = ucType;
		pData[1] = ucCode;
		pData[2] = 0;
		pData[3] = 0;
		BUFPUT32(&pData[4], ulUnused);
		BUFPUT16(&pData[2], ASFIPCkSum((char *)pSkb->data, iplen + 8 + ASF_ICMPLEN));
		pSkb->data -= ASF_IPLEN;
		skb_reset_network_header(pSkb);
		skb_set_transport_header(pSkb, ASF_IPLEN);

		iph = ip_hdr(pSkb);
		iph->version = 4;
		iph->ihl = 5;
		iph->check = 0;
		iph->ttl = 120;
		iph->id = asf_getNextId();
		iph->tos = 0;
		iph->frag_off = 0;

		iph->daddr = BUFGET32((unsigned char *)(pOrgData + 12));
		iph->protocol = IPPROTO_ICMP;
		pSkb->protocol = __constant_htons(ETH_P_IP);
		iph->tot_len = ASF_HTONS(ASF_IPLEN + ASF_ICMPLEN + iplen + 8);
		pSkb->len = ASF_HTONS(iph->tot_len);


	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		fl.fl4_dst =  iph->daddr;
		if (ip_route_output_key(&init_net, &pRt, &fl)) {
	#else
		fl.u.ip4.daddr = iph->daddr;
		pRt = ip_route_output_key(&init_net, &fl.u.ip4);
		if (IS_ERR(pRt)) {
	#endif

			ASFKernelSkbFree(pSkb);
			return 1;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
		skb_dst_set(pSkb, dst_clone(&(pRt->dst)));
#else
		skb_dst_set(pSkb, dst_clone(&pRt->u.dst));
#endif
		ip_rt_put(pRt);
		dst = skb_dst(pSkb);
		pSkb->dev = dst->dev;
		in_dev = (struct in_device *)(pSkb->dev->ip_ptr);
		if ((in_dev == NULL) || (in_dev->ifa_list == NULL)) {
			ASFKernelSkbFree(pSkb);
			return 1;
		}
		iph->saddr = ASF_HTONL(in_dev->ifa_list->ifa_local);
		BUFPUT16(&iph->check, ASFIPCkSum((char *)pSkb->data, ASF_IPLEN));

		neigh = dst_neigh_lookup_skb(dst, pSkb);
		if (neigh) {
			dst_neigh_output(dst, neigh, pSkb);
			rcu_read_unlock();
		} else
			ASFKernelSkbFree(pSkb);

	}
	return 0;
}
EXPORT_SYMBOL(ASFSendIcmpErrMsg);
