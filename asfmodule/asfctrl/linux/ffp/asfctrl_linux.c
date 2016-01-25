/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_linux.c
 *
 * Description: Control module for Configuring ASF and integrating it with
 * Linux Networking Stack
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/*
 * History
*  Version     Date         Author              Change Description
*  1.0        20/07/2010    Hemant Agrawal      Initial Development
*  1.1	      29/09/2010    Arun Pathak         Added the Firewall Code
*/
/***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <net/dst.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#ifdef CONFIG_DPA
#include <dpa/dpaa_eth.h>
#include <dpa/dpaa_eth_common.h>
#else
#include <gianfar.h>
#ifndef ASF_ARM
#include <asf_gianfar.h>
#endif
#endif
#include <net/neighbour.h>
#include <net/dst.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/route.h>
#include <net/sch_generic.h>
#ifdef ASF_IPV6_FP_SUPPORT
#include <net/ip6_route.h>
#endif
#ifdef ASFCTRL_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 33))
#include <8021q/vlan.h>
#endif
#include "../../../asfffp/driver/gplcode.h"
#include "../../../asfffp/driver/asfcmn.h"
#include "../../../asfffp/driver/asf.h"
#include "asfctrl.h"
#include <net/ipv6.h>


#define ASFCTRL_LINUX_VERSION		"0.0.1"
#define ASFCTRL_LINUX_DESC 		"ASF Linux Integration Driver"

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
MODULE_DESCRIPTION(ASFCTRL_LINUX_DESC);


/* Index is used as common interface ID */
struct net_device *p_asfctrl_netdev_cii[ASF_MAX_IFACES];

ASFCap_t  	g_cap;

uint32_t asfctrl_vsg_config_id[ASF_MAX_VSGS];
EXPORT_SYMBOL(asfctrl_vsg_config_id);

uint32_t asfctrl_vsg_l2blobconfig_id[ASF_MAX_VSGS];
EXPORT_SYMBOL(asfctrl_vsg_l2blobconfig_id);

#ifdef CONFIG_VLAN_8021Q
static inline struct net_device *
__vlan_get_real_dev(struct net_device *dev, u16 *vlan_id)
{
	if (vlan_id)
		*vlan_id = vlan_dev_priv(dev)->vlan_id;
		return vlan_dev_priv(dev)->real_dev;
}
#endif

#ifdef ASFCTRL_FWD_FP_SUPPORT
asfctrl_fwd_l2blob_update  fn_fwd_l2blob_update;
asfctrl_fwd_l3_route_flush_t  fn_fwd_l3_route_flush;
asfctrl_fwd_l3_route_add_t  fn_fwd_l3_route_add;


void asfctrl_register_fwd_func(asfctrl_fwd_l2blob_update  p_l2blob,
				asfctrl_fwd_l3_route_add_t route_add,
				asfctrl_fwd_l3_route_flush_t  route_flush)
{
	fn_fwd_l2blob_update = p_l2blob;
	fn_fwd_l3_route_flush = route_flush;
	fn_fwd_l3_route_add   = route_add;
}
EXPORT_SYMBOL(asfctrl_register_fwd_func);
#endif

#ifdef ASFCTRL_TERM_FP_SUPPORT
asfctrl_term_l2blob_update fn_term_l2blob_update;
asfctrl_term_cache_flush_t fn_term_cache_flush;

void asfctrl_register_term_func(asfctrl_term_l2blob_update p_l2blob,
				asfctrl_term_cache_flush_t cache_flush)
{
	fn_term_l2blob_update = p_l2blob;
	fn_term_cache_flush = cache_flush;
}
EXPORT_SYMBOL(asfctrl_register_term_func);
#endif

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
asfctrl_ipsec_get_flow_info fn_ipsec_get_flow4;
EXPORT_SYMBOL(fn_ipsec_get_flow4);
asfctrl_ipsec_l2blob_update fn_ipsec_l2blob_update;
asfctrl_ipsec_vsg_magicnum_update fn_ipsec_vsg_magic_update;
extern int asf_max_vsgs;
void asfctrl_register_ipsec_func(asfctrl_ipsec_get_flow_info   p_flow,
				asfctrl_ipsec_l2blob_update  p_l2blob,
				asfctrl_ipsec_vsg_magicnum_update p_vsgmagic)
{
	uint32_t vsg;
	ASFCTRL_FUNC_ENTRY;
	fn_ipsec_get_flow4 = p_flow;
	fn_ipsec_l2blob_update = p_l2blob;
	fn_ipsec_vsg_magic_update = p_vsgmagic;

	for (vsg = 0; vsg < asf_max_vsgs; vsg++)
		asfctrl_invalidate_vsg_sessions(vsg);
	ASFCTRL_FUNC_EXIT;
}
EXPORT_SYMBOL(asfctrl_register_ipsec_func);
#endif

ASF_void_t  asfctrl_invalidate_sessions(void)
{
	ASFFFPConfigIdentity_t cmd;
	int i;
	ASFCTRL_FUNC_ENTRY;
	for (i = 0; i < ASF_MAX_VSGS; i++) {
		asfctrl_vsg_config_id[i] += 1;
		memset(&cmd, 0, sizeof(cmd));
		cmd.ulConfigMagicNumber = asfctrl_vsg_config_id[i];
		ASFFFPUpdateConfigIdentity(i, cmd);
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_vsg_magic_update)
		fn_ipsec_vsg_magic_update(i);
#endif
		ASFCTRL_DBG("Exit:ulConfigMagicNumber =%d", asfctrl_vsg_config_id[i]);
	}
	ASFCTRL_FUNC_EXIT;
}
EXPORT_SYMBOL(asfctrl_invalidate_sessions);
ASF_void_t  asfctrl_invalidate_vsg_sessions(ASF_uint32_t ulVSGId)
{
	ASFFFPConfigIdentity_t cmd;
	ASFCTRL_FUNC_ENTRY;
	asfctrl_vsg_config_id[ulVSGId] += 1;
	memset(&cmd, 0, sizeof(cmd));
	cmd.ulConfigMagicNumber = asfctrl_vsg_config_id[ulVSGId];
	ASFFFPUpdateConfigIdentity(ulVSGId, cmd);

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_vsg_magic_update)
		fn_ipsec_vsg_magic_update(ulVSGId);
#endif
	ASFCTRL_DBG("Exit:ulConfigMagicNumber =%d",
		asfctrl_vsg_config_id[ulVSGId]);
	ASFCTRL_FUNC_EXIT;
}
EXPORT_SYMBOL(asfctrl_invalidate_vsg_sessions);

ASF_void_t  asfctrl_invalidate_l2blob(ASF_uint32_t ulVSGId)
{
	ASFFFPConfigIdentity_t cmd;
	ASFCTRL_FUNC_ENTRY;

	asfctrl_vsg_l2blobconfig_id[ulVSGId] += 1;
	memset(&cmd, 0, sizeof(cmd));
	cmd.l2blobConfig.ulL2blobMagicNumber =
		asfctrl_vsg_l2blobconfig_id[ulVSGId];
	cmd.bL2blobMagicNumber = 1;
	ASFFFPUpdateConfigIdentity(ulVSGId, cmd);

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_vsg_magic_update)
		fn_ipsec_vsg_magic_update(ulVSGId);
#endif
	ASFCTRL_DBG("Exit:ulL2blobMagic =%d",
		asfctrl_vsg_l2blobconfig_id[ulVSGId]);
}

#ifdef ASF_IPV6_FP_SUPPORT
ASF_void_t asfctrl_l3_ipv6_route_flush(void)
{
	ASFCTRL_FUNC_ENTRY;

	/* TODO: passing Default vsg but we need to get vsg
	for the route from kernel */
	asfctrl_invalidate_l2blob(ASF_DEF_VSG);

	ASFCTRL_FUNC_EXIT;
}
#endif
ASF_void_t asfctrl_l3_route_flush(void)
{
	ASFCTRL_FUNC_ENTRY;

	/* TODO: passing Default vsg but we need to get vsg
	for the route from kernel */
	asfctrl_invalidate_l2blob(ASF_DEF_VSG);

#ifdef ASFCTRL_FWD_FP_SUPPORT
	if (fn_fwd_l3_route_flush)
			fn_fwd_l3_route_flush();
#endif
	ASFCTRL_FUNC_EXIT;
}

int asf_ip_send(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct neighbour *neigh;
	int res;
	ASFCTRL_FUNC_ENTRY;
	rcu_read_lock();

	neigh = dst_neigh_lookup_skb(dst, skb);
	if (neigh) {
		res = dst_neigh_output(dst, neigh, skb);
		neigh_release(neigh);
		rcu_read_unlock();
		return res;
	}
	rcu_read_unlock();
	ASFCTRL_DBG(" Packet send failure");
	ASFCTRLKernelSkbFree(skb);

	ASFCTRL_FUNC_EXIT;
	return -EINVAL;
}
EXPORT_SYMBOL(asf_ip_send);

int asfctrl_dev_get_cii(struct net_device *dev)
{
	ASFCTRL_FUNC_ENTRY;

	if ((dev->ifindex < ASF_MAX_IFACES)
		&& (dev == p_asfctrl_netdev_cii[dev->ifindex])) {
			return dev->ifindex;
	} else {
		ASF_int32_t ii;
		/* avoid this and cache cii in netdev struct itself */
		for (ii = 0; ii < ASF_MAX_IFACES; ii++) {
			if (dev == p_asfctrl_netdev_cii[ii])
				return ii;
		}
	}
	ASFCTRL_FUNC_EXIT;
	return -1;
}
EXPORT_SYMBOL(asfctrl_dev_get_cii);

struct net_device *asfctrl_dev_get_dev(int cii)
{
	ASFCTRL_FUNC_ENTRY;

	if (cii > ASF_MAX_IFACES)
		return NULL;
	return p_asfctrl_netdev_cii[cii];
}
EXPORT_SYMBOL(asfctrl_dev_get_dev);

int asfctrl_dev_get_free_cii(struct net_device *dev)
{
	ASF_int32_t jj;
	ASFCTRL_FUNC_ENTRY;
	if (dev->ifindex < ASF_MAX_IFACES) {
		if (p_asfctrl_netdev_cii[dev->ifindex] == NULL)
			return dev->ifindex;
	}

	/* find a free index in reverse order */
	for (jj = ASF_MAX_IFACES-1; jj >= 0; jj--) {
		if (p_asfctrl_netdev_cii[jj] == NULL)
			return jj;
	}
	ASFCTRL_FUNC_EXIT;
	return -1;
}
EXPORT_SYMBOL(asfctrl_dev_get_free_cii);

ASF_uint32_t asfctrl_get_dev_vsgid(struct net_device *dev)
{
	/* TODO: Get proper VSG ID */
	return ASF_DEF_VSG;
}
ASF_int32_t asfctrl_create_dev_map(struct net_device *dev, ASF_int32_t bForce)
{
	ASF_int32_t cii;
	ASFInterfaceInfo_t  info;
#if defined CONFIG_VLAN_8021Q || defined CONFIG_PPPOE
	ASF_uint64_t relIds[2];
#endif
#ifdef CONFIG_VLAN_8021Q
	ASF_uint16_t usVlanId;
#endif
#ifdef CONFIG_PPPOE
	ASF_uint16_t usPPPoESessId;
#endif
	ASF_uint32_t ulVSGId;


	ASFCTRL_FUNC_ENTRY;
	cii = asfctrl_dev_get_cii(dev);
	if (cii >= 0) {
		if (!bForce) {
			ASFCTRL_DBG("Device %s is already mapped to cii %d\n",
				dev->name, cii);
			return T_FAILURE;
		}
		ASFCTRL_DBG("Dev %s is already mapped to cii %d" \
			"(forcing removal)\n", dev->name, cii);
		asfctrl_delete_dev_map(dev);
	}

	cii = asfctrl_dev_get_free_cii(dev);
	if (cii < 0) {
		ASFCTRL_DBG("Failed to allocate free cii for device %s\n",
			dev->name);
		return T_FAILURE;
	}
	dev->cii = cii;

	memset(&info, 0, sizeof(info));
	info.ulMTU = dev->mtu;

	/* Need to avoid WLAN device!!?? */
	if (dev->type == ARPHRD_ETHER) {
#ifdef CONFIG_VLAN_8021Q
		if (dev->priv_flags & IFF_802_1Q_VLAN) {
			struct net_device  *pdev;

			pdev = __vlan_get_real_dev(dev, &usVlanId);
			if (!pdev)
				return T_FAILURE;
			info.ulDevType = ASF_IFACE_TYPE_VLAN;
			relIds[0] = asfctrl_dev_get_cii(pdev);
			relIds[1] = dev;
			info.ucDevIdentifierInPkt = (ASF_uint8_t *)&usVlanId;
			info.ulDevIdentiferInPktLen = 2;
			info.ucDevIdentifierType = ASF_IFACE_DEV_IDENTIFIER;
			info.ulRelatedIDs = (ASF_uint64_t *)relIds;
			info.ulNumRelatedIDs = 1;
		} else {
#endif
		info.ulDevType = ASF_IFACE_TYPE_ETHER;
		info.ucDevIdentifierInPkt = (ASF_uint8_t *) dev->dev_addr;
		info.ulDevIdentiferInPktLen = dev->addr_len;
		info.ucDevIdentifierType = ASF_IFACE_MAC_IDENTIFIER;
		ASFCTRL_DBG("MAP interface %s (mac %pM) [%02x:%02x:%02x..]\n",
			dev->name, dev->dev_addr,
			dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2]);

#ifdef CONFIG_VLAN_8021Q
	}
#endif
#ifdef CONFIG_PPPOE
	} else if (dev->type == ARPHRD_PPP) {
		ASF_int32_t parent_cii;
		struct net_device  *pdev;

		pdev = ppp_get_parent_dev(dev, &usPPPoESessId);
		if (!pdev) {
			ASFCTRL_ERR("PPPoE %s parent device not found\n",
					dev->name);
			return T_FAILURE;
		}
		info.ulDevType = ASF_IFACE_TYPE_PPPOE;

		parent_cii = asfctrl_dev_get_cii(pdev);

		if (-1 == parent_cii) {
			ASFCTRL_ERR("PPPoE %s parent device not mapped\n",
					dev->name);
			return T_FAILURE;
		}

		relIds[0] = parent_cii;
		relIds[1] = (size_t) dev;
		info.ucDevIdentifierInPkt = (ASF_uint8_t *)&usPPPoESessId;
		info.ulDevIdentiferInPktLen = 2;
		info.ucDevIdentifierType = ASF_IFACE_DEV_IDENTIFIER;
		info.ulRelatedIDs = (ASF_uint64_t *)relIds;
		info.ulNumRelatedIDs = 1;
		ASFCTRL_DBG("PPPOE %s (parent %s) SESS_ID 0x%x mtu %d\n",
			dev->name, pdev->name, usPPPoESessId, dev->mtu);
#endif
	} else {
		ASFCTRL_DBG("Device %s type %u flags 0x%x is not supported!\n",
			dev->name, dev->type, dev->flags);
		return T_FAILURE;
	}

	if (ASFMapInterface(cii, &info) == ASF_SUCCESS) {
		dev_hold(dev);
		p_asfctrl_netdev_cii[cii] = dev;
	} else
		ASFCTRL_DBG("MAP interface %s with cii %d failed\n",
				dev->name, cii);

	ulVSGId = asfctrl_get_dev_vsgid(dev);
	ASFBindDeviceToVSG(ulVSGId, cii);
	ASFFFPBindInterfaceToZone(ulVSGId, cii, ASF_DEF_ZN_ID);

	ASFCTRL_FUNC_EXIT;
	return T_SUCCESS;
}
EXPORT_SYMBOL(asfctrl_create_dev_map);

ASF_int32_t asfctrl_delete_dev_map(struct net_device *dev)
{
	ASF_int32_t  cii;
	ASFCTRL_FUNC_ENTRY;
#ifdef CONFIG_PPPOE
	if ((dev->type == ARPHRD_ETHER) || (dev->type == ARPHRD_PPP)) {
#else
	if (dev->type == ARPHRD_ETHER) {
#endif
		cii = asfctrl_dev_get_cii(dev);
		if (cii < 0) {
			ASFCTRL_DBG("Failed to determine cii for device %s\n",
				dev->name);
			return T_FAILURE;
		}
		ASFCTRL_DBG("UNMAP interface %s\n",  dev->name);
		ASFUnMapInterface(cii);
		dev_put(dev);
		p_asfctrl_netdev_cii[cii] = NULL;
		return T_SUCCESS;
	}

	ASFCTRL_FUNC_EXIT;
	return T_FAILURE;
}
EXPORT_SYMBOL(asfctrl_delete_dev_map);

#if (ASFCTRL_DEBUG_LEVEL >= LOGS)
char *print_netevent(int event)
{
	switch (event) {
	case NETDEV_UP:
		return (char *)"NETDEV_UP";
	case NETDEV_DOWN:
		return (char *)"NETDEV_DOWN";
	case NETDEV_REBOOT:
		return (char *)"NETDEV_REBOOT";
	case NETDEV_CHANGE:
		return (char *)"NETDEV_CHANGE";
	case NETDEV_REGISTER:
		return (char *)"NETDEV_REGISTER";
	case NETDEV_UNREGISTER:
		return (char *)"NETDEV_UNREGISTER";
	case NETDEV_CHANGEMTU:
		return (char *)"NETDEV_CHANGEMTU";
	case NETDEV_CHANGEADDR:
		return (char *)"NETDEV_CHANGEADDR";
	case NETDEV_GOING_DOWN:
		return (char *)"NETDEV_GOING_DOWN";
	case NETDEV_CHANGENAME:
		return (char *)"NETDEV_CHANGENAME";
	case NETDEV_PRE_UP:
		return (char *)"NETDEV_PRE_UP";
	default:
		return (char *)"UNKNOWN";
	}
}
#endif

static int asfctrl_dev_notifier_fn(struct notifier_block *this,
				unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);
	ASF_uint32_t ulVSGId;

	ASFCTRL_FUNC_ENTRY;
	ASFCTRL_DBG("%s - event %ld (%s)\n",
			dev->name, event, print_netevent(event));

	/* handle only ethernet, vlan, bridge and pppoe (ppp) interfaces */
	switch (event) {
	case NETDEV_REGISTER: /* A  new device is allocated*/
		ASFCTRL_INFO("Register Device type %d mac %pM\n", dev->type,
			dev->dev_addr);
		if (dev->type == ARPHRD_ETHER)
			asfctrl_create_dev_map(dev, 1);
		break;

	case NETDEV_UNREGISTER:/* A new device is deallocated*/
		ASFCTRL_INFO("Unregister Device type %d mac %pM\n", dev->type,
			dev->dev_addr);
#ifdef CONFIG_PPPOE
		if (dev->type == ARPHRD_ETHER  || dev->type == ARPHRD_PPP)
#else
		if (dev->type == ARPHRD_ETHER)
#endif
			asfctrl_delete_dev_map(dev);
		break;

#ifdef CONFIG_PPPOE
	case NETDEV_UP:
		if (dev->type == ARPHRD_PPP)
			asfctrl_create_dev_map(dev, 1);
		break;
#endif
	case NETDEV_CHANGEMTU:
#ifdef CONFIG_PPPOE
		if ((dev->type == ARPHRD_ETHER) || (dev->type == ARPHRD_PPP)) {
#else
		if (dev->type == ARPHRD_ETHER) {
#endif
			if (asfctrl_dev_get_cii(dev) < 0) {
				ASFCTRL_WARN("Not offloaded device %s",
					dev->name);
				return NOTIFY_BAD;
			}
			ulVSGId = asfctrl_get_dev_vsgid(dev);
			asfctrl_invalidate_l2blob(ulVSGId);
		}
		break;
	}
	ASFCTRL_FUNC_EXIT;
	return NOTIFY_DONE;
}

int asfctrl_dev_fp_tx_hook(struct sk_buff *skb, struct net_device *dev)
{
	ASF_uint16_t	usEthType;
	ASF_int32_t		hh_len;
	ASF_boolean_t	bPPPoE = 0;
	struct iphdr       *iph = 0;
	struct ipv6hdr       *ipv6h;
	unsigned int proto;
	unsigned int  tun_hdr = 0;

	ASFCTRL_FUNC_ENTRY;

	if (!asfctrl_skb_is_dummy(skb))
		return AS_FP_PROCEED;

	asfctrl_skb_unmark_dummy(skb);

	if (dev->type != ARPHRD_ETHER)
		goto drop;


	usEthType = skb->protocol;
	hh_len = ETH_HLEN;

	if (usEthType == __constant_htons(ETH_P_8021Q)) {
		struct vlan_hdr *vhdr = (struct vlan_hdr *)(skb->data+hh_len);
		ASFCTRL_TRACE("8021Q packet");
		hh_len += VLAN_HLEN;
		usEthType = vhdr->h_vlan_encapsulated_proto;
	}

	if (usEthType == __constant_htons(ETH_P_PPP_SES)) {
		unsigned char *poe_hdr = skb->data+hh_len;
		unsigned short ppp_proto;

		ASFCTRL_TRACE("PPPoE packet");

		/*PPPoE header is of 6 bytes */
		ppp_proto = *(unsigned short *)(poe_hdr+6);
		/* PPPOE: VER=1,TYPE=1,CODE=0 and  PPP:_PROTO=0x0021 (IP) */
		if ((poe_hdr[0] != 0x11) || (poe_hdr[1] != 0) ||
			(ppp_proto != __constant_htons(0x0021))) {
				goto drop;
		}

		hh_len += (8); /* 6+2 -- pppoe+ppp headers */
		usEthType = __constant_htons(ETH_P_IP);
		bPPPoE = 1;
	}

	if (usEthType != __constant_htons(ETH_P_IP) &&
		usEthType != __constant_htons(ETH_P_IPV6))
		goto drop;

	if (usEthType == __constant_htons(ETH_P_IP)) {
		iph = (struct iphdr *)(skb->data+hh_len);
		proto = iph->protocol;
		if (proto == IPPROTO_IPV6) {
			ipv6h = (struct ipv6hdr *)(skb->data+hh_len+sizeof(struct iphdr));
			proto = ipv6h->nexthdr;
			tun_hdr = sizeof(struct iphdr);
		}
	} else {
		ipv6h = (struct ipv6hdr *)(skb->data+hh_len);
		proto = ipv6h->nexthdr;
		if (proto == IPPROTO_IPIP) {
			iph = (struct iphdr *)(skb->data+hh_len+sizeof(struct ipv6hdr));
			proto = iph->protocol;
			tun_hdr = sizeof(struct ipv6hdr);
		}
	}

	switch (proto) {
		asf_linux_L2blobPktData_t *pData;
		ASFFFPUpdateFlowParams_t  cmd;

	case ASFCTRL_IPPROTO_DUMMY_L2BLOB:

		/*
		* if the packet is coming on a PPP interface,
		* network header points to start of PPPOE header
		* instaed of IP header.
		*  So always dynamically identify start of IP header!
		*/

		memset(&cmd, 0, sizeof(cmd));
		cmd.u.l2blob.bUpdatePPPoELen = bPPPoE;


		ASFCTRL_INFO(
			"DUMMY_L2BLOB: %pM:%pM..%02x%02x (skb->proto 0x%04x) "
			"data 0x%p nw_hdr 0x%p tr_hdr 0x%p\n",
			skb->data, skb->data+6, skb->data[12], skb->data[13],
			skb->protocol, skb->data, skb_network_header(skb),
			skb_transport_header(skb));

		if (usEthType == __constant_htons(ETH_P_IP)) {
			pData = (asf_linux_L2blobPktData_t *)(skb->data+hh_len +
							(iph->ihl * 4) + (tun_hdr ? sizeof(struct ipv6hdr) : 0));
			cmd.u.l2blob.tunnel.bIP6IP4Out = tun_hdr ? 1 : 0;
		} else {
			pData = (asf_linux_L2blobPktData_t *)(skb->data+hh_len +
							sizeof(struct ipv6hdr) + (tun_hdr ? sizeof(struct iphdr) : 0));
			cmd.u.l2blob.tunnel.bIP4IP6Out = tun_hdr ? 1 : 0;
		}

		memcpy(&cmd.tuple, &pData->tuple, sizeof(cmd.tuple));
		cmd.ulZoneId = pData->ulZoneId;
		cmd.bL2blobUpdate = 1;
		cmd.u.l2blob.ulDeviceId = asfctrl_dev_get_cii(dev);
		cmd.u.l2blob.ulPathMTU = pData->ulPathMTU;

		cmd.u.l2blob.ulL2blobMagicNumber =
			asfctrl_vsg_l2blobconfig_id[pData->ulVsgId];

		/* need to include PPPOE+PPP header if any */
		cmd.u.l2blob.l2blobLen = hh_len + tun_hdr;

		memcpy(cmd.u.l2blob.l2blob, skb->data, cmd.u.l2blob.l2blobLen);
#ifdef CONFIG_VLAN_8021Q
		if (skb_vlan_tag_present(skb)) {
			cmd.u.l2blob.bTxVlan = 1;
			cmd.u.l2blob.usTxVlanId = (skb_vlan_tag_get(skb)
							| VLAN_TAG_PRESENT);
		} else
#endif
			cmd.u.l2blob.bTxVlan = 0;

		ASFFFPRuntime(pData->ulVsgId, ASF_FFP_MODIFY_FLOWS, &cmd,
			sizeof(cmd), NULL, 0);
		break;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	case ASFCTRL_IPPROTO_DUMMY_IPSEC_L2BLOB:
		ASFCTRL_INFO("DUMMY_IPSEC_L2BLOB");

		skb->protocol = usEthType;
		if (fn_ipsec_l2blob_update)
			fn_ipsec_l2blob_update(skb,
				hh_len, asfctrl_dev_get_cii(dev));

		break;
#endif

#ifdef ASFCTRL_FWD_FP_SUPPORT
	case ASFCTRL_IPPROTO_DUMMY_FWD_L2BLOB:
		ASFCTRL_INFO("DUMMY_FWD_L2BLOB");

		if (fn_fwd_l2blob_update)
			fn_fwd_l2blob_update(skb, hh_len,
				asfctrl_dev_get_cii(dev));

		break;
#endif
#ifdef ASFCTRL_TERM_FP_SUPPORT
	case ASFCTRL_IPPROTO_DUMMY_TERM_L2BLOB:
		ASFCTRL_INFO("DUMMY_TERM_L2BLOB");

		if (fn_term_l2blob_update)
			fn_term_l2blob_update(skb, hh_len,
				asfctrl_dev_get_cii(dev));

		break;
#endif
	}
drop:
	ASFCTRLKernelSkbFree(skb);
	ASFCTRL_FUNC_EXIT;
	return AS_FP_STOLEN;
}

static struct notifier_block asfctrl_dev_notifier = {
	.notifier_call = asfctrl_dev_notifier_fn,
};

ASF_void_t  asfctrl_fnInterfaceNotFound(
			ASFBuffer_t Buffer,
			genericFreeFn_t pFreeFn,
			ASF_void_t *freeArg)
{
	struct sk_buff  *skb;
	int bVal = in_softirq();

	ASFCTRL_FUNC_ENTRY;
	skb = AsfBuf2Skb(Buffer);

	if (!bVal)
		local_bh_disable();
	/* Send it to for normal path handling */
	ASFCTRL_netif_receive_skb(skb);

	if (!bVal)
		local_bh_enable();
	ASFCTRL_FUNC_EXIT;
}

ASF_void_t  asfctrl_fnVSGMappingNotFound(
			ASF_uint32_t ulCommonInterfaceId,
			ASFBuffer_t Buffer,
			genericFreeFn_t pFreeFn,
			ASF_void_t *freeArg)
{
	struct sk_buff  *skb;
	int bVal = in_softirq();

	ASFCTRL_FUNC_ENTRY;
	skb = AsfBuf2Skb(Buffer);

	if (!bVal)
		local_bh_disable();
	/* Send it to for normal path handling */
	ASFCTRL_netif_receive_skb(skb);

	if (!bVal)
		local_bh_enable();
	ASFCTRL_FUNC_EXIT;
}

static int process_ceetm_queue_dummy(struct sk_buff *skb)
{
	ASFCTRL_FUNC_ENTRY;
	/* If recevied DUMMY L2-blob packet, absorve it*/
	if (asfctrl_dev_fp_tx_hook(skb, skb->dev) == AS_FP_STOLEN)
		return 0;
	return 1;
}

static int __init asfctrl_init(void)
{
	ASFFFPConfigIdentity_t cmd;
	ASFFFPCallbackFns_t asfctrl_Cbs = {
		asfctrl_fnInterfaceNotFound,
		asfctrl_fnVSGMappingNotFound,
		asfctrl_fnZoneMappingNotFound,
		asfctrl_fnNoFlowFound,
		asfctrl_fnRuntime,
		asfctrl_fnFlowRefreshL2Blob,
		asfctrl_fnFlowActivityRefresh,
		asfctrl_fnFlowTcpSpecialPkts,
		asfctrl_fnFlowValidate,
		asfctrl_fnAuditLog
	};
	int i;

	ASFCTRL_FUNC_ENTRY;

	memset(p_asfctrl_netdev_cii, 0, sizeof(p_asfctrl_netdev_cii));

	ASFGetCapabilities(&g_cap);

	if (!g_cap.bBufferHomogenous) {
		ASFCTRL_ERR("ASF capabilities: Non homogenous buffer");
		return -1;
	}
	for (i = 0; i < ASF_MAX_VSGS; i++) {
		asfctrl_vsg_config_id[i] = jiffies;
		memset(&cmd, 0, sizeof(cmd));
		cmd.ulConfigMagicNumber = asfctrl_vsg_config_id[i];
		ASFFFPUpdateConfigIdentity(i, cmd);

		memset(&cmd, 0, sizeof(cmd));
		cmd.bL2blobMagicNumber = 1;
		cmd.l2blobConfig.ulL2blobMagicNumber =
			asfctrl_vsg_l2blobconfig_id[i];
		ASFFFPUpdateConfigIdentity(i, cmd);
	}

	ASFFFPRegisterCallbackFns(&asfctrl_Cbs);

	register_netdevice_notifier(&asfctrl_dev_notifier);
	devfp_register_hook(asf_ffp_devfp_rx, asfctrl_dev_fp_tx_hook);
	route_hook_fn_register(&asfctrl_l3_route_flush);
#ifdef ASF_IPV6_FP_SUPPORT
	ipv6_route_hook_fn_register(&asfctrl_l3_ipv6_route_flush);
#endif

#ifdef ASF_LINUX_QOS
	/* Register Linux QoS Hook for receiving the L2blob packets */
	asf_qos_fn_register(&process_ceetm_queue_dummy);
#endif

	asfctrl_sysfs_init();


	if (g_cap.mode & fwMode)
		asfctrl_linux_register_ffp();

	if (ASFGetStatus() == 0)
		ASFDeploy();

	ASFCTRL_INFO("ASF Control Module - Core Loaded.\n");
	ASFCTRL_FUNC_EXIT;
	return 0;
}

static void __exit asfctrl_exit(void)
{
	int ii;

	ASFCTRL_FUNC_ENTRY;

	if (g_cap.mode & fwMode)
		asfctrl_linux_unregister_ffp();

	asfctrl_sysfs_exit();

#ifdef ASF_LINUX_QOS
	asf_qos_fn_register(NULL);
#endif

	/* Unregister the hook*/
	route_hook_fn_register(NULL);
#ifdef ASF_IPV6_FP_SUPPORT
	ipv6_route_hook_fn_register(NULL);
#endif
	devfp_register_hook(NULL, NULL);
	unregister_netdevice_notifier(&asfctrl_dev_notifier);

	for (ii = 0; ii < ASF_MAX_IFACES; ii++) {
		if (p_asfctrl_netdev_cii[ii])
			asfctrl_delete_dev_map(p_asfctrl_netdev_cii[ii]);
	}

	ASFRemove();

	ASFCTRL_INFO("ASF Control Module - Core Unloaded \n");
	ASFCTRL_FUNC_EXIT;
}

module_init(asfctrl_init);
module_exit(asfctrl_exit);
