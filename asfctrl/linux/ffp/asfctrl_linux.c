/* Copyright (C) 2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfctrl_linux.c
 *
 * Control module for Configuring ASF and integrating it with
 * Linux Networking Stack
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
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
/*  Revision History    : 1.1
*  Version     Date         Author              Change Description
*  1.0        20/07/2010    Hemant Agrawal      Initial Development
*  1.1	      29/09/2010    Arun Pathak         Added the Firewall Code
***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <net/dst.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <gianfar.h>
#include <net/dst.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/route.h>

#include "../../../asfffp/driver/asf.h"
#include "asfctrl.h"


#define ASFCTRL_LINUX_VERSION		"0.0.1"
#define ASFCTRL_LINUX_DESC 		"ASF Linux Integration Driver"

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
MODULE_DESCRIPTION(ASFCTRL_LINUX_DESC);


/* Index is used as common interface ID */
struct net_device *p_asfctrl_netdev_cii[ASFCTRL_MAX_IFACES];

ASFCap_t  	g_cap;

uint32_t asfctrl_vsg_config_id;
EXPORT_SYMBOL(asfctrl_vsg_config_id);

#ifdef ASFCTRL_FWD_FP_SUPPORT
asfctrl_fwd_l2blob_update  fn_fwd_l2blob_update;

void asfctrl_register_fwd_func(asfctrl_fwd_l2blob_update  p_l2blob)
{
	fn_fwd_l2blob_update = p_l2blob;
}
EXPORT_SYMBOL(asfctrl_register_fwd_func);
#endif

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
asfctrl_ipsec_get_flow_info   fn_ipsec_get_flow4;
asfctrl_ipsec_l2blob_update   fn_ipsec_l2blob_update;
asfctrl_ipsec_vsg_magicnum_update fn_ipsec_vsg_magic_update;
void asfctrl_register_ipsec_func(asfctrl_ipsec_get_flow_info   p_flow,
				asfctrl_ipsec_l2blob_update  p_l2blob,
				asfctrl_ipsec_vsg_magicnum_update p_vsgmagic)
{
	ASFCTRL_FUNC_ENTRY;
	fn_ipsec_get_flow4 = p_flow;
	fn_ipsec_l2blob_update = p_l2blob;
	fn_ipsec_vsg_magic_update = p_vsgmagic;
	ASFCTRL_FUNC_EXIT;
}
EXPORT_SYMBOL(asfctrl_register_ipsec_func);
#endif

ASF_void_t  asfctrl_invalidate_sessions(void)
{
	ASFFFPConfigIdentity_t cmd;
	ASFCTRL_FUNC_ENTRY;
	asfctrl_vsg_config_id += 1;
	cmd.ulConfigMagicNumber = asfctrl_vsg_config_id;
	ASFFFPUpdateConfigIdentity(ASF_DEF_VSG, cmd);

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_vsg_magic_update)
		fn_ipsec_vsg_magic_update();
#endif
	ASFCTRL_FUNC_EXIT;
}
EXPORT_SYMBOL(asfctrl_invalidate_sessions);

int asf_ip_send(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	ASFCTRL_FUNC_ENTRY;

	if (dst->hh)
		return neigh_hh_output(dst->hh, skb);
	else if (dst->neighbour)
		return dst->neighbour->output(skb);

	ASFCTRL_DBG(" Packet send failure");
	kfree_skb(skb);

	ASFCTRL_FUNC_EXIT;
	return -EINVAL;
}
EXPORT_SYMBOL(asf_ip_send);

int asfctrl_dev_get_cii(struct net_device *dev)
{
	ASFCTRL_FUNC_ENTRY;

	if ((dev->ifindex < ASFCTRL_MAX_IFACES)
		&& (dev == p_asfctrl_netdev_cii[dev->ifindex])) {
			return dev->ifindex;
	} else {
		T_INT32 ii;
		/* avoid this and cache cii in netdev struct itself */
		for (ii = 0; ii < ASFCTRL_MAX_IFACES; ii++) {
			if (dev == p_asfctrl_netdev_cii[ii])
				return ii;
		}
	}
	ASFCTRL_FUNC_EXIT;
	return -1;
}
EXPORT_SYMBOL(asfctrl_dev_get_cii);

int asfctrl_dev_get_free_cii(struct net_device *dev)
{
	T_INT32 jj;
	ASFCTRL_FUNC_ENTRY;
	if (dev->ifindex < ASFCTRL_MAX_IFACES) {
		if (p_asfctrl_netdev_cii[dev->ifindex] == NULL)
			return dev->ifindex;
	}

	/* find a free index in reverse order */
	for (jj = ASFCTRL_MAX_IFACES-1; jj >= 0; jj--) {
		if (p_asfctrl_netdev_cii[jj] == NULL)
			return jj;
	}
	ASFCTRL_FUNC_EXIT;
	return -1;
}
EXPORT_SYMBOL(asfctrl_dev_get_free_cii);

T_INT32 asfctrl_create_dev_map(struct net_device *dev, T_INT32 bForce)
{
	T_INT32 cii;
	ASFInterfaceInfo_t  info;

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

	memset(&info, 0, sizeof(info));
	info.ulMTU = dev->mtu;

	/* Need to avoid WLAN device!!?? */
	if (dev->type == ARPHRD_ETHER) {
#ifdef CONFIG_VLAN_8021Q
		if (dev->priv_flags & IFF_802_1Q_VLAN) {
			struct net_device  *pdev;
			T_UINT16           usVlanId;
			ASF_uint32_t       relIds[1];

			pdev = __vlan_get_real_dev(dev, &usVlanId);
			if (!pdev)
				return T_FAILURE;
			info.ulDevType = ASF_IFACE_TYPE_VLAN;
			relIds[0] = asfctrl_dev_get_cii(pdev);
			info.ucDevIdentifierInPkt = (ASF_uint8_t *)&usVlanId;
			info.ulDevIdentiferInPktLen = 2;
			info.ulRelatedIDs = (ASF_uint32_t *)relIds;
			info.ulNumRelatedIDs = 1;
		} else {
#endif
		info.ulDevType = ASF_IFACE_TYPE_ETHER;
		info.ucDevIdentifierInPkt = (ASF_uint8_t *) dev->dev_addr;
		info.ulDevIdentiferInPktLen = dev->addr_len;
		ASFCTRL_DBG("MAP interface %s (mac %pM) [%02x:%02x:%02x..]\n",
			dev->name, dev->dev_addr,
			dev->dev_addr[0], dev->dev_addr[1], dev->dev_addr[2]);

#ifdef CONFIG_VLAN_8021Q
	}
#endif
#ifdef CONFIG_PPPOE
	} else if (dev->type == ARPHRD_PPP) {
		T_UINT16 usPPPoESessId;
		T_INT32 parent_cii;
		struct net_device  *pdev;
		ASF_uint32_t       relIds[1];

		pdev = ppp_asf_get_parent_dev(dev, &usPPPoESessId);
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
		info.ucDevIdentifierInPkt = (ASF_uint8_t *)&usPPPoESessId;
		info.ulDevIdentiferInPktLen = 2;
		info.ulRelatedIDs = (ASF_uint32_t *)relIds;
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

	/* Assign Default VSG and ZoneID */
	ASFBindDeviceToVSG(ASF_DEF_VSG, cii);
	ASFFFPBindInterfaceToZone(ASF_DEF_VSG, cii, ASF_DEF_ZN_ID);

	ASFCTRL_FUNC_EXIT;
	return T_SUCCESS;
}
EXPORT_SYMBOL(asfctrl_create_dev_map);

T_INT32 asfctrl_delete_dev_map(struct net_device *dev)
{
	T_INT32  cii;
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

#if (DEBUG_GLOBAL_LEVEL >= LOGS)
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
	struct net_device *dev = (struct net_device *)ptr;

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
	}
	ASFCTRL_FUNC_EXIT;
	return NOTIFY_DONE;
}

int asfctrl_dev_fp_tx_hook(struct sk_buff *skb, struct net_device *dev)
{
	T_UINT16           usEthType;
	T_INT32            hh_len;
	T_BOOL             bPPPoE = 0;
	struct iphdr       *iph;

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

	if (usEthType != __constant_htons(ETH_P_IP))
		goto drop;

	iph = (struct iphdr *)(skb->data+hh_len);

	switch (iph->protocol) {
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

		pData = (asf_linux_L2blobPktData_t *)(skb->data+hh_len +
						(iph->ihl * 4));

		memcpy(&cmd.tuple, &pData->tuple, sizeof(cmd.tuple));
		cmd.ulZoneId = pData->ulZoneId;
		cmd.bL2blobUpdate = 1;
		cmd.u.l2blob.ulDeviceId = asfctrl_dev_get_cii(dev);
		cmd.u.l2blob.ulPathMTU = pData->ulPathMTU;

		/* need to include PPPOE+PPP header if any */
		cmd.u.l2blob.l2blobLen = hh_len;

		memcpy(cmd.u.l2blob.l2blob, skb->data, cmd.u.l2blob.l2blobLen);

		if (vlan_tx_tag_present(skb)) {
			cmd.u.l2blob.bTxVlan = 1;
			cmd.u.l2blob.usTxVlanId = vlan_tx_tag_get(skb);
		} else {
			cmd.u.l2blob.bTxVlan = 0;
		}

		ASFFFPRuntime(pData->ulVsgId, ASF_FFP_MODIFY_FLOWS, &cmd,
			sizeof(cmd), NULL, 0);
		break;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	case ASFCTRL_IPPROTO_DUMMY_IPSEC_L2BLOB:
		ASFCTRL_INFO("DUMMY_IPSEC_L2BLOB");

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
	}
drop:
	kfree_skb(skb);
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
	netif_receive_skb(skb);

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
	netif_receive_skb(skb);

	if (!bVal)
		local_bh_enable();
	ASFCTRL_FUNC_EXIT;
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

	ASFCTRL_FUNC_ENTRY;

	memset(p_asfctrl_netdev_cii, 0, sizeof(p_asfctrl_netdev_cii));

	ASFGetCapabilities(&g_cap);

	if (!g_cap.bBufferHomogenous) {
		ASFCTRL_ERR("ASF capabilities: Non homogenous buffer");
		return -1;
	}
	asfctrl_vsg_config_id = jiffies;
	cmd.ulConfigMagicNumber = asfctrl_vsg_config_id;
	ASFFFPUpdateConfigIdentity(ASF_DEF_VSG, cmd);

	ASFFFPRegisterCallbackFns(&asfctrl_Cbs);

	register_netdevice_notifier(&asfctrl_dev_notifier);
	devfp_register_tx_hook(asfctrl_dev_fp_tx_hook);

	asfctrl_sysfs_init();


	if (g_cap.mode[fwMode])
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

	if (g_cap.mode[fwMode])
		asfctrl_linux_unregister_ffp();

	asfctrl_sysfs_exit();
	devfp_register_tx_hook(NULL);
	unregister_netdevice_notifier(&asfctrl_dev_notifier);

	for (ii = 0; ii < ASFCTRL_MAX_IFACES; ii++) {
		if (p_asfctrl_netdev_cii[ii])
			asfctrl_delete_dev_map(p_asfctrl_netdev_cii[ii]);
	}

	ASFRemove();

	ASFCTRL_INFO("ASF Control Module - Core Unloaded \n");
	ASFCTRL_FUNC_EXIT;
}

module_init(asfctrl_init);
module_exit(asfctrl_exit);
