/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_linux_term.c
 *
 * Description: Added Support for dynamic rules manupulation for
 * User Space Termination by integrating with ASF module.
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/*
 * History
 * Version	Date		Author		Change Description *
 * 1.0		01 Feb 2011	Hemant Agrawal	Initial Version.
 *
 */
/***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/if_pmal.h>
#include <gianfar.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/route.h>

#include "../../../asfffp/driver/asf.h"
#include "../../../asfffp/driver/asfcmn.h"
#include "../../../asfterm/driver/asftermapi.h"
#include "../ffp/asfctrl.h"


#define ASFCTRL_LINUX_TERM_VERSION "1.0"
#define ASFCTRL_LINUX_TERM_DESC "ASF Linux-Termination Integration Driver"

/** \brief	Driver's license
 * \details	GPL
 * \ingroup	Linux_module
 */
MODULE_LICENSE("GPL");
/** \brief	Module author
 * \ingroup	Linux_module
 */
MODULE_AUTHOR("Freescale Semiconductor, Inc");
/** \brief	Module description
 * \ingroup	Linux_module
 */
MODULE_DESCRIPTION(ASFCTRL_LINUX_TERM_DESC);

int term_expiry_timeout = 180; /* in sec */

module_param(term_expiry_timeout, int, 0644);
MODULE_PARM_DESC(term_expiry_timeout, "Expiry Timeout for Term Cache Entry");

/* Global Variables */
ASFTERMCap_t g_term_cap;
atomic_t	g_dynamic_flow_learning;
/* Dummy Commom Interface ID for sending the self packets out*/
ASF_uint32_t g_dummy_cii = 5;
ASF_uint32_t g_out_cii = 4; /*eth2*/

typedef struct asfctrl_term_L2blobPktData_s {
	ASFTERMCacheEntryTuple_t	tuple;
	ASF_uint32_t ulVsgId;
	ASF_uint32_t ulPathMTU;
} asfctrl_term_L2blobPktData_t;

extern uint32_t asfctrl_vsg_config_id;
extern uint32_t asfctrl_vsg_l2blobconfig_id;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
extern asfctrl_ipsec_get_flow_info fn_ipsec_get_flow4;
#endif

int asfctrl_term_entry_add(
	struct net_device *dev,
	ASFTERMCacheEntryTuple_t tuple,
	bool aging,
	void *ctx);

void asfctrl_generic_free(ASF_void_t *freeArg)
{
	ASFCTRLSkbFree((struct sk_buff *)freeArg);
}

static ASF_int32_t asfctrl_term_veify_firewall(ASF_uint32_t ulVSGId,
			ASF_uint32_t hook,
			ASFTERMCacheEntryTuple_t *tpl)
{
	unsigned int verdict = NF_ACCEPT;

	/* TBD */

	return verdict;
}

static ASF_int32_t asfctrl_term_XmitL2blobDummyPkt(
			ASFTERMCacheEntryTuple_t *tpl)
{
	struct	sk_buff *skb;
	struct net_device *dev;
	int	ret;

	skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
	if (skb) {
		asfctrl_term_L2blobPktData_t *pData;
		struct iphdr *iph;
		struct flowi fl;
		struct rtable *rt = skb_rtable(skb);

		dev = asfctrl_dev_get_dev(g_out_cii);
		if (!dev) {
			ASFCTRLKernelSkbFree(skb);
			return T_FAILURE;
		}

		memset(&fl, 0, sizeof(fl));
		fl.oif = dev->ifindex;
		fl.proto = IPPROTO_UDP,
		fl.nl_u.ip4_u.saddr = 0;
		fl.nl_u.ip4_u.daddr = tpl->ulDestIp;
		fl.nl_u.ip4_u.tos = 0;
		fl.uli_u.ports.sport = tpl->usSrcPort;
		fl.uli_u.ports.dport = tpl->usDestPort;

		ASFCTRL_DBG("dst = %x src = %x, port =%x",
			tpl->ulDestIp, tpl->ulSrcIp, tpl->usSrcPort);

		ret = ip_route_output_key(&init_net, &rt, &fl);
		if (ret || !rt) {
			ASFCTRL_INFO("Route not found for ret = %d"\
				"rt = %x dst %x ",
				ret, rt, tpl->ulDestIp);
			ASFCTRLKernelSkbFree(skb);
			return T_FAILURE;
		}

		skb_dst_set(skb, &rt->u.dst);

		ASFCTRL_INFO("Route found for dst %x, src %x, "\
				"rt =%x - flags= %x",
				tpl->ulDestIp, tpl->ulSrcIp,
				rt, rt ? rt->rt_flags : 0);

		skb->dev = skb_dst(skb)->dev;
		skb_reserve(skb, LL_RESERVED_SPACE(skb->dev));
		skb_reset_network_header(skb);
		skb_put(skb, sizeof(struct iphdr));
		iph = ip_hdr(skb);
		iph->version = 5;
		iph->ihl = 5;
		iph->ttl = 1;
		iph->saddr = tpl->ulSrcIp;
		iph->daddr = tpl->ulDestIp;
		iph->protocol = ASFCTRL_IPPROTO_DUMMY_TERM_L2BLOB;

		pData = (asfctrl_term_L2blobPktData_t *)skb_put(skb,
			sizeof(asfctrl_term_L2blobPktData_t));
		pData->ulVsgId = ASF_DEF_VSG;
		memcpy(&pData->tuple, tpl, sizeof(ASFTERMCacheEntryTuple_t));

		pData->ulPathMTU = skb->dev->mtu;
		skb->protocol = htons(ETH_P_IP);
		asfctrl_skb_mark_dummy(skb);
		ASFCTRL_INFO("Dummy Mark [0x%X] [0x%X]",
			skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET],
			skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET+1]);

		ret = ip_local_out(skb);
		if (ret == -EINVAL)
			ASFCTRL_ERR("Sending L2Blob Dummy packet Failed.\n");
	}
	return T_SUCCESS;
}

ASF_void_t asfctrl_term_fnCacheEntryNotFound(
		ASF_uint32_t ulVSGId,
		ASF_uint32_t ulCommonInterfaceId,
		ASFBuffer_t Buffer,
		genericFreeFn_t pFreeFn,
		ASF_void_t	*freeArg,
		ASF_void_t	*pIpsecOpaque,
		ASF_boolean_t	sendOut)
{
	struct sk_buff *skb = AsfBuf2Skb(Buffer);
	struct iphdr	*iph;
	int bVal = in_softirq();

	ASFCTRL_FUNC_ENTRY;

	if (!bVal)
		local_bh_disable();

	iph = ip_hdr(skb);
	ASFCTRL_INFO("iph->saddr = %x proto = %d, dynamic = %d", iph->saddr,
		iph->protocol, atomic_read(&g_dynamic_flow_learning));
	if ((iph->protocol == IPPROTO_UDP) &&
		(ASF_TRUE == atomic_read(&g_dynamic_flow_learning))) {
		struct packet_con_s conn;
		int type;

		conn.saddr.sin_addr.s_addr = iph->saddr;
		conn.daddr.sin_addr.s_addr = iph->daddr;
		conn.saddr.sin_port = BUFGET16((char *) (iph) + iph->ihl*4);
		conn.daddr.sin_port =
			BUFGET16(((char *) (iph) + iph->ihl*4) + 2);
		conn.proto = iph->protocol;
		conn.ctxt = 0;

		type = sendOut ? e_TX_UDP : e_RX_UDP;

		if (packet_is_valid_flow(&conn, type)) {
			ASFTERMCacheEntryTuple_t tuple;
			struct net_device *dev;

			tuple.ulDestIp = iph->daddr;
			tuple.ulSrcIp = iph->saddr;
			tuple.usSrcPort = conn.saddr.sin_port;
			tuple.usDestPort = conn.daddr.sin_port;
			tuple.ucProtocol = IPPROTO_UDP;
			ASFCTRL_INFO("Add Dynamic Flow src=%x:%d, dst=%x:%d",
				tuple.ulSrcIp, tuple.usSrcPort,
				tuple.ulDestIp, tuple.usDestPort);

			dev = asfctrl_dev_get_dev(ulCommonInterfaceId);
			if (!dev)
				goto fexit;

			asfctrl_term_entry_add(dev, tuple, ASF_TRUE, (void *)conn.ctxt);
			skb->pmal_ctxt = conn.ctxt;

			/*if (sendOut) can we feed it back to Process function*/
			/*TBD - vlan case not supported need to optimize it */
			/*TBD - IPSEC- currently not verifying the In SPD */
			/*TBD - decrypted packet need to have the skb->sp set */
			if (!sendOut) {
				if (skb->data != skb_mac_header(skb)) {
					skb->data -= ETH_HLEN;
					skb->len += ETH_HLEN;
					memcpy(skb->data,
						skb_mac_header(skb), ETH_HLEN);
				}
				/* Send it to for normal path handling */
				pmal_receive_skb(skb);
				goto fexit;
			}
			ASFCTRL_ERR("Dropping the skb %x", (unsigned int) skb);
			pFreeFn(Buffer.nativeBuffer);
			goto fexit;
		}
	}

	ASFProcessNonTermPkt(ulVSGId, ulCommonInterfaceId,
			Buffer, pFreeFn, freeArg, pIpsecOpaque);
fexit:
	if (!bVal)
		local_bh_enable();
	ASFCTRL_FUNC_EXIT;

	return;
}

ASF_void_t asfctrl_term_fnCacheValidate(ASF_uint32_t ulVSGId,
			ASFTERMCacheValidateCbInfo_t *pInfo)
{
	int	result;
	struct net_device *dev;
	struct net *net;
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	bool bIPsecIn = 0, bIPsecOut = 0;
	struct flowi fl_out;
#endif
	ASFTERMUpdateCacheEntry_t cmd;
	ASFCTRL_FUNC_ENTRY;

	memset(&cmd, 0, sizeof(cmd));

	if (asfctrl_term_veify_firewall(ulVSGId,
		pInfo->bLocalTerm ? NF_INET_LOCAL_IN : NF_INET_LOCAL_OUT,
		&pInfo->tuple) != NF_ACCEPT) {
		goto delete_entry;
	}

	cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
	cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
	cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
	cmd.tuple.usDestPort = pInfo->tuple.usDestPort;
	cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;


	cmd.bTERMConfigIdentityUpdate = 1;

	cmd.u.termConfigIdentity.ulConfigMagicNumber =
			asfctrl_vsg_config_id;

	if (ASFTERMRuntime(ulVSGId,
		ASF_TERM_UPDATE_CACHE_ENTRY,
		&cmd, sizeof(cmd), NULL, 0) ==
		ASFTERM_RESPONSE_SUCCESS) {
			ASFCTRL_INFO("Entry modified successfully");
	} else {
			ASFCTRL_ERR("Entry modification failure");
	}
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_get_flow4) {
		ASFFFPIpsecInfo_t ipsecInInfo;

		memset(&cmd, 0, sizeof(cmd));

		memset(&fl_out, 0, sizeof(fl_out));
		fl_out.fl_ip_sport = pInfo->tuple.usSrcPort;
		fl_out.fl_ip_dport = pInfo->tuple.usDestPort;
		fl_out.proto = pInfo->tuple.ucProtocol;
		fl_out.fl4_dst = pInfo->tuple.ulDestIp;
		fl_out.fl4_src = pInfo->tuple.ulSrcIp;
		fl_out.fl4_tos = 0;

		dev = dev_get_by_name(&init_net, "lo");
		net = dev_net(dev);

		result = fn_ipsec_get_flow4(&bIPsecIn, &bIPsecOut,
			&ipsecInInfo, net, fl_out);
		if (result)
			ASFCTRL_INFO("IPSEC Not Offloadable for flow");
		dev_put(dev);

		cmd.u.ipsec.ipsecInfo = ipsecInInfo;
		cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
		cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
		cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
		cmd.tuple.usDestPort = pInfo->tuple.usDestPort;
		cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;

		cmd.bIPsecConfigIdentityUpdate = 1;

		cmd.u.ipsec.bIPsecIn = bIPsecIn ? 1 : 0;
		cmd.u.ipsec.bIPsecOut = bIPsecOut ? 1 : 0;
		cmd.u.ipsec.bIn = cmd.u.ipsec.bOut = 1;

		ASFCTRL_INFO("Configured tunnel ID is %d ",
			ipsecInInfo.outContainerInfo.ulTunnelId);
		if (ASFTERMRuntime(ulVSGId,
			ASF_TERM_UPDATE_CACHE_ENTRY,
			&cmd, sizeof(cmd), NULL, 0) ==
			ASFTERM_RESPONSE_SUCCESS) {
			ASFCTRL_INFO("Entry for IPSEC modified successfully");
		} else {
			ASFCTRL_WARN("Entry for IPSEC modification failure");
		}
	}
	ASFCTRL_FUNC_EXIT;
	return;
#endif
delete_entry:
	{
		ASFTERMDeleteCacheEntry_t cmd;

		memcpy(&cmd.tuple, &pInfo->tuple,
			sizeof(ASFTERMCacheEntryTuple_t));

		ASFCTRL_INFO("\n sip : %x dip : %x srcport : %d\n",
			tuple.ulSrcIp,
			tuple.ulDestIp,
			tuple.usSrcPort);

		if (ASFTERMRuntime(ASF_DEF_VSG, ASF_TERM_DELETE_CACHE_ENTRY,
			&cmd, sizeof(cmd), NULL, 0)
			== ASFTERM_RESPONSE_SUCCESS) {

			ASFCTRL_INFO("Entry deleted successfully! --\n");
		} else
			ASFCTRL_INFO("Entry deleted Failed! --\n");
	}
	return;
}


ASF_void_t asfctrl_term_fnCacheRcvPkt(
		ASF_uint32_t ulVSGId,
		ASF_uint32_t ulCommonInterfaceId,
		ASFBuffer_t Buffer,
		genericFreeFn_t pFreeFn,
		ASF_void_t *freeArg)
{
	struct sk_buff *skb;
	int bVal = in_softirq();

	ASFCTRL_FUNC_ENTRY;

	skb = AsfBuf2Skb(Buffer);

	if (!bVal)
		local_bh_disable();
	/*TBD - vlan case not supported need to optimize it */
	if (skb->data != skb_mac_header(skb)) {
		skb->data -= ETH_HLEN;
		skb->len += ETH_HLEN;
		memcpy(skb->data, skb_mac_header(skb), ETH_HLEN);
	}

	/* Send it to for normal path handling */
	pmal_receive_skb(skb);

	if (!bVal)
		local_bh_enable();
	ASFCTRL_FUNC_EXIT;
}

ASF_void_t asfctrl_term_fnRuntime(
		ASF_uint32_t ulVSGId,
		ASF_uint32_t cmd,
		ASF_void_t *pReqIdentifier,
		ASF_uint32_t ulReqIdentifierlen,
		ASF_void_t *pResp,
		ASF_uint32_t ulRespLen)
{
	ASFCTRL_FUNC_TRACE;
	switch (cmd) {
	case ASF_TERM_CREATE_CACHE_ENTRY:
	{
#if (DEBUG_GLOBAL_LEVEL >= INFO)
		ASFTERMCreateCacheEntryResp_t *pInfo =
			(ASFTERMCreateCacheEntryResp_t *)pResp;
#endif

		ASFCTRL_INFO("CreateCacheEntry Response (Result %d) hash %d\n",
				ntohl(pInfo->iResult), pInfo->ulHashVal);
	}
	break;

	case ASF_TERM_DELETE_CACHE_ENTRY:
	{
#if (DEBUG_GLOBAL_LEVEL >= INFO)
		ASFTERMDeleteCacheEntryResp_t *pInfo =
			(ASFTERMDeleteCacheEntryResp_t *)pResp;
#endif

		ASFCTRL_INFO("DeleteCacheEntry Response (Result %d)\n",
						ntohl(pInfo->iResult));
	}
	break;

	default:
		ASFCTRL_INFO("response for unknown command %u (vsg %u)\n",
								cmd, ulVSGId);
	}
	return;
}

ASF_void_t asfctrl_term_fnCacheEntryRefreshL2Blob(ASF_uint32_t ulVSGId,
			ASFTERMCacheEntryL2BlobRefreshCbInfo_t *pInfo)
{
	struct sk_buff *skb;

	ASFCTRL_FUNC_TRACE;
	ASFCTRL_INFO("L2Blob Refresh Request Indication\n");
	skb = AsfBuf2Skb(pInfo->Buffer);
	if (skb)
		ASFCTRL_netif_receive_skb(skb);

	asfctrl_term_XmitL2blobDummyPkt(&pInfo->packetTuple);
	return;
}

ASF_void_t asfctrl_term_fnCacheEntryExpiry(
	ASF_uint32_t ulVSGId,
	ASFTERMCacheEntryExpiryCbInfo_t *pInfo)
{
	ASFCTRL_FUNC_TRACE;
	ASFCTRL_INFO("Cache Entry Expiry Indication\n");
	return;
}


ASF_void_t asfctrl_term_fnAuditLog(ASFLogInfo_t *pLogInfo)
{
	ASFCTRL_FUNC_TRACE;
	ASFCTRL_INFO(" VSG[%u], MsgId[%u]\n",
					pLogInfo->ulVSGId,
					pLogInfo->ulMsgId);
	return;
}


ASF_void_t asfctrl_term_l2blob_update_fn(
	struct sk_buff *skb,
	ASF_uint32_t hh_len,
	ASF_uint32_t ulDeviceID)
{
	ASFTERMUpdateCacheEntry_t pCacheData;
	ASF_uint32_t		ulVSGId;
	asfctrl_term_L2blobPktData_t *pData;
	struct iphdr		*iph;
	int err = ASFTERM_RESPONSE_FAILURE;

	iph = (struct iphdr *)(skb->data + hh_len);

	pData = (asfctrl_term_L2blobPktData_t *) (skb->data
				+ hh_len + iph->ihl * 4);
	ASFCTRL_INFO("pData: SrcIP %x, DstIp %x, Protocol %d\n",
				pData->tuple.ulSrcIp,
				pData->tuple.ulDestIp,
				pData->tuple.ucProtocol);
	memcpy(&pCacheData.tuple, &pData->tuple,
			sizeof(ASFTERMCacheEntryTuple_t));
	ulVSGId = pData->ulVsgId;
	pCacheData.bL2blobUpdate = 1;
	pCacheData.u.l2blob.ulPathMTU = pData->ulPathMTU;
	pCacheData.u.l2blob.ulDeviceId = ulDeviceID;
	pCacheData.u.l2blob.l2blobLen = hh_len;
	memcpy(&pCacheData.u.l2blob.l2blob, skb->data,
					pCacheData.u.l2blob.l2blobLen);
#ifdef CONFIG_VLAN_8021Q
	if (vlan_tx_tag_present(skb)) {
		pCacheData.u.l2blob.bTxVlan = 1;
		pCacheData.u.l2blob.usTxVlanId = (vlan_tx_tag_get(skb)
							| VLAN_TAG_PRESENT);
	} else
#endif
		pCacheData.u.l2blob.bTxVlan = 0;

	pCacheData.u.l2blob.bUpdatePPPoELen = 0;
	pCacheData.u.l2blob.ulL2blobMagicNumber = asfctrl_vsg_l2blobconfig_id;

	err = ASFTERMRuntime(ulVSGId, ASF_TERM_UPDATE_CACHE_ENTRY,
			&pCacheData, sizeof(ASFTERMUpdateCacheEntry_t),
			NULL, 0);
	if (err)
		ASFCTRL_ERR("ASF_TERM_UPDATE_CACHE_ENTRY fialed.\n");
	/* Packet will be dropped by Calling function "asfctrl_dev_fp_tx_hook"*/
	return;
}
EXPORT_SYMBOL(asfctrl_term_l2blob_update_fn);

int asfctrl_term_entry_add(
	struct net_device *dev,
	ASFTERMCacheEntryTuple_t tuple,
	bool aging,
	void *ctx)
{
	int	result;
	struct net *net;
	ASFTERMCreateCacheEntry_t cmd;
	ASF_Modes_t mode;
	bool bIPsecIn = 0, bIPsecOut = 0;
	struct	sk_buff *skb;
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	struct flowi fl_in, fl_out;
#endif
	ASFCTRL_FUNC_ENTRY;

	ASFGetVSGMode(ASF_DEF_VSG, &mode);
	/* If ASF is disabled or mode is not TERM, simply return */
	if ((0 == ASFGetStatus()) || !(mode & termMode)) {
		ASFCTRL_INFO("ASF not ready or invalid mode 0x%x\n", mode);
		return 0;
	}

	memset(&cmd, 0, sizeof(cmd));

	ASFCTRL_INFO("sip : %x dip : %x src port : %d, iif =%d",
		tuple.ulSrcIp, tuple.ulDestIp, tuple.usSrcPort,
		asf_cii_cache(dev));

	/* Fill command for flow 1 */
	cmd.entry1.tuple.ucProtocol = tuple.ucProtocol;
	cmd.entry1.tuple.ulDestIp = tuple.ulDestIp;
	cmd.entry1.tuple.ulSrcIp = tuple.ulSrcIp;
	cmd.entry1.tuple.usDestPort = tuple.usDestPort;
	cmd.entry1.tuple.usSrcPort = tuple.usSrcPort;
	cmd.entry1.ulExpTimeout = aging ? term_expiry_timeout : 0;


	/* Fill command for flow 2 */
	cmd.entry2.tuple.ucProtocol = tuple.ucProtocol;
	cmd.entry2.tuple.ulDestIp = tuple.ulSrcIp;
	cmd.entry2.tuple.ulSrcIp = tuple.ulDestIp;
	cmd.entry2.tuple.usDestPort = tuple.usSrcPort;
	cmd.entry2.tuple.usSrcPort = tuple.usDestPort;
	cmd.entry2.ulExpTimeout =  aging ? term_expiry_timeout : 0;


	skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
	if (skb) {
		result = ip_route_input(skb, tuple.ulDestIp,
				tuple.ulSrcIp, 0, dev);
		ASFCTRL_INFO("ip_route_input : result = %d, rt = %x - %x",
			result, skb_rtable(skb),
			skb_rtable(skb) ? skb_rtable(skb)->rt_flags : 0);
		if (!result &&
			((skb_rtable(skb) ? skb_rtable(skb)->rt_flags : 0)
				& RTCF_LOCAL)) {
			ASFCTRL_INFO(" Local Route dst %x local host : 0x%x",
				tuple.ulDestIp, skb_rtable(skb)->rt_flags);
			cmd.entry1.bLocalTerm = 1;
		}

		ASFCTRLKernelSkbFree(skb);
	}

	skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
	if (skb) {
		result = ip_route_input(skb, tuple.ulSrcIp,
				tuple.ulDestIp, 0, dev);
		ASFCTRL_INFO("ip_route_input : result = %d, rt = %x - %x",
			result, skb_rtable(skb),
			skb_rtable(skb) ? skb_rtable(skb)->rt_flags : 0);
		if (!result &&
			((skb_rtable(skb) ? skb_rtable(skb)->rt_flags : 0)
				& RTCF_LOCAL)) {
			ASFCTRL_INFO(" Local Route dst %x local host : 0x%x",
				tuple.ulSrcIp, skb_rtable(skb)->rt_flags);
			cmd.entry2.bLocalTerm = 1;
		}
		ASFCTRLKernelSkbFree(skb);
	}

	cmd.configIdentity.ulConfigMagicNumber = asfctrl_vsg_config_id;

	cmd.configIdentity.l2blobConfig.ulL2blobMagicNumber =
			asfctrl_vsg_l2blobconfig_id;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_get_flow4) {
		memset(&fl_out, 0, sizeof(fl_out));
		fl_out.fl_ip_sport = tuple.usSrcPort;
		fl_out.fl_ip_dport = tuple.usDestPort;
		fl_out.proto = tuple.ucProtocol;
		fl_out.fl4_dst = tuple.ulDestIp;
		fl_out.fl4_src = tuple.ulSrcIp;
		fl_out.fl4_tos = 0;

		net = dev_net(dev);
		result = fn_ipsec_get_flow4(&bIPsecIn, &bIPsecOut,
			&(cmd.entry1.ipsecInInfo), net, fl_out);
		if (result) {
			ASFCTRL_INFO("IPSEC Not Offloadable for flow 1");
			return result;
		}
	}
#endif
	cmd.entry1.bIPsecIn = bIPsecIn ? 1 : 0;
	cmd.entry1.bIPsecOut = bIPsecOut ? 1 : 0;
	/* If this is a terminating flow of outgoig flow*/
	if (!cmd.entry1.bLocalTerm)
		cmd.entry1.bLocalTerm = bIPsecIn ? 1 : 0;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_get_flow4) {
		memset(&fl_in, 0, sizeof(fl_out));
		fl_in.fl_ip_sport = tuple.usDestPort;
		fl_in.fl_ip_dport = tuple.usSrcPort;
		fl_in.proto = tuple.ucProtocol;
		fl_in.fl4_dst = tuple.ulSrcIp;
		fl_in.fl4_src = tuple.ulDestIp;
		fl_in.fl4_tos = 0;

		result = fn_ipsec_get_flow4(&bIPsecIn, &bIPsecOut,
			&(cmd.entry2.ipsecInInfo), net, fl_in);
		if (result) {
			ASFCTRL_INFO("IPSEC Not Offloadable for flow 2");
			return result;
		}
	}
#endif
	cmd.entry2.bIPsecIn = bIPsecIn ? 1 : 0;
	cmd.entry2.bIPsecOut = bIPsecOut ? 1 : 0;
	/* If this is a terminating flow of outgoig flow*/
	if (!cmd.entry2.bLocalTerm)
		cmd.entry2.bLocalTerm = bIPsecIn ? 1 : 0;

	cmd.ASFTermInfo = (ASF_uint32_t *)ctx;

	/* TBD - FIX IT - even if one flow is qualified with firewall,
		we are not creating the flow*/

	if (asfctrl_term_veify_firewall(ASF_DEF_VSG,
		cmd.entry1.bLocalTerm ? NF_INET_LOCAL_IN : NF_INET_LOCAL_OUT,
		&cmd.entry1.tuple) != NF_ACCEPT) {
		goto firewall_fail;
	}

	if (asfctrl_term_veify_firewall(ASF_DEF_VSG,
		cmd.entry2.bLocalTerm ? NF_INET_LOCAL_IN : NF_INET_LOCAL_OUT,
		&cmd.entry2.tuple) != NF_ACCEPT) {
		goto firewall_fail;
	}

	if (ASFTERMRuntime(ASF_DEF_VSG, ASF_TERM_CREATE_CACHE_ENTRY,
		&cmd, sizeof(cmd), NULL, 0) == ASFTERM_RESPONSE_SUCCESS) {

		/* Cache Entry crated successfully.
		populate the L2 info if not IPSEC*/
		if (!cmd.entry1.bIPsecIn && !cmd.entry1.bIPsecOut
			&& !cmd.entry1.bLocalTerm)
			asfctrl_term_XmitL2blobDummyPkt(&cmd.entry1.tuple);

		if (!cmd.entry2.bIPsecIn && !cmd.entry2.bIPsecOut
			&& !cmd.entry2.bLocalTerm)
			asfctrl_term_XmitL2blobDummyPkt(&cmd.entry2.tuple);

		ASFCTRL_INFO("Flow created successfully! --\n");
		return 0;
	}
firewall_fail:
	ASFCTRL_INFO("Flow creation Failed! --\n");
	return -1;
}
EXPORT_SYMBOL(asfctrl_term_entry_add);

int asfctrl_term_entry_delete(ASFTERMCacheEntryTuple_t tuple)
{
	ASFTERMDeleteCacheEntry_t cmd;
	ASF_Modes_t mode;

	ASFGetVSGMode(ASF_DEF_VSG, &mode);
	/* If ASF is disabled or mode is not TERM, simply return */
	if ((0 == ASFGetStatus()) || !(mode & termMode)) {
		ASFCTRL_INFO("ASF not ready or invalid mode 0x%x\n", mode);
		return 0;
	}
	memcpy(&cmd.tuple, &tuple, sizeof(ASFTERMCacheEntryTuple_t));

	ASFCTRL_INFO("\n sip : %x dip : %x srcport : %d\n",
		tuple.ulSrcIp,
		tuple.ulDestIp,
		tuple.usSrcPort);

	if (ASFTERMRuntime(ASF_DEF_VSG, ASF_TERM_DELETE_CACHE_ENTRY,
		&cmd, sizeof(cmd), NULL, 0) == ASFTERM_RESPONSE_SUCCESS) {

		ASFCTRL_INFO("Entry deleted successfully! --\n");
	} else
		ASFCTRL_INFO("Entry deleted Failed! --\n");
	return 0;
}

/* Thourgh hit and trial, it has been found that there is a gap of
 maximum of 17 sec between multiple flush calls invoke by
 Linux for same event */
#define MAX_FLUSH_GAP 17
void asfctrl_term_cache_flush(void)
{
	static unsigned long last_jiffes;

	if ((jiffies - last_jiffes) > MAX_FLUSH_GAP) {
		ASFCTRL_INFO("Flushing Route Table! --\n");
		ASFTERMRuntime(ASF_DEF_VSG,
				ASF_TERM_FLUSH_CACHE_TABLE,
				NULL, 0, NULL, 0);
	}
	last_jiffes = jiffies;

	return;
}

static int asfctrl_term_pkt_pmal_config(int type, void *param)
{
	int ret;
	ASFCTRL_INFO("type %d", type);

	switch (type) {
	case ASF_PACKET_CONN_ADD:
	{
		struct packet_con_s *conn = (struct packet_con_s *)param;
		ASFTERMCacheEntryTuple_t tuple;
		ASFNetDevEntry_t *asf_dev;

		tuple.ulSrcIp = conn->saddr.sin_addr.s_addr;
		tuple.ulDestIp = conn->daddr.sin_addr.s_addr;
		tuple.usSrcPort = conn->saddr.sin_port;
		tuple.usDestPort = conn->daddr.sin_port;
		tuple.ucProtocol = IPPROTO_UDP;

		asf_dev = ASFCiiToNetDev(g_dummy_cii);
		if (!asf_dev)
			return -1;
		ret = asfctrl_term_entry_add(asf_dev->ndev,
			tuple, ASF_FALSE, (void *)conn->ctxt);
		return ret;
	}
	case ASF_PACKET_CONN_DEL:
	{
		struct packet_con_s *conn = (struct packet_con_s *)param;
		ASFTERMCacheEntryTuple_t tuple;

		tuple.ulSrcIp = conn->saddr.sin_addr.s_addr;
		tuple.ulDestIp = conn->daddr.sin_addr.s_addr;
		tuple.usSrcPort = conn->saddr.sin_port;
		tuple.usDestPort = conn->daddr.sin_port;
		tuple.ucProtocol = IPPROTO_UDP;

		ret = asfctrl_term_entry_delete(tuple);
		return ret;
	}
	case ASF_PACKET_DYNM_LEARNING:
	{
		int *val = (int *)param;
		ASFCTRL_INFO("DYNAMIC LEARNING IS = %s", *val ? "ON" : "OFF");

		if (*val)
			atomic_set(&g_dynamic_flow_learning, ASF_TRUE);
		else
			atomic_set(&g_dynamic_flow_learning, ASF_FALSE);
		return 0;
	}
	case ASF_PACKET_FLUSH_CONN:
	{
		asfctrl_term_cache_flush();
		return 0;
	}
	case ASF_PACKET_OUT_INTERFACE:
	{
		int *val = (int *)param;
		ASFCTRL_INFO("OUT INTERFACE IS =%s", *val);

		if (!asfctrl_dev_get_dev(*val)) {
			ASFCTRL_WARN("Device not offload..ignoring");
			return 0;
		}
		g_out_cii = *val;
		return 0;
	}

	}
	return 0;
}

static int asfctrl_term_pkt_tx_hook(struct sk_buff *skb, void *info)
{
	ASFBuffer_t Buffer;
	struct iphdr		*iph;

	if (!skb)
		return -1;

	iph = ip_hdr(skb);
	Buffer.nativeBuffer = skb;
	skb_pull(skb, ETH_HLEN);

	ASFCTRL_DBG("data = 0x%x (len=%d) src =%x, dest = %x",
		skb->data, skb->len, iph->saddr, iph->daddr);

	ip_send_check(iph);
	ASFTERMProcessPkt(ASF_DEF_VSG,
				g_dummy_cii,
				Buffer,
				asfctrl_generic_free,
				skb,
				NULL,
				ASF_TRUE);
	return 0;
}

static int __init asfctrl_linux_term_init(void)
{
	struct packet_asf_cb packet_asf = {
		asfctrl_term_pkt_tx_hook,
		asfctrl_term_pkt_pmal_config
	};
	struct net_device *dev;
	ASFCap_t asf_cap;
	ASFTERMCallbackFns_t asfctrl_Cbs = {
		NULL,
		NULL,
		asfctrl_term_fnCacheEntryNotFound,
		asfctrl_term_fnRuntime,
		asfctrl_term_fnCacheEntryExpiry,
		asfctrl_term_fnCacheEntryRefreshL2Blob,
		asfctrl_term_fnCacheRcvPkt,
		asfctrl_term_fnCacheValidate,
		asfctrl_term_fnAuditLog
	};

	ASFGetCapabilities(&asf_cap);
	if (!(asf_cap.mode & termMode)) {
		ASFCTRL_ERR("Termination mode Not supported in ASF");
		return -1;
	}
	if (!asf_cap.bBufferHomogenous) {
		ASFCTRL_ERR("Hetrogeneous Buffer mode is not supported in ASF");
		return -1;
	}
	ASFTERMSetNotifyPreference(ASF_ASYNC_RESPONSE);

	ASFTERMGetCapabilities(&g_term_cap);
	/* Number of VSG in TERM module must not greater
	than those of ASF Core module */
	if (g_term_cap.ulMaxVSGs > asf_cap.ulNumVSGs) {
		ASFCTRL_ERR("ERROR: TERM VSG[%d] > ASF VSG[%d].\n",
			g_term_cap.ulMaxVSGs, asf_cap.ulNumVSGs);
		return -1;
	}
	if (!g_term_cap.bBufferHomogenous) {
		ASFCTRL_ERR("Hetrogeneous Buffer mode is"
				" not supported in ASFTERM\n");
		return -1;
	}

	ASFTERMRegisterCallbackFns(&asfctrl_Cbs);

	/* Register Callback function with ASF control layer to
	get L2blob information, route add event and flush events */
	asfctrl_register_term_func(&asfctrl_term_l2blob_update_fn,
				&asfctrl_term_cache_flush);

	dev = dev_get_by_name(&init_net, "dummy0");
	if (dev) {
		g_dummy_cii = asf_cii_cache(dev);
		ASFCTRL_INFO("dummy0 Interface = %d\n", g_dummy_cii);
	} else {
		ASFCTRL_INFO("dummy0 Interface not found. default CID = %d\n",
			g_dummy_cii);
	}
	dev_put(dev);

	if (0 != pmal_register_tx_hook(&packet_asf)) {
		ASFCTRL_ERR("PMAL Socket exists, can not load");

		memset(&asfctrl_Cbs, 0, sizeof(ASFTERMCallbackFns_t));
		ASFTERMRegisterCallbackFns(&asfctrl_Cbs);
		asfctrl_register_term_func(NULL, NULL);
		return -1;
	}

	ASFCTRL_DBG("ASF Control Module - Forward Loaded\n");
	return 0;
}

static void __exit asfctrl_linux_term_exit(void)
{
	ASFTERMCallbackFns_t asfctrl_Cbs = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};
	pmal_unregister_tx_hook();

	/* De-register Callback functins with TERM module */
	ASFTERMRegisterCallbackFns(&asfctrl_Cbs);

	asfctrl_register_term_func(NULL, NULL);

	ASFCTRL_DBG("ASF Control Module - Forward Unloaded \n");
}

module_init(asfctrl_linux_term_init);
module_exit(asfctrl_linux_term_exit);
