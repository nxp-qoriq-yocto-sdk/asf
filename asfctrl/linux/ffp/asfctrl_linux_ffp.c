/* Copyright (C) 2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfctrl_linux_ffp.c
 *
 * Control module for Configuring ASF and integrating it with
 * Linux Networking Stack
 *
 * Authors:	Arun Pathak <Arun.Pathak@freescale.com>
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
/*  Revision History    : 1.0
*  Version     Date         Author              Change Description
*  1.0        20/09/2010    Arun Pathak      Initial Development
***************************************************************************/
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <net/dst.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <gianfar.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/dst.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/route.h>

#include "../../../asfffp/driver/asf.h"
#include "asfctrl.h"

#define tuple(ct, dir) (&(ct)->tuplehash[dir].tuple)

ASFFFPCap_t	g_fw_cap;

static uint32_t asf_ffp_udp_tmout = ASF_UDP_INAC_TMOUT;
static uint32_t asf_ffp_tcp_tmout = ASF_TCP_INAC_TMOUT;
static uint32_t asf_ffp_tcp_state_check = ASFCTRL_TRUE;
static uint32_t asf_ffp_tcp_tm_stmp_check = ASFCTRL_TRUE;
static uint32_t asf_ffp_activity_divisor = DEFVAL_INACTIVITY_DIVISOR;


static T_INT32 asf_linux_XmitL2blobDummyPkt(
				ASF_uint32_t ulVsgId,
				ASF_uint32_t ulZoneId,
				ASFFFPFlowTuple_t *tpl,
				ASF_IPv4Addr_t    ulSrcIp,
				ASF_IPv4Addr_t    uldestIp,
				ASF_uint32_t tos,
				T_UINT32 ulHashVal,
				ASF_uint32_t ulCII)
{
	struct sk_buff *skb;
	asf_linux_L2blobPktData_t *pData;
	struct iphdr *iph;
	struct net_device *dev;

	ASFCTRL_FUNC_ENTRY;

	skb = alloc_skb(1024, GFP_ATOMIC);
	if (!skb)
		return T_FAILURE;

	dev = dev_get_by_name(&init_net, "lo");

	if ((0 != ip_route_input(skb, uldestIp, ulSrcIp, 0, dev)) ||
		(skb_rtable(skb)->rt_flags & RTCF_LOCAL)) {
		ASFCTRL_INFO("Route not found for dst %x local host : %d",
			uldestIp,
			(skb_rtable(skb)->rt_flags & RTCF_LOCAL) ? 1 : 0);
		dev_put(dev);
		kfree_skb(skb);
		return T_FAILURE;
	}
	dev_put(dev);
	ASFCTRL_INFO("Route found for dst %x ", uldestIp);
	skb->dev = skb_dst(skb)->dev;
	skb_reserve(skb, LL_RESERVED_SPACE(skb->dev));
	skb_reset_network_header(skb);
	skb_put(skb, sizeof(struct iphdr));
	iph = ip_hdr(skb);
	iph->version = 5;
	iph->ihl = 5;
	iph->ttl = 1;
	iph->saddr = ulSrcIp;
	iph->daddr = uldestIp;
	iph->protocol = ASFCTRL_IPPROTO_DUMMY_L2BLOB;
	pData = (asf_linux_L2blobPktData_t *)skb_put(skb,
				sizeof(asf_linux_L2blobPktData_t));
	pData->ulZoneId = 0;
	pData->ulVsgId = 0;
	memcpy(&pData->tuple, tpl, sizeof(ASFFFPFlowTuple_t));

	pData->ulPathMTU = skb->dev->mtu;
	skb->protocol = htons(ETH_P_IP);
	asfctrl_skb_mark_dummy(skb);

	asf_ip_send(skb);

	ASFCTRL_FUNC_EXIT;

	return T_SUCCESS;
}

ASF_void_t asfctrl_fnZoneMappingNotFound(
					ASF_uint32_t ulVSGId,
					ASF_uint32_t ulCommonInterfaceId,
					ASFBuffer_t Buffer,
					genericFreeFn_t pFreeFn,
					ASF_void_t    *freeArg)
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

ASF_void_t  asfctrl_fnNoFlowFound(
				ASF_uint32_t ulVSGId,
				ASF_uint32_t ulCommonInterfaceId,
				ASF_uint32_t ulZoneId,
				ASFBuffer_t Buffer,
				genericFreeFn_t pFreeFn,
				ASF_void_t    *freeArg)
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

ASF_void_t asfctrl_fnRuntime(
			ASF_uint32_t ulVSGId,
			ASF_uint32_t cmd,
			ASF_void_t    *pReqIdentifier,
			ASF_uint32_t ulReqIdentifierlen,
			ASF_void_t   *pResp,
			ASF_uint32_t ulRespLen)
{
	ASFCTRL_FUNC_ENTRY;

	switch (cmd) {
	case ASF_FFP_CREATE_FLOWS:
	{
		ASFFFPCreateFlowsResp_t *pInfo =
			(ASFFFPCreateFlowsResp_t *)pResp;

		ASFCTRL_INFO("CreateFlows Response (Result %d) hash %d\n",
			ntohl(pInfo->iResult), pInfo->ulHashVal);
	}
	break;

	case ASF_FFP_DELETE_FLOWS:
	{
		ASFFFPDeleteFlowsResp_t *pInfo =
			(ASFFFPDeleteFlowsResp_t *)pResp;

		ASFCTRL_INFO("DeleteFlows Response (Result %d)\n",
			ntohl(pInfo->iResult));
	}
	break;

	default:
		ASFCTRL_INFO("response for unknown command %u (vsg %u)\n",
			cmd, ulVSGId);
	}

	ASFCTRL_FUNC_EXIT;
}


ASF_void_t asfctrl_fnFlowRefreshL2Blob(ASF_uint32_t ulVSGId,
			ASFFFPFlowL2BlobRefreshCbInfo_t *pInfo)
{
	ASFCTRL_FUNC_ENTRY;
	asf_linux_XmitL2blobDummyPkt(ulVSGId, pInfo->ulZoneId,
			&pInfo->flowTuple, pInfo->flowTuple.ulSrcIp,
			pInfo->packetTuple.ulDestIp, 0,
			pInfo->ulHashVal, 0);

	ASFCTRL_FUNC_EXIT;
}


ASF_void_t asfctrl_fnFlowActivityRefresh(ASF_uint32_t ulVSGId,
			ASFFFPFlowRefreshInfo_t *pRefreshInfo)
{
	struct nf_conn *ct = (struct nf_conn *)pRefreshInfo->ASFwInfo;
	uint32_t	ulTimeout;
	ASFCTRL_FUNC_ENTRY;

	ulTimeout = (pRefreshInfo->tuple.ucProtocol == IPPROTO_TCP) ?
			asf_ffp_tcp_tmout : asf_ffp_udp_tmout;

	if (pRefreshInfo->ulInactiveTime <=
		(ulTimeout / asf_ffp_activity_divisor)) {
		/* Passing 1 as dummy SKB, is not used in the function */
		nf_ct_refresh(ct, (struct sk_buff *)1, (ulTimeout*HZ));
	}

	ASFCTRL_FUNC_EXIT;
}

ASF_void_t asfctrl_fnFlowTcpSpecialPkts(ASF_uint32_t ulVSGId,
			ASFFFPFlowSpecialPacketsInfo_t *pInfo)
{
	struct nf_conn *ct = (struct nf_conn *)pInfo->ASFwInfo;
	uint32_t        ulTimeout;
	uint8_t	uTcpState;

	ASFCTRL_FUNC_ENTRY;
	switch (pInfo->ulTcpState) {

	case ASF_FFP_TCP_STATE_FIN_RCVD:
		uTcpState = TCP_CONNTRACK_FIN_WAIT;
		ulTimeout = 10*60;
		break;

	case ASF_FFP_TCP_STATE_RST_RCVD:
		uTcpState = TCP_CONNTRACK_CLOSE;
		ulTimeout = 10;
		break;

	case ASF_FFP_TCP_STATE_FIN_COMP:
		uTcpState = TCP_CONNTRACK_TIME_WAIT;
		ulTimeout = 10*60;
		break;
	default:
		return;
	}

	ct->proto.tcp.state = uTcpState;
	/* Passing 1 as dummy SKB, is not used in the function */
	nf_ct_refresh(ct, (struct sk_buff *)1, (ulTimeout*HZ));
	ASFCTRL_FUNC_EXIT;
}

ASF_void_t asfctrl_fnFlowValidate(ASF_uint32_t ulVSGId,
			ASFFFPFlowValidateCbInfo_t *pInfo)
{
	struct nf_conn *ct = (struct nf_conn *)(pInfo->ASFwInfo);
	struct net *net = nf_ct_net(ct);
	struct nf_conntrack_tuple *ct_tuple_orig, *ct_tuple_reply;
	struct sk_buff *skb;
	struct iphdr *iph;
	struct tcphdr *tcph;
	struct udphdr *udph;
	uint32_t	result;
	struct net_device *dev;
	uint32_t uldestIp;
	uint16_t usdport;
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	ASFFFPCreateFlowsInfo_t cmd1;
	bool bIPsecIn = 0, bIPsecOut = 0;
	struct flowi fl_out;
#endif
	ASFCTRL_FUNC_ENTRY;

	ct_tuple_orig = tuple(ct, IP_CT_DIR_ORIGINAL);

	ct_tuple_reply = tuple(ct, IP_CT_DIR_REPLY);


	/* Identify whether this flow is DNAT or SNAT */

	if (ct_tuple_orig->dst.u3.ip == pInfo->tuple.ulDestIp) {
		if (pInfo->tuple.ulDestIp == ct_tuple_reply->src.u3.ip) {
			uldestIp = pInfo->tuple.ulDestIp;
			usdport = pInfo->tuple.usDestPort;
		} else {
			uldestIp = ct_tuple_reply->src.u3.ip;
			usdport = ct_tuple_reply->src.u.tcp.port;
		}
	} else {
		if (pInfo->tuple.ulDestIp == ct_tuple_orig->src.u3.ip) {
			uldestIp = pInfo->tuple.ulDestIp;
			usdport = pInfo->tuple.usDestPort;
		} else {
			uldestIp = ct_tuple_orig->src.u3.ip;
			usdport = ct_tuple_orig->src.u.tcp.port;
		}
	}

	skb = alloc_skb(1024, GFP_ATOMIC);
	if (!skb) {
		ASFCTRL_ERR("SKB allocation failed");
		return;
	}

	dev = dev_get_by_name(&init_net, "lo");

	if ((0 != ip_route_input(skb, uldestIp, pInfo->tuple.ulSrcIp, 0, dev))
		|| (skb_rtable(skb)->rt_flags & RTCF_LOCAL)) {
		ASFCTRL_INFO("Route not found for dst %x local host : %d",
			uldestIp,
			(skb_rtable(skb)->rt_flags & RTCF_LOCAL) ? 1 : 0);
		dev_put(dev);
		kfree_skb(skb);
		return;
	}
	dev_put(dev);
	skb->dev = skb_dst(skb)->dev;

	skb_reset_network_header(skb);
	skb_put(skb, sizeof(struct iphdr));
	iph = ip_hdr(skb);
	iph->version = 5;
	iph->ihl = 5;
	iph->ttl = 1;
	iph->saddr = pInfo->tuple.ulSrcIp;
	iph->daddr = uldestIp;
	iph->protocol = pInfo->tuple.ucProtocol;

	skb_reset_transport_header(skb);

	if (pInfo->tuple.ucProtocol == IPPROTO_TCP) {
		tcph = (struct tcphdr *)skb_put(skb, sizeof(struct tcphdr));
		tcph->source = pInfo->tuple.usSrcPort;
		tcph->dest = usdport;

	} else {
		udph = (struct udphdr *)skb_put(skb, sizeof(struct udphdr));
		udph->source = pInfo->tuple.usSrcPort;
		udph->dest = usdport;
	}


	result = ipt_do_table(skb, NF_INET_FORWARD, dev, skb->dev,
			net->ipv4.iptable_filter);
	switch (result) {
	case NF_ACCEPT:
		{
		ASFFFPUpdateFlowParams_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
		cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
		cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
		cmd.tuple.usDestPort =  pInfo->tuple.usDestPort;
		cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;


		cmd.ulZoneId = ASF_DEF_ZN_ID;

		cmd.bFFPConfigIdentityUpdate = 1;

		cmd.u.fwConfigIdentity.ulConfigMagicNumber =
				asfctrl_vsg_config_id;

		if (ASFFFPRuntime(ASF_DEF_VSG,
			ASF_FFP_MODIFY_FLOWS,
			&cmd, sizeof(cmd), NULL, 0) ==
			ASFFFP_RESPONSE_SUCCESS) {
				ASFCTRL_INFO("Flow modified successfully");
		} else {
				ASFCTRL_ERR("Flow modification failure");
		}
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	{
		uint32_t orig_sip = ct_tuple_orig->src.u3.ip;
		uint32_t orig_dip = ct_tuple_orig->dst.u3.ip;
		uint16_t orig_sport = ct_tuple_orig->src.u.tcp.port;
		uint16_t orig_dport = ct_tuple_orig->dst.u.tcp.port;
		uint8_t orig_prot = ct_tuple_orig->dst.protonum;

		memset(&cmd, 0, sizeof(cmd));
		memset(&cmd1, 0, sizeof(cmd1));

		/* Fill command for flow 1 */
		cmd1.flow1.tuple.ucProtocol = orig_prot;
		cmd1.flow1.tuple.ulDestIp = orig_dip;
		cmd1.flow1.tuple.ulSrcIp = orig_sip;
		cmd1.flow1.tuple.usDestPort = orig_dport;
		cmd1.flow1.tuple.usSrcPort = orig_sport;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
		if (fn_ipsec_get_flow4) {
			memset(&fl_out, 0, sizeof(fl_out));
			fl_out.fl_ip_sport = orig_sport;
			fl_out.fl_ip_dport = orig_dport;
			fl_out.proto = orig_prot;
			fl_out.fl4_dst = orig_dip;
			fl_out.fl4_src = orig_sip;
			fl_out.fl4_tos = 0;

			dev = dev_get_by_name(&init_net, "lo");
			net = dev_net(dev);
			fn_ipsec_get_flow4(&bIPsecIn, &bIPsecOut,
				&(cmd1.flow1.ipsecInInfo), net, fl_out);
		}
#endif
		cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
		cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
		cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
		cmd.tuple.usDestPort =  pInfo->tuple.usDestPort;
		cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;

		cmd.u.ipsec.ipsecInfo = cmd1.flow1.ipsecInInfo;
		cmd.u.ipsec.bIPsecIn = bIPsecIn ? 1 : 0;
		cmd.u.ipsec.bIPsecOut = bIPsecOut ? 1 : 0;
		cmd.u.ipsec.bIn = cmd.u.ipsec.bOut = 1;
		cmd.ulZoneId = ASF_DEF_ZN_ID;
		cmd.bIPsecConfigIdentityUpdate = 1;
		cmd.u.fwConfigIdentity.ulConfigMagicNumber =
				asfctrl_vsg_config_id;

		if (ASFFFPRuntime(ASF_DEF_VSG,
			ASF_FFP_MODIFY_FLOWS,
			&cmd, sizeof(cmd), NULL, 0) ==
			ASFFFP_RESPONSE_SUCCESS) {
				ASFCTRL_INFO("Flow modified successfully");
		} else {
				ASFCTRL_WARN("Flow modification failure");
		}
	}
#endif
		break;
		}
	case NF_DROP:
		{
		ASFFFPDeleteFlowsInfo_t cmd;

		memset(&cmd, 0, sizeof(cmd));


		cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
		cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
		cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
		cmd.tuple.usDestPort =  pInfo->tuple.usDestPort;
		cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;


		cmd.ulZoneId = ASF_DEF_ZN_ID;



		if (ASFFFPRuntime(ASF_DEF_VSG,
			ASF_FFP_DELETE_FLOWS,
			&cmd, sizeof(cmd), NULL, 0) ==
			ASFFFP_RESPONSE_SUCCESS) {
				ASFCTRL_INFO("Flow deleted successfully");
		} else {
				ASFCTRL_ERR("Flow deletion failure");
		}
		break;
		}
	}
	ASFCTRL_FUNC_EXIT;
}


ASF_void_t asfctrl_fnAuditLog(ASFLogInfo_t  *pLogInfo)
{
	ASFCTRL_FUNC_ENTRY;
	ASFCTRL_FUNC_EXIT;
}

static int32_t asfctrl_destroy_session(struct nf_conn *ct_event)
{
	struct nf_conntrack_tuple *ct_tuple_orig, *ct_tuple_reply;
	ASFFFPDeleteFlowsInfo_t cmd;

	ASFCTRL_FUNC_ENTRY;

	ct_tuple_orig = tuple(ct_event, IP_CT_DIR_ORIGINAL);

	ct_tuple_reply = tuple(ct_event, IP_CT_DIR_REPLY);


	ASFCTRL_INFO("[1ORIGINAL]proto = %u src ip = " NIPQUAD_FMT
		"/%u dst ip = " NIPQUAD_FMT "/%u\n",
		ct_tuple_orig->dst.protonum,
		NIPQUAD(ct_tuple_orig->src.u3.ip),
		ct_tuple_orig->src.u.tcp.port,
		NIPQUAD(ct_tuple_orig->dst.u3.ip),
		ct_tuple_orig->dst.u.tcp.port);

	ASFCTRL_INFO("[REPLY]proto = %u src ip = " NIPQUAD_FMT
		"/%u dst ip = " NIPQUAD_FMT "/%u\n",
		ct_tuple_reply->dst.protonum,
		NIPQUAD(ct_tuple_reply->src.u3.ip),
		ct_tuple_reply->src.u.tcp.port,
		NIPQUAD(ct_tuple_reply->dst.u3.ip),
		ct_tuple_reply->dst.u.tcp.port);

	memset(&cmd, 0, sizeof(cmd));


	cmd.tuple.ucProtocol = ct_tuple_orig->dst.protonum;
	cmd.tuple.ulDestIp = ct_tuple_orig->dst.u3.ip;
	cmd.tuple.ulSrcIp = ct_tuple_orig->src.u3.ip;
	cmd.tuple.usDestPort = ct_tuple_orig->dst.u.tcp.port;
	cmd.tuple.usSrcPort = ct_tuple_orig->src.u.tcp.port;


	cmd.ulZoneId = ASF_DEF_ZN_ID;



	if (ASFFFPRuntime(ASF_DEF_VSG,
			 ASF_FFP_DELETE_FLOWS,
			 &cmd, sizeof(cmd), NULL, 0) ==
					ASFFFP_RESPONSE_SUCCESS) {
		ASFCTRL_INFO("Flow deleted successfully");
	} else {
		ASFCTRL_ERR("Flow deletion failure");
	}


	ASFCTRL_FUNC_EXIT;
	return 0;
}

static int32_t asfctrl_offload_session(struct nf_conn *ct_event)
{
	struct nf_conntrack_tuple *ct_tuple_orig, *ct_tuple_reply;
	struct net_device *dev;
	struct net *net = NULL;

	ASFCTRL_FUNC_ENTRY;

	/* ALG session cannot be offloaded */
	if (nf_ct_ext_exist(ct_event, NF_CT_EXT_HELPER)) {
		ASFCTRL_INFO("ALG flow.. ignoring");
		return -EINVAL;
	}

	net = ct_event->ct_net;
	ct_tuple_orig = tuple(ct_event, IP_CT_DIR_ORIGINAL);

	ASFCTRL_INFO("[ORIGINAL]proto = %u src ip = " NIPQUAD_FMT
		"/%u dst ip = " NIPQUAD_FMT "/%u\n",
		ct_tuple_orig->dst.protonum,
		NIPQUAD(ct_tuple_orig->src.u3.ip),
		ct_tuple_orig->src.u.tcp.port,
		NIPQUAD(ct_tuple_orig->dst.u3.ip),
		ct_tuple_orig->dst.u.tcp.port);

	ct_tuple_reply = tuple(ct_event, IP_CT_DIR_REPLY);

	ASFCTRL_INFO("[REPLY]proto = %u src ip = " NIPQUAD_FMT
		"/%u dst ip = " NIPQUAD_FMT "/%u\n",
		ct_tuple_reply->dst.protonum,
		NIPQUAD(ct_tuple_reply->src.u3.ip),
		ct_tuple_reply->src.u.tcp.port,
		NIPQUAD(ct_tuple_reply->dst.u3.ip),
		ct_tuple_reply->dst.u.tcp.port);

	/* Non IPv4 session cannot be offloaded */
	if ((ct_tuple_orig->src.l3num != PF_INET)
		|| (ct_tuple_reply->src.l3num != PF_INET)) {

		ASFCTRL_INFO("Non IPv4 connection, ignoring");
		return -EINVAL;
	}

	/* Non  TCT/UDP session cannot be offloaded */
	if ((ct_tuple_orig->dst.protonum != IPPROTO_UDP)
		&& (ct_tuple_orig->dst.protonum != IPPROTO_TCP)
		&& (ct_tuple_reply->dst.protonum != IPPROTO_UDP)
		&& (ct_tuple_reply->dst.protonum != IPPROTO_TCP)) {

		ASFCTRL_INFO("Non TCP/UDP connection, ignoring");
		return -EINVAL;
	}

	/* TCP Non established session cannot be offloaded  */
	if ((ct_tuple_orig->dst.protonum == IPPROTO_TCP)
	&& (ct_event->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED)) {

		ASFCTRL_INFO("Ignoring non-established TCP connection");
		return -EINVAL;
	}

	/* Session originating or terminating
		locally cannot be offloaded  */
	if ((inet_addr_type(net, ct_tuple_orig->src.u3.ip) == RTN_LOCAL)
	|| (inet_addr_type(net, ct_tuple_reply->src.u3.ip) == RTN_LOCAL)) {

		/* Connection with Local IP, no need to do anything */
		dev = ip_dev_find(net, ct_tuple_orig->src.u3.ip);
		if (dev != NULL)
			ASFCTRL_INFO("NH ORIG: local dst if = %s\n", dev->name);
		dev = ip_dev_find(net, ct_tuple_reply->src.u3.ip);
		if (dev != NULL)
			ASFCTRL_INFO("NH ORIG: local src if = %s\n", dev->name);
		return -EINVAL;
	}

	/* multicast/broadcast session cannot be offloaded  */
	if ((inet_addr_type(net, ct_tuple_orig->dst.u3.ip) == RTN_MULTICAST)
	|| (inet_addr_type(net, ct_tuple_orig->dst.u3.ip) == RTN_BROADCAST)
	|| (inet_addr_type(net, ct_tuple_reply->dst.u3.ip) == RTN_MULTICAST)
	|| (inet_addr_type(net, ct_tuple_reply->dst.u3.ip) == RTN_BROADCAST)) {

		ASFCTRL_INFO("Ignoring multicast connection");
		return -EINVAL;
	}


	/* Bad hack: Modify the UDP timer from single floe timeout
	* to double flow timeout
	*/
	if (ct_tuple_orig->dst.protonum == IPPROTO_UDP) {
		nf_ct_refresh(ct_event, (struct sk_buff *)1,
				(asf_ffp_udp_tmout*HZ));
	}

	{ /* New scope */

	ASFFFPCreateFlowsInfo_t cmd;
	bool bIPsecIn = 0, bIPsecOut = 0;
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	struct flowi fl_in, fl_out;
#endif

	uint32_t orig_sip = ct_tuple_orig->src.u3.ip;
	uint32_t orig_dip = ct_tuple_orig->dst.u3.ip;
	uint32_t reply_sip = ct_tuple_reply->src.u3.ip;
	uint32_t reply_dip = ct_tuple_reply->dst.u3.ip;
	uint16_t orig_sport = ct_tuple_orig->src.u.tcp.port;
	uint16_t orig_dport = ct_tuple_orig->dst.u.tcp.port;
	uint16_t reply_sport = ct_tuple_reply->src.u.tcp.port;
	uint16_t reply_dport = ct_tuple_reply->dst.u.tcp.port;
	uint8_t orig_prot = ct_tuple_orig->dst.protonum;
	uint8_t reply_prot = ct_tuple_reply->dst.protonum;
	uint8_t ulCommonInterfaceId = 0;


	memset(&cmd, 0, sizeof(cmd));

	/* Fill command for flow 1 */
	cmd.flow1.tuple.ucProtocol = orig_prot;
	cmd.flow1.tuple.ulDestIp = orig_dip;
	cmd.flow1.tuple.ulSrcIp = orig_sip;
	cmd.flow1.tuple.usDestPort = orig_dport;
	cmd.flow1.tuple.usSrcPort = orig_sport;

	/* Fill command for flow 2 */
	cmd.flow2.tuple.ucProtocol = reply_prot;
	cmd.flow2.tuple.ulDestIp = reply_dip;
	cmd.flow2.tuple.ulSrcIp = reply_sip;
	cmd.flow2.tuple.usDestPort = reply_dport;
	cmd.flow2.tuple.usSrcPort = reply_sport;

	/* Check for NAT */
	if (orig_dport == reply_sport &&
		orig_sport == reply_dport &&
		orig_dip == reply_sip &&
		orig_sip == reply_dip) {
			cmd.flow1.bNAT = 0;
			cmd.flow2.bNAT = 0;
	} else {
			cmd.flow1.bNAT = 1;
			cmd.flow2.bNAT = 1;
	}

	/* This will be used while refereshing the flow activity and
		flow validation */
	cmd.ASFWInfo = (ASF_uint8_t *)ct_event;

	cmd.configIdentity.ulConfigMagicNumber = asfctrl_vsg_config_id;

	cmd.flow1.ulZoneId = ASF_DEF_ZN_ID;

	if (cmd.flow1.tuple.ucProtocol == IPPROTO_TCP) {

		/* TCP state offload for flow 1 */
		struct ip_ct_tcp_state *tcp_state_orig =
			&(ct_event->proto.tcp.seen[IP_CT_DIR_ORIGINAL]);
		 struct ip_ct_tcp_state *tcp_state_reply =
			&(ct_event->proto.tcp.seen[IP_CT_DIR_REPLY]);
		cmd.flow1.ulInacTimeout = asf_ffp_tcp_tmout;
		cmd.flow1.bTcpOutOfSeqCheck = asf_ffp_tcp_state_check;
		cmd.flow1.bTcpTimeStampCheck = asf_ffp_tcp_tm_stmp_check;

		cmd.flow1.ulTcpTimeStamp = tcp_state_orig->td_tcptimestamp;

		cmd.flow1.tcpState.ulHighSeqNum = tcp_state_orig->td_end;
		if (tcp_state_orig->td_delta < 0) {
			cmd.flow1.tcpState.ulSeqDelta =
				-(tcp_state_orig->td_delta);
			cmd.flow1.tcpState.bPositiveDelta = 0;
		} else {
			cmd.flow1.tcpState.ulSeqDelta =
				tcp_state_orig->td_delta;
			cmd.flow1.tcpState.bPositiveDelta = 1;
		}
		cmd.flow1.tcpState.ucWinScaleFactor = 0;
		cmd.flow1.tcpState.ulRcvNext = tcp_state_reply->td_end;
		cmd.flow1.tcpState.ulRcvWin = tcp_state_reply->td_rcvwin;
		cmd.flow1.tcpState.ulMaxRcvWin = tcp_state_reply->td_maxwin;
	} else {
		cmd.flow1.ulInacTimeout = asf_ffp_udp_tmout;
	}


#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_get_flow4) {
		memset(&fl_out, 0, sizeof(fl_out));
		fl_out.fl_ip_sport = orig_sport;
		fl_out.fl_ip_dport = orig_dport;
		fl_out.proto = orig_prot;
		fl_out.fl4_dst = orig_dip;
		fl_out.fl4_src = orig_sip;
		fl_out.fl4_tos = 0;

		dev = dev_get_by_name(&init_net, "lo");
		net = dev_net(dev);
		fn_ipsec_get_flow4(&bIPsecIn, &bIPsecOut,
			&(cmd.flow1.ipsecInInfo),
			net,
			fl_out);
	}
#endif
	cmd.flow1.bIPsecIn = bIPsecIn ? 1 : 0;
	cmd.flow1.bIPsecOut = bIPsecOut ? 1 : 0;

	/* Fill the command for flow 2 */
	cmd.flow2.ulZoneId = ASF_DEF_ZN_ID;

	if (cmd.flow2.tuple.ucProtocol == IPPROTO_TCP) {
		/* TCP state offload for flow 2 */
		struct ip_ct_tcp_state *tcp_state_orig =
			&(ct_event->proto.tcp.seen[IP_CT_DIR_ORIGINAL]);
		struct ip_ct_tcp_state *tcp_state_reply =
			&(ct_event->proto.tcp.seen[IP_CT_DIR_REPLY]);
		cmd.flow2.ulInacTimeout = asf_ffp_tcp_tmout;
		cmd.flow2.bTcpOutOfSeqCheck = asf_ffp_tcp_state_check;
		cmd.flow2.bTcpTimeStampCheck = asf_ffp_tcp_tm_stmp_check;

		cmd.flow2.ulTcpTimeStamp = tcp_state_reply->td_tcptimestamp;

		cmd.flow2.tcpState.ulHighSeqNum = tcp_state_reply->td_end;
		if (tcp_state_reply->td_delta < 0) {
			cmd.flow2.tcpState.ulSeqDelta =
				-(tcp_state_reply->td_delta);
			cmd.flow2.tcpState.bPositiveDelta = 0;
		} else {
			cmd.flow2.tcpState.ulSeqDelta =
				tcp_state_reply->td_delta;
			cmd.flow2.tcpState.bPositiveDelta = 1;
		}
		cmd.flow2.tcpState.ucWinScaleFactor = 0;
		cmd.flow2.tcpState.ulRcvNext = tcp_state_orig->td_end;
		cmd.flow2.tcpState.ulRcvWin = tcp_state_orig->td_rcvwin;
		cmd.flow2.tcpState.ulMaxRcvWin = tcp_state_orig->td_maxwin;
	} else {
		cmd.flow2.ulInacTimeout = asf_ffp_udp_tmout;
	}

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_get_flow4) {
		memset(&fl_in, 0, sizeof(fl_out));
		fl_in.fl_ip_sport = reply_sport;
		fl_in.fl_ip_dport = reply_dport;
		fl_in.proto = reply_prot;
		fl_in.fl4_dst = reply_dip;
		fl_in.fl4_src = reply_sip;
		fl_in.fl4_tos = 0;


		fn_ipsec_get_flow4(&bIPsecIn, &bIPsecOut,
				&(cmd.flow2.ipsecInInfo),
				net,
				fl_in);
	}
#endif
	cmd.flow2.bIPsecIn = bIPsecIn ? 1 : 0;
	cmd.flow2.bIPsecOut = bIPsecOut ? 1 : 0;

	if (cmd.flow1.bNAT) {
		ASFCTRL_INFO("\nNAT Enabled\n ");
		cmd.flow1.natInfo.ulDestNATIp = reply_sip;
		cmd.flow1.natInfo.ulSrcNATIp = reply_dip;
		cmd.flow1.natInfo.usDestNATPort = reply_sport;
		cmd.flow1.natInfo.usSrcNATPort = reply_dport;

		cmd.flow2.natInfo.ulDestNATIp = orig_sip;
		cmd.flow2.natInfo.ulSrcNATIp = orig_dip;
		cmd.flow2.natInfo.usDestNATPort = orig_sport;
		cmd.flow2.natInfo.usSrcNATPort = orig_dport;
	}

	if (ASFFFPRuntime(ASF_DEF_VSG,
			 ASF_FFP_CREATE_FLOWS,
			 &cmd, sizeof(cmd), NULL, 0) ==
					ASFFFP_RESPONSE_SUCCESS) {
		/* Flow created successfully. populate the L2 info*/
		uint32_t flow1_dip, flow2_dip;

		ASFCTRL_INFO("Flow created successfully in ASF");

		if (cmd.flow1.bNAT) {
			flow1_dip =  cmd.flow1.natInfo.ulDestNATIp;
			flow2_dip = cmd.flow2.natInfo.ulDestNATIp;
		} else {
			flow1_dip = cmd.flow1.tuple.ulDestIp;
			flow2_dip = cmd.flow2.tuple.ulDestIp;
		}


		asf_linux_XmitL2blobDummyPkt(0, 0, &cmd.flow1.tuple,
					cmd.flow1.tuple.ulSrcIp,
					flow1_dip,
					0, 0, ulCommonInterfaceId);
		asf_linux_XmitL2blobDummyPkt(0, 0, &cmd.flow2.tuple,
					cmd.flow2.tuple.ulSrcIp,
					flow2_dip,
					0, 0, ulCommonInterfaceId);
		/* Session is offloaded successfuly,
		** Mark the offload status bit is status bit
		** this will be used when destroy event come */
		ct_event->status |= IPS_ASF_OFFLOADED;
	} else {
		/* Error hanling */
		ASFCTRL_WARN("Flow creation failure in ASF");
	}

	} /* New scope end */


	ASFCTRL_FUNC_EXIT;
	return 0;
}

static int asfctrl_conntrack_event(unsigned int events, struct nf_ct_event *ptr)
{
	struct nf_conn *ct = (struct nf_conn *)ptr->ct;
	struct nf_conntrack_tuple *ct_tuple = tuple(ct, IP_CT_DIR_ORIGINAL);

	ASFCTRL_FUNC_ENTRY;

	if (events & (1 << IPCT_DESTROY)) {
		ASFCTRL_INFO("IPCT_DESTROY!");
		/* Remove the connection if its previously offloaded */
		if (ct->status & IPS_ASF_OFFLOADED) {
			asfctrl_destroy_session(ct);
			/* Clear the IPS_ASF_OFFLOADED bit */
			ct->status &= ~IPS_ASF_OFFLOADED;
		} else
			ASFCTRL_INFO("Destroy event for non offloaded session");
	} else if (events & ((1 << IPCT_NEW) | (1 << IPCT_RELATED))) {
		ASFCTRL_INFO("IPCT_NEW!");
		/* Special case for handling UDP streaming */
		if (ct_tuple->dst.protonum == IPPROTO_UDP) {
			ASFCTRL_INFO("UDP flow");
			asfctrl_offload_session(ct);
		}
	} else if (events & (1 << IPCT_STATUS)) {
		ASFCTRL_INFO("IPCT_STATUS!");
		/* Offload the connection if status is assured */
		if ((ct_tuple->dst.protonum == IPPROTO_TCP) &&
			(ct->status & IPS_ASSURED)) {
			ASFCTRL_INFO("TCP flow");
			asfctrl_offload_session(ct);
		}
	} else {
		ASFCTRL_INFO("DEFAULT event! {0x%x} ", events);
	}

	ASFCTRL_FUNC_EXIT;
	return NOTIFY_DONE;
}

static struct nf_ct_event_notifier asfctrl_conntrack_event_nb = {
	.fcn = asfctrl_conntrack_event
};

struct kobject *asfctrl_ffp_kobj;

static ssize_t asfctrl_ffp_udp_tmout_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", asf_ffp_udp_tmout);
}
static ssize_t asfctrl_ffp_udp_tmout_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	sscanf(buf, "%u", &asf_ffp_udp_tmout);
	return count;
}

static ssize_t asfctrl_ffp_tcp_tmout_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", asf_ffp_tcp_tmout);
}
static ssize_t asfctrl_ffp_tcp_tmout_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	sscanf(buf, "%u", &asf_ffp_tcp_tmout);
	return count;
}

static ssize_t asfctrl_ffp_tcp_state_check_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", asf_ffp_tcp_state_check);
}
static ssize_t asfctrl_ffp_tcp_state_check_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	sscanf(buf, "%u", &asf_ffp_tcp_state_check);
	return count;
}

static ssize_t asfctrl_ffp_tcp_tm_stmp_check_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", asf_ffp_tcp_tm_stmp_check);
}
static ssize_t asfctrl_ffp_tcp_tm_stmp_check_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	sscanf(buf, "%u", &asf_ffp_tcp_tm_stmp_check);
	return count;
}

static ssize_t asfctrl_ffp_activity_divisor_show(struct kobject *kobj,
					struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%u\n", asf_ffp_activity_divisor);
}
static ssize_t asfctrl_ffp_activity_divisor_store(struct kobject *kobj,
					struct kobj_attribute *attr,
					const char *buf, size_t count)
{
	sscanf(buf, "%u", &asf_ffp_activity_divisor);
	return count;
}




static struct kobj_attribute asfctrl_ffp_udp_tmout_attr = \
	__ATTR(asfctrl_ffp_udp_tmout, 0644,
		asfctrl_ffp_udp_tmout_show, asfctrl_ffp_udp_tmout_store);

static struct kobj_attribute asfctrl_ffp_tcp_tmout_attr = \
	__ATTR(asfctrl_ffp_tcp_tmout, 0644,
		asfctrl_ffp_tcp_tmout_show, asfctrl_ffp_tcp_tmout_store);

static struct kobj_attribute asfctrl_ffp_tcp_state_check_attr = \
	__ATTR(asfctrl_ffp_tcp_state_check, 0644,
		asfctrl_ffp_tcp_state_check_show,
		asfctrl_ffp_tcp_state_check_store);

static struct kobj_attribute asfctrl_ffp_tcp_tm_stmp_check_attr = \
	__ATTR(asfctrl_ffp_tcp_tm_stmp_check, 0644,
		asfctrl_ffp_tcp_tm_stmp_check_show,
		asfctrl_ffp_tcp_tm_stmp_check_store);

static struct kobj_attribute asfctrl_ffp_activity_divisor_attr = \
	__ATTR(asfctrl_ffp_activity_divisor, 0644,
		asfctrl_ffp_activity_divisor_show,
		asfctrl_ffp_activity_divisor_store);




static struct attribute *asfctrl_ffp_attrs[] = {
	&asfctrl_ffp_udp_tmout_attr.attr,
	&asfctrl_ffp_tcp_tmout_attr.attr,
	&asfctrl_ffp_tcp_state_check_attr.attr,
	&asfctrl_ffp_tcp_tm_stmp_check_attr.attr,
	&asfctrl_ffp_activity_divisor_attr.attr,
	NULL
};

static struct attribute_group asfctrl_ffp_attr_group = {
	.attrs = asfctrl_ffp_attrs,
};


void ffp_sysfs_init(void)
{

	int error;

	asfctrl_ffp_kobj = kobject_create_and_add("ffp", asfctrl_kobj);
	if (!asfctrl_ffp_kobj) {
		ASFCTRL_ERR("ffp kobject creation failed");
		goto exit;
	}

	error = sysfs_create_group(asfctrl_ffp_kobj, &asfctrl_ffp_attr_group);
	if (error)
		goto ffp_attr_exit;

	return;

ffp_attr_exit:
	kobject_put(asfctrl_ffp_kobj);
exit:
	return;
}

void ffp_sysfs_exit(void)
{
	sysfs_remove_group(asfctrl_ffp_kobj, &asfctrl_ffp_attr_group);
	kobject_put(asfctrl_ffp_kobj);
}

void asfctrl_linux_register_ffp(void)
{
	ASFFFPInacRefreshParams_t inacCmd;
	struct firewall_asfctrl fwasfctrl;

	ASFCTRL_FUNC_ENTRY;

	need_ipv4_conntrack();
	if (nf_conntrack_register_notifier(&asfctrl_conntrack_event_nb) < 0) {
		ASFCTRL_ERR("Register conntrack notifications failed!");
		return ;
	}


	fwasfctrl.firewall_asfctrl_cb = asfctrl_invalidate_sessions;
	hook_firewall_asfctrl_cb(&fwasfctrl);

	inacCmd.ulDivisor = asf_ffp_activity_divisor;
	ASFFFPSetInacRefreshParams(&inacCmd);
	/* L2blob refresh params
	 after each VSG addition.
	frag ctrl params
	TCP control params
	 */
	/* create the /sys/asfctrl/ffp directory */
	ffp_sysfs_init();


	ASFCTRL_FUNC_EXIT;
	return;
}

void asfctrl_linux_unregister_ffp(void)
{
	struct firewall_asfctrl fwasfctrl;
	ASFCTRL_FUNC_ENTRY;

	fwasfctrl.firewall_asfctrl_cb = NULL;

	hook_firewall_asfctrl_cb(&fwasfctrl);

	nf_conntrack_unregister_notifier(&asfctrl_conntrack_event_nb);

	ASFCTRL_FUNC_EXIT;
	return;
}
