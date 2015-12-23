/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_linux_ffp.c
 *
 * Description: Control module for Configuring ASF and integrating it with
 * Linux Networking Stack for Firewall/NAT function
 *
 * Authors:	Arun Pathak <Arun.Pathak@freescale.com>
 *
 */
/*
 * History
 *  Version     Date         Author              Change Description
 *  1.0        20/09/2010    Arun Pathak      Initial Development
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
#ifdef ASFCTRL_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#ifdef ASFCTRL_SCTP_SUPPORT
#include <linux/sctp.h>
#endif
#include <net/dst.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>

#include "../../../asfffp/driver/asf.h"
#include "../../../asfffp/driver/asfcmn.h"
#include "asfctrl.h"

#define tuple(ct, dir) (&(ct)->tuplehash[dir].tuple)

ASFFFPCap_t	g_fw_cap;

static uint32_t asf_ffp_udp_tmout = ASF_UDP_INAC_TMOUT;
static uint32_t asf_ffp_tcp_tmout = ASF_TCP_INAC_TMOUT;
static uint32_t asf_ffp_tcp_state_check = ASFCTRL_TRUE;
static uint32_t asf_ffp_tcp_tm_stmp_check = ASFCTRL_TRUE;
static uint32_t asf_ffp_activity_divisor = DEFVAL_INACTIVITY_DIVISOR;

module_param(asf_ffp_tcp_state_check, int, 0644);
MODULE_PARM_DESC(asf_ffp_tcp_state_check, "Drop TCP out of sequence packets");

static ASF_int32_t asf_linux_XmitL2blobDummyPkt(
				ASF_uint32_t ulVsgId,
				ASF_uint32_t ulZoneId,
				ASFFFPFlowTuple_t *tpl,
				ASF_IPv4Addr_t    ulSrcIp,
				ASF_IPv4Addr_t    uldestIp,
				ASF_uint32_t tos,
				ASF_uint32_t ulHashVal,
				ASF_uint32_t ulCII)
{
	struct sk_buff *skb;
	asf_linux_L2blobPktData_t *pData;
	struct iphdr *iph;
	struct flowi4 fl = {};
	struct rtable *rt;
	static unsigned short IPv4_IDs[NR_CPUS];

	ASFCTRL_FUNC_ENTRY;

	fl.daddr = uldestIp;
	fl.saddr = ulSrcIp;
	fl.flowi4_oif = 0;
	fl.flowi4_flags = FLOWI_FLAG_ANYSRC;

	rt = ip_route_output_key(&init_net, &fl);
	if (IS_ERR(rt)) {
		ASFCTRL_INFO("Route not found for dst %x\n", uldestIp);
		return T_FAILURE;
	}
	ASFCTRL_INFO("Route found for dst %x ", uldestIp);

	skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
	if (!skb)
		return T_FAILURE;

	skb_dst_set(skb, &(rt->dst));
	skb->dev = skb_dst(skb)->dev;
	skb_reserve(skb, LL_RESERVED_SPACE(skb->dev));
	skb_reset_network_header(skb);
	skb_put(skb, sizeof(struct iphdr));
	iph = ip_hdr(skb);
	iph->version = 5;
	iph->ihl = 5;
	iph->ttl = 1;
	iph->id = ASF_HTONS(IPv4_IDs[smp_processor_id()]++);
	iph->tos = 0;
	iph->frag_off = 0;
	iph->saddr = ulSrcIp;
	iph->daddr = uldestIp;
	iph->protocol = ASFCTRL_IPPROTO_DUMMY_L2BLOB;
	pData = (asf_linux_L2blobPktData_t *)skb_put(skb,
				sizeof(asf_linux_L2blobPktData_t));
	pData->ulZoneId = 0;
	pData->ulVsgId = ulVsgId;
	memcpy(&pData->tuple, tpl, sizeof(ASFFFPFlowTuple_t));

	pData->ulPathMTU = skb->dev->mtu;
	skb->protocol = ASF_HTONS(ETH_P_IP);
	asfctrl_skb_mark_dummy(skb);

	asf_ip_send(skb);

	ASFCTRL_FUNC_EXIT;

	return T_SUCCESS;
}

static ASF_int32_t asf_linux_IPv6XmitL2blobDummyPkt(
				ASF_uint32_t ulVsgId,
				ASF_uint32_t ulZoneId,
				ASFFFPFlowTuple_t *tpl,
				struct in6_addr    *ipv6SrcIp,
				struct in6_addr    *ipv6DestIp,
				ASF_uint32_t priority,
				ASF_uint32_t ulHashVal,
				ASF_uint32_t ulCII)
{
	struct sk_buff *skb;
	asf_linux_L2blobPktData_t *pData;
	struct ipv6hdr *iph;
	struct net_device *dev;

	ASFCTRL_FUNC_ENTRY;

	skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
	if (!skb)
		return T_FAILURE;


	/*	ASFCTRL_INFO("Route found for dst %x ", uldestIp); */

	skb_reserve(skb, 64);
	skb_reset_network_header(skb);
	skb_put(skb, sizeof(struct ipv6hdr));
	iph = ipv6_hdr(skb);
	iph->version = 5;
	iph->hop_limit = 1;
	iph->priority = 0;
	ipv6_addr_copy((struct in6_addr *)&(iph->saddr), (struct in6_addr *)ipv6SrcIp);
	ipv6_addr_copy((struct in6_addr *)&(iph->daddr), (struct in6_addr *)ipv6DestIp);
	iph->nexthdr = ASFCTRL_IPPROTO_DUMMY_L2BLOB;

	dev = dev_get_by_name(&init_net, "lo");
	skb->dev = dev;
	ip6_route_input(skb);
	if (skb_dst(skb)->error || (skb_dst(skb)->dev->flags & IFF_LOOPBACK)) {
		ASFCTRLKernelSkbFree(skb);
		return T_FAILURE;
	}

	dev_put(dev);
	skb->dev = skb_dst(skb)->dev;


	/* need to check for error and local route */

	pData = (asf_linux_L2blobPktData_t *)skb_put(skb,
				sizeof(asf_linux_L2blobPktData_t));
	pData->ulZoneId = 0;
	pData->ulVsgId = ulVsgId;
	memcpy(&pData->tuple, tpl, sizeof(ASFFFPFlowTuple_t));

	pData->ulPathMTU = skb->dev->mtu;
	skb->protocol = ASF_HTONS(ETH_P_IPV6);
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
	ASFCTRL_netif_receive_skb(skb);

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
	ASFCTRL_netif_receive_skb(skb);

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
		/* Just to remove the warning */
		pInfo = pInfo;

		ASFCTRL_INFO("CreateFlows Response (Result %d) hash %d\n",
			ASF_NTOHL(pInfo->iResult), pInfo->ulHashVal);
	}
	break;

	case ASF_FFP_DELETE_FLOWS:
	{
		ASFFFPDeleteFlowsResp_t *pInfo =
			(ASFFFPDeleteFlowsResp_t *)pResp;
		pInfo = pInfo;

		ASFCTRL_INFO("DeleteFlows Response (Result %d)\n",
			ASF_NTOHL(pInfo->iResult));
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
	if (pInfo->flowTuple.bIPv4OrIPv6 == 1) {
		asf_linux_IPv6XmitL2blobDummyPkt(ulVSGId, pInfo->ulZoneId,
				&pInfo->flowTuple, (struct in6_addr *)(pInfo->flowTuple.ipv6SrcIp),
				(struct in6_addr *)(pInfo->packetTuple.ipv6DestIp), 0,
				pInfo->ulHashVal, 0);
	} else {
		asf_linux_XmitL2blobDummyPkt(ulVSGId, pInfo->ulZoneId,
				&pInfo->flowTuple, pInfo->flowTuple.ulSrcIp,
				pInfo->packetTuple.ulDestIp, 0,
				pInfo->ulHashVal, 0);
	}

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
		ulTimeout = 2*60;
		break;

	case ASF_FFP_TCP_STATE_RST_RCVD:
		uTcpState = TCP_CONNTRACK_CLOSE;
		ulTimeout = 10;
		break;

	case ASF_FFP_TCP_STATE_FIN_COMP:
		uTcpState = TCP_CONNTRACK_TIME_WAIT;
		ulTimeout = 2*60;
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
	struct ipv6hdr *ipv6h;
	struct tcphdr *tcph;
	struct udphdr *udph;
	int	result;
	struct net_device *dev;
	uint32_t uldestIp;
	uint16_t usdport = pInfo->tuple.usDestPort;
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	bool bIPsecIn = 0, bIPsecOut = 0;
	struct flowi fl_out;
#endif
	bool	bIPv6;
	ASFCTRL_FUNC_ENTRY;


	ct_tuple_orig = tuple(ct, IP_CT_DIR_ORIGINAL);

	ct_tuple_reply = tuple(ct, IP_CT_DIR_REPLY);

	bIPv6 = pInfo->tuple.bIPv4OrIPv6 == 1 ? true : false;
	/* Identify whether this flow is DNAT or SNAT */

	skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
	if (!skb) {
		ASFCTRL_ERR("SKB allocation failed");
		return;
	}

	if (bIPv6 == true) {
		skb_reset_network_header(skb);
		skb_put(skb, sizeof(struct ipv6hdr));
		ipv6h = ipv6_hdr(skb);
		ipv6h->version = 5;
		ipv6h->hop_limit = 1;
		ipv6h->priority = 0;
		ipv6_addr_copy((struct in6_addr *)&(ipv6h->saddr), (struct in6_addr *)&(pInfo->tuple.ipv6SrcIp));
		ipv6_addr_copy((struct in6_addr *)&(ipv6h->daddr), (struct in6_addr *)&(pInfo->tuple.ipv6DestIp));
		ipv6h->nexthdr = pInfo->tuple.ucProtocol;

		dev = dev_get_by_name(&init_net, "lo");
		skb->dev = dev;
		ip6_route_input(skb);
		dev_put(dev);
		if (!skb_dst(skb))
			return;
		skb->dev = skb_dst(skb)->dev;
	} else { /* IPv4 case */
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
		dev = pInfo->idev;

		if ((0 != ip_route_input(skb, uldestIp, pInfo->tuple.ulSrcIp, 0, dev))
			|| (skb_rtable(skb)->rt_flags & RTCF_LOCAL)) {
			ASFCTRL_INFO("Route not found for dst %x local host : %d",
			uldestIp,
			(skb_rtable(skb)->rt_flags & RTCF_LOCAL) ? 1 : 0);
			dev_put(dev);
			ASFCTRLKernelSkbFree(skb);
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
	}

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
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv6 == true) {
		result = ip6t_do_table(skb, NF_INET_FORWARD, dev, skb->dev,
				net->ipv6.ip6table_filter);
	} else
#endif
		result = ipt_do_table(skb, NF_INET_FORWARD, dev, skb->dev,
				net->ipv4.iptable_filter);
	ASFCTRLKernelSkbFree(skb);

	switch (result) {
	case NF_ACCEPT:
		{
		ASFFFPUpdateFlowParams_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;

		if (bIPv6 == true) {
			ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6SrcIp, (struct in6_addr *)&(pInfo->tuple.ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6DestIp, (struct in6_addr *)&(pInfo->tuple.ipv6DestIp));
		} else {
			cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
			cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
		}
		cmd.tuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;
		cmd.tuple.usDestPort =  pInfo->tuple.usDestPort;
		cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;


		cmd.ulZoneId = ASF_DEF_ZN_ID;

		cmd.bFFPConfigIdentityUpdate = 1;
		cmd.bDrop = 0;

		cmd.u.fwConfigIdentity.ulConfigMagicNumber =
				asfctrl_vsg_config_id[ulVSGId];

#ifdef ASF_INGRESS_MARKER
		if (pASFCbFnQosMarker_p) {
			if (bIPv6)
				cmd.mkinfo.uciDscp = pASFCbFnQosMarker_p(
						cmd.tuple.ipv6SrcIp,
						cmd.tuple.ipv6DestIp,
						cmd.tuple.usSrcPort,
						cmd.tuple.usDestPort,
						cmd.tuple.ucProtocol,
						bIPv6);
			else
				cmd.mkinfo.uciDscp = pASFCbFnQosMarker_p(
						&cmd.tuple.ulSrcIp,
						&cmd.tuple.ulDestIp,
						cmd.tuple.usSrcPort,
						cmd.tuple.usDestPort,
						cmd.tuple.ucProtocol,
						bIPv6);
		} else
			cmd.mkinfo.uciDscp = ASF_QM_NULL_DSCP;
#endif
		if (ASFFFPRuntime(ulVSGId,
			ASF_FFP_MODIFY_FLOWS,
			&cmd, sizeof(cmd), NULL, 0) ==
			ASFFFP_RESPONSE_SUCCESS) {
				ASFCTRL_INFO("Flow modified successfully");
		} else {
				ASFCTRL_ERR("Flow modification failure");
		}
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
		if (fn_ipsec_get_flow4) {

			memset(&cmd, 0, sizeof(cmd));

			memset(&fl_out, 0, sizeof(fl_out));
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
			fl_out.fl_ip_sport = pInfo->tuple.usSrcPort;
			fl_out.fl_ip_dport = pInfo->tuple.usDestPort;
			fl_out.proto = pInfo->tuple.ucProtocol;
			if (bIPv6 == true) {
				ipv6_addr_copy(&fl_out.fl6_src, &(pInfo->tuple.ipv6SrcIp));
				ipv6_addr_copy(&fl_out.fl6_dst, &(pInfo->tuple.ipv6DestIp));
			} else {
				fl_out.fl4_src = pInfo->tuple.ulSrcIp;
				fl_out.fl4_dst = pInfo->tuple.ulDestIp;
			}
			fl_out.fl4_tos = 0;
		#else
			fl_out.u.ip4.fl4_sport = pInfo->tuple.usSrcPort;
			fl_out.u.ip4.fl4_dport = pInfo->tuple.usDestPort;
			fl_out.flowi_proto = pInfo->tuple.ucProtocol;
			if (bIPv6 == true) {
				ipv6_addr_copy(&fl_out.u.ip6.saddr,
				(struct in6_addr *)&(pInfo->tuple.ipv6SrcIp));
				ipv6_addr_copy(&fl_out.u.ip6.daddr,
				(struct in6_addr *)&(pInfo->tuple.ipv6DestIp));
			} else {
				fl_out.u.ip4.daddr = pInfo->tuple.ulDestIp;
				fl_out.u.ip4.saddr = pInfo->tuple.ulSrcIp;
			}
			fl_out.flowi_tos = 0;
		#endif
			result = fn_ipsec_get_flow4(ulVSGId, &bIPsecIn,
				&bIPsecOut, &cmd.u.ipsec.ipsecInfo, net,
				fl_out, bIPv6);
			if (result) {
				ASFCTRL_INFO("IPSEC Not Offloadable for flow");
				goto delete_flow;
			}
			if (bIPv6 == true) {
				ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6SrcIp,
				 (struct in6_addr *)&(pInfo->tuple.ipv6SrcIp));
				ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6DestIp,
				(struct in6_addr *)&(pInfo->tuple.ipv6DestIp));
			} else {
				cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
				cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
			}
			/* No need to update the IPsec src natInfo */
			cmd.tuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;
			cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
			cmd.tuple.usDestPort =  pInfo->tuple.usDestPort;
			cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;

			cmd.bIPsecConfigIdentityUpdate = 1;

			cmd.u.ipsec.bIPsecIn = bIPsecIn ? 1 : 0;
			cmd.u.ipsec.bIPsecOut = bIPsecOut ? 1 : 0;
			cmd.u.ipsec.bIn = cmd.u.ipsec.bOut = 1;
			cmd.ulZoneId = ASF_DEF_ZN_ID;

			ASFCTRL_INFO("Configured tunnel ID is %d ",
			cmd.u.ipsec.ipsecInfo.outContainerInfo.ulTunnelId);
			if (ASFFFPRuntime(ulVSGId,
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
			ASFFFPUpdateFlowParams_t cmd;

			memset(&cmd, 0, sizeof(cmd));

			if (bIPv6 == true) {
				ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6SrcIp, (struct in6_addr *)&(pInfo->tuple.ipv6SrcIp));
				ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6DestIp, (struct in6_addr *)&(pInfo->tuple.ipv6DestIp));
			} else {
				cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
				cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
			}
			cmd.tuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;
			cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
			cmd.tuple.usDestPort =  pInfo->tuple.usDestPort;
			cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;


			cmd.ulZoneId = ASF_DEF_ZN_ID;

			cmd.bFFPConfigIdentityUpdate = 1;
			cmd.bDrop = 1;

			cmd.u.fwConfigIdentity.ulConfigMagicNumber =
				asfctrl_vsg_config_id[ulVSGId];

			if (ASFFFPRuntime(ulVSGId,
						ASF_FFP_MODIFY_FLOWS,
						&cmd, sizeof(cmd), NULL, 0) ==
					ASFFFP_RESPONSE_SUCCESS) {
				ASFCTRL_INFO("Flow modified successfully");
			} else {
				ASFCTRL_ERR("Flow modification failure");
			}
		}
	}
	ASFCTRL_FUNC_EXIT;
	return;
delete_flow:
	{
		ASFFFPDeleteFlowsInfo_t cmd;

		memset(&cmd, 0, sizeof(cmd));

		cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
		if (bIPv6 == true) {
			ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6SrcIp, (struct in6_addr *)&(pInfo->tuple.ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&cmd.tuple.ipv6DestIp, (struct in6_addr *)&(pInfo->tuple.ipv6DestIp));
		} else {
			cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
			cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
		}
		cmd.tuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;
		cmd.tuple.usDestPort =  pInfo->tuple.usDestPort;
		cmd.tuple.usSrcPort = pInfo->tuple.usSrcPort;

		cmd.ulZoneId = ASF_DEF_ZN_ID;

		if (ASFFFPRuntime(ulVSGId,
			ASF_FFP_DELETE_FLOWS,
			&cmd, sizeof(cmd), NULL, 0) ==
			ASFFFP_RESPONSE_SUCCESS) {
				ASFCTRL_INFO("Flow deleted successfully");
		} else {
				ASFCTRL_ERR("Flow deletion failure");
		}
	}
	ASFCTRL_FUNC_EXIT;
}


ASF_void_t asfctrl_fnAuditLog(ASFLogInfo_t  *pLogInfo)
{
	ASFCTRL_FUNC_ENTRY;
	ASFCTRL_FUNC_EXIT;
}

ASF_uint32_t asfctrl_get_nf_conn_vsgid(struct nf_conn *nf_conn)
{
	/* TODO: Get proper VSG ID */
	return ASF_DEF_VSG;
}
static int32_t asfctrl_destroy_session(struct nf_conn *ct_event)
{
	struct nf_conntrack_tuple *ct_tuple_orig, *ct_tuple_reply;
	ASFFFPDeleteFlowsInfo_t cmd;
	bool pf_ipv6 = 0;
	ASF_uint32_t ulVSGId;

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

	if ((ct_tuple_orig->src.l3num == PF_INET6) &&
		(ct_tuple_reply->src.l3num == PF_INET6)) {
		pf_ipv6 = 1;
	}

	memset(&cmd, 0, sizeof(cmd));


	cmd.tuple.ucProtocol = ct_tuple_orig->dst.protonum;
	if (pf_ipv6 == 1) {
		ipv6_addr_copy((struct in6_addr *)&(cmd.tuple.ipv6SrcIp), (struct in6_addr *)&(ct_tuple_orig->src.u3.in6));
		ipv6_addr_copy((struct in6_addr *)&(cmd.tuple.ipv6DestIp), (struct in6_addr *)&(ct_tuple_orig->dst.u3.in6));
	} else {
		cmd.tuple.ulDestIp = ct_tuple_orig->dst.u3.ip;
		cmd.tuple.ulSrcIp = ct_tuple_orig->src.u3.ip;
	}

	cmd.tuple.bIPv4OrIPv6 = pf_ipv6;

	cmd.tuple.usDestPort = ct_tuple_orig->dst.u.tcp.port;
	cmd.tuple.usSrcPort = ct_tuple_orig->src.u.tcp.port;


	cmd.ulZoneId = ASF_DEF_ZN_ID;


	ulVSGId = asfctrl_get_nf_conn_vsgid(ct_event);
	if (ASFFFPRuntime(ulVSGId, ASF_FFP_DELETE_FLOWS,
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
	struct net_device *dev = NULL;
	struct net *net = NULL;
	int result = 0;
	bool pf_ipv6 = false;

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
	if (!((ct_tuple_orig->src.l3num == PF_INET)
		&& (ct_tuple_reply->src.l3num == PF_INET)) &&
		!((ct_tuple_orig->src.l3num == PF_INET6) &&
		(ct_tuple_reply->src.l3num == PF_INET6))) {

		ASFCTRL_INFO("Non IPv4/IPv6 connection, ignoring");
		return -EINVAL;
	}


	if ((ct_tuple_orig->src.l3num == PF_INET6) &&
		(ct_tuple_reply->src.l3num == PF_INET6)) {
		pf_ipv6 = true;
	}

	/* Non  TCT/UDP session cannot be offloaded */
	if ((ct_tuple_orig->dst.protonum != IPPROTO_UDP)
		&& (ct_tuple_orig->dst.protonum != IPPROTO_TCP)
		&& (ct_tuple_reply->dst.protonum != IPPROTO_UDP)
		&& (ct_tuple_reply->dst.protonum != IPPROTO_TCP)
#ifdef ASFCTRL_SCTP_SUPPORT
		&& (ct_tuple_orig->dst.protonum != IPPROTO_SCTP)
		&& (ct_tuple_reply->dst.protonum != IPPROTO_SCTP)
#endif
	) {
		ASFCTRL_INFO("Non TCP/UDP/SCTP connection, ignoring");
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
	if (pf_ipv6 == false) {
		if ((inet_addr_type(net, ct_tuple_orig->src.u3.ip) == RTN_LOCAL)
		|| (inet_addr_type(net, ct_tuple_reply->src.u3.ip) == RTN_LOCAL)) {
			/* Connection with Local IP, no need to do anything */
			ASFCTRL_INFO("Ignoring Local connection");
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
	} else {
		if (ipv6_chk_addr(net, &(ct_tuple_orig->src.u3.in6), NULL, 0)
		|| ipv6_chk_addr(net, &(ct_tuple_reply->src.u3.in6), NULL, 0)) {
			ASFCTRL_INFO("Ignoring Local connection");
			return -EINVAL;
		}
		/* multicast/broadcast session cannot be offloaded  */
		if (!((ipv6_addr_type(&ct_tuple_orig->dst.u3.in6) & IPV6_ADDR_UNICAST)
		&& (ipv6_addr_type(&ct_tuple_reply->dst.u3.in6) & IPV6_ADDR_UNICAST))) {
			ASFCTRL_INFO("Ignoring multicast connection");
			return -EINVAL;
		}
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

	uint32_t orig_sip = 0;
	uint32_t orig_dip = 0;
	uint32_t reply_sip = 0;
	uint32_t reply_dip = 0;

	struct in6_addr ip6_orig_sip;
	struct in6_addr ip6_orig_dip;
	struct in6_addr ip6_reply_sip;
	struct in6_addr ip6_reply_dip;

	uint16_t orig_sport = ct_tuple_orig->src.u.tcp.port;
	uint16_t orig_dport = ct_tuple_orig->dst.u.tcp.port;
	uint16_t reply_sport = ct_tuple_reply->src.u.tcp.port;
	uint16_t reply_dport = ct_tuple_reply->dst.u.tcp.port;
	uint8_t orig_prot = ct_tuple_orig->dst.protonum;
	uint8_t reply_prot = ct_tuple_reply->dst.protonum;
	uint8_t ulCommonInterfaceId = 0;

	ASF_uint32_t ulVSGId;

	if (pf_ipv6 == true) {
		ipv6_addr_copy((struct in6_addr *)&ip6_orig_sip, (struct in6_addr *)&(ct_tuple_orig->src.u3.in6));
		ipv6_addr_copy((struct in6_addr *)&ip6_orig_dip, (struct in6_addr *)&(ct_tuple_orig->dst.u3.in6));
		ipv6_addr_copy((struct in6_addr *)&ip6_reply_sip, (struct in6_addr *)&(ct_tuple_reply->src.u3.in6));
		ipv6_addr_copy((struct in6_addr *)&ip6_reply_dip, (struct in6_addr *)&(ct_tuple_reply->dst.u3.in6));
	} else {
		orig_sip = ct_tuple_orig->src.u3.ip;
		orig_dip = ct_tuple_orig->dst.u3.ip;
		reply_sip = ct_tuple_reply->src.u3.ip;
		reply_dip = ct_tuple_reply->dst.u3.ip;
	}


	memset(&cmd, 0, sizeof(cmd));

	/* Fill command for flow 1 */
	cmd.flow1.tuple.ucProtocol = orig_prot;

	if (pf_ipv6 == true) {
		ipv6_addr_copy((struct in6_addr *)&(cmd.flow1.tuple.ipv6SrcIp), (struct in6_addr *)&ip6_orig_sip);
		ipv6_addr_copy((struct in6_addr *)&(cmd.flow1.tuple.ipv6DestIp), (struct in6_addr *)&ip6_orig_dip);
	} else {
		cmd.flow1.tuple.ulDestIp = orig_dip;
		cmd.flow1.tuple.ulSrcIp = orig_sip;
	}

	cmd.flow1.tuple.bIPv4OrIPv6 = pf_ipv6;

	cmd.flow1.tuple.usDestPort = orig_dport;
	cmd.flow1.tuple.usSrcPort = orig_sport;
#ifdef ASF_INGRESS_MARKER
	if (pASFCbFnQosMarker_p) {
		if (pf_ipv6)
			cmd.flow1.mkinfo.uciDscp = pASFCbFnQosMarker_p(
					cmd.flow1.tuple.ipv6SrcIp,
					cmd.flow1.tuple.ipv6DestIp,
							orig_sport,
							orig_dport,
							orig_prot,
							pf_ipv6);
		else
			cmd.flow1.mkinfo.uciDscp = pASFCbFnQosMarker_p(
							&orig_sip,
							&orig_dip,
							orig_sport,
							orig_dport,
							orig_prot,
							pf_ipv6);
	} else
		cmd.flow1.mkinfo.uciDscp = ASF_QM_NULL_DSCP;
#endif

	/* Fill command for flow 2 */
	cmd.flow2.tuple.ucProtocol = reply_prot;
#ifdef ASF_INGRESS_MARKER
	if (pASFCbFnQosMarker_p) {
		if (pf_ipv6)
			cmd.flow2.mkinfo.uciDscp = pASFCbFnQosMarker_p(
					cmd.flow2.tuple.ipv6SrcIp,
					cmd.flow2.tuple.ipv6DestIp,
							orig_sport,
							orig_dport,
							orig_prot,
							pf_ipv6);
		else
			cmd.flow2.mkinfo.uciDscp = pASFCbFnQosMarker_p(
							&orig_sip,
							&orig_dip,
							orig_sport,
							orig_dport,
							orig_prot,
							pf_ipv6);
	} else
		cmd.flow2.mkinfo.uciDscp = ASF_QM_NULL_DSCP;
#endif


	if (pf_ipv6 == true) {
		ipv6_addr_copy((struct in6_addr *)&(cmd.flow2.tuple.ipv6SrcIp), (struct in6_addr *)&ip6_reply_sip);
		ipv6_addr_copy((struct in6_addr *)&(cmd.flow2.tuple.ipv6DestIp), (struct in6_addr *)&ip6_reply_dip);
	} else {
		cmd.flow2.tuple.ulDestIp = reply_dip;
		cmd.flow2.tuple.ulSrcIp = reply_sip;
	}

	cmd.flow2.tuple.bIPv4OrIPv6 = pf_ipv6;

	cmd.flow2.tuple.usDestPort = reply_dport;
	cmd.flow2.tuple.usSrcPort = reply_sport;

	/* Check for NAT */
	if (pf_ipv6 == false) {
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
	}

       /* Check for Firewall */
	{
		struct net_device *idev = NULL;
		struct sk_buff *skb;
		struct iphdr *iph;
		struct ipv6hdr *ipv6h;
		struct tcphdr *tcph;
		struct udphdr *udph;

		skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
		if (!skb) {
			ASFCTRL_INFO("SKB allocation failed !!\n");
			return -EINVAL;
		}

		if (pf_ipv6 == false) {
			struct flowi4 fl = {};
			struct rtable *rt;

			fl.daddr = ct_tuple_reply->dst.u3.ip;
			fl.saddr = ct_tuple_reply->src.u3.ip;
			fl.flowi4_oif = 0;
			fl.flowi4_flags = FLOWI_FLAG_ANYSRC;
			rt = ip_route_output_key(&init_net, &fl);
			if (IS_ERR(rt)) {
				ASFCTRL_INFO("Route not found dst %x !!\n",
						ct_tuple_reply->dst.u3.ip);
				ASFCTRLKernelSkbFree(skb);
				return -EINVAL;
			}
			skb_dst_set(skb, &(rt->dst));
			skb->dev = skb_dst(skb)->dev;

			idev = dev_get_by_name(&init_net, "lo");
			skb_reset_network_header(skb);
			skb_put(skb, sizeof(struct iphdr));
			iph = ip_hdr(skb);
			iph->version = 5;
			iph->ihl = 5;
			iph->ttl = 1;
			iph->saddr = ct_tuple_reply->src.u3.ip;
			iph->daddr = ct_tuple_reply->dst.u3.ip;
			iph->protocol = ct_tuple_reply->dst.protonum;
		} else {
			skb_reset_network_header(skb);
			skb_put(skb, sizeof(struct ipv6hdr));
			ipv6h = ipv6_hdr(skb);
			ipv6h->version = 5;
			ipv6h->hop_limit = 1;
			ipv6h->priority = 0;
			ipv6_addr_copy((struct in6_addr *)&(ipv6h->saddr),
					(struct in6_addr *)&(ct_tuple_reply->src.u3.in6));
			ipv6_addr_copy((struct in6_addr *)&(ipv6h->daddr),
					(struct in6_addr *)&(ct_tuple_reply->dst.u3.in6));
			ipv6h->nexthdr = ct_tuple_reply->dst.protonum;

			idev = dev_get_by_name(&init_net, "lo");

			skb->dev = idev;
			ip6_route_input(skb);
			dev_put(idev);
			if (!skb_dst(skb)) {
				ASFCTRL_INFO("Route not found dst %x !!\n",
						ct_tuple_reply->dst.u3.ip);
				ASFCTRLKernelSkbFree(skb);
				return -EINVAL;
			}
			skb->dev = skb_dst(skb)->dev;
		}
		skb_reset_transport_header(skb);

		if (ct_tuple_reply->dst.protonum == IPPROTO_TCP) {
			tcph = (struct tcphdr *)skb_put(skb,
					sizeof(struct tcphdr));
			tcph->source = ct_tuple_reply->src.u.tcp.port;
			tcph->dest = ct_tuple_reply->dst.u.tcp.port;

		} else {
			udph = (struct udphdr *)skb_put(skb,
					sizeof(struct udphdr));
			udph->source = ct_tuple_reply->src.u.udp.port;
			udph->dest = ct_tuple_reply->dst.u.udp.port;
		}

#ifdef ASF_IPV6_FP_SUPPORT
		if (pf_ipv6 == true) {
			result = ip6t_do_table(skb, NF_INET_FORWARD, idev,
					skb->dev, net->ipv6.ip6table_filter);
		} else
#endif
			result = ipt_do_table(skb, NF_INET_FORWARD, idev,
					skb->dev, net->ipv4.iptable_filter);

		ASFCTRLKernelSkbFree(skb);

		if (result) {
			ASFCTRL_INFO("Firewall bDrop bit not set !!\n");
			cmd.flow2.bDrop = 0;
		} else {
			ASFCTRL_INFO("Firewall bDrop bit is set !!\n");
			cmd.flow2.bDrop = 1;
		}
	}


	/* This will be used while refereshing the flow activity and
		flow validation */
	cmd.ASFWInfo = (ASF_uint8_t *)ct_event;

	ulVSGId = asfctrl_get_nf_conn_vsgid(ct_event);
	cmd.configIdentity.ulConfigMagicNumber = asfctrl_vsg_config_id[ulVSGId];

	cmd.configIdentity.l2blobConfig.ulL2blobMagicNumber =
			asfctrl_vsg_l2blobconfig_id[ulVSGId];

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
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		fl_out.fl_ip_sport = reply_dport;
		fl_out.fl_ip_dport = reply_sport;
		fl_out.proto = orig_prot;
		if (pf_ipv6 == true) {
			ipv6_addr_copy(&fl_out.fl6_dst, &ip6_reply_sip);
			ipv6_addr_copy(&fl_out.fl6_src, &ip6_reply_dip);
		} else {
			fl_out.fl4_dst = reply_sip;
			fl_out.fl4_src = reply_dip;
		}
		fl_out.fl4_tos = 0;
	#else
		fl_out.u.ip4.fl4_sport = reply_dport;
		fl_out.u.ip4.fl4_dport = reply_sport;
		fl_out.flowi_proto = orig_prot;
		if (pf_ipv6 == true) {
			ipv6_addr_copy(&fl_out.u.ip6.daddr, &ip6_reply_sip);
			ipv6_addr_copy(&fl_out.u.ip6.saddr, &ip6_reply_dip);
		} else {
			fl_out.u.ip4.daddr = reply_sip;
			fl_out.u.ip4.saddr = reply_dip;
		}
		fl_out.flowi_tos = 0;
	#endif

		dev = dev_get_by_name(&init_net, "lo");
		net = dev_net(dev);
		result = fn_ipsec_get_flow4(ulVSGId, &bIPsecIn, &bIPsecOut,
			&(cmd.flow1.ipsecInInfo), net, fl_out, pf_ipv6);
		if (result) {
			ASFCTRL_INFO("IPSEC Not Offloadable for flow 1");
			dev_put(dev);
			return result;
		}
		cmd.flow1.ipsecInInfo.natInfo.bSrcNAT = 0;
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
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		fl_in.fl_ip_sport = reply_sport;
		fl_in.fl_ip_dport = reply_dport;
		fl_in.proto = reply_prot;
		if (pf_ipv6 == true) {
			ipv6_addr_copy(&fl_in.fl6_dst, &ip6_reply_dip);
			ipv6_addr_copy(&fl_in.fl6_src, &ip6_reply_sip);
		} else {
			fl_in.fl4_dst = reply_dip;
			fl_in.fl4_src = reply_sip;
		}
		fl_in.fl4_tos = 0;
	#else
		fl_in.u.ip4.fl4_sport = reply_sport;
		fl_in.u.ip4.fl4_dport = reply_dport;
		fl_in.flowi_proto = orig_prot;
		if (pf_ipv6 == true) {
			ipv6_addr_copy(&fl_in.u.ip6.daddr, &ip6_reply_dip);
			ipv6_addr_copy(&fl_in.u.ip6.saddr, &ip6_reply_sip);
		} else {
			fl_in.u.ip4.daddr = reply_dip;
			fl_in.u.ip4.saddr = reply_sip;
		}
		fl_in.flowi_tos = 0;
	#endif

		result = fn_ipsec_get_flow4(ulVSGId, &bIPsecIn, &bIPsecOut,
			&(cmd.flow2.ipsecInInfo), net, fl_in, pf_ipv6);
		dev_put(dev);
		if (result) {
			ASFCTRL_INFO("IPSEC Not Offloadable for flow 2");
			return result;
		}
		cmd.flow2.ipsecInInfo.natInfo.bSrcNAT = 0;
	}
#endif
	cmd.flow2.bIPsecIn = bIPsecIn ? 1 : 0;
	cmd.flow2.bIPsecOut = bIPsecOut ? 1 : 0;

	if (cmd.flow1.bNAT) {
		ASFCTRL_INFO("NAT Enabled\n ");
		cmd.flow1.natInfo.ulDestNATIp = reply_sip;
		cmd.flow1.natInfo.ulSrcNATIp = reply_dip;
		cmd.flow1.natInfo.usDestNATPort = reply_sport;
		cmd.flow1.natInfo.usSrcNATPort = reply_dport;

		if (reply_dip != orig_sip) {
			cmd.flow1.ipsecInInfo.natInfo.bSrcNAT = 1;
			cmd.flow1.ipsecInInfo.natInfo.OrgSrcIp = orig_sip;
		}

		cmd.flow2.natInfo.ulDestNATIp = orig_sip;
		cmd.flow2.natInfo.ulSrcNATIp = orig_dip;
		cmd.flow2.natInfo.usDestNATPort = orig_sport;
		cmd.flow2.natInfo.usSrcNATPort = orig_dport;

		if (reply_sip != orig_dip) {
			cmd.flow2.ipsecInInfo.natInfo.bSrcNAT = 1;
			cmd.flow2.ipsecInInfo.natInfo.OrgSrcIp = reply_sip;
		}
	}

	if (ASFFFPRuntime(ulVSGId,
			 ASF_FFP_CREATE_FLOWS,
			 &cmd, sizeof(cmd), NULL, 0) ==
					ASFFFP_RESPONSE_SUCCESS) {
		/* Flow created successfully. populate the L2 info*/
		uint32_t flow1_dip, flow2_dip;

		ASFCTRL_INFO("Flow created successfully in ASF");

		if (pf_ipv6 == true) {
			asf_linux_IPv6XmitL2blobDummyPkt(0, 0, &cmd.flow1.tuple,
						(struct in6_addr *)(cmd.flow1.tuple.ipv6SrcIp),
						(struct in6_addr *)(cmd.flow1.tuple.ipv6DestIp),
						0, 0, ulCommonInterfaceId);
			asf_linux_IPv6XmitL2blobDummyPkt(0, 0, &cmd.flow2.tuple,
						(struct in6_addr *)(cmd.flow2.tuple.ipv6SrcIp),
						(struct in6_addr *)(cmd.flow2.tuple.ipv6DestIp),
						0, 0, ulCommonInterfaceId);
		} else {

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
		}
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
#ifdef ASFCTRL_SCTP_SUPPORT
		} else if (ct_tuple->dst.protonum == IPPROTO_SCTP) {
			ASFCTRL_INFO("SCTP flow");
			asfctrl_offload_session(ct);
#endif
		}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
	} else if (events & (1 << IPCT_ASSURED)) {
		ASFCTRL_INFO("IPCT_ASSURED!");
#else
	} else if (events & (1 << IPCT_STATUS)) {
#endif
		/* Offload the connection if status is assured */
		if ((ct_tuple->dst.protonum == IPPROTO_TCP) &&
			(ct->status & IPS_ASSURED)) {
			ASFCTRL_INFO("TCP flow");
			asfctrl_offload_session(ct);
		}
	} else {
		ASFCTRL_DBG("DEFAULT event! {0x%x} ", events);
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
	if (nf_conntrack_register_notifier(&init_net, &asfctrl_conntrack_event_nb) < 0) {
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

	nf_conntrack_unregister_notifier(&init_net, &asfctrl_conntrack_event_nb);

	ffp_sysfs_exit();
	ASFCTRL_FUNC_EXIT;
	return;
}
