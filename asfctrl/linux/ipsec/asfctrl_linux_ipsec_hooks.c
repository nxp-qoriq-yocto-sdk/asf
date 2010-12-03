/* Copyright (C) 2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * This file implements the hook used to offload the security
 * policy and security association from linux.
 *
 * Author:	Sandeep Malik <Sandeep.Malik@freescale.com>
 *		Hemant Agrawal <hemant@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 * 02111-1307  USA
 *
*/
/****************************************************************************
Revision History:
*  Version	Date		Author		Change Description
*  1.0	29/07/2010	Hemant Agrawal		Initial Development
*
***************************************************************************/

#include <linux/capability.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/ipsec.h>
#include <linux/skbuff.h>
#include <linux/rtnetlink.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/proc_fs.h>
#include <linux/init.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/atomic.h>
#include "../../../asfipsec/driver/ipsfpapi.h"
#include "../ffp/asfctrl.h"
#include "asfctrl_linux_ipsec_hooks.h"

#define XFRM_ACTION(act) (act ? "BLOCK" : "ALLOW")
#define XFRM_MODE(mode) (mode ? "TUNNEL" : "TRANSPORT")


struct sa_node {
	__be16 status;
	__be16 ref_count;
	__be32 saddr_a4;
	__be32 daddr_a4;
	__be32 spi;
	__be32 iifindex;
	__be32 container_id;
	uintptr_t asf_cookie;
};
static struct sa_node sa_table[2][SECFP_MAX_SAS];
static atomic_t current_sa_index[2];

static const struct algo_info
algo_types[MAX_ALGO_TYPE][MAX_AUTH_ENC_ALGO] = {
	{
		{"cbc(aes)", ASF_IPSEC_EALG_AES},
		{"cbc(des3_ede)", ASF_IPSEC_EALG_3DESCBC},
		{NULL, -1}
	},
	{
		{"hmac(sha1)", ASF_IPSEC_AALG_SHA1HMAC},
		{"hmac(sha256)", ASF_IPSEC_AALG_SHA256HMAC},
		{"hmac(md5)", ASF_IPSEC_AALG_MD5HMAC},
		{NULL, -1}
	}
};

static inline int asfctrl_alg_getbyname(char *name, int type)
{
	int i;
	for (i = 0; ; i++) {
		const struct algo_info *info = &algo_types[type][i];
		if (!info->alg_name || info->alg_type == -1)
			break;
		if (strcmp(info->alg_name, name) == 0)
			return info->alg_type;
	}
	return -EINVAL;
}

void asfctrl_generic_free(ASF_void_t *freeArg)
{
	dev_kfree_skb_any((struct sk_buff *)freeArg);
}

/**** Container Indices ***/
static T_BOOL containers_ids[MAX_POLICY_CONT_ID][ASFCTRL_MAX_SPD_CONTAINERS];
static atomic_t current_index[MAX_POLICY_CONT_ID];

void init_container_indexes(void)
{
	memset(containers_ids[ASF_OUT_CONTANER_ID], 0,
		sizeof(T_BOOL) * ASFCTRL_MAX_SPD_CONTAINERS);

	memset(containers_ids[ASF_IN_CONTANER_ID], 0,
		sizeof(T_BOOL) * ASFCTRL_MAX_SPD_CONTAINERS);

	atomic_set(&current_index[ASF_OUT_CONTANER_ID], 1);
	atomic_set(&current_index[ASF_IN_CONTANER_ID], 1);
}

static inline int alloc_container_index(int cont_dir)
{
	int i, cur_id = atomic_read(&current_index[cont_dir]);
	if (containers_ids[cont_dir][cur_id - 1] == 0) {
		containers_ids[cont_dir][cur_id - 1] = 1;
		atomic_inc(&current_index[cont_dir]);
		if (atomic_read(&current_index[cont_dir]) >
					asfctrl_max_policy_cont)
			atomic_set(&current_index[cont_dir], 0);

		return cur_id;
	}

	for (i = 1; i <= asfctrl_max_policy_cont; i++) {
		if (containers_ids[cont_dir][i - 1] == 0) {
			containers_ids[cont_dir][i - 1] = 1;
			atomic_set(&current_index[cont_dir], i + 1);
			if (atomic_read(&current_index[cont_dir]) >
				asfctrl_max_policy_cont)
				atomic_set(&current_index[cont_dir], 1);
			return i;
		}
	}
	return -1;
}

inline int free_container_index(int index, int cont_dir)
{
	if (index > 0 && index <= asfctrl_max_policy_cont) {
		containers_ids[cont_dir][index - 1] = 0;
		return 0;
	}
	return -1;
}

static inline int verify_container_index(int index, int cont_dir)
{
	if (index > 0 && index <= asfctrl_max_policy_cont) {
		if (containers_ids[cont_dir][index - 1])
			return 0;
	}
	return -1;
}

void init_sa_indexes(void)
{
	/* cleaning up the SA Table*/
	memset(sa_table, 0, sizeof(struct sa_node)*2*SECFP_MAX_SAS);

	/* TBD: Make them atomic */
	atomic_set(&current_sa_index[IN_SA], 0);
	atomic_set(&current_sa_index[OUT_SA], 0);
}

static inline int alloc_sa_index(int dir)
{
	int i, cur_id = atomic_read(&current_sa_index[dir]);
	if (sa_table[dir][cur_id].status == 0) {
		sa_table[dir][cur_id].status = 1;

		atomic_inc(&current_sa_index[dir]);
		if (atomic_read(&current_sa_index[dir]) == asfctrl_max_sas)
			atomic_set(&current_sa_index[dir], 0);

		return cur_id;
	}

	for (i = 0; i < asfctrl_max_sas; i++) {
		if (sa_table[dir][i].status == 0) {
			sa_table[dir][i].status = 1;
			atomic_set(&current_sa_index[dir], i + 1);
			if (atomic_read(&current_sa_index[dir]) == asfctrl_max_sas)
				atomic_set(&current_sa_index[dir], 0);
			return i;
		}
	}
	return -1;
}

static inline int free_sa_index(int index, int dir)
{
	if (index > 0 && index < asfctrl_max_sas) {
		sa_table[dir][index].status = 0;
		return 0;
	}
	return -1;
}

/* tbd - this will not work for DSCP based SAs*/
static inline int get_sa_index(struct xfrm_state *xfrm, int direction)
{
	int i;
	ASFCTRL_TRACE("SA-TABLE: saddr 0x%x daddr 0x%x spi 0x%x",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi);

	if (direction != IN_SA && direction != OUT_SA) {
		ASFCTRL_ERR("direction %d", direction);
		return -EINVAL;
	}

	for (i = 0; i < asfctrl_max_sas; i++) {
		ASFCTRL_DBG("SA-TABLE-%d: saddr 0x%x daddr 0x%x spi 0x%x",
			sa_table[direction][i].status,
			sa_table[direction][i].saddr_a4,
			sa_table[direction][i].daddr_a4,
			sa_table[direction][i].spi);

		if (sa_table[direction][i].status
		&& (xfrm->props.saddr.a4 == sa_table[direction][i].saddr_a4)
		&& (xfrm->id.daddr.a4 == sa_table[direction][i].daddr_a4)
		&& (xfrm->id.spi == sa_table[direction][i].spi))
				return i;
	}
	return -EINVAL;
}

static inline int validate_policy_info(struct xfrm_policy *xp)
{
	struct xfrm_tmpl 	*tmpl;

	ASFCTRL_FUNC_ENTRY;
	if (!xp) {
		ASFCTRL_ERR("Invalid Policy Pointer");
		return -EINVAL;
	}
	if (xp->action != XFRM_POLICY_ALLOW) {
		ASFCTRL_ERR("Not a IPSEC policy");
		return -EINVAL;
	}
	tmpl = &(xp->xfrm_vec[0]);
	if (xp->xfrm_nr > 1) {
		ASFCTRL_ERR("Multiple Transforms not supported");
		return -EINVAL;
	}
	if (tmpl->mode != XFRM_MODE_TUNNEL) {
		ASFCTRL_ERR("IPSEC Transport Mode not supported");
		return -EINVAL;
	}
	if (tmpl->id.proto != IPPROTO_ESP) {
		ASFCTRL_ERR("Non ESP protocol not supported");
		return -EINVAL;
	}
	if (tmpl->calgos != 0) {
		ASFCTRL_ERR("Compression is not supported");
		return -EINVAL;
	}
	ASFCTRL_FUNC_EXIT;
	return 0;
}

static inline int validate_sa_info(struct xfrm_state *xfrm)
{
	if (!xfrm) {
		ASFCTRL_ERR("Invalid Pointer");
		return -EINVAL;
	}
	/* lifetime in byte or packet is not supported
	** here XFRM_INF is  (~(__u64)0)  */
	if (xfrm->lft.soft_byte_limit != XFRM_INF ||
		xfrm->lft.soft_packet_limit != XFRM_INF ||
		xfrm->lft.hard_byte_limit != XFRM_INF ||
		xfrm->lft.hard_packet_limit != XFRM_INF) {
		ASFCTRL_ERR("Data Based lifetime is not supported");
		return -EINVAL;
	}
	return 0;
}

int asfctrl_xfrm_add_policy(struct xfrm_policy *xp, int dir)
{
	int i;
	int 	handle;

	ASFCTRL_FUNC_ENTRY;

	if (validate_policy_info(xp))
		return -EINVAL;

	if (dir == OUT_SA) {
		ASFIPSecConfigAddOutSPDContainerArgs_t outSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		if (xp->asf_cookie &&
			!(verify_container_index(xp->asf_cookie,
					ASF_OUT_CONTANER_ID))) {
			ASFCTRL_ERR("Policy is already offloaded cookie = %x",
				xp->asf_cookie);
			goto fn_return;
		} else {
			i = alloc_container_index(ASF_OUT_CONTANER_ID);
			if (i >= 0) {
				ASFCTRL_TRACE("Out Container Index %d", i);
				outSPDContainer.ulSPDContainerIndex = i;
				xp->asf_cookie = i;
				outSPDContainer.ulMagicNumber =
					asfctrl_vsg_ipsec_cont_magic_id;
			} else {
				ASFCTRL_ERR("No OUT free containder index");
				goto err;
			}
		}
		outSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;

		memset(&spdParams, 0, sizeof(ASF_IPSecPolicy_t));
		spdParams.policyID = xp->index;
		spdParams.policyAction = ASF_IPSEC_POLICY_ACTION_IPSEC;
		handle = (uint32_t)(xp);
		outSPDContainer.pSPDParams = &spdParams;

		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_ADD_OUTSPDCONTAINER,
			&outSPDContainer,
			sizeof(ASFIPSecConfigAddOutSPDContainerArgs_t)
			+ sizeof(ASF_IPSecPolicy_t),
			&handle,
			sizeof(uint32_t));
		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();
	} else if (dir == IN_SA) {
		ASFIPSecConfigAddInSPDContainerArgs_t	inSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		if (xp->asf_cookie &&
			!(verify_container_index(xp->asf_cookie,
					ASF_IN_CONTANER_ID))) {
			ASFCTRL_ERR("Policy is already offloaded cookie = %x",
				xp->asf_cookie);
			goto fn_return;
		} else {
			i = alloc_container_index(ASF_IN_CONTANER_ID);
			if (i >= 0) {
				ASFCTRL_TRACE("In Container Index %d", i);
				inSPDContainer.ulSPDContainerIndex = i;
				xp->asf_cookie = i;
				inSPDContainer.ulMagicNumber =
					asfctrl_vsg_ipsec_cont_magic_id;

			} else {
				ASFCTRL_ERR("No IN free containder index");
				goto err;
			}
		}
		inSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;

		memset(&spdParams, 0, sizeof(ASF_IPSecPolicy_t));
		spdParams.policyID = xp->index;
		spdParams.policyAction = ASF_IPSEC_POLICY_ACTION_IPSEC;

		inSPDContainer.pSPDParams = &spdParams;
		handle = (uint32_t)(xp);
		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_ADD_INSPDCONTAINER,
			&inSPDContainer,
			sizeof(ASFIPSecConfigAddInSPDContainerArgs_t)
			+ sizeof(ASF_IPSecPolicy_t),
			&handle,
			sizeof(uint32_t));

		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();
	} else {
		ASFCTRL_DBG("\nPOLICY is neither IN nor OUT\n");
	}

	ASFCTRL_DBG("COKKIE = %d", xp->asf_cookie);
fn_return:
	ASFCTRL_FUNC_EXIT;

	return 0;
err:
	return -EINVAL;

}

int asfctrl_xfrm_delete_policy(struct xfrm_policy *xp, int dir)
{
	int 	handle;

	ASFCTRL_FUNC_ENTRY;

	if (xp->asf_cookie) {
		ASFCTRL_ERR("Not offloaded policy");
		return -EINVAL;
	}
	if (dir == OUT_SA) {
		ASFIPSecConfigDelOutSPDContainerArgs_t outSPDContainer;

		outSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		outSPDContainer.ulMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		outSPDContainer.ulContainerIndex = xp->asf_cookie;

		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_DEL_OUTSPDCONTAINER,
			&outSPDContainer,
			sizeof(ASFIPSecConfigDelOutSPDContainerArgs_t),
			&handle,
			sizeof(uint32_t));
		xp->asf_cookie = 0;
		free_container_index(outSPDContainer.ulContainerIndex,
			ASF_OUT_CONTANER_ID);
		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();

	} else if (dir == IN_SA) {
		ASFIPSecConfigDelInSPDContainerArgs_t	inSPDContainer;

		inSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		inSPDContainer.ulMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		inSPDContainer.ulContainerIndex = xp->asf_cookie;

		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_DEL_INSPDCONTAINER,
			&inSPDContainer,
			sizeof(ASFIPSecConfigDelInSPDContainerArgs_t),
			&handle,
			sizeof(uint32_t));
		xp->asf_cookie = 0;
		free_container_index(inSPDContainer.ulContainerIndex,
			ASF_IN_CONTANER_ID);
		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();
	}
	ASFCTRL_DBG("COKKIE %d", xp->asf_cookie);

	ASFCTRL_FUNC_EXIT;

	return 0;
}
int asfctrl_xfrm_update_policy(struct xfrm_policy *xp, int ifindex)
{
	ASFCTRL_FUNC_TRACE;
	ASFCTRL_WARN("Not Implemented");
	return -1;
}

int asfctrl_xfrm_flush(void)
{
	ASFCTRL_FUNC_TRACE;
	init_container_indexes();
	/* Changing the VSG Magic Number of Policy Delete */
	asfctrl_invalidate_sessions();
	/* Changing the IPSEC Container Magic Number */
	asfctrl_vsg_ipsec_cont_magic_id++;
	return ASFIPSecFlushContainers(ASF_DEF_VSG, ASF_DEF_IPSEC_TUNNEL_ID);
}

int asfctrl_xfrm_add_outsa(struct xfrm_state *xfrm, struct xfrm_policy *xp)
{
	uint32_t handle;
	int i, sa_id, ret = -EINVAL;
	struct xfrm_selector *sel = NULL;
/*	struct net *xfrm_net = xs_net(xfrm);*/
	ASFIPSecRuntimeAddOutSAArgs_t outSA;
	ASF_IPSecSASelector_t   outSASel;
	ASF_IPSecSelectorSet_t srcSel, dstSel;
	ASF_IPSecSA_t SAParams;

	ASFCTRL_FUNC_ENTRY;

	if (xfrm->asf_sa_cookie) {
		for (i = 0; i < asfctrl_max_sas; i++)
			if (sa_table[OUT_SA][i].asf_cookie ==
				xfrm->asf_sa_cookie) {
				/*already offloaded, no need to add SA*/
				sa_table[OUT_SA][i].ref_count++;
				ASFCTRL_ERR("\n already offloaded SA ");
				goto err;
			}
		if (i == asfctrl_max_sas) {
			ASFCTRL_ERR("SA offloaded with Junk cookie");
			xfrm->asf_sa_cookie = 0;
		}
	}

	sa_id = alloc_sa_index(OUT_SA);
	if (sa_id < 0) {
		ASFCTRL_ERR("Maximum SAs are offloaded, Not anymore");
		return sa_id;
	}

	memset(&outSA, 0, sizeof(ASFIPSecRuntimeAddOutSAArgs_t));

	sel = &xfrm->sel;
	outSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;

	outSA.ulMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
	outSA.ulSPDContainerIndex = xp->asf_cookie;

	memset(&SAParams, 0, sizeof(ASF_IPSecSA_t));
	memset(&srcSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&dstSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&outSASel, 0, sizeof(ASF_IPSecSASelector_t));

	SAParams.bVerifyInPktWithSASelectors =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NOT_NEEDED;
	SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
				ASF_IPSEC_ADAPT_PEER_GATEWAY_DISABLE;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_ON;

	SAParams.bDoAntiReplayCheck = ASF_IPSEC_SA_SAFLAGS_REPLAY_ON;
	SAParams.replayWindowSize = 32;/*xfrm->props.replay_window;*/
	if (xfrm->lft.hard_use_expires_seconds != XFRM_INF) {
		SAParams.bSALifeTimeInSecs = ASF_IPSEC_SA_SAFLAGS_LIFESECS_ON;
		SAParams.softSecsLimit = xfrm->lft.soft_use_expires_seconds;
		SAParams.hardSecsLimit = xfrm->lft.hard_use_expires_seconds;
	} else
		SAParams.bSALifeTimeInSecs = ASF_IPSEC_SA_SAFLAGS_LIFESECS_OFF;

	SAParams.bEncapsulationMode = ASF_IPSEC_SA_SAFLAGS_TUNNELMODE;
	SAParams.handleToSOrDSCPAndFlowLabel = ASF_IPSEC_QOS_TOS_COPY;
	/*if not copy than set - SAParams.qos = defined value */
	SAParams.handleDFBit = ASF_IPSEC_DF_COPY;
	SAParams.protocol = ASF_IPSEC_PROTOCOL_ESP;

	SAParams.TE_Addr.IP_Version = 4;
	SAParams.TE_Addr.srcIP.bIPv4OrIPv6 = 0;
	SAParams.TE_Addr.srcIP.ipv4addr = xfrm->props.saddr.a4;
	SAParams.TE_Addr.dstIP.bIPv4OrIPv6 = 0;
	SAParams.TE_Addr.dstIP.ipv4addr = xfrm->id.daddr.a4;

	if (xfrm->aalg) {
		ret = asfctrl_alg_getbyname(xfrm->aalg->alg_name,
					AUTHENTICATION);
		if (ret == -EINVAL) {
			ASFCTRL_ERR("Auth algorithm not supported");
			return ret;
		}
		SAParams.authAlgo = ret;
		SAParams.authKeyLenBits = xfrm->aalg->alg_key_len;
		SAParams.authKey = xfrm->aalg->alg_key;
	}

	if (xfrm->ealg) {
		ret = asfctrl_alg_getbyname(xfrm->ealg->alg_name, ENCRYPTION);
		if (ret == -EINVAL) {
			ASFCTRL_ERR("Encryption algorithm not supported");
			return ret;
		}
		SAParams.encAlgo = ret;
		SAParams.encDecKeyLenBits = xfrm->ealg->alg_key_len;
		SAParams.encDecKey = xfrm->ealg->alg_key;
	}

	SAParams.spi = xfrm->id.spi;
	/*tbd - find the common interface Id or we can use some default here */
	/* SAParams.ulCommonInterfaceId = ; */
	SAParams.ulMtu = 1500;

	/*if UDP Encapsulation is enabled */
	if (xfrm->encap) {
		struct xfrm_encap_tmpl *encap = xfrm->encap;

		SAParams.bDoUDPEncapsulationForNATTraversal =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NEEDED;
		SAParams.IPsecNatInfo.usSrcPort = encap->encap_sport;
		SAParams.IPsecNatInfo.usDstPort = encap->encap_dport;

		/* tbd  -find the correct NATtV1 and V2 mappings*/
		switch (encap->encap_type) {
		default:
		case UDP_ENCAP_ESPINUDP:
			/* esph = (struct ip_esp_hdr *)(uh + 1); */
			SAParams.IPsecNatInfo.ulNATt = ASF_IPSEC_IKE_NATtV2;
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
		/* 	udpdata32 = (__be32 *)(uh + 1);
			udpdata32[0] = udpdata32[1] = 0;
			esph = (struct ip_esp_hdr *)(udpdata32 + 2);*/
			SAParams.IPsecNatInfo.ulNATt = ASF_IPSEC_IKE_NATtV1;
			break;
		}
	}

	srcSel.IP_Version = 4;
	srcSel.protocol = dstSel.protocol = sel->proto;
	srcSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	srcSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->saddr.a4;
	srcSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_s;
	srcSel.port.start = sel->sport;
	srcSel.port.end = sel->sport + ~(sel->sport_mask);

	dstSel.IP_Version = 4;
	dstSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	dstSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->daddr.a4;
	dstSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_d;
	dstSel.port.start = sel->dport;
	dstSel.port.end = sel->dport + ~(sel->dport_mask);

	outSASel.nsrcSel = 1;
	outSASel.srcSel = &srcSel;
	outSASel.ndstSel = 1;
	outSASel.dstSel = &dstSel;

	outSA.pSASelector = &outSASel;
	outSA.pSAParams = &SAParams;
	handle = (uint32_t)xfrm;
	ASFIPSecRuntime(ASF_DEF_VSG,
			ASF_IPSEC_RUNTIME_ADD_OUTSA,
			&outSA,
			sizeof(ASFIPSecRuntimeAddOutSAArgs_t),
			&handle, sizeof(uint32_t));

	xfrm->asf_sa_direction = OUT_SA;
	xfrm->asf_sa_cookie = (uintptr_t)xfrm;

	sa_table[OUT_SA][sa_id].saddr_a4 = xfrm->props.saddr.a4;
	sa_table[OUT_SA][sa_id].daddr_a4 = xfrm->id.daddr.a4;
	sa_table[OUT_SA][sa_id].spi = xfrm->id.spi;
	sa_table[OUT_SA][sa_id].asf_cookie = (uintptr_t)xfrm;
	sa_table[OUT_SA][sa_id].container_id = outSA.ulSPDContainerIndex;
	sa_table[OUT_SA][sa_id].ref_count++;
/*tbd	sa_table[OUT_SA][sa_id].iifindex = ifindex; */
	ASFCTRL_TRACE("saddr %x daddr %x spi 0x%x OUT-SPD=%d",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi,
		outSA.ulSPDContainerIndex);

	ASFCTRL_FUNC_EXIT;

	return 0;
err:
	return -EINVAL;
}

int asfctrl_xfrm_add_insa(struct xfrm_state *xfrm, struct xfrm_policy *xp)
{
	uint32_t handle;
	int i, sa_id, ret = -EINVAL;
	struct xfrm_selector *sel;

	ASFIPSecRuntimeAddInSAArgs_t inSA;
	ASF_IPSecSASelector_t   inSASel;
	ASF_IPSecSelectorSet_t srcSel, dstSel;
	ASF_IPSecSA_t SAParams;

	ASFCTRL_FUNC_ENTRY;

	if (xfrm->asf_sa_cookie) {
		for (i = 0; i < asfctrl_max_sas; i++)
			if (sa_table[IN_SA][i].asf_cookie ==
				xfrm->asf_sa_cookie) {
				/*already offloaded, no need to add SA*/
				sa_table[OUT_SA][i].ref_count++;
				ASFCTRL_ERR("\n already offloaded SA ");
				goto err;
			}
		if (i == asfctrl_max_sas) {
			ASFCTRL_ERR("SA offloaded with Junk cookie");
			xfrm->asf_sa_cookie = 0;
		}
	}

	sa_id = alloc_sa_index(IN_SA);
	if (sa_id < 0) {
		ASFCTRL_ERR("Maximum SAs are offloaded, Not anymore");
		return sa_id;
	}

	memset(&inSA, 0, sizeof(ASFIPSecRuntimeAddInSAArgs_t));
	memset(&inSASel, 0, sizeof(ASF_IPSecSASelector_t));
	memset(&srcSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&dstSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&SAParams, 0, sizeof(ASF_IPSecSA_t));

	inSA.ulInSPDMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
	inSA.ulInSPDContainerIndex = xp->asf_cookie;

	sel = &xfrm->sel;
	inSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
	inSA.ulOutSPDMagicNumber = 0;
	inSA.ulOutSPDContainerIndex = 0;
	inSA.ulOutSPI = 0;
	inSA.DestAddr.bIPv4OrIPv6 = 0;
	inSA.DestAddr.ipv4addr = xfrm->id.daddr.a4;

	SAParams.bVerifyInPktWithSASelectors =
			ASF_IPSEC_SA_SELECTOR_VERIFICATION_NOT_NEEDED;
	SAParams.bRedSideFragment = ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
			ASF_IPSEC_ADAPT_PEER_GATEWAY_DISABLE;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_ON;
	SAParams.bDoAntiReplayCheck = ASF_IPSEC_SA_SAFLAGS_REPLAY_ON;
	SAParams.replayWindowSize = 32;/*xfrm->props.replay_window;*/

	if (xfrm->lft.hard_use_expires_seconds != XFRM_INF) {
		SAParams.bSALifeTimeInSecs = ASF_IPSEC_SA_SAFLAGS_LIFESECS_ON;
		SAParams.softSecsLimit = xfrm->lft.soft_use_expires_seconds;
		SAParams.hardSecsLimit = xfrm->lft.hard_use_expires_seconds;
	} else
		SAParams.bSALifeTimeInSecs = ASF_IPSEC_SA_SAFLAGS_LIFESECS_OFF;

	SAParams.bEncapsulationMode = ASF_IPSEC_SA_SAFLAGS_TUNNELMODE;
	SAParams.handleToSOrDSCPAndFlowLabel = ASF_IPSEC_QOS_TOS_COPY;
	SAParams.handleDFBit = ASF_IPSEC_DF_COPY;
	SAParams.protocol = ASF_IPSEC_PROTOCOL_ESP;

	SAParams.ulMtu = 1500;
	/*tbd - find the common interface Id or we can use some default here*/
	/* SAParams.ulCommonInterfaceId = ; */

	SAParams.TE_Addr.IP_Version = 4;
	SAParams.TE_Addr.srcIP.bIPv4OrIPv6 = 0;
	SAParams.TE_Addr.srcIP.ipv4addr = xfrm->props.saddr.a4;
	SAParams.TE_Addr.dstIP.bIPv4OrIPv6 = 0;
	SAParams.TE_Addr.dstIP.ipv4addr = xfrm->id.daddr.a4;

	if (xfrm->aalg) {
		ret = asfctrl_alg_getbyname(xfrm->aalg->alg_name,
					AUTHENTICATION);
		if (ret == -EINVAL) {
			ASFCTRL_ERR("Auth algorithm not supported");
			return ret;
		}
		SAParams.authAlgo = ret;
		SAParams.authKeyLenBits = xfrm->aalg->alg_key_len;
		SAParams.authKey = xfrm->aalg->alg_key;
	}

	if (xfrm->ealg) {
		ret = asfctrl_alg_getbyname(xfrm->ealg->alg_name, ENCRYPTION);
		if (ret == -EINVAL) {
			ASFCTRL_ERR("Encryption algorithm not supported");
			return ret;
		}
		SAParams.encAlgo = ret;
		SAParams.encDecKeyLenBits = xfrm->ealg->alg_key_len;
		SAParams.encDecKey = xfrm->ealg->alg_key;
	}

	SAParams.spi = xfrm->id.spi;

	/*if UDP Encapsulation is enabled */
	if (xfrm->encap) {
		struct xfrm_encap_tmpl *encap = xfrm->encap;

		SAParams.bDoUDPEncapsulationForNATTraversal =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NEEDED;
		SAParams.IPsecNatInfo.usSrcPort = encap->encap_sport;
		SAParams.IPsecNatInfo.usDstPort = encap->encap_dport;

		switch (encap->encap_type) {
		default:
		case UDP_ENCAP_ESPINUDP:
			/*esph = (struct ip_esp_hdr *)(uh + 1);*/
			SAParams.IPsecNatInfo.ulNATt = ASF_IPSEC_IKE_NATtV2;
			break;
		case UDP_ENCAP_ESPINUDP_NON_IKE:
			/* udpdata32 = (__be32 *)(uh + 1);
			udpdata32[0] = udpdata32[1] = 0;
			esph = (struct ip_esp_hdr *)(udpdata32 + 2); */
			SAParams.IPsecNatInfo.ulNATt = ASF_IPSEC_IKE_NATtV1;
			break;
		}
	}

	srcSel.IP_Version = 4;
	srcSel.protocol = dstSel.protocol = sel->proto;
	srcSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	srcSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->saddr.a4;
	srcSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_s;
	srcSel.port.start = sel->sport;
	srcSel.port.end = sel->sport + ~(sel->sport_mask);

	dstSel.IP_Version = 4;
	dstSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	dstSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->daddr.a4;
	dstSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_d;
	dstSel.port.start = sel->dport;
	dstSel.port.end = sel->dport + ~(sel->dport_mask);

	inSASel.nsrcSel = 1;
	inSASel.srcSel = &srcSel;
	inSASel.ndstSel = 1;
	inSASel.dstSel = &dstSel;

	inSA.pSASelector = &inSASel;
	inSA.pSAParams = &SAParams;
	handle = (uint32_t)xfrm;
	ASFIPSecRuntime(ASF_DEF_VSG,
			ASF_IPSEC_RUNTIME_ADD_INSA,
			&inSA,
			sizeof(ASFIPSecRuntimeAddInSAArgs_t),
			&handle, sizeof(uint32_t));

	xfrm->asf_sa_direction = IN_SA;
	xfrm->asf_sa_cookie = (uintptr_t)xfrm;

	sa_table[IN_SA][sa_id].saddr_a4 = xfrm->props.saddr.a4;
	sa_table[IN_SA][sa_id].daddr_a4 = xfrm->id.daddr.a4;
	sa_table[IN_SA][sa_id].spi = xfrm->id.spi;
	sa_table[IN_SA][sa_id].asf_cookie = (uintptr_t)xfrm;
	sa_table[IN_SA][sa_id].container_id = inSA.ulInSPDContainerIndex;
	sa_table[IN_SA][sa_id].ref_count++;
/*	sa_table[OUT_SA][sa_id].iifindex = ifindex; */

	ASFCTRL_TRACE("saddr %x daddr %x spi 0x%x IN-SPD=%d",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi,
		inSA.ulInSPDContainerIndex);

err:
	ASFCTRL_FUNC_EXIT;
	return 0;
}


int asfctrl_xfrm_add_sa(struct xfrm_state *xfrm)
{
	struct xfrm_policy *xp = NULL;

	ASFCTRL_FUNC_TRACE;

	if (!xfrm) {
		ASFCTRL_ERR("NULL Pointer");
		return -EINVAL;
	}

	if (validate_sa_info(xfrm))
		return -EINVAL;

	xp = xfrm_state_policy_mapping(xfrm);
	if (!xp || !xp->asf_cookie) {
		ASFCTRL_ERR("Policy not offloaded for this SA");
		return -EINVAL;
	}

	if (xfrm->asf_sa_direction == OUT_SA)
		return asfctrl_xfrm_add_outsa(xfrm, xp);
	else
		return asfctrl_xfrm_add_insa(xfrm, xp);
	return -EINVAL;
}


int asfctrl_xfrm_update_enc_stream(struct xfrm_state *xfrm)
{
	ASFCTRL_FUNC_TRACE;
	return 0;
}

/*This will add a new entry into the inSA table. */
int asfctrl_xfrm_update_dec_stream(struct xfrm_state *xfrm)
{
	ASFCTRL_FUNC_TRACE;
	return 0;
}


int asfctrl_xfrm_update_sa(struct xfrm_state *xfrm)
{
	ASFCTRL_FUNC_TRACE;

	ASFCTRL_ERR("************* CHECK *************");
	if (!xfrm->asf_sa_cookie)
		return 0;

	if (xfrm->asf_sa_direction == OUT_SA)
		return asfctrl_xfrm_update_enc_stream(xfrm);
	else
		return asfctrl_xfrm_update_dec_stream(xfrm);
}

int asfctrl_xfrm_delete_sa(struct xfrm_state *xfrm)
{
	int ret;
	int handle;

	ASFCTRL_FUNC_ENTRY;

	if (!xfrm->asf_sa_cookie)
		return 0;

	ret = get_sa_index(xfrm, xfrm->asf_sa_direction);
	if (ret < 0) {
		ASFCTRL_ERR("Not an offloaded SA?=%d\n", ret);
		return ret;
	}

	if (xfrm->asf_sa_direction == OUT_SA) {
		ASFIPSecRuntimeDelOutSAArgs_t delSA;
		ASFCTRL_INFO("Delete Encrypt SA");

		delSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		delSA.ulSPDContainerIndex = sa_table[OUT_SA][ret].container_id;
		delSA.ulSPDMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		delSA.DestAddr.ipv4addr = xfrm->id.daddr.a4;
		delSA.ucProtocol = ASF_IPSEC_PROTOCOL_ESP;
		delSA.ulSPI = xfrm->id.spi;
		delSA.usDscpStart = 0;
		delSA.usDscpEnd = 0;

		ASFIPSecRuntime(ASF_DEF_VSG,
			ASF_IPSEC_RUNTIME_DEL_OUTSA,
			&delSA,
			sizeof(ASFIPSecRuntimeDelOutSAArgs_t),
			&handle, sizeof(uint32_t));

	} else if (xfrm->asf_sa_direction == IN_SA) {
		ASFIPSecRuntimeDelInSAArgs_t delSA;

		ASFCTRL_INFO("Delete Decrypt SA");

		delSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		delSA.ulSPDContainerIndex = sa_table[IN_SA][ret].container_id;
		delSA.ulSPDMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		delSA.DestAddr.ipv4addr = xfrm->id.daddr.a4;
		delSA.ucProtocol = ASF_IPSEC_PROTOCOL_ESP;
		delSA.ulSPI = xfrm->id.spi;

		ASFIPSecRuntime(ASF_DEF_VSG,
			ASF_IPSEC_RUNTIME_DEL_INSA,
			&delSA,
			sizeof(ASFIPSecRuntimeDelInSAArgs_t),
			&handle, sizeof(uint32_t));
	}

	free_sa_index(ret, xfrm->asf_sa_direction);
	xfrm->asf_sa_cookie = 0;
	xfrm->asf_sa_direction = 0;
	ASFCTRL_FUNC_EXIT;
	return 0;
}

int asfctrl_xfrm_flush_sa(void)
{
	ASFCTRL_FUNC_TRACE;
	init_sa_indexes();

	if (ASFIPSecFlushAllSA(ASF_DEF_VSG,
		ASF_DEF_IPSEC_TUNNEL_ID)) {
		ASFCTRL_WARN(" Failure in Flushing the SAs");
	}

	return 0;
}

int asfctrl_xfrm_enc_hook(struct xfrm_policy *xp,
		struct xfrm_state *xfrm,
		struct flowi *fl, int ifindex)
{
	int i;
	int 	handle;

	ASFCTRL_FUNC_ENTRY;

	if (validate_policy_info(xp))
		return -EINVAL;

	if (validate_sa_info(xfrm))
		return -EINVAL;

	/* Check if Container is already configured down. */
	if (xp->asf_cookie && !(verify_container_index(xp->asf_cookie,
					ASF_OUT_CONTANER_ID))) {
		ASFCTRL_ERR("Policy is already offloaded cookie = %x",
			xp->asf_cookie);
		goto sa_check;
	} else {
		/* Offloading the out policy */
		ASFIPSecConfigAddOutSPDContainerArgs_t outSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		i = alloc_container_index(ASF_OUT_CONTANER_ID);
		if (i >= 0) {
			ASFCTRL_TRACE("Out Container Index %d", i);
			outSPDContainer.ulSPDContainerIndex = i;
			xp->asf_cookie = i;
			outSPDContainer.ulMagicNumber =
				asfctrl_vsg_ipsec_cont_magic_id;
		} else {
			ASFCTRL_ERR("No free containder index");
			goto err;
		}
		outSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		memset(&spdParams, 0, sizeof(ASF_IPSecPolicy_t));
		spdParams.policyID = xp->index;
		spdParams.policyAction = ASF_IPSEC_POLICY_ACTION_IPSEC;
		outSPDContainer.pSPDParams = &spdParams;

		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_ADD_OUTSPDCONTAINER,
			&outSPDContainer,
			sizeof(ASFIPSecConfigAddOutSPDContainerArgs_t)
			+ sizeof(ASF_IPSecPolicy_t),
			&handle,
			sizeof(uint32_t));
	}

sa_check:
	if (asfctrl_xfrm_add_outsa(xfrm, xp)) {
		ASFCTRL_WARN("Unable to offload the OUT SA");
		goto err;
	}
	ASFCTRL_FUNC_EXIT;
	return 0;
err:
	return -EINVAL;
}

int asfctrl_xfrm_dec_hook(struct xfrm_policy *xp,
		struct xfrm_state *xfrm,
		struct flowi *fl, int ifindex)
{
	int i;
	int 	handle;

	ASFCTRL_FUNC_ENTRY;

	if (validate_policy_info(xp))
		return -EINVAL;

	if (validate_sa_info(xfrm))
		return -EINVAL;

	/* Check if Container is already configured down. */
	if (xp->asf_cookie && !(verify_container_index(xp->asf_cookie,
					ASF_IN_CONTANER_ID))) {
		ASFCTRL_ERR("Policy is already offloaded cookie = %x",
			xp->asf_cookie);
		goto sa_check;
	} else {
		ASFIPSecConfigAddInSPDContainerArgs_t	inSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		i = alloc_container_index(ASF_IN_CONTANER_ID);
		if (i >= 0) {
			ASFCTRL_TRACE("In Container Index %d", i);
			inSPDContainer.ulSPDContainerIndex = i;
			xp->asf_cookie = i;
			inSPDContainer.ulMagicNumber =
				asfctrl_vsg_ipsec_cont_magic_id;
		} else {
			ASFCTRL_ERR("No free containder index");
			goto err;
		}
		inSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;

		memset(&spdParams, 0, sizeof(ASF_IPSecPolicy_t));
		spdParams.policyID = xp->index;
		spdParams.policyAction = ASF_IPSEC_POLICY_ACTION_IPSEC;
		inSPDContainer.pSPDParams = &spdParams;

		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_ADD_INSPDCONTAINER,
			&inSPDContainer,
			sizeof(ASFIPSecConfigAddInSPDContainerArgs_t)
			+ sizeof(ASF_IPSecPolicy_t),
			&handle,
			sizeof(uint32_t));
	}
sa_check:
	if (asfctrl_xfrm_add_insa(xfrm, xp)) {
		ASFCTRL_WARN("Unable to offload the IN SA");
		goto err;
	}
	ASFCTRL_FUNC_EXIT;
	return 0;
err:
	return -EINVAL;
}

/*tbd - to be completed*/
/* Need to set it properly in Linux networking Stack*/
int asfctrl_xfrm_encrypt_n_send(struct sk_buff *skb,
		struct xfrm_policy *xp)
{
	struct xfrm_tmpl	*tmpl;
	ASFBuffer_t Buffer;
	ASF_IPAddr_t daddr;

	ASFCTRL_FUNC_ENTRY;

	if (validate_policy_info(xp))
		return -EINVAL;

	if (!xp->asf_cookie) {
		ASFCTRL_ERR("Policy not offloaded");
		return -EINVAL;
	}

	tmpl = &xp->xfrm_vec[0];

	Buffer.nativeBuffer = skb;
	daddr.bIPv4OrIPv6 = 0;
	daddr.ipv4addr = tmpl->id.daddr.a4;

	ASFIPSecEncryptAndSendPkt(ASF_DEF_VSG,
			ASF_DEF_IPSEC_TUNNEL_ID,
			xp->asf_cookie,
			asfctrl_vsg_ipsec_cont_magic_id,
			tmpl->id.spi,
			daddr,
			tmpl->id.proto,
			Buffer,
			asfctrl_generic_free,
			skb);

	ASFCTRL_FUNC_EXIT;
	return -EINVAL;
}

static int fsl_send_notify(struct xfrm_state *x, struct km_event *c)
{
	ASFCTRL_FUNC_TRACE;

	if (!x && (c->event != XFRM_MSG_FLUSHSA)) {
		ASFCTRL_ERR("Null SA passed.");
		return 0;
	}
#ifdef ASFCTRL_IPSEC_DEBUG
	if (x)
		asfctrl_xfrm_dump_state(x);
#endif
	switch (c->event) {
	case XFRM_MSG_EXPIRE:
		ASFCTRL_INFO("XFRM_MSG_EXPIRE Hard=%d\n", c->data.hard);
		if (c->data.hard)
			asfctrl_xfrm_delete_sa(x);
		return 0;
	case XFRM_MSG_DELSA:
		ASFCTRL_INFO("XFRM_MSG_DELSA");
		asfctrl_xfrm_delete_sa(x);
		break;
	case XFRM_MSG_NEWSA:
		ASFCTRL_INFO("XFRM_MSG_NEWSA");
		asfctrl_xfrm_add_sa(x);
		break;
	case XFRM_MSG_UPDSA:
		ASFCTRL_INFO("XFRM_MSG_UPDSA");
		asfctrl_xfrm_add_sa(x);
		break;
	case XFRM_MSG_FLUSHSA:
		ASFCTRL_INFO("XFRM_MSG_FLUSHSA");
		asfctrl_xfrm_flush_sa();
		break;
	case XFRM_MSG_NEWAE: /* not yet supported */
		break;
	default:
		ASFCTRL_ERR("XFRM_MSG_UNKNOWN: SA event %d\n", c->event);
		break;
	}
	ASFCTRL_FUNC_EXIT;
	return 0;
}

static int fsl_send_policy_notify(struct xfrm_policy *xp, int dir,
				struct km_event *c)
{
	ASFCTRL_FUNC_ENTRY;
	ASFCTRL_INFO("EVENT = %d xp=%x\n", c->event, (unsigned int) xp);

	if (xp && xp->type != XFRM_POLICY_TYPE_MAIN) {
		ASFCTRL_INFO("Policy Type=%d ", xp->type);
		return 0;
	}
	if (!xp && (c->event != XFRM_MSG_FLUSHPOLICY)) {
		ASFCTRL_ERR("Null Policy.");
		return 0;
	}

#ifdef ASFCTRL_IPSEC_DEBUG
	if (xp)
		asfctrl_xfrm_dump_policy(xp, dir);
#endif
	switch (c->event) {
	case XFRM_MSG_POLEXPIRE:
		break;
	case XFRM_MSG_DELPOLICY:
		ASFCTRL_INFO("XFRM_MSG_DELPOLICY");
		asfctrl_xfrm_delete_policy(xp, dir);
		break;
	case XFRM_MSG_NEWPOLICY:
		ASFCTRL_INFO("XFRM_MSG_NEWPOLICY-%s",
			(dir == OUT_SA) ? "OUT" : "IN");
		asfctrl_xfrm_add_policy(xp, dir);
		break;
	case XFRM_MSG_UPDPOLICY:
		ASFCTRL_INFO("XFRM_MSG_UPDPOLICY");
		asfctrl_xfrm_update_policy(xp, dir);
		break;
	case XFRM_MSG_FLUSHPOLICY:
		ASFCTRL_INFO("XFRM_MSG_FLUSHPOLICY");
		asfctrl_xfrm_flush();
		break;
	default:
		ASFCTRL_ERR("Unknown policy event %d\n", c->event);
		break;
	}
	ASFCTRL_FUNC_EXIT;
	return 0;
}

static int fsl_send_acquire(struct xfrm_state *x, struct xfrm_tmpl *t,
	struct xfrm_policy *xp, int dir)
{
	ASFCTRL_FUNC_TRACE;
#ifdef ASFCTRL_IPSEC_DEBUG
	asfctrl_xfrm_dump_policy(xp, dir);
	asfctrl_xfrm_dump_tmpl(t);
	asfctrl_xfrm_dump_state(x);
#endif
	return 0;
}

static struct xfrm_policy *fsl_compile_policy(struct sock *sk, int opt,
					u8 *data, int len, int *dir)
{
	ASFCTRL_FUNC_TRACE;
	return NULL;
}

static int fsl_send_new_mapping(struct xfrm_state *x, xfrm_address_t *ipaddr,
		__be16 sport)
{
	ASFCTRL_FUNC_TRACE;
	return 0;
}

#ifdef CONFIG_NET_KEY_MIGRATE
static int fsl_send_migrate(struct xfrm_selector *sel, u8 dir, u8 type,
			struct xfrm_migrate *m, int num_bundles,
			struct xfrm_kmaddress *k)
{
	ASFCTRL_INFO("With CONFIG_NET_KEY_MIGRATE");
	return -EINVAL;
}
#else
static int fsl_send_migrate(struct xfrm_selector *sel, u8 dir, u8 type,
		struct xfrm_migrate *m, int num_bundles,
		struct xfrm_kmaddress *k)
{
	ASFCTRL_FUNC_TRACE;
	ASFCTRL_INFO("With NO CONFIG_NET_KEY_MIGRATE");
	return -ENOPROTOOPT;
}
#endif

static struct xfrm_mgr fsl_key_mgr = {
	.id             = "fsl_key_mgr",
	.notify         = fsl_send_notify,
	.acquire        = fsl_send_acquire,
	.compile_policy = fsl_compile_policy,
	.new_mapping    = fsl_send_new_mapping,
	.notify_policy  = fsl_send_policy_notify,
	.migrate        = fsl_send_migrate,
};

void asfctrl_ipsec_km_unregister(void)
{
	ASFCTRL_FUNC_TRACE;
	xfrm_unregister_km(&fsl_key_mgr);
}

int asfctrl_ipsec_km_register(void)
{
	int err = xfrm_register_km(&fsl_key_mgr);
	ASFCTRL_FUNC_TRACE;
	return err;
}


#ifdef ASFCTRL_IPSEC_DEBUG
void asfctrl_xfrm_dump_tmpl(struct xfrm_tmpl *t)
{
	if (t) {
		ASFCTRL_INFO("TMPL daddr = %x, spi=%x, saddr = %x,"
			"proto=%x, encap = %d reqid = %d, mode = %d,"
			"allalgs=%x, eal=%x, aal=%x, cal =%x\n",
			t->id.daddr.a4, t->id.spi, t->saddr.a4,
			t->id.proto, t->encap_family, t->reqid, t->mode,
			t->allalgs, t->ealgos, t->aalgos, t->calgos);
	}
}

void asfctrl_xfrm_dump_policy(struct xfrm_policy *xp, u8 dir)
{
	struct xfrm_sec_ctx *uctx = xp->security;
	struct xfrm_tmpl *t ;

	ASFCTRL_INFO("  POLICY - %d(%s)- %s, proto=%d",
		dir, XFRM_DIR(dir), XFRM_ACTION(xp->action),
		xp->selector.proto);

	ASFCTRL_INFO(" SELECTOR - saddr =%x, daddr %x, prefix_s=%u,"
			"sport=%u, prefix_d=%u, dport=%u, IFINDEX=%d",
			xp->selector.saddr.a4, xp->selector.daddr.a4,
			xp->selector.prefixlen_s, xp->selector.sport,
			xp->selector.prefixlen_d, xp->selector.dport,
			xp->selector.ifindex);

	t = xp->xfrm_vec;
	ASFCTRL_INFO("  NR=%d, tmpl = %p, security = %p",
				xp->xfrm_nr, t, uctx);
	if (uctx) {
		ASFCTRL_INFO("  ctx_doi=%u, ctx_alg=%u,"
			"ctx_len=%u, ctx_sid=%u",
			uctx->ctx_doi, uctx->ctx_alg,
			uctx->ctx_len, uctx->ctx_sid);
	}
	asfctrl_xfrm_dump_tmpl(t);
}

void asfctrl_xfrm_dump_state(struct xfrm_state *xfrm)
{
	struct xfrm_sec_ctx *uctx = xfrm->security;
	struct xfrm_algo_aead *aead = xfrm->aead;
	struct esp_data *esp = xfrm->data;
	int i;

	ASFCTRL_INFO("SA- STATE = family = %u proto=%d",
			xfrm->sel.family, xfrm->sel.proto);

	ASFCTRL_INFO("SELECTOR saddr =%x, daddr %x, prefix_s=%u,"
		"sport=%u, prefix_d=%u, dport=%u, ifIndex=%d",
		xfrm->sel.saddr.a4, xfrm->sel.daddr.a4,
		xfrm->sel.prefixlen_s, xfrm->sel.sport,
		xfrm->sel.prefixlen_d, xfrm->sel.dport,
		xfrm->sel.ifindex);

	if (uctx) {
		ASFCTRL_INFO("  ctx_doi=%u, ctx_alg=%u, ctx_len=%u,"
				"ctx_sid=%u key=%s", uctx->ctx_doi,
				uctx->ctx_alg, uctx->ctx_len, uctx->ctx_sid,
				uctx->ctx_str);
	}

	ASFCTRL_INFO(" ID -daddr = %x, spi=%x, proto=%x, saddr = %x"
	"\nreqid = %d, eal=%x, aal=%x, cal =%x aead=%p, esp =%p\n",
	xfrm->id.daddr.a4, xfrm->id.spi, xfrm->id.proto, xfrm->props.saddr.a4,
	xfrm->props.reqid, xfrm->props.ealgo, xfrm->props.aalgo,
	xfrm->props.calgo, xfrm->aead, esp);

	if (xfrm->aalg) {
		ASFCTRL_INFO(" EALG alg_name = %s,(%d), key is 0x",
				xfrm->aalg->alg_name, xfrm->aalg->alg_key_len);
		for (i = 0; i < xfrm->aalg->alg_key_len/8; i++)
			ASFCTRL_INFO("%x", xfrm->aalg->alg_key[i]);
	}

	if (xfrm->ealg) {
		ASFCTRL_INFO(" EALG alg_name = %s,(%d), key is 0x",
				xfrm->ealg->alg_name, xfrm->ealg->alg_key_len);
		for (i = 0; i < xfrm->ealg->alg_key_len/8; i++)
			ASFCTRL_INFO("%x", xfrm->ealg->alg_key[i]);
	}

	if (aead && esp)
		ASFCTRL_INFO(" alg_name=%s, key_len=%d, icv_len=%d",
		aead->alg_name, aead->alg_key_len, aead->alg_icv_len);

}
#endif

