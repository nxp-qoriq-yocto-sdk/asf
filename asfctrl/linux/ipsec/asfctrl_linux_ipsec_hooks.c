/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * This file implements the hook used to offload the security
 * policy and security association from linux.
 *
 * Author:	Sandeep Malik <Sandeep.Malik@freescale.com>
 *		Hemant Agrawal <hemant@freescale.com>
 *
*/
/* History
*  Version	Date		Author		Change Description
*  1.0	29/07/2010	Hemant Agrawal		Initial Development
*
*/
/***************************************************************************/

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
	__be32 con_magic_num;
};
static struct sa_node sa_table[2][SECFP_MAX_SAS];
static int current_sa_count[2];
static spinlock_t sa_table_lock;

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
static spinlock_t cont_lock;
static T_BOOL containers_ids[MAX_POLICY_CONT_ID][ASFCTRL_MAX_SPD_CONTAINERS];
static int current_index[MAX_POLICY_CONT_ID];


void init_container_indexes(bool init)
{
	if (init)
		spin_lock_init(&cont_lock);
	else
		spin_lock(&cont_lock);

	memset(containers_ids[ASF_OUT_CONTANER_ID], 0,
		sizeof(T_BOOL) * ASFCTRL_MAX_SPD_CONTAINERS);

	memset(containers_ids[ASF_IN_CONTANER_ID], 0,
		sizeof(T_BOOL) * ASFCTRL_MAX_SPD_CONTAINERS);

	current_index[ASF_OUT_CONTANER_ID] = 1;
	current_index[ASF_IN_CONTANER_ID] = 1;

	if (!init)
		spin_unlock(&cont_lock);

}

static inline int alloc_container_index(int cont_dir)
{
	int i, cur_id;

	spin_lock(&cont_lock);
	cur_id = current_index[cont_dir];
	if (containers_ids[cont_dir][cur_id - 1] == 0) {
		containers_ids[cont_dir][cur_id - 1] = 1;
		current_index[cont_dir]++;
		if (current_index[cont_dir] > asfctrl_max_policy_cont)
			current_index[cont_dir] = 1;

		i = cur_id;
		goto ret_id;
	}

	for (i = 1; i <= asfctrl_max_policy_cont; i++) {
		if (containers_ids[cont_dir][i - 1] == 0) {
			containers_ids[cont_dir][i - 1] = 1;
			if (i == asfctrl_max_policy_cont)
				current_index[cont_dir] = 1;
			else
				current_index[cont_dir] = i + 1;
			goto ret_id;
		}
	}
	i = -1;
ret_id:
	spin_unlock(&cont_lock);
	return i;
}

inline int free_container_index(int index, int cont_dir)
{
	if (index > 0 && index <= asfctrl_max_policy_cont) {
		spin_lock(&cont_lock);
		containers_ids[cont_dir][index - 1] = 0;
		spin_unlock(&cont_lock);

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

void init_sa_indexes(bool init)
{
	if (init)
		spin_lock_init(&sa_table_lock);
	else
		spin_lock(&sa_table_lock);

	/* cleaning up the SA Table*/
	memset(sa_table, 0, sizeof(struct sa_node)*2*SECFP_MAX_SAS);

	current_sa_count[IN_SA] = 0;
	current_sa_count[OUT_SA] = 0;

	if (!init)
		spin_unlock(&sa_table_lock);
}

static inline int match_sa_index_no_lock(struct xfrm_state *xfrm, int dir)
{
	int cur_id;
	for (cur_id = 0; cur_id < asfctrl_max_sas; cur_id++) {
		if ((sa_table[dir][cur_id].spi == xfrm->id.spi)
			&& (sa_table[dir][cur_id].status)
			&& (sa_table[dir][cur_id].con_magic_num ==
			asfctrl_vsg_ipsec_cont_magic_id)) {
				xfrm->asf_sa_cookie = cur_id + 1;
				xfrm->asf_sa_direction = dir;
				ASFCTRL_INFO("SA offloaded");
				return 0;
		}
	}
	return -1;
}

static inline int alloc_sa_index(struct xfrm_state *xfrm, int dir)
{
	int cur_id;
	spin_lock(&sa_table_lock);

	if (!match_sa_index_no_lock(xfrm, dir)) {
		ASFCTRL_INFO("SA already allocated");
		goto ret_unlock;
	}

	if (current_sa_count[dir] >= asfctrl_max_sas)
		goto ret_unlock;

	for (cur_id = 0; cur_id < asfctrl_max_sas; cur_id++) {
		if (sa_table[dir][cur_id].status == 0) {
			sa_table[dir][cur_id].status = 1;
			current_sa_count[dir]++;
			spin_unlock(&sa_table_lock);
			return cur_id;
		}
	}
	ASFCTRL_WARN("\nMaximum SAs are offloaded")

ret_unlock:
	spin_unlock(&sa_table_lock);
	return -EINVAL;
}

static inline int free_sa_index(struct xfrm_state *xfrm, int dir)
{
	int err = -EINVAL;
	int cookie = xfrm->asf_sa_cookie;
	ASFCTRL_TRACE("SA-TABLE: saddr 0x%x daddr 0x%x spi 0x%x",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi);

	spin_lock(&sa_table_lock);
	if (cookie > 0 &&  cookie <= asfctrl_max_sas) {
		if (sa_table[dir][cookie - 1].status) {
			sa_table[dir][cookie - 1].status = 0;
			sa_table[dir][cookie - 1].spi = 0;
			current_sa_count[dir]--;
			err = 0;
		}
	} else {
		ASFCTRL_WARN("\nxfrm ASF Cookie is corrupted\n");
	}
	spin_unlock(&sa_table_lock);

	return err;
}

int is_policy_offloadable(struct xfrm_policy *xp)
{
	struct xfrm_tmpl 	*tmpl;

	ASFCTRL_FUNC_ENTRY;
	if (!xp) {
		ASFCTRL_WARN("Invalid Policy Pointer");
		return -EINVAL;
	}
	if (xp->action != XFRM_POLICY_ALLOW) {
		ASFCTRL_WARN("Not a IPSEC policy");
		return -EINVAL;
	}
	if (xp->xfrm_nr > 1) {
		ASFCTRL_WARN("Multiple Transforms not supported");
		return -EINVAL;
	}
	tmpl = &(xp->xfrm_vec[0]);
	if (!tmpl) {
		ASFCTRL_WARN("NULL IPSEC Template");
		return -EINVAL;
	}
	if (tmpl->mode != XFRM_MODE_TUNNEL) {
		ASFCTRL_WARN("IPSEC Transport Mode not supported");
		return -EINVAL;
	}
	if (tmpl->id.proto != IPPROTO_ESP) {
		ASFCTRL_WARN("Non ESP protocol not supported");
		return -EINVAL;
	}
	if (tmpl->calgos != 0) {
		ASFCTRL_WARN("Compression is not supported");
		return -EINVAL;
	}
	ASFCTRL_FUNC_EXIT;
	return 0;
}

static inline int is_sa_offloadable(struct xfrm_state *xfrm)
{
	if (!xfrm) {
		ASFCTRL_WARN("Invalid Pointer");
		return -EINVAL;
	}
	/* lifetime in byte or packet is not supported
	** here XFRM_INF is  (~(__u64)0)  */
	if (xfrm->lft.soft_byte_limit != XFRM_INF ||
		xfrm->lft.soft_packet_limit != XFRM_INF ||
		xfrm->lft.hard_byte_limit != XFRM_INF ||
		xfrm->lft.hard_packet_limit != XFRM_INF) {
		ASFCTRL_WARN("Data Based lifetime is not supported");
		return -EINVAL;
	}
	return 0;
}

int asfctrl_xfrm_add_policy(struct xfrm_policy *xp, int dir)
{
	int i;
	int 	handle;

	ASFCTRL_FUNC_ENTRY;

	if (is_policy_offloadable(xp))
		return -EINVAL;

	if (dir == OUT_SA) {
		ASFIPSecConfigAddOutSPDContainerArgs_t outSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		if (xp->asf_cookie &&
			!(verify_container_index(xp->asf_cookie,
					ASF_OUT_CONTANER_ID))) {
			ASFCTRL_WARN("Policy is already offloaded cookie = %x",
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
				ASFCTRL_WARN("No OUT free containder index");
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
			ASFCTRL_WARN("Policy is already offloaded cookie = %x",
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
				ASFCTRL_WARN("No IN free containder index");
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
		ASFCTRL_WARN("Not offloaded policy");
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
	int err = 0;
	ASFCTRL_FUNC_TRACE;
	/* Changing the IPSEC Container Magic Number */
	asfctrl_vsg_ipsec_cont_magic_id++;

	/* Changing the VSG Magic Number of Policy Delete */
	asfctrl_invalidate_sessions();

	err = ASFIPSecFlushContainers(ASF_DEF_VSG, ASF_DEF_IPSEC_TUNNEL_ID);

	init_container_indexes(0);
	return err;
}

int asfctrl_xfrm_add_outsa(struct xfrm_state *xfrm, struct xfrm_policy *xp)
{
	uint32_t handle;
	int sa_id, ret = -EINVAL;
	struct xfrm_selector *sel = NULL;
	ASFIPSecRuntimeAddOutSAArgs_t outSA;
	ASF_IPSecSASelector_t   outSASel;
	ASF_IPSecSelectorSet_t srcSel, dstSel;
	ASF_IPSecSA_t SAParams;

	ASFCTRL_FUNC_ENTRY;

	sa_id = alloc_sa_index(xfrm, OUT_SA);
	if (sa_id < 0)
		return sa_id;

	memset(&outSA, 0, sizeof(ASFIPSecRuntimeAddOutSAArgs_t));

	sel = &xfrm->sel;
	outSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;

	outSA.ulMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
	outSA.ulSPDContainerIndex = xp->asf_cookie;

	memset(&SAParams, 0, sizeof(ASF_IPSecSA_t));
	memset(&srcSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&dstSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&outSASel, 0, sizeof(ASF_IPSecSASelector_t));

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	SAParams.bVerifyInPktWithSASelectors =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NEEDED;
	SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
				ASF_IPSEC_ADAPT_PEER_GATEWAY_ENABLE;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_ON;

	SAParams.bDoAntiReplayCheck =
		xfrm->props.replay_window ? ASF_IPSEC_SA_SAFLAGS_REPLAY_ON
			: ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF;

	if (xfrm->props.replay_window < 32)
		SAParams.replayWindowSize = 32;
	else
		SAParams.replayWindowSize = xfrm->props.replay_window;
	ASFCTRL_INFO("Out Replay window size = %d ", xfrm->props.replay_window);

#else
	SAParams.bVerifyInPktWithSASelectors =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NOT_NEEDED;
	SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
				ASF_IPSEC_ADAPT_PEER_GATEWAY_DISABLE;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_OFF;

	SAParams.bDoAntiReplayCheck = ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF;

#endif
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
			ASFCTRL_WARN("Auth algorithm not supported");
			return ret;
		}
		SAParams.authAlgo = ret;
		SAParams.authKeyLenBits = xfrm->aalg->alg_key_len;
		SAParams.authKey = xfrm->aalg->alg_key;
	}

	if (xfrm->ealg) {
		ret = asfctrl_alg_getbyname(xfrm->ealg->alg_name, ENCRYPTION);
		if (ret == -EINVAL) {
			ASFCTRL_WARN("Encryption algorithm not supported");
			return ret;
		}
		SAParams.encAlgo = ret;
		SAParams.encDecKeyLenBits = xfrm->ealg->alg_key_len;
		SAParams.encDecKey = xfrm->ealg->alg_key;
	}

	SAParams.spi = xfrm->id.spi;
	SAParams.ulMtu = ASFCTRL_DEF_PMTU;

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
	xfrm->asf_sa_cookie = sa_id + 1;
	spin_lock(&sa_table_lock);

	sa_table[OUT_SA][sa_id].saddr_a4 = xfrm->props.saddr.a4;
	sa_table[OUT_SA][sa_id].daddr_a4 = xfrm->id.daddr.a4;
	sa_table[OUT_SA][sa_id].spi = xfrm->id.spi;
	sa_table[OUT_SA][sa_id].container_id = outSA.ulSPDContainerIndex;
	sa_table[OUT_SA][sa_id].ref_count++;
	sa_table[OUT_SA][sa_id].con_magic_num = asfctrl_vsg_ipsec_cont_magic_id;
	spin_unlock(&sa_table_lock);

	ASFCTRL_TRACE("saddr %x daddr %x spi 0x%x OUT-SPD=%d",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi,
		outSA.ulSPDContainerIndex);

	ASFCTRL_FUNC_EXIT;

	return 0;
}

int asfctrl_xfrm_add_insa(struct xfrm_state *xfrm, struct xfrm_policy *xp)
{
	uint32_t handle;
	int sa_id, ret = -EINVAL;
	struct xfrm_selector *sel;

	ASFIPSecRuntimeAddInSAArgs_t inSA;
	ASF_IPSecSASelector_t   inSASel;
	ASF_IPSecSelectorSet_t srcSel, dstSel;
	ASF_IPSecSA_t SAParams;

	ASFCTRL_FUNC_ENTRY;

	sa_id = alloc_sa_index(xfrm, IN_SA);
	if (sa_id < 0)
		return sa_id;

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

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	SAParams.bVerifyInPktWithSASelectors =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NEEDED;
	SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
				ASF_IPSEC_ADAPT_PEER_GATEWAY_ENABLE;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_ON;
	SAParams.bDoAntiReplayCheck =
		xfrm->props.replay_window ? ASF_IPSEC_SA_SAFLAGS_REPLAY_ON
			: ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF;
	if (xfrm->props.replay_window < 32)
		SAParams.replayWindowSize = 32;
	else
		SAParams.replayWindowSize = xfrm->props.replay_window;
	ASFCTRL_INFO("In  Replay window size = %d ", xfrm->props.replay_window);

#else
	SAParams.bVerifyInPktWithSASelectors =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NOT_NEEDED;
	SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
				ASF_IPSEC_ADAPT_PEER_GATEWAY_DISABLE;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_OFF;

	SAParams.bDoAntiReplayCheck = ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF;
#endif
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

	SAParams.ulMtu = ASFCTRL_DEF_PMTU;

	SAParams.TE_Addr.IP_Version = 4;
	SAParams.TE_Addr.srcIP.bIPv4OrIPv6 = 0;
	SAParams.TE_Addr.srcIP.ipv4addr = xfrm->props.saddr.a4;
	SAParams.TE_Addr.dstIP.bIPv4OrIPv6 = 0;
	SAParams.TE_Addr.dstIP.ipv4addr = xfrm->id.daddr.a4;

	if (xfrm->aalg) {
		ret = asfctrl_alg_getbyname(xfrm->aalg->alg_name,
					AUTHENTICATION);
		if (ret == -EINVAL) {
			ASFCTRL_WARN("Auth algorithm not supported");
			return ret;
		}
		SAParams.authAlgo = ret;
		SAParams.authKeyLenBits = xfrm->aalg->alg_key_len;
		SAParams.authKey = xfrm->aalg->alg_key;
	}

	if (xfrm->ealg) {
		ret = asfctrl_alg_getbyname(xfrm->ealg->alg_name, ENCRYPTION);
		if (ret == -EINVAL) {
			ASFCTRL_WARN("Encryption algorithm not supported");
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
	xfrm->asf_sa_cookie = sa_id + 1;
	spin_lock(&sa_table_lock);
	sa_table[IN_SA][sa_id].saddr_a4 = xfrm->props.saddr.a4;
	sa_table[IN_SA][sa_id].daddr_a4 = xfrm->id.daddr.a4;
	sa_table[IN_SA][sa_id].spi = xfrm->id.spi;
	sa_table[IN_SA][sa_id].container_id = inSA.ulInSPDContainerIndex;
	sa_table[IN_SA][sa_id].ref_count++;
/*	sa_table[OUT_SA][sa_id].iifindex = ifindex; */
	sa_table[IN_SA][sa_id].con_magic_num = asfctrl_vsg_ipsec_cont_magic_id;
	spin_unlock(&sa_table_lock);
	ASFCTRL_TRACE("saddr %x daddr %x spi 0x%x IN-SPD=%d",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi,
		inSA.ulInSPDContainerIndex);

	ASFCTRL_FUNC_EXIT;
	return 0;
}


int asfctrl_xfrm_add_sa(struct xfrm_state *xfrm)
{
	struct xfrm_policy *xp = NULL;

	ASFCTRL_FUNC_TRACE;

	if (!xfrm) {
		ASFCTRL_WARN("NULL Pointer");
		return -EINVAL;
	}

	if (is_sa_offloadable(xfrm))
		return -EINVAL;

	xp = xfrm_state_policy_mapping(xfrm);
	if (!xp || !xp->asf_cookie) {
		ASFCTRL_WARN("Policy not offloaded for this SA");
		return -EINVAL;
	}

	if (xp->dir == OUT_SA)
		return asfctrl_xfrm_add_outsa(xfrm, xp);
	else
		return asfctrl_xfrm_add_insa(xfrm, xp);
	return -EINVAL;
}

int asfctrl_xfrm_delete_sa(struct xfrm_state *xfrm)
{
	int cont_id, dir;
	int handle;

	ASFCTRL_FUNC_ENTRY;

	if (!xfrm->asf_sa_cookie || xfrm->asf_sa_cookie > asfctrl_max_sas) {
		ASFCTRL_WARN("Not an offloaded SA");
		return -1;
	}
	dir = xfrm->asf_sa_direction;

	spin_lock(&sa_table_lock);

	if (match_sa_index_no_lock(xfrm, dir) < 0) {
		ASFCTRL_WARN("Not an offloaded SA -1");
		spin_unlock(&sa_table_lock);
		return -1;
	}
	cont_id = sa_table[dir][xfrm->asf_sa_cookie - 1].container_id;
	spin_unlock(&sa_table_lock);

	if (dir == OUT_SA) {
		ASFIPSecRuntimeDelOutSAArgs_t delSA;
		ASFCTRL_INFO("Delete Encrypt SA");

		delSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		delSA.ulSPDContainerIndex = cont_id;
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

	} else {
		ASFIPSecRuntimeDelInSAArgs_t delSA;

		ASFCTRL_INFO("Delete Decrypt SA");

		delSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		delSA.ulSPDContainerIndex = cont_id;
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
	free_sa_index(xfrm, dir);
	xfrm->asf_sa_cookie = 0;

	ASFCTRL_FUNC_EXIT;
	return 0;
}

int asfctrl_xfrm_flush_sa(void)
{
	ASFCTRL_FUNC_TRACE;
	init_sa_indexes(0);

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

	if (is_policy_offloadable(xp))
		return -EINVAL;

	if (is_sa_offloadable(xfrm))
		return -EINVAL;

	/* Check if Container is already configured down. */
	if (xp->asf_cookie && !(verify_container_index(xp->asf_cookie,
					ASF_OUT_CONTANER_ID))) {
		ASFCTRL_WARN("Policy is already offloaded cookie = %x",
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
			ASFCTRL_WARN("No free containder index");
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

int asfctrl_xfrm_dec_hook(struct xfrm_policy *pol,
		struct xfrm_state *xfrm,
		struct flowi *fl, int ifindex)
{
	int i;
	int 	handle;
	struct xfrm_policy *xp = pol;

	if (is_sa_offloadable(xfrm))
		return -EINVAL;

	if (!xp) {
		xp = xfrm_state_policy_mapping(xfrm);
		if (!xp) {
			ASFCTRL_WARN("Policy not found for this SA");
			return -EINVAL;
		}
	}

	if (is_policy_offloadable(xp))
		return -EINVAL;

	/* Check if Container is already configured down. */
	if (xp->asf_cookie && !(verify_container_index(xp->asf_cookie,
					ASF_IN_CONTANER_ID))) {
		ASFCTRL_WARN("Policy is already offloaded cookie = %x",
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
			ASFCTRL_WARN("No free containder index");
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

int asfctrl_xfrm_encrypt_n_send(struct sk_buff *skb,
		struct xfrm_state *xfrm)
{
	ASFBuffer_t Buffer;
	ASF_IPAddr_t daddr;
	int sa_id, cont_id;

	ASFCTRL_FUNC_ENTRY;

	ASFCTRL_WARN("Packet received spi =0x%x", xfrm->id.spi);

	spin_lock(&sa_table_lock);
	if (match_sa_index_no_lock(xfrm, OUT_SA) < 0) {
		ASFCTRL_INFO("SA offloaded with Junk cookie");
		xfrm->asf_sa_cookie = 0;
		spin_unlock(&sa_table_lock);
		return -EINVAL;
	}

	sa_id = xfrm->asf_sa_cookie - 1;
	Buffer.nativeBuffer = skb;
	daddr.bIPv4OrIPv6 = 0;
	daddr.ipv4addr = xfrm->id.daddr.a4;
	cont_id = sa_table[OUT_SA][sa_id].container_id;

	spin_unlock(&sa_table_lock);

	skb_dst_drop(skb);

	ASFIPSecEncryptAndSendPkt(ASF_DEF_VSG,
			ASF_DEF_IPSEC_TUNNEL_ID,
			cont_id,
			asfctrl_vsg_ipsec_cont_magic_id,
			xfrm->id.spi,
			daddr,
			ASF_IPSEC_PROTOCOL_ESP,
			Buffer,
			asfctrl_generic_free,
			skb);

	ASFCTRL_FUNC_EXIT;
	return 0;
}

int asfctrl_xfrm_decrypt_n_send(struct sk_buff *skb,
		struct xfrm_state *xfrm)
{
	ASFBuffer_t Buffer;
	T_INT32 cii;
	struct net_device *dev = skb->dev;

	ASFCTRL_FUNC_ENTRY;

	ASFCTRL_WARN("Packet received spi =0x%x", xfrm->id.spi);

	spin_lock(&sa_table_lock);
	if (match_sa_index_no_lock(xfrm, IN_SA) < 0) {
		ASFCTRL_INFO("SA offloaded with Junk cookie");
		xfrm->asf_sa_cookie = 0;
		spin_unlock(&sa_table_lock);
		return -EINVAL;
	}
	spin_unlock(&sa_table_lock);

	cii = asfctrl_dev_get_cii(dev);

	ASFCTRL_INFO("Pkt received data = 0x%x, net = 0x%x, skb->len = %d",
		(unsigned int)skb->data,
		(unsigned int)skb_network_header(skb), skb->len);

	Buffer.nativeBuffer = skb;

	skb->len += sizeof(struct iphdr);
	skb->data -= sizeof(struct iphdr);
	skb_dst_drop(skb);
	ASFIPSecDecryptAndSendPkt(ASF_DEF_VSG,
			Buffer,
			asfctrl_generic_free,
			skb,
			cii);

	ASFCTRL_FUNC_EXIT;
	return 0;
}

static int fsl_send_notify(struct xfrm_state *x, struct km_event *c)
{
	ASFCTRL_FUNC_TRACE;

	if (!x && (c->event != XFRM_MSG_FLUSHSA)) {
		ASFCTRL_WARN("Null SA passed.");
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
		break;
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
		ASFCTRL_WARN("XFRM_MSG_UNKNOWN: SA event %d\n", c->event);
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
		ASFCTRL_WARN("Null Policy.");
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
		ASFCTRL_WARN("Unknown policy event %d\n", c->event);
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

