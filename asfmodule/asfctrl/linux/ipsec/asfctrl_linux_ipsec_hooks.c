/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
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
#ifdef ASFCTRL_TERM_FP_SUPPORT
#include <linux/if_packet.h>
#include <linux/if_pmal.h>
#endif
#include <net/ip.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/xfrm.h>
#include <net/sock.h>
#include <asm/atomic.h>
#include "../../../asfipsec/driver/ipsfpapi.h"
#include "../ffp/asfctrl.h"
#include "asfctrl_linux_ipsec_hooks.h"


#define ASF_IPSEC_NEEDED_HEADROOM	128
#define ASF_IPSEC_NEEDED_TAILROOM	128

#define XFRM_ACTION(act) (act ? "BLOCK" : "ALLOW")
#define XFRM_MODE(mode) (mode ? "TUNNEL" : "TRANSPORT")

#define ASF_SPIN_LOCK(bLockFlag, spinLock) do { \
		bLockFlag = in_softirq(); \
		if (bLockFlag) { \
			spin_lock(spinLock); \
		} else { \
			spin_lock_bh(spinLock); \
		} \
	} while (0)

#define ASF_SPIN_UNLOCK(bLockFlag, spinLock) do { \
		if (bLockFlag) { \
			spin_unlock(spinLock); \
		} else { \
			spin_unlock_bh(spinLock); \
		} \
	} while (0)

struct sa_node {
	__be16 status;
	__be16 ref_count;
	__be32 spi;
	__be32 iifindex;
	__be32 container_id;
	__be32 con_magic_num;
	ASF_IPAddr_t saddr;
	ASF_IPAddr_t daddr;
};
static struct sa_node sa_table[2][SECFP_MAX_SAS];
static int current_sa_count[2];
static spinlock_t sa_table_lock;

static const struct algo_info
algo_types[MAX_ALGO_TYPE][MAX_AUTH_ENC_ALGO] = {
	{
		{"cbc(aes)", ASF_IPSEC_EALG_AES},
		{"cbc(des3_ede)", ASF_IPSEC_EALG_3DESCBC},
		{"cbc(des)", ASF_IPSEC_EALG_DESCBC},
		{"rfc3686(ctr(aes))", ASF_IPSEC_EALG_AES_CTR},
		{"rfc4309(ccm(aes))", ASF_IPSEC_EALG_AES_CCM_ICV8},
		{"rfc4106(gcm(aes))", ASF_IPSEC_EALG_AES_GCM_ICV8},
		{"rfc4543(gcm(aes))", ASF_IPSEC_EALG_NULL_AES_GMAC},
		{NULL, -1}
	},
	{
		{"hmac(sha1)", ASF_IPSEC_AALG_SHA1HMAC},
		{"hmac(sha256)", ASF_IPSEC_AALG_SHA256HMAC},
		{"hmac(sha384)", ASF_IPSEC_AALG_SHA384HMAC},
		{"hmac(sha512)", ASF_IPSEC_AALG_SHA512HMAC},
		{"hmac(md5)", ASF_IPSEC_AALG_MD5HMAC},
		{"xcbc(aes)", ASF_IPSEC_AALG_AESXCBC},
		{"digest_null", ASF_IPSEC_AALG_NONE},
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
	ASFCTRLSkbFree((struct sk_buff *)freeArg);
}

/**** Container Indices ***/
static spinlock_t cont_lock;
static ASF_uint32_t
	containers_ids[MAX_POLICY_CONT_ID][ASFCTRL_MAX_SPD_CONTAINERS];
static int current_index[MAX_POLICY_CONT_ID];


void init_container_indexes(bool init)
{
	bool bLockFlag;
	if (init)
		spin_lock_init(&cont_lock);
	else
		ASF_SPIN_LOCK(bLockFlag, &cont_lock);

	memset(containers_ids[ASF_OUT_CONTANER_ID], 0,
		sizeof(ASF_uint32_t) * ASFCTRL_MAX_SPD_CONTAINERS);

	memset(containers_ids[ASF_IN_CONTANER_ID], 0,
		sizeof(ASF_uint32_t) * ASFCTRL_MAX_SPD_CONTAINERS);

	current_index[ASF_OUT_CONTANER_ID] = 1;
	current_index[ASF_IN_CONTANER_ID] = 1;

	if (!init)
		ASF_SPIN_UNLOCK(bLockFlag, &cont_lock);

}

static inline int alloc_container_index(struct xfrm_policy *xp, int cont_dir)
{
	int i = 0, cur_id;
	bool bLockFlag;

	ASF_SPIN_LOCK(bLockFlag, &cont_lock);
	cur_id = current_index[cont_dir];
	if (containers_ids[cont_dir][cur_id - 1] == 0) {
		containers_ids[cont_dir][cur_id - 1] = xp->index;
		xp->asf_cookie = cur_id;
		current_index[cont_dir]++;
		if (current_index[cont_dir] > asfctrl_max_policy_cont)
			current_index[cont_dir] = 1;

		i = cur_id;
		goto ret_id;
	}

	for (i = 1; i <= asfctrl_max_policy_cont; i++) {
		if (containers_ids[cont_dir][i - 1] == 0) {
			containers_ids[cont_dir][i - 1] = xp->index;
			xp->asf_cookie = i;
			if (i == asfctrl_max_policy_cont)
				current_index[cont_dir] = 1;
			else
				current_index[cont_dir] = i + 1;
			goto ret_id;
		}
	}
	i = 0;
ret_id:
	ASF_SPIN_UNLOCK(bLockFlag, &cont_lock);
	return i;
}

int free_container_index(struct xfrm_policy *xp, int cont_dir)
{
	int index = xp->asf_cookie;
	bool bLockFlag;
	ASF_SPIN_LOCK(bLockFlag, &cont_lock);
	if (index > 0 && index <= asfctrl_max_policy_cont) {
		containers_ids[cont_dir][index - 1] = 0;
		xp->asf_cookie = 0;
		goto ret_id;
	}

	for (index = 1; index <= asfctrl_max_policy_cont; index++) {
		if (containers_ids[cont_dir][index - 1] == xp->index) {
			containers_ids[cont_dir][index - 1] = 0;
			goto ret_id;
		}
	}
	index = 0;
ret_id:
	ASF_SPIN_UNLOCK(bLockFlag, &cont_lock);
	return index;
}

static inline int verify_container_index(struct xfrm_policy *xp, int cont_dir)
{
	int index = xp->asf_cookie;
	bool bLockFlag;
	ASF_SPIN_LOCK(bLockFlag, &cont_lock);
	if (index > 0 && index <= asfctrl_max_policy_cont) {
		if (containers_ids[cont_dir][index - 1] == xp->index)
			goto ret_id;
	}

	for (index = 1; index <= asfctrl_max_policy_cont; index++) {
		if (containers_ids[cont_dir][index - 1] == xp->index) {
			xp->asf_cookie = index;
			goto ret_id;
		}
	}
	index = 0;
ret_id:
	ASF_SPIN_UNLOCK(bLockFlag, &cont_lock);
	return index;
}

void init_sa_indexes(bool init)
{
	bool bLockFlag;
	if (init)
		spin_lock_init(&sa_table_lock);
	else
		ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);

	/* cleaning up the SA Table*/
	memset(sa_table, 0, sizeof(struct sa_node)*2*SECFP_MAX_SAS);

	current_sa_count[IN_SA] = 0;
	current_sa_count[OUT_SA] = 0;

	if (!init)
		ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
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

	if (!match_sa_index_no_lock(xfrm, dir)) {
		ASFCTRL_INFO("SA already allocated");
		goto ret_unlock;
	}

	if (unlikely(current_sa_count[dir] >= asfctrl_max_sas))
		goto ret_unlock;

	for (cur_id = 0; cur_id < asfctrl_max_sas; cur_id++) {
		if (sa_table[dir][cur_id].status == 0) {
			sa_table[dir][cur_id].status = 1;
			current_sa_count[dir]++;
			return cur_id;
		}
	}
	ASFCTRL_WARN("\nMaximum SAs are offloaded");

ret_unlock:
	return -EINVAL;
}

static inline int free_sa_index(struct xfrm_state *xfrm, int dir)
{
	int err = -EINVAL;
	int cookie = xfrm->asf_sa_cookie;
	bool bLockFlag;
	ASFCTRL_TRACE("SA-TABLE: saddr 0x%x daddr 0x%x spi 0x%x",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi);

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);
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
	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);

	return err;
}

int is_policy_offloadable(struct xfrm_policy *xp)
{
	struct xfrm_tmpl 	*tmpl;

	ASFCTRL_FUNC_ENTRY;
	if (unlikely(!xp)) {
		ASFCTRL_WARN("Invalid Policy Pointer");
		return -EINVAL;
	}
	if (unlikely(xp->action != XFRM_POLICY_ALLOW)) {
		ASFCTRL_WARN("Not a IPSEC policy");
		return -EINVAL;
	}
	if (unlikely(xp->xfrm_nr > 1)) {
		ASFCTRL_WARN("Multiple Transforms not supported");
		return -EINVAL;
	}
	tmpl = &(xp->xfrm_vec[0]);
	if (unlikely(!tmpl)) {
		ASFCTRL_WARN("NULL IPSEC Template");
		return -EINVAL;
	}
	if (unlikely(tmpl->mode != XFRM_MODE_TUNNEL)) {
		ASFCTRL_WARN("IPSEC Transport Mode not supported");
		return -EINVAL;
	}
	if ((unlikely(tmpl->id.proto != IPPROTO_ESP) &&
		(tmpl->id.proto != IPPROTO_AH))) {
		ASFCTRL_WARN("Non ESP/AH protocol not supported");
		return -EINVAL;
	}
	if ((tmpl->calgos != 0) && (tmpl->calgos != 0xffffffff)) {
		ASFCTRL_WARN("Compression is not supported");
		return -EINVAL;
	}
	ASFCTRL_FUNC_EXIT;
	return 0;
}

static inline int is_sa_offloadable(struct xfrm_state *xfrm)
{
	if (unlikely(!xfrm)) {
		ASFCTRL_WARN("Invalid Pointer");
		return -EINVAL;
	}

	if (unlikely(xfrm->km.state != XFRM_STATE_VALID)) {
		ASFCTRL_WARN("Invalid State %d", xfrm->km.state);
		return -EINVAL;
	}

	if (unlikely((xfrm->id.proto != IPPROTO_ESP)
		&& (xfrm->id.proto != IPPROTO_AH)
		)) {
		ASFCTRL_WARN("Non ESP/AH protocol not supported");
		return -EINVAL;
	}
	return 0;
}

int asfctrl_xfrm_add_policy(struct xfrm_policy *xp, int dir)
{
	int i;
	uintptr_t handle;

	ASFCTRL_FUNC_ENTRY;

	if (is_policy_offloadable(xp))
		return -EINVAL;

	if (dir == XFRM_POLICY_OUT) {
		ASFIPSecConfigAddOutSPDContainerArgs_t outSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		if (verify_container_index(xp, ASF_OUT_CONTANER_ID)) {
			ASFCTRL_WARN("Offloaded Policy cookie = 0x%x id = %u",
				xp->asf_cookie, xp->index);
			goto fn_return;
		} else {
			i = alloc_container_index(xp, ASF_OUT_CONTANER_ID);
			if (i >= 0) {
				ASFCTRL_TRACE("Out Container Index %d", i);
				outSPDContainer.ulSPDContainerIndex = i;
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
		handle = (uintptr_t)(xp);
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
	} else if (dir == XFRM_POLICY_IN) {
		ASFIPSecConfigAddInSPDContainerArgs_t	inSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		if (verify_container_index(xp, ASF_IN_CONTANER_ID)) {
			ASFCTRL_WARN("Offloaded Policy cookie = 0x%x id = %u",
				xp->asf_cookie, xp->index);
			goto fn_return;
		} else {
			i = alloc_container_index(xp, ASF_IN_CONTANER_ID);
			if (i >= 0) {
				ASFCTRL_TRACE("In Container Index %d", i);
				inSPDContainer.ulSPDContainerIndex = i;
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
		handle = (uintptr_t)(xp);
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
		ASFCTRL_DBG("\nPOLICY is FWD");
	}

	ASFCTRL_INFO("Policy =%p COOKIE = 0x%x, id = %d",
		xp, xp->asf_cookie, xp->index);
fn_return:
	ASFCTRL_FUNC_EXIT;

	return 0;
err:
	return -EINVAL;

}

int asfctrl_xfrm_delete_policy(struct xfrm_policy *xp, int dir)
{
	uintptr_t handle;

	ASFCTRL_FUNC_ENTRY;

	if (!verify_container_index(xp, dir)) {
		ASFCTRL_WARN("Not Offloaded Policy = %x id = %u",
				xp->asf_cookie, xp->index);
		return -EINVAL;
	}
	if (dir == XFRM_POLICY_OUT) {
		ASFIPSecConfigDelOutSPDContainerArgs_t outSPDContainer;

		outSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		outSPDContainer.ulMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		outSPDContainer.ulContainerIndex =
			free_container_index(xp, ASF_OUT_CONTANER_ID);

		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_DEL_OUTSPDCONTAINER,
			&outSPDContainer,
			sizeof(ASFIPSecConfigDelOutSPDContainerArgs_t),
			&handle,
			sizeof(uint32_t));

		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();

	} else if (dir == XFRM_POLICY_IN) {
		ASFIPSecConfigDelInSPDContainerArgs_t	inSPDContainer;

		inSPDContainer.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		inSPDContainer.ulMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		inSPDContainer.ulContainerIndex =
			free_container_index(xp, ASF_IN_CONTANER_ID);

		ASFIPSecConfig(ASF_DEF_VSG,
			ASF_IPSEC_CONFIG_DEL_INSPDCONTAINER,
			&inSPDContainer,
			sizeof(ASFIPSecConfigDelInSPDContainerArgs_t),
			&handle,
			sizeof(uint32_t));

		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();
	}
	ASFCTRL_DBG("COKKIE %d id =%d", xp->asf_cookie, xp->index);

	ASFCTRL_FUNC_EXIT;

	return 0;
}
int asfctrl_xfrm_update_policy(struct xfrm_policy *xp, int dir)
{
	ASFCTRL_FUNC_TRACE;

	if (verify_container_index(xp, dir))
		ASFCTRL_WARN("Offloaded Policy with cookie = %x id = %u",
				xp->asf_cookie, xp->index);

	return 0;
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
	uintptr_t handle;
	int sa_id, ret = -EINVAL;
	struct xfrm_selector *sel = NULL;
#ifdef ASF_IPV6_FP_SUPPORT
	bool bIPv4OrIPv6 = 0;
	bool bSelIPv4OrIPv6 = 0;
#endif
	bool bLockFlag;
	ASFIPSecRuntimeAddOutSAArgs_t outSA;
	ASF_IPSecSASelector_t   outSASel;
	ASF_IPSecSelectorSet_t srcSel, dstSel;
	ASF_IPSecSA_t SAParams;
	struct xfrm_algo_aead *aead = xfrm->aead;
	struct esp_data *esp = xfrm->data;

	ASFCTRL_FUNC_ENTRY;

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);
	sa_id = alloc_sa_index(xfrm, OUT_SA);
	if (sa_id < 0) {
		ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
		return sa_id;
	}
	sa_table[OUT_SA][sa_id].spi = xfrm->id.spi;
	sa_table[OUT_SA][sa_id].con_magic_num = asfctrl_vsg_ipsec_cont_magic_id;
	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);

	xfrm->asf_sa_direction = OUT_SA;
	xfrm->asf_sa_cookie = sa_id + 1;

	memset(&outSA, 0, sizeof(ASFIPSecRuntimeAddOutSAArgs_t));

	sel = &xp->selector;
	outSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;

	outSA.ulMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
	outSA.ulSPDContainerIndex = xp->asf_cookie;

	memset(&SAParams, 0, sizeof(ASF_IPSecSA_t));
	memset(&srcSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&dstSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&outSASel, 0, sizeof(ASF_IPSecSASelector_t));
#ifdef ASF_IPV6_FP_SUPPORT
	if (sel->family == AF_INET6)
		bSelIPv4OrIPv6 = 1;
	if (xfrm->props.family == AF_INET6)
		bIPv4OrIPv6 = 1;
#endif
	SAParams.bVerifyInPktWithSASelectors =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NOT_NEEDED;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef ASF_IPV6_FP_SUPPORT
	if (!bIPv4OrIPv6) {
#endif
	SAParams.bRedSideFragment = bRedSideFragment;
#ifdef ASF_IPV6_FP_SUPPORT
	} else
		SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
#endif
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
				ASF_IPSEC_ADAPT_PEER_GATEWAY_DISABLE;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_ON;

	SAParams.bDoAntiReplayCheck =
		xfrm->props.replay_window ? ASF_IPSEC_SA_SAFLAGS_REPLAY_ON
			: ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF;

	SAParams.bDoAntiReplayCheck =
		SAParams.bDoAntiReplayCheck ? bAntiReplayCheck : 0;

	if (xfrm->props.replay_window < 32)
		SAParams.replayWindowSize = 32;
	else
		SAParams.replayWindowSize = xfrm->props.replay_window;
	ASFCTRL_INFO("Out Replay window size = %d ", xfrm->props.replay_window);

#else
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

	if (bVolumeBasedExpiry && xfrm->lft.hard_byte_limit != XFRM_INF) {
		SAParams.softKbyteLimit = xfrm->lft.soft_byte_limit/1024;
		SAParams.hardKbyteLimit = xfrm->lft.hard_byte_limit/1024;
	}

	if (bPacketBasedExpiry && xfrm->lft.hard_packet_limit != XFRM_INF) {
		SAParams.softPacketLimit = xfrm->lft.soft_packet_limit;
		SAParams.hardPacketLimit = xfrm->lft.hard_packet_limit;
	}

	SAParams.bEncapsulationMode = ASF_IPSEC_SA_SAFLAGS_TUNNELMODE;
	SAParams.handleToSOrDSCPAndFlowLabel = ASF_IPSEC_QOS_TOS_COPY;
	/*if not copy than set - SAParams.qos = defined value */
	SAParams.handleDFBit = ASF_IPSEC_DF_COPY;
	SAParams.protocol = xfrm->id.proto ;

#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv4OrIPv6) {
		SAParams.TE_Addr.IP_Version = 6;
		memcpy(SAParams.TE_Addr.srcIP.ipv6addr, xfrm->props.saddr.a6, 16);
		memcpy(SAParams.TE_Addr.dstIP.ipv6addr, xfrm->id.daddr.a6, 16);
		SAParams.TE_Addr.srcIP.bIPv4OrIPv6 = bIPv4OrIPv6;
		SAParams.TE_Addr.dstIP.bIPv4OrIPv6 = bIPv4OrIPv6;
	} else {
#endif
		SAParams.TE_Addr.IP_Version = 4;
		SAParams.TE_Addr.srcIP.ipv4addr = xfrm->props.saddr.a4;
		SAParams.TE_Addr.dstIP.ipv4addr = xfrm->id.daddr.a4;
		SAParams.TE_Addr.srcIP.bIPv4OrIPv6 = 0;
		SAParams.TE_Addr.dstIP.bIPv4OrIPv6 = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif

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
		SAParams.icvSizeinBits = xfrm->aalg->alg_trunc_len;
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

	/* CCM/GCM/GMAC mode case, aalg and ealg will be NULL
	 * from linux stack, xfrm support three algorithm modes, aalg/ealg/aead
	 */
	if (aead && esp) {
		ret = asfctrl_alg_getbyname(aead->alg_name, ENCRYPTION);
		if (ret == -EINVAL) {
			ASFCTRL_WARN("Encryption algorithm not supported");
			return ret;
		}
		/* check aead mode */
		if (ASF_IPSEC_EALG_AES_CCM_ICV8 == ret) {
			switch (aead->alg_icv_len) {
			case 64:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_CCM_ICV8;
				break;
			case 96:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_CCM_ICV12;
				break;
			case 128:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_CCM_ICV16;
				break;
			default:
				ASFCTRL_WARN("CCM ICV length not supported");
				return -EINVAL;
			}
		} else if (ASF_IPSEC_EALG_AES_GCM_ICV8 == ret) {
			switch (aead->alg_icv_len) {
			case 64:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_GCM_ICV8;
				break;
			case 96:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_GCM_ICV12;
				break;
			case 128:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_GCM_ICV16;
				break;
			default:
				ASFCTRL_WARN("GCM ICV length not supported");
				return -EINVAL;
			}
		} else {
			SAParams.encAlgo = ASF_IPSEC_EALG_NULL_AES_GMAC;
		}
		SAParams.icvSizeinBits = aead->alg_icv_len;
		SAParams.encDecKeyLenBits = aead->alg_key_len;
		SAParams.encDecKey = aead->alg_key;
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
#ifdef ASF_IPV6_FP_SUPPORT
	if (bSelIPv4OrIPv6) {
		srcSel.IP_Version = 6;
		dstSel.IP_Version = 6;
		memcpy(srcSel.addr.u.prefixAddr.v6.IPv6Addr.u.w_addr,
			sel->saddr.a6, 16);
		srcSel.addr.u.prefixAddr.v6.IPv6Plen = sel->prefixlen_s;
		memcpy(dstSel.addr.u.prefixAddr.v6.IPv6Addr.u.w_addr,
			sel->daddr.a6, 16);
		dstSel.addr.u.prefixAddr.v6.IPv6Plen = sel->prefixlen_d;
	} else {
#endif
		srcSel.IP_Version = 4;
		dstSel.IP_Version = 4;
		srcSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->saddr.a4;
		srcSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_s;
		dstSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->daddr.a4;
		dstSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_d;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif
	srcSel.protocol = dstSel.protocol = sel->proto;
	srcSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	srcSel.port.start = sel->sport;
	srcSel.port.end = sel->sport + ~(sel->sport_mask);

	dstSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	dstSel.port.start = sel->dport;
	dstSel.port.end = sel->dport + ~(sel->dport_mask);

	outSASel.nsrcSel = 1;
	outSASel.srcSel = &srcSel;
	outSASel.ndstSel = 1;
	outSASel.dstSel = &dstSel;

	outSA.pSASelector = &outSASel;
	outSA.pSAParams = &SAParams;
	handle = (uintptr_t)xfrm;
	ASFIPSecRuntime(ASF_DEF_VSG,
			ASF_IPSEC_RUNTIME_ADD_OUTSA,
			&outSA,
			sizeof(ASFIPSecRuntimeAddOutSAArgs_t),
			&handle, sizeof(uint32_t));

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv4OrIPv6) {
		memcpy(sa_table[OUT_SA][sa_id].saddr.ipv6addr,
						xfrm->props.saddr.a6, 16);
		memcpy(sa_table[OUT_SA][sa_id].daddr.ipv6addr,
						xfrm->id.daddr.a6, 16);
		sa_table[OUT_SA][sa_id].saddr.bIPv4OrIPv6 = bIPv4OrIPv6;
		sa_table[OUT_SA][sa_id].daddr.bIPv4OrIPv6 = bIPv4OrIPv6;
	} else {
#endif
		sa_table[OUT_SA][sa_id].saddr.ipv4addr = xfrm->props.saddr.a4;
		sa_table[OUT_SA][sa_id].daddr.ipv4addr = xfrm->id.daddr.a4;
		sa_table[OUT_SA][sa_id].saddr.bIPv4OrIPv6 = 0;
		sa_table[OUT_SA][sa_id].daddr.bIPv4OrIPv6 = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif
	sa_table[OUT_SA][sa_id].container_id = outSA.ulSPDContainerIndex;
	sa_table[OUT_SA][sa_id].ref_count++;
	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);

	ASFCTRL_TRACE("saddr %x daddr %x spi 0x%x OUT-SPD=%d",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi,
		outSA.ulSPDContainerIndex);

	ASFCTRL_FUNC_EXIT;

	return 0;
}

int asfctrl_xfrm_add_insa(struct xfrm_state *xfrm, struct xfrm_policy *xp)
{
	uintptr_t handle;
	int sa_id, ret = -EINVAL;
	struct xfrm_selector *sel;
#ifdef ASF_IPV6_FP_SUPPORT
	bool bIPv4OrIPv6 = 0;
	bool bSelIPv4OrIPv6 = 0;
#endif
	bool bLockFlag;
	ASFIPSecRuntimeAddInSAArgs_t inSA;
	ASF_IPSecSASelector_t   inSASel;
	ASF_IPSecSelectorSet_t srcSel, dstSel;
	ASF_IPSecSA_t SAParams;
	struct xfrm_algo_aead *aead = xfrm->aead;
	struct esp_data *esp = xfrm->data;

	ASFCTRL_FUNC_ENTRY;

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);
	sa_id = alloc_sa_index(xfrm, IN_SA);
	if (sa_id < 0) {
		ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
		return sa_id;
	}
	sa_table[IN_SA][sa_id].spi = xfrm->id.spi;
	sa_table[IN_SA][sa_id].con_magic_num = asfctrl_vsg_ipsec_cont_magic_id;
	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
	xfrm->asf_sa_direction = IN_SA;
	xfrm->asf_sa_cookie = sa_id + 1;

	memset(&inSA, 0, sizeof(ASFIPSecRuntimeAddInSAArgs_t));
	memset(&inSASel, 0, sizeof(ASF_IPSecSASelector_t));
	memset(&srcSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&dstSel, 0, sizeof(ASF_IPSecSelectorSet_t));
	memset(&SAParams, 0, sizeof(ASF_IPSecSA_t));

	inSA.ulInSPDMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
	inSA.ulInSPDContainerIndex = xp->asf_cookie;

	sel = &xp->selector;
#ifdef ASF_IPV6_FP_SUPPORT
	if (sel->family == AF_INET6)
		bSelIPv4OrIPv6 = 1;
	if (xfrm->props.family == AF_INET6)
		bIPv4OrIPv6 = 1;
#endif
	inSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
	inSA.ulOutSPDMagicNumber = 0;
	inSA.ulOutSPDContainerIndex = 0;
	inSA.ulOutSPI = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	inSA.DestAddr.bIPv4OrIPv6 = bIPv4OrIPv6;
		if (bIPv4OrIPv6)
			memcpy(inSA.DestAddr.ipv6addr,
					xfrm->id.daddr.a6, 16);
		else
#endif
			inSA.DestAddr.ipv4addr = xfrm->id.daddr.a4;

	SAParams.bVerifyInPktWithSASelectors =
				ASF_IPSEC_SA_SELECTOR_VERIFICATION_NOT_NEEDED;
	SAParams.bDoPeerGWIPAddressChangeAdaptation =
				ASF_IPSEC_ADAPT_PEER_GATEWAY_DISABLE;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef ASF_IPV6_FP_SUPPORT
	if (!bIPv4OrIPv6)
#endif
		SAParams.bRedSideFragment = bRedSideFragment;
#ifdef ASF_IPV6_FP_SUPPORT
	 else
		SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
#endif
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_ON;
	SAParams.bDoAntiReplayCheck =
		xfrm->props.replay_window ? ASF_IPSEC_SA_SAFLAGS_REPLAY_ON
			: ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF;

	SAParams.bDoAntiReplayCheck =
		SAParams.bDoAntiReplayCheck ? bAntiReplayCheck : 0;

	if (xfrm->props.replay_window < 32)
		SAParams.replayWindowSize = 32;
	else
		SAParams.replayWindowSize = xfrm->props.replay_window;
	ASFCTRL_INFO("In  Replay window size = %d ", xfrm->props.replay_window);

#else
	SAParams.bRedSideFragment =
				ASF_IPSEC_RED_SIDE_FRAGMENTATION_DISABLED;
	SAParams.bPropogateECN = ASF_IPSEC_QOS_TOS_ECN_CHECK_OFF;

	SAParams.bDoAntiReplayCheck = ASF_IPSEC_SA_SAFLAGS_REPLAY_OFF;
#endif
	if (xfrm->lft.hard_use_expires_seconds != XFRM_INF) {
		SAParams.bSALifeTimeInSecs = ASF_IPSEC_SA_SAFLAGS_LIFESECS_ON;
		SAParams.softSecsLimit = xfrm->lft.soft_use_expires_seconds;
		SAParams.hardSecsLimit = xfrm->lft.hard_use_expires_seconds;
	} else
		SAParams.bSALifeTimeInSecs = ASF_IPSEC_SA_SAFLAGS_LIFESECS_OFF;

	if (bVolumeBasedExpiry && xfrm->lft.hard_byte_limit != XFRM_INF) {
		SAParams.softKbyteLimit = xfrm->lft.soft_byte_limit/1024;
		SAParams.hardKbyteLimit = xfrm->lft.hard_byte_limit/1024;
	}

	if (bPacketBasedExpiry && xfrm->lft.hard_packet_limit != XFRM_INF) {
		SAParams.softPacketLimit = xfrm->lft.soft_packet_limit;
		SAParams.hardPacketLimit = xfrm->lft.hard_packet_limit;
	}

	SAParams.bEncapsulationMode = ASF_IPSEC_SA_SAFLAGS_TUNNELMODE;
	SAParams.handleToSOrDSCPAndFlowLabel = ASF_IPSEC_QOS_TOS_COPY;
	SAParams.handleDFBit = ASF_IPSEC_DF_COPY;
	SAParams.protocol = xfrm->id.proto;

	SAParams.ulMtu = ASFCTRL_DEF_PMTU;
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv4OrIPv6) {
		SAParams.TE_Addr.IP_Version = 6;
		memcpy(SAParams.TE_Addr.srcIP.ipv6addr, xfrm->props.saddr.a6, 16);
		memcpy(SAParams.TE_Addr.dstIP.ipv6addr, xfrm->id.daddr.a6, 16);
		SAParams.TE_Addr.srcIP.bIPv4OrIPv6 = bIPv4OrIPv6;
		SAParams.TE_Addr.dstIP.bIPv4OrIPv6 = bIPv4OrIPv6;
	} else {
#endif
		SAParams.TE_Addr.IP_Version = 4;
		SAParams.TE_Addr.srcIP.ipv4addr = xfrm->props.saddr.a4;
		SAParams.TE_Addr.dstIP.ipv4addr = xfrm->id.daddr.a4;
		SAParams.TE_Addr.srcIP.bIPv4OrIPv6 = 0;
		SAParams.TE_Addr.dstIP.bIPv4OrIPv6 = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif

	if (xfrm->aalg) {
		ret = asfctrl_alg_getbyname(xfrm->aalg->alg_name,
					AUTHENTICATION);
		if (unlikely(ret == -EINVAL)) {
			ASFCTRL_WARN("Auth algorithm not supported");
			return ret;
		}
		SAParams.authAlgo = ret;
		SAParams.authKeyLenBits = xfrm->aalg->alg_key_len;
		SAParams.authKey = xfrm->aalg->alg_key;
		SAParams.icvSizeinBits = xfrm->aalg->alg_trunc_len;
	}
	if (xfrm->ealg) {
		ret = asfctrl_alg_getbyname(xfrm->ealg->alg_name, ENCRYPTION);
		if (unlikely(ret == -EINVAL)) {
			ASFCTRL_WARN("Encryption algorithm not supported");
			return ret;
		}
		SAParams.encAlgo = ret;
		SAParams.encDecKeyLenBits = xfrm->ealg->alg_key_len;
		SAParams.encDecKey = xfrm->ealg->alg_key;
	}

	/* CCM/GCM/GMAC mode case, aalg and ealg will be NULL
	  * from linux stack, xfrm support three algorithm modes, aalg/ealg/aead
	  */
	if (aead && esp) {
		ret = asfctrl_alg_getbyname(aead->alg_name, ENCRYPTION);
		if (ret == -EINVAL) {
			ASFCTRL_WARN("Encryption algorithm not supported");
			return ret;
		}
		/* check aead mode */
		if (ASF_IPSEC_EALG_AES_CCM_ICV8 == ret) {
			switch (aead->alg_icv_len) {
			case 64:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_CCM_ICV8;
				break;
			case 96:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_CCM_ICV12;
				break;
			case 128:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_CCM_ICV16;
				break;
			default:
				ASFCTRL_WARN("CCM ICV length not supported");
				return -EINVAL;
			}
		} else if (ASF_IPSEC_EALG_AES_GCM_ICV8 == ret) {
			switch (aead->alg_icv_len) {
			case 64:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_GCM_ICV8;
				break;
			case 96:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_GCM_ICV12;
				break;
			case 128:
				SAParams.encAlgo = ASF_IPSEC_EALG_AES_GCM_ICV16;
				break;
			default:
				ASFCTRL_WARN("GCM ICV length not supported");
				return -EINVAL;
			}
		} else {
			SAParams.encAlgo = ASF_IPSEC_EALG_NULL_AES_GMAC;
		}
		SAParams.icvSizeinBits = aead->alg_icv_len;
		SAParams.encDecKeyLenBits = aead->alg_key_len;
		SAParams.encDecKey = aead->alg_key;
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
#ifdef ASF_IPV6_FP_SUPPORT
	if (bSelIPv4OrIPv6) {
		srcSel.IP_Version = 6;
		dstSel.IP_Version = 6;
		memcpy(srcSel.addr.u.prefixAddr.v6.IPv6Addr.u.w_addr,
			sel->saddr.a6, 16);
		srcSel.addr.u.prefixAddr.v6.IPv6Plen = sel->prefixlen_s;
		memcpy(dstSel.addr.u.prefixAddr.v6.IPv6Addr.u.w_addr,
			sel->daddr.a6, 16);
		dstSel.addr.u.prefixAddr.v6.IPv6Plen = sel->prefixlen_d;
	} else {
#endif
		srcSel.IP_Version = 4;
		dstSel.IP_Version = 4;
		srcSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->saddr.a4;
		srcSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_s;
		dstSel.addr.u.prefixAddr.v4.IPv4Addrs = sel->daddr.a4;
		dstSel.addr.u.prefixAddr.v4.IPv4Plen = sel->prefixlen_d;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif
	srcSel.protocol = dstSel.protocol = sel->proto;
	srcSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	srcSel.port.start = sel->sport;
	srcSel.port.end = sel->sport + ~(sel->sport_mask);

	dstSel.addr.addrType = ASF_IPSEC_ADDR_TYPE_SUBNET;
	dstSel.port.start = sel->dport;
	dstSel.port.end = sel->dport + ~(sel->dport_mask);

	inSASel.nsrcSel = 1;
	inSASel.srcSel = &srcSel;
	inSASel.ndstSel = 1;
	inSASel.dstSel = &dstSel;

	inSA.pSASelector = &inSASel;
	inSA.pSAParams = &SAParams;
	handle = (uintptr_t)xfrm;
	ASFIPSecRuntime(ASF_DEF_VSG,
			ASF_IPSEC_RUNTIME_ADD_INSA,
			&inSA,
			sizeof(ASFIPSecRuntimeAddInSAArgs_t),
			&handle, sizeof(uint32_t));

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIPv4OrIPv6) {
		memcpy(sa_table[IN_SA][sa_id].saddr.ipv6addr,
						xfrm->props.saddr.a6, 16);
		memcpy(sa_table[IN_SA][sa_id].daddr.ipv6addr,
						xfrm->id.daddr.a6, 16);
		sa_table[IN_SA][sa_id].saddr.bIPv4OrIPv6 = bIPv4OrIPv6;
		sa_table[IN_SA][sa_id].daddr.bIPv4OrIPv6 = bIPv4OrIPv6;
	} else {
#endif
		sa_table[IN_SA][sa_id].saddr.ipv4addr = xfrm->props.saddr.a4;
		sa_table[IN_SA][sa_id].daddr.ipv4addr = xfrm->id.daddr.a4;
		sa_table[IN_SA][sa_id].saddr.bIPv4OrIPv6 = 0;
		sa_table[IN_SA][sa_id].daddr.bIPv4OrIPv6 = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif

	sa_table[IN_SA][sa_id].container_id = inSA.ulInSPDContainerIndex;
	sa_table[IN_SA][sa_id].ref_count++;
/*	sa_table[OUT_SA][sa_id].iifindex = ifindex; */
	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
	ASFCTRL_TRACE("saddr %x daddr %x spi 0x%x IN-SPD=%d",
		xfrm->props.saddr.a4, xfrm->id.daddr.a4, xfrm->id.spi,
		inSA.ulInSPDContainerIndex);

	ASFCTRL_FUNC_EXIT;
	return 0;
}


int asfctrl_xfrm_add_sa(struct xfrm_state *xfrm)
{
	struct xfrm_policy *xp = NULL;
	int dir;

	ASFCTRL_FUNC_TRACE;

	if (unlikely(is_sa_offloadable(xfrm)))
		return -EINVAL;

	xp = xfrm_state_policy_mapping(xfrm);
	if (!xp) {
		ASFCTRL_WARN("Policy not Available for this SA");
		return -EINVAL;
	}
	dir = xfrm_policy_id2dir(xp->index);
	if (!xp->asf_cookie) {
		ASFCTRL_WARN("Policy not offloaded, xp = %p DIR=%d(%s) ",
			xp, dir, XFRM_DIR(dir));
		if (asfctrl_xfrm_add_policy(xp, dir)) {
			ASFCTRL_WARN("Unable to offload Policy");
			return -EINVAL;
		}
	}

	if (dir == XFRM_POLICY_OUT)
		return asfctrl_xfrm_add_outsa(xfrm, xp);
	else
		return asfctrl_xfrm_add_insa(xfrm, xp);
	return -EINVAL;
}

int asfctrl_xfrm_delete_sa(struct xfrm_state *xfrm)
{
	int cont_id, dir;
	int handle;
	bool bLockFlag;

	ASFCTRL_FUNC_ENTRY;

	if (!xfrm->asf_sa_cookie || xfrm->asf_sa_cookie > asfctrl_max_sas) {
		ASFCTRL_WARN("Not an offloaded SA");
		return -EINVAL;
	}
	dir = xfrm->asf_sa_direction;

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);

	if (match_sa_index_no_lock(xfrm, dir) < 0) {
		ASFCTRL_WARN("Not an offloaded SA -1");
		ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
		return -EINVAL;
	}
	cont_id = sa_table[dir][xfrm->asf_sa_cookie - 1].container_id;
	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);

	if (dir == OUT_SA) {
		ASFIPSecRuntimeDelOutSAArgs_t delSA;
		ASFCTRL_INFO("Delete Encrypt SA");

		delSA.ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		delSA.ulSPDContainerIndex = cont_id;
		delSA.ulSPDMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
#ifdef ASF_IPV6_FP_SUPPORT
		if (xfrm->props.family == AF_INET6) {
			delSA.DestAddr.bIPv4OrIPv6 = 1;
			memcpy(delSA.DestAddr.ipv6addr,
					xfrm->id.daddr.a6, 16);
		} else {
#endif
			delSA.DestAddr.bIPv4OrIPv6 = 0;
			delSA.DestAddr.ipv4addr = xfrm->id.daddr.a4;
#ifdef ASF_IPV6_FP_SUPPORT
		}
#endif
		delSA.ucProtocol = xfrm->id.proto;
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
#ifdef ASF_IPV6_FP_SUPPORT
		if (xfrm->props.family == AF_INET6) {
			delSA.DestAddr.bIPv4OrIPv6 = 1;
			memcpy(delSA.DestAddr.ipv6addr,
					xfrm->id.daddr.a6, 16);
		} else {
#endif
			delSA.DestAddr.bIPv4OrIPv6 = 0;
			delSA.DestAddr.ipv4addr = xfrm->id.daddr.a4;
#ifdef ASF_IPV6_FP_SUPPORT
		}
#endif
		delSA.ucProtocol = xfrm->id.proto;
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

	if (is_sa_offloadable(xfrm))
		return -EINVAL;

	if (unlikely(!xp)) {
		xp = xfrm_state_policy_mapping(xfrm);
		if (unlikely(!xp)) {
			ASFCTRL_WARN("Policy not found for this SA");
			return -EINVAL;
		}
	}

	if (is_policy_offloadable(xp))
		return -EINVAL;

	/* Check if Container is already configured down. */
	if (verify_container_index(xp, ASF_OUT_CONTANER_ID)) {
		ASFCTRL_WARN("Policy is already offloaded cookie = %x id =%u",
			xp->asf_cookie, xp->index);
		goto sa_check;
	} else {
		/* Offloading the out policy */
		ASFIPSecConfigAddOutSPDContainerArgs_t outSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		i = alloc_container_index(xp, ASF_OUT_CONTANER_ID);
		if (i >= 0) {
			ASFCTRL_TRACE("Out Container Index %d", i);
			outSPDContainer.ulSPDContainerIndex = i;
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
		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();
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

	if (unlikely(!xp)) {
		xp = xfrm_state_policy_mapping(xfrm);
		if (unlikely(!xp)) {
			ASFCTRL_WARN("Policy not found for this SA");
			return -EINVAL;
		}
	}

	if (is_policy_offloadable(xp))
		return -EINVAL;

	/* Check if Container is already configured down. */
	if (verify_container_index(xp, ASF_IN_CONTANER_ID)) {
		ASFCTRL_WARN("Offloaded  Policy cookie = %x id =%d",
			xp->asf_cookie, xp->index);
		goto sa_check;
	} else {
		ASFIPSecConfigAddInSPDContainerArgs_t	inSPDContainer;
		ASF_IPSecPolicy_t			spdParams;

		i = alloc_container_index(xp, ASF_IN_CONTANER_ID);
		if (i >= 0) {
			ASFCTRL_TRACE("In Container Index %d", i);
			inSPDContainer.ulSPDContainerIndex = i;
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
		/* Changing the VSG Magic Number of Policy Delete */
		asfctrl_invalidate_sessions();
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
	bool bLockFlag;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	ASFCTRL_FUNC_ENTRY;

	ASFCTRL_WARN("Packet received spi =0x%x", xfrm->id.spi);

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);
	if (match_sa_index_no_lock(xfrm, OUT_SA) < 0) {
		ASFCTRL_INFO("SA offloaded with Junk cookie");
		xfrm->asf_sa_cookie = 0;
		ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
		return -EINVAL;
	}

	sa_id = xfrm->asf_sa_cookie - 1;
	Buffer.nativeBuffer = skb;
#ifdef ASF_IPV6_FP_SUPPORT
	if (xfrm->props.family == AF_INET6) {
		daddr.bIPv4OrIPv6 = 1;
		memcpy(daddr.ipv6addr, xfrm->id.daddr.a6, 16);
	} else {
#endif
		daddr.bIPv4OrIPv6 = 0;
		daddr.ipv4addr = xfrm->id.daddr.a4;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif
	cont_id = sa_table[OUT_SA][sa_id].container_id;

	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);

	skb_dst_drop(skb);

	if ((skb_tailroom(skb) < ASF_IPSEC_NEEDED_TAILROOM)
		|| (skb_headroom(skb) < ASF_IPSEC_NEEDED_HEADROOM)) {
		int headroom, tailroom;
		tailroom = ASF_IPSEC_NEEDED_TAILROOM - skb_tailroom(skb);
		headroom = ASF_IPSEC_NEEDED_HEADROOM - skb_headroom(skb);

		if (pskb_expand_head(skb, (headroom > 0) ? headroom : 0,
			(tailroom > 0) ? tailroom : 0, flags)) {
			ASFCTRL_ERR("Packet does not have enough"
				"eadroom & tailroom for IPSEC");
			return -EINVAL;
		}
	}

	ASFIPSecEncryptAndSendPkt(ASF_DEF_VSG,
			ASF_DEF_IPSEC_TUNNEL_ID,
			cont_id,
			asfctrl_vsg_ipsec_cont_magic_id,
			xfrm->id.spi,
			daddr,
			xfrm->id.proto,
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
	ASF_int32_t cii;
	bool bLockFlag;
	struct net_device *dev = skb->dev;
#ifdef ASF_IPV6_FP_SUPPORT
	struct iphdr *iph = ip_hdr(skb);
#endif
	ASFCTRL_FUNC_ENTRY;

	ASFCTRL_WARN("Packet received spi =0x%x", xfrm->id.spi);

	ASF_SPIN_LOCK(bLockFlag, &sa_table_lock);
	if (match_sa_index_no_lock(xfrm, IN_SA) < 0) {
		ASFCTRL_INFO("SA offloaded with Junk cookie");
		xfrm->asf_sa_cookie = 0;
		ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);
		return -EINVAL;
	}
	ASF_SPIN_UNLOCK(bLockFlag, &sa_table_lock);

	cii = asfctrl_dev_get_cii(dev);

	ASFCTRL_INFO("Pkt received data = 0x%x, net = 0x%x, skb->len = %d",
		(unsigned int)skb->data,
		(unsigned int)skb_network_header(skb), skb->len);

	Buffer.nativeBuffer = skb;
#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6) {
		skb->data = skb->data - sizeof(struct ipv6hdr);
		skb->len = skb->len + sizeof(struct ipv6hdr);
	} else {
#endif
	skb->len += sizeof(struct iphdr);
	skb->data -= sizeof(struct iphdr);
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif
	skb_dst_drop(skb);
	ASFIPSecDecryptAndSendPkt(ASF_DEF_VSG,
			Buffer,
			asfctrl_generic_free,
			skb,
			cii);

	ASFCTRL_FUNC_EXIT;
	return 0;
}

static int fsl_send_notify(struct xfrm_state *x, const struct km_event *c)
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
				const struct km_event *c)
{
	ASFCTRL_FUNC_ENTRY;
	ASFCTRL_INFO("EVENT = %d xp=%x", c->event, (unsigned int) xp);

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
		(dir == XFRM_POLICY_IN) ? "IN" :
		((dir == XFRM_POLICY_OUT) ? "OUT" : "FWD"));
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
	struct xfrm_policy *xp)
{
	ASFCTRL_FUNC_TRACE;
#ifdef ASFCTRL_IPSEC_DEBUG
	asfctrl_xfrm_dump_policy(xp, 0);
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
static int fsl_send_migrate(const struct xfrm_selector *sel, u8 dir, u8 type,
			const struct xfrm_migrate *m, int num_bundles,
			const struct xfrm_kmaddress *k)
{
	ASFCTRL_INFO("With CONFIG_NET_KEY_MIGRATE");
	return -EINVAL;
}
#else
static int fsl_send_migrate(const struct xfrm_selector *sel, u8 dir, u8 type,
		const struct xfrm_migrate *m, int num_bundles,
		const struct xfrm_kmaddress *k)
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
		ASFCTRL_INFO("TMPL daddr = 0x%x, spi=0x%x, saddr = 0x%x,"
			"proto=0x%x, encap = %d reqid = %d, mode = %d,"
			"allalgs=0x%x, eal=0x%x, aal=0x%x, cal =0x%x\n",
			t->id.daddr.a4, t->id.spi, t->saddr.a4,
			t->id.proto, t->encap_family, t->reqid, t->mode,
			t->allalgs, t->ealgos, t->aalgos, t->calgos);
	}
}

void asfctrl_xfrm_dump_policy(struct xfrm_policy *xp, u8 dir)
{
	struct xfrm_sec_ctx *uctx = xp->security;

	ASFCTRL_INFO("xp=0x%x POLICY - %d(%s)- %s, proto=%d, prio = %d, id=%d,"\
		"cookie=0x%x", xp, dir, XFRM_DIR(dir), XFRM_ACTION(xp->action),
		xp->selector.proto, xp->priority, xp->index, xp->asf_cookie);

	ASFCTRL_INFO("type=%d, Flags =0x%x  NR=%d, tmpl = %p, security = %p",
		xp->type, xp->flags, xp->xfrm_nr, xp->xfrm_vec, xp->security);

	ASFCTRL_INFO(" SELECTOR - saddr =0x%x, daddr 0x%x, prefix_s=%u,"
		"sport=%u, prefix_d=%u, dport=%u, IFINDEX=%d",
		xp->selector.saddr.a4, xp->selector.daddr.a4,
		xp->selector.prefixlen_s, xp->selector.sport,
		xp->selector.prefixlen_d, xp->selector.dport,
		xp->selector.ifindex);

	if (uctx) {
		ASFCTRL_INFO("  ctx_doi=%u, ctx_alg=%u,"
			"ctx_len=%u, ctx_sid=%u",
			uctx->ctx_doi, uctx->ctx_alg,
			uctx->ctx_len, uctx->ctx_sid);
	}
	asfctrl_xfrm_dump_tmpl(xp->xfrm_vec);
}

void asfctrl_xfrm_dump_state(struct xfrm_state *xfrm)
{
	struct xfrm_sec_ctx *uctx = xfrm->security;
	struct xfrm_algo_aead *aead = xfrm->aead;
	struct esp_data *esp = xfrm->data;
	int i;

	ASFCTRL_INFO("SA- STATE = family = %u proto=%d",
			xfrm->sel.family, xfrm->sel.proto);

	ASFCTRL_INFO("SELECTOR saddr =0x%x, daddr 0x%x, prefix_s=%u,"
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
	"\nreqid = %d, eal=%x, aal=%x, cal =%x aead=%p, esp =%p",
	xfrm->id.daddr.a4, xfrm->id.spi, xfrm->id.proto, xfrm->props.saddr.a4,
	xfrm->props.reqid, xfrm->props.ealgo, xfrm->props.aalgo,
	xfrm->props.calgo, xfrm->aead, esp);

	if (xfrm->aalg) {
		ASFCTRL_INFO(" EALG alg_name = %s,(%d), key is 0x",
				xfrm->aalg->alg_name, xfrm->aalg->alg_key_len);
#ifdef ASFCTRL_IPSEC_DEBUG2
		for (i = 0; i < xfrm->aalg->alg_key_len/8; i++)
			printk(KERN_INFO "%x", xfrm->aalg->alg_key[i]);
#endif
	}

	if (xfrm->ealg) {
		ASFCTRL_INFO(" EALG alg_name = %s,(%d), key is 0x",
				xfrm->ealg->alg_name, xfrm->ealg->alg_key_len);
#ifdef ASFCTRL_IPSEC_DEBUG2
		for (i = 0; i < xfrm->ealg->alg_key_len/8; i++)
			printk(KERN_INFO "%x", xfrm->ealg->alg_key[i]);
#endif
	}

	if (aead && esp)
		ASFCTRL_INFO(" alg_name=%s, key_len=%d, icv_len=%d",
		aead->alg_name, aead->alg_key_len, aead->alg_icv_len);

	ASFCTRL_INFO(" LifeTime Soft-Hard = %u -%u KBytes = %u - %u",
		xfrm->lft.soft_use_expires_seconds,
		xfrm->lft.hard_use_expires_seconds,
		xfrm->lft.soft_byte_limit/1024,
		xfrm->lft.hard_byte_limit/1024);
}
#endif

