/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * Author:	Sandeep Malik <Sandeep.Malik@freescale.com>
 *		Hemant Agrawal <hemant@freescale.com>
 *
*/
/* History
*  Version	Date		Author		Change Description
*
*/

/***************************************************************************/

#ifndef _IPSEC_HOOKS_H
#define _IPSEC_HOOKS_H
#include <net/xfrm.h>

struct algo_info {
	const char *alg_name;
	int alg_type;
};

enum alg_type {
	ENCRYPTION = 0,
	AUTHENTICATION,
	INVALID
};

#define OUT_SA	1
#define IN_SA	0
#define ASFCTRL_MAX_SPD_CONTAINERS 300

#define ASF_DEF_IPSEC_TUNNEL_ID 0
#define ASF_DEF_IPSEC_TUNNEL_MAGIC_NUM 1
#define ASF_MAX_TUNNEL		64

#define ASF_OUT_CONTANER_ID 	0
#define ASF_IN_CONTANER_ID 	1
#define MAX_POLICY_CONT_ID 	2

#define ASFCTRL_DEF_PMTU 1500
#define MAX_AUTH_ENC_ALGO	5
#define MAX_ALGO_TYPE		2

#define XFRM_DIR(dir) ((dir == 0) ? "IN" : ((dir == 1) ? "OUT" : "FWD"))

void init_container_indexes(bool init);
void init_sa_indexes(bool init);
int free_container_index(int index, int cont_dir);
int is_policy_offloadable(struct xfrm_policy *xp);

int asfctrl_xfrm_encrypt_n_send(struct sk_buff *skb, struct xfrm_state *xfrm);

int asfctrl_xfrm_decrypt_n_send(struct sk_buff *skb, struct xfrm_state *xfrm);

int asfctrl_xfrm_dec_hook(
		struct xfrm_policy *xp,
		struct xfrm_state *xfrm,
		struct flowi *fl,
		int ifindex);
int asfctrl_xfrm_enc_hook(
		struct xfrm_policy *xp,
		struct xfrm_state *xfrm,
		struct flowi *fl,
		int ifindex);

#ifdef ASFCTRL_IPSEC_DEBUG
void asfctrl_xfrm_dump_tmpl(struct xfrm_tmpl *t);
void asfctrl_xfrm_dump_policy(struct xfrm_policy *xp, u8 dir);
void asfctrl_xfrm_dump_state(struct xfrm_state *xfrm);
#endif

void asfctrl_ipsec_km_unregister(void);
int asfctrl_ipsec_km_register(void);

extern uint32_t asfctrl_vsg_ipsec_cont_magic_id;
extern uint32_t asfctrl_max_sas;
extern uint32_t asfctrl_max_policy_cont;
extern int bRedSideFragment;
extern int bAntiReplayCheck;

extern void  register_ipsec_offload_hook(struct asf_ipsec_callbackfn_s *);
extern void unregister_ipsec_offload_hook(void);

extern int ip_forward_asf_packet(struct sk_buff *);
extern struct xfrm_policy *xfrm_policy_check_flow(struct net *, struct flowi *,
					u16, u8);
extern struct xfrm_policy *xfrm_state_policy_mapping(struct xfrm_state *);

#endif
