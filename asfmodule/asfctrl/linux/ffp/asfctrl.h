/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl.h
 *
 * Description: Common definations for the ASF Control Module
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/*
 * History
*  Version     Date         Author              Change Description
*  1.0        20/07/2010    Hemant Agrawal      Initial Development
*/
/***************************************************************************/
#ifndef __ASFCTRL_H__
#define __ASFCTRL_H__

#include <net/xfrm.h>
#define ASFCTRL_TRUE	((ASF_boolean_t)1)
#define ASFCTRL_FALSE	((ASF_boolean_t)0)

#define T_SUCCESS	0
#define T_FAILURE	1

#define ASF_DEF_VSG 		0
#define ASF_DEF_ZN_ID 		0

#define ASFCTRL_MAX_IFACES	(16)

#define ASF_ASYNC_RESPONSE ASF_FALSE

#define ASFCTRL_DUMMY_SKB_CB_OFFSET	(46)
#define ASFCTRL_DUMMY_SKB_MAGIC1	(0xDE)
#define ASFCTRL_DUMMY_SKB_MAGIC2	(0xAD)

#define ASFCTRL_IPPROTO_DUMMY_L2BLOB 		(0x6F)
#define ASFCTRL_IPPROTO_DUMMY_IPSEC_L2BLOB 	(0x70)
#define ASFCTRL_IPPROTO_DUMMY_FWD_L2BLOB 	(0x71)
#define ASFCTRL_IPPROTO_DUMMY_TERM_L2BLOB	(0x72)

#define ASF_TCP_INAC_TMOUT	(5*60*60*24)
#define ASF_UDP_INAC_TMOUT	(180)

/*NF_CONN status BIT for Session offloaded to ASF */
#define IPS_ASF_OFFLOADED_BIT 20
#define IPS_ASF_OFFLOADED (1 << IPS_ASF_OFFLOADED_BIT)

#define DEFVAL_INACTIVITY_DIVISOR	(4)
#ifdef ASF_IPV6_FP_SUPPORT
#define ASF_IPV6_HDR_LEN	(40)
#endif
#define AsfBuf2Skb(a)	((struct sk_buff *)(a.nativeBuffer))
#define ASFCTRLKernelSkbAlloc	alloc_skb

#define ASFCTRLKernelSkbFree(freeArg)	kfree_skb((struct sk_buff *)freeArg)
#ifdef ASFCTRL_TERM_FP_SUPPORT
#define ASFCTRLSkbFree(freeArg)		packet_kfree_skb((struct sk_buff *)freeArg)
#else
#define ASFCTRLSkbFree(freeArg)		kfree_skb((struct sk_buff *)freeArg)
#endif

#ifdef ASFCTRL_TERM_FP_SUPPORT
#define ASFCTRL_netif_receive_skb	pmal_netif_receive_skb
#else
#define ASFCTRL_netif_receive_skb	netif_receive_skb
#endif

ASF_void_t  asfctrl_fnNoFlowFound(
				ASF_uint32_t ulVSGId,
				ASF_uint32_t ulCommonInterfaceId,
				ASF_uint32_t ulZoneId,
				ASFBuffer_t Buffer,
				genericFreeFn_t pFreeFn,
				ASF_void_t    *freeArg);


ASF_void_t asfctrl_fnRuntime(
			ASF_uint32_t ulVSGId,
			ASF_uint32_t cmd,
			ASF_void_t    *pReqIdentifier,
			ASF_uint32_t ulReqIdentifierlen,
			ASF_void_t   *pResp,
			ASF_uint32_t ulRespLen);


ASF_void_t asfctrl_fnFlowRefreshL2Blob(ASF_uint32_t ulVSGId,
			ASFFFPFlowL2BlobRefreshCbInfo_t *pInfo);


ASF_void_t asfctrl_fnFlowActivityRefresh(ASF_uint32_t ulVSGId,
			ASFFFPFlowRefreshInfo_t *pRefreshInfo);


ASF_void_t asfctrl_fnFlowTcpSpecialPkts(ASF_uint32_t ulVSGId,
			ASFFFPFlowSpecialPacketsInfo_t *pInfo);


ASF_void_t asfctrl_fnFlowValidate(ASF_uint32_t ulVSGId,
			ASFFFPFlowValidateCbInfo_t *pInfo);



ASF_void_t asfctrl_fnAuditLog(ASFLogInfo_t  *pLogInfo);



ASF_void_t asfctrl_fnZoneMappingNotFound(
					ASF_uint32_t ulVSGId,
					ASF_uint32_t ulCommonInterfaceId,
					ASFBuffer_t Buffer,
					genericFreeFn_t pFreeFn,
					ASF_void_t    *freeArg);


typedef struct asf_linux_L2blobPktData_s {
   ASFFFPFlowTuple_t  tuple;
   ASF_uint32_t       ulVsgId;
   ASF_uint32_t       ulZoneId;
   ASF_uint32_t       ulPathMTU;
} asf_linux_L2blobPktData_t;

static inline void asfctrl_skb_mark_dummy(struct sk_buff *skb)
{
	skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET] = ASFCTRL_DUMMY_SKB_MAGIC1;
	skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET+1] = ASFCTRL_DUMMY_SKB_MAGIC2;
}

static inline void asfctrl_skb_unmark_dummy(struct sk_buff *skb)
{
	skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET] = 0;
	skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET+1] = 0;
}

static inline int asfctrl_skb_is_dummy(struct sk_buff *skb)
{
	if ((skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET] == ASFCTRL_DUMMY_SKB_MAGIC1)
	&& (skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET+1] == ASFCTRL_DUMMY_SKB_MAGIC2))
		return 1;

	return 0;
}

extern uint32_t asfctrl_vsg_config_id[ASF_MAX_VSGS];
extern uint32_t asfctrl_vsg_l2blobconfig_id[ASF_MAX_VSGS];

extern int asf_ip_send(struct sk_buff *skb);
extern ASF_int32_t asfctrl_create_dev_map(struct net_device *dev,
				ASF_int32_t bForce);
extern ASF_int32_t asfctrl_delete_dev_map(struct net_device *dev);
extern int asfctrl_sysfs_init(void);
extern int asfctrl_sysfs_exit(void);

extern int asfctrl_dev_get_cii(struct net_device *dev);
extern struct net_device *asfctrl_dev_get_dev(int cii);
extern struct kobject *asfctrl_kobj;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT

typedef int (*asfctrl_ipsec_get_flow_info)(uint32_t ulVSGId,
					bool *ipsec_in, bool *ipsec_out,
					ASFFFPIpsecInfo_t *ipsec_info,
					struct net *net,
					struct flowi flow, bool bIsIpv6);

typedef void (*asfctrl_ipsec_l2blob_update)(struct sk_buff *skb,
					ASF_uint32_t hh_len,
					ASF_uint16_t ulDeviceID);

typedef void (*asfctrl_ipsec_vsg_magicnum_update)(ASF_uint32_t ulVSGId);

extern void asfctrl_register_ipsec_func(asfctrl_ipsec_get_flow_info   p_flow,
					asfctrl_ipsec_l2blob_update  p_l2blob,
				asfctrl_ipsec_vsg_magicnum_update p_vsgmagic);

extern asfctrl_ipsec_get_flow_info fn_ipsec_get_flow4;

#endif

extern ASF_uint32_t asfctrl_get_ipsec_pol_vsgid(struct xfrm_policy *);
extern ASF_uint32_t asfctrl_get_ipsec_sa_vsgid(struct xfrm_state *);
extern void asfctrl_invalidate_sessions(void);
extern void asfctrl_invalidate_vsg_sessions(ASF_uint32_t ulVSGId);
#ifdef CONFIG_PPPOE
extern struct net_device *ppp_get_parent_dev(struct net_device *pDev,
							ASF_uint16_t *pSessId);
#endif

#ifdef ASFCTRL_FWD_FP_SUPPORT

typedef void (*asfctrl_fwd_l2blob_update)(struct sk_buff *skb,
					ASF_uint32_t hh_len,
					ASF_uint32_t ulDeviceID);
typedef void (*asfctrl_fwd_l3_route_flush_t)(void);
typedef int (*asfctrl_fwd_l3_route_add_t)(int iif,
					struct net_device *dev,
					uint32_t daddr,
					uint32_t saddr,
					int tos,
					void *ctx);

extern void  asfctrl_register_fwd_func(asfctrl_fwd_l2blob_update  p_l2blob,
					asfctrl_fwd_l3_route_add_t route_add,
					asfctrl_fwd_l3_route_flush_t  route_flush);
#endif

#ifdef ASFCTRL_TERM_FP_SUPPORT

typedef void (*asfctrl_term_l2blob_update)(struct sk_buff *skb,
					ASF_uint32_t hh_len,
					ASF_uint32_t ulDeviceID);
typedef void (*asfctrl_term_cache_flush_t)(ASF_uint32_t ulVSGId);

extern void  asfctrl_register_term_func(asfctrl_term_l2blob_update p_l2blob,
					asfctrl_term_cache_flush_t cache_flush);
#endif
extern int ipv6_chk_addr(struct net *net, struct in6_addr *addr,
			struct net_device *dev, int strict);
extern void asfctrl_linux_unregister_ffp(void);
extern void asfctrl_linux_register_ffp(void);
#define PRINT_IPV6(a) pr_info("%x:%x:%x:%x:%x:%x:%x:%x\n", a.s6_addr16[0], \
	a.s6_addr16[1], a.s6_addr16[2], a.s6_addr16[3], a.s6_addr16[4],\
	a.s6_addr16[5], a.s6_addr16[6], a.s6_addr16[7])

/* ********** Debugging Stuff *****************/

/************defining the levels ***************/
#define CRITICAL	1 /**< Crasher: Incorrect flow, NULL pointers/handles.*/
#define ERROR		2 /**< Cannot proceed: Invalid operation, parameters or
				configuration. */
#define WARNING		3 /**< Something is not exactly right, yet it is not
				an error. */
#define INFO		4 /**< Messages which may be of interest to
				user/programmer. */
#define TRACE		5 /**< Program flow messages. */
#define LOGS		6 /**< Program flow messages. */

#ifdef ASFCTRL_DEBUG
	#define ASFCTRL_DEBUG_LEVEL	TRACE
#else
	#define ASFCTRL_DEBUG_LEVEL	ERROR
#endif

#define ASFCTRL_FATAL(fmt, arg...) \
	pr_err("\n %s-%d:FATAL:" fmt, __func__, __LINE__, ##arg)

#if (ASFCTRL_DEBUG_LEVEL >= ERROR)
	#define ASFCTRL_ERR(fmt, arg...) \
	pr_err("\n %s-%d:ERROR:" fmt, __func__, __LINE__, ##arg)
#else
	#define ASFCTRL_ERR(fmt, arg...)
#endif

#if (ASFCTRL_DEBUG_LEVEL >= WARNING)
	#define ASFCTRL_WARN(fmt, arg...) \
	pr_warning("\n %s-%d:WARNING:" fmt, __func__, __LINE__, ##arg)
#else
	#define ASFCTRL_WARN(fmt, arg...)
#endif

#if (ASFCTRL_DEBUG_LEVEL >= INFO)
	#define ASFCTRL_INFO(fmt, arg...) \
	pr_info("\n %s-%d:INFO:" fmt, __func__, __LINE__, ##arg)
#else
	#define ASFCTRL_INFO(fmt, arg...)
#endif

#if (ASFCTRL_DEBUG_LEVEL >= TRACE)
	#define ASFCTRL_TRACE(fmt, arg...) \
	pr_info("\n%s-%d:DBG:"fmt, __func__, __LINE__, ##arg)
	#define ASFCTRL_FUNC_ENTRY \
	pr_info("%s-ENTRY", __func__)

	#define ASFCTRL_FUNC_EXIT \
	pr_info("%s-EXIT", __func__)

	#define ASFCTRL_FUNC_TRACE \
	pr_info("%s-%d-TRACE", __func__, __LINE__)

#else
	#define ASFCTRL_TRACE(fmt, arg...)
	#define ASFCTRL_FUNC_ENTRY
	#define ASFCTRL_FUNC_EXIT
	#define ASFCTRL_FUNC_TRACE
#endif

#if (ASFCTRL_DEBUG_LEVEL >= LOGS)
	#define ASFCTRL_DBG(fmt, arg...) \
	pr_info("\n%s-%d:DBGL2:"fmt, __func__, __LINE__, ##arg)

#else
	#define ASFCTRL_DBG(fmt, arg...)
#endif

#endif /*__ASFCTRL_H__*/
