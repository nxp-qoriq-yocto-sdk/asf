/* Copyright (C) 2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asfctrl.h
 *
 * Common definations for the ASF Control Module
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
/*  Revision History    : 1.0
*  Version     Date         Author              Change Description
*  1.0        20/07/2010    Hemant Agrawal      Initial Development
***************************************************************************/
#ifndef __ASFCTRL_H__
#define __ASFCTRL_H__

#define T_BOOL		uint8_t
#define T_UINT8		uint8_t
#define T_UINT16	uint16_t
#define T_UINT32	uint32_t
#define T_UCHAR8	uint8_t
#define T_CHAR8		int8_t
#define T_INT32		int32_t

#define ASFCTRL_TRUE	((T_BOOL)1)
#define ASFCTRL_FALSE	((T_BOOL)0)

#define T_SUCCESS	0
#define T_FAILURE	1

#define ASF_DEF_VSG 		0
#define ASF_DEF_ZN_ID 		0
#define ASF_MAX_NUM_VSG	2

#define ASFCTRL_MAX_IFACES	(16)

#define ASF_ASYNC_RESPONSE ASF_FALSE

#define ASFCTRL_DUMMY_SKB_CB_OFFSET	(16)
#define ASFCTRL_DUMMY_SKB_MAGIC1	(0xDE)
#define ASFCTRL_DUMMY_SKB_MAGIC2	(0xAD)

#define ASFCTRL_IPPROTO_DUMMY_L2BLOB 		(0x6F)
#define ASFCTRL_IPPROTO_DUMMY_IPSEC_L2BLOB 	(0x70)
#define ASFCTRL_IPPROTO_DUMMY_FWD_L2BLOB 	(0x71)

#define ASF_TCP_INAC_TMOUT	(5*60*60)
#define ASF_UDP_INAC_TMOUT	(180)

#define DEFVAL_INACTIVITY_DIVISOR	(4)

#define AsfBuf2Skb(a)   ((struct sk_buff *)(a.nativeBuffer))

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

extern uint32_t asfctrl_vsg_config_id;

extern int asf_ip_send(struct sk_buff *skb);
extern T_INT32 asfctrl_create_dev_map(struct net_device *dev,
				T_INT32 bForce);
extern T_INT32 asfctrl_delete_dev_map(struct net_device *dev);
extern int asfctrl_sysfs_init(void);
extern int asfctrl_sysfs_exit(void);

extern int asfctrl_dev_get_cii(struct net_device *dev);
extern struct kobject *asfctrl_kobj;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT

typedef int (*asfctrl_ipsec_get_flow_info)(bool *ipsec_in, bool *ipsec_out,
					ASFFFPIpsecInfo_t *ipsec_info,
					struct net *net,
					struct flowi flow);

typedef void (*asfctrl_ipsec_l2blob_update)(struct sk_buff *skb,
					ASF_uint32_t hh_len,
					T_UINT16 ulDeviceID);

typedef void (*asfctrl_ipsec_vsg_magicnum_update)(void);

extern void asfctrl_register_ipsec_func(asfctrl_ipsec_get_flow_info   p_flow,
					asfctrl_ipsec_l2blob_update  p_l2blob,
				asfctrl_ipsec_vsg_magicnum_update p_vsgmagic);

extern asfctrl_ipsec_get_flow_info fn_ipsec_get_flow4;

#endif

extern void asfctrl_invalidate_sessions(void);
#ifdef CONFIG_PPPOE
extern struct net_device *ppp_asf_get_parent_dev(struct net_device *pDev,
							T_UINT16 *pSessId);
#endif

#ifdef CONFIG_VLAN_8021Q
extern struct net_device *__vlan_get_real_dev(struct net_device *dev,
						u16 *vlan_id);
#endif

#ifdef ASFCTRL_FWD_FP_SUPPORT

typedef void (*asfctrl_fwd_l2blob_update)(struct sk_buff *skb,
					ASF_uint32_t hh_len,
					T_UINT32 ulDeviceID);
typedef void (*asfctrl_fwd_l3_route_flush_t)(void);
typedef void (*asfctrl_fwd_l3_route_add_t)(void);

extern void  asfctrl_register_fwd_func(asfctrl_fwd_l2blob_update  p_l2blob,
					asfctrl_fwd_l3_route_add_t route_add,
					asfctrl_fwd_l3_route_flush_t  route_flush );

#endif

extern void asfctrl_linux_unregister_ffp(void);
extern void asfctrl_linux_register_ffp(void);

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
	#define DEBUG_GLOBAL_LEVEL 	TRACE
#else
	#define DEBUG_GLOBAL_LEVEL 	ERROR
#endif

#define ASFCTRL_FATAL(fmt, arg...) \
	printk(KERN_ERR"\n %s-%d:FATAL:" fmt, __func__, __LINE__, ##arg)

#if (DEBUG_GLOBAL_LEVEL >= ERROR)
	#define ASFCTRL_ERR(fmt, arg...) \
	printk(KERN_ERR"\n %s-%d:ERROR:" fmt, __func__, __LINE__, ##arg)
#else
	#define ASFCTRL_ERR(fmt, arg...)
#endif

#if (DEBUG_GLOBAL_LEVEL >= WARNING)
	#define ASFCTRL_WARN(fmt, arg...) \
	printk(KERN_WARNING"\n %s-%d:WARNING:" fmt, \
	__func__, __LINE__, ##arg)
#else
	#define ASFCTRL_WARN(fmt, arg...)
#endif

#if (DEBUG_GLOBAL_LEVEL >= INFO)
	#define ASFCTRL_INFO(fmt, arg...) \
	printk(KERN_INFO"\n %s-%d:INFO:" fmt, __func__, __LINE__, ##arg)
#else
	#define ASFCTRL_INFO(fmt, arg...)
#endif

#if (DEBUG_GLOBAL_LEVEL >= TRACE)
	#define ASFCTRL_TRACE(fmt, arg...) \
	printk(KERN_INFO"\n%s-%d:DBG:"fmt, \
		__func__, __LINE__, ##arg)
	#define ASFCTRL_FUNC_ENTRY \
	printk(KERN_INFO"%s-ENTRY", __func__)

	#define ASFCTRL_FUNC_EXIT \
	printk(KERN_INFO"%s-EXIT", __func__)

	#define ASFCTRL_FUNC_TRACE \
	printk(KERN_INFO"%s-%d-TRACE", __func__, __LINE__)

#else
	#define ASFCTRL_TRACE(fmt, arg...)
	#define ASFCTRL_FUNC_ENTRY
	#define ASFCTRL_FUNC_EXIT
	#define ASFCTRL_FUNC_TRACE
#endif

#if (DEBUG_GLOBAL_LEVEL >= LOGS)
	#define ASFCTRL_DBG(fmt, arg...) \
	printk(KERN_INFO"\n%s-%d:DBGL2:"fmt, \
	__func__, __LINE__, ##arg)

#else
	#define ASFCTRL_DBG(fmt, arg...)
#endif

#endif /*__ASFCTRL_H__*/
