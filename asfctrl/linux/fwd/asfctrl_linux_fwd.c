/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_linux_fwd.c
 *
 * Description: Added Support for dynamic rules manupulation for Forwarding by
 * integrating with ASF module.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/*
*  History
*  Version     Date		Author		Change Description
*  1.0	     22/09/2010	     Sachin Saxena	Initial Development
*
*/
/***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <gianfar.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/route.h>

#include "../../../asfffp/driver/asf.h"
#include "../../../asffwd/driver/asffwdapi.h"
#include "../ffp/asfctrl.h"


#define ASFCTRL_LINUX_FWD_VERSION	"1.0"
#define ASFCTRL_LINUX_FWD_DESC 	"ASF Linux-Forwarding Integration Driver"

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
MODULE_DESCRIPTION(ASFCTRL_LINUX_FWD_DESC);
#define ASFCTRL_FWD_EXPIRY_TIMER	(180) /* Sec */
/* Global Variables */
ASFFWDCap_t g_fwd_cap;

typedef struct asfctrl_fwd_L2blobPktData_s {
	ASFFWDCacheEntryTuple_t	tuple;
	ASF_uint32_t       ulVsgId;
	ASF_uint32_t       ulPathMTU;
} asfctrl_fwd_L2blobPktData_t;


static T_INT32 asfctrl_fwd_XmitL2blobDummyPkt(ASFFWDCacheEntryTuple_t *tpl)
{
	struct	sk_buff *skb;
	int	ret;

	skb = ASFKernelSkbAlloc(1024, GFP_ATOMIC);
	if (skb) {
		asfctrl_fwd_L2blobPktData_t *pData;
		struct iphdr *iph;
		struct net_device *dev;

		dev = dev_get_by_name(&init_net, "lo");

		if (0 != ip_route_input(skb, tpl->ulDestIp,
					tpl->ulSrcIp, tpl->ucDscp, dev)
			|| skb_rtable(skb)->rt_flags & RTCF_LOCAL) {
			ASFCTRL_INFO("\n Route not found for"
				" dst %x local host : %d", tpl->ulDestIp,
			(skb_rtable(skb)->rt_flags & RTCF_LOCAL) ? 1 : 0);
			dev_put(dev);
			ASFKernelSkbFree(skb);
			return T_FAILURE;
		}
		dev_put(dev);
		ASFCTRL_INFO("\n Route found for dst %x, src %x, tos %d ",
				tpl->ulDestIp, tpl->ulSrcIp, tpl->ucDscp);
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
		iph->tos = tpl->ucDscp;
		iph->protocol = ASFCTRL_IPPROTO_DUMMY_FWD_L2BLOB;

		pData = (asfctrl_fwd_L2blobPktData_t *)skb_put(skb,
			sizeof(asfctrl_fwd_L2blobPktData_t));
		pData->ulVsgId = ASF_DEF_VSG;
		memcpy(&pData->tuple, tpl, sizeof(ASFFWDCacheEntryTuple_t));

		pData->ulPathMTU = skb->dev->mtu;
		skb->protocol = htons(ETH_P_IP);
		asfctrl_skb_mark_dummy(skb);
		ASFCTRL_INFO("\n DUmmy Mark [0x%X] [0x%X] \n",
			skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET],
			skb->cb[ASFCTRL_DUMMY_SKB_CB_OFFSET+1]);

		ret = asf_ip_send(skb);
		if (ret == -EINVAL)
			ASFCTRL_ERR("Sending L2Blob Dummy packet Failed.\n");
	}
	return T_SUCCESS;
}

ASF_void_t asfctrl_fwd_fnCacheEntryNotFound(
					ASF_uint32_t ulVSGId,
					ASF_uint32_t ulCommonInterfaceId,
					ASFBuffer_t Buffer,
					genericFreeFn_t pFreeFn,
					ASF_void_t    *freeArg)
{
	struct sk_buff *skb = AsfBuf2Skb(Buffer);
	ASFCTRL_FUNC_TRACE;

	if (skb)
		netif_receive_skb(skb);
	return;
}

ASF_void_t asfctrl_fwd_fnRuntime(
				ASF_uint32_t ulVSGId,
				ASF_uint32_t cmd,
				ASF_void_t    *pReqIdentifier,
				ASF_uint32_t ulReqIdentifierlen,
				ASF_void_t   *pResp,
				ASF_uint32_t ulRespLen)
{
	ASFCTRL_FUNC_TRACE;
	switch (cmd) {
	case ASF_FWD_CREATE_CACHE_ENTRY:
	{
#if (DEBUG_GLOBAL_LEVEL >= INFO)
		ASFFWDCreateCacheEntryResp_t *pInfo =
			(ASFFWDCreateCacheEntryResp_t *)pResp;
#endif

		ASFCTRL_INFO("CreateCacheEntry Response (Result %d) hash %d\n",
				ntohl(pInfo->iResult), pInfo->ulHashVal);
	}
	break;

	case ASF_FWD_DELETE_CACHE_ENTRY:
	{
#if (DEBUG_GLOBAL_LEVEL >= INFO)
		ASFFWDDeleteCacheEntryResp_t *pInfo =
			(ASFFWDDeleteCacheEntryResp_t *)pResp;
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

ASF_void_t asfctrl_fwd_fnCacheEntryRefreshL2Blob(ASF_uint32_t ulVSGId,
			ASFFWDCacheEntryL2BlobRefreshCbInfo_t *pInfo)
{
	struct sk_buff  *skb;

	ASFCTRL_FUNC_TRACE;
	ASFCTRL_INFO("L2Blob Refresh Request Indication\n");
	skb = AsfBuf2Skb(pInfo->Buffer);
	if (skb)
		netif_receive_skb(skb);

	asfctrl_fwd_XmitL2blobDummyPkt(&pInfo->packetTuple);
	return;
}

ASF_void_t asfctrl_fwd_fnCacheEntryExpiry(ASF_uint32_t ulVSGId,
				ASFFWDCacheEntryExpiryCbInfo_t *pInfo)
{
	ASFCTRL_FUNC_TRACE;
	ASFCTRL_INFO("Cache Entry Expiry Indication\n");
	return;
}


ASF_void_t asfctrl_fwd_fnAuditLog(ASFLogInfo_t *pLogInfo)
{
	ASFCTRL_FUNC_TRACE;
	ASFCTRL_INFO(" VSG[%u], MsgId[%u]\n",
					pLogInfo->ulVSGId,
					pLogInfo->ulMsgId);
	return;
}


ASF_void_t asfctrl_fwd_l2blob_update_fn(struct sk_buff *skb,
	ASF_uint32_t hh_len,
	T_UINT32 ulDeviceID)
{
	ASFFWDUpdateCacheEntry_t pCacheData;
	ASF_uint32_t		ulVSGId;
	asfctrl_fwd_L2blobPktData_t *pData;
	struct iphdr		*iph;
	int err = ASFFWD_RESPONSE_FAILURE;

	iph = (struct iphdr *)(skb->data+hh_len);
	ASFCTRL_INFO("L2 Blob Indication:--------------\n");


	pData = (asfctrl_fwd_L2blobPktData_t *) (skb->data+hh_len+iph->ihl * 4);
	ASFCTRL_INFO("pData: SrcIP %x, DstIp %x, Tos %d\n",
				pData->tuple.ulSrcIp,
				pData->tuple.ulDestIp,
				pData->tuple.ucDscp);
	memcpy(&pCacheData.tuple, &pData->tuple,
			sizeof(ASFFWDCacheEntryTuple_t));
	ulVSGId = pData->ulVsgId;
	pCacheData.bL2blobUpdate = 1;
	pCacheData.u.l2blob.ulPathMTU = pData->ulPathMTU;
	pCacheData.u.l2blob.ulDeviceId = ulDeviceID;
	pCacheData.u.l2blob.l2blobLen =  hh_len;
	memcpy(&pCacheData.u.l2blob.l2blob, skb->data,
					pCacheData.u.l2blob.l2blobLen);
	if (vlan_tx_tag_present(skb)) {
		pCacheData.u.l2blob.bTxVlan = 1;
		pCacheData.u.l2blob.usTxVlanId = vlan_tx_tag_get(skb);
	} else
		pCacheData.u.l2blob.bTxVlan = 0;

	pCacheData.u.l2blob.bUpdatePPPoELen = 0;

	err = ASFFWDRuntime(ulVSGId, ASF_FWD_UPDATE_CACHE_ENTRY,
			&pCacheData, sizeof(ASFFWDUpdateCacheEntry_t),
			NULL, 0);
	if (err)
		ASFCTRL_ERR("ASF_FWD_UPDATE_CACHE_ENTRY fialed.\n");
	/* Packet will be dropped by Calling function
	   "asfctrl_dev_fp_tx_hook"*/
	return;
}
EXPORT_SYMBOL(asfctrl_fwd_l2blob_update_fn);

int  asfctrl_fwd_l3_route_add(
	int iif,
	struct net_device *dev,
	uint32_t daddr,
	uint32_t saddr,
	int tos,
	void *l2_head
)
{
	ASFFWDCreateCacheEntry_t cmd;
	ASF_Modes_t mode;

	ASFGetVSGMode(ASF_DEF_VSG, &mode);
	/* If ASF is disabled or mode is not FWD, simply return */
	if ((0 == ASFGetStatus()) || (mode != fwdMode))
		return 0;
	/*loopback dummy packet */
	if (iif == 1) {
		ASFCTRL_INFO("dummy Loop Back offload...ignoring\n");
		return 0;
	}
	if (iif == 0) {
		ASFCTRL_INFO("Self generated packet offload...ignoring\n");
		return 0;
	}
	if ((daddr & 0x000000FF) == 0xFF)
		return 0;

	if (dev->type != ARPHRD_ETHER) {
		ASFCTRL_INFO("NON-ETHERNET Device flow are"
					" not offload...ignoring\n");
		return 0;
	}
	if (asfctrl_dev_get_cii(dev) < 0) {
		ASFCTRL_INFO("Unregistered Device"
					" not offload...ignoring\n");
		return 0;
	}
	cmd.CacheEntry.tuple.ucDscp = tos;
	cmd.CacheEntry.tuple.ulDestIp = daddr;
	cmd.CacheEntry.tuple.ulSrcIp = saddr;
	cmd.CacheEntry.ulExpTimeout = ASFCTRL_FWD_EXPIRY_TIMER;
	cmd.ASFFwdInfo = NULL;

	ASFCTRL_INFO("\n sip : %x dip : %x tos : %d, iif: %d\n",
		cmd.CacheEntry.tuple.ulSrcIp,
		cmd.CacheEntry.tuple.ulDestIp,
		cmd.CacheEntry.tuple.ucDscp,
		iif);

	if (ASFFWDRuntime(ASF_DEF_VSG, ASF_FWD_CREATE_CACHE_ENTRY,
		&cmd, sizeof(cmd), NULL, 0) == ASFFWD_RESPONSE_SUCCESS) {

		/* Cache Entry crated successfully. populate the L2 info*/
		asfctrl_fwd_XmitL2blobDummyPkt(&cmd.CacheEntry.tuple);
		ASFCTRL_INFO("Flow created successfully! --\n");
	} else
		ASFCTRL_INFO("Flow creation Failed! --\n");
	return 0;
}

/* Thourgh hit and trial, it has been found that there is a gap of
   maximum of 17 sec between multiple flush calls invoke by
   Linux for same event */
#define MAX_FLUSH_GAP 17
void asfctrl_fwd_l3_route_flush(void)
{
	static unsigned long last_jiffes;

	if ((jiffies - last_jiffes) > MAX_FLUSH_GAP) {
		ASFCTRL_INFO("Flushing Route Table! --\n");
		ASFFWDRuntime(ASF_DEF_VSG,
				ASF_FWD_FLUSH_CACHE_TABLE,
				NULL, 0, NULL, 0);
	}
	last_jiffes = jiffies;

	return;
}
static int __init asfctrl_linux_fwd_init(void)
{

	ASFFWDExpiryParams_t expCmd;
	ASFCap_t  asf_cap;
	ASFFWDCallbackFns_t asfctrl_Cbs = {
		NULL,
		NULL,
		asfctrl_fwd_fnCacheEntryNotFound,
		asfctrl_fwd_fnRuntime,
		asfctrl_fwd_fnCacheEntryExpiry,
		asfctrl_fwd_fnCacheEntryRefreshL2Blob,
		asfctrl_fwd_fnAuditLog
	};

	ASFGetCapabilities(&asf_cap);
	if (!asf_cap.mode[fwdMode]) {
		ASFCTRL_ERR("Forwarding mode Not supported in ASF");
		return -1;
	}
	if (!asf_cap.bBufferHomogenous) {
		ASFCTRL_ERR("Hetrogeneous Buffer mode is not supported in ASF");
		return -1;
	}
	ASFFWDSetNotifyPreference(ASF_ASYNC_RESPONSE);

	ASFFWDRegisterCallbackFns(&asfctrl_Cbs);

	expCmd.ulExpiryInterval = ASFCTRL_FWD_EXPIRY_TIMER;
	ASFFWDSetCacheEntryExpiryParams(&expCmd);

	ASFFWDGetCapabilities(&g_fwd_cap);
	/* Number of VSG in FWD module must not greater
	than those of ASF Core module */
	if (g_fwd_cap.ulMaxVSGs > asf_cap.ulNumVSGs) {
		ASFCTRL_ERR("ERROR: FWD VSG[%d] > ASF VSG[%d].\n",
			g_fwd_cap.ulMaxVSGs, asf_cap.ulNumVSGs);
		return -1;
	}
	if (!g_fwd_cap.bBufferHomogenous) {
		ASFCTRL_ERR("Hetrogeneous Buffer mode is"
				" not supported in ASFFWD\n");
		return -1;
	}
	/* Register Callback function with ASF control layer to
	get L2blob information, route add event and flush events */
	asfctrl_register_fwd_func(&asfctrl_fwd_l2blob_update_fn,
				&asfctrl_fwd_l3_route_add,
				&asfctrl_fwd_l3_route_flush);

	ASFCTRL_DBG("ASF Control Module - Forward Loaded\n");
	return 0;
}

static void __exit asfctrl_linux_fwd_exit(void)
{
	ASFFWDCallbackFns_t asfctrl_Cbs = {
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	};

	/* De-register Callback functins with FWD module */
	ASFFWDRegisterCallbackFns(&asfctrl_Cbs);

	asfctrl_register_fwd_func(NULL, NULL, NULL);

	ASFCTRL_DBG("ASF Control Module - Forward Unloaded \n");
}

module_init(asfctrl_linux_fwd_init);
module_exit(asfctrl_linux_fwd_exit);
