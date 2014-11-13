/**************************************************************************
 * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_linux_qos.c
 *
 * Description: Added Support for dynamic QoS configuration via Linux TC.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/*
*  History
*  Version     Date		Author		Change Description
*  1.0	     20/07/2012	     Sachin Saxena	Initial Development
*
*/
/***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/vmalloc.h>
#ifndef CONFIG_DPA
#include <gianfar.h>
#ifndef ASF_ARM
#include <asf_gianfar.h>
#endif
#endif
#ifdef ASFCTRL_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <net/ip.h>
#include <net/sch_generic.h>

#include "../../../asfffp/driver/asf.h"
#include "../ffp/asfctrl.h"
#include "../../../asfqos/driver/asfqosapi.h"


#define ASFCTRL_LINUX_QOS_VERSION	"1.0"
#define ASFCTRL_LINUX_QOS_DESC 	"ASF QoS Configuration Driver"

/** \brief	Driver's license
 *  \details	Dual BSD/GPL
 *  \ingroup	Linux_module
 */
MODULE_LICENSE("Dual BSD/GPL");
/** \brief	Module author
 *  \ingroup	Linux_module
 */
MODULE_AUTHOR("Freescale Semiconductor, Inc");
/** \brief	Module description
 *  \ingroup	Linux_module
 */
MODULE_DESCRIPTION(ASFCTRL_LINUX_QOS_DESC);

#ifdef ASF_INGRESS_MARKER

#define PORT_ANY 0xFFFF
#ifdef	ASF_IPV6_FP_SUPPORT
markerRule_t	*marker_rule_v6;
unsigned int	num_rules_v6;
#endif
markerRule_t	*marker_rule_v4;
unsigned int	num_rules_v4;
u8		dscp_default = ASF_QM_NULL_DSCP;

/* This Function will match the input arguments with Marker databse
   and reurns the DSCP value to be marked, if configured */
ASF_uint8_t ASFMatchMarkerRule(ASF_uint32_t	*src_ip,
				ASF_uint32_t	*dst_ip,
				ASF_uint16_t	src_port,
				ASF_uint16_t	dst_port,
				ASF_uint8_t	proto,
				bool		is_ipv6)
{
	int		i;
	markerRule_t	*rule;
	int             iDscp = dscp_default;

	if (is_ipv6) {
#ifdef	ASF_IPV6_FP_SUPPORT
		if (!marker_rule_v6)
			return ASF_QM_NULL_DSCP;

		ASFCTRL_INFO("I/P: src_ip[0x%X%X%X%X], dst_ip[0x%X%X%X%X], src_port[%d],"
			" dst_port[%d], proto[%d]\n",
			src_ip[0], src_ip[1], src_ip[2], src_ip[3],
			dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3],
			src_port, dst_port, proto);

		for (i = 0; i < num_rules_v6; i++) {
			rule = (markerRule_t *) &marker_rule_v6[i];

			if ((src_ip[0] == rule->src_ip[0])
			&& (src_ip[1] == rule->src_ip[1])
			&& (src_ip[2] == rule->src_ip[2])
			&& (src_ip[3] == rule->src_ip[3])
			&& (dst_ip[0] == rule->dst_ip[0])
			&& (dst_ip[1] == rule->dst_ip[1])
			&& (dst_ip[2] == rule->dst_ip[2])
			&& (dst_ip[3] == rule->dst_ip[3])
			&& ((rule->src_port == PORT_ANY) ||
				(src_port == rule->src_port))
			&& ((rule->dst_port == PORT_ANY) ||
				(dst_port == rule->dst_port))
			&& (proto == rule->proto)) {
				ASFCTRL_INFO("Rule Matched\n");
				/* Masking the Last 2 bits */
				iDscp = rule->uciDscp & 0xFC;
			}
		}
#endif
	} else {/* IPv4 */
		if (!marker_rule_v4)
			return ASF_QM_NULL_DSCP;

		ASFCTRL_INFO("I/P: src_ip[0x%X], dst_ip[0x%X], src_port[%d],"
			" dst_port[%d], proto[%d]\n",
			src_ip[0], dst_ip[0], src_port, dst_port, proto);

		for (i = 0; i < num_rules_v4; i++) {
			rule = (markerRule_t *) &marker_rule_v4[i];

			if ((src_ip[0] == rule->src_ip[0])
			&& (dst_ip[0] == rule->dst_ip[0])
			&& ((rule->src_port == PORT_ANY) ||
				(src_port == rule->src_port))
			&& ((rule->dst_port == PORT_ANY) ||
				(dst_port == rule->dst_port))
			&& (proto == rule->proto)) {
				ASFCTRL_INFO("Rule Matched\n");
				/* Masking the Last 2 bits */
				iDscp = rule->uciDscp & 0xFC;
			}
		}
	}
	/* Reaching here means, No match found */
	return iDscp;
}

ASF_uint8_t ASFMarkLnxPkt(void *buf)
{
	/* Treat all linux packets at priority 2 */
	return 1;
}

void asfctrl_qos_invalidate_flows(void)
{
	ASFFFPConfigIdentity_t cmd;

	/* Invalidate flows */
	memset(&cmd, 0, sizeof(cmd));
	cmd.ulConfigMagicNumber = jiffies;
	ASFFFPUpdateConfigIdentity(0, cmd);
}

void ASFFlushIPv4Marker(void)
{
	if (NULL != marker_rule_v4) {
		vfree(marker_rule_v4);
		marker_rule_v4 = NULL;
		num_rules_v4 = 0;
	}
	/* Invalidate flows */
	asfctrl_qos_invalidate_flows();
	printk(KERN_INFO "IPv4 Marker Rules Flushed\n");
}

int ASFConfigIPv4Marker(marker_db_t *arg)
{
	int			i;

	if (!arg->num_rules || !arg->rule)
		return -EINVAL;

	if (NULL != marker_rule_v4)
		vfree(marker_rule_v4);

	ASFCTRL_INFO("Marker rules[%d] configuration request!\n",
						arg->num_rules);

	num_rules_v4 = arg->num_rules;
	/* Allocate Marker Database */
	marker_rule_v4 = vmalloc(num_rules_v4 * sizeof(markerRule_t));
	if (NULL == marker_rule_v4)
		return -ENOMEM;
	memcpy(marker_rule_v4, arg->rule,
		sizeof(markerRule_t) * num_rules_v4);

	for (i = 0; i < num_rules_v4; i++) {
		markerRule_t *rule;

		rule = (markerRule_t *) &marker_rule_v4[i];

		printk(KERN_INFO"src_ip[%pI4] dst_ip[%pI4] proto[%d] ",
			&rule->src_ip[0], &rule->dst_ip[0], rule->proto);

		if (rule->src_port == PORT_ANY)
			printk("src_port[ANY]  ");
		else
			printk("src_port[%d] ", rule->src_port);

		if (rule->dst_port == PORT_ANY)
			printk("dst_port[ANY] ");
		else
			printk("dst_port[%d] ", rule->dst_port);

		printk("Dscp[0x%X]\n", rule->uciDscp);
	}
	/* Invalidate flows */
	asfctrl_qos_invalidate_flows();

	return 0;
}

#ifdef	ASF_IPV6_FP_SUPPORT
void ASFFlushIPv6Marker(void)
{
	if (NULL != marker_rule_v6) {
		vfree(marker_rule_v6);
		marker_rule_v6 = NULL;
		num_rules_v6 = 0;
	}
	/* Invalidate flows */
	asfctrl_qos_invalidate_flows();
	printk(KERN_INFO "IPv6 Marker Rules Flushed\n");
}

int ASFConfigIPv6Marker(marker_db_t *arg)
{
	int			i;

	if (!arg->num_rules || !arg->rule)
		return -EINVAL;

	if (NULL != marker_rule_v6)
		vfree(marker_rule_v6);

	ASFCTRL_INFO("Marker rules[%d] configuration request!\n",
						arg->num_rules);

	num_rules_v6 = arg->num_rules;
	/* Allocate Marker Database */
	marker_rule_v6 = vmalloc(num_rules_v6 * sizeof(markerRule_t));
	if (NULL == marker_rule_v6)
		return -ENOMEM;
	memcpy(marker_rule_v6, arg->rule,
		sizeof(markerRule_t) * num_rules_v6);

	for (i = 0; i < num_rules_v6; i++) {
		markerRule_t *rule;

		rule = (markerRule_t *) &marker_rule_v6[i];

		printk(KERN_INFO"src_ip[%-15pI6] dst_ip[%-15pI6] proto[%d] ",
			&rule->src_ip[0], &rule->dst_ip[0], rule->proto);

		if (rule->src_port == PORT_ANY)
			printk("src_port[ANY]  ");
		else
			printk("src_port[%d] ", rule->src_port);

		if (rule->dst_port == PORT_ANY)
			printk("dst_port[ANY] ");
		else
			printk("dst_port[%d] ", rule->dst_port);

		printk("Dscp[0x%X]\n", rule->uciDscp);
	}
	/* Invalidate flows */
	asfctrl_qos_invalidate_flows();

	return 0;
}
#endif
#endif /* CONFIG_MARKER */

/* Global Variables */
/*ASFQOSCap_t g_qos_cap; */

ASF_void_t asfctrl_qos_fnInterfaceNotFound(
			ASFQOSCreateQdisc_t cmd,
			genericFreeFn_t pFreeFn,
			ASF_void_t    *freeArg)
{
	ASFCTRL_FUNC_TRACE;
	return;
}

ASF_void_t asfctrl_qos_fnQdiscNotFound(
			ASFQOSCreateQdisc_t cmd,
			genericFreeFn_t pFreeFn,
			ASF_void_t    *freeArg)
{
	ASFCTRL_FUNC_TRACE;
	return;
}

ASF_void_t asfctrl_qos_fnRuntime(
				ASF_uint32_t cmd,
				ASF_void_t   *pResp,
				ASF_uint32_t ulRespLen)
{
	ASFCTRL_FUNC_TRACE;
	switch (cmd) {
	case ASF_QOS_CREATE_QDISC:
	{
		ASFCTRL_INFO("Successful Response for command %u \n", cmd);
	}
	break;

	case ASF_QOS_DELETE_QDISC:
	{
		ASFCTRL_INFO("Successful Response for command %u \n", cmd);
	}
	break;
	case ASF_QOS_FLUSH:
	{
		ASFCTRL_INFO("Successful Response for command %u \n", cmd);
	}
	break;

	default:
		ASFCTRL_INFO("response for unknown command %u \n", cmd);
	}
	return;
}

#if defined(ASF_EGRESS_SCH) || defined(ASF_HW_SCH)
int  asfctrl_qos_prio_add(
		struct net_device	*dev,
		uint32_t		handle,
		uint32_t		parent,
		uint32_t		bands
)
{
	int	err = -EINVAL;
	ASFQOSCreateQdisc_t qdisc;

	if (dev == NULL) {
		ASFCTRL_ERR("Invalid Interface pointer\n");
		return err;
	}

#ifdef CONFIG_DPA
	if (bands != DPA_MAX_PRIO_QUEUES) {
		ASFCTRL_ERR("Invalid Bands[%d]: Required %d Bands\n",
						bands, DPA_MAX_PRIO_QUEUES);
#else
	if (bands != ASF_PRIO_MAX) {
		ASFCTRL_ERR("Invalid Bands[%d]: Required %d Bands\n",
						bands, ASF_PRIO_MAX);
#endif
		return err;
	}
	/* If ASF is disabled, simply return */
	if (0 == ASFGetStatus()) {
		ASFCTRL_INFO("ASF not ready\n");
		return err;
	}
	qdisc.qdisc_type = ASF_QDISC_PRIO;
	qdisc.dev = dev;
	qdisc.handle = handle;
	qdisc.parent = parent;
	qdisc.u.prio.bands = bands;

	err = ASFQOSRuntime(0, ASF_QOS_CREATE_QDISC , &qdisc);
	if (err != ASFQOS_SUCCESS)
		ASFCTRL_INFO("Qdisc creation Failed! --\n");

	return err;
}

int asfctrl_qos_prio_flush(
		struct net_device	*dev,
		uint32_t		handle,
		uint32_t		parent
)
{
	int	err = -EINVAL;
	ASFQOSDeleteQdisc_t qdisc;

	if (dev == NULL) {
		ASFCTRL_ERR("Invalid Interface pointer\n");
		return err;
	}

	qdisc.qdisc_type = ASF_QDISC_PRIO;
	qdisc.dev = dev;
	qdisc.handle = handle;
	qdisc.parent = parent;

	err = ASFQOSRuntime(0, ASF_QOS_FLUSH, &qdisc);
	if (err != ASFQOS_SUCCESS)
		ASFCTRL_INFO("Qdisc Flush Failed! --\n");

	return err;
}

int  asfctrl_qos_drr_add(
		struct net_device	*dev,
		uint32_t		handle,
		uint32_t		parent,
		uint32_t		quantum
)
{
	int	err = -EINVAL;
	ASFQOSCreateQdisc_t qdisc;

	if (dev == NULL) {
		ASFCTRL_ERR("Invalid Interface pointer\n");
		return err;
	}

	/* If ASF is disabled, simply return */
	if (0 == ASFGetStatus()) {
		ASFCTRL_INFO("ASF not ready\n");
		return err;
	}
	qdisc.qdisc_type = ASF_QDISC_DRR;
	qdisc.dev = dev;
	qdisc.handle = handle;
	qdisc.parent = parent;
	qdisc.u.drr.quantum = quantum;

	if (!quantum)
		err = ASFQOSRuntime(0, ASF_QOS_CREATE_QDISC , &qdisc);
	else
		err = ASFQOSRuntime(0, ASF_QOS_ADD_QDISC , &qdisc);

	if (err != ASFQOS_SUCCESS)
		ASFCTRL_ERR("Qdisc creation Failed! --\n");

	return err;
}

int asfctrl_qos_drr_flush(
		struct net_device	*dev,
		uint32_t		handle,
		uint32_t		parent
)
{
	int	err = -EINVAL;
	ASFQOSDeleteQdisc_t qdisc;

	if (dev == NULL) {
		ASFCTRL_ERR("Invalid Interface pointer\n");
		return err;
	}

	qdisc.qdisc_type = ASF_QDISC_DRR;
	qdisc.dev = dev;
	qdisc.handle = handle;
	qdisc.parent = parent;

	err = ASFQOSRuntime(0, ASF_QOS_FLUSH, &qdisc);
	if (err != ASFQOS_SUCCESS)
		ASFCTRL_INFO("Qdisc Flush Failed! --\n");

	return err;
}
#endif

#if defined(ASF_EGRESS_SHAPER) || defined(ASF_HW_SHAPER)
int  asfctrl_qos_tbf_add(struct tbf_opt *opt)
{
	ASFQOSCreateQdisc_t qdisc;
	int	err = -EINVAL;

	if (opt->dev == NULL) {
		ASFCTRL_ERR("Invalid Interface pointer\n");
		return err;
	}
	if (opt->parent != ROOT_ID) {
		ASFCTRL_ERR(" Only Port Shaper is support!"
				" Handle[0x%X]\n", opt->handle);
		return err;
	}
	qdisc.qdisc_type = ASF_QDISC_TBF;
	qdisc.dev = opt->dev;
	qdisc.handle = opt->handle;
	qdisc.parent = opt->parent;
	qdisc.u.tbf.rate = opt->rate;

	err = ASFQOSRuntime(0, ASF_QOS_ADD_QDISC , &qdisc);
	if (err != ASFQOS_SUCCESS)
		ASFCTRL_INFO("Qdisc creation Failed! --\n");

	return err;
}

int asfctrl_qos_tbf_del(
		struct net_device	*dev,
		uint32_t		handle,
		uint32_t		parent
)
{
	int	err = -EINVAL;
	ASFQOSDeleteQdisc_t qdisc;

	if (dev == NULL) {
		ASFCTRL_ERR("Invalid Interface pointer\n");
		return err;
	}

	qdisc.qdisc_type = ASF_QDISC_TBF;
	qdisc.dev = dev;
	qdisc.handle = handle;
	qdisc.parent = parent;

	err = ASFQOSRuntime(0, ASF_QOS_DELETE_QDISC, &qdisc);
	if (err != ASFQOS_SUCCESS)
		ASFCTRL_INFO("Qdisc Deletion Failed! --\n");

	return err;
}
#endif

extern void asfctrl_invalidate_sessions(void);

static int __init asfctrl_linux_qos_init(void)
{

	ASFQOSCallbackFns_t asfctrl_Cbs = {
		asfctrl_qos_fnInterfaceNotFound,
		asfctrl_qos_fnQdiscNotFound,
		asfctrl_qos_fnRuntime
	};

	ASFQOSRegisterCallbackFns(&asfctrl_Cbs);

#if defined(ASF_EGRESS_SCH) || defined(ASF_HW_SCH)
	/* Register Callback function with ASF control layer to */
	prio_hook_fn_register(&asfctrl_qos_prio_add,
				&asfctrl_qos_prio_flush);
	drr_hook_fn_register(&asfctrl_qos_drr_add,
				&asfctrl_qos_drr_flush,
				&asfctrl_invalidate_sessions);
#endif

#if defined(ASF_EGRESS_SHAPER) || defined(ASF_HW_SHAPER)
	tbf_hook_fn_register(&asfctrl_qos_tbf_add,
				&asfctrl_qos_tbf_del);
#endif
#ifdef ASF_INGRESS_MARKER
	/*  Register Marker Rules */
	ASFRegisterQosMarkerFn(&ASFMatchMarkerRule, &ASFMarkLnxPkt);
	marker_v4_hook_fn_register(&ASFConfigIPv4Marker, &ASFFlushIPv4Marker);
#ifdef	ASF_IPV6_FP_SUPPORT
	marker_v6_hook_fn_register(&ASFConfigIPv6Marker, &ASFFlushIPv6Marker);
#endif
#endif
	ASFCTRL_DBG("ASF Control Module - Forward Loaded\n");
	return 0;
}

static void __exit asfctrl_linux_qos_exit(void)
{
	ASFQOSCallbackFns_t asfctrl_Cbs = {
		NULL,
		NULL,
		NULL
	};

	/* De-register Callback functins with QOS module */
	ASFQOSRegisterCallbackFns(&asfctrl_Cbs);
#if defined(ASF_EGRESS_SCH) || defined(ASF_HW_SCH)
	prio_hook_fn_register(NULL, NULL);
	drr_hook_fn_register(NULL, NULL, NULL);
#endif
#if defined(ASF_EGRESS_SHAPER) || defined(ASF_HW_SHAPER)
	tbf_hook_fn_register(NULL, NULL);
#endif
#ifdef ASF_INGRESS_MARKER
	/*  Register Marker Rules */
	ASFRegisterQosMarkerFn(NULL, NULL);
	marker_v4_hook_fn_register(NULL, NULL);
#ifdef	ASF_IPV6_FP_SUPPORT
	marker_v6_hook_fn_register(NULL, NULL);
#endif
#endif
	ASFCTRL_DBG("ASF QOS Control Module Unloaded\n");
}

module_init(asfctrl_linux_qos_init);
module_exit(asfctrl_linux_qos_exit);
