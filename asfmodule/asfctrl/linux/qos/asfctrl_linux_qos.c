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
#include <gianfar.h>
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
MODULE_DESCRIPTION(ASFCTRL_LINUX_QOS_DESC);

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

#ifdef ASF_EGRESS_SCH
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

	if (bands != ASF_PRIO_MAX) {
		ASFCTRL_ERR("Invalid Bands[%d]: Required %d Bands\n",
						bands, ASF_PRIO_MAX);
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
#endif

#ifdef ASF_EGRESS_SHAPER
int  asfctrl_qos_tbf_add(struct tbf_opt *opt)
{
	ASFQOSCreateQdisc_t qdisc;
	int	err = -EINVAL;

	if (opt->dev == NULL) {
		ASFCTRL_ERR("Invalid Interface pointer\n");
		return err;
	}

	if (opt->parent == ROOT_ID) {
		ASFCTRL_ERR(" TBF is not allowed as ROOT !,"
				" Handle[0x%X]\n", opt->handle);
		return err;
	}
	/* If ASF is disabled, simply return */
	if (0 == ASFGetStatus()) {
		ASFCTRL_INFO("ASF not ready\n");
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

static int __init asfctrl_linux_qos_init(void)
{

	ASFQOSCallbackFns_t asfctrl_Cbs = {
		asfctrl_qos_fnInterfaceNotFound,
		asfctrl_qos_fnQdiscNotFound,
		asfctrl_qos_fnRuntime
	};

	ASFQOSRegisterCallbackFns(&asfctrl_Cbs);

#ifdef ASF_EGRESS_SCH
	/* Register Callback function with ASF control layer to */
	prio_hook_fn_register(&asfctrl_qos_prio_add,
				&asfctrl_qos_prio_flush);
#endif

#ifdef ASF_EGRESS_SHAPER
	tbf_hook_fn_register(&asfctrl_qos_tbf_add,
				&asfctrl_qos_tbf_del);
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
#ifdef ASF_EGRESS_SCH
	prio_hook_fn_register(NULL, NULL);
#endif
#ifdef ASF_EGRESS_SHAPER
	tbf_hook_fn_register(NULL, NULL);

#endif
	ASFCTRL_DBG("ASF QOS Control Module Unloaded \n");
}

module_init(asfctrl_linux_qos_init);
module_exit(asfctrl_linux_qos_exit);
