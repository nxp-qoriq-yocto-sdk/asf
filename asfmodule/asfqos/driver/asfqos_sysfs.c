/*
 * File:	asfqos_sysfs.c
 *
 * Description: SysFS interface for configuring / View QoS the  options
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Copyright 2012 Freescale Semiconductor, Inc.
*/

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/sysctl.h>
#include <net/sock.h>
/* #include <linux/if_pmal.h>*/

#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfctrl/linux/ffp/asfctrl.h"
#include "asfqosapi.h"
#include "asfqos_pvt.h"


struct net_device *curr_if;

static ssize_t qos_enabled_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	if (asf_qos_enable)
		return sprintf(buf, "%s\n", "YES");
	else
		return sprintf(buf, "%s\n", "NO");
}


static ssize_t qos_enabled_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int val;
	sscanf(buf, "%d", &val);
	if (val < 0) {
		pr_info("[%d] is INVALID... Please enter"
					" a value > 0 !\n", val);
		return -EINVAL;
	}
	/* Reset value to 0 or 1 */
	if (val)
		val = 1;

	if (val != asf_qos_enable) {
		asf_qos_enable = val;
		if (val)
			pr_info("ASF QoS Functinality"
						" is now Enabled.\n");
		else
			pr_info("ASF QoS Functionality"
						" is Disabled.\n");
	}
	return count;
}

static ssize_t set_if_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	char str[10];

	sscanf(buf, "%s", &str[0]);

	curr_if = dev_get_by_name(&init_net, (const char *)str);
	if (curr_if == NULL) {
		pr_err("OHHH Device %s not found\n", str);
		return -EINVAL;
	}
	pr_info("\nQuery cmd will be executed for"
					" I/F [%s].\n\n", curr_if->name);
	return count;
}

static void print_stats(struct net_device *dev)
{
	struct  asf_qdisc	*root = NULL;
	int	i;
#ifdef CONFIG_DPA
	int	j;
#else
	struct  asf_prio_sched_data *priv = NULL;
#endif

	root = dev->asf_qdisc;

	if (!root) {
		pr_info(" QoS not configured on dev %s\n",
							dev->name);
		return;
	}
#ifdef CONFIG_DPA
	/* Print stats */
	pr_info("\nQoS Stats for Dev %s ::\n", dev->name);
	for (i = 0; i < DPA_MAX_PRIO_QUEUES; i++) {
		struct asf_qos_fq *asf_fq = NULL;
		int ulEnqueuePkts = 0, ulDroppedPkts = 0;

		for (j = 0; j < 8; j++) {
			asf_fq = root->asf_fq[i][j];
			if (!asf_fq)
				break;

			ulEnqueuePkts += asf_fq->ulEnqueuePkts;
			ulDroppedPkts += asf_fq->ulDroppedPkts;
		}
		pr_info("WQ [%d] :-->\n", i);
		pr_info("nEnqueuePkts = %-10u  DroppedPkts = %-10u\n\n",
			ulEnqueuePkts, ulDroppedPkts);
	}
#else
	priv = (struct  asf_prio_sched_data *) root->priv;

	/* Print stats */
	pr_info("\nQoS Stats for Dev %s ::\n", dev->name);
	for (i = 0; i < ASF_PRIO_MAX; i++) {
		pr_info("QUEUE [%d] :-->\n", i);
		pr_info("nEnqueuePkts = %-10u  DequeuePkts = %-10u "
		"DroppedPkts = %-10u TxErrorPkts = %-10u\n\n",
			priv->q[i].ulEnqueuePkts,
			priv->q[i].ulDequeuePkts,
			priv->q[i].ulDroppedPkts,
			priv->q[i].ulTxErrorPkts);
	}
#endif
}

static ssize_t qos_stats_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	if (!curr_if) {
		pr_info("Please set the Interface First\n");
		return 0;
	}
	print_stats(curr_if);
	return 0;
}

static ssize_t get_config_show(struct kobject *kobj,
				struct kobj_attribute *attr,
				char *buf)
{
	ASFQOSQueryConfig_t info;
	int i;

	if (!curr_if) {
		pr_info("Please set the Interface First\n");
		return 0;
	}

	info.dev = curr_if;
	if (ASFQOS_SUCCESS != ASFQOSQueryConfig(ASF_DEF_VSG, &info)) {
		pr_info("Get QoS Config Failed for [%s] \n",
							curr_if->name);
		return 0;
	}

	pr_info("------------------------------------\n");
#ifdef CONFIG_DPA
	if (info.sch_type == ASF_QDISC_PRIO) {
		pr_info("Scheduler type =	%s\n", "STRICT_PRIORITY");
	} else if (info.sch_type == ASF_QDISC_DRR) {
		pr_info("Scheduler type =	%s\n", "DRR");
		for (i = 0; i < ASF_PRIO_MAX; i++)
			pr_info("(Quantum[%d])  =	%d\n", i,
							info.quantum[i]);
	} else if (info.sch_type == ASF_QDISC_WRR) {
		pr_info("Scheduler type =	%s\n", "WRR");
		for (i = 0; i < DPA_MAX_WRR_QUEUES; i++)
			pr_info("(weight[%d])  =	%d\n", i,
							info.quantum[i]);
	}
	pr_info("Handle         =	0x%X\n", info.handle);
	pr_info("------------------------------------\n");
	if (info.b_port_shaper)
		pr_info("Port Shaper Rate is"
				" %d  Kbps\n", info.pShaper_rate);
	else
		pr_info("Port Shaper Not configured\n");
#else
	if (info.sch_type == ASF_QDISC_PRIO) {
		pr_info("Scheduler type =	%s\n",
							"STRICT_PRIORITY");
		pr_info("Handle         =	0x%X\n", info.handle);
		pr_info("Num Queues     =	%d\n", info.bands);
		pr_info("Queue Max Size =	%d\n",
						info.queue_max_size);
		pr_info("------------------------------------\n");
		for (i = 0; i < info.bands; i++) {
			if (info.b_queue_shaper[i])
				pr_info("Shaper Rate for Q[%d] is"
					" %d Kbps\n", i,
					info.qShaper_rate[i]/1000);
			else
				pr_info("Shaper Not configured"
							" for Q[%d]\n", i);
		}
	} else {
		pr_info("Scheduler type =	%s\n", "PRIO_DRR");
		pr_info("Handle         =	0x%X\n", info.handle);
		pr_info("Num Queues     =	%d\n", info.bands);
		pr_info("Queue Max Size =	%d\n",
						info.queue_max_size);
		for (i = 0; i < info.bands; i++)
			pr_info("Quantum(Q[%d])  =	%d\n", i,
							info.quantum[i]);

		pr_info("------------------------------------\n");
		if (info.b_port_shaper)
			pr_info("Port Shaper Rate is"
					" %d Kbps\n", info.pShaper_rate/1000);
		else
			pr_info("Port Shaper Not configured\n");
	}
#endif
	pr_info("------------------------------------\n");
	return 0;
}

static ssize_t reset_stats_write(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int val;
#ifndef CONFIG_DPA
	ASFQOSQueryStatsInfo_t info;
#else
	int	i, j;
	struct  asf_qdisc	*root = NULL;

#endif
	if (!curr_if) {
		pr_info("Please set the Interface First\n");
		return -EINVAL;
	}

	sscanf(buf, "%d", &val);
	/* Reset stats if  value is not 0*/
	if (0 == val)
		return count;
#ifdef CONFIG_DPA
	root = curr_if->asf_qdisc;
	if (!root) {
		pr_info(" QoS not configured on dev %s\n",
							curr_if->name);
		return count;
	}
	/* Reset stats */
	for (i = 0; i < DPA_MAX_PRIO_QUEUES; i++) {
		struct asf_qos_fq *asf_fq = NULL;

		for (j = 0; j < 8; j++) {
			asf_fq = root->asf_fq[i][j];
			if (!asf_fq)
				return count;

			asf_fq->ulEnqueuePkts = 0;
			asf_fq->ulDroppedPkts = 0;
		}
	}
#else
	info.dev = curr_if;
	info.b_reset = 1;
	ASFQOSQueryQueueStats(ASF_DEF_VSG, &info);
#endif
	return count;
}


static struct kobj_attribute qos_enabled_attr = \
	__ATTR(qos_enabled, 0644,
		qos_enabled_show, qos_enabled_store);

static struct kobj_attribute set_if_attr = \
	__ATTR(set_curr_if, 0644,
		NULL, set_if_store);

static struct kobj_attribute qos_stats_attr = \
	__ATTR(qos_stats, 0444,
		qos_stats_show, NULL);

static struct kobj_attribute get_config_attr = \
	__ATTR(get_config, 0444,
		get_config_show, NULL);

static struct kobj_attribute reset_stats_attr = \
	__ATTR(reset_stats, 0644,
		NULL, reset_stats_write);

static struct attribute *asfqos_attrs[] = {
	&qos_enabled_attr.attr,
	&set_if_attr.attr,
	&qos_stats_attr.attr,
	&get_config_attr.attr,
	&reset_stats_attr.attr,
	NULL
};

static struct attribute_group asfqos_attr_group = {
	.attrs = asfqos_attrs,
};

struct kobject *asfqos_kobj;
EXPORT_SYMBOL_GPL(asfqos_kobj);



int asfqos_sysfs_init(void)
{
	int error;

	asfqos_kobj = kobject_create_and_add("asfqos", NULL);
	if (!asfqos_kobj) {
		error = -ENOMEM;
		goto exit;
	}

	error = sysfs_create_group(asfqos_kobj, &asfqos_attr_group);
	if (error)
		goto attr_exit;

	return 0;

attr_exit:
	kobject_put(asfqos_kobj);
exit:
	return error;
}

int asfqos_sysfs_exit(void)
{
	if (!asfqos_kobj)
		return 0;

	sysfs_remove_group(asfqos_kobj, &asfqos_attr_group);
	kobject_put(asfqos_kobj);
	return 0;
}
