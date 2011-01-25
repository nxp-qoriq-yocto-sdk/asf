/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwdproc.c
 *
 * Description: ASF Forwarding module Proc Interface implementation.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include "asffwd_pvt.h"
/*
 * Implement following proc
 *	/proc/sys/asf/fwd/
 *	/proc/asf/fwd
 */
enum {
	ASF_FWD_AGING_ENABLE = 1,
	ASF_FWD_EXP_TIMEOUT,
	ASF_FWD_L2BLOB_REFRESH_NPKTS,
	ASF_FWD_L2BLOB_REFRESH_INTERVAL,
	ASF_FWD_MAX_ENTRY
};


static int proc_asf_cache_stats(char *page, char **start,
				 off_t off, int count,
				 int *eof, void *data)
{
	int i, j = 1;
	fwd_cache_t	*head, *Cache;

	printk(KERN_INFO "Index	SRC_IP		DST_IP	   TOS  VSG   "
			"  InPkts    OutPkts    InBytes    OutBytes\n");
	for (i = 0; i < fwd_hash_buckets; i++) {
		spin_lock_bh(&fwd_cache_table[i].lock);
		head = (fwd_cache_t *) &fwd_cache_table[i];
		Cache = head->pNext;
		while (Cache != head) {
			printk(KERN_INFO "%2u    %d.%d.%d.%d     "
				"%d.%d.%d.%d  %2u %4u	%5u %10u %10u %12u\n",
						j++,
						NIPQUAD(Cache->ulSrcIp),
						NIPQUAD(Cache->ulDestIp),
						Cache->ucDscp,
						Cache->ulVsgId,
						Cache->stats.ulInPkts,
						Cache->stats.ulOutPkts,
						Cache->stats.ulInBytes,
						Cache->stats.ulOutBytes);
			Cache = Cache->pNext;
		}
		spin_unlock_bh(&fwd_cache_table[i].lock);
	}
	return 0;

}

static int proc_asf_fwd_aging_enable(ctl_table *ctl, int write,
				void __user *buffer,
				size_t *lenp, loff_t *ppos)
{
	int old_state = fwd_aging_enable, ret;

	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	/* reset the value to 0 or 1 */
	if (fwd_aging_enable != 0)
		fwd_aging_enable = 1;

	if (fwd_aging_enable != old_state) {
		if (fwd_aging_enable)
			printk(KERN_INFO "ASF FWD Cache Aging is ENABLED.\n");
		else
			printk(KERN_INFO "ASF FWD Cache Aging is DISABLED.\n");
	}

	return ret;
}

static struct ctl_table asf_fwd_proc_table[] = {
	{
		.ctl_name       = ASF_FWD_AGING_ENABLE,
		.procname       = "aging_enable",
		.data           = &fwd_aging_enable,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_asf_fwd_aging_enable,
		.strategy       = sysctl_intvec,
	},
	{
		.ctl_name       = ASF_FWD_EXP_TIMEOUT,
		.procname       = "cache_expiry_interval",
		.data           = &fwd_expiry_timeout,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	},
	{
		.ctl_name       = ASF_FWD_L2BLOB_REFRESH_NPKTS,
		.procname       = "l2blob_refresh_npkts",
		.data           = &fwd_l2blob_refresh_npkts,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	},
	{
		.ctl_name       = ASF_FWD_L2BLOB_REFRESH_INTERVAL,
		.procname       = "l2blob_refresh_interval",
		.data           = &fwd_l2blob_refresh_interval,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	},
	{
		.ctl_name       = ASF_FWD_MAX_ENTRY,
		.procname       = "max_num_entry",
		.data           = &fwd_max_entry,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	},
	{}
};


static struct ctl_table asf_fwd_proc_root_table[] = {
	{
		.ctl_name       = ASF_FWD,
		.procname       = "fwd",
		.mode           = 0555,
		.child          = asf_fwd_proc_table,
	},
	{}
};

static struct ctl_table_header *asf_fwd_proc_header;


#define ASF_FWD_CACHE_STAT_NAME "cache_stats"

int asf_fwd_register_proc(void)
{
	const struct ctl_path asf_fwd_path[] = {
	{ .procname = asf_proc_header->ctl_table->procname,
	.ctl_name = asf_proc_header->ctl_table->ctl_name, },
	{} };

	/* register sysctl tree */
	asf_fwd_proc_header = register_sysctl_paths(asf_fwd_path,
						asf_fwd_proc_root_table);
	if (!asf_fwd_proc_header)
		return -ENOMEM;

	create_proc_read_entry(ASF_FWD_CACHE_STAT_NAME,
				0444, asf_dir,
				proc_asf_cache_stats,
				NULL);
	return 0;
}
EXPORT_SYMBOL(asf_fwd_register_proc);

int asf_fwd_unregister_proc(void)
{
	if (asf_fwd_proc_header)
		unregister_sysctl_table(asf_fwd_proc_header);

	remove_proc_entry(ASF_FWD_CACHE_STAT_NAME, asf_dir);
	return 0;
}
EXPORT_SYMBOL(asf_fwd_unregister_proc);

