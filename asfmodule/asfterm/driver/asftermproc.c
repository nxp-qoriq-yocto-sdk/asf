/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asftermproc.c
 *
 * Description: ASF Termination module Proc Interface implementation.
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
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
#include <linux/if_pmal.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/version.h>
#include <linux/proc_fs.h>
#include "asfterm_pvt.h"
/*
 * Implement following proc
 *	/proc/sys/asf/term/
 *	/proc/asf/term
 */
enum {
	ASF_TERM_AGING_ENABLE = 1,
	ASF_TERM_EXP_TIMEOUT,
	ASF_TERM_L2BLOB_REFRESH_NPKTS,
	ASF_TERM_L2BLOB_REFRESH_INTERVAL,
	ASF_TERM_MAX_ENTRY
};

static int term_debug_show_index;
static int term_debug_show_count = 50;

void print_bigbuf(char *s)
{
	/* printk appears to truncate the buffer if > 2k.
	 * so print 1 line at a time
	 */
	char *c;

	while (*s && (c = strchr(s, '\n'))) {
		*c = '\0';
		printk(KERN_INFO "%s\n", s);
		s = c+1;
	}
	printk(s);
}


static int display_asf_term_cache_stats(char *page, char **start,
				 off_t off, int count,
				 int *eof, void *data)
{
	int i, j = 1;
	term_cache_t	*head, *Cache;

	printk(KERN_INFO "Index	SRC_IP:SRCPORT	DST_IP:DSTPORT	"
			"InPkts  OutPkts  InBytes  OutBytes"
			"  l2blob  local  IPSEC\n ");
	for (i = 0; i < term_hash_buckets; i++) {
		spin_lock_bh(&term_cache_table[i].lock);
		head = (term_cache_t *) &term_cache_table[i];
		Cache = head->pNext;
		while (Cache != head) {
			printk(KERN_INFO "%2u    %d.%d.%d.%d:%d  "
				"%d.%d.%d.%d:%d  %5u %5u %10u %10u"
				"\t%d    %s    %s    %s\n",
				j++,
				NIPQUAD(Cache->ulSrcIp),
				ntohs((Cache->ulPorts&0xffff0000) >> 16),
				NIPQUAD(Cache->ulDestIp),
				ntohs(Cache->ulPorts&0xffff),
				Cache->stats.ulInPkts,
				Cache->stats.ulOutPkts,
				Cache->stats.ulInBytes,
				Cache->stats.ulOutBytes,
				Cache->l2blob_len,
				Cache->bLocalTerm ? "NON-IPSEC" : "-",
				Cache->bIPsecIn ? "IN" : "-",
				Cache->bIPsecOut ? "OUT" : "-");
			Cache = Cache->pNext;
		}
		spin_unlock_bh(&term_cache_table[i].lock);
	}
	return 0;

}


static int display_asf_proc_term_debug(char *page, char **start,
				off_t off, int count,
				int *eof, void *data)
{
	int i, total = 0;
	term_cache_t	*head, *cache;
	char	*buf, *p;
	unsigned int disp_cnt = 0, display = 0;
	unsigned long curTime = jiffies, last_in, ulIdleTime;

	buf = kmalloc(300 * (term_debug_show_count + 2), GFP_KERNEL);
	if (!buf) {
		printk(KERN_INFO "term_debug_show_count is too large :"\
			"couldn't allocate memory!\n");
		return 0;
	}

	/* display private information for each for debugging */

	printk(KERN_INFO "{ID}\t{OTH-ID}\tFLAGS\tPMTU\tBLEN\tTXVID"\
			"\tIDLE/INAC\t{BLOB}\n");
	p = buf;
	*p = '\0';
	for (i = 0; i < term_hash_buckets; i++) {
		head = (term_cache_t *)  &term_cache_table[i];
		if (i == term_debug_show_index)
			display = 1;

		spin_lock_bh(&term_cache_table[i].lock);
		for (cache = head->pNext; cache != head; cache = cache->pNext) {
			total++;
			if (cache == cache->pNext) {
				printk(KERN_INFO "possible infinite loop.."\
					"exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;

			last_in = cache->ulLastPktInAt;
			if (curTime > last_in)
				ulIdleTime = curTime - last_in;
			else
				ulIdleTime = (((2^32)-1) - (last_in) + curTime);

			ulIdleTime = ulIdleTime/HZ;


			p += sprintf(p, "{%lu, %lu}\t{%lu, %lu}\t%c%c%c%c%c%c"\
				"\t%u\t%u\t%u\t%lu/%lu\t%pM:%pM..%02x%02x\n",
				cache->id.ulArg1, cache->id.ulArg2,
				cache->other_id.ulArg1, cache->other_id.ulArg2,
				cache->bDeleted ? 'D' : '-',
				cache->l2blob_len ? 'B' : '-',
				cache->bVLAN ? 'V' : '-',
				cache->bPPPoE ? 'P' : '-',
				cache->bIPsecIn ? 'I' : '-',
				cache->bIPsecOut ? 'O' : '-',

				cache->pmtu,
				cache->l2blob_len,
				cache->tx_vlan_id,
				ulIdleTime,
				cache->ulInacTime,
				cache->l2blob,
				cache->l2blob+6,
				cache->l2blob[cache->l2blob_len-2],
				cache->l2blob[cache->l2blob_len-1]);


			disp_cnt++;
			if (disp_cnt >= term_debug_show_count)
				display = 0;
		}
		spin_unlock_bh(&term_cache_table[i].lock);
	}
	print_bigbuf(buf);
	printk(KERN_INFO "\nTotal %d\n", total);
	kfree(buf);
	return 0;
}
static int proc_asf_term_aging_enable(ctl_table *ctl, int write,
				void __user *buffer,
				size_t *lenp, loff_t *ppos)
{
	int old_state = term_aging_enable, ret;

	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);

	/* reset the value to 0 or 1 */
	if (term_aging_enable != 0)
		term_aging_enable = 1;

	if (term_aging_enable != old_state) {
		if (term_aging_enable)
			printk(KERN_INFO "ASF TERM Cache Aging is ENABLED.\n");
		else
			printk(KERN_INFO "ASF TERM Cache Aging is DISABLED.\n");
	}

	return ret;
}

static struct ctl_table asf_term_proc_table[] = {
	{
		.procname       = "aging_enable",
		.data           = &term_aging_enable,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_asf_term_aging_enable,
	},
	{
		.procname       = "l2blob_refresh_npkts",
		.data           = &term_l2blob_refresh_npkts,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "l2blob_refresh_interval",
		.data           = &term_l2blob_refresh_interval,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "max_num_entry",
		.data           = &term_max_entry,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{}
};


static struct ctl_table asf_term_proc_root_table[] = {
	{
		.procname       = "term",
		.mode           = 0555,
		.child          = asf_term_proc_table,
	},
	{}
};

static struct ctl_table_header *asf_term_proc_header;


#define ASF_TERM_CACHE_STAT_NAME "term_stats"
#define ASF_TERM_CACHE_DEBUG_NAME "term_debug"

int asf_term_register_proc(void)
{
	const struct ctl_path asf_term_path[] = {
	{ .procname = asf_proc_header->ctl_table->procname,
	},
	{} };

	/* register sysctl tree */
	asf_term_proc_header = register_sysctl_paths(asf_term_path,
						asf_term_proc_root_table);
	if (!asf_term_proc_header)
		return -ENOMEM;

	create_proc_read_entry(ASF_TERM_CACHE_STAT_NAME,
				0444, asf_dir,
				display_asf_term_cache_stats,
				NULL);

	create_proc_read_entry(ASF_TERM_CACHE_DEBUG_NAME,
				0444, asf_dir,
				display_asf_proc_term_debug,
				NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
	return 0;
}
EXPORT_SYMBOL(asf_term_register_proc);

int asf_term_unregister_proc(void)
{
	if (asf_term_proc_header)
		unregister_sysctl_table(asf_term_proc_header);

	remove_proc_entry(ASF_TERM_CACHE_STAT_NAME, asf_dir);
	remove_proc_entry(ASF_TERM_CACHE_DEBUG_NAME, asf_dir);
	return 0;
}
EXPORT_SYMBOL(asf_term_unregister_proc);

