/**************************************************************************
 * Copyright 2011-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asftoolkit.c
 *
 * Description: Main module for User Space ASF Application Tools Kit Handling.
 *
 * Authors:	Sachin saxena <sachin.saxena@freescale.com>
 *
 */
/*
 * History
 *
 */
/******************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <linux/io.h>
#include <asm/irq.h>
#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/sysctl.h>
#ifdef CONFIG_DPA
#include <dpaa_eth_asf.h>
#else
#include <gianfar.h>
#include <asf_gianfar.h>
#endif
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include "gplcode.h"
#include "asftoolkit.h"
#include "asfcmn.h"
#include "asftmr.h"
#include "asfreasm.h"
#include "asfpvt.h"
#include "asftcp.h"

#define MAX_ETH_IF 4

#ifndef CONFIG_DPA
static int config_lan_afx(unsigned long);
static int config_lan_filer(unsigned long);
static int read_lan_filer(unsigned long);
#endif

static int asf_interface_open(struct inode *inode, struct file *filp);
static int asf_interface_release(struct inode *inode, struct file *filp);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
static int asf_interface_ioctl(struct inode *inode,
			       struct file *filp,
#else
static long asf_interface_ioctl(struct file *filp,
#endif
			       unsigned int cmd,
			       unsigned long arg);
/*!
  \brief Interfaces provided by this driver
*/
const struct file_operations asf_interface_fops = {
	.open =		asf_interface_open,
	.release =	asf_interface_release,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	.ioctl =		asf_interface_ioctl,
#else
	.unlocked_ioctl = asf_interface_ioctl,
#endif
};

spinlock_t		asf_app_lock;
static int 		asf_open_count;	/* concurrent use (open) count */
const char *asf_ioctl_str[] = {
  "HLD_ERROR_STR",
  "HLD_CONFIG_LAN_PAUSE",
  "HLD_CONFIG_LAN_VLAN",
  "HLD_CONFIG_LAN_FILER",
  "HLD_CONFIG_LAN_AFX",
  "HLD_CONFIG_LAN_PARSE_DEPTH",
  "HLD_CONFIG_LAN_PADCRC",
  "HLD_CONTROL_ENABLE",
  "HLD_CONTROL_DISABLE",
  "HLD_TEST_0",
  "HLD_TEST_1",
  "HLD_TEST_2",
  "HLD_TEST_3",
  "HLD_TEST_4",
  "HLD_TEST_5",
  "HLD_TEST_6",
  "HLD_TEST_7",
  "HLD_TEST_8",
  "HLD_TEST_9",
  "HLD_PRINT_FILER"
};

filer_afx_t afx_g[MAX_ETH_IF][AFX_NUM_FIELDS];  /* AFX Setting storage */

static int asf_interface_open(struct inode *inode, struct file *filp)
{
	int minor = MINOR(inode->i_rdev);

	/*  Allow only one process to open
	    and use the single device at a time. */
	if (minor != 0)
		return -ENODEV; /*it must be minor number 0 */

	spin_lock_bh(&asf_app_lock);
	if (asf_open_count) {
		spin_unlock_bh(&asf_app_lock);
		return -EUSERS;
	}
	asf_open_count++;
	spin_unlock_bh(&asf_app_lock);

	asf_debug("ASF HLD Interface driver opened\n");
	return 0;
}

static int asf_interface_release(struct inode *inode, struct file *filp)
{
	asf_debug("ASF HLD Interface driver released\n");

	spin_lock_bh(&asf_app_lock);
	asf_open_count--;
	spin_unlock_bh(&asf_app_lock);

	return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
static int asf_interface_ioctl(struct inode *inode,
				struct file *filp,
#else
static long asf_interface_ioctl(struct file *filp,
#endif
				unsigned int cmd,
				unsigned long arg)
{
	int ret = 0;

	asf_debug("ioctl cmd (%u): %s arg %lu\n", cmd, asf_ioctl_str[cmd], arg);

	if ((cmd >= HLD_TEST_0) && (cmd <= HLD_TEST_1))
		asf_debug("Runnng ASF Test CMD #%d\n", (cmd - HLD_TEST_0));

	switch (cmd) {
#ifndef CONFIG_DPA
	case HLD_CONFIG_LAN_FILER:
		ret =  config_lan_filer(arg);
		break;

	case HLD_PRINT_FILER:
		ret =  read_lan_filer(arg);
		break;

	case HLD_CONFIG_LAN_AFX:
		ret =  config_lan_afx(arg);
		break;
#endif

	case HLD_CONFIG_LAN_PARSE_DEPTH:
	case HLD_CONFIG_LAN_VLAN:
	case HLD_CONFIG_LAN_PAUSE:
	case HLD_CONFIG_LAN_PADCRC:
	case HLD_CONTROL_ENABLE:
	case HLD_CONTROL_DISABLE:
	case HLD_ERROR_STR:
	case HLD_TEST_0:
	case HLD_TEST_1:
		printk(KERN_INFO "Not supported Yet.!\n");
		break;
	default:
		printk(KERN_INFO "Invalid ASF IOCTL cmd\n");
		ret = -EBADRQC;
		break;
	}

	return ret;
}

#ifndef CONFIG_DPA
static int config_lan_afx(unsigned long arg)
{
	ioctl_config_lan_afx_t		config;
	filer_afx_t			*afx;
	struct net_device		*dev = NULL;
	u8				buf[6], byte;
	u32				reg = 0;
	int				field;

	if (copy_from_user(&config, (ioctl_config_lan_afx_t *)arg,
					sizeof(ioctl_config_lan_afx_t)))
		return -EFAULT;

	afx = (filer_afx_t *)vmalloc(sizeof(filer_afx_t));
	if (NULL == afx)
		return -ENOMEM;

	if (copy_from_user(afx, config.lan_afx, sizeof(filer_afx_t))) {
		vfree(afx);
		return -EFAULT;
	}

	config.lan = (config.lan % MAX_ETH_IF);
	sprintf(buf, "eth%d", config.lan);
	dev = dev_get_by_name(&init_net, buf);
	if (NULL == dev) {
		vfree(afx);
		return -EFAULT;
	}

	/* Store current AFX byte settings */
	afx_g[config.lan][config.field] = *afx;

	for (field = 0; field < AFX_NUM_FIELDS; field++) {
		/* build up byte for each field.
		   MS 2 bits = control. LS 6 bits = offset */
		byte = (((afx_g[config.lan][field].control & 0x3) << 6) |
			(afx_g[config.lan][field].offset & 0x3F));

		/* Shift byte over 3 - field bytes before OR'ing */
		reg |= byte << (8 * (3 - field));
	}

	printk(KERN_INFO "Writing to %s: RBIFX = 0x%X\n", dev->name, reg);
	gfar_config_afx(dev, reg);

	vfree(afx);
	return 0;
}
#endif

static int config_lan_filer(unsigned long arg)
{
	ioctl_config_lan_filer_t	lan_filer;
	lan_ftr_t			*filer_rule, *rule;
	int				i;
	u32				rqfcr, rqfar, rqfpr;
	struct net_device		*dev = NULL;
	u8				buf[6];

	if (copy_from_user(&lan_filer, (ioctl_config_lan_filer_t *)arg,
					sizeof(ioctl_config_lan_filer_t)))
		return -EFAULT;

	if (!lan_filer.num_rules || !lan_filer.filer_rule)
		return -EINVAL;

	filer_rule = (lan_ftr_t *)vmalloc(lan_filer.num_rules *
						sizeof(lan_ftr_t));
	if (NULL == filer_rule)
		return -ENOMEM;

	if (copy_from_user(filer_rule, lan_filer.filer_rule,
				sizeof(lan_ftr_t) * lan_filer.num_rules)) {
		vfree(filer_rule);
		return -EFAULT;
	}

	sprintf(buf, "eth%d", lan_filer.lan % MAX_ETH_IF);
	dev = dev_get_by_name(&init_net, buf);
	if (NULL == dev) {
		vfree(filer_rule);
		return -EFAULT;
	}

	asf_debug("LAN [%d]:[%s], Filer rules[%d] configuration request!\n",
			lan_filer.lan, dev->name, lan_filer.num_rules);

	for (i = 0; i < lan_filer.num_rules; i++) {
		rule = (lan_ftr_t *) &filer_rule[i];
		asf_debug("Index[%d], queue[%d], cluster[%d], rej[%d],"\
			"and[%d], cmp[%d], pid[0x%X], prop_val[0x%X]\n",
			rule->index, rule->queue, rule->cluster, rule->reject,
			rule->and_next, rule->cmp, rule->pid,
			rule->prop_val);

		rqfar = rule->index;
		rqfpr = rule->prop_val;

/* Receive queue index */
#define RQFCR_Q		0x0000FC00
/* Property identifier */
#define RQFCR_PID	0x0000000F
		/* RQFCR - First 32-bits of rule */
		rqfcr = ((rule->queue << 10) & RQFCR_Q);
		if (rule->cluster)
			rqfcr |= RQFCR_CLE;
		if (rule->reject)
			rqfcr |= RQFCR_RJE;
		if (rule->and_next)
			rqfcr |= RQFCR_AND;
		rqfcr |= ((rule->cmp << 5) & RQFCR_CMP_NOMATCH);
		rqfcr |= (rule->pid & RQFCR_PID);
		asf_debug("RQFCR [0x%X]\n", rqfcr);

		gfar_config_filer(dev, rqfar, rqfcr, rqfpr);
	}

	vfree(filer_rule);

	return 0;
}

static int read_lan_filer(unsigned long arg)
{
	int				i;
	u32				rqfcr, rqfpr;
	struct net_device		*dev = NULL;
	u8				buf[6];

	sprintf(buf, "eth%d", (*(unsigned int *) arg % MAX_ETH_IF));
	dev = dev_get_by_name(&init_net, buf);
	if (NULL == dev)
		return -EFAULT;

	printk(KERN_INFO "\n###### Filer rules for [%s] ############!\n\n",
								dev->name);

	for (i = 0; i <= MAX_FILER_IDX; i++) {
		gfar_get_filer(dev, i , &rqfcr, &rqfpr);
		printk(KERN_INFO "Rule %d: queue[%d] "\
			"cluster[%d] rej[%d] and[%d] "\
			"cmp[%d] pid[0x%X] prop_val[0x%X]\n", i,
			((rqfcr & RQFCR_Q) >> 10), (rqfcr & RQFCR_CLE) ? 1 : 0,
			(rqfcr & RQFCR_RJE) ? 1 : 0,
			(rqfcr & RQFCR_AND) ? 1 : 0,
			((rqfcr & RQFCR_CMP_NOMATCH) >> 5), (rqfcr & RQFCR_PID),
			rqfpr);
	}
	return 0;
}
