/**************************************************************************
 * Copyright 2013, Freescale Semiconductor, Inc. All rights reserved.
 *************************************************************************/
/*
 * File:	asfdebugcore.c
 *
 * Description: Module for debugging the performance of ASF.
 *
 * Authors:	Sunil Kumar Kori <B42948@freescale.com>
 *
 */
/*
 * History
 */
/**************************************************************************/
#include <linux/version.h>
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
#include <linux/if_bridge.h>
#include <linux/if_arp.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/crc32.h>
#ifdef CONFIG_FSL_DPAA_ETH
#include <dpa/dpaa_eth.h>
#include <dpa/dpaa_eth_common.h>
#include <linux/fsl_bman.h>
#include <linux/fsl_qman.h>
#else
#include <gianfar.h>
#endif
#include "asfdebug.h"


MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION("Debug Module For Application Specific FastPath");
MODULE_LICENSE("Dual BSD/GPL");


int asf_debug_devfp_rx(void *ptr, struct net_device *real_dev,
							unsigned int  fqid)
{
	struct qm_fd		*tx_fd  = (struct qm_fd *)ptr;
	struct iphdr		*iph;
	ASFDebugBuffer_t	abuf;
	uint32_t		retryCount = 0, err = 0;
	dma_addr_t		addr;
	struct dpa_priv_s	*priv;
	struct dpa_bp		*dpa_bp;
	t_FmPrsResult		*pParse;

	/*Initialise the required fields*/
	/* gather all pointers used often */
	abuf.pAnnot	= phys_to_virt(qm_fd_addr(tx_fd));
	pParse		= &abuf.pAnnot->parse_result;
	abuf.ethh	= (struct ethhdr *)((void *)abuf.pAnnot + tx_fd->offset);
	abuf.iph	= (struct iphdr *)((void *)abuf.ethh + pParse->ip_off[0]);
	iph		= abuf.iph;
	abuf.ndev	= real_dev;
	/* overwrite physical addr with virt addr */
	abuf.pAnnot->fd = tx_fd;
	abuf.nativeBuffer = NULL;
	abuf.frag_list = 0;
	abuf.bbuffInDomain = 0;

	/*Transmit the packet as it is*/
	priv = netdev_priv(real_dev);
	dpa_bp = priv->dpa_bp;
	addr = dma_map_single(dpa_bp->dev, abuf.pAnnot,
				dpa_bp->size, DMA_TO_DEVICE);
	if (unlikely(addr == 0)) {
		printk("xmit dma_map Error\n");
		goto drop_pkt;
	}
	*(u32 *)tx_fd = 0; /* Resetting the unused area */
	tx_fd->bpid = dpa_bp->bpid;
	tx_fd->addr_hi = upper_32_bits(addr);
	tx_fd->addr_lo = lower_32_bits(addr);
	/* Only Contiguous Frame Handling for now */
	tx_fd->format = qm_fd_contig;
	/* if L2 header on egress is make sure that enough
	   headroom exists.
	 */
	tx_fd->offset = (uintptr_t)iph - (uintptr_t)abuf.pAnnot - ASF_ETH_HDR_DEF_SIZE;
	/* Indicate to Recycle Buffer */
	tx_fd->cmd = FM_FD_CMD_FCO;

	do {
		err = qman_enqueue(priv->egress_fqs[smp_processor_id()],
								tx_fd, 0);
		if (err == 0)
			break;
		if (++retryCount == ASF_MAX_TX_TRY_COUNT) {
			printk("qman_enque Error\n");
			goto drop_pkt;
		}
		__delay(50);
	} while (1);

	return err;

drop_pkt:
	printk("Packet is dropped\n");
	return AS_FP_STOLEN;

}

static int __init asf_debug_init(void)
{
	uint32_t err = 0;

	/*Registering a RX/TX Hooks to DPAA Eth Driver*/
	devfp_debug_register_hook(asf_debug_devfp_rx, NULL);
	return err;
}

static void __exit asf_debug_exit(void)
{
	/*Un-Registering a RX/TX Hooks to DPAA Eth Driver*/
	devfp_debug_register_hook(NULL, NULL);
	return;
}
module_init(asf_debug_init);
module_exit(asf_debug_exit);
