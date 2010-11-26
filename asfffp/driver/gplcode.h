/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	gplcode.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
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
/*
 * History
 *
 */
/******************************************************************************/


#ifndef __ASF_GPL_CODE_H
#define __ASF_GPL_CODE_H

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 32)
#define asfAllocPerCpu(size)	__alloc_percpu(size, 4)
#define asfFreePerCpu(ptr)	free_percpu(ptr)
#define asfPerCpuPtr(ptr, cpu)	per_cpu_ptr(ptr, cpu)

#define asfDevHardXmit(dev, skb)	(dev->netdev_ops->ndo_start_xmit(skb, dev))

#else

#define asfAllocPerCpu(size)	percpu_alloc(size, GFP_KERNEL)
#define asfFreePerCpu(ptr)	percpu_free(ptr)
#define asfPerCpuPtr(ptr, cpu)	percpu_ptr(ptr, cpu)
#define asfDevHardXmit(dev, skb)	(dev->hard_start_xmit(skb, dev))
#endif



void asf_ip_options_fragment(struct sk_buff  *skb);
int asf_ip_options_compile(struct net *net, struct ip_options  *opt, struct sk_buff  *skb, struct iphdr *ipheader);

#endif

