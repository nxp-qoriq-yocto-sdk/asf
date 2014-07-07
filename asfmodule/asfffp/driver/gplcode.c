/**************************************************************************
 * Copyright 2009,2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/******************************************************************************
 * File Name: gplcode.c
 * Description : contains the reassembly/fragmentation routines for ASF
 * Version  : 0.1
 * Author : Subha
 * Modifier: Sachin Saxena -B32168
 * Date : October 2009
 ******************************************************************************/
/*******************Include files *********************************************/
#include <linux/version.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/route.h>
#include <net/icmp.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#include <linux/icmp.h>
#include "gplcode.h"

/** copy of GPL code */
void asf_ip_options_fragment(struct sk_buff *skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options *opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	if (l > 40) {
		pr_info("INVALID OPT-LEN (%d).. SKB->CB CORRUPTED!!!"
				" MIGHT OVERWRITE MEMORY ... RETURN\n", l);
		return;
	}

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l)
			return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
	return;
}
#if 0
int asf_ip_options_compile(struct net *net,
			struct ip_options *opt,
			struct sk_buff *skb,
			struct iphdr *ipheader)
{
	int l;
	unsigned char *iph;
	unsigned char *optptr;
	int optlen;
	unsigned char *pp_ptr = NULL;
	struct rtable *rt = NULL;

	if (skb != NULL)
		rt = skb_rtable(skb);
	iph = (unsigned char *)ipheader;
	optptr = (unsigned char *) &ipheader[1];

	for (l = opt->optlen; l > 0; ) {
		switch (*optptr) {
		case IPOPT_END:
			for (optptr++, l--; l > 0; optptr++, l--) {
				if (*optptr != IPOPT_END) {
					*optptr = IPOPT_END;
					opt->is_changed = 1;
				}
			}
			goto eol;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l) {
			pp_ptr = optptr;
			goto error;
		}
		switch (*optptr) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/* NB: cf RFC-1812 5.2.4.1 */
			if (opt->srr) {
				pp_ptr = optptr;
				goto error;
			}
			if (!skb) {
				if (optptr[2] != 4 || optlen < 7
					|| ((optlen-3) & 3)) {
					pp_ptr = optptr + 1;
					goto error;
				}
				memcpy(&opt->faddr, &optptr[3], 4);
				if (optlen > 7)
					memmove(&optptr[3], &optptr[7],
								optlen-7);
			}
			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
			opt->srr = optptr - iph;
			break;
		case IPOPT_RR:
			if (opt->rr) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				if (skb) {
					if (rt) {
						memcpy(&optptr[optptr[2] - 1],
							&rt->rt_spec_dst, 4);
						opt->is_changed = 1;
					}
				}
				optptr[2] += 4;
				opt->rr_needaddr = 1;
			}
			opt->rr = optptr - iph;
			break;
		case IPOPT_TIMESTAMP:
			if (opt->ts) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				__be32 *timeptr = NULL;
				if (optptr[2]+3 > optptr[1]) {
					pp_ptr = optptr + 2;
					goto error;
				}
				switch (optptr[3]&0xF) {
				case IPOPT_TS_TSONLY:
					opt->ts = optptr - iph;
					if (skb)
						timeptr = (__be32 *)
							&optptr[optptr[2]-1];
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				case IPOPT_TS_TSANDADDR:
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					if (skb) {
						if (rt) {
							memcpy(
							&optptr[optptr[2]-1],
							&rt->rt_spec_dst,
							4);
							timeptr = (__be32 *)
							&optptr[optptr[2]+3];
						}
					}
					opt->ts_needaddr = 1;
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				case IPOPT_TS_PRESPEC:
					if (optptr[2]+7 > optptr[1]) {
						pp_ptr = optptr + 2;
						goto error;
					}
					opt->ts = optptr - iph;
					{
						__be32 addr;
						memcpy(&addr,
							&optptr[optptr[2]-1],
							4);
						if (inet_addr_type(net, addr)
								== RTN_UNICAST)
							break;
						if (skb)
							timeptr = (__be32 *)
							&optptr[optptr[2]+3];
					}
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				default:
					if (!skb && !capable(CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				if (timeptr) {
					struct timespec tv;
					__be32  midtime;
					getnstimeofday(&tv);
					midtime = htonl((tv.tv_sec % 86400) *
						MSEC_PER_SEC + tv.tv_nsec /
						NSEC_PER_MSEC);
						memcpy(timeptr, &midtime,
							sizeof(__be32));
						opt->is_changed = 1;
				}
			} else {
				unsigned overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				opt->ts = optptr - iph;
				if (skb) {
					optptr[3] = (optptr[3]&0xF) |
						((overflow+1) << 4);
					opt->is_changed = 1;
				}
			}
			break;
		case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] == 0 && optptr[3] == 0)
				opt->router_alert = optptr - iph;
			break;
		case IPOPT_CIPSO:
			if ((!skb && !capable(CAP_NET_RAW)) || opt->cipso) {
				pp_ptr = optptr;
				goto error;
			}
			opt->cipso = optptr - iph;
			if (-ENOSYS /*cipso_v4_validate(skb,&optptr)*/) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		case IPOPT_SEC:
		case IPOPT_SID:
		default:
			if (!skb && !capable(CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

error:
	if (skb) {
		icmp_send(skb, ICMP_PARAMETERPROB, 0,
				htonl((pp_ptr-iph) << 24));
	}
	return -EINVAL;
}
#endif
