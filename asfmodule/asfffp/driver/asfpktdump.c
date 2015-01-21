/**************************************************************************
 * Copyright 2014, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asf_pktdump.c
 *
 * Authors:	Sahil Malhotra <B42224@freescale.com>
 *
 */
/******************************************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/sctp.h>
#include <linux/icmp.h>
#include <net/xfrm.h>
#include "asf.h"
#include "asfcmn.h"
#include "asffwd.h"
#include "asfipsec.h"
#include "asftmr.h"
#include "asfpvt.h"
#include "asftcp.h"
#include "asfipv6pvt.h"

#define	ASF_DUMP_STR_LEN	1024

void asf_pktdump(unsigned char *buf)
{
	char *data = buf;
	char pbuf[ASF_DUMP_STR_LEN];
	char *p = pbuf;
	struct iphdr *iph = (struct iphdr *)buf;
	int proto = 0;

	if (iph->version == 4) {
		p += sprintf(p, "\nV4 %d.%d.%d.%d-%d.%d.%d.%d"
			"(Len=%d proto=%d frag_off=%x)",
			NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
			ASF_NTOHS(iph->tot_len), iph->protocol,
			ASF_NTOHS(iph->frag_off) & 0x7);
		proto = iph->protocol;
		if (iph->ihl != 5) {
			p += sprintf(p, "Packet dump of packets"
				"containing options is not supported");
			goto no_proto;
		}
		data += sizeof(struct iphdr);
		if (proto == IPPROTO_IPV6) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)data;
			p += sprintf(p, " V6-in-v4 %x:%x:%x:%x:%x:%x:%x:%x-"
				"%x:%x:%x:%x:%x:%x:%x:%x (Len=%d nexthdr=%d)",
				PRINT_IPV6_OTH(ip6h->saddr),
				PRINT_IPV6_OTH(ip6h->daddr),
				(int)(ASF_NTOHS(ip6h->payload_len) +
				sizeof(struct ipv6hdr)),
				ip6h->nexthdr);
			data += sizeof(struct ipv6hdr);
		}
		if (iph->frag_off & ASF_MF_OFFSET_FLAG_NET_ORDER) {
			p += sprintf(p, "Packet dump of Fragmented Packet"
				"is not supported");
			goto no_proto;
		}
	} else if (iph->version == 6) {
		struct ipv6hdr *ip6h = (struct ipv6hdr *)data;
		p += sprintf(p, " V6 %x:%x:%x:%x:%x:%x:%x:%x-"
			"%x:%x:%x:%x:%x:%x:%x:%x (Len=%d nexthdr=%d)",
			PRINT_IPV6_OTH(ip6h->saddr),
			PRINT_IPV6_OTH(ip6h->daddr),
			(int)(ASF_NTOHS(ip6h->payload_len) +
			sizeof(struct ipv6hdr)),
			ip6h->nexthdr);
		proto = ip6h->nexthdr;
		data += sizeof(struct ipv6hdr);
		if (proto == NEXTHDR_IPV6) {
			struct ipv6hdr *ip6h = (struct ipv6hdr *)data;
			p += sprintf(p, " V6-in-V6 %x:%x:%x:%x:%x:%x:%x:%x-"
				"%x:%x:%x:%x:%x:%x:%x:%x (Len=%d nexthdr=%d)",
				PRINT_IPV6_OTH(ip6h->saddr),
				PRINT_IPV6_OTH(ip6h->daddr),
				(int)(ASF_NTOHS(ip6h->payload_len) +
				sizeof(struct ipv6hdr)),
				ip6h->nexthdr);
			data += sizeof(struct ipv6hdr);
		} else if (proto == IPPROTO_IPIP) {
			struct iphdr *iph = (struct iphdr *)data;
			p += sprintf(p, " V4-in-V6 %d.%d.%d.%d-%d.%d.%d.%d"
				"(Len=%d proto=%d frag_off=%x)",
				NIPQUAD(iph->saddr), NIPQUAD(iph->daddr),
				ASF_NTOHS(iph->tot_len), iph->protocol,
				ASF_NTOHS(iph->frag_off) & 0x7);
			data += sizeof(struct iphdr);
		}
	} else {
		p += sprintf(p, " NON IP pkt");
		return;
	}
	switch (proto) {
	case IPPROTO_TCP:
		{
		struct tcphdr *tcph = (struct tcphdr *)data;
		p += sprintf(p, " TCP %d:%d", tcph->source, tcph->dest);
		p += sprintf(p, " syn=%d, fin =%d, ack =%d, ackseq=%d",
			tcph->syn, tcph->fin, tcph->ack, tcph->ack_seq);
		}
		break;
	case IPPROTO_UDP:
		{
		struct udphdr *udph = (struct udphdr *)data;
		p += sprintf(p, " UDP %d:%d", udph->source, udph->dest);
		}
		break;
	case IPPROTO_ESP:
		{
		struct ip_esp_hdr *eh = (struct ip_esp_hdr *)data;
		p += sprintf(p, " ESP spi-0x%x seq=%d", eh->spi, eh->seq_no);
		}
		break;
	case IPPROTO_AH:
		{
		struct ip_auth_hdr *ahh = (struct ip_auth_hdr *)data;
		p += sprintf(p, " AH spi-0x%x seq-%d", ahh->spi, ahh->seq_no);
		}
		break;
	case IPPROTO_SCTP:
		{
		struct sctphdr *sctph = (struct sctphdr *)data;
		p += sprintf(p, " SCTP %d:%d", sctph->source, sctph->dest);
		}
		break;
	case IPPROTO_ICMP:
		{
		struct icmphdr *icmph = (struct icmphdr *)data;
		p += sprintf(p, " ICMP type=%d", icmph->type);
		}
		break;
	case NEXTHDR_ICMP:
		{
		struct icmp6hdr *icmph = (struct icmp6hdr *)data;
		p += sprintf(p, " ICMP type=%d code=%x", icmph->icmp6_type,
			icmph->icmp6_code);
		}
		break;
	case NEXTHDR_HOP:
	case NEXTHDR_ROUTING:
	case NEXTHDR_FRAGMENT:
	case NEXTHDR_NONE:
	case NEXTHDR_DEST:
		p += sprintf(p, "EXTN HDR=%x", proto);
		break;
	}
no_proto:
	pr_info("%s", pbuf);

	return;
}
EXPORT_SYMBOL(asf_pktdump);

