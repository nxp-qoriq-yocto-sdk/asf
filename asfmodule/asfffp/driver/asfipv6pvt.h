/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfpvt.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 * 22 Jul 2011 - Sachin Saxena - Changes to introduce ASF tool kit support.
 *
*/
/******************************************************************************/

#ifndef __ASF_IPV6_PVT_H
#define __ASF_IPV6_PVT_H

#include "asfdeps.h"
#include "asfparry.h"

+#define PRINT_IPV6(a) printk(KERN_INFO"%x:%x:%x:%x:%x:%x:%x:%x\n", a.s6_addr16[0], a.s6_addr16[1], a.s6_addr16[2], a.s6_addr16[3], a.s6_addr16[4], a.s6_addr16[5], a.s6_addr16[6], a.s6_addr16[7])
+#define PRINT_IPV6_OTH(a) a.s6_addr16[0], a.s6_addr16[1], a.s6_addr16[2], a.s6_addr16[3], a.s6_addr16[4], a.s6_addr16[5], a.s6_addr16[6], a.s6_addr16[7]

extern int ffp_ipv6_hash_buckets;
#define FFP_IPV6_HINDEX(hval) ASF_HINDEX(hval, ffp_ipv6_hash_buckets)

#define IPV6_POINTER_TABLE_MAGIC_NUM	0xFACE

extern int asf_ffp_ipv6_init(void);
extern void asf_ffp_ipv6_exit(void);

void asf_ffp_ipv6_cleanup_all_flows(void);


extern ASFFFPGlobalStats_t *asf_gstats;
extern ASFFFPCallbackFns_t      ffpCbFns;
extern ASFFFPVsgStats_t *asf_vsg_stats;

extern int asf_l2blob_refresh_npkts;
extern int asf_l2blob_refresh_interval;



extern int ffp_ipv6_max_flows;

extern ptrIArry_tbl_t ffp_ipv6_ptrary;
extern ffp_bucket_t *ffp_ipv6_flow_table;
extern unsigned long asf_ffp_ipv6_hash_init_value;

static __u32 ipv6_rule_salt __read_mostly;
static inline unsigned long ASFFFPIPv6ComputeFlowHash1(
				ASF_IPv6Addr_t *ip6SrcIp,
				ASF_IPv6Addr_t *ip6DestIp,
				unsigned long ulPorts,
				unsigned long ulVsgId,
				unsigned long ulZoneId,
				unsigned long initval)
{
	unsigned long ulSrcIp = 0;
	unsigned long ulDestIp = 0;
	unsigned int	i;


	for (i = 0; i < 4; ++i)
		ulSrcIp += ip6SrcIp->s6_addr32[i];

	for (i = 0; i < 4; ++i)
		ulDestIp += ip6DestIp->s6_addr32[i];

	ulSrcIp += ipv6_rule_salt;
	ulDestIp += JHASH_GOLDEN_RATIO;
	ulPorts += initval;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulPorts);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ulSrcIp += ulVsgId;
	ulDestIp += ulZoneId;
	ASF_BJ3_MIX(ulSrcIp, ulDestIp, ulPorts);
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	return ipv6_rule_salt + ulPorts;
}

static inline unsigned long ASFFFPIPv6ComputeFlowHashEx(
				ASFFFPFlowTuple_t *tuple,
				unsigned long ulVsgId,
				unsigned long ulZoneId,
				unsigned long initval)
{
	return ASFFFPIPv6ComputeFlowHash1((ASF_IPv6Addr_t *)(tuple->ipv6SrcIp),
					(ASF_IPv6Addr_t *)(tuple->ipv6DestIp),
		(tuple->usSrcPort << 16)|tuple->usDestPort,
		ulVsgId, ulZoneId, initval);
}

static inline ffp_bucket_t *asf_ffp_ipv6_bucket_by_hash(unsigned long ulHashVal)
{
	return &ffp_ipv6_flow_table[FFP_IPV6_HINDEX(ulHashVal)];
}

static inline ffp_flow_t *ffp_ipv6_flow_by_id(ASFFFPFlowId_t *id)
{
	return (ffp_flow_t *) (ffp_ipv6_ptrary.pBase[id->ulArg1].ulMagicNum == id->ulArg2) ? ffp_ipv6_ptrary.pBase[id->ulArg1].pData : NULL;
}

static inline ffp_flow_t *ffp_ipv6_flow_by_id_ex(unsigned int ulIndex, unsigned int ulMagicNum)
{
	return (ffp_flow_t *) (ffp_ipv6_ptrary.pBase[ulIndex].ulMagicNum == ulMagicNum) ? ffp_ipv6_ptrary.pBase[ulIndex].pData : NULL;
}

void ffp_ipv6_flow_free_rcu(struct rcu_head *rcu);

void ffp_ipv6_flow_free(ffp_flow_t *flow);
ffp_flow_t *ffp_ipv6_flow_alloc(void);
ffp_flow_t *asf_ffp_ipv6_flow_lookup_by_tuple(ASFFFPFlowTuple_t *tpl,
			unsigned long ulVsgId,
			unsigned long ulZoneId,
			unsigned long *pHashVal);
ffp_flow_t *asf_ffp_ipv6_flow_lookup_in_bkt_ex(ASFFFPFlowTuple_t *tuple,
				unsigned long ulVsgId,
				unsigned long ulZoneId,
				ffp_flow_t *pHead);

ASF_uint32_t ASFFFPIPv6ProcessAndSendPkt(
				ASF_uint32_t    ulVsgId,
				ASF_uint32_t    ulCommonInterfaceId,
				ASFBuffer_t     Buffer,
				genericFreeFn_t pFreeFn,
				ASF_void_t      *freeArg,
				ASF_void_t      *pIpsecOpaque
				/* pass this to VPN In Hook */
				);



#endif
