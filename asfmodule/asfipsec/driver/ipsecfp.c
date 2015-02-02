/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecfp.c
 * Description: Contains the routines for ipsec fast path at the
 * device driver level
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 * Updated By:	Hemant Agrawal <hemant@freescale.com>
 *		Sandeep Malik <b02416@freescale.com>
 *		Nikhil Agrawal <b38457@freescale.com>
 */
/* History
 * Version	Date		Author		Change Description
 *
*/
/****************************************************************************/
#include <linux/version.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <linux/ip.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/dst.h>
#include <net/route.h>
#include <linux/inetdevice.h>
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfterm.h"
#include "../../asfffp/driver/asfipsec.h"
#include "../../asfffp/driver/asfreasm.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include "ipseccmn.h"


/* Data Structure initialization */
/* Inbound SA SPI Table */
char aNonIkeMarker_g[ASF_IPSEC_MAX_NON_IKE_MARKER_LEN];
char aNonESPMarker_g[ASF_IPSEC_MAX_NON_ESP_MARKER_LEN];

/* pad_words to be used for creating padding */
unsigned int pad_words[] = {
	0x01020304,
	0x05060708,
	0x090a0b0c,
	0x0d0e0f10
};

extern unsigned int asf_l2blob_grace_timeout;
#ifdef ASF_TERM_FP_SUPPORT
extern ASFTERMProcessPkt_f	pTermProcessPkt;
#endif

AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats_g;
AsfIPSec4GlobalPPStats_t IPSec4GblPPStats_g;

struct device *pdev;
#ifdef CONFIG_ASF_SEC3x
struct secfp_iv_info_s {
	dma_addr_t paddr;
	unsigned long *vaddr;
	unsigned long ul_iv_index;
	bool b_update_pending;
	unsigned int ul_num_avail;
	unsigned int ul_update_index;
};

/* Data structure to hold IV data */
struct secfp_iv_info_s *secfp_IVData;

extern u8 dual_intr;
#endif
unsigned int *pulVSGMagicNumber;
unsigned int *pulVSGL2blobMagicNumber;
unsigned int ulTimeStamp_g;

static int secfp_CheckInPkt(unsigned int ulVSGId,
		struct sk_buff *skb1, ASF_uint32_t ulCommonInterfaceId,
		ASFFFPIpsecInfo_t *pSecInfo, void *pIpsecOpq);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
static int ASFIPSec4SendIcmpErrMsg(unsigned char *pOrgData,
				unsigned char ucType,
				unsigned char ucCode,
				unsigned int ulUnused,
				unsigned int ulSNetId);
#endif
unsigned short ASFIPCkSum(char *data, unsigned short cnt);
unsigned short ASFascksum(unsigned short *pusData, unsigned short usLen);
unsigned short ASFIpEac(unsigned int sum); /* Carries in high order 16 bits */

int secfp_try_fastPathOut(unsigned int ulVSGId, struct sk_buff *skb,
		ASFFFPIpsecInfo_t *pSecInfo);

extern struct sk_buff *asf_alloc_buf_skb(struct net_device *dev);
extern void asf_dec_skb_buf_count(struct sk_buff *skb);
void asfFillLogInfo(ASFLogInfo_t *pAsfLogInfo , inSA_t *pSA);
static inline void asfFillLogInfoOut(ASFLogInfo_t *pAsfLogInfo, outSA_t *pSA);

#ifndef ASF_QMAN_IPSEC
struct kmem_cache *icv_cache __read_mostly;
struct kmem_cache *desc_cache __read_mostly;
void *desc_rec_queue[NR_CPUS][MAX_IPSEC_RECYCLE_DESC];
static unsigned int curr_desc[NR_CPUS];

static inline void *secfp_desc_alloc(void)
{
	u32 smp_processor_id = smp_processor_id();
	u32 current_edesc = curr_desc[smp_processor_id];
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	if (unlikely(current_edesc == 0)) {
		return kmem_cache_alloc(desc_cache, GFP_DMA | flags);
	} else {
		curr_desc[smp_processor_id] = current_edesc - 1;
		return desc_rec_queue[smp_processor_id][current_edesc - 1];
	}
}

void secfp_desc_free(void *desc)
{
	u32 smp_processor_id = smp_processor_id();
	u32 current_edesc = curr_desc[smp_processor_id];
	if (desc == NULL)
		return ;
	if (unlikely(current_edesc == (MAX_IPSEC_RECYCLE_DESC - 1))) {
		kmem_cache_free(desc_cache, desc);
	} else {
		desc_rec_queue[smp_processor_id][current_edesc] = desc;
		curr_desc[smp_processor_id] = current_edesc + 1;
	}
	return;
}
#ifdef CONFIG_ASF_SEC3x

static inline void update_chan_out(outSA_t *pSA)
{
#ifdef CONFIG_SMP
	if (dual_intr) {
		if (smp_processor_id()) {
			pSA->chan = 2 * pSA->last_chan[1] + 1;
			pSA->last_chan[1] ^= 1;
		} else {
			pSA->chan = 2 * pSA->last_chan[0];
			pSA->last_chan[0] ^= 1;
		}
	} else
#endif
	{
		pSA->chan = pSA->last_chan[0];
		pSA->last_chan[0] += 1;
		pSA->last_chan[0] &= 0x3;
	}
}

static inline void update_chan_in(inSA_t *pSA)
{
#ifdef CONFIG_SMP
	if (dual_intr) {
		if (smp_processor_id()) {
			pSA->chan = 2 * pSA->last_chan[1] + 1;
			pSA->last_chan[1] ^= 1;
		} else {
			pSA->chan = 2 * pSA->last_chan[0];
			pSA->last_chan[0] ^= 1;
		}
	} else
#endif
	{
		pSA->chan = pSA->last_chan[0];
		pSA->last_chan[0] += 1;
		pSA->last_chan[0] &= 0x3;
	}
}

/* nr_entries = number of 32 bit entries */
#define SECFP_IV_DATA_LO_THRESH 2
#define SECFP_NUM_IV_DATA_GET_AT_ONE_TRY 1
#define SECFP_NUM_IV_ENTRIES 8

int secfp_rng_read_data(struct device *dev, struct secfp_iv_info_s *ptr)
{
	struct talitos_private *priv = dev_get_drvdata(dev);
	u32 i, ofl;

	if (ptr && ptr->ul_num_avail < SECFP_IV_DATA_LO_THRESH) {
		ofl = in_be32(priv->reg + TALITOS_RNGUSR_LO) &
				TALITOS_RNGUSR_LO_OFL;
		ofl = ((ofl - 1) * 2) < SECFP_NUM_IV_DATA_GET_AT_ONE_TRY ?
				((ofl - 1) * 2) :
					SECFP_NUM_IV_DATA_GET_AT_ONE_TRY;

		if (ofl) {
			for (i = 0; i < ofl; i += 2) {
				ptr->vaddr[ptr->ul_update_index] =
					in_be32(priv->reg + TALITOS_RNGU_FIFO);
				ptr->ul_update_index =
					(ptr->ul_update_index + 1)
					& (SECFP_NUM_IV_ENTRIES - 1);
				ptr->vaddr[ptr->ul_update_index] = in_be32(
					priv->reg + TALITOS_RNGU_FIFO_LO);
				ptr->ul_update_index =
					(ptr->ul_update_index + 1) &
					(SECFP_NUM_IV_ENTRIES - 1);
			}
			ptr->ul_num_avail += ofl * 2;
		}
	}
	return 0;
}

/* Initialization routines/De-Initialization routines */
/* IV table initialization */
unsigned int secfp_IVinit(void)
{
	int ii;
	struct secfp_iv_info_s *ptr;

	secfp_IVData = asfAllocPerCpu(sizeof(struct secfp_iv_info_s));
	if (secfp_IVData) {
		for_each_possible_cpu(ii) {
			ptr = per_cpu_ptr(secfp_IVData, ii);

#ifdef SECFP_USE_L2SRAM
			ptr->paddr = (unsigned long) (SECFP_SRAM_BASE +
				SECFP_SRAM_SIZE + SECFP_OUTSA_TABLE_SIZE +
				SECFP_INSA_TABLE_SIZE +
				(ii * SECFP_NUM_IV_ENTRIES *
				sizeof(unsigned int)));
			ptr->vaddr = ioremap_flags(ptr->paddr,
				(sizeof(unsigned int)*SECFP_NUM_IV_ENTRIES),
				PAGE_KERNEL | _PAGE_COHERENT);
#else
			ptr->vaddr = kzalloc(sizeof(unsigned int) *
					SECFP_NUM_IV_ENTRIES, GFP_KERNEL);
			ptr->paddr = dma_map_single(pdev, ptr->vaddr,
					sizeof(unsigned int) *
					SECFP_NUM_IV_ENTRIES,
					DMA_TO_DEVICE);
#endif
			if (!ptr->vaddr) {
				ASFIPSEC_ERR("Allocation of IV Data"
						" storage failed");
				return 1;
			}
		}
	} else {
		ASFIPSEC_ERR("Allocation of Per CPU holder of IV Data failed");
		return 1;
	}
	return 0;
}

void secfp_IVDeInit(void)
{
	struct secfp_iv_info_s *ptr;
	int ii;
	if (secfp_IVData) {
		for_each_possible_cpu(ii) {
			ptr = per_cpu_ptr(secfp_IVData, ii);
#ifndef SECFP_USE_L2SRAM
			SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t) ptr->paddr,
				sizeof(unsigned int)*SECFP_NUM_IV_ENTRIES);
			kfree(ptr->vaddr);
#endif
		}
		asfFreePerCpu(secfp_IVData);
	}
}
#endif
#define SECFP_DESC_FREE secfp_desc_free
#else
#define SECFP_DESC_FREE(desc)
#endif


inline ASF_void_t secfp_SkbFree(ASF_void_t *freeArg)
{
	ASFSkbFree(freeArg);
}

void secfp_deInit(void)
{
	ASFIPSEC_PRINT("DeInitializing Sec FP ");

	ASFFFPRegisterIPSecFunctions(NULL, NULL, NULL, NULL);

	secfp_data_deinit();
#ifdef ASF_QMAN_IPSEC
	secfp_qman_deinit();
#else
	if (desc_cache) {
		void *desc;
		u32 current_edesc, i;

		for_each_possible_cpu(i) {
			current_edesc = curr_desc[i];
			while (current_edesc) {
				desc = desc_rec_queue[i][current_edesc - 1];
				kmem_cache_free(desc_cache, desc);
				current_edesc--;
			}
		}

		kmem_cache_destroy(desc_cache);
	}
#endif
#ifndef ASF_SECFP_PROTO_OFFLOAD
#ifdef CONFIG_ASF_SEC3x
	secfp_IVDeInit();
#endif
#endif
	if (pIPSecPPGlobalStats_g)
		asfFreePerCpu(pIPSecPPGlobalStats_g);
}

int secfp_init(void)
{
#ifndef ASF_SECFP_PROTO_OFFLOAD
#ifdef CONFIG_ASF_SEC3x
	/* Global IV Table setup */
	if (secfp_IVinit()) {
		secfp_deInit();
		ASFIPSEC_ERR("IV Initialization failed ");
		return SECFP_FAILURE;
	}
#endif
#endif
	if (secfp_data_init()) {
		secfp_deInit();
		ASFIPSEC_ERR("secfp_data_init failed");
		return SECFP_FAILURE;
	}
#ifdef ASF_QMAN_IPSEC
	if (secfp_qman_init()) {
		secfp_deInit();
		ASFIPSEC_ERR("secfp_qman_init failed");
		return SECFP_FAILURE;
	}
#else
	desc_cache = kmem_cache_create("desc_cache",
#ifndef CONFIG_ASF_SEC4x
			sizeof(struct ipsec_ah_full_desc),
			__alignof__(struct ipsec_ah_full_desc),
			SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA, NULL);
#else
			sizeof(struct aead_edesc) + CAAM_DESC_BYTES_MAX,
			__alignof__(struct aead_edesc),
			SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA, NULL);
#endif
	if (desc_cache == NULL) {
		secfp_deInit();
		ASFIPSEC_ERR("desc_cache create failed");
		return -ENOMEM;
	}

	icv_cache = kmem_cache_create("icv_cache",
#ifndef CONFIG_ASF_SEC4x
			sizeof(struct ipsec_ah_full_desc),
			__alignof__(struct ipsec_ah_full_desc),
			SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA, NULL);
#else
			sizeof(struct ipsec_ah_edesc) + CAAM_DESC_BYTES_MAX,
			__alignof__(struct ipsec_ah_edesc),
			SLAB_HWCACHE_ALIGN | SLAB_CACHE_DMA, NULL);
#endif
	if (icv_cache == NULL) {
		secfp_deInit();
		ASFIPSEC_ERR("icv_cache create failed");
		return -ENOMEM;
	}
#endif /*ASF_QMAN_IPSEC*/

	pIPSecPPGlobalStats_g = asfAllocPerCpu(sizeof(AsfIPSecPPGlobalStats_t));
	if (!pIPSecPPGlobalStats_g) {
		secfp_deInit();
		ASFIPSEC_ERR("Failed to allocate per-cpu memory for stats\n");
		return -ENOMEM;
	}
	ASFFFPRegisterIPSecFunctions(secfp_try_fastPathIn,
					secfp_try_fastPathOut,
					secfp_CheckInPkt,
					NULL);

	return SECFP_SUCCESS;
}


/*
 * Following are the API definitions which Normal Path/Control Planes
 * can use
 */

#ifndef ASF_SECFP_PROTO_OFFLOAD
/* Packet Processing routines */
/* Check if IVLength required is always 8 bytes To be checked */
/* This function reads from the SEC random number registers. If data is not available
	it reads from the internal IV Array maintained. Upon encryption, some blob is copied
	into this array for use if any
	*/
#ifdef CONFIG_ASF_SEC3x
unsigned int ulRndMisses[NR_CPUS];
static inline void secfp_GetIVData(unsigned int *pData, unsigned int ulNumWords)
{
	int ii;
	int coreId = smp_processor_id();
	struct secfp_iv_info_s *ptr = per_cpu_ptr(secfp_IVData, coreId);
	if (secfp_rng_read_data(pdev, ptr))
		return;
	for (ii = 0; ii < ulNumWords; ii++) {
		*pData = ptr->vaddr[ptr->ul_iv_index];
		ptr->ul_iv_index =
			(ptr->ul_iv_index + 1) & (SECFP_NUM_IV_ENTRIES - 1);
	}
	if (ulNumWords <= ptr->ul_num_avail) {
		ptr->ul_num_avail -= ulNumWords;
	} else {
		ulRndMisses[coreId]++;
		if ((ulRndMisses[coreId] % 0xffffffff) == 0)
			ASFIPSEC_PRINT("ulRndMisses[%d] = %d",
			coreId, ulRndMisses[coreId]);
	}
	return;
}

int vqentr_talitos_rng_data_read(unsigned int len, unsigned int *data)
{
	secfp_GetIVData(data, len/4);
	return len;
}
EXPORT_SYMBOL(vqentr_talitos_rng_data_read);
#endif
#endif
/*
 * This populates the ID field to be supplied as the IP identifier field
 * of the Outer IP header
 */

__be16 secfp_IPv4_IDs[NR_CPUS];
inline __be16 secfp_getNextId(void)
{
	/* Stub : To be filled */
	return secfp_IPv4_IDs[smp_processor_id()]++;
}


#ifndef ASF_SECFP_PROTO_OFFLOAD
/*
 * Outbound packet processing is split as follows -
 * Lookup SA
 * prepare the packet sufficiently for SEC processing such as SEC header
 * addition, padding etc. This is done in prepareOutPacket function. Also required
 * information is copied from the inner IP header to the outer IP header
 * Then prepareOutDescriptor is called to prepare the descriptor. Then
 * talitos_submit is called, which submits descriptors to the SEC block
 * While SEC is processing, finishOutPacket is called by core. This will finish
 * the remaining processing including updating the outer IP header, adjusting
 * the length, skb data, preparing the ethernet header etc.
 * when SEC completes, it calls outComplete, which will call the ethernet
 * driver transmit routine. IV data if available in the packet is copied into
 * the IV array
 */

void
secfp_finishOutPacket(struct sk_buff *skb, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int *pOuterIpHdr,
		unsigned int ulVSGId,
		unsigned int ulSPDContainerIndex)
{
	struct iphdr *iph, *org_iphdr;
	unsigned int *pIpHdrInSA;
	int ii, cpu;
	AsfSPDPolicyPPStats_t *pIPSecPolicyPPStats;
	unsigned short	tot_len = 0;
	unsigned short ipHdrLen = 0;
	unsigned short	etherproto = 0;
	unsigned long uPacket = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	ASF_IPSecTunEndAddr_t TunAddress;
	unsigned short	bl2blobRefresh = 0;
#endif
#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->ipHdrInfo.bIpVersion) {
#endif
	pIpHdrInSA = (unsigned int *) &(pSA->ipHdrInfo.hdrdata.iphv4);
	org_iphdr = (struct iphdr *) pIpHdrInSA;
	/* Outer IP already has the TOS and the length field */
	/* Since length and TOS bits are already set, copy the rest */

	ASFIPSEC_PRINT("FinishPkt: pOuterIpHdr = 0x%x", (int)pOuterIpHdr);
	for (ii = 1; ii < 5; ii++) {
		/* Copy prepared header from SA */
		*(unsigned int *) &(pOuterIpHdr[ii]) = pIpHdrInSA[ii];
	}
	iph = (struct iphdr *) pOuterIpHdr;

	iph->version = pSA->ipHdrInfo.hdrdata.iphv4.version;
	iph->ihl = (unsigned char)5;
	iph->id = secfp_getNextId();

	if (!pSA->SAParams.bCopyDscp) {
		/* We have set the DSCP value from the SA, We need to copy
			the ESN related from the packet */
		iph->tos |= (unsigned char)(org_iphdr->tos & 0x1100);
	}
	tot_len = iph->tot_len;
	ipHdrLen = SECFP_IPV4_HDR_LEN;
	etherproto = ETH_P_IP;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {

		struct udphdr *uh = (struct udphdr *) ((u32 *)iph + iph->ihl);

		ASFIPSEC_DEBUG("NAT Overhead is %d\n", pSA->usNatHdrSize);

		uh->source = pSA->SAParams.IPsecNatInfo.usSrcPort;
		uh->dest = pSA->SAParams.IPsecNatInfo.usDstPort;
		uh->len = tot_len - ipHdrLen;
		uh->check = 0;

		if (pSA->SAParams.IPsecNatInfo.ulNATt == ASF_IPSEC_IKE_NATtV1) {
			u32 *ike = (u32 *) (uh + 8);
			ike[0] = 0;
			ike[1] = 0;
		}
		iph->protocol = IPPROTO_UDP;
		iph->tot_len += pSA->usNatHdrSize;
		tot_len += pSA->usNatHdrSize;
	}

	/* Calculate checksum for L3 */
	iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		struct ipv6hdr *ipv6h;
		unsigned short payload_len = 0;

		pIpHdrInSA = (unsigned int *) &(pSA->ipHdrInfo.hdrdata.iphv6);
		/* Outer IP already has the TOS and the length field */
		/* Since length and TOS bits are already set, copy the rest */

		ipv6h = (struct ipv6hdr *) pOuterIpHdr;
		payload_len = ipv6h->payload_len;
		ASFIPSEC_PRINT("pOuterIpHdr = 0x%x", (int)pOuterIpHdr);
		for (ii = 0; ii < 10; ii++) {
			/* Copy prepared header from SA */
			*(unsigned int *) &(pOuterIpHdr[ii]) = pIpHdrInSA[ii];
		}
		ipv6h->payload_len = payload_len;
		tot_len = ipv6h->payload_len + SECFP_IPV6_HDR_LEN;
		ipHdrLen = SECFP_IPV6_HDR_LEN;
		etherproto = ETH_P_IPV6;
		/*TODO TOS related processing*/
	}
#endif

	/* Update SA Statistics */
	pSA->ulPkts[smp_processor_id()]++;
	pSA->ulBytes[smp_processor_id()] += tot_len - pSA->ulSecHdrLen;
	pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
	pIPSecPolicyPPStats->NumOutBoundOutPkts++;

	/* Update the skb fields */
	skb->len += pSA->ulSecLenIncrease;
	skb->protocol = etherproto;
	if (skb_shinfo(skb)->nr_frags) {
		unsigned int total_frags;
		skb_frag_t *frag;
		total_frags = skb_shinfo(skb)->nr_frags;
		frag = &(skb_shinfo(skb)->frags[total_frags - 1]);
		frag->size += pSA->SAParams.uICVSize;
		skb->data_len += pSA->SAParams.uICVSize;
	}
	skb->data = skb->data - ipHdrLen - pSA->usNatHdrSize;
	if (pSA->SAParams.bAuth)
		skb->tail += pSA->SAParams.uICVSize;
	skb->len += pSA->usNatHdrSize;
	ASFIPSEC_PRINT("Finish packet: ulSecLenIncrease = %d, IP_HDR_LEN=%d "\
		"Updated skb->data = 0x%x",
			pSA->ulSecLenIncrease, ipHdrLen, (int)skb->data);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (pulVSGL2blobMagicNumber[ulVSGId] !=
		pSA->l2blobConfig.ulL2blobMagicNumber) {
		ASFIPSEC_PRINT("L2blob Magic Num Mismatch %d != %d ",
			pulVSGL2blobMagicNumber[ulVSGId],
			pSA->l2blobConfig.ulL2blobMagicNumber);
		if (!pSA->l2blobConfig.bl2blobRefreshSent) {
			pSA->l2blobConfig.ulOldL2blobJiffies = jiffies;
			pSA->l2blobConfig.bl2blobRefreshSent = 1;
		}
		if (time_after(jiffies,
			pSA->l2blobConfig.ulOldL2blobJiffies +
			asf_l2blob_grace_timeout*HZ)) {
			bl2blobRefresh = ASF_L2BLOB_REFRESH_DROP_PKT;
			goto send_l2blob;
		}

		bl2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
	}
#endif
	/* Update L2 Blob information and send pkt out */
	if (pSA->bl2blob) {
		skb->data -= pSA->ulL2BlobLen;
		skb->len += pSA->ulL2BlobLen;

		/* make following unconditional*/
		if (pSA->bVLAN)
			skb->vlan_tci = pSA->tx_vlan_id;
		else
			skb->vlan_tci = 0;

		asfCopyWords((unsigned int *) skb->data,
				(unsigned int *) pSA->l2blob, pSA->ulL2BlobLen);
		if (pSA->bPPPoE) {
			/* PPPoE packet.. Set Payload length in PPPoE header */
			*((short *)&(skb->data[pSA->ulL2BlobLen-4])) =
						htons(ntohs(tot_len) + 2);
		}
		ASFIPSEC_DEBUG("skb->network_header = 0x%x,"
			"skb->transport_header = 0x%x\r\n",
			(unsigned int)skb_network_header(skb),
			(unsigned int)skb_transport_header(skb));
		skb_set_network_header(skb, pSA->ulL2BlobLen);
		skb_set_transport_header(skb, (ipHdrLen + pSA->ulL2BlobLen));
	} else {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT25]);
		ASFIPSEC_DEBUG("OutSA - L2blob info not available");
		skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		goto ret_pkt;
	}

	/* set up the Skb dev pointer */
	skb->dev = pSA->odev;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
send_l2blob:
	if (ASFIPSecCbFn.pFnRefreshL2Blob) {
		if (bl2blobRefresh) {
send_l2blob_2:
		ASFIPSEC_PRINT("Sending L2blob Refresh");
#ifdef ASF_IPV6_FP_SUPPORT
		if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
			TunAddress.IP_Version = 4;
			TunAddress.dstIP.bIPv4OrIPv6 = 0;
			TunAddress.srcIP.bIPv4OrIPv6 = 0;
			TunAddress.dstIP.ipv4addr =
				pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
			TunAddress.srcIP.ipv4addr =
				pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
#ifdef ASF_IPV6_FP_SUPPORT
		} else {
			TunAddress.IP_Version = 6;
			TunAddress.dstIP.bIPv4OrIPv6 = 1;
			TunAddress.srcIP.bIPv4OrIPv6 = 1;
			memcpy(TunAddress.dstIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
			memcpy(TunAddress.srcIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
		}
#endif
		ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId, pSA->ulTunnelId,
			ulSPDContainerIndex,
			ptrIArray_getMagicNum(&(secfp_OutDB),
				ulSPDContainerIndex), &TunAddress,
			pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
		} else if (ulL2BlobRefreshPktCnt_g) {
			for_each_possible_cpu(cpu) {
				uPacket += pSA->ulPkts[cpu];
			}
			if (uPacket % ulL2BlobRefreshPktCnt_g == 0)
				goto send_l2blob_2;
		}
	}
	if (bl2blobRefresh == ASF_L2BLOB_REFRESH_DROP_PKT)
		skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;

#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
ret_pkt:
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (ASFIPSecCbFn.pFnSAExpired) {
		int cpu;
		ASF_boolean_t bHard = ASF_FALSE;
		ASF_boolean_t bExpiry = ASF_FALSE;

		if (pSA->SAParams.hardKbyteLimit) {
			unsigned long ulKBytes = 0;
			for_each_possible_cpu(cpu) {
				ulKBytes += pSA->ulBytes[cpu];
			}
			ulKBytes = ulKBytes/1024;

			if (pSA->SAParams.softKbyteLimit <= ulKBytes) {
				if (pSA->SAParams.hardKbyteLimit <= ulKBytes) {
					bHard = ASF_TRUE;
					skb->cb[SECFP_ACTION_INDEX] =
						SECFP_DROP;
					goto sa_expired1;
				} else
					bExpiry = ASF_TRUE;

				ASFIPSEC_WARN(
				"SA Expired KB=%u (hard=%d) SPI=0x%x",
				ulKBytes, bHard, pSA->SAParams.ulSPI);
			}
		}
		if (pSA->SAParams.hardPacketLimit) {
			unsigned long uPacket = 0;

			for_each_possible_cpu(cpu) {
				uPacket += pSA->ulPkts[cpu];
			}
			if (pSA->SAParams.softPacketLimit <= uPacket) {
				if (pSA->SAParams.hardPacketLimit <= uPacket) {
					bHard = ASF_TRUE;
					skb->cb[SECFP_ACTION_INDEX] =
						SECFP_DROP;
				} else
					bExpiry = ASF_TRUE;

				ASFIPSEC_WARN(
				"SA Expired Pkt=%lu (hard=%d) SPI=0x%x",
				uPacket, bHard, pSA->SAParams.ulSPI);
			}
		}
sa_expired1:
		if (bHard || (bExpiry && !pSA->bSoftExpiry)) {
			ASF_IPAddr_t DestAddr;
			if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
				DestAddr.ipv4addr =
					pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
			} else {
				DestAddr.bIPv4OrIPv6 = 1;
				memcpy(DestAddr.ipv6addr,
					pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
			}
			ASFIPSecCbFn.pFnSAExpired(ulVSGId,
				ulSPDContainerIndex,
				pSA->SAParams.ulSPI,
				pSA->SAParams.ucProtocol,
				DestAddr,
				bHard,
				SECFP_OUT);
			pSA->bSoftExpiry = ASF_TRUE;
		}
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	return;
}

/*
 * Prepares packet for SEC submission: including setting up ESP header, sequence
 * number etc.
 */

void
secfp_prepareOutPacket(struct sk_buff *skb1, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int **pOuterIpHdr)
{
	struct iphdr *iph, *org_iphdr;
	int ii, jj;
	unsigned short usPadLen, usLastByte, usNxtProto;
	unsigned short orig_pktlen;
	unsigned int ulLoSeqNum, ulHiSeqNum;
	struct sk_buff *pHeadSkb, *pTailSkb;
	skb_frag_t *frag = NULL;
	unsigned char *charp = NULL;
	unsigned char tos;
	unsigned int total_frags;

	pTailSkb = pHeadSkb = skb1;
	if (skb_shinfo(skb1)->frag_list) {
		for (pTailSkb = skb_shinfo(skb1)->frag_list;
		pTailSkb->next != NULL; pTailSkb = pTailSkb->next)
			;
	}

	org_iphdr = ip_hdr(skb1);
#ifdef ASF_IPV6_FP_SUPPORT
	if (org_iphdr->version == 6) {
		struct ipv6hdr *org_ipv6hdr = (struct ipv6hdr *) org_iphdr;
		orig_pktlen = org_ipv6hdr->payload_len + SECFP_IPV6_HDR_LEN;
		ASFIPSEC_DEBUG("\n orig_pktlen %d =", orig_pktlen);
		usNxtProto = SECFP_PROTO_IPV6;
		ipv6_traffic_class(tos, org_ipv6hdr);
	} else {
#endif
		orig_pktlen = org_iphdr->tot_len;
		usNxtProto = SECFP_PROTO_IP;
		tos = org_iphdr->tos;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif

	if (skb_shinfo(skb1)->nr_frags) {
		total_frags = skb_shinfo(skb1)->nr_frags;
		frag = &(skb_shinfo(skb1)->frags[total_frags - 1]);
		charp = (u8 *)(page_address((const struct page *)frag->page.p) + frag->page_offset);
	}
	/* Padding length calculation assumes that the block size is always
		8 or 16 as is the case for DES/3DES/AES); In which case we
		don't need to check the 4 byte alignment post padding
			*/
	usPadLen = (orig_pktlen + SECFP_ESP_TRAILER_LEN)
			& (pSA->SAParams.ulBlockSize - 1);
	usPadLen = (usPadLen == 0) ? 0 : pSA->SAParams.ulBlockSize
			- usPadLen;
	/* We need to fill the padding field with 010203 etc. */
	/* Instead of implementing a while loop for this based on the
	pad length, if pad length is non-zero, write block
	size worth of words i.e. either 8/4 or 16/4 starting at tail
	*/
	if (skb_shinfo(skb1)->nr_frags)
		for (ii = 0, jj = 0;
			ii < usPadLen; ii += 4, jj++)
			*(unsigned int *)&(charp[frag->size + ii])
							= pad_words[jj];
	else
		for (ii = 0, jj = 0;
			ii < usPadLen; ii += 4, jj++)
		*(unsigned int *) &(pTailSkb->data[pTailSkb->len+ii])
							= pad_words[jj];
	ASFIPSEC_DEBUG("Total Len = %d +2(ESP TRAILER), padLen=%d",
				org_iphdr->tot_len, usPadLen);

	/* Forming the ESP packet */
	usLastByte = usPadLen << 8 | usNxtProto;
	/* Need to add handling for NR_FRAGS */

	if (skb_shinfo(skb1)->nr_frags) {
		*(unsigned short int *)&(charp[frag->size + usPadLen])
				= usLastByte;
		/* Need to see what can be done in case of frags */
	} else {
		*(unsigned short int *) &(pTailSkb->data[pTailSkb->len +
				usPadLen]) = usLastByte;

		skb_set_tail_pointer(pTailSkb, pTailSkb->len + usPadLen
				+ SECFP_ESP_TRAILER_LEN);
	}
	/* skb->data is at the Original IP header */

	/* If UDP Encapsulation is enabled the headers are as follows -
		IP:UDP:ESP:IV:Payload:Trailer:OptionalICV
		else
		IP:ESP:IV:Payload:Trailer:OptionalICV
	*/

	/* Just copy enough information from inner header */
	/* the rest can be filled in later */
#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->ipHdrInfo.bIpVersion) {
#endif
		*pOuterIpHdr = (unsigned int *)
			(pHeadSkb->data - pSA->usNatHdrSize - SECFP_IPV4_HDR_LEN - pSA->ulSecHdrLen);
		ASFIPSEC_DEBUG("(Pointer update:)pOuterIpHdr = 0x%x",
				(int)*pOuterIpHdr);

	iph = (struct iphdr *) (*pOuterIpHdr);

	/* Total length = Outer IP hdr + Sec hdr len (inclusive of IV) + payload len + padding length + Trailer len */
	iph->tot_len = orig_pktlen + pSA->usNatHdrSize +
				(unsigned short)pSA->ulSecHdrLen +
				(unsigned short)pSA->ulSecLenIncrease
				+ usPadLen + SECFP_ESP_TRAILER_LEN ;
	iph->tos = tos;
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		struct ipv6hdr *ipv6h;
		*pOuterIpHdr = (unsigned int *)
			(pHeadSkb->data - pSA->usNatHdrSize - SECFP_IPV6_HDR_LEN - pSA->ulSecHdrLen);

		ASFIPSEC_DEBUG("(Pointer update:)pOuterIpHdr = 0x%x pSA->ulSecHdrLen = %d",
				(int)*pOuterIpHdr, pSA->ulSecHdrLen);
		ipv6h = (struct ipv6hdr *) (*pOuterIpHdr);

		/* Total length = Outer IP hdr + Sec hdr len (inclusive of IV) + payload len + padding length + Trailer len */
		ipv6h->payload_len = orig_pktlen + pSA->usNatHdrSize +
			(unsigned short)pSA->ulSecHdrLen +
			(unsigned short)pSA->ulSecLenIncrease - SECFP_IPV6_HDR_LEN
			+ usPadLen + SECFP_ESP_TRAILER_LEN ;
		ASFIPSEC_DBGL2("New payload len %d", ipv6h->payload_len);
		ipv6h->priority = (tos >> 4);
		ipv6h->flow_lbl[0] = (tos << 4);
	}
#endif

	/* Now get into ESP header construction */
	/* Assign the end pointer */
	ASFIPSEC_PRINT("PrepareOut Packet ulSecHdrLen = %d", pSA->ulSecHdrLen);
	pHeadSkb->data -= pSA->ulSecHdrLen;

	ASFIPSEC_DBGL2("After preparing sec header skb->data = 0x%x",
			(int)pHeadSkb->data);

	*(unsigned int *) &(pHeadSkb->data[0]) = pSA->SAParams.ulSPI;

	ulHiSeqNum = 0;
	if (pSA->SAParams.bDoAntiReplayCheck) {
		if (pSA->SAParams.bUseExtendedSequenceNumber) {
			ulLoSeqNum = atomic_inc_return(&pSA->ulLoSeqNum);
			if (ulLoSeqNum == 0) {
				ulHiSeqNum = atomic_inc_return(&pSA->ulHiSeqNum);
				if ((ulHiSeqNum == 0) && ASFIPSecCbFn.pFnSeqNoOverFlow) {
					ASF_IPAddr_t	DstAddr;
					DstAddr.bIPv4OrIPv6 = pSA->SAParams.tunnelInfo.bIPv4OrIPv6;
#ifdef ASF_IPV6_FP_SUPPORT
					if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
						memcpy(DstAddr.ipv6addr,
							pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
					else
#endif
					DstAddr.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
					ASFIPSecCbFn.pFnSeqNoOverFlow(*(unsigned int *) &(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
									pSA->ulTunnelId, pSA->SAParams.ulSPI,
									pSA->SAParams.ucProtocol, DstAddr);
				}
			}
		} else {
			ulLoSeqNum = atomic_inc_return(&pSA->ulLoSeqNum);
			if ((ulLoSeqNum == 0) && ASFIPSecCbFn.pFnSeqNoOverFlow) {
				ASF_IPAddr_t	DstAddr;
				DstAddr.bIPv4OrIPv6 = pSA->SAParams.tunnelInfo.bIPv4OrIPv6;
#ifdef ASF_IPV6_FP_SUPPORT
				if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
					memcpy(DstAddr.ipv6addr, pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
				else
#endif
				DstAddr.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
				ASFIPSecCbFn.pFnSeqNoOverFlow(*(unsigned int *) &(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
								pSA->ulTunnelId, pSA->SAParams.ulSPI,
								pSA->SAParams.ucProtocol,
								DstAddr);
			}
		}
	} else {
		pSA->ulLoSeqNum.counter++;
		if (pSA->ulLoSeqNum.counter == 0)
			pSA->ulLoSeqNum.counter = 1;
		ulLoSeqNum = pSA->ulLoSeqNum.counter;
	}
	*(unsigned int *) &(pHeadSkb->data[4]) = ulLoSeqNum;

	/* Alright sequence number will be either the right one in extended sequence number
		support or it will be set to 0 */
	if (pSA->SAParams.bUseExtendedSequenceNumber)
		*(unsigned int *) skb_tail_pointer(pTailSkb) = ulHiSeqNum;

	/* Finished handling the SEC Header */
	/* Now prepare the IV Data */
#ifdef CONFIG_ASF_SEC3x
	if (pSA->SAParams.ucCipherAlgo != SECFP_ESP_NULL)
		secfp_GetIVData((unsigned int *) &pHeadSkb->data[SECFP_ESP_HDR_LEN],
			pSA->SAParams.ulIvSize/4);
#endif

	if (skb_shinfo(pHeadSkb)->nr_frags) {
		ASFIPSEC_DEBUG("frag->size:%d pHeadSkb->data_len:%d\n",
					frag->size, pHeadSkb->data_len);
		frag->size += usPadLen + SECFP_ESP_TRAILER_LEN;
		pHeadSkb->data_len += usPadLen + SECFP_ESP_TRAILER_LEN;
		pHeadSkb->len = orig_pktlen + pSA->ulSecHdrLen + usPadLen
				+ SECFP_ESP_TRAILER_LEN;
		ASFIPSEC_DEBUG("pHeadSkb->len:%d pHeadSkb->len1:%d\n",
					pHeadSkb->len, org_iphdr->tot_len);
		ASFIPSEC_DEBUG("frag->size:%d pHeadSkb->data_len:%d\n",
					frag->size, pHeadSkb->data_len);
	} else {
		/* Update skb->len */
		pHeadSkb->len += pSA->ulSecHdrLen /*ulSecHdrLen includes IV */ ;
		pTailSkb->len += usPadLen + SECFP_ESP_TRAILER_LEN;
	}
	ASFIPSEC_DBGL2("pHeadSkb->data_len = %d",
		(int)pHeadSkb->data_len);
	ASFIPSEC_DBGL2("HeadSkb: skb->data = 0x%x, skb->len = %d,"\
		"usPadLen =%d, trailer=%d",
		(int)pHeadSkb->data, pHeadSkb->len, usPadLen, SECFP_ESP_TRAILER_LEN);
	ASFIPSEC_DBGL2("TailSkb: skb->data = 0x%x, skb->len = %d,"\
		"usPadLen =%d, trailer=%d",
		(int)pTailSkb->data, pTailSkb->len, usPadLen, SECFP_ESP_TRAILER_LEN);

	ASFIPSEC_HEXDUMP(skb1->data, 64);
}
#else /*ASF_SECFP_PROTO_OFFLOAD*/
void
secfp_finishOffloadOutPacket(struct sk_buff *skb, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int *pIpHdr,
		unsigned int ulVSGId,
		unsigned int ulSPDContainerIndex)
{
	struct iphdr *iph = (struct iphdr *) pIpHdr;
	AsfSPDPolicyPPStats_t *pIPSecPolicyPPStats;
	unsigned short	tot_len = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int cpu;
	unsigned long uPacket = 0;
	ASF_IPSecTunEndAddr_t TunAddress;
	unsigned short	bl2blobRefresh = 0;
#endif

#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6) {
		struct ipv6hdr *ipv6h;
		ipv6h = (struct ipv6hdr *) pIpHdr;
		tot_len = ipv6h->payload_len + SECFP_IPV6_HDR_LEN;
	} else
#endif
		tot_len = iph->tot_len;

	/* Update SA Statistics */
	pSA->ulPkts[smp_processor_id()]++;
	pSA->ulBytes[smp_processor_id()] += tot_len;
	pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
	pIPSecPolicyPPStats->NumOutBoundOutPkts++;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (pulVSGL2blobMagicNumber[ulVSGId] !=
		pSA->l2blobConfig.ulL2blobMagicNumber) {
		ASFIPSEC_PRINT("L2blob Magic Num Mismatch %d != %d ",
			pulVSGL2blobMagicNumber[ulVSGId],
			pSA->l2blobConfig.ulL2blobMagicNumber);
		if (!pSA->l2blobConfig.bl2blobRefreshSent) {
			pSA->l2blobConfig.ulOldL2blobJiffies = jiffies;
			pSA->l2blobConfig.bl2blobRefreshSent = 1;
		}
		if (time_after(jiffies,
			pSA->l2blobConfig.ulOldL2blobJiffies +
			asf_l2blob_grace_timeout*HZ)) {
			bl2blobRefresh = ASF_L2BLOB_REFRESH_DROP_PKT;
			goto send_l2blob;
		}

		bl2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
	}
#endif
	/* set up the Skb dev pointer */
	skb->dev = pSA->odev;

	if (likely(pSA->bl2blob)) {
		/* Moving data pointer to copy L2blob */
		/* L2blob will be copied before the tunnel headers
		which are inserted before current data location */
		skb->data -= (pSA->ulL2BlobLen + pSA->ulXmitHdrLen);

		skb->cb[SECFP_OUTB_L2_OVERHEAD] = pSA->ulL2BlobLen;

		if (pSA->bVLAN)
			skb->vlan_tci = pSA->tx_vlan_id;
		else
			skb->vlan_tci = 0;

		asfCopyWords((unsigned int *) skb->data,
				(unsigned int *) pSA->l2blob, pSA->ulL2BlobLen);
		if (pSA->bPPPoE)
			skb->cb[SECFP_OUTB_L2_WITH_PPPOE] = 1;

		/*Reverting the data pointer to it's original location*/
		skb->data += (pSA->ulL2BlobLen + pSA->ulXmitHdrLen);
		skb_reset_network_header(skb);
	} else {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT25]);
		ASFIPSEC_DPERR("OutSA - L2blob info not available");
		skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		goto ret_pkt;
	}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
send_l2blob:
	if (ASFIPSecCbFn.pFnRefreshL2Blob) {

		if (bl2blobRefresh) {
send_l2blob_2:
			ASFIPSEC_PRINT("Sending L2blob Refresh");
#ifdef ASF_IPV6_FP_SUPPORT
			if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
				TunAddress.IP_Version = 4;
				TunAddress.dstIP.bIPv4OrIPv6 = 0;
				TunAddress.srcIP.bIPv4OrIPv6 = 0;
				TunAddress.dstIP.ipv4addr =
					pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
				TunAddress.srcIP.ipv4addr =
					pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
#ifdef ASF_IPV6_FP_SUPPORT
			} else {
				TunAddress.IP_Version = 6;
				TunAddress.dstIP.bIPv4OrIPv6 = 1;
				TunAddress.srcIP.bIPv4OrIPv6 = 1;
				memcpy(TunAddress.dstIP.ipv6addr,
					pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
				memcpy(TunAddress.srcIP.ipv6addr,
					pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
			}
#endif
			ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId, pSA->ulTunnelId,
				ulSPDContainerIndex,
				ptrIArray_getMagicNum(&(secfp_OutDB),
				ulSPDContainerIndex), &TunAddress,
				pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
		} else if (ulL2BlobRefreshPktCnt_g) {
			for_each_possible_cpu(cpu) {
				uPacket += pSA->ulPkts[cpu];
			}
			if (uPacket % ulL2BlobRefreshPktCnt_g == 0)
				goto send_l2blob_2;
		}
	}
	if (bl2blobRefresh == ASF_L2BLOB_REFRESH_DROP_PKT)
		skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;

#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
ret_pkt:
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (ASFIPSecCbFn.pFnSAExpired) {
		ASF_boolean_t bHard = ASF_FALSE;
		ASF_boolean_t bExpiry = ASF_FALSE;

		if (pSA->SAParams.hardKbyteLimit) {
			unsigned long ulKBytes = 0;
			for_each_possible_cpu(cpu) {
				ulKBytes += pSA->ulBytes[cpu];
			}
			ulKBytes = ulKBytes/1024;

			if (pSA->SAParams.softKbyteLimit <= ulKBytes) {
				if (pSA->SAParams.hardKbyteLimit <= ulKBytes) {
					bHard = ASF_TRUE;
					skb->cb[SECFP_ACTION_INDEX] =
						SECFP_DROP;
					goto sa_expired1;
				} else
					bExpiry = ASF_TRUE;

				ASFIPSEC_WARN(
				"SA Expired KB=%lu (hard=%d) SPI=0x%x",
				ulKBytes, bHard, pSA->SAParams.ulSPI);
			}
		}
		if (pSA->SAParams.hardPacketLimit) {
			for_each_possible_cpu(cpu) {
				uPacket += pSA->ulPkts[cpu];
			}
			if (pSA->SAParams.softPacketLimit <= uPacket) {
				if (pSA->SAParams.hardPacketLimit <= uPacket) {
					bHard = ASF_TRUE;
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				} else
					bExpiry = ASF_TRUE;

				ASFIPSEC_WARN(
				"SA Expired Pkt=%lu (hard=%d) SPI=0x%x",
				uPacket, bHard, pSA->SAParams.ulSPI);
			}
		}
sa_expired1:
		if (bHard || (bExpiry && !pSA->bSoftExpiry)) {
			ASF_IPAddr_t DestAddr;
			if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
				DestAddr.ipv4addr =
					pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
			} else {
				DestAddr.bIPv4OrIPv6 = 1;
				memcpy(DestAddr.ipv6addr,
					pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
			}
			ASFIPSecCbFn.pFnSAExpired(ulVSGId,
				ulSPDContainerIndex,
				pSA->SAParams.ulSPI,
				pSA->SAParams.ucProtocol,
				DestAddr,
				bHard,
				SECFP_OUT);
			pSA->bSoftExpiry = ASF_TRUE;
		}
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	return;
}
#endif /*ASF_SECFP_PROTO_OFFLOAD*/

/*
 * V6 hook function
 */
#define SECFP_MAX_BYTES_TO_LINEARIZE 128
#ifdef ASF_IPV6_FP_SUPPORT
static inline int secfp_try_fastPathOutv6(unsigned int ulVSGId,
				struct sk_buff *skb1,
				ASFFFPIpsecInfo_t *pSecInfo)
{
	outSA_t *pSA ;
	struct ipv6hdr *ipv6h = ipv6_hdr(skb1);
	unsigned int *pOuterIpHdr;
	struct sk_buff *pNextSkb = NULL;
	SPDOutContainer_t *pContainer;
	struct sk_buff *skb = skb1;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	AsfSPDPolicyPPStats_t *pIPSecPolicyPPStats;
	ASF_boolean_t	bRevalidate = ASF_FALSE;
	unsigned char ipv6TClass = 0;
#ifndef CONFIG_ASF_SEC4x
	struct talitos_desc *desc = NULL;
#elif !defined(ASF_QMAN_IPSEC)
	void *desc;
#endif
	char bScatterGatherList = SECFP_NO_SCATTER_GATHER;
	unsigned char secout_sg_flag;
#ifdef ASFIPSEC_LOG_MSG
	ASFLogInfo_t AsfLogInfo;
	char aMsg[ASF_MAX_MESG_LEN + 1];
#endif

	rcu_read_lock();

	ipv6_traffic_class(ipv6TClass, ipv6h);
	pIPSecPPGlobalStats = asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
	pIPSecPPGlobalStats->ulTotOutRecvPkts++;

	ASFIPSEC_FPRINT("Pkt received skb->len = %d, ipv6h->payload_len = %d",
		skb1->len, ipv6h->payload_len);
	ASFIPSEC_HEXDUMP(skb->data - 14, skb1->len + 14);

	ASFIPSEC_FENTRY;
	pSA = secfp_findOutSA(ulVSGId, pSecInfo, skb1, ipv6TClass,
			&pContainer, &bRevalidate);
	if (unlikely(pSA == NULL)) {
		ASFIPSEC_DEBUG("SA Not Found");
		goto no_sa;
	}
	ASFIPSEC_DEBUG("SA Found");

	if (unlikely(pSA->odev == NULL)) {
		ASFIPSEC_DEBUG("L2blob Not Resolved. Drop the packet");
		goto l2blob_missing;
	}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (skb_shinfo(skb1)->frag_list) {
		struct sk_buff *pSkb;
		asfIpv6MakeFragment(skb, &pSkb);
		skb = pSkb;
		ipv6h = ipv6_hdr(skb);
	}
#endif
	pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
	pIPSecPolicyPPStats->NumOutBoundInPkts++;
	/* Check if there is enough head room and tail room */

	/* Fragment handling and TTL decrement already done in FW Fast Path */
#ifndef ASF_SECFP_PROTO_OFFLOAD
	/* Need to remove decrement TTL by firewall */
	ipv6h->hop_limit--;
#endif

	if (skb_shinfo(skb1)->nr_frags) {
		ASFIPSEC_DEBUG("has nr_frags = %d",
				skb_shinfo(skb1)->nr_frags);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		bScatterGatherList = SECFP_SCATTER_GATHER;
		skb = skb1;
#else /*MINIMUM MODE*/
		/* Fragmentation is not handled in minimum mode */
		skb->data_len = 0;
		goto drop_skb_list;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	}
	secout_sg_flag = SECFP_OUT|bScatterGatherList;
	ASFIPSEC_DEBUG("outV6: bScatterGather = %d", bScatterGatherList);
	/* For frag_list case, this will send each frag independently
	   to SEC for encryption*/

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	for (; skb != NULL; skb = pNextSkb)
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
	{
		pNextSkb = skb->next;
		skb->next = NULL;
		if (skb->len > pSA->ulInnerPathMTU) {
			if (pSecInfo->outContainerInfo.bControlPathPkt) {
				skb->cb[SECFP_OUTB_FRAG_REQD] = 1;
			} else {
				ASFIPSEC_DEBUG("Packet size is > Path MTU and fragment bit set in SA or packet");
				/* Need to send to normal path */
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT21);
				icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0,
						pSA->ulInnerPathMTU);
				goto drop_skb_list;
			}
		}
		ASFIPSEC_DEBUG("outv6: skb = 0x%x skb1 = 0x%x, nextSkb = 0x%x",
			(unsigned int) skb, (unsigned int) skb1, (unsigned int) pNextSkb);
		if (pSA->prepareOutPktFnPtr)
			(*pSA->prepareOutPktFnPtr)(skb, pSA,
				pContainer, &pOuterIpHdr);
		else
			pOuterIpHdr = (unsigned int *) ipv6h;

		ASFIPSEC_DBGL2("Out Process; pOuterIPHdr set to 0x%x",
			(int)pOuterIpHdr);
		/* Put sufficient data in the skb for post SEC processing */
		skb->cb[SECFP_ICV_LENGTH] = pSA->SAParams.uICVSize;
		*(unsigned int *) &(skb->cb[SECFP_SPD_CI_INDEX]) =
				pSecInfo->outContainerInfo.ulSPDContainerId;
		*(unsigned int *) &(skb->cb[SECFP_VSG_ID_INDEX]) = ulVSGId;
		*(unsigned int *) &(skb->cb[SECFP_SPD_CI_MAGIC_INDEX]) =
				pSecInfo->outContainerInfo.ulSPDMagicNumber;
		*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_INDEX]) =
				pSecInfo->outSAInfo.ulSAIndex;
		*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX]) =
				pSecInfo->outSAInfo.ulSAMagicNumber;

		ASFIPSEC_DBGL2("IOut SA Index =%d, Magic No = %d",
			pSecInfo->outContainerInfo.ulSPDContainerId,
			pSecInfo->outSAInfo.ulSAMagicNumber);
		ASFIPSEC_DBGL2("Out SA Index =%d, Magic Number = %d",
			*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_INDEX]),
			*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX]));

		ASFIPSEC_DBGL2("Before secfp-submit:"
			"skb= 0x%x, skb->data= 0x%x, skb->dev= 0x%x\n",
			(int)skb, (int)skb->data, (int)skb->dev);
#ifndef ASF_QMAN_IPSEC
		/* Keeping REF_INDEX as 2, one for the h/w
		and one for the core */
		skb->cb[SECFP_REF_INDEX] = 2;

		desc = secfp_desc_alloc();
		if (!desc) {
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
			ASFIPSEC_DPERR("desc allocation failure");
			goto drop_skb_list;
		}
		if ((secout_sg_flag & SECFP_SCATTER_GATHER)
			== SECFP_SCATTER_GATHER)
			pSA->prepareOutDescriptorWithFrags(skb, pSA,
						desc, 0);
		else
			pSA->prepareOutDescriptor(skb, pSA, desc, 0);
#endif /*ASF_QMAN_IPSEC*/

		ASFIPSEC_FPRINT("Pkt Pre Processing len=%d", skb->len);
		ASFIPSEC_HEXDUMP(skb->data, skb->len);

		(*pSA->finishOutPktFnPtr)(skb, pSA, pContainer,
				pOuterIpHdr, ulVSGId,
			pSecInfo->outContainerInfo.ulSPDContainerId);

		ASFIPSEC_FPRINT("Pkt Post Processing %d", skb->len);
		ASFIPSEC_HEXDUMP(skb->data, skb->len);

		if (skb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
			ASFIPSEC_DPERR("Packet Action is Drop");
			skb->data_len = 0;
#ifndef ASF_QMAN_IPSEC
			SECFP_DESC_FREE(desc);
#endif
			goto drop_skb_list;
		}

		ASFIPSEC_DEBUG("OUT-submit to SEC");
		pIPSecPPGlobalStats->ulTotOutRecvPktsSecApply++;
#ifndef CONFIG_ASF_SEC4x
		update_chan_out(pSA);
		if (talitos_submit(pdev, pSA->chan, (char *)desc,
			pSA->outComplete, (void *)skb) == -EAGAIN)
#elif defined(ASF_QMAN_IPSEC)
		if (secfp_qman_out_submit(pSA, (void *) skb))
#else
		if (caam_jr_enqueue(pSA->ctx.jrdev,
			((struct aead_edesc *)desc)->hw_desc,
			pSA->outComplete, (void *)skb))
#endif
		{
#ifdef ASFIPSEC_LOG_MSG
			ASFIPSEC_DEBUG("Outbound Submission to"\
					"SEC failed ");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				"Cipher Operation Failed-5");
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			AsfLogInfo.u.IPSecInfo.ulSPDContainerIndex =
				pSecInfo->outContainerInfo.ulSPDContainerId;
			AsfLogInfo.ulVSGId = ulVSGId;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfoOut(&AsfLogInfo, pSA);
#endif
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);

			skb->data_len = 0;
			SECFP_DESC_FREE(desc);
			goto drop_skb_list;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifndef CONFIG_ASF_SEC4x
		skb->cb[SECFP_REF_INDEX]--;
		if (pSA->option[1] != SECFP_NONE) {
			ASFIPSEC_DEBUG("2nd Iteration");
			/* 2nd iteration required ICV */
			skb->cb[SECFP_REF_INDEX]++;

			desc = secfp_desc_alloc();
			if (!desc) {
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
				ASFIPSEC_WARN("desc allocation failure");
				if (skb->cb[SECFP_REF_INDEX] != 0) {
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				} else {

					/* So, we can release it */
					skb->data_len = 0;
					goto drop_skb_list;
				}
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
			if ((secout_sg_flag & SECFP_SCATTER_GATHER)
					== SECFP_SCATTER_GATHER)
				pSA->prepareOutDescriptorWithFrags(skb,
					pSA, desc, 1);
			else
				pSA->prepareOutDescriptor(skb, pSA, desc, 1);

			if (talitos_submit(pdev, pSA->chan, desc,
					pSA->outComplete,
					(void *)skb) == -EAGAIN) {
				ASFIPSEC_WARN("Outbound Submission to"\
						"SEC failed ");
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
				/* We cannot free the skb now, as it is submitted to h/w */
				skb->cb[SECFP_REF_INDEX] -= 2; /* Removed for the core and current submission */
				if (skb->cb[SECFP_REF_INDEX] != 0) {
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				} else { /* CB already happened, and returned */

					/* So, we can release it */
					skb->data_len = 0;
					SECFP_DESC_FREE(desc);
					goto drop_skb_list;
				}
				SECFP_DESC_FREE(desc);
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
		}
		if (skb->cb[SECFP_REF_INDEX] == 0) {
			/* Some error happened in the c/b. Free the skb */
			ASFIPSEC_DEBUG("O/b Proc Completed REF_CNT == 0, freeing the skb");
			skb->data_len = 0;
			goto drop_skb_list;
		}
#endif /*CONFIG_ASF_SEC3x */
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	}
	rcu_read_unlock();
	return 0;

no_sa:
	rcu_read_unlock();
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	for (; skb != NULL; skb = pNextSkb)
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
	{
		pNextSkb = skb->next;
		skb->next = NULL;
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
				IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT24]);
		if (ASFIPSecCbFn.pFnNoOutSA) {
			ASF_uchar8_t bSPDContainerPresent;
			ASFBuffer_t Buffer;
			Buffer.nativeBuffer = skb;
			if (pContainer)
				bSPDContainerPresent = 1;
			else
				bSPDContainerPresent = 0;
#ifdef CONFIG_DPA
			asf_dec_skb_buf_count(skb1);
#endif
			ASFIPSecCbFn.pFnNoOutSA(ulVSGId , NULL, Buffer,
					secfp_SkbFree, skb1,
					bSPDContainerPresent,
					bRevalidate);
			if (pNextSkb == NULL)
				return 0;
		}
	}
	return 1;

l2blob_missing:
	{
		ASF_IPSecTunEndAddr_t TunAddress;
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT25]);

		TunAddress.IP_Version = 6;
		TunAddress.dstIP.bIPv4OrIPv6 = 1;
		TunAddress.srcIP.bIPv4OrIPv6 = 1;
		memcpy(TunAddress.dstIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
		memcpy(TunAddress.srcIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);

		if (ASFIPSecCbFn.pFnRefreshL2Blob)
			ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId,
					pSecInfo->outContainerInfo.ulTunnelId,
					pSecInfo->outContainerInfo.ulSPDContainerId,
					pSecInfo->outContainerInfo.ulSPDMagicNumber,
					&TunAddress,
					pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
	}

drop_skb_list:
	ASFSkbFree(skb);
	while (pNextSkb) {
		skb = pNextSkb;
		pNextSkb = skb->next;
		skb->next = NULL;
		ASFSkbFree(skb);
	}

	rcu_read_unlock();
	return 0;
}

#endif /*IPV6*/

/*
 * Outbound fast path function invoked from the ethernet driver. Passed information
 * includes cached VSGId, skbuffer, cached Outbound SPD container index/magic
 * Outbound SA/magic. If Outbound SA/magic is not available or does not match
 * the SA lookup happens, and if SA is found based on Selector Set match or DSCP
 * match, the cache variables are updated. If SPD container does not exist, or
 * SA does not exist, packet has to be given to normal path
 * If SA exists, fragmentation options are determined such as red side fragmentation
 * Post that prepareOutPacket() for sec submission is called, Subsequently
 * talitos_submit()
 * is called for descriptor submission. talitos_submit() is defined in
 * talitos.c. It allcoates
 * descriptor and calls prepareOutDescriptor() to prepare the descriptor. Post that
 * the descriptor is submitted to SEC. The function continues to finishOutPacket()
 * - i.e. put the outer IP address, update the length, MAC address etc. and makes it
 * ready for transmission. outComplete() is called from talitos.c (flush_channel() as
 * part of talitos_done() finally submits the packet to the ethernet driver for
 * transmission
 * Return values: 1 means packet is absorbed by SEC. 0 means packet is available
 * for caller.
 */
static inline int secfp_try_fastPathOutv4(
		unsigned int ulVSGId,
		struct sk_buff *skb1, ASFFFPIpsecInfo_t *pSecInfo)
{
	outSA_t *pSA;
	struct iphdr *iph = ip_hdr(skb1);
	unsigned int *pOuterIpHdr;
	struct sk_buff *pNextSkb = NULL;
	SPDOutContainer_t *pContainer;
	struct sk_buff *skb = skb1;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	AsfSPDPolicyPPStats_t *pIPSecPolicyPPStats;
	ASF_boolean_t	bRevalidate = ASF_FALSE;
#ifndef CONFIG_ASF_SEC4x
	struct talitos_desc *desc = NULL;
	int iRetVal = 0;
#elif !defined(ASF_QMAN_IPSEC)
	void *desc;
#endif
	char bScatterGatherList = SECFP_NO_SCATTER_GATHER;
	unsigned char secout_sg_flag;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	unsigned int ulMTU;
	ASFLogInfo_t AsfLogInfo;
	char aMsg[ASF_MAX_MESG_LEN + 1];
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
	rcu_read_lock();

	ASFIPSEC_FENTRY;

	pIPSecPPGlobalStats = asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
	pIPSecPPGlobalStats->ulTotOutRecvPkts++;

	ASFIPSEC_FPRINT("*****secfp_out: Pkt received skb->len = %d,"\
		"iph->tot_len = %d", skb1->len, iph->tot_len);
	ASFIPSEC_HEXDUMP(skb1->data - 14, skb1->len + 14);

	pSA = secfp_findOutSA(ulVSGId, pSecInfo, skb1, iph->tos,
			&pContainer, &bRevalidate);
	if (unlikely(pSA == NULL)) {
		ASFIPSEC_DEBUG("SA Not Found");
		goto no_sa;
	}
	if (unlikely(pSA->odev == NULL)) {
		ASFIPSEC_DEBUG("L2blob Not Resolved. Drop the packet");
		goto l2blob_missing;
	}
	if (!skb1->dev)
		skb1->dev = pSA->odev;

	ASFIPSEC_DEBUG("SA Found");
	pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
	pIPSecPolicyPPStats->NumOutBoundInPkts++;
	/* todo Check if there is enough head room and tail room */

	/* Fragment handling and TTL decrement already done in FW Fast Path */
#ifndef ASF_SECFP_PROTO_OFFLOAD
	ip_decrease_ttl(iph);
#endif

	if (unlikely(skb_shinfo(skb1)->frag_list)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (pSecInfo->outContainerInfo.bControlPathPkt)
			ulMTU = pSA->ulInnerPathMTU;
		else
			ulMTU = SECFP_MAX_MTU;
		if (unlikely(asfIpv4Fragment(skb1, ulMTU, 0, ASF_TRUE,
					skb1->dev, &skb))) {
						ASF_IPSEC_PPS_ATOMIC_INC(
						IPSec4GblPPStats_g.IPSec4GblPPStat
						[ASF_IPSEC_PP_GBL_CNT22]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA,
						ASF_IPSEC_PP_POL_CNT22);
						rcu_read_unlock();
						return 0;
					}
		skb1 = skb;
		iph = ip_hdr(skb);
#else /*MINIMUM MODE*/
		/* Fragmentation is not handled in minimum mode */
		skb->data_len = 0;
		goto drop_skb_list;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	}
	if (unlikely(skb_shinfo(skb1)->nr_frags)) {
		ASFIPSEC_DEBUG("has nr_frags = %d",
			skb_shinfo(skb1)->nr_frags);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			bScatterGatherList = SECFP_SCATTER_GATHER;
			skb = skb1;
#else /*MINIMUM MODE*/
			/* Fragmentation is not handled in minimum mode */
			skb->data_len = 0;
			goto drop_skb_list;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	/* For frag_list case, this will send each frag independently
	to SEC for encryption*/

	for (; skb != NULL; skb = pNextSkb)
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
	{
		pNextSkb = skb->next;
		skb->next = NULL;
		ASFIPSEC_DEBUG("outv4: skb = 0x%x skb1 = 0x%x, nextSkb = 0x%x",
			(unsigned int) skb, (unsigned int) skb1,
			(unsigned int) pNextSkb);
		/* SEC overhead already accounted for in Inner path MTU */
		if (unlikely(skb->len > pSA->ulInnerPathMTU)) {
			ASFIPSEC_DEBUG("Total Leng is > ulPathMTU "
					"tot_len = %d, ulPathMTU = %d",
					iph->tot_len, pSA->ulInnerPathMTU);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			ASFIPSEC_DEBUG("Fragmentation activated");
			if (pSA->SAParams.bRedSideFragment) {
				struct sk_buff *tempSkb;
				ASFIPSEC_DEBUG("Red side fragmentation is enabled");
				if (iph->frag_off & IP_DF) {
					ASFIPSEC_DEBUG("DF Bit is set while"\
						" Red side fragmentation is enabled");
					snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
						"Packet size is > Path MTU and fragment"
						"bit set in SA or packet");
					AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID10;
					AsfLogInfo.ulVSGId = ulVSGId;
					AsfLogInfo.aMsg = aMsg;
					AsfLogInfo.u.IPSecInfo.ulSPDContainerIndex =
						pSecInfo->outContainerInfo.ulSPDContainerId;
					asfFillLogInfoOut(&AsfLogInfo, pSA);
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
							IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT21]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA,
							ASF_IPSEC_PP_POL_CNT21);
					if (pSecInfo->natInfo.bSrcNAT) {
#ifdef ASF_DO_INC_CHECKSUM
						csum_replace4(&iph->check, iph->saddr,
							pSecInfo->natInfo.OrgSrcIp);
#endif
						iph->saddr = pSecInfo->natInfo.OrgSrcIp;
					}
					ASFIPSec4SendIcmpErrMsg(skb->data,
							ASF_ICMP_DEST_UNREACH,
							ASF_ICMP_CODE_FRAG_NEEDED,
							pSA->ulInnerPathMTU, ulVSGId);
					goto drop_skb_list;
				}
				if (unlikely(asfIpv4Fragment(skb,
						pSA->ulInnerPathMTU,
#ifndef ASF_SECFP_PROTO_OFFLOAD
						(pSA->ulSecHdrLen + pSA->usNatHdrSize) +
#endif
						pSA->ulL2BlobLen,
						ASF_TRUE, skb->dev, &skb))) {
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
						IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT22]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA,
						ASF_IPSEC_PP_POL_CNT22);
					goto drop_skb_list;
				}
				tempSkb = skb->next;
				for (; tempSkb->next != NULL; tempSkb = tempSkb->next)
					;
				tempSkb->next = pNextSkb;
				pNextSkb = skb->next;
				skb->next = NULL;
				bScatterGatherList = SECFP_NO_SCATTER_GATHER;
			} else {
				if (((pSA->SAParams.handleDf == SECFP_DF_SET) ||
				((iph->frag_off & IP_DF) && (pSA->SAParams.handleDf
				== SECFP_DF_COPY)) || pSA->ipHdrInfo.bIpVersion)) {
					ASFIPSEC_DEBUG("Packet size is > Path MTU"\
							"and fragment bit set in SA or packet");
					snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
							"Packet size is > Path MTU and fragment"
							"bit set in SA or packet");
					AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID10;
					AsfLogInfo.ulVSGId = ulVSGId;
					AsfLogInfo.aMsg = aMsg;
					AsfLogInfo.u.IPSecInfo.ulSPDContainerIndex =
						pSecInfo->outContainerInfo.ulSPDContainerId;
					asfFillLogInfoOut(&AsfLogInfo, pSA);
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
							IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT21]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA,
							ASF_IPSEC_PP_POL_CNT21);
					if (pSecInfo->natInfo.bSrcNAT) {
#ifdef ASF_DO_INC_CHECKSUM
						csum_replace4(&iph->check, iph->saddr,
							pSecInfo->natInfo.OrgSrcIp);
#endif
						iph->saddr = pSecInfo->natInfo.OrgSrcIp;
					}
					ASFIPSec4SendIcmpErrMsg(skb->data,
							ASF_ICMP_DEST_UNREACH,
							ASF_ICMP_CODE_FRAG_NEEDED,
							pSA->ulInnerPathMTU, ulVSGId);
					goto drop_skb_list;
				}
				ASFIPSEC_PRINT("Need to fragment the packet"
						"POST SEC and send it out ");
				/* Need to fragment the packet */
				skb->cb[SECFP_OUTB_FRAG_REQD] = 1;
			}
#else /*MINIMUM MODE*/
			/* Fragmentation is not handled in minimum mode */
			skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		} /* Fragmentation */
		secout_sg_flag = SECFP_OUT|bScatterGatherList;
		ASFIPSEC_DEBUG("outV4: bScatterGather = %d", bScatterGatherList);
		if (pSA->prepareOutPktFnPtr)
			(*pSA->prepareOutPktFnPtr)(skb, pSA,
				pContainer, &pOuterIpHdr);
		else
			pOuterIpHdr = (unsigned int *) ip_hdr(skb);

		ASFIPSEC_DBGL2("Out Process; pOuterIPHdr set to 0x%x",
			(int)pOuterIpHdr);
		/* Put sufficient data in the skb for post SEC processing */
		skb->cb[SECFP_ICV_LENGTH] = pSA->SAParams.uICVSize;
		*(unsigned int *) &(skb->cb[SECFP_SPD_CI_INDEX]) =
				pSecInfo->outContainerInfo.ulSPDContainerId;
		*(unsigned int *) &(skb->cb[SECFP_VSG_ID_INDEX]) = ulVSGId;
		*(unsigned int *) &(skb->cb[SECFP_SPD_CI_MAGIC_INDEX]) =
				pSecInfo->outContainerInfo.ulSPDMagicNumber;
		*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_INDEX]) =
				pSecInfo->outSAInfo.ulSAIndex;
		*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX]) =
				pSecInfo->outSAInfo.ulSAMagicNumber;

		ASFIPSEC_DBGL2("IOut SA Index =%d, Magic No = %d",
			pSecInfo->outContainerInfo.ulSPDContainerId,
			pSecInfo->outSAInfo.ulSAMagicNumber);
		ASFIPSEC_DBGL2("Out SA Index =%d, Magic Number = %d",
			*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_INDEX]),
			*(unsigned int *) &(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX]));

		ASFIPSEC_DBGL2("Before secfp-submit:"
			"skb= 0x%x, skb->data= 0x%x, skb->dev= 0x%x\n",
			(int)skb, (int)skb->data, (int)skb->dev);
#ifndef ASF_QMAN_IPSEC
		/* Keeping REF_INDEX as 2, one for the h/w
		and one for the core */
		skb->cb[SECFP_REF_INDEX] = 2;

		desc = secfp_desc_alloc();
		if (!desc) {
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
			ASFIPSEC_WARN("desc allocation failure");
			goto drop_skb_list;
		}
		if ((secout_sg_flag & SECFP_SCATTER_GATHER)
			== SECFP_SCATTER_GATHER)
			pSA->prepareOutDescriptorWithFrags(skb, pSA,
						desc, 0);
		else
			pSA->prepareOutDescriptor(skb, pSA, desc, 0);
#endif /*ASF_QMAN_IPSEC*/

		ASFIPSEC_FPRINT("Pkt Pre Processing len=%d", skb->len);
		ASFIPSEC_HEXDUMP(skb->data, skb->len);

		(*pSA->finishOutPktFnPtr)(skb, pSA, pContainer,
				pOuterIpHdr, ulVSGId,
			pSecInfo->outContainerInfo.ulSPDContainerId);

		ASFIPSEC_FPRINT("Pkt Post Processing %d", skb->len);
		ASFIPSEC_HEXDUMP(skb->data, skb->len);

		if (skb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
			ASFIPSEC_DPERR("Packet Action is Drop");
			SECFP_DESC_FREE(desc);
			skb->data_len = 0;
			goto drop_skb_list;
		}

		ASFIPSEC_DEBUG("OUT-submit to SEC");
		pIPSecPPGlobalStats->ulTotOutRecvPktsSecApply++;
#ifndef CONFIG_ASF_SEC4x
		update_chan_out(pSA);
		if (likely(pSA->SAParams.ucProtocol == SECFP_PROTO_ESP)) {
			iRetVal = talitos_submit(pdev, pSA->chan, desc,
				pSA->outComplete, (void *)skb);
		} else {
			void *desc1;
			char *offset = (char *) desc;
			desc1 = (char *)offset + sizeof(struct ipsec_ah_edesc);

			iRetVal = talitos_submit(pdev, pSA->chan, (struct talitos_desc *)desc1,
					pSA->outComplete, (void *)skb);
		}
		if (iRetVal == -EAGAIN)
#elif defined(ASF_QMAN_IPSEC)
		if (secfp_qman_out_submit(pSA, (void *) skb))
#else
		if (caam_jr_enqueue(pSA->ctx.jrdev,
			((struct aead_edesc *)desc)->hw_desc,
			pSA->outComplete, (void *)skb))
#endif
		{
#ifdef ASFIPSEC_LOG_MSG
			ASFIPSEC_DEBUG("Outbound Submission to"\
					"SEC failed ");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				"Cipher Operation Failed-5");
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			AsfLogInfo.u.IPSecInfo.ulSPDContainerIndex =
				pSecInfo->outContainerInfo.ulSPDContainerId;
			AsfLogInfo.ulVSGId = ulVSGId;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfoOut(&AsfLogInfo, pSA);
#endif
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);

			skb->data_len = 0;
			SECFP_DESC_FREE(desc);
			goto drop_skb_list;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef CONFIG_ASF_SEC3x
		skb->cb[SECFP_REF_INDEX]--;
		if (pSA->option[1] != SECFP_NONE) {
			ASFIPSEC_DEBUG("2nd Iteration");
			/* 2nd iteration required ICV */
			skb->cb[SECFP_REF_INDEX]++;

			desc = secfp_desc_alloc();
			if (!desc) {
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
				ASFIPSEC_WARN("desc allocation failure");
				if (skb->cb[SECFP_REF_INDEX] != 0) {
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				} else {

					/* So, we can release it */
					skb->data_len = 0;
					goto drop_skb_list;
				}
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
			if ((secout_sg_flag & SECFP_SCATTER_GATHER)
					== SECFP_SCATTER_GATHER)
				secfp_prepareOutDescriptorWithFrags(skb,
					pSA, desc, 1);
			else
				secfp_prepareOutDescriptor(skb, pSA, desc, 1);

			if (likely(pSA->SAParams.ucProtocol == SECFP_PROTO_ESP)) {
				iRetVal = talitos_submit(pdev, pSA->chan, desc,
					pSA->outComplete, (void *)skb);
			} else {
				char *desc1 = (struct ipsec_ah_edesc *)desc;
				desc1 += offsetof(struct ipsec_ah_edesc, hw_desc);
				iRetVal = talitos_submit(pdev, pSA->chan, (struct talitos_desc *)desc1,
						pSA->outComplete, (void *)skb);
			}
			if (iRetVal == -EAGAIN) {
				ASFIPSEC_WARN("Outbound Submission to"\
						"SEC failed ");
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
				/* We cannot free the skb now, as it is submitted to h/w */
				skb->cb[SECFP_REF_INDEX] -= 2; /* Removed for the core and current submission */
				if (skb->cb[SECFP_REF_INDEX] != 0) {
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
					SECFP_DESC_FREE(desc);
				} else { /* CB already happened, and returned */

					/* So, we can release it */
					skb->data_len = 0;
					SECFP_DESC_FREE(desc);
					goto drop_skb_list;
				}
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
		}
		if (skb->cb[SECFP_REF_INDEX] == 0) {
			/* Some error happened in the c/b. Free the skb */
			ASFIPSEC_DEBUG("O/b Proc Completed REF_CNT == 0, freeing the skb");
			if (desc)
				SECFP_DESC_FREE(desc);
			skb->data_len = 0;
			goto drop_skb_list;
		}
#endif /*CONFIG_ASF_SEC3x */
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	}
	rcu_read_unlock();
	return 0;

no_sa:
	ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT24]);
	if (ASFIPSecCbFn.pFnNoOutSA) {
		ASF_uchar8_t bSPDContainerPresent;
		ASFBuffer_t Buffer;
		/* Homogenous buffer */
		rcu_read_unlock();
		/* TBD - No need for this check, once the frag_list of asf is same as linux frag_list*/
		if (skb_shinfo(skb1)->frag_list) {
			if (asfReasmLinearize(&skb1, iph->tot_len,
				VPN_TOT_OVHD, VPN_HDROOM)) {
				ASFIPSEC_DEBUG("asflLinearize failed");
				ASFSkbFree(skb1);
				return 0;
			}
			skb_reset_network_header(skb1);
		}
		Buffer.nativeBuffer = skb1;
		if (pContainer)
			bSPDContainerPresent = 1;
		else
			bSPDContainerPresent = 0;
#ifdef CONFIG_DPA
		asf_dec_skb_buf_count(skb);
#endif
		ASFIPSecCbFn.pFnNoOutSA(ulVSGId , NULL, Buffer,
				secfp_SkbFree, skb1, bSPDContainerPresent,
				bRevalidate);
		return 0;
	}
	rcu_read_unlock();
	return 1;
l2blob_missing:
	{
		ASF_IPSecTunEndAddr_t TunAddress;
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT25]);

		TunAddress.IP_Version = 4;
		TunAddress.dstIP.bIPv4OrIPv6 = 0;
		TunAddress.srcIP.bIPv4OrIPv6 = 0;
		TunAddress.dstIP.ipv4addr =
		pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
		TunAddress.srcIP.ipv4addr =
		pSA->SAParams.tunnelInfo.addr.iphv4.saddr;

		if (ASFIPSecCbFn.pFnRefreshL2Blob)
			ASFIPSecCbFn.pFnRefreshL2Blob(ulVSGId,
				pSecInfo->outContainerInfo.ulTunnelId,
				pSecInfo->outContainerInfo.ulSPDContainerId,
				pSecInfo->outContainerInfo.ulSPDMagicNumber,
				&TunAddress,
				pSA->SAParams.ulSPI, pSA->SAParams.ucProtocol);
	}


drop_skb_list:
	if (skb)
		ASFSkbFree(skb);
	while (pNextSkb) {
		skb = pNextSkb;
		pNextSkb = skb->next;
		skb->next = NULL;
		ASFSkbFree(skb);
	}

	rcu_read_unlock();
	return 0;
}

inline int secfp_try_fastPathOut(unsigned int ulVSGId,
		struct sk_buff *skb,
		ASFFFPIpsecInfo_t *pSecInfo) {
#ifdef ASF_IPV6_FP_SUPPORT
	struct iphdr *iph = ip_hdr(skb);
	if (iph->version == 6)
		return secfp_try_fastPathOutv6(ulVSGId, skb, pSecInfo);
	else
#endif
		return secfp_try_fastPathOutv4(ulVSGId, skb, pSecInfo);
}

static inline void secfp_unmap_descs(struct sk_buff *skb)
{
	struct sk_buff *pTempSkb;

	for (pTempSkb = skb_shinfo(skb)->frag_list; pTempSkb != NULL;
		pTempSkb = pTempSkb->next) {
		SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t)*((unsigned int *)
				&(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX])),
				skb_end_pointer(pTempSkb) - pTempSkb->head);
	}
#ifdef CONFIG_ASF_SEC3x
	secfp_dma_unmap_sglist(skb);
#endif
}

/*
 * Called from talitos driver flush_channel() when descriptor is done by SEC. In the
 * two case submission, where two descriptors have to be submitted for same packet,
 * e.g. AES_XCBC with 3DES, the first callback should do nothing. We just decrement
 * the REF_INDEX. If there is an error, we note the action to be taken later
 * Error is noted. If no error IV data is updated and packet submitted to ethernet
 * driver
 */
#ifndef CONFIG_ASF_SEC4x
void secfp_outComplete(struct device *dev, struct talitos_desc *desc,
		void *context, int error)
#else
void secfp_outComplete(struct device *dev, u32 *pdesc,
		u32 error, void *context)
#endif
{
	struct sk_buff *skb = (struct sk_buff *) context;
	struct sk_buff *pOutSkb = skb, *pTempSkb;
	outSA_t *pSA;
	struct iphdr *iph;
#ifdef CONFIG_DPA
	struct dpa_priv_s       *priv;
	struct dpa_bp           *dpa_bp;
#endif
#ifdef ASF_SECFP_PROTO_OFFLOAD
#ifdef ASF_IPV6_FP_SUPPORT
	struct ipv6hdr *ipv6h;
#endif
	int tot_len;
#endif
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
#ifndef ASF_QOS
	struct netdev_queue *txq;
	struct net_device       *netdev;
#endif
#if defined(CONFIG_ASF_SEC4x) && !defined(ASF_QMAN_IPSEC)
	struct aead_edesc *desc;
	desc = (struct aead_edesc *)((char *)pdesc -
			offsetof(struct aead_edesc, hw_desc));
#endif
#ifdef CONFIG_DPA
	if (skb->cb[BUF_INDOMAIN_INDEX]) {
		if (skb->dev) {
			priv = netdev_priv(skb->dev);
			dpa_bp = priv->dpa_bp;
		}
	}
#endif
	pIPSecPPGlobalStats = asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
	pIPSecPPGlobalStats->ulTotOutPktsSecAppled++;

	ASFIPSEC_DEBUG(" Entry");

	SECFP_DESC_FREE(desc);
#if (ASF_FEATURE_OPTION > ASF_MINIMUM) && !defined(CONFIG_ASF_SEC4x)
	skb->cb[SECFP_REF_INDEX]--;
	if (skb->cb[SECFP_REF_INDEX]) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
		/* Waiting for another iteration to complete */
		if (error)
			skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		return;
	}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t)(*(unsigned int *)
			&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])),
			skb_end_pointer(skb) - skb->head);

	if (unlikely(error || skb->cb[SECFP_ACTION_INDEX] == SECFP_DROP)) {
#ifdef CONFIG_ASF_SEC4x
		if (error) {
#ifdef ASF_IPSEC_DEBUG
			ASFIPSEC_DPERR("%08x", error);
			if (net_ratelimit())
				caam_jr_strstatus(dev, error);
#endif
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
			if ((error & SEQ_NO_OVERFLOW) == SEQ_NO_OVERFLOW) {
				ASF_IPAddr_t DestAddr;
				ASF_uint32_t ulVSGId =
					skb->cb[SECFP_VSG_ID_INDEX];
				ASFIPSEC_PRINT("Going for re-keying");
				pSA = (outSA_t *)ptrIArray_getData(
					&secFP_OutSATable,
					*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]));
				if (pSA) {
					DestAddr.bIPv4OrIPv6 =
						pSA->SAParams.tunnelInfo.bIPv4OrIPv6;
#ifdef ASF_IPV6_FP_SUPPORT
					if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
						memcpy(DestAddr.ipv6addr,
							pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
					else
#endif
					DestAddr.ipv4addr =
						pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
					if (atomic_read(&pSA->SeqOverflow) == 0) {
						ASFIPSecCbFn.pFnSeqNoOverFlow(ulVSGId,
							pSA->ulTunnelId,
							pSA->SAParams.ulSPI,
							pSA->SAParams.ucProtocol,
							DestAddr);
					/*If Anti-Replay On-Seq Number reset will not happen.
					So, Avoid giving multiple triggers to the Control Plane */
					if (pSA->SAParams.bDoAntiReplayCheck)
						atomic_inc(&pSA->SeqOverflow);
					}
				}
			}
		}
		ASFIPSEC_DPERR("error = %x DROP PKT ", error);
#endif
		skb->data_len = 0;
		ASFSkbFree(skb);
		return;
	}

	if (skb_shinfo(skb)->nr_frags == 0)
		skb->data_len = 0; /* No req for this field anymore */
#ifndef ASF_SECFP_PROTO_OFFLOAD
	ASFIPSEC_DEBUG("skb->prev =%x skb->len =%d",
			skb->prev, skb->len);
	if (skb->prev) {
		/* Put the prev pointer in the frag list and release frag list
			some dirty work
		*/
		skb_shinfo(skb)->frag_list = skb->prev;
		skb->len -= skb->prev->len;
		skb->prev = NULL;
	}
#endif
	iph = (struct iphdr *) skb->data;
#ifdef ASF_SECFP_PROTO_OFFLOAD
	if ((iph->version == 4) && (iph->protocol == IPPROTO_UDP)) {
		struct udphdr *uh = (struct udphdr *) ((u32 *) iph + iph->ihl);
			uh->len = iph->tot_len - (iph->ihl * 4);
	}
#endif
	ASFIPSEC_FPRINT("Sending packet to:"
		"skb = 0x%x, skb->data = 0x%x, skb->dev = 0x%x, skb->len = %d*",
		skb, skb->data, skb->dev, skb->len);
	if (skb_shinfo(skb)->nr_frags) {
		skb_frag_t *frag;
		unsigned char *charp;
		unsigned int total_frags;
		total_frags = skb_shinfo(skb)->nr_frags;
		frag = &(skb_shinfo(skb)->frags[total_frags - 1]);
		charp = (u8 *)(page_address((const struct page *)frag->page.p) +
					frag->page_offset);
		ASFIPSEC_HEXDUMP(skb->data, skb_headlen(skb));
		ASFIPSEC_HEXDUMP(charp, frag->size);
	} else {
		skb->data_len = 0; /* No req for this field anymore */
		ASFIPSEC_HEXDUMP(skb->data, skb->len);
#ifdef ASF_SECFP_PROTO_OFFLOAD
		skb_set_tail_pointer(skb, skb->len);
#endif
	}
#ifdef CONFIG_ASF_SEC4x
#ifdef ASF_SECFP_PROTO_OFFLOAD
	/*In case of IPv6-in-IPv4 tunnel*/
	if (*(unsigned char *) &(skb->cb[SECFP_IN_OUT_HDR_DIFF]) &
			SECFP_IPv6_IN_IPv4) {
		struct iphdr *iph = (struct iphdr *) skb->data;
		iph->tos = *(unsigned char *) &(skb->cb[SECFP_TOS_TC_INDEX]);
		ip_send_check(iph);
	} else if (*(unsigned char *) &(skb->cb[SECFP_IN_OUT_HDR_DIFF]) &
			SECFP_IPv4_IN_IPv6) {
		/*In case of IPv4-in-IPv6 tunnel*/
		struct ipv6hdr *ipv6h = (struct ipv6hdr *) skb->data;
		ipv6h->priority = (*(unsigned char *) &(skb->cb[SECFP_TOS_TC_INDEX])
					& 0xf0) >> 4;
		ipv6h->flow_lbl[0] &= 0x0f;
		ipv6h->flow_lbl[0] |= (*(unsigned char *) &(skb->cb[SECFP_TOS_TC_INDEX])
				& 0x0f) << 4;
	}
#endif /*ASF_SECFP_PROTO_OFFLOAD*/
#endif
	if (!skb->cb[SECFP_OUTB_FRAG_REQD]) {
#ifdef ASF_SECFP_PROTO_OFFLOAD
		skb->data -= skb->cb[SECFP_OUTB_L2_OVERHEAD];
		skb->len += skb->cb[SECFP_OUTB_L2_OVERHEAD];

		ASFIPSEC_DEBUG("\n L2blob length =%d, PPPoe =%d",
			skb->cb[SECFP_OUTB_L2_OVERHEAD],
			skb->cb[SECFP_OUTB_L2_WITH_PPPOE]);

		if (unlikely(skb->cb[SECFP_OUTB_L2_WITH_PPPOE])) {
#ifdef ASF_IPV6_FP_SUPPORT
			if (iph->version == 6) {
				ipv6h = (struct ipv6hdr *) iph;
				tot_len = ipv6h->payload_len + SECFP_IPV6_HDR_LEN;
			} else
#endif
				tot_len = iph->tot_len;
			/* PPPoE packet:
			Set Payload length in PPPoE header */
			*((short *)&(skb->data[skb->cb[SECFP_OUTB_L2_OVERHEAD]-4]))
					= htons(ntohs(tot_len) + 2);
		}
#endif /*ASF_SECFP_PROTO_OFFLOAD*/
		/* FASTROUTE is required for selective recycling*/
		skb->pkt_type = PACKET_FASTROUTE;
#ifdef ASF_IPV6_FP_SUPPORT
		if (iph->version == 6) {
			struct ipv6_redef *hdr;

			hdr = (struct ipv6_redef *) iph;
			asf_set_queue_mapping(skb, hdr->tc);
		} else
#endif
			asf_set_queue_mapping(skb, iph->tos);
#ifdef CONFIG_DPA
		if (skb->cb[BUF_INDOMAIN_INDEX])
			PER_CPU_BP_COUNT(dpa_bp)--;
#endif
#ifdef ASF_QOS
		pSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
			*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]));
		if (!pSA) {
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.
					IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT24]);
			ASFIPSEC_DEBUG("OutSA info not available");
			skb->data_len = 0;
			ASFSkbFree(skb);
			return;
		}

		/* Enqueue the packet in Linux QoS framework */
		asf_qos_handling(skb, &pSA->tc_filter_res);
#else
		txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
		netdev = skb->dev;
		if (asfDevHardXmit(skb->dev, skb) != 0) {
#ifndef ASF_QMAN_IPSEC
			/*TODO: DPAA driver always consumes skb */
			ASFSkbFree(skb);
#endif
			return;
		} else
			netdev->trans_start = txq->trans_start = jiffies;
#endif
		pIPSecPPGlobalStats->ulTotOutProcPkts++;
	} else {
		ASFIPSEC_DEBUG("Need to call fragmentation module ");
		/* Need to do dma unmapping for rest of the fragments */
		if (skb_shinfo(skb)->frag_list)
			secfp_unmap_descs(skb);

		rcu_read_lock();
		ASFIPSEC_DEBUG("Out SA Index =%d, Magic Number = %d",
			*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]),
			*(unsigned int *)&(skb->cb[SECFP_OUT_SA_MAGIC_NUM]));
		if (likely(ptrIArray_getMagicNum(&secFP_OutSATable,
			*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]))
			== *(unsigned int *)&(skb->cb[SECFP_SAD_SAI_MAGIC_INDEX]))) {
			ASFIPSEC_DEBUG("Magic number matched\n");

			pSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
				*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]));
			if (likely(pSA && pSA->bl2blob)) {

				ASFIPSEC_FPRINT("Sending packet to gfar:"
					"skb = 0x%x, skb->data = 0x%x,"
					"skb->dev = 0x%x, skb->len = %d*****",
					skb, skb->data, skb->dev, skb->len);
				ASFIPSEC_FPRINT("Printing SEC Header ");
				ASFIPSEC_HEXDUMP(skb->data, skb->len);

#ifndef ASF_SECFP_PROTO_OFFLOAD
				skb->data += pSA->ulL2BlobLen;
				skb->len -= pSA->ulL2BlobLen;
#endif
				iph = ip_hdr(skb);
#ifdef ASF_IPV6_FP_SUPPORT
				if (iph->version == 4) {
#endif
					if (unlikely(asfIpv4Fragment(skb,
						pSA->odev->mtu,
						pSA->ulL2BlobLen,
						ASF_TRUE, pSA->odev, &pOutSkb))) {
						ASFIPSEC_DEBUG("Error in Fragmentation");
						rcu_read_unlock();
						return;
					}
#ifdef ASF_IPV6_FP_SUPPORT
				} else {
					if (unlikely(asfIpv6Fragment(skb,
								pSA->odev->mtu,
								pSA->odev,
								&pOutSkb))) {
						ASFIPSEC_DEBUG("Error in Fragmentation");
						rcu_read_unlock();
						return;
					}
				}
#endif
				for (; pOutSkb != NULL; pOutSkb = pTempSkb) {
					pTempSkb = pOutSkb->next;
					iph = ip_hdr(pOutSkb);
					pOutSkb->next = NULL;

					pOutSkb->pkt_type = PACKET_FASTROUTE;
					pOutSkb->data -= pSA->ulL2BlobLen;
					pOutSkb->len += pSA->ulL2BlobLen;

					skb_set_tail_pointer(pOutSkb, pOutSkb->len);
					pOutSkb->dev = pSA->odev;
#ifdef ASF_IPV6_FP_SUPPORT
					if (iph->version == 6) {
						struct ipv6_redef *hdr;

						hdr = (struct ipv6_redef *) iph;
						asf_set_queue_mapping(pOutSkb,
								hdr->tc);
					} else
#endif
						asf_set_queue_mapping(pOutSkb,
								iph->tos);
					ASFIPSEC_FPRINT("Next skb = 0x%x", pTempSkb);
					ASFIPSEC_FPRINT("Frag : skb = 0x%x, skb->data = 0x%x, skb->dev = 0x%x, skb->len = %d*****",
						pOutSkb, pOutSkb->data, pOutSkb->dev, pOutSkb->len);
					ASFIPSEC_HEXDUMP(pOutSkb->data,
							pOutSkb->len);

					if (pSA->bVLAN)
						pOutSkb->vlan_tci = pSA->tx_vlan_id;
					else
						pOutSkb->vlan_tci = 0;

					asfCopyWords((unsigned int *)pOutSkb->data,
						(unsigned int *)pSA->l2blob, pSA->ulL2BlobLen);
					if (pSA->bPPPoE) {
						/* PPPoE packet.. Set Payload length in PPPoE header */
						*((short *)&(pOutSkb->data[pSA->ulL2BlobLen-4])) = htons(ntohs(iph->tot_len) + 2);
					}
					ASFIPSEC_DEBUG("skb->network_header = 0x%x, skb->transport_header = 0x%x\r\n",
						skb_network_header(pOutSkb), skb_transport_header(pOutSkb));

					ASFIPSEC_FPRINT("skb->network_header = 0x%x, skb->transport_header = 0x%x",
						skb_network_header(pOutSkb), skb_transport_header(pOutSkb));
					ASFIPSEC_FPRINT("Transmitting buffer = 0x%x dev->index = %d", pOutSkb, pOutSkb->dev->ifindex);

					ASFIPSEC_FPRINT("Fragment offset field = 0x%x", iph->frag_off);

					pIPSecPPGlobalStats->ulTotOutProcPkts++;
#ifdef CONFIG_DPA
					if (skb->cb[BUF_INDOMAIN_INDEX])
						PER_CPU_BP_COUNT(dpa_bp)--;
#endif
#ifdef ASF_QOS
					/* Enqueue the packet For QoS */
					asf_qos_handling(pOutSkb, &pSA->tc_filter_res);
#else
					txq = netdev_get_tx_queue(pOutSkb->dev, pOutSkb->queue_mapping);
					netdev = pOutSkb->dev;
					if (asfDevHardXmit(pOutSkb->dev, pOutSkb) != 0) {
						ASFIPSEC_WARN("Error in transmit: Should not happen");
#ifndef ASF_QMAN_IPSEC
						ASFSkbFree(pOutSkb);
#endif
					} else
						netdev->trans_start = txq->trans_start = jiffies;
#endif
				}
				rcu_read_unlock();
				return;
			} else {
				ASFIPSEC_WARN("SA not Found");
				ASFSkbFree(skb);
				rcu_read_unlock();
				return;
			}
		} else {
			ASFIPSEC_WARN("Magic Number mismatch");
			ASFSkbFree(skb);
			rcu_read_unlock();
			return;
		}
	}

	ASFIPSEC_TRACE;
}

#ifndef ASF_SECFP_PROTO_OFFLOAD
/*
 * This function does sequence number tracking for Anti replay
 * window check. Called post SEC inbound processing. Most the
 * calculated values such as co-ef/remainder etc. are carried
 * over from the calculation done prior to SEC inbound processing
 * for anti-replay window check. This function just updates the
 * bitmap based on previously calculated values.
 */
void secfp_updateBitMap(inSA_t *pSA, struct sk_buff *skb)
{
	unsigned int usSize = pSA->SAParams.AntiReplayWin >> 5;
	unsigned int ulDiff;
	int uiCount = 0;
	unsigned int ucCo_Efficient = 0, ucRemainder = 0;

	ASFIPSEC_DEBUG("updateBitMap: parameters: SeqNum in packet=0x%x,"\
		"Last seen sequence number = 0x%x, AntiReplayWin = 0x%x",
		*(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]),
		pSA->ulLastSeqNum, pSA->SAParams.AntiReplayWin);

	if (!pSA->SAParams.bUseExtendedSequenceNumber) {
		if (*(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]) <= pSA->ulLastSeqNum) {
			ulDiff = pSA->ulLastSeqNum - *(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]);
			if (ulDiff >= pSA->SAParams.AntiReplayWin) {
				ASFIPSEC_DEBUG("Ignoring a corner case condition, where the Seq Number Index has already removed from the bitmap");
				return;
			}
		}
	}

	ASFIPSEC_DEBUG("Bitmap update variables: Index = %d, CO-eff = %d ,"\
		"ucSize = %d, remainder = %d ",
		skb->cb[SECFP_SABITMAP_INFO_INDEX],
		skb->cb[SECFP_SABITMAP_COEF_INDEX], usSize,
		skb->cb[SECFP_SABITMAP_REMAIN_INDEX]);

	switch (skb->cb[SECFP_SABITMAP_INFO_INDEX]) {
	case 1:
		pSA->pWinBitMap[(usSize - 1) - skb->cb[
			SECFP_SABITMAP_COEF_INDEX]] |=
		((u32)1 << skb->cb[SECFP_SABITMAP_REMAIN_INDEX]);
		break;
	case 2:
		IGW_SAD_SET_BIT_IN_WINDOW(pSA,
			*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]),
			usSize, uiCount, ucCo_Efficient, ucRemainder);
		pSA->ulLastSeqNum =
			*(unsigned int *)&(skb->cb[SECFP_SEQNUM_INDEX]);
		break;
	case 3:
		IGW_SAD_SET_BIT_IN_WINDOW(pSA,
			*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]),
			usSize, uiCount, ucCo_Efficient, ucRemainder);
		pSA->ulHOSeqNum++;
		break;
	default:
		ASFIPSEC_WARN("Error in updating SA Bitmap ");
		break;
	}

	ASFIPSEC_DEBUG("Bitmap update variables: pSA->pWinBitMap = 0x%8x",
		pSA->pWinBitMap[0]);
}
#endif


/*
 * This code needs to be filled for Gateway adaptation. i.e. When the remote gateway
 * changes, the gateway address has to be udpated in the the outbound SAs.
 * For this purpose the Out SPD container index is maintained along with the
 * In SA
 */
void secfp_adaptPeerGW(unsigned int ulVSGId, inSA_t *pSA,
		ASF_IPAddr_t saddr, unsigned short usSourcePort)
{
	outSA_t *pOutSA = NULL;
	SPDOutContainer_t *pOutContainer;
	SPDOutSALinkNode_t *pOutSALinkNode;
	ASF_IPAddr_t	OldDstAddr;
	unsigned short	usNewSourcePort = 0, usOldSourcePort = 0;
	int ii;

#ifdef ASF_IPV6_FP_SUPPORT
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		OldDstAddr.bIPv4OrIPv6 = 1;
		memcpy(OldDstAddr.ipv6addr,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
	} else {
#endif
		OldDstAddr.bIPv4OrIPv6 = 0;
		OldDstAddr.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif
	if (pSA->SAParams.bDoUDPEncapsulationForNATTraversal) {
		usOldSourcePort = pSA->SAParams.IPsecNatInfo.usSrcPort;
		pSA->SAParams.IPsecNatInfo.usSrcPort = usSourcePort;
		usNewSourcePort = pSA->SAParams.IPsecNatInfo.usSrcPort;
	}

	if (pSA->ulSPDOutContainerMagicNumber == ptrIArray_getMagicNum(
					&secfp_OutDB,
					pSA->ulSPDOutContainerIndex)) {
		pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(
					&(secfp_OutDB),
					pSA->ulSPDOutContainerIndex));
		if (pOutContainer) {
			if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
				for (ii = 0; ii < SECFP_MAX_DSCP_SA; ii++) {
					pOutSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
							pOutContainer->SAHolder.ulSAIndex[ii]);
					/* NEEDS */
				}
			} else {
				pOutSALinkNode = secfp_findOutSALinkNode(
							pOutContainer,
							OldDstAddr,
							pSA->SAParams.ucProtocol
							, pSA->ulOutSPI);
				if (pOutSALinkNode) {
					pOutSA = (outSA_t *)ptrIArray_getData(
						&secFP_OutSATable,
						pOutSALinkNode->ulSAIndex);
				}
			}
			if (pOutSA && ASFIPSecCbFn.pFnPeerChange) {
#ifdef ASF_IPV6_FP_SUPPORT
				if (saddr.bIPv4OrIPv6) {
					pOutSA->ipHdrInfo.bIpVersion = 1;
					memcpy(pOutSA->ipHdrInfo.hdrdata.iphv6.daddr.s6_addr,
							saddr.ipv6addr, 16);
				} else {
#endif
					pOutSA->ipHdrInfo.bIpVersion = 0;
					pOutSA->ipHdrInfo.hdrdata.iphv4.daddr = saddr.ipv4addr;
#ifdef ASF_IPV6_FP_SUPPORT
				}
#endif
				pSA->SAParams.IPsecNatInfo.usDstPort = usSourcePort;
				ASFIPSecCbFn.pFnPeerChange(ulVSGId,
						pSA->SAParams.ulSPI,
						pSA->pSASPDMapNode->ulSPDInContainerIndex,
						pSA->SAParams.ucProtocol,
						OldDstAddr, saddr,
						usOldSourcePort, usNewSourcePort);
			} else {
				GlobalErrors.ulOutSANotFound++;
				ASFIPSEC_DEBUG("IP Address adaptation: pOutSA not found");
			}
		} else {
			GlobalErrors.ulSPDOutContainerNotFound++;
			ASFIPSEC_DEBUG("SPD Out Container not found for Address adaptation");
		}
	} else {
		ASFIPSEC_DEBUG("Address adaptation: IP Address mismatch");
	}
}

/*
 * Post inbound processing, in some cases, we need to do ICV check
 * This function does that and updates the packet length
 * For AES-XCBC-HMAC, currently h/w ICV comparison is failing, so
 * doing this through memcmp
 * In the 2 descriptor submission case, appropriate option index has
 * to be updated, so that check is not done again when the 2nd
 * iteration completes
 */
static inline unsigned int secfp_inHandleICVCheck(void *dsc, struct sk_buff *skb)
{
#ifdef CONFIG_ASF_SEC4x
	if (skb_shinfo(skb)->nr_frags) {
		int total_frag;
		skb_frag_t *frag;
		total_frag = skb_shinfo(skb)->nr_frags;
		frag = &skb_shinfo(skb)->frags[total_frag - 1];
		if (likely(frag->size > skb->cb[SECFP_ICV_LENGTH])) {
			frag->size -= skb->cb[SECFP_ICV_LENGTH];
			skb->data_len -= skb->cb[SECFP_ICV_LENGTH];
			skb->len -= skb->cb[SECFP_ICV_LENGTH];
		} else
			__pskb_trim(skb, skb->cb[SECFP_ICV_LENGTH]);
		ASFIPSEC_PRINT("\nskb->data_len %d", skb->data_len);
	} else
		skb->len -= skb->cb[SECFP_ICV_LENGTH];

#else
	return secfp_inHandleICVCheck3x(dsc, skb);
#endif
	return 0;
}

/* In complete for v4 gateways */
/* This does ICV verification completion, updates ICV length,
 * compares padding in the case of ESP-non-NULL, verifies
 * IPv4 header as next expected header. It should also
 * inner header checksum verification. Currently stubbed out
 * It updates the sequence number in the sequence number
 * bitmap. If peer gateway adaption is enabled, records changes
 * outbound SAs if any. If SA selector verification is enabled
 * packet selectors are verified with SA selectors. If packet
 * survives all this, it is given to firewall fast path. If firewall
 * is not able to find the flow, the packet is given to the stack
 * SPI verification does not happen here. Firewall calls
 * checkInPacket ( ) function to do SPI verification. The SPD
 * in container index is cached in firewall flow
 */

#ifdef ASF_IPSEC_DEBUG
unsigned int ulNumIter[NR_CPUS];
#endif

static inline int secfp_inCompleteCheckAndTrimPkt(
			struct sk_buff *pHeadSkb,
			struct sk_buff *pTailSkb,
			unsigned int *pTotLen,
			unsigned char *pNextProto,
			ASF_IPAddr_t *daddr)
{
	inSA_t *pSA = NULL;
	int total_frag = 0;
	skb_frag_t *last_frag = NULL;
	unsigned char *charp = NULL;
#ifdef ASF_SECFP_PROTO_OFFLOAD
	unsigned int nhoffset = 0;
	struct sk_buff *skb1 = NULL;
	struct iphdr *iph = (struct iphdr *)*(uintptr_t *)
				&(pHeadSkb->cb[SECFP_IPHDR_INDEX]);
#endif /*ASF_SECFP_PROTO_OFFLOAD*/
	struct sk_buff *pTailPrevSkb;
	struct iphdr *inneriph = (struct iphdr *)(pHeadSkb->data);
	unsigned int ulStripLen;
#ifdef ASF_IPV6_FP_SUPPORT
	if (inneriph->version == 6) {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *) inneriph;
		ulStripLen = *pTotLen - (ipv6h->payload_len + SECFP_IPV6_HDR_LEN);
	} else
#endif
		ulStripLen = *pTotLen - inneriph->tot_len;


	ASFIPSEC_FPRINT("pHeadSkb->data = 0x%x,"
		"pHeadSkb->data - 20 - 16 =0x%x, pHeadSkb->len = %d",
		pHeadSkb->data, pHeadSkb->data - 20 - 16, *pTotLen);
	ASFIPSEC_HEXDUMP(pHeadSkb->data,
		((pHeadSkb->len + 20 + 16 + 20) < 256 ?
		(pHeadSkb->len + 20 + 16 + 20) : 256));

	/* Look at the Next protocol field */
	if (skb_shinfo(pHeadSkb)->nr_frags) {
		total_frag = skb_shinfo(pTailSkb)->nr_frags;
		last_frag = &skb_shinfo(pTailSkb)->frags[total_frag - 1];
		charp = (void *)page_address((const struct page *)last_frag->page.p)
				+ last_frag->page_offset;
#ifndef ASF_SECFP_PROTO_OFFLOAD
		*pNextProto = charp[last_frag->size - 1];
#else
		if (last_frag->size >= pHeadSkb->cb[SECFP_ICV_LENGTH] + 1) {
			*pNextProto = charp[last_frag->size -
					pHeadSkb->cb[SECFP_ICV_LENGTH] - 1];
		} else {
			unsigned int last_frag_size = last_frag->size;
			if (total_frag == 1) {
#ifdef ASF_IPV6_FP_SUPPORT
			if (iph->version == 6) {
				struct ipv6hdr *ipv6h = (struct ipv6hdr *) iph;
				*pNextProto = *((u8 *)iph + ipv6h->payload_len
					+ SECFP_IPV6_HDR_LEN - pHeadSkb->cb[SECFP_ICV_LENGTH] - 1);
			} else
#endif
				*pNextProto = *((u8 *)iph + iph->tot_len
						- pHeadSkb->cb[SECFP_ICV_LENGTH] - 1);
			} else {
				skb_frag_t *frag = &skb_shinfo(pTailSkb)->frags
							[total_frag - 2];
				charp = (void *)page_address((const struct page *)frag->page.p)
					+ frag->page_offset;
				*pNextProto = charp[frag->size + last_frag_size
					- pHeadSkb->cb[SECFP_ICV_LENGTH] - 1];
			}
		}
#endif
		ASFIPSEC_PRINT("\n PROTO IS %d", *pNextProto);
	} else if (skb_shinfo(pHeadSkb)->frag_list) {
#ifndef ASF_SECFP_PROTO_OFFLOAD
		*pNextProto = pTailSkb->data[pTailSkb->len - 1];
#else
		if (pTailSkb->len >= pHeadSkb->cb[SECFP_ICV_LENGTH] + 1) {
			*pNextProto = pTailSkb->data[pTailSkb->len - pHeadSkb->cb[SECFP_ICV_LENGTH] - 1];
		} else {
			nhoffset = *pTotLen - pHeadSkb->cb[SECFP_ICV_LENGTH] - 1;
			if (pHeadSkb->len >= nhoffset) {
				*pNextProto = *((u8 *)pHeadSkb->data + nhoffset);
			} else {
				nhoffset -= pHeadSkb->len;
				skb1 = skb_shinfo(pHeadSkb)->frag_list;
				while (skb1 && skb1->len < nhoffset) {
					nhoffset -= skb1->len;
					skb1 = skb1->next;
				}
				*pNextProto = *((u8 *)skb1->data + nhoffset);
			}
		}
#endif
		ASFIPSEC_PRINT("\n PROTO IS %d", *pNextProto);
	} else {
#ifdef ASF_SECFP_PROTO_OFFLOAD
#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6) {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *) iph;
		*pNextProto = *((u8 *)iph + ipv6h->payload_len
			+ SECFP_IPV6_HDR_LEN - pHeadSkb->cb[SECFP_ICV_LENGTH] - 1);
	} else
#endif
		*pNextProto = *((u8 *)iph + iph->tot_len
				- pHeadSkb->cb[SECFP_ICV_LENGTH] - 1);
#else
		*pNextProto = pTailSkb->data[pTailSkb->len - 1];
#endif
		ASFIPSEC_PRINT("\n PROTO IS %d", *(unsigned int *)pNextProto);
	}
	if ((*pNextProto != SECFP_PROTO_IP) && (*pNextProto != SECFP_PROTO_IPV6)) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT11]);
		rcu_read_lock();

		pSA = secfp_findInSA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
			SECFP_PROTO_ESP,
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
			*daddr,
			(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT11);
			pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();
		ASFIPSEC_PRINT(KERN_INFO "Decrypted Protocol != IPV4 or IPV6");
		return 1;
	}

	if (unlikely(*pTotLen <= ulStripLen)) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT12]);
		rcu_read_lock();
		pSA = secfp_findInSA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
			SECFP_PROTO_ESP,
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
			*daddr,
			(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
			pSA->ulPkts[smp_processor_id()]--;
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT12);
		}
		ASFIPSEC_WARN("Invalid Pad length");
		rcu_read_unlock();
		return 1;
	}

	if (!skb_shinfo(pHeadSkb)->frag_list) {
		pHeadSkb->len -= ulStripLen;
		*pTotLen -= ulStripLen;
	} else {
		if (pTailSkb->len > ulStripLen)
			pTailSkb->len -= ulStripLen;
		else if (skb_shinfo(pHeadSkb)->frag_list == pTailSkb) {
			pHeadSkb->len -= (ulStripLen - pTailSkb->len);
			ASFSkbFree(pTailSkb);
			skb_shinfo(pHeadSkb)->frag_list = NULL;
		} else {
			for (pTailPrevSkb = pHeadSkb,
				pTailSkb = skb_shinfo(pHeadSkb)->frag_list;
				pTailSkb->next != NULL;
				pTailPrevSkb = pTailSkb,
				pTailSkb = pTailSkb->next)
				;
			if (pTailSkb->len == ulStripLen) {
				pTailPrevSkb->next = NULL;
			} else {
				pTailPrevSkb->len -=
					(ulStripLen - pTailSkb->len);
				pTailPrevSkb->next = NULL;
			}
			ASFSkbFree(pTailSkb);
			pTailSkb = pTailPrevSkb;
		}
		*pTotLen -= ulStripLen;
	}
	return 0;
}

int secfp_inCompleteSAProcess(struct sk_buff **pSkb,
					ASFIPSecOpqueInfo_t *pIPSecOpaque,
					unsigned char ucProto,
					unsigned int *pulCommonInterfaceId) {
	ASFLogInfo_t AsfLogInfo;
	char aMsg[ASF_MAX_MESG_LEN + 1];
	unsigned int  fragCnt = 0;
	inSA_t *pSA;
	struct iphdr *inneriph;
	struct sk_buff *pHeadSkb;
	pHeadSkb = *pSkb;

	ASFIPSEC_DEBUG("inComplete: Doing SA related processing");
	ASFIPSEC_DEBUG("Saved values: ulSPI=%d, ipaddr_ptr=0x%x, ulHashVal=%d",
		*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
		*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]),
		*(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));

	rcu_read_lock();

	pSA = secfp_findInSA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
			ucProto,
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
			pIPSecOpaque->DestAddr,
			(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));

	if (unlikely(pSA == NULL)) {
		ASFIPSEC_DEBUG("SA Not found ");
		rcu_read_unlock();
		return 1;
	}
	pIPSecOpaque->ulInSPDContainerId = pSA->pSASPDMapNode->ulSPDInContainerIndex;
	pIPSecOpaque->ulInSPDMagicNumber = pSA->pSASPDMapNode->ulSPDInMagicNum;
	pIPSecOpaque->ucProtocol = pSA->SAParams.ucProtocol;
	*pulCommonInterfaceId = pSA->ucIfaceId ;
	ASFIPSEC_DEBUG();
#ifndef ASF_SECFP_PROTO_OFFLOAD
	if (pSA->SAParams.bDoAntiReplayCheck) {
		ASFIPSEC_DEBUG("Doing Anti Replay window check");
		if (pHeadSkb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT19]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT19);
				pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
				pSA->ulPkts[smp_processor_id()]--;
				rcu_read_unlock();
				return 1;
		} else {
			if (pSA->SAParams.bAuth)
				secfp_updateBitMap(pSA, pHeadSkb);
		}
	}
#endif
	inneriph = (struct iphdr *)(pHeadSkb->data);
	if (inneriph->version == 4 &&
			((inneriph->frag_off) & SECFP_MF_OFFSET_FLAG_NET_ORDER)) {
		skb_reset_network_header(pHeadSkb);
		pHeadSkb = asfIpv4Defrag((*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX])),
				pHeadSkb, NULL, NULL, NULL, &fragCnt);
		if (pHeadSkb == NULL) {
			ASFIPSEC_DEBUG(" ESP Packet absorbed by IP reasembly module");
			rcu_read_unlock();
			return 2; /*Pkt absorbed */
		}
		skb_reset_network_header(pHeadSkb);
		inneriph = (struct iphdr *)(pHeadSkb->data);
#ifndef ASF_SECFP_PROTO_OFFLOAD
		if (unlikely(pHeadSkb->len < ((inneriph->ihl*4) + SECFP_ESP_HDR_LEN))) {
			ASFIPSEC_WARN("ESP header length is invalid"
				"len = %d ", pHeadSkb->len);
			rcu_read_unlock();
			return 1;
		}
#endif /*ASF_SECFP_PROTO_OFFLOAD*/
		*pSkb = pHeadSkb;
	}

	if (pSA->SAParams.bVerifyInPktWithSASelectors) {
		unsigned short int *ptrhdrOffset;
		unsigned short sport, dport;
		ASF_IPAddr_t saddr;
		ASF_IPAddr_t tunnelsaddr;
		struct iphdr *iph;
		ASF_IPAddr_t seldaddr, selsaddr;
		SPDOutSALinkNode_t *pOutSALinkNode;
		SPDOutContainer_t *pOutContainer;
		outSA_t *pOutSA = NULL;
		unsigned short inneriphdrlen;
		unsigned int ulPathMTU, ii;
		char	*pIcmpHdr;
		unsigned char protocol;
		bool isFragmented = 0;

		iph = (struct iphdr *)*(uintptr_t *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]);


#ifdef ASF_IPV6_FP_SUPPORT
		/* outer IP stuff */
		if (iph->version == 6) {
			struct ipv6hdr *ipv6h;
			ipv6h = (struct ipv6hdr *) iph;
			saddr.bIPv4OrIPv6 = 1;
			memcpy(saddr.ipv6addr, ipv6h->saddr.s6_addr32, 16);
		} else {
#endif
			saddr.bIPv4OrIPv6 = 0;
			saddr.ipv4addr = iph->saddr;
#ifdef ASF_IPV6_FP_SUPPORT
		}
		if (inneriph->version == 6) {
			struct ipv6hdr *inneripv6h = (struct ipv6hdr *) inneriph;
			seldaddr.bIPv4OrIPv6 = 1;
			memcpy(seldaddr.ipv6addr, inneripv6h->daddr.s6_addr32, 16);
			selsaddr.bIPv4OrIPv6 = 1;
			memcpy(selsaddr.ipv6addr, inneripv6h->saddr.s6_addr32, 16);
			ptrhdrOffset = (unsigned short int *)(&(pHeadSkb->data[SECFP_IPV6_HDR_LEN]));
			protocol = inneripv6h->nexthdr;
			inneriphdrlen = SECFP_IPV6_HDR_LEN;
		} else
#endif
		{
			seldaddr.bIPv4OrIPv6 = 0;
			seldaddr.ipv4addr = inneriph->daddr;
			selsaddr.bIPv4OrIPv6 = 0;
			selsaddr.ipv4addr = inneriph->saddr;
			ptrhdrOffset = (unsigned short int *)(&(pHeadSkb->data[(inneriph->ihl*4)]));
			protocol = inneriph->protocol;
			isFragmented = (inneriph->frag_off) & SECFP_MF_OFFSET_FLAG_NET_ORDER;
			inneriphdrlen = (inneriph->ihl*4);
		}
		sport = *ptrhdrOffset;
		dport = *(ptrhdrOffset+1);

		if ((secfp_verifySASels(pSA, protocol, sport, dport, selsaddr, seldaddr)) == ASF_FALSE) {

			if (protocol == SECFP_IPPROTO_ICMP) {

				pIcmpHdr = ((char *)pHeadSkb->data) + inneriphdrlen;
				if ((pIcmpHdr[0] == ASF_ICMP_DEST_UNREACH) ||
					(pIcmpHdr[0] == ASF_ICMP_QUENCH) ||
					(pIcmpHdr[0] == ASF_ICMP_REDIRECT) ||
					(pIcmpHdr[0] == ASF_ICMP_TIME_EXCEED) ||
					(pIcmpHdr[0] == ASF_ICMP_PARAM_PROB)) {
					sport = pIcmpHdr[0];
					dport = pIcmpHdr[1];

					if ((secfp_verifySASels(pSA, protocol, dport, sport, seldaddr, selsaddr)) == ASF_TRUE) {
						if ((pIcmpHdr[0] == ASF_ICMP_DEST_UNREACH) &&
							(pIcmpHdr[1] == ASF_ICMP_CODE_FRAG_NEEDED)) {
							ulPathMTU = BUFGET32((unsigned char *)(pIcmpHdr + 4));
							ASFIPSEC_DEBUG("Path MTU = %d", ulPathMTU);

							if (pSA->ulSPDOutContainerMagicNumber == ptrIArray_getMagicNum(&secfp_OutDB,
															pSA->ulSPDOutContainerIndex)) {
								pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
															pSA->ulSPDOutContainerIndex));
								if (pOutContainer) {
									if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
										for (ii = 0; ii < SECFP_MAX_DSCP_SA; ii++) {
											pOutSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
																pOutContainer->SAHolder.ulSAIndex[ii]);
										}
									} else {
										tunnelsaddr.bIPv4OrIPv6 =
											pSA->SAParams.tunnelInfo.bIPv4OrIPv6;
#ifdef ASF_IPV6_FP_SUPPORT
										if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
											memcpy(tunnelsaddr.ipv6addr,
												pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
										else
#endif
											tunnelsaddr.ipv4addr =
												pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
										pOutSALinkNode = secfp_findOutSALinkNode(
										pOutContainer, tunnelsaddr,
										pSA->SAParams.ucProtocol, pSA->ulOutSPI);
										if (pOutSALinkNode) {
											pOutSA = (outSA_t *)ptrIArray_getData(
												&secFP_OutSATable,
												pOutSALinkNode->ulSAIndex);
										}
									}
									if (pOutSA)
										pOutSA->ulInnerPathMTU = ulPathMTU;
								}
							}
						}
					}
				}
			}

			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT20]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT20);
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "SA Selectos Verification Failed");
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID9;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfo(&AsfLogInfo, pSA);
			pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
			pSA->ulPkts[smp_processor_id()]--;
			rcu_read_unlock();
			return 1;
		}
		if ((!memcmp(&tunnelsaddr, &saddr, sizeof(ASF_IPAddr_t))) ||
			(pSA->SAParams.bDoUDPEncapsulationForNATTraversal &&
			(pSA->SAParams.IPsecNatInfo.usSrcPort !=
				*(unsigned short *)&(pHeadSkb->cb[SECFP_UDP_SOURCE_PORT])))) {
			snprintf(aMsg, ASF_MAX_MESG_LEN-1,
				"SPI = 0x%x, Seq. No = %d :: Inbounbd IPSec packet source IP or UDP "
				"port is not same as SA source IP or UDP port"
				"Dropping the packet",
				pSA->SAParams.ulSPI, pSA->ulLastSeqNum);
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID11;
			AsfLogInfo.aMsg = aMsg;
			ASFIPSEC_WARN("%s", aMsg);
			asfFillLogInfo(&AsfLogInfo, pSA);
			pSA->ulBytes[smp_processor_id()] -= pHeadSkb->len;
			pSA->ulPkts[smp_processor_id()]--;
			rcu_read_unlock();
			return 1;
		}
	}
	rcu_read_unlock();
	return 0;
}

void secfp_inCompleteUpdateIpv4Pkt(struct sk_buff *pHeadSkb)
{
	struct iphdr *iph;
	u8 tos;

	skb_reset_network_header(pHeadSkb);

	iph = ip_hdr(pHeadSkb);

	/* Do header checksum verification */
	if (!ip_compute_csum(iph, (iph->ihl * sizeof(unsigned int))))
		pHeadSkb->ip_summed = CHECKSUM_UNNECESSARY;
	else {
		pHeadSkb->ip_summed = CHECKSUM_NONE;
	}

	/* ECN Handling*/
	if ((pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX]) &&
		(pHeadSkb->cb[SECFP_TOS_INDEX] & SECFP_ECN_ECT_CE) &&
		!(iph->tos & SECFP_ECN_ECT_CE)) {
		tos = iph->tos | SECFP_ECN_ECT_CE;
		ASFIPSEC_DEBUG("doing incremental checksum here");
		csum_replace4(&iph->check, iph->tos, tos);
		iph->tos = tos;
	}
}
#ifndef CONFIG_ASF_SEC4x
void secfp_inCompleteWithFrags(struct device *dev,
				struct talitos_desc *desc,
				void *context, int err)
#else
void secfp_inCompleteWithFrags(struct device *dev, u32 *pdesc,
				u32 err, void *context)
#endif
{
	struct sk_buff *skb1 = (struct sk_buff *) context;
	unsigned int ulFragCnt;
	struct sk_buff *pHeadSkb, *pTailSkb;
#ifndef ASF_SECFP_PROTO_OFFLOAD
	struct sk_buff *pTempSkb;
#endif
	unsigned int ulTotLen = 0, iRetVal;
	unsigned char ucNextProto;
	unsigned char *pOrgEthHdr;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	struct iphdr *iph = (struct iphdr *)*(uintptr_t *)
				&(skb1->cb[SECFP_IPHDR_INDEX]);
	inSA_t *pSA;
	char aMsg[ASF_MAX_MESG_LEN + 1];
	ASFLogInfo_t AsfLogInfo;
	ASFIPSecOpqueInfo_t IPSecOpque = {};
	unsigned int ulCommonInterfaceId;
	int transport_hdr_len;
#if defined(CONFIG_ASF_SEC4x) && !defined(ASF_QMAN_IPSEC)
	struct aead_edesc *desc;
	desc = (struct aead_edesc *)((char *)pdesc -
		offsetof(struct aead_edesc, hw_desc));

	ASFIPSEC_DEBUG("InComplete: iteration=%d, desc=0x%x, err = %d"
			" refIndex = %d\n",
			++ulNumIter[smp_processor_id()],
			(unsigned int) desc, err, skb1->cb[SECFP_REF_INDEX]);
#endif
	pIPSecPPGlobalStats = asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
	pIPSecPPGlobalStats->ulTotInProcSecPkts++;
	ASFIPSEC_FENTRY;
#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6) {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *) iph;
		IPSecOpque.DestAddr.bIPv4OrIPv6 = 1;
		memcpy(IPSecOpque.DestAddr.ipv6addr,
				ipv6h->daddr.s6_addr32, 16);
		transport_hdr_len = SECFP_IPV6_HDR_LEN + SECFP_ESP_HDR_LEN;
	} else {
#endif
		IPSecOpque.DestAddr.bIPv4OrIPv6 = 0;
		IPSecOpque.DestAddr.ipv4addr = iph->daddr;
		transport_hdr_len = SECFP_IPV4_HDR_LEN + SECFP_ESP_HDR_LEN;
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM) && !defined(CONFIG_ASF_SEC4x)
	skb1->cb[SECFP_REF_INDEX]--;
#else
	skb1->cb[SECFP_REF_INDEX] = 0;
#endif
	if (unlikely(err)) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
		rcu_read_lock();
		pSA = secfp_findInSA(*(unsigned int *)&(skb1->cb[SECFP_VSG_ID_INDEX]),
				SECFP_PROTO_ESP,
				*(unsigned int *)&(skb1->cb[SECFP_SPI_INDEX]),
				IPSecOpque.DestAddr,
				(unsigned int *)&(skb1->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			pSA->ulBytes[smp_processor_id()] -= skb1->len;
			pSA->ulPkts[smp_processor_id()]--;
			snprintf((aMsg), ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-1");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
		}
		rcu_read_unlock();
#ifndef CONFIG_ASF_SEC4x
		if (skb1->cb[SECFP_REF_INDEX]) {
			skb1->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		} else
#endif
		{
			SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t)*((unsigned int *)
					&(skb1->cb[SECFP_SKB_DATA_DMA_INDEX])),
					skb_end_pointer(skb1) - skb1->head);
			skb1->prev = NULL;
			secfp_unmap_descs(skb1);
			SECFP_DESC_FREE(desc);
			ASFSkbFree(skb1);
			return;
		}
	} else {
		pHeadSkb = skb1;
		ulTotLen = pHeadSkb->len;

		if (skb_shinfo(skb1)->frag_list) {
#ifndef ASF_SECFP_PROTO_OFFLOAD
			if ((unsigned int)(skb1->prev) == SECFP_IN_GATHER_NO_SCATTER) {	/* Using this as a hint, this means output buffer is single */
				pTailSkb = skb1;
			} else
#endif
			{
				for (ulFragCnt = 1, pTailSkb = skb_shinfo(skb1)->frag_list;
					pTailSkb->next != NULL;
					ulTotLen += pTailSkb->len,
					pTailSkb = pTailSkb->next,
					ulFragCnt++)
					;
				ulTotLen += pTailSkb->len;
			}
		ASFIPSEC_PRINT("\n ulTotLen IS %d ulFragCnt %d", ulTotLen, ulFragCnt);
		} else {
			pTailSkb = skb1;
		}
#ifndef ASF_SECFP_PROTO_OFFLOAD
		if (secfp_inHandleICVCheck(desc, pTailSkb)) {
#ifndef CONFIG_ASF_SEC4x
			/* Failure case - only in case of SEC3x*/
			rcu_read_lock();
			pSA = secfp_findInSA(*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
						SECFP_PROTO_ESP,
						*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
						IPSecOpque.DestAddr,
						(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT17]);
			if (pSA) {
				pSA->ulBytes[smp_processor_id()] -= skb1->len;
				pSA->ulPkts[smp_processor_id()]--;
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT17);
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "ICV Comparision Failed");
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID8;
				asfFillLogInfo(&AsfLogInfo, pSA);
			}
			rcu_read_unlock();
			if (pHeadSkb->cb[SECFP_REF_INDEX]) {
				pHeadSkb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				SECFP_DESC_FREE(desc);
				return;
			} /*else */

			SECFP_UNMAP_SINGLE_DESC(pdev,
				(dma_addr_t)*((unsigned int *)&(skb1->cb[SECFP_SKB_DATA_DMA_INDEX])),
				skb_end_pointer(skb1) - skb1->head);
			skb1->prev = NULL;
			secfp_unmap_descs(skb1);
			SECFP_DESC_FREE(desc);
			ASFSkbFree(skb1);
			return;
#endif
		}
		SECFP_DESC_FREE(desc);
		if (pHeadSkb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
			ASFIPSEC_DEBUG("Due to PRE-SEC operations failure,"
				"skb has to be dropped");
			rcu_read_lock();
			pSA = secfp_findInSA(*(unsigned int *)&(
				pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
				SECFP_PROTO_ESP,
				*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
				IPSecOpque.DestAddr,
				(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
			if (pSA) {
				pSA->ulBytes[smp_processor_id()] -= skb1->len;
				pSA->ulPkts[smp_processor_id()]--;
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-2");
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
				asfFillLogInfo(&AsfLogInfo, pSA);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
			}
			rcu_read_unlock();
			ASFSkbFree(pHeadSkb);
			return;
		}
		/* In the 2nd iteration if pTailSkb len is 0, we can go ahead and release it */
		if ((unsigned int)(skb1->prev) == SECFP_IN_GATHER_NO_SCATTER) {
			/* Hint says, we made 2 buffers into one, so go ahead and eliminate frag_list completely */
			ASFSkbFree(skb_shinfo(skb1)->frag_list);
			skb_shinfo(skb1)->frag_list = NULL;
			pTailSkb = skb1; /* For any further manipulations in the code */
		} else {
			/* Ok: We had a frag list, but let us say, the last skb had only the ICV, and hence it got
				elimated, time to clean up */
			if (unlikely(pTailSkb->len == 0)) {
				ASFIPSEC_DEBUG("This should not happen :pTailSkb->len = 0");
				pTempSkb = pTailSkb;
				if (pTempSkb == skb_shinfo(pHeadSkb)->frag_list) {
					skb_shinfo(pHeadSkb)->frag_list = NULL;
					pTailSkb = pHeadSkb;
				} else {
					for (pTailSkb = skb_shinfo(pHeadSkb)->frag_list; pTailSkb->next == pTempSkb; pTailSkb = pTailSkb->next)
						;
					pTailSkb->next = NULL;
				}
				ASFSkbFree(pTempSkb);
			}
		}
		/* We have no requirement for the hint field anymore, let us clean up */
		pHeadSkb->prev = NULL;
		SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t)*((unsigned int *)
				&(pHeadSkb->cb[SECFP_SKB_DATA_DMA_INDEX])),
				skb_end_pointer(pHeadSkb) - pHeadSkb->head);
		secfp_unmap_descs(pHeadSkb);
#endif
		if (secfp_inCompleteCheckAndTrimPkt(pHeadSkb, pTailSkb,
			&ulTotLen, &ucNextProto, &IPSecOpque.DestAddr)) {
			ASFIPSEC_WARN("Packet check failed");
			ASFSkbFree(pHeadSkb);
			return;
		}

		if ((skb_shinfo(pHeadSkb)->frag_list) && (pHeadSkb->len < transport_hdr_len)) {
			if (!asfReasmPullBuf(pHeadSkb, transport_hdr_len, &ulFragCnt)) {
				ASFIPSEC_WARN("asfReasmPullBuf Failed");
				ASFSkbFree(pHeadSkb);
				return;
			}
		}

		iRetVal = secfp_inCompleteSAProcess(&pHeadSkb, &IPSecOpque,
				SECFP_PROTO_ESP, &ulCommonInterfaceId);
		if (iRetVal == 1) {
			ASFIPSEC_WARN("secfp_inCompleteSAProcess failed");
			ASFSkbFree(pHeadSkb);
			return;
		} else if (iRetVal == 2) {
			ASFIPSEC_DEBUG("Absorbed by frag process");
			return;
		}

		ulTotLen = pHeadSkb->data_len;
		pHeadSkb->data_len = 0;

		if (ucNextProto == SECFP_PROTO_IP) {
			ASFBuffer_t Buffer;

			pOrgEthHdr = skb_network_header(pHeadSkb)-ETH_HLEN;

			secfp_inCompleteUpdateIpv4Pkt(pHeadSkb);
/*todo			pHeadSkb->protocol = ETH_P_IP;*/
			/* Need to give it to the stack */
			ASFIPSEC_FPRINT("pOrgEthHdr = 0x%x:0x%x:0x%x",
					*(unsigned int *)&pOrgEthHdr[0],
					*(unsigned int *)&(pOrgEthHdr[4]),
					*(unsigned int *)&(pOrgEthHdr[8]));
			ASFIPSEC_FPRINT("Pkt received skb->len = %d", pHeadSkb->len);
			ASFIPSEC_HEXDUMP(pHeadSkb->data, pHeadSkb->len);
		/* Packet is ready to go */
		/* Assuming ethernet as the receiving device of original packet */
		/* Homogenous buffer */
			Buffer.nativeBuffer = pHeadSkb;
#ifdef ASF_TERM_FP_SUPPORT
			if (pHeadSkb->mapped && pTermProcessPkt)
				pTermProcessPkt(
				*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
				ulCommonInterfaceId, Buffer, secfp_SkbFree,
				pHeadSkb, &IPSecOpque, ASF_FALSE);
			else
#endif
				ASFFFPProcessAndSendPkt(
				*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
				ulCommonInterfaceId, Buffer, secfp_SkbFree,
				pHeadSkb, &IPSecOpque);

			pIPSecPPGlobalStats->ulTotInProcPkts++;
#ifdef ASF_IPV6_FP_SUPPORT
		} else if (ucNextProto == SECFP_PROTO_IPV6) {
			ASFBuffer_t Buffer;
			pOrgEthHdr = skb_network_header(pHeadSkb)-ETH_HLEN;
			skb_reset_network_header(pHeadSkb);
			pHeadSkb->protocol = ETH_P_IPV6;
			ASFIPSEC_DEBUG("\n ipv6 packet decrypted successfully"
					" need to send it to ipv6stack");
			/* Homogenous buffer */
			Buffer.nativeBuffer = pHeadSkb;
			if (ASFFFPIPv6ProcessAndSendPkt(
				*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]),
				ulCommonInterfaceId, Buffer, secfp_SkbFree,
				pHeadSkb, &IPSecOpque) == ASF_RTS) {
				ASFIPSEC_DEBUG("Sending Decrypted Packet Up");
#ifdef CONFIG_DPA
				asf_dec_skb_buf_count(pHeadSkb);
#endif
				netif_receive_skb(pHeadSkb);
				return;
			}
			pIPSecPPGlobalStats->ulTotInProcPkts++;
#endif
		} else {
			ASFIPSEC_WARN("Protocol not supported 0x%x", ucNextProto);
			ASFSkbFree(pHeadSkb);
			return;
		}
	}
}

#ifndef ASF_QMAN_IPSEC
static void secfp_free_frags(void *desc, struct sk_buff *skb)
{
#ifndef CONFIG_ASF_SEC4x
	SECFP_DESC_FREE(desc);
#else
	struct aead_edesc *edesc = (struct aead_edesc *)
				((char *)desc -	offsetof(struct aead_edesc,
							hw_desc));
	struct sec4_sg_entry *link_ptr, *link_ptr_base;
	dma_unmap_single(pdev, edesc->sec4_sg_dma, edesc->sec4_sg_bytes,
						DMA_BIDIRECTIONAL);
	link_ptr = (struct sec4_sg_entry *)
		*((unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]));
	link_ptr_base = link_ptr;
	if (link_ptr) {
		while (1) {
			if (link_ptr->len & cpu_to_be32(0x40000000)) {
				link_ptr->len = link_ptr->len &
						cpu_to_be32(0xBFFFFFFF);
				dma_unmap_single(pdev, link_ptr->ptr,
					link_ptr->len, DMA_BIDIRECTIONAL);
				break;
			}
			dma_unmap_single(pdev, link_ptr->ptr, link_ptr->len,
						DMA_BIDIRECTIONAL);
			link_ptr++;
		}
		kfree(link_ptr_base);
	}
#endif
}
#endif

#ifndef CONFIG_ASF_SEC4x
void secfp_inComplete(struct device *dev, struct talitos_desc *desc,
		void *context, int err)
#else
void secfp_inComplete(struct device *dev, u32 *pdesc,
		u32 err, void *context)
#endif
{
	struct sk_buff *skb = (struct sk_buff *) context;
	unsigned char ucNextProto;
	unsigned int ulTempLen, iRetVal;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	inSA_t *pSA;
	struct iphdr *iph = (struct iphdr *)*(uintptr_t *)&(skb->cb[SECFP_IPHDR_INDEX]);
	ASFLogInfo_t AsfLogInfo;
	char aMsg[ASF_MAX_MESG_LEN + 1];
	ASFIPSecOpqueInfo_t IPSecOpque = {};
	ASFBuffer_t Buffer;
	unsigned int ulCommonInterfaceId;
#if defined(CONFIG_ASF_SEC4x)
	struct aead_edesc *desc;
	desc = (struct aead_edesc *)((char *)pdesc -
			offsetof(struct aead_edesc, hw_desc));
#endif
	ASFIPSEC_FENTRY;

#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6) {
		struct ipv6hdr *ipv6h = (struct ipv6hdr *) iph;
		IPSecOpque.DestAddr.bIPv4OrIPv6 = 1;
		memcpy(IPSecOpque.DestAddr.ipv6addr, ipv6h->daddr.s6_addr32, 16);
	} else
#endif
	{
		IPSecOpque.DestAddr.bIPv4OrIPv6 = 0;
		IPSecOpque.DestAddr.ipv4addr = iph->daddr;
	}
	pIPSecPPGlobalStats =
		asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
	pIPSecPPGlobalStats->ulTotInProcSecPkts++;

#ifndef ASF_QMAN_IPSEC
	ASFIPSEC_DEBUG("InComplete: iteration=%d, desc=0x%x, err = %x"
			"refIndex = %d\n", ++ulNumIter[smp_processor_id()],
			(unsigned int) desc, err, skb->cb[SECFP_REF_INDEX]);
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM) && !defined(CONFIG_ASF_SEC4x)
	skb->cb[SECFP_REF_INDEX]--;
#else
	skb->cb[SECFP_REF_INDEX] = 0;
#endif
	if (unlikely(err)) {
#if defined(CONFIG_ASF_SEC4x) && !defined(ASF_QMAN_IPSEC)
#ifdef ASF_IPSEC_DEBUG
		ASFIPSEC_DPERR("%08x", err);
		if (net_ratelimit())
			caam_jr_strstatus(dev, err);
#endif
		if (skb_shinfo(skb)->nr_frags)
			secfp_free_frags(desc, skb);
		else
#endif
			SECFP_DESC_FREE(desc);
		rcu_read_lock();
		pSA = secfp_findInSA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
					SECFP_PROTO_ESP,
					*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
					IPSecOpque.DestAddr,
					(unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
		if (pSA) {
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-3");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			asfFillLogInfo(&AsfLogInfo, pSA);
			/* TBD - length being deducted is not
				same as lengh added*/
			pSA->ulBytes[smp_processor_id()] -= skb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();
#ifndef CONFIG_ASF_SEC4x
		if (skb->cb[SECFP_REF_INDEX]) {
			skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
			return;
		}
#endif
		SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t) *((unsigned int *)
				&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])),
				skb_end_pointer(skb) - skb->head);
		skb->data_len = 0;
		skb->next = NULL;
		ASFSkbFree(skb);
		return;
	}
#ifndef ASF_SECFP_PROTO_OFFLOAD
	if (secfp_inHandleICVCheck(desc, skb)) {
#ifndef CONFIG_ASF_SEC4x
		/* Failure case - only in case of SEC3x*/
		SECFP_DESC_FREE(desc);
		/* Failure case */
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT17]);
		rcu_read_lock();
		pSA = secfp_findInSA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
			SECFP_PROTO_ESP,
			*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
			IPSecOpque.DestAddr,
			(unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				"ICV Comparision Failed");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID8;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA,
				ASF_IPSEC_PP_POL_CNT17);
			pSA->ulBytes[smp_processor_id()] -= skb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();
		if (skb->cb[SECFP_REF_INDEX]) {
			skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
			return;
		} else {
			SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t)
				*((unsigned int *) &(skb->cb
				[SECFP_SKB_DATA_DMA_INDEX])),
				skb_end_pointer(skb) - skb->head);
			skb->data_len = 0;
			skb->next = NULL;
			ASFSkbFree(skb);
			return;
		}
#endif
	}
#endif /*OFFLOAD*/
#ifndef ASF_QMAN_IPSEC
	if (skb_shinfo(skb)->nr_frags)
		secfp_free_frags(desc, skb);
	else
		SECFP_DESC_FREE(desc);

	SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t) *((unsigned int *)
			&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])),
		skb_end_pointer(skb) - skb->head);
#endif /*ASF_QMAN_IPSEC*/
#ifndef ASF_SECFP_PROTO_OFFLOAD
	if (skb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
		rcu_read_lock();
		pSA = secfp_findInSA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
					SECFP_PROTO_ESP,
					*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
					IPSecOpque.DestAddr,
					(unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
		if (pSA) {
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Cipher Operation Failed-4");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			asfFillLogInfo(&AsfLogInfo, pSA);
			pSA->ulBytes[smp_processor_id()] -= skb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();
		ASFIPSEC_DEBUG("Due to prior operation failure, skb has to be dropped");
		skb->data_len = 0;
		skb->next = NULL;
		ASFSkbFree(skb);
		return;
	}
	ASFIPSEC_FPRINT("skb->data = 0x%x, skb->data - 20 - 16 =0x%x,"\
		"skb->len = %d",
		skb->data, skb->data - 20 - 16, skb->len);
	ASFIPSEC_HEXDUMP(skb->data, 64);
#endif /* ASF_SECFP_PROTO_OFFLOAD */

	if (skb_shinfo(skb)->nr_frags == 0)
		skb->data_len = 0;
	skb->next = NULL;

	/* Look at the Next protocol field */
	ulTempLen = skb_headlen(skb);
	if (secfp_inCompleteCheckAndTrimPkt(skb, skb, &ulTempLen,
			&ucNextProto, &IPSecOpque.DestAddr)) {
		ASFIPSEC_WARN("secfp_incompleteCheckAndTrimPkt failed");
		ASFSkbFree(skb);
		return;
	}
	iRetVal = secfp_inCompleteSAProcess(&skb, &IPSecOpque,
		SECFP_PROTO_ESP, &ulCommonInterfaceId);
	ASFIPSEC_DEBUG("\nUL Common IFACE ID is %d\n",
				ulCommonInterfaceId);
	if (iRetVal == 1) {
		ASFIPSEC_WARN("secfp_inCompleteSAProcess failed");
		ASFSkbFree(skb);
		return;
	} else if (iRetVal == 2) {
		ASFIPSEC_DEBUG("Absorbed by frag process");
		return;
	}
	ASFIPSEC_DEBUG("inComplete: Exiting SA related processing");
	/* Packet is ready to go */
	/* Assuming ethernet as the receiving device of original packet */
	if (ucNextProto == SECFP_PROTO_IP) {
		secfp_inCompleteUpdateIpv4Pkt(skb);
		skb->protocol = ETH_P_IP;

		ASFIPSEC_FPRINT("decrypt skb %p len %d frag %p\n",
			skb->head, skb->len,
			skb_shinfo(skb)->frag_list);
		ASFIPSEC_HEXDUMP(skb->data, skb->len);
		/* Homogenous buffer */
		Buffer.nativeBuffer = skb;
#ifdef ASF_TERM_FP_SUPPORT
		if (skb->mapped && pTermProcessPkt)
			pTermProcessPkt(
			*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
			ulCommonInterfaceId, Buffer, secfp_SkbFree,
			skb, &IPSecOpque, ASF_FALSE);
		else
#endif
			ASFFFPProcessAndSendPkt(
			*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
			ulCommonInterfaceId, Buffer, secfp_SkbFree,
			skb, &IPSecOpque);

		pIPSecPPGlobalStats->ulTotInProcPkts++;
#ifdef ASF_IPV6_FP_SUPPORT
	} else if (ucNextProto == SECFP_PROTO_IPV6) {
		ASFIPSEC_DEBUG("\n ipv6 packet decrypted successfully"
				" need to send it to ipv6stack");
		skb_reset_network_header(skb);
		skb->protocol = ETH_P_IPV6;
		/* Homogenous buffer */
		Buffer.nativeBuffer = skb;
		if (ASFFFPIPv6ProcessAndSendPkt(
			*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
			ulCommonInterfaceId, Buffer, secfp_SkbFree,
			skb, &IPSecOpque) == ASF_RTS) {
			ASFIPSEC_DEBUG("Sending Decrypted Packet Up");
#ifdef CONFIG_DPA
			asf_dec_skb_buf_count(skb);
#endif
			netif_receive_skb(skb);
			return;
		}
		pIPSecPPGlobalStats->ulTotInProcPkts++;
#endif
	} else {
		ASFIPSEC_WARN("Protocol not supported 0x%x", ucNextProto);
		ASFSkbFree(skb);
		return;
	}
}
/*
 * This function finds out the Extended sequence number to be appended to the
 * end of the packet when ICV calculation. This value is passed back in *pData
 */
static inline void secfp_appendESN(inSA_t *pSA, unsigned int ulSeqNum,
				unsigned int *ulLBoundSeqNum, unsigned int *pData)
{
	int uiCount = pSA->ulLastSeqNum - pSA->SAParams.AntiReplayWin + 1;
	unsigned int ulHOSeqNum;

	if (uiCount < 0) {
		uiCount = (-uiCount);
		*ulLBoundSeqNum = (~uiCount) + 1;
	} else {
		*ulLBoundSeqNum = uiCount;
	}
	if (pSA->ulLastSeqNum >= (unsigned int)(pSA->SAParams.AntiReplayWin -
				1)) {
		if (ulSeqNum >= (pSA->ulLastSeqNum - pSA->SAParams.AntiReplayWin
					+ 1))
			ulHOSeqNum = pSA->ulHOSeqNum;
		else
			ulHOSeqNum = pSA->ulHOSeqNum + 1;
	} else {
		if (ulSeqNum >= *ulLBoundSeqNum)
			ulHOSeqNum = pSA->ulHOSeqNum - 1;
		else
			ulHOSeqNum = pSA->ulHOSeqNum;
	}
	(*(unsigned int *)(pData)) = ulHOSeqNum;
}

/* When an inbound packet arrives, first it is checked to see if it
 * is a replay packet. This routine does the replay check
 */
#ifndef ASF_QMAN_IPSEC
static void secfp_checkSeqNum(inSA_t *pSA,
					u32 ulSeqNum, u32 ulLowerBoundSeqNum, struct sk_buff *skb)
{
	unsigned int usSize = 0;
	unsigned int uiDiff;
	unsigned int usCo_Efficient = 0, usRemainder = 0;
	ASFLogInfo_t AsfLogInfo;
	char aMsg[ASF_MAX_MESG_LEN + 1];

	skb->cb[SECFP_SABITMAP_INFO_INDEX] = 0;
	/* if sequence number is 0 drop the packet and increment stats */
	if (ulSeqNum == 0) {
		ASFIPSEC_DEBUG("Invalid sequence number");
		snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Invalid sequence number");
		AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID4;
		AsfLogInfo.aMsg = aMsg;
		asfFillLogInfo(&AsfLogInfo, pSA);
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT14]);
		ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT14);
		/* Increment stats */
		skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
		return;
	}
	if (!pSA->SAParams.bUseExtendedSequenceNumber) {
		if (ulSeqNum <= pSA->ulLastSeqNum) {
			uiDiff = pSA->ulLastSeqNum - ulSeqNum;
			if (uiDiff >= pSA->SAParams.AntiReplayWin) {
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
				AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID5;
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
					"Anti-replay window check failed for ESN");
				ASFIPSEC_WARN("%s", aMsg);
				AsfLogInfo.aMsg = aMsg;
				asfFillLogInfo(&AsfLogInfo, pSA);
				/* Update SA Statistics */
				skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
				return;
			}
			usSize = pSA->SAParams.AntiReplayWin >> 5;
			usCo_Efficient = uiDiff >> 5; /* or uiDiff / 32 */
			usRemainder	= uiDiff & 31; /* or uiDiff % 32 */
			if ((pSA->pWinBitMap[(usSize - 1) - usCo_Efficient]) &
				((unsigned int)1 << usRemainder)) {
				snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet for ESN");
				ASFIPSEC_WARN("%s", aMsg);
				AsfLogInfo.aMsg = aMsg;
				AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID6;
				asfFillLogInfo(&AsfLogInfo, pSA);
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
				ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
				skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				return;
			} else {	/* Have it ready for Post SEC update */
				skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
				skb->cb[SECFP_SABITMAP_COEF_INDEX] =
					usCo_Efficient;
				skb->cb[SECFP_SABITMAP_REMAIN_INDEX] =
					usRemainder;
			}
			return;
		} else {
			skb->cb[SECFP_SABITMAP_INFO_INDEX] = 2;	/* available */
			*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]) = ulSeqNum - pSA->ulLastSeqNum;
			ASFIPSEC_DEBUG("Sequence Number check: ulLastSeqNum = %d, ulSeqNum = %d", pSA->ulLastSeqNum, ulSeqNum);
		}
		return;
	} else {
		if (pSA->ulLastSeqNum >= pSA->SAParams.AntiReplayWin - 1) {
			/*
			window size			ulLastSeqNum
			<-----------><----------------------->
			*/
			if (ulSeqNum >= (pSA->ulLastSeqNum -
					pSA->SAParams.AntiReplayWin + 1)) {
				/* sequence number is more than lower bound */
				if (ulSeqNum <= pSA->ulLastSeqNum) {
					/* sequence number is lesser than
					* last seen highest sequence number */
					uiDiff = pSA->ulLastSeqNum - ulSeqNum;
					if (uiDiff > pSA->SAParams.AntiReplayWin) {
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Anti-replay window check failed #2");
						ASFIPSEC_WARN("%s", aMsg);
						AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID5;
						AsfLogInfo.aMsg = aMsg;
						asfFillLogInfo(&AsfLogInfo, pSA);
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
						/* Update SA Statistics */
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
						return;
					}
					usSize = pSA->SAParams.AntiReplayWin
							>> 5;
					usCo_Efficient = uiDiff >> 5;
					usRemainder	= uiDiff & 31;
					if ((pSA->pWinBitMap[(usSize - 1) -
						usCo_Efficient]) &
						((unsigned int)1 <<
						usRemainder)) {
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet");
						ASFIPSEC_WARN("%s", aMsg);
						AsfLogInfo.aMsg = aMsg;
						asfFillLogInfo(&AsfLogInfo, pSA);
						AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID6;
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
						/* Update SA Statistics */
						return;
					} else {
						/* Have it ready for Post SEC update */
						skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
						skb->cb[
						SECFP_SABITMAP_COEF_INDEX] =
							usCo_Efficient;
						skb->cb[
						SECFP_SABITMAP_REMAIN_INDEX] =
							usRemainder;
					}
				}
				/* else of this is a good condition - nothing to check */
				else {	/* Update the information */
					skb->cb[SECFP_SABITMAP_INFO_INDEX] = 2;	/* available */
					*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]) = ulSeqNum - pSA->ulLastSeqNum;
				}
			} /* else of this seems to be bad case, but not handled */
			else {
				skb->cb[SECFP_SABITMAP_INFO_INDEX] = 3;	/* available, update higher order sequence number also */
				skb->cb[SECFP_SABITMAP_INFO_INDEX] = ulSeqNum + (SECFP_MAX_32BIT_VALUE - pSA->ulLastSeqNum);
			}
			return;
		} else {
			/*
			window								window
			<-------><----------------------><---->
			*/
			if (ulSeqNum >= ulLowerBoundSeqNum) {
				/* sequence number is in the right hand side window */
				uiDiff = pSA->ulLastSeqNum + (SECFP_MAX_32BIT_VALUE - ulSeqNum);
				if (uiDiff >= pSA->SAParams.AntiReplayWin) {
					AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID5;
					/* Update SA Statistics */
					snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
					"Anti-replay window check failed #3");
					ASFIPSEC_WARN("%s", aMsg);
					AsfLogInfo.aMsg = aMsg;
					asfFillLogInfo(&AsfLogInfo, pSA);
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
					return;
				}
				usSize = pSA->SAParams.AntiReplayWin >> 5;
				usCo_Efficient = uiDiff >> 5;
				usRemainder	= uiDiff & 31;
				if ((pSA->pWinBitMap[(usSize - 1) -
							usCo_Efficient]) &
					((unsigned int)1 << usRemainder)) {
					snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet");
					ASFIPSEC_WARN("%s", aMsg);
					AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID6;
					AsfLogInfo.aMsg = aMsg;
					asfFillLogInfo(&AsfLogInfo, pSA);
					ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
					ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
					skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
					/* Update SA Statistics */
					return;
				} else {
					/* Have it ready for Post SEC update */
					skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
					skb->cb[SECFP_SABITMAP_COEF_INDEX] =
							usCo_Efficient;
					skb->cb[SECFP_SABITMAP_REMAIN_INDEX] =
							usRemainder;
				}
				return;
			} else {	/* sequence number is in the left hand side window */
				if (ulSeqNum <= pSA->ulLastSeqNum) {
					uiDiff = pSA->ulLastSeqNum - ulSeqNum;
					if (uiDiff >= pSA->SAParams.
							AntiReplayWin) {
						/* Update SA Statistics */
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Anti-replay window check failed #4");
						ASFIPSEC_WARN("%s", aMsg);
						AsfLogInfo.aMsg = aMsg;
						AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID5;
						asfFillLogInfo(&AsfLogInfo, pSA);
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT15]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT15);
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP; /* DROP = 1*/
					}
					usSize = pSA->SAParams.AntiReplayWin
							>> 5;
					usCo_Efficient = uiDiff >> 5;
					usRemainder	= uiDiff & 31;
					if ((pSA->pWinBitMap[(usSize - 1) -
						usCo_Efficient]) &
						((unsigned int)1 <<
						usRemainder)) {
						snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "replay Packet");
						ASFIPSEC_WARN("%s", aMsg);
						AsfLogInfo.aMsg = aMsg;
						AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID6;
						asfFillLogInfo(&AsfLogInfo, pSA);
						ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT16]);
						ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT16);
						skb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
						/* Update SA Statistics */
						return;
					} else {
						/* Have it ready for Post SEC update */
						skb->cb[SECFP_SABITMAP_INFO_INDEX] = 1;	/* available */
						skb->cb[
						SECFP_SABITMAP_COEF_INDEX] =
							usCo_Efficient;
						skb->cb[
						SECFP_SABITMAP_REMAIN_INDEX] =
							usRemainder;
					}
					return;
				} else {
					skb->cb[SECFP_SABITMAP_INFO_INDEX] = 2;	/* available */
					*(unsigned int *)&(skb->cb[SECFP_SABITMAP_DIFF_INDEX]) = ulSeqNum - pSA->ulLastSeqNum;
				}
				return;
			}
		}
	}
}
#endif

/*
 * return values = 0, pkt consumed
			= 1, send packet up to stack
 */
/* Inbound IPv6 packet handling
 * Currently stub
 */
#ifdef ASF_IPV6_FP_SUPPORT
static inline int secfp_try_fastPathInv6(struct sk_buff *skb1,
			ASF_boolean_t bCheckLen, unsigned int ulVSGId,
			ASF_uint32_t ulCommonInterfaceId)
{
	unsigned int ulSPI, ulSeqNum;
	inSA_t *pSA;
	struct ipv6hdr *ipv6h = ipv6_hdr(skb1);
	unsigned int ulLowerBoundSeqNum;
	unsigned int ulHashVal = usMaxInSAHashTaleSize_g;
	struct sk_buff *pHeadSkb = NULL, *pTailSkb = NULL;
	bool bScatterGather;
	unsigned int len = 0;
	char aMsg[ASF_MAX_MESG_LEN + 1];
	ASFLogInfo_t AsfLogInfo;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	AsfSPDPolicyPPStats_t *pIPSecPolicyPPStats;
	unsigned char secin_sg_flag;
#ifndef CONFIG_ASF_SEC4x
	struct talitos_desc *desc = NULL;
#elif !defined(ASF_QMAN_IPSEC)
	void *desc;
#ifdef ASF_SECFP_PROTO_OFFLOAD
	unsigned int ulFragpadlen = 0;
#endif
#endif
	unsigned char ipv6TClass = 0;
	unsigned int ulIpv6Exthl = 0;
	unsigned int ulIpv6hl = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	struct sk_buff *pTailPrevSkb = 0;
#ifndef ASF_SECFP_PROTO_OFFLOAD
	int ii;
	unsigned int ulICVInPrevFrag;
	unsigned char *pCurICVLocBytePtrInPrevFrag, *pCurICVLocBytePtr;
	unsigned int *pCurICVLoc = 0, *pNewICVLoc = 0;
	unsigned char *pNewICVLocBytePtr;
#endif
	ASF_boolean_t bHard = ASF_FALSE;
	ASF_boolean_t bExpiry = ASF_FALSE;
	ASF_IPAddr_t saDestAddr;
	SPDInContainer_t *pContainer;

	if (ulVSGId == ulMaxVSGs_g) {
		ASFIPSEC_DEBUG("send packet up for VSG determination");
		ASFIPSEC_DEBUG("Need to call registered callback function ");
		return 1; /* Send it up to Stack */
	}

#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	ulIpv6hl = SECFP_IPV6_HDR_LEN + ulIpv6Exthl;
	ipv6_traffic_class(ipv6TClass, ipv6h);
	if (ipv6h->nexthdr == NEXTHDR_FRAGMENT ||
		ipv6h->nexthdr == NEXTHDR_HOP ||
		ipv6h->nexthdr == NEXTHDR_ROUTING) {
		ASFIPSEC_WARN("fragmentation header should have been removed");
		return 1; /* Send it up to Stack */
	}
	ASFIPSEC_FPRINT("Pkt received skb->len = %d", skb1->len);
	ASFIPSEC_HEXDUMP(skb1->data - 14, skb1->len);

	rcu_read_lock();
	SECFP_EXTRACT_IPV6_PKTINFO(skb1, ipv6h, ulIpv6hl, ulSPI, ulSeqNum);
	pSA = secfp_findInv6SA(ulVSGId, ipv6h->nexthdr,
				ulSPI, ipv6h->daddr.s6_addr32, &ulHashVal);
	if (pSA) {

		ASFIPSEC_DEBUG(" pSA Found coreId=%d", smp_processor_id());
		pIPSecPPGlobalStats = asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
		pIPSecPPGlobalStats->ulTotInRecvPkts++;

		pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
		pIPSecPolicyPPStats->NumInBoundInPkts++;

		if (unlikely(pSA->bSendPktToNormalPath)) {
			/* This can happen if SPDs have been modified and there is
					a requirement for revalidation
				*/
			ASFIPSEC_DEBUG("Need to send packet up to Normal Path");
			rcu_read_unlock();
			return 1; /* Send it up to Stack */
		}
		/* SA Found */
		/* Need to have this check when packets are coming in from upper layer, but not from the driver interface */
		if (skb_shinfo(skb1)->frag_list ||
			skb_shinfo(skb1)->nr_frags) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifndef CONFIG_ASF_SEC3x
			pHeadSkb = skb1;
			if (skb_shinfo(skb1)->frag_list)
				for (pTailPrevSkb = skb1,
					pTailSkb = skb_shinfo(skb1)->frag_list;
					pTailSkb->next != NULL;
					pTailPrevSkb = pTailSkb,
					pTailSkb = pTailSkb->next)
					;
			else
				pHeadSkb = pTailSkb = skb1;
			bScatterGather = SECFP_SCATTER_GATHER;

			if (likely((ipv6h->payload_len - (pSA->ulSecHdrLen)) < pSA->ulRcvMTU)
				&& (pSA->SAParams.ucCipherAlgo != SECFP_ESP_NULL)) {
				/* We go into gather input , single output */
				/* use skb->prev for indicating single output */
				skb1->prev = (void *) SECFP_IN_GATHER_NO_SCATTER;
			} else {
				/* We go into gather input, scatter output */
				skb1->prev = (void *) SECFP_IN_GATHER_SCATTER;
			}
			len = ipv6h->payload_len + SECFP_IPV6_HDR_LEN;
#else
			ASFIPSEC_DEBUG("Before Linearize : skb1->dev = 0x%x\n",
				(unsigned int) skb1->dev);
			if (asfReasmLinearize(&skb1,
				ipv6h->payload_len + SECFP_IPV6_HDR_LEN,
				VPN_TOT_OVHD, VPN_HDROOM)) {
				ASFIPSEC_WARN("skb->linearize failed");
				ASFSkbFree(skb1);
				rcu_read_unlock();
				return 0;
			}
			skb_reset_network_header(skb1);
			ipv6h = ipv6_hdr(skb1);
			len = ipv6h->payload_len + SECFP_IPV6_HDR_LEN;
			pHeadSkb = pTailSkb = skb1;
			bScatterGather = SECFP_NO_SCATTER_GATHER;

			ASFIPSEC_DEBUG("skb1->len = %d", skb1->len);
			ASFIPSEC_DEBUG("skb->dev = 0x%x",
					(unsigned int) skb1->dev);
#endif
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		} else {
			pHeadSkb = pTailSkb = skb1;
			len = skb1->len;
			bScatterGather = SECFP_NO_SCATTER_GATHER;
		}
		secin_sg_flag = SECFP_IN|bScatterGather;
/*TBD - In the following Code, pTailSkb will not work for nr_frags.
So all these special boundary cases need to be handled for nr_frags*/
		if ((bCheckLen) && ((skb_tailroom(pTailSkb))
					< pSA->ulReqTailRoom)) {
			ASFIPSEC_WARN("Received Skb does not have"
					" enough tail room to continue");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				"SPI = 0x%x, Seq. No = %u ::"
				" No free Buffer is available."
				" Returning with out processing"
				" the packet", ulSPI, ulSeqNum);
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID1;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT9]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT9);
		}

		if ((ipv6h->payload_len + SECFP_IPV6_HDR_LEN) < pSA->validIpPktLen) {
			ASFIPSEC_DEBUG("Invalid ESP or AH Pkt");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				"SPI = 0x%x, Seq. No = %u"
				" Packet length is less than the"
				" sum of IP Header, ESP Header length,"
				" IV and ICV length", ulSPI, ulSeqNum);
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID2;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT10]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT10);
			ASFSkbFree(pHeadSkb);
			rcu_read_unlock();
			return 0;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		pContainer = (SPDInContainer_t *)(ptrIArray_getData(
				&(secfp_InDB), pSA->pSASPDMapNode->ulSPDInContainerIndex));
		if (pContainer && pContainer->SPDParams.bDPDAlive) {
			ASF_IPAddr_t DestAddr;
			DestAddr.bIPv4OrIPv6 = 1;
			memcpy(DestAddr.ipv6addr,
				ipv6h->daddr.s6_addr32, sizeof(struct in6_addr));
			ASFIPSEC_DEBUG("Calling DPD alive callback VSG=%u, \
				Tunnel=%u, address=%s, Container=%u, SPI=%x",
					ulVSGId, pSA->ulTunnelId, ipv6h->daddr.s6_addr,
					pSA->pSASPDMapNode->ulSPDInContainerIndex, ulSPI);
			if (ASFIPSecCbFn.pFnDPDAlive)
				ASFIPSecCbFn.pFnDPDAlive(ulVSGId,
					pSA->ulTunnelId, ulSPI,
					ipv6h->nexthdr, DestAddr,
					pSA->pSASPDMapNode->ulSPDInContainerIndex);
			pContainer->SPDParams.bDPDAlive = 0;
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		ulLowerBoundSeqNum = 0;
	if (likely(pSA->SAParams.ucProtocol == SECFP_PROTO_ESP)) {
		if (pSA->SAParams.bAuth) {
#ifndef ASF_SECFP_PROTO_OFFLOAD /* anti-replay check done in HW */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (unlikely(pTailSkb->len < pSA->SAParams.uICVSize)) {
				/* pTailPrevSkb gets initialized in the case of fragments; This case comes
				into picture only when we have fragments */
				ulICVInPrevFrag = pSA->SAParams.uICVSize - pTailSkb->len;
				pCurICVLocBytePtrInPrevFrag = skb_tail_pointer(pTailPrevSkb) - ulICVInPrevFrag;
				pCurICVLocBytePtr = pTailSkb->data;

				pTailPrevSkb->len -= ulICVInPrevFrag;
				pTailSkb->len += ulICVInPrevFrag;

				if (pSA->SAParams.bDoAntiReplayCheck) {
					pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
					if (pSA->SAParams.bUseExtendedSequenceNumber) {
						/* Packet has ICV towards the end, so we need to put the ESN and then the ICV */
						/* Leave a 4 byte gap for the ESN and move the ICV */
						/* In this case copy the entire ICV to pTailSkb->data + sizeof (unsigned int);
							Trim the previous skb->len by ulICVInPrevLen
							Update the data for the Tail frag

							Eg: Input:
							<--prevTailFrag----><-----Tail Frag------>
								<-------ICV----->

							Output:
							<-prevTailFrag-><---Tail Frag----------->
										< 1 integer gap, ICV----------->

						*/

						pNewICVLocBytePtr = pTailSkb->data + sizeof(unsigned int);

						/* Real exception case, do byte copy */
						/* Good question here would be why not pull into previous frag, but not sure if
							there will be enough room there, but we have already checked for tail room
							in tail skb */
						for (ii = pTailSkb->len - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii +
							ulICVInPrevFrag] =
							pCurICVLocBytePtr[ii];

						for (ii = ulICVInPrevFrag - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

						secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pCurICVLoc);
					} else {
						/* Copy to Tail frag */
						pNewICVLocBytePtr = pTailSkb->data;
						for (ii = pTailSkb->len - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii +
							ulICVInPrevFrag]
							= pCurICVLocBytePtr[ii];

						for (ii = ulICVInPrevFrag - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

					}
				} else {
					/* Copy to Tail frag */
					pNewICVLocBytePtr = pTailSkb->data;
					for (ii = pTailSkb->len - 1;
							ii >= 0; ii--)
						pNewICVLocBytePtr[ii +
							ulICVInPrevFrag] =
							pCurICVLocBytePtr[ii];


					for (ii = ulICVInPrevFrag - 1;
							ii >= 0; ii--)
						pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

				}
			} else {
				if (pSA->SAParams.bDoAntiReplayCheck) {
					pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
					if (pSA->SAParams.ucAuthAlgo == SECFP_HMAC_AES_XCBC_MAC) {
						if (pSA->SAParams.bUseExtendedSequenceNumber)
							*((unsigned int *)(skb_tail_pointer(pTailSkb) + SECFP_ESN_MARKER_POSITION)) = 0xAAAAAAAA;
						else
							*((unsigned int *)(skb_tail_pointer(pTailSkb) + SECFP_ESN_MARKER_POSITION)) = 0;
					}
					if (pSA->SAParams.bUseExtendedSequenceNumber) {
						int kk;
						pCurICVLoc = (unsigned int *)(skb_tail_pointer(pTailSkb) - pSA->SAParams.uICVSize);
						pNewICVLoc = (unsigned int *)(skb_tail_pointer(pTailSkb) - pSA->SAParams.uICVSize + sizeof(unsigned int));
						for (kk = 2; kk >= 0; kk--)
							*(pNewICVLoc + kk) = *(pCurICVLoc + kk);
						secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pCurICVLoc);
					}

				} else
					ASFIPSEC_DEBUG("No Antoreplay check\n");
			}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
#endif /* ASF_SECFP_PROTO_OFFLOAD */
		} else {
			pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 0;
			/* No need to do post SEC Lookup */
			skb_set_tail_pointer(pTailSkb, skb_headlen(pTailSkb));
			*(unsigned int *)skb_tail_pointer(pTailSkb) = 0;
		}
#ifndef ASF_SECFP_PROTO_OFFLOAD /* anti-replay check done in HW */
	} else {
		/* check anything needed for AH */
		/* do not remove the tunnel header */
		unsigned int *pESNLoc = 0;
		if (pSA->SAParams.bDoAntiReplayCheck) {
			if (pSA->SAParams.bUseExtendedSequenceNumber) {
				pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
				pESNLoc = (unsigned int *)
						(skb_tail_pointer(pTailSkb));
				secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pESNLoc);
				*(unsigned int *)&(pHeadSkb->cb[SECFP_SEQNUM_INDEX]) = ulSeqNum;
				secfp_checkSeqNum(pSA, ulSeqNum,
						ulLowerBoundSeqNum, pHeadSkb);
			}
		}
	}
#else
		}
#endif

		if (pSA->SAParams.bVerifyInPktWithSASelectors)
			pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1;

		/* Copying information that is required post SEC operation */
		pHeadSkb->cb[SECFP_ICV_LENGTH] = pSA->SAParams.uICVSize;
		*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]) = ulVSGId;
		*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]) = pSA->SAParams.ulSPI;
		/* Pass the skb data pointer */
		*(uintptr_t *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]) = (uintptr_t)(&(pHeadSkb->data[0]));
		*(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]) = ulHashVal;

		ASFIPSEC_DBGL2("In Packet ulSPI=%d, ipaddr_ptr=0x%x,"
			" ulHashVal= %d, Saved values: ulSPI=%d,"
			" ipaddr_ptr=0x%x, ulHashVal=%d",
			pSA->SAParams.ulSPI, (unsigned int)&(pHeadSkb->data[0]),
			ulHashVal,
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
			*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]),
			*(unsigned int *)
			&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
#ifndef ASF_SECFP_PROTO_OFFLOAD
		if (pSA->SAParams.bPropogateECN) {
			pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX] = 1;
			pHeadSkb->cb[SECFP_TOS_INDEX] = ipv6TClass;
		} else
			pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX] = 0;

		if (pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX])
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SEQNUM_INDEX]) = ulSeqNum;

		/* Move the skb data pointer to beginning of ESP header */
		ASFIPSEC_DEBUG("In Offsetting data by ipheader len=%d", ulIpv6hl);
		pHeadSkb->data += ulIpv6hl;
		pHeadSkb->len -= ulIpv6hl;
#endif
		/* Storing Common Interface Id */
		if (!pSA->ulTunnelId)
			pSA->ucIfaceId = ulCommonInterfaceId;
		else
			pSA->ucIfaceId = pSA->SAParams.ulCId;

		ASFIPSEC_DEBUG("Calling secfp-submit");
		pHeadSkb->cb[SECFP_REF_INDEX] = 2;
#ifndef ASF_QMAN_IPSEC
		desc = secfp_desc_alloc();
		if (!desc) {
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
			ASFIPSEC_WARN("desc allocation failure");
			pHeadSkb->data_len = 0;
			ASFSkbFree(pHeadSkb);
			rcu_read_unlock();
			return 0;
		}
#ifdef CONFIG_ASF_SEC3x
		if ((secin_sg_flag & SECFP_SCATTER_GATHER)
			== SECFP_SCATTER_GATHER)
			pSA->prepareInDescriptorWithFrags(pHeadSkb, pSA,
						desc, 0);
		else
#endif /* CONFIG_ASF_SEC3x */
			pSA->prepareInDescriptor(pHeadSkb, pSA, desc, 0);

		/* Post submission, we can move the data pointer beyond the ESP header */
		/* Trim the length accordingly */
		/* Since we will be giving packet to fwnat processing,
		keep the data pointer as 14 bytes before data start */
		ASFIPSEC_DEBUG("In: Offseting data by ulSecHdrLen = %d",
					pSA->ulSecHdrLen);

#ifndef ASF_SECFP_PROTO_OFFLOAD
		pHeadSkb->len -= (pSA->ulSecHdrLen);
		pHeadSkb->data += (pSA->ulSecHdrLen);
		pHeadSkb->cb[SECFP_REF_INDEX]--;
		ASFIPSEC_DEBUG("IN-submit to SEC");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (pSA->SAParams.bAuth && pSA->SAParams.bDoAntiReplayCheck)
			secfp_checkSeqNum(pSA, ulSeqNum,
				ulLowerBoundSeqNum, pHeadSkb);
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
#else
		/* updating the length and data pointer of packet according
		   to the packet after decryption */
		if (likely(pSA->SAParams.ucProtocol == SECFP_PROTO_ESP)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (skb_shinfo(pHeadSkb)->frag_list)
			if (pSA->ulSecHdrLen % 8)
				ulFragpadlen = 8 - (pSA->ulSecHdrLen);
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		pHeadSkb->data += SECFP_IPV6_HDR_LEN + pSA->ulSecHdrLen + ulFragpadlen;
		pHeadSkb->len -= (SECFP_IPV6_HDR_LEN + pSA->ulSecHdrLen) - ulFragpadlen;

		}
#endif /*ASF_SECFP_PROTO_OFFLOAD*/
#endif /*ASF_QMAN_IPSEC*/

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (ASFIPSecCbFn.pFnSAExpired) {
			int cpu;
			if (pSA->SAParams.hardKbyteLimit) {
				unsigned long ulKBytes = len;
				for_each_possible_cpu(cpu) {
					ulKBytes += pSA->ulBytes[cpu];
				}
				ulKBytes = ulKBytes/1024;

				if (pSA->SAParams.softKbyteLimit <= ulKBytes) {
					saDestAddr.bIPv4OrIPv6 = 1;
					memcpy(saDestAddr.ipv6addr,
						ipv6h->daddr.s6_addr32,
						sizeof(struct in6_addr));

					if (pSA->SAParams.hardKbyteLimit <= ulKBytes) {
						bHard = ASF_TRUE;
						pHeadSkb->cb[SECFP_ACTION_INDEX] =
							SECFP_DROP;
						ASF_IPSEC_PPS_ATOMIC_INC(
							IPSec4GblPPStats_g.IPSec4GblPPStat
							[ASF_IPSEC_PP_GBL_CNT27]);
						goto sa_expired;
					} else
						bExpiry = ASF_TRUE;

					ASFIPSEC_WARN(
					"SA Expired KB=%u (hard=%d) SPI=0x%x",
					ulKBytes, bHard, pSA->SAParams.ulSPI);
				}
			}
			if (pSA->SAParams.hardPacketLimit) {
				unsigned long uPacket = 1;

				for_each_possible_cpu(cpu) {
					uPacket += pSA->ulPkts[cpu];
				}
				if (pSA->SAParams.softPacketLimit <= uPacket) {
					saDestAddr.bIPv4OrIPv6 = 1;
					memcpy(saDestAddr.ipv6addr,
						ipv6h->daddr.s6_addr32,
						sizeof(struct in6_addr));
					if (pSA->SAParams.hardPacketLimit <= uPacket) {
						bHard = ASF_TRUE;
						pHeadSkb->cb[SECFP_ACTION_INDEX] =
							SECFP_DROP;
						ASF_IPSEC_PPS_ATOMIC_INC(
							IPSec4GblPPStats_g.IPSec4GblPPStat
							[ASF_IPSEC_PP_GBL_CNT27]);
					} else
						bExpiry = ASF_TRUE;

					ASFIPSEC_WARN(
					"SA Expired Pkt=%lu (hard=%d) SPI=0x%x",
					uPacket, bHard, pSA->SAParams.ulSPI);
				}
			}
sa_expired:
			if (pHeadSkb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
				pHeadSkb->data_len = 0;
				SECFP_DESC_FREE(desc);
				ASFSkbFree(pHeadSkb);
				goto sa_error;
			}
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		pIPSecPPGlobalStats->ulTotInRecvSecPkts++;
#ifndef CONFIG_ASF_SEC4x
		update_chan_in(pSA);
		if (talitos_submit(pdev, pSA->chan, desc,
			(secin_sg_flag & SECFP_SCATTER_GATHER) ?
			pSA->inCompleteWithFrags : pSA->inComplete,
			(void *)pHeadSkb) == -EAGAIN)
#elif defined(ASF_QMAN_IPSEC)
		if (secfp_qman_in_submit(pSA, pHeadSkb))
#else
		if (caam_jr_enqueue(pSA->ctx.jrdev,
			((struct aead_edesc *)desc)->hw_desc,
			(secin_sg_flag & SECFP_SCATTER_GATHER) ?
			pSA->inCompleteWithFrags : pSA->inComplete,
			(void *)pHeadSkb))
#endif
	{
#ifdef ASFIPSEC_LOG_MSG
			ASFIPSEC_DEBUG("Inbound Submission to SEC failed");
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			AsfLogInfo.aMsg = aMsg;
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "In Crypto Operation Failed");
			asfFillLogInfo(&AsfLogInfo, pSA);
#endif
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
			pHeadSkb->data_len = 0;
			SECFP_DESC_FREE(desc);
			ASFSkbFree(pHeadSkb);
			rcu_read_unlock();
			return 0;
		}

		/* length of skb memory to unmap upon completion */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifndef CONFIG_ASF_SEC4x
		if (pSA->option[1] != SECFP_NONE) {
			pHeadSkb->cb[SECFP_REF_INDEX]++;

			desc = secfp_desc_alloc();

			if (!desc) {
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
				ASFIPSEC_WARN("desc allocation failure");
				/* Mark SKB action index to drop */
				pHeadSkb->cb[SECFP_REF_INDEX] -= 2 ;
				if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
					/* CB finished */
					ASFSkbFree(pHeadSkb);
				} else {
					pHeadSkb->cb[SECFP_ACTION_INDEX]
						= SECFP_DROP;
				}
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
			if ((secin_sg_flag & SECFP_SCATTER_GATHER)
				== SECFP_SCATTER_GATHER)
				pSA->prepareInDescriptorWithFrags(pHeadSkb,
						pSA, desc, 0);
			else
				pSA->prepareInDescriptor(pHeadSkb, pSA, desc, 0);
			if (talitos_submit(pdev, pSA->chan, desc,
				(secin_sg_flag & SECFP_SCATTER_GATHER) ?
				pSA->inCompleteWithFrags : pSA->inComplete,
				(void *)pHeadSkb) == -EAGAIN) {
				ASFIPSEC_WARN("Inbound Submission to SEC failed");

				/* Mark SKB action index to drop */
				pHeadSkb->cb[SECFP_REF_INDEX] -= 2 ;
				if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
					/* CB finished */
					ASFSkbFree(pHeadSkb);
				} else {
					pHeadSkb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				}
				SECFP_DESC_FREE(desc);
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
		}
		/* Post submission, we can move the data pointer beyond the ESP header */
		/* Trim the length accordingly */
		/* Since we will be giving packet to fwnat processing, keep the data pointer as 14 bytes before data start */
		ASFIPSEC_DEBUG("In: Offseting data by ulSecHdrLen = %d",
					pSA->ulSecHdrLen);
		if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
			ASFIPSEC_TRACE;
			SECFP_DESC_FREE(desc);
			pHeadSkb->data_len = 0;
			/* CB already finished processing the skb & there was an error*/
			ASFSkbFree(pHeadSkb);
		}
#endif /*(CONFIG_ASF_SEC3x)*/
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		/* Assumes successful processing of the Buffer */
		pSA->ulBytes[smp_processor_id()] += len;
		pSA->ulPkts[smp_processor_id()]++;
		pIPSecPolicyPPStats->NumInBoundOutPkts++;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
sa_error:
		if (unlikely(bHard || (bExpiry && !pSA->bSoftExpiry))) {
			pSA->bSoftExpiry = ASF_TRUE;
			rcu_read_unlock();

			ASFIPSecCbFn.pFnSAExpired(ulVSGId,
				pSA->pSASPDMapNode->ulSPDInContainerIndex,
				pSA->SAParams.ulSPI,
				pSA->SAParams.ucProtocol,
				saDestAddr,
				bHard,
				SECFP_IN);
			return 0;
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		rcu_read_unlock();
		return 0;
	} else {
		ASFBuffer_t Buffer;
		rcu_read_unlock();
		ASFIPSEC_DEBUG("Inbound SA Not found ");
		/* Homogenous buffer */
		Buffer.nativeBuffer = skb1;
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT23]);
#ifdef CONFIG_DPA
		asf_dec_skb_buf_count(skb1);
#endif
		if (ASFIPSecCbFn.pFnNoInSA) {
			ASFIPSecCbFn.pFnNoInSA(ulVSGId, Buffer, secfp_SkbFree,
				skb1, ulCommonInterfaceId);
		}
		return 0;
	}
}
#endif

int secfp_process_udp_encapsulator(struct sk_buff **skbuff,
	unsigned int ulVSGId,
	unsigned char *pSkipHeader,
	unsigned char *pucSkepLen)
{
	struct udphdr *uh;
	char ucNatT, ucSkipLen;
	unsigned short usIPHdrLen, usSourcePort;
	char aIpHeader[ASF_IPLEN + ASF_IP_MAXOPT];
	char aMarker[32]; /* atleast 8 bytes required */
	int mark_len = 0, expected_mark_len;
	struct sk_buff *skb = *skbuff;

	uh = (struct udphdr *) skb_transport_header(skb);
	usIPHdrLen = ip_hdr(skb)->ihl * 4;
	usSourcePort = uh->source;

/*
	if (uh->len < (SECFP_MAX_UDP_HDR_LEN + 8)) {
	return ASF_NON_NATT_PACKET;
	}
*/

	if ((uh->source == ASF_IKE_SERVER_PORT) ||
		(uh->dest == ASF_IKE_SERVER_PORT)) {

		ucNatT = ASF_IPSEC_IKE_NATtV1;

	} else if ((uh->source == ASF_IKE_NAT_FLOAT_PORT) ||
		(uh->dest == ASF_IKE_NAT_FLOAT_PORT)) {

		ucNatT = ASF_IPSEC_IKE_NATtV2;
	} else {
		/****
		* If UDP packet's port values not matching with IKE port values
		* then it is plain packet and returning with T_SUCCESS
		****/
		return ASF_NON_NATT_PACKET;
	}
	expected_mark_len = (ucNatT == ASF_IPSEC_IKE_NATtV1) ?
		ASF_IPSEC_MAX_NON_IKE_MARKER_LEN : ASF_IPSEC_MAX_NON_ESP_MARKER_LEN;

	/* skb could be a list of fragments */
	/* each fragment is expected to have at least 8 bytes
		of IP data. i.e 28 bytes of ip len */
	mark_len = ASF_MIN(expected_mark_len,
				skb->len-usIPHdrLen - SECFP_MAX_UDP_HDR_LEN);
	if (mark_len)
		memcpy(aMarker, skb->data + usIPHdrLen + SECFP_MAX_UDP_HDR_LEN,
			mark_len);

	if (mark_len < expected_mark_len) {
		if (skb_shinfo(skb)->frag_list)
			memcpy(aMarker + mark_len, skb_shinfo(skb)->frag_list->data,
				expected_mark_len - mark_len);
		else
			return ASF_NON_NATT_PACKET;
		mark_len = expected_mark_len;
	}

	if (ucNatT == ASF_IPSEC_IKE_NATtV1) {
		/****
		* If UDP packet contains the matching IKE port values
		* then check with the NON-IKE marker header
		* If not matched , then return T_SUCCESS
		****/
		if (memcmp(aMarker, aNonIkeMarker_g, ASF_IPSEC_MAX_NON_IKE_MARKER_LEN) != 0)
			return ASF_NON_NATT_PACKET;

		/* Copy the IP header */
		ucSkipLen = ASF_IPSEC_MAX_NON_IKE_MARKER_LEN + SECFP_MAX_UDP_HDR_LEN;
	} else {
		if (memcmp(aMarker, aNonESPMarker_g, ASF_IPSEC_MAX_NON_ESP_MARKER_LEN) == 0)
			return ASF_NON_NATT_PACKET;

		ucSkipLen = SECFP_MAX_UDP_HDR_LEN;
	}
#ifdef CONFIG_ASF_SEC3x

	if (skb_shinfo(skb)->frag_list) {
		if (asfReasmLinearize(&skb,
			ip_hdr(skb)->tot_len, VPN_TOT_OVHD, VPN_HDROOM)) {
			ASFIPSEC_WARN("skb->linearize failed ");
			ASFSkbFree(skb);
			*skbuff = NULL;
			return ASF_IPSEC_CONSUMED;
		}
		skb_reset_network_header(skb);
		usIPHdrLen = ip_hdr(skb)->ihl * 4;
	}
#endif
	*((unsigned short *)&skb->cb[SECFP_UDP_SOURCE_PORT]) = usSourcePort;
/* todo need to optimize it for PAC*/
	*pucSkepLen = ucSkipLen;
	memcpy(pSkipHeader, skb->data + usIPHdrLen, ucSkipLen);

	memcpy(aIpHeader, skb->data, usIPHdrLen);
	skb->data = skb->data + ucSkipLen;
	memcpy(skb->data, aIpHeader, usIPHdrLen);
	skb->len -= ucSkipLen;
	skb_reset_network_header(skb);
	ip_hdr(skb)->tot_len -= ucSkipLen;
	ip_hdr(skb)->protocol = SECFP_PROTO_ESP;
	*skbuff = skb;
	return ASF_NATT_PACKET;
}


/* Inbound IPv4 fast path handling
 * Finds the SA based on the SPI value. If SA is found,
 * it reassembles the packet if required
 * It does anti-replay check. It appends ESN to the packet
 * if enabled.
 * Then submits the packet to SEC. If multiple submissions are
 * required, multiple descriptors are prepared and submitted
 * Any packet length adjustment such as removal of outer
 * IP header/SEC header happens.
 * Post sec submission and completion, inComplete() is called by
 * flush_channel() in talitos.c file. inComplete does the remaining
 * processing such as ICV verification, updating the Sequence
 * number bitmap, doing remote gateway adaptation, SA selector
 * set verification etc. before giving packet to the firewall for
 * further procession
 * Sufficient information is passed through the skb->cb fields
 * to handle post SEC In processing.
 */
static inline int secfp_try_fastPathInv4(struct sk_buff *skb1,
			ASF_boolean_t bCheckLen, unsigned int ulVSGId,
			ASF_uint32_t ulCommonInterfaceId)
{
	unsigned int ulSPI, ulSeqNum;
	inSA_t *pSA;
	struct iphdr *iph = ip_hdr(skb1);
	unsigned int ulLowerBoundSeqNum;
	unsigned int ulHashVal = usMaxInSAHashTaleSize_g;
	struct sk_buff *pHeadSkb = NULL, *pTailSkb = NULL;
	unsigned char bScatterGather;
	unsigned int len = 0;
	char aMsg[ASF_MAX_MESG_LEN + 1];
	ASFLogInfo_t AsfLogInfo;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	AsfSPDPolicyPPStats_t *pIPSecPolicyPPStats;
	unsigned char aSkipHeader[32], ucSkipLen = 0;
	unsigned char secin_sg_flag = 0;
#ifndef ASF_QMAN_IPSEC
	unsigned int ulSecLen = 0, ulSecLenIncrease;
#endif
#ifndef CONFIG_ASF_SEC4x
	struct talitos_desc *desc = NULL;
#elif !defined(ASF_QMAN_IPSEC)
	void *desc;
#ifdef ASF_SECFP_PROTO_OFFLOAD
	unsigned int ulFragpadlen = 0;
#endif
#endif
	signed int iRetVal;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	struct sk_buff *pTailPrevSkb = 0;
#ifndef ASF_SECFP_PROTO_OFFLOAD
	int ii;
	unsigned int ulICVInPrevFrag;
	unsigned char *pCurICVLocBytePtrInPrevFrag, *pCurICVLocBytePtr;
	unsigned char *pNewICVLocBytePtr;
#endif
	unsigned int fragCnt = 0;
	ASF_boolean_t bHard = ASF_FALSE;
	ASF_boolean_t bExpiry = ASF_FALSE;
	ASF_IPAddr_t saDestAddr;
	SPDInContainer_t *pContainer;

	if (ulVSGId == ulMaxVSGs_g) {
		ASFIPSEC_DEBUG("send packet up for VSG determination");
		ASFIPSEC_DEBUG("Need to call registered callback function ");
		return 1; /* Send it up to Stack */
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	if (iph->protocol == IPPROTO_UDP) {
		iRetVal = secfp_process_udp_encapsulator(&skb1, ulVSGId,
			aSkipHeader, &ucSkipLen);

		if (iRetVal == ASF_NON_NATT_PACKET)
			return 1; /* Send it up to Stack */
		else if (iRetVal == ASF_IPSEC_CONSUMED)
			return 0;
		iph = ip_hdr(skb1);
	}

	if (((ip_hdr(skb1)->frag_off) & SECFP_MF_OFFSET_FLAG_NET_ORDER)) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		ASFIPSEC_DEBUG("should not happen: received encrypted frag %d\n", skb1->len);
		skb_reset_network_header(skb1);
		skb1 = asfIpv4Defrag(ulVSGId, skb1, NULL, NULL, NULL, &fragCnt);
		if (skb1 == NULL) {
			ASFIPSEC_DEBUG("ESP Packet absorbed by IP reasembly module");
			return 0; /*Pkt absorbed */
		}

		iph = ip_hdr(skb1);
#ifdef CONFIG_ASF_SEC3x
		ASFIPSEC_DEBUG("encrypted frags, linearizing skb %p ...\n", skb1->head);
		if (asfReasmLinearize(&skb1, iph->tot_len, VPN_TOT_OVHD, VPN_HDROOM)) {
			ASFIPSEC_WARN("skb->linearize failed ");
			ASFSkbFree(skb1);
			return 0;
		}
		fragCnt = 0;
		skb_reset_network_header(skb1);
		iph = ip_hdr(skb1);
#endif
		ASFIPSEC_FPRINT("Reassmebled Pkt received skb->len = %d", skb1->len);
		ASFIPSEC_HEXDUMP(skb1->data - 14, skb1->len);

		if (unlikely(skb1->len < ((iph->ihl*4) + SECFP_ESP_HDR_LEN))) {
			ASFIPSEC_WARN("ESP header length is invalid len = %d ", skb1->len);
			ASFSkbFree(skb1);
			return 0;
		}
#else /* ASF_MINIMUM MODE */
		ASFIPSEC_WARN("Fragmented Packets Not supported in this mode");
		return 1; /* Send it up to Stack */
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
	}
	ASFIPSEC_FPRINT("Pkt received skb->len = %d", skb1->len);
	ASFIPSEC_HEXDUMP(skb1->data - 14, skb1->len);

	rcu_read_lock();
	SECFP_EXTRACT_PKTINFO(skb1, iph, (iph->ihl*4), ulSPI, ulSeqNum)
	pSA = secfp_findInv4SA(ulVSGId, iph->protocol, ulSPI, iph->daddr, &ulHashVal);
	if (likely(pSA)) {
		/* SA Found */
		ASFIPSEC_DEBUG(" pSA Found coreId=%d", smp_processor_id());
		pIPSecPPGlobalStats = asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
		pIPSecPPGlobalStats->ulTotInRecvPkts++;

		pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
		pIPSecPolicyPPStats->NumInBoundInPkts++;

		if (unlikely(pSA->bSendPktToNormalPath)) {
			/* This can happen if SPDs have been modified and there is
					a requirement for revalidation
				*/
			ASFIPSEC_DEBUG("Need to send packet up to Normal Path");
			rcu_read_unlock();
			return 1; /* Send it up to Stack */
		}
		/* SA Found */
		/* Need to have this check when packets are coming in from upper layer, but not from the driver interface */
		if (skb_shinfo(skb1)->frag_list ||
			skb_shinfo(skb1)->nr_frags) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			pHeadSkb = skb1;
			if (skb_shinfo(skb1)->frag_list)
				for (pTailPrevSkb = skb1,
					pTailSkb = skb_shinfo(skb1)->frag_list;
					pTailSkb->next != NULL;
					pTailPrevSkb = pTailSkb,
					pTailSkb = pTailSkb->next)
					;
			else
				pHeadSkb = pTailSkb = skb1;
			bScatterGather = SECFP_SCATTER_GATHER;
			len = iph->tot_len;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		} else {
			pHeadSkb = pTailSkb = skb1;
			len = skb1->len;
			bScatterGather = SECFP_NO_SCATTER_GATHER;
		}
		secin_sg_flag = SECFP_IN|bScatterGather;
/*TBD - In the following Code, pTailSkb will not work for nr_frags.
So all these special boundary cases need to be handled for nr_frags*/
		if ((bCheckLen) && ((skb_tailroom(pTailSkb))
					< pSA->ulReqTailRoom)) {
			ASFIPSEC_WARN("Received Skb does not have"
					" enough tail room to continue");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				"SPI = 0x%x, Seq. No = %u ::"
				" No free Buffer is available."
				" Returning with out processing"
				" the packet", ulSPI, ulSeqNum);
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID1;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT9]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT9);
		}

		if (iph->tot_len < pSA->validIpPktLen) {
			ASFIPSEC_DEBUG("Invalid ESP or AH Pkt");
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1,
				"SPI = 0x%x, Seq. No = %u"
				" Packet length is less than the"
				" sum of IP Header, ESP Header length,"
				" IV and ICV length", ulSPI, ulSeqNum);
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID2;
			AsfLogInfo.aMsg = aMsg;
			asfFillLogInfo(&AsfLogInfo, pSA);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT10]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT10);
			ASFSkbFree(pHeadSkb);
			rcu_read_unlock();
			return 0;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		pContainer = (SPDInContainer_t *)(ptrIArray_getData(
				&(secfp_InDB), pSA->pSASPDMapNode->ulSPDInContainerIndex));
		if (pContainer && pContainer->SPDParams.bDPDAlive) {
			ASF_IPAddr_t DestAddr;
			DestAddr.bIPv4OrIPv6 = 0;
			DestAddr.ipv4addr = iph->daddr;
			ASFIPSEC_DEBUG("Calling DPD alive callback VSG=%u, Tunnel=%u, address=%x, Container=%u, SPI=%x", \
					ulVSGId, pSA->ulTunnelId, iph->daddr, pSA->pSASPDMapNode->ulSPDInContainerIndex, ulSPI);
			if (ASFIPSecCbFn.pFnDPDAlive)
				ASFIPSecCbFn.pFnDPDAlive(ulVSGId,
					pSA->ulTunnelId, ulSPI,
					iph->protocol, DestAddr,
					pSA->pSASPDMapNode->ulSPDInContainerIndex);
			pContainer->SPDParams.bDPDAlive = 0;
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM) */
		pHeadSkb->cb[SECFP_SECHDR_INDEX] = pSA->ulSecHdrLen;
		pHeadSkb->cb[SECFP_SECLEN_INDEX] = SECFP_IPV4_HDR_LEN;

		ulLowerBoundSeqNum = 0;
#ifndef ASF_QMAN_IPSEC
		if (likely(pSA->SAParams.ucProtocol == SECFP_PROTO_ESP)) {
#endif
			if (pSA->SAParams.bAuth) {
#ifndef ASF_SECFP_PROTO_OFFLOAD /* anti-replay check done in HW */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			unsigned int *pCurICVLoc = 0;
			if (unlikely(pTailSkb->len < pSA->SAParams.uICVSize)) {
				/* pTailPrevSkb gets initialized in the case of fragments; This case comes
				into picture only when we have fragments */
				ulICVInPrevFrag = pSA->SAParams.uICVSize - pTailSkb->len;
				pCurICVLocBytePtrInPrevFrag = skb_tail_pointer(pTailPrevSkb) - ulICVInPrevFrag;
				pCurICVLocBytePtr = pTailSkb->data;

				pTailPrevSkb->len -= ulICVInPrevFrag;
				pTailSkb->len += ulICVInPrevFrag;

				if (pSA->SAParams.bDoAntiReplayCheck) {
					pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
					if (pSA->SAParams.bUseExtendedSequenceNumber) {
						/* Packet has ICV towards the end, so we need to put the ESN and then the ICV */
						/* Leave a 4 byte gap for the ESN and move the ICV */
						/* In this case copy the entire ICV to pTailSkb->data + sizeof (unsigned int);
							Trim the previous skb->len by ulICVInPrevLen
							Update the data for the Tail frag

							Eg: Input:
							<--prevTailFrag----><-----Tail Frag------>
								<-------ICV----->

							Output:
							<-prevTailFrag-><---Tail Frag----------->
										< 1 integer gap, ICV----------->

						*/

						pNewICVLocBytePtr = pTailSkb->data + sizeof(unsigned int);

						/* Real exception case, do byte copy */
						/* Good question here would be why not pull into previous frag, but not sure if
							there will be enough room there, but we have already checked for tail room
							in tail skb */
						for (ii = pTailSkb->len - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii +
							ulICVInPrevFrag] =
							pCurICVLocBytePtr[ii];

						for (ii = ulICVInPrevFrag - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

						secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pCurICVLoc);
					} else {
						/* Copy to Tail frag */
						pNewICVLocBytePtr = pTailSkb->data;
						for (ii = pTailSkb->len - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii +
							ulICVInPrevFrag]
							= pCurICVLocBytePtr[ii];

						for (ii = ulICVInPrevFrag - 1;
								ii >= 0; ii--)
							pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

					}
				} else {
					/* Copy to Tail frag */
					pNewICVLocBytePtr = pTailSkb->data;
					for (ii = pTailSkb->len - 1;
							ii >= 0; ii--)
						pNewICVLocBytePtr[ii +
							ulICVInPrevFrag] =
							pCurICVLocBytePtr[ii];


					for (ii = ulICVInPrevFrag - 1;
							ii >= 0; ii--)
						pNewICVLocBytePtr[ii] =
						pCurICVLocBytePtrInPrevFrag[ii];

				}
			} else {
				unsigned int *pNewICVLoc = 0;
				if (pSA->SAParams.bDoAntiReplayCheck) {
					pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
					if (pSA->SAParams.ucAuthAlgo == SECFP_HMAC_AES_XCBC_MAC) {
						if (pSA->SAParams.bUseExtendedSequenceNumber) {
							*((unsigned int *)(skb_tail_pointer(pTailSkb) + SECFP_ESN_MARKER_POSITION)) = 0xAAAAAAAA;
						} else {
							*((unsigned int *)(skb_tail_pointer(pTailSkb) + SECFP_ESN_MARKER_POSITION)) = 0;
						}
					}
					if (pSA->SAParams.bUseExtendedSequenceNumber) {
						int kk;
						pCurICVLoc = (unsigned int *)(skb_tail_pointer(pTailSkb) - pSA->SAParams.uICVSize);
						pNewICVLoc = (unsigned int *)(skb_tail_pointer(pTailSkb) - pSA->SAParams.uICVSize + sizeof(unsigned int));
						for (kk = 2; kk >= 0; kk--)
							*(pNewICVLoc + kk) = *(pCurICVLoc + kk);
						secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pCurICVLoc);
					}

				} else
					ASFIPSEC_DEBUG("No Antoreplay check\n");
			}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
#endif /*ASF_SECFP_PROTO_OFFLOAD*/
		} else {
			pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 0;
			/* No need to do post SEC Lookup */
			skb_set_tail_pointer(pTailSkb, skb_headlen(pTailSkb));
			*(unsigned int *)skb_tail_pointer(pTailSkb) = 0;
		}
		/* byte offset to move past the tunnel header for ESP*/
#ifndef ASF_QMAN_IPSEC
#ifndef ASF_SECFP_PROTO_OFFLOAD
			ulSecLen = pSA->ulSecHdrLen;
#else
			ulSecLen = pSA->ulSecHdrLen + SECFP_IPV4_HDR_LEN;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (skb_shinfo(pHeadSkb)->frag_list)
				if (ulSecLen % 8)
					ulFragpadlen = (8 - (ulSecLen % 8));
			ulSecLen+= ulFragpadlen;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
#endif
			ulSecLenIncrease = 4;
		} else {

			/* check anything needed for AH  --guess none*/
			/* do not remove the tunnel header */
			unsigned int *pESNLoc = 0;
			ulSecLen = 0;
			ulSecLenIncrease = 0;

			if (pSA->SAParams.bDoAntiReplayCheck) {
				if (pSA->SAParams.bUseExtendedSequenceNumber) {
					pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1; /* To do lookup Post SEC */
					pESNLoc = (unsigned int *)
						(skb_tail_pointer(pTailSkb));
					secfp_appendESN(pSA, ulSeqNum, &ulLowerBoundSeqNum, (unsigned int *)pESNLoc);
					*(unsigned int *)&(pHeadSkb->cb[SECFP_SEQNUM_INDEX]) = ulSeqNum;
					secfp_checkSeqNum(pSA, ulSeqNum,
							ulLowerBoundSeqNum, pHeadSkb);
				}
			}
		}
#endif

		if (pSA->SAParams.bVerifyInPktWithSASelectors)
			pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX] = 1;

		/* Copying information that is required post SEC operation */
		pHeadSkb->cb[SECFP_ICV_LENGTH] = pSA->SAParams.uICVSize;
		*(unsigned int *)&(pHeadSkb->cb[SECFP_VSG_ID_INDEX]) = ulVSGId;
		*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]) = pSA->SAParams.ulSPI;
		/* Pass the skb data pointer */
		*(uintptr_t *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]) = (uintptr_t)(&(pHeadSkb->data[0]));
		*(unsigned int *)&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]) = ulHashVal;

		ASFIPSEC_DBGL2("In Packet ulSPI=%d, ipaddr_ptr=0x%x,"
			" ulHashVal= %d, Saved values: ulSPI=%d,"
			" ipaddr_ptr=0x%x, ulHashVal=%d",
			pSA->SAParams.ulSPI, (unsigned int)&(pHeadSkb->data[0]),
			ulHashVal,
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SPI_INDEX]),
			*(unsigned int *)&(pHeadSkb->cb[SECFP_IPHDR_INDEX]),
			*(unsigned int *)
			&(pHeadSkb->cb[SECFP_HASH_VALUE_INDEX]));
#ifndef ASF_SECFP_PROTO_OFFLOAD
		if (pSA->SAParams.bPropogateECN) {
			pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX] = 1;
			pHeadSkb->cb[SECFP_TOS_INDEX] = iph->tos;
		} else
			pHeadSkb->cb[SECFP_UPDATE_TOS_INDEX] = 0;

		if (pHeadSkb->cb[SECFP_LOOKUP_SA_INDEX])
			*(unsigned int *)&(pHeadSkb->cb[SECFP_SEQNUM_INDEX]) = ulSeqNum;

		/* if Proto is ESP -Move the skb data pointer  beginning of ESP header */
		/* For AH -  data pointer should still point to outer ip header */

		ASFIPSEC_DEBUG("In Offsetting data by len=%d", iph->ihl*ulSecLenIncrease);
		pHeadSkb->data += (iph->ihl * ulSecLenIncrease);
		pHeadSkb->len -= (iph->ihl*ulSecLenIncrease);
#endif
		/* Storing Common Interface Id */
		if (!pSA->ulTunnelId)
			pSA->ucIfaceId = ulCommonInterfaceId;
		else
			pSA->ucIfaceId = pSA->SAParams.ulCId;

		ASFIPSEC_DEBUG("Calling secfp-submit");
		pHeadSkb->cb[SECFP_REF_INDEX] = 2;
#ifndef ASF_QMAN_IPSEC
		desc = secfp_desc_alloc();
		if (!desc) {
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
			ASFIPSEC_WARN("desc allocation failure");
			pHeadSkb->data_len = 0;
			ASFSkbFree(pHeadSkb);
			rcu_read_unlock();
			return 0;
		}
#if defined(CONFIG_ASF_SEC3x)
		if ((secin_sg_flag & SECFP_SCATTER_GATHER)
			== SECFP_SCATTER_GATHER)
			pSA->prepareInDescriptorWithFrags(pHeadSkb, pSA,
						desc, 0);
		else
			pSA->prepareInDescriptor(pHeadSkb, pSA, desc, 0);
#else
			pSA->prepareInDescriptor(pHeadSkb, pSA, desc, 0);
#endif

		/* Post submission, we can move the data pointer beyond the ESP header */
		/* Trim the length accordingly */
		/* Since we will be giving packet to fwnat processing,
		keep the data pointer as 14 bytes before data start */
		ASFIPSEC_DEBUG("In: Offseting data by ulSecHdrLen = %d",
					ulSecLen);

#ifndef ASF_SECFP_PROTO_OFFLOAD
		pHeadSkb->len -= ulSecLen;
		pHeadSkb->data += ulSecLen;
		pHeadSkb->cb[SECFP_REF_INDEX]--;
		ASFIPSEC_DEBUG("IN-submit to SEC");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (pSA->SAParams.bAuth && pSA->SAParams.bDoAntiReplayCheck)
			secfp_checkSeqNum(pSA, ulSeqNum,
				ulLowerBoundSeqNum, pHeadSkb);
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
#else
		/* updating the length and data pointer of packet according
		   to the packet after decryption */
		pHeadSkb->data += ulSecLen;
		pHeadSkb->len -= ulSecLen;
		pTailSkb->len += ulFragpadlen;
#endif /*ASF_SECFP_PROTO_OFFLOAD*/
#endif /*ASF_QMAN_IPSEC*/

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (ASFIPSecCbFn.pFnSAExpired) {
			int cpu;
			if (pSA->SAParams.hardKbyteLimit) {
				unsigned long ulKBytes = len;
				for_each_possible_cpu(cpu) {
					ulKBytes += pSA->ulBytes[cpu];
				}
				ulKBytes = ulKBytes/1024;

				if (pSA->SAParams.softKbyteLimit <= ulKBytes) {
					saDestAddr.ipv4addr = iph->daddr;
					if (pSA->SAParams.hardKbyteLimit <= ulKBytes) {
						bHard = ASF_TRUE;
						pHeadSkb->cb[SECFP_ACTION_INDEX] =
							SECFP_DROP;
						ASF_IPSEC_PPS_ATOMIC_INC(
							IPSec4GblPPStats_g.IPSec4GblPPStat
							[ASF_IPSEC_PP_GBL_CNT27]);
						goto sa_expired;
					} else
						bExpiry = ASF_TRUE;

					ASFIPSEC_WARN(
					"SA Expired KB=%u (hard=%d) SPI=0x%x",
					ulKBytes, bHard, pSA->SAParams.ulSPI);
				}
			}
			if (pSA->SAParams.hardPacketLimit) {
				unsigned long uPacket = 1;

				for_each_possible_cpu(cpu) {
					uPacket += pSA->ulPkts[cpu];
				}
				if (pSA->SAParams.softPacketLimit <= uPacket) {
					saDestAddr.ipv4addr = iph->daddr;
					if (pSA->SAParams.hardPacketLimit <= uPacket) {
						bHard = ASF_TRUE;
						pHeadSkb->cb[SECFP_ACTION_INDEX] =
							SECFP_DROP;
						ASF_IPSEC_PPS_ATOMIC_INC(
							IPSec4GblPPStats_g.IPSec4GblPPStat
							[ASF_IPSEC_PP_GBL_CNT27]);
					} else
						bExpiry = ASF_TRUE;

					ASFIPSEC_WARN(
					"SA Expired Pkt=%lu (hard=%d) SPI=0x%x",
					uPacket, bHard, pSA->SAParams.ulSPI);
				}
			}
sa_expired:
			if (pHeadSkb->cb[SECFP_ACTION_INDEX] == SECFP_DROP) {
				pHeadSkb->data_len = 0;
				SECFP_DESC_FREE(desc);
				ASFSkbFree(pHeadSkb);
				goto sa_error;
			}
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		pIPSecPPGlobalStats->ulTotInRecvSecPkts++;
#ifndef CONFIG_ASF_SEC4x
		update_chan_in(pSA);
		if (likely(pSA->SAParams.ucProtocol == SECFP_PROTO_ESP)) {
			iRetVal = talitos_submit(pdev, pSA->chan, desc,
			(secin_sg_flag & SECFP_SCATTER_GATHER) ?
			pSA->inCompleteWithFrags : pSA->inComplete,
			(void *)pHeadSkb);
		} else {
			void *desc1;
			desc1 = (char *)desc + sizeof(struct ipsec_ah_edesc);
			iRetVal = talitos_submit(pdev, pSA->chan, (struct talitos_desc *)desc1,
					(secin_sg_flag & SECFP_SCATTER_GATHER) ?
					pSA->inCompleteWithFrags : pSA->inComplete,
					(void *)pHeadSkb);
		}
		if (iRetVal == -EAGAIN)
#elif defined(ASF_QMAN_IPSEC)
		if (secfp_qman_in_submit(pSA, pHeadSkb))
#else
		if (caam_jr_enqueue(pSA->ctx.jrdev,
			((struct aead_edesc *)desc)->hw_desc,
			(secin_sg_flag & SECFP_SCATTER_GATHER) ?
			pSA->inCompleteWithFrags : pSA->inComplete,
			(void *)pHeadSkb))
#endif
		{
#ifdef ASFIPSEC_LOG_MSG
			ASFIPSEC_DEBUG("Inbound Submission to SEC failed");
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			AsfLogInfo.aMsg = aMsg;
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "In Crypto Operation Failed");
			asfFillLogInfo(&AsfLogInfo, pSA);
#endif
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT13);
			ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT13]);
			pHeadSkb->data_len = 0;
			SECFP_DESC_FREE(desc);
			ASFSkbFree(pHeadSkb);
			rcu_read_unlock();
			return 0;
		}

		/* length of skb memory to unmap upon completion */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifndef CONFIG_ASF_SEC4x
		if (likely(pSA->SAParams.ucProtocol == SECFP_PROTO_ESP)) {
		if (pSA->option[1] != SECFP_NONE) {
			pHeadSkb->cb[SECFP_REF_INDEX]++;

			desc = secfp_desc_alloc();

			if (!desc) {
				ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT26]);
				ASFIPSEC_WARN("desc allocation failure");
				/* Mark SKB action index to drop */
				pHeadSkb->cb[SECFP_REF_INDEX] -= 2 ;
				if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
					/* CB finished */
					ASFSkbFree(pHeadSkb);
				} else {
					pHeadSkb->cb[SECFP_ACTION_INDEX]
						= SECFP_DROP;
				}
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
			if ((secin_sg_flag & SECFP_SCATTER_GATHER)
				== SECFP_SCATTER_GATHER)
				pSA->prepareInDescriptorWithFrags(pHeadSkb,
						pSA, desc, 0);
			else
				pSA->prepareInDescriptor(pHeadSkb, pSA, desc, 0);
			if (talitos_submit(pdev, pSA->chan, desc,
				(secin_sg_flag & SECFP_SCATTER_GATHER)
				? pSA->inCompleteWithFrags : pSA->inComplete,
				(void *)pHeadSkb) == -EAGAIN) {
				ASFIPSEC_WARN("Inbound Submission to SEC failed");

				/* Mark SKB action index to drop */
				pHeadSkb->cb[SECFP_REF_INDEX] -= 2 ;
				if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
					/* CB finished */
					ASFSkbFree(pHeadSkb);
				} else {
					pHeadSkb->cb[SECFP_ACTION_INDEX] = SECFP_DROP;
				}
				SECFP_DESC_FREE(desc);
				/* Increment statistics */
				rcu_read_unlock();
				return 0;
			}
		}
		}
		/* Post submission, we can move the data pointer beyond the ESP header */
		/* Trim the length accordingly */
		/* Since we will be giving packet to fwnat processing, keep the data pointer as 14 bytes before data start */
		ASFIPSEC_DEBUG("In: Offseting data by ulSecHdrLen = %d",
					pSA->ulSecHdrLen);
		if (pHeadSkb->cb[SECFP_REF_INDEX] == 0) {
			ASFIPSEC_TRACE;
			SECFP_DESC_FREE(desc);
			pHeadSkb->data_len = 0;
			/* CB already finished processing the skb & there was an error*/
			ASFSkbFree(pHeadSkb);
		}
#endif /*(CONFIG_ASF_SEC3x)*/
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		/* Assumes successful processing of the Buffer */
		pSA->ulBytes[smp_processor_id()] += len;
		pSA->ulPkts[smp_processor_id()]++;
		pIPSecPolicyPPStats->NumInBoundOutPkts++;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
sa_error:
		if (unlikely(bHard || (bExpiry && !pSA->bSoftExpiry))) {
			pSA->bSoftExpiry = ASF_TRUE;
			rcu_read_unlock();
			ASFIPSecCbFn.pFnSAExpired(ulVSGId,
				pSA->pSASPDMapNode->ulSPDInContainerIndex,
				pSA->SAParams.ulSPI,
				pSA->SAParams.ucProtocol,
				saDestAddr,
				bHard,
				SECFP_IN);
			return 0;
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		rcu_read_unlock();
		return 0;
	} else {
		ASFBuffer_t Buffer;
		rcu_read_unlock();
		ASFIPSEC_DEBUG("Inbound SA Not found ");
		/* Homogenous buffer */
		Buffer.nativeBuffer = skb1;
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT23]);
		if (ASFIPSecCbFn.pFnNoInSA) {
#ifndef ASF_SECFP_PROTO_OFFLOAD
			if (ucSkipLen) {
				unsigned short usIPHdrLen;
				char aIpHeader[ASF_IPLEN + ASF_IP_MAXOPT];
				usIPHdrLen = ip_hdr(skb1)->ihl * 4;
				memcpy(aIpHeader, skb1->data, usIPHdrLen);
				memcpy(skb1->data + usIPHdrLen - ucSkipLen,
					aSkipHeader, ucSkipLen);
				skb1->data = skb1->data - ucSkipLen;
				memcpy(skb1->data, aIpHeader, usIPHdrLen);
				skb1->len += ucSkipLen;
				skb_reset_network_header(skb1);
				ip_hdr(skb1)->tot_len += ucSkipLen;
				ip_hdr(skb1)->protocol = IPPROTO_UDP;
			}
#endif
#ifdef CONFIG_DPA
			asf_dec_skb_buf_count(skb1);
#endif
			ASFIPSecCbFn.pFnNoInSA(ulVSGId, Buffer, secfp_SkbFree,
				skb1, ulCommonInterfaceId);
		}
		return 0;
	}
}

inline int secfp_try_fastPathIn(struct sk_buff *skb1,
			ASF_boolean_t bCheckLen, unsigned int ulVSGId,
			ASF_uint32_t ulCommonInterfaceId)
{
#ifdef ASF_IPV6_FP_SUPPORT
	struct iphdr *iph = ip_hdr(skb1);
	if (iph->version == 6)
		return secfp_try_fastPathInv6(skb1, bCheckLen,
				ulVSGId, ulCommonInterfaceId);
	else
#endif
		return secfp_try_fastPathInv4(skb1, bCheckLen,
				ulVSGId, ulCommonInterfaceId);
}

/*
 * This function called from firewall checks if the given packet came on the correct SA
 * by doing SPI verification
 */
static int secfp_CheckInPkt(unsigned int ulVSGId,
		struct sk_buff *skb,
		ASF_uint32_t ulCommonInterfaceId,
		ASFFFPIpsecInfo_t *pSecInfo,
		void *pIpsecOpq) {
	SPDInSPIValLinkNode_t *pNode;
	SPDInContainer_t *pContainer;
	ASFIPSecOpqueInfo_t *pIPSecOpque;
	ASFBuffer_t Buffer;
	ASF_boolean_t bRevalidate = ASF_FALSE;

	pIPSecOpque = (ASFIPSecOpqueInfo_t *)pIpsecOpq;
	if (pSecInfo != NULL) {
		ASFIPSEC_DBGL2(" VSGId = %d, OCI= %x, OMN=%d ICN=%d IMN=%x ",
			ulVSGId,
			pSecInfo->outContainerInfo.ulSPDContainerId,
			pSecInfo->outContainerInfo.ulSPDMagicNumber,
			pSecInfo->inContainerInfo.ulSPDContainerId,
			pSecInfo->inContainerInfo.ulSPDMagicNumber);
		ASFIPSEC_DBGL2("SPI value stored in cb field of skb is %p, ",
			(void *) *(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]));

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (unlikely(pSecInfo->inContainerInfo.ulTimeStamp < ulTimeStamp_g)) {
			if ((pSecInfo->inContainerInfo.configIdentity.ulVSGConfigMagicNumber !=
				pulVSGMagicNumber[ulVSGId]) ||
				(pSecInfo->inContainerInfo.configIdentity.ulTunnelConfigMagicNumber !=
				secFP_TunnelIfaces[ulVSGId][pSecInfo->inContainerInfo.ulTunnelId].ulTunnelMagicNumber)) {
				ASFIPSEC_DBGL2("vsg %d != %d",
					pSecInfo->inContainerInfo.configIdentity.ulVSGConfigMagicNumber,
					pulVSGMagicNumber[ulVSGId]);
				bRevalidate = ASF_TRUE;
				goto callverify;
			}
			pSecInfo->inContainerInfo.ulTimeStamp = ulTimeStamp_g;
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/

		pContainer = (SPDInContainer_t *)ptrIArray_getData(&(secfp_InDB),
				pSecInfo->inContainerInfo.ulSPDContainerId);
		if (pContainer) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (ptrIArray_getMagicNum(&(secfp_InDB),
				pSecInfo->inContainerInfo.ulSPDContainerId)
			== pSecInfo->inContainerInfo.ulSPDMagicNumber) {
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
			pNode = secfp_findInSPINode(pContainer,
				*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]));
			if (pNode) {
				ASFIPSEC_DEBUG("pNode->ulSPIVal = %d: matches "\
					"with stored value", pNode->ulSPIVal);
				return 0 /* ASF_IPSEC_PROCEED */;
			} else {
				ASFIPSEC_DEBUG("Stored values don't match");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				goto callverify;
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
			}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		} else {
			ASFIPSEC_DEBUG("Stored SPD not matched");
		}
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
		} else {
			ASFIPSEC_DEBUG("SPD IN Container not found.");
		}
		ASFSkbFree(skb);
		return 1;
	}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
callverify:
#endif /*(ASF_FEATURE_OPTION > ASF_MINIMUM)*/
	ASFIPSEC_DEBUG("Calling Inbound SPD verification function");
	if (!ASFIPSecCbFn.pFnVerifySPD) {
		ASFIPSEC_DEBUG("IPsec not registered\n");
		ASFSkbFree(skb);
		return 1;
	}
	/* Homogenous buffer */
	Buffer.nativeBuffer = skb;
#ifdef CONFIG_DPA
	asf_dec_skb_buf_count(skb);
#endif
	ASFIPSecCbFn.pFnVerifySPD(*(unsigned int *)
			&(skb->cb[SECFP_VSG_ID_INDEX]),
			pIPSecOpque->ulInSPDContainerId,
			pIPSecOpque->ulInSPDMagicNumber,
			*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
			pIPSecOpque->ucProtocol,
			pIPSecOpque->DestAddr,
			Buffer,
			secfp_SkbFree,
			skb, bRevalidate, ulCommonInterfaceId);
	return 1;
}


ASF_void_t ASFIPSecEncryptAndSendPkt(ASF_uint32_t ulVsgId,
					ASF_uint32_t ulTunnelId,
					ASF_uint32_t ulSPDContainerIndex,
					ASF_uint32_t ulSPDMagicNumber,
					ASF_uint32_t ulSPI,
					ASF_IPAddr_t daddr,
					ASF_uint8_t ucProtocol,
					ASFBuffer_t Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t	*freeArg)
{
	ASFFFPIpsecInfo_t SecInfo;
	struct sk_buff *skb;
	unsigned char bHomogenous = ASF_TRUE;
	unsigned int ulSAIndex;
	SPDOutContainer_t *pOutContainer;
	SPDOutSALinkNode_t *pOutSALinkNode;
	struct sk_buff	*trailer;
	int tailbits;
	int retval;
#ifdef ASF_QOS
	outSA_t *pSA ;
#endif
	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(&(secfp_OutDB),
							ulSPDContainerIndex));

	if (!pOutContainer) {
		if (pFreeFn)
			(pFreeFn)(freeArg);
		if (!bVal)
			local_bh_enable();
		return;
	}

	if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
		ulSAIndex = ulMaxSupportedIPSecSAs_g;
	} else {
		pOutSALinkNode = secfp_findOutSALinkNode(pOutContainer,
				daddr, ucProtocol, ulSPI);
		if (!pOutSALinkNode) {
			ASFIPSEC_PRINT("SA not found");
			if (pFreeFn)
				(pFreeFn)(freeArg);
			if (!bVal)
				local_bh_enable();
			return;
		}
		ulSAIndex = pOutSALinkNode->ulSAIndex;
	}

	SecInfo.outContainerInfo.bControlPathPkt = ASF_TRUE;
	SecInfo.outContainerInfo.ulSPDContainerId = ulSPDContainerIndex;
	SecInfo.outContainerInfo.ulSPDMagicNumber = ulSPDMagicNumber;
	SecInfo.outContainerInfo.ulTunnelId = ulTunnelId;
	SecInfo.outContainerInfo.ulTimeStamp = ulTimeStamp_g;
	SecInfo.outContainerInfo.configIdentity.ulVSGConfigMagicNumber =
			pulVSGMagicNumber[ulVsgId];
	SecInfo.outContainerInfo.configIdentity.ulTunnelConfigMagicNumber =
		secFP_TunnelIfaces[ulVsgId][ulTunnelId].ulTunnelMagicNumber;
	SecInfo.outSAInfo.ulSAIndex = ulSAIndex;
	SecInfo.outSAInfo.ulSAMagicNumber =
		ptrIArray_getMagicNum(&secFP_OutSATable, ulSAIndex);
	SecInfo.natInfo.bSrcNAT = 0;
#ifdef ASF_QOS
	pSA = (outSA_t *) ptrIArray_getData(&secFP_OutSATable, ulSAIndex);
	pSA->tc_filter_res = TC_FILTER_RES_INVALID;
#endif
	if (bHomogenous) {
		skb = (struct sk_buff *)Buffer.nativeBuffer;
	} else {
		/* Freeing the buffer in case of hetrogeneous buffers*/
		if (pFreeFn)
			(pFreeFn)(freeArg);
		goto ret_stk;
	}
	tailbits = skb_tailroom(skb);
	if (skb_cloned(skb)) {
		if (skb_cow_data(skb, tailbits, &trailer) < 1) {
			if (pFreeFn)
				(pFreeFn)(freeArg);
			goto ret_stk;
		}
	}

	/* skb_linearise will do linearisation of frag_list or nr_frags
	otherwise it will just return */
	retval = skb_linearize(skb);
	if (retval) {
		if (pFreeFn)
			(pFreeFn)(freeArg);
		goto ret_stk;
	}

#ifdef CONFIG_DPA
	skb->cb[BUF_INDOMAIN_INDEX] = 0;
#endif
	if (secfp_try_fastPathOut(ulVsgId, skb, &SecInfo) != 0) {
		if (pFreeFn)
			(pFreeFn)(freeArg);
	}
ret_stk:
	if (!bVal)
		local_bh_enable();
	return;
}
EXPORT_SYMBOL(ASFIPSecEncryptAndSendPkt);

ASF_void_t ASFIPSecDecryptAndSendPkt(ASF_uint32_t ulVSGId,
					ASFBuffer_t Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t	*freeArg,
					ASF_uint32_t ulCommonInterfaceId)
{
	struct sk_buff *skb;
	unsigned char bHomogenous = ASF_TRUE;

	int bVal = in_interrupt();

	if (!bVal)
		local_bh_disable();

	if (bHomogenous) {
		skb = (struct sk_buff *)Buffer.nativeBuffer;
	} else {
		/* Freeing the buffer in case of hetrogeneous buffers*/
		if (pFreeFn)
			(pFreeFn)(freeArg);
		goto ret_stk;
	}
#ifdef CONFIG_DPA
	skb->cb[BUF_INDOMAIN_INDEX] = 0;
#endif
	if (secfp_try_fastPathIn(skb, 0, ulVSGId, ulCommonInterfaceId) != 0) {
		if (pFreeFn)
			(pFreeFn)(freeArg);
	}
ret_stk:
	if (!bVal)
		local_bh_enable();

	return;
}
EXPORT_SYMBOL(ASFIPSecDecryptAndSendPkt);
inline void asfFillLogInfo(ASFLogInfo_t *pAsfLogInfo , inSA_t *pSA)
{
	int ii;
	if (!ASFIPSecCbFn.pFnAuditLog)
		return;
	pAsfLogInfo->u.IPSecInfo.ucDirection = 0;
	pAsfLogInfo->ulVSGId = pSA->ulVSGId;
	pAsfLogInfo->u.IPSecInfo.ucDirection = 0;
	pAsfLogInfo->u.IPSecInfo.ulSPDContainerIndex = pSA->pSASPDMapNode->ulSPDInContainerIndex;
	for_each_possible_cpu(ii) {
		pAsfLogInfo->u.IPSecInfo.ulNumOfPktsProcessed += pSA->ulPkts[ii];
		pAsfLogInfo->u.IPSecInfo.ulNumOfBytesProcessed += pSA->ulBytes[ii];
	}
	pAsfLogInfo->u.IPSecInfo.ucProtocol = pSA->SAParams.ucProtocol;
	pAsfLogInfo->u.IPSecInfo.ulSeqNumber = pSA->ulLastSeqNum;
	pAsfLogInfo->u.IPSecInfo.ulPathMTU = pSA->ulRcvMTU;
	pAsfLogInfo->u.IPSecInfo.ulSPI = pSA->SAParams.ulSPI;
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 0) {
		pAsfLogInfo->u.IPSecInfo.Address.IP_Version = 4;
		pAsfLogInfo->u.IPSecInfo.Address.srcIP.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		pAsfLogInfo->u.IPSecInfo.Address.dstIP.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
	}
#ifdef ASF_IPV6_FP_SUPPORT
	else {
		pAsfLogInfo->u.IPSecInfo.Address.IP_Version = 6;
		memcpy(pAsfLogInfo->u.IPSecInfo.Address.srcIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
		memcpy(pAsfLogInfo->u.IPSecInfo.Address.dstIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
	}
#endif
	ASFIPSecCbFn.pFnAuditLog(pAsfLogInfo);
}

void asfFillLogInfoOut(ASFLogInfo_t *pAsfLogInfo, outSA_t *pSA)
{
	int ii;
	if (!ASFIPSecCbFn.pFnAuditLog)
		return;
	pAsfLogInfo->u.IPSecInfo.ucDirection = 1;
	for_each_possible_cpu(ii) {
		pAsfLogInfo->u.IPSecInfo.ulNumOfPktsProcessed += pSA->ulPkts[ii];
		pAsfLogInfo->u.IPSecInfo.ulNumOfBytesProcessed += pSA->ulBytes[ii];
	}
	pAsfLogInfo->u.IPSecInfo.ucProtocol = pSA->SAParams.ucProtocol;
	pAsfLogInfo->u.IPSecInfo.ulSeqNumber = 0xffff;
	pAsfLogInfo->u.IPSecInfo.ulPathMTU = pSA->ulInnerPathMTU;
	pAsfLogInfo->u.IPSecInfo.ulSPI = pSA->SAParams.ulSPI;
	if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6 == 0) {
		pAsfLogInfo->u.IPSecInfo.Address.IP_Version = 4;
		pAsfLogInfo->u.IPSecInfo.Address.srcIP.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		pAsfLogInfo->u.IPSecInfo.Address.dstIP.ipv4addr = pSA->SAParams.tunnelInfo.addr.iphv4.daddr;
	}
#ifdef ASF_IPV6_FP_SUPPORT
	else {
		pAsfLogInfo->u.IPSecInfo.Address.IP_Version = 6;
		memcpy(pAsfLogInfo->u.IPSecInfo.Address.srcIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
		memcpy(pAsfLogInfo->u.IPSecInfo.Address.dstIP.ipv6addr,
				pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
	}
#endif

	ASFIPSecCbFn.pFnAuditLog(pAsfLogInfo);
}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
static int ASFIPSec4SendIcmpErrMsg (unsigned char *pOrgData,
				unsigned char ucType,
				unsigned char ucCode,
				unsigned int ulUnused,
				unsigned int ulSNetId)
{
	unsigned char *pData;
	struct rtable *pRt = NULL;
	struct iphdr *iph;
	struct sk_buff *pSkb;
	unsigned char iplen;
	struct flowi fl = {};
	struct in_device *in_dev;
	struct dst_entry *dst;
	struct neighbour *neigh;

	pSkb = ASFKernelSkbAlloc(1024, GFP_ATOMIC);

	if (pSkb) {
		pSkb->data += 128; /* Reserve space to avoid reallocation */
		pSkb->data += ASF_IPLEN + ASF_ICMPLEN;
		iplen = ((*(unsigned char *)(pOrgData) & 0xf) << 2);
		memcpy(pSkb->data, pOrgData, iplen + 8);

		/* Fill Icmp Hdr */
		pSkb->data -= ASF_ICMPLEN;
		pData = pSkb->data;
		pData[0] = ucType;
		pData[1] = ucCode;
		pData[2] = 0;
		pData[3] = 0;
		BUFPUT32(&pData[4], ulUnused);
		BUFPUT16(&pData[2], ASFIPCkSum((char *)pSkb->data, iplen + 8 + ASF_ICMPLEN));
		pSkb->data -= ASF_IPLEN;
		skb_reset_network_header(pSkb);
		skb_set_transport_header(pSkb, ASF_IPLEN);

		iph = ip_hdr(pSkb);
		iph->version = 4;
		iph->ihl = 5;
		iph->check = 0;
		iph->ttl = SECFP_IP_TTL;
		iph->id = secfp_getNextId();
		iph->tos = 0;
		iph->frag_off = 0;

		iph->daddr = BUFGET32((unsigned char *)(pOrgData + 12));
		iph->protocol = SECFP_IPPROTO_ICMP;
		pSkb->protocol = __constant_htons(ETH_P_IP);
		iph->tot_len = htons(ASF_IPLEN + ASF_ICMPLEN + iplen + 8);
		pSkb->len = htons(iph->tot_len);


	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		fl.fl4_dst =  iph->daddr;
		if (ip_route_output_key(&init_net, &pRt, &fl)) {
	#else
		fl.u.ip4.daddr = iph->daddr;
		pRt = ip_route_output_key(&init_net, &fl.u.ip4);
		if (IS_ERR(pRt)) {
	#endif

			ASFKernelSkbFree(pSkb);
			return 1;
		}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36)
		skb_dst_set(pSkb, dst_clone(&(pRt->dst)));
#else
		skb_dst_set(pSkb, dst_clone(&pRt->u.dst));
#endif
		ip_rt_put(pRt);
		dst = skb_dst(pSkb);
		pSkb->dev = dst->dev;
		in_dev = (struct in_device *)(pSkb->dev->ip_ptr);
		if ((in_dev == NULL) || (in_dev->ifa_list == NULL)) {
			ASFKernelSkbFree(pSkb);
			return 1;
		}
		iph->saddr = htonl(in_dev->ifa_list->ifa_local);
		BUFPUT16(&iph->check, ASFIPCkSum((char *)pSkb->data, ASF_IPLEN));

		neigh = dst_neigh_lookup_skb(dst, pSkb);
		if (neigh) {
			dst_neigh_output(dst, neigh, pSkb);
			rcu_read_unlock();
		} else
			ASFKernelSkbFree(pSkb);


	}
	return 0;
}
#endif

unsigned short ASFIPCkSum(char *data, unsigned short cnt)
{
	unsigned short cnt1;
	unsigned int sum = 0, csum;
	unsigned short csum1;
	char	*pUp;
	bool swap = ASF_FALSE;

	cnt1 = cnt;
	pUp = (char *)data;
	csum = csum1 = 0;

	if (((uintptr_t)pUp) & 1) {
	/* Handle odd leading byte */
		csum = ((unsigned short)UCHAR(*pUp++) << 8);
		cnt1--;
		swap = !swap;
	}

	if (cnt1 > 1) {
		csum1 = ASFascksum((unsigned short *)pUp, (cnt1 >> 1));
		if (swap)
			csum1 = (csum1 << 8) | (csum1 >> 8);
		csum += csum1;
	}

	if (cnt1 & 1) {
		if (swap)
			csum += UCHAR(pUp[--cnt1]);
		else
			csum += ((unsigned short)UCHAR(pUp[--cnt1]) << 8);
	}
	sum += csum;

	/* Do final end-around carry, complement and return */

	return (unsigned short)(~(ASFIpEac (sum)) & 0xffff);
}

unsigned short ASFascksum(unsigned short *pusData, unsigned short usLen)
{
	unsigned int sum = 0;
	unsigned short csum1, csum2;
	char *pSum;

	for (; usLen; usLen--)
		sum += *pusData++;

	csum1 = ASFIpEac(sum) & 0xffffl;

	pSum = (char *)&csum1;
	csum2 = csum1;

	BUFPUT16(pSum, csum2);
	return csum1;
}

unsigned short ASFIpEac(unsigned int sum) /* Carries in high order 16 bits */{
	unsigned short csum;

	while ((csum = ((sum >> 16)&0xffffl)) != 0)
		sum = csum + (sum & 0xffffL);

	return (unsigned short) (sum & 0xffffl); /* Chops to 16 bits */
}
