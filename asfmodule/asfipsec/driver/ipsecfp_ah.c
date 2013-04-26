/**************************************************************************
 * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecfp_ah.c
 * Description: Contains the routines for ipsec AH protocol implementation
 * Authors:	Kalyani Chowdhury <B39211@freescale.com>
 *
 */
/* History
 * Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#include <linux/ip.h>
#include <net/ip.h>
#include <linux/device.h>
#include <linux/crypto.h>
#include <linux/skbuff.h>
#include <linux/route.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include <linux/version.h>
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asfmpool.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfcmn.h"
#include "../../asfffp/driver/asfterm.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include <net/dst.h>
#include <net/route.h>
#include <linux/kernel.h>
#include <linux/inetdevice.h>
#include "dcl.h"
#include "ipseccmn.h"
extern struct device *pdev;
#ifndef ASF_QMAN_IPSEC
extern struct kmem_cache *icv_cache;
#ifdef ASFIPSEC_SEC_ICV_RECYCLING
void *icv_rec_queue[NR_CPUS][ASF_MAX_IPSEC_RECYCLE_ICV];
static unsigned int curr_icv[NR_CPUS];
#endif
inline void *secfp_ah_icv_alloc(void);
inline void secfp_ah_icv_free(void *icv);
#endif

#ifdef ASF_TERM_FP_SUPPORT
extern ASFTERMProcessPkt_f	pTermProcessPkt;
#endif

extern secfp_desc_free(void *desc);
extern void secfp_inCompleteUpdateIpv4Pkt(struct sk_buff *pHeadSkb);
extern void asfFillLogInfo(ASFLogInfo_t *pAsfLogInfo , inSA_t *pSA);
extern int secfp_inCompleteSAProcess(struct sk_buff **pSkb,
					ASFIPSecOpqueInfo_t *pIPSecOpaque,
					unsigned char ucProto,
					unsigned int *pulCommonInterfaceId);
void secfp_inAHComplete(struct device *dev,
		u32 *pdesc,
		u32 err, void *context);
int secfp_createAHInCaamCtx(inSA_t *pSA);
int secfp_createAHOutCaamCtx(outSA_t *pSA);
int secfp_buildAHProtocolDesc(struct caam_ctx *ctx,
	void *pSA, int dir);

static inline uint32_t *cmd_insert_bkey(
	uint32_t	*descwd,
	uint8_t		*key,
	uint32_t	keylen,
	enum ref_type	sgref,
	enum key_dest	dest,
	enum key_cover	cover,
	enum item_inline	imm,
	enum item_purpose	purpose);

unsigned int secfp_genCaamSplitKey(struct caam_ctx *ctx,
					const u8 *key_in, u32 authkeylen);
int32_t secfp_cnstr_shdsc_hmac(uint32_t *descbuf, uint16_t *bufsize,
			uint8_t *algkey, uint32_t cipher, u_int8_t keylen, uint8_t *icv,
			uint8_t clear, enum key_dest keydest,
			enum key_cover keycover);
int32_t secfp_cnstr_shdsc_xcbc(uint32_t *descbuf, uint16_t *bufsize,
			uint8_t *algkey, uint32_t cipher, u_int8_t keylen, uint8_t *icv,
			uint8_t clear, enum key_dest keydest,
			enum key_cover keycover);
int secfp_cnstr_seq_jobdesc(uint32_t *jobdesc, uint16_t *jobdescsz,
			uint32_t *shrdesc, uint16_t shrdescsz,
			void *inbuf, uint32_t insize,
			void *outbuf, uint32_t outsize, uint32_t flag);

static inline ASF_void_t secfp_SkbFree(ASF_void_t *freeArg)
{
	ASFSkbFree(freeArg);
}

extern __be16 secfp_IPv4_IDs[NR_CPUS];
static inline __be16 secfp_getNextId(void)
{
	/* Stub : To be filled */
	return secfp_IPv4_IDs[smp_processor_id()]++;
}


#ifndef ASF_QMAN_IPSEC
inline void *secfp_ah_icv_alloc(void)
{
#ifndef ASFIPSEC_SEC_ICV_RECYCLING
	return kmem_cache_alloc(icv_cache, GFP_DMA | GFP_ATOMIC);
#else
	u32 smp_processor_id = smp_processor_id();
	u32 current_eicv = curr_icv[smp_processor_id];
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	if (unlikely(current_eicv == 0)) {
		return kmem_cache_alloc(icv_cache, GFP_DMA | flags);
	} else {
		curr_icv[smp_processor_id] = current_eicv - 1;
		return icv_rec_queue[smp_processor_id][current_eicv - 1];
	}
#endif
}

inline void secfp_ah_icv_free(void *icv)
{
#ifndef ASFIPSEC_SEC_DESC_RECYCLING
	kmem_cache_free(icv_cache, icv);
#else
	u32 smp_processor_id = smp_processor_id();
	u32 current_eicv = curr_icv[smp_processor_id];
	if (icv == NULL)
		return ;
	if (unlikely(current_eicv == (MAX_IPSEC_RECYCLE_ICV - 1))) {
		kmem_cache_free(icv_cache, icv);
	} else {
		icv_rec_queue[smp_processor_id][current_eicv] = icv;
		curr_icv[smp_processor_id] = current_eicv + 1;
	}
#endif
	return;
}
static inline void secfp_ahdesc_free_frags(void *desc, struct sk_buff *skb)
{
	struct ipsec_ah_edesc *edesc = desc;
#if defined(SECFP_SG_SUPPORT) && defined(CONFIG_ASF_SEC4x)
	struct link_tbl_entry *link_ptr;
	if (skb_shinfo(skb)->nr_frags) {
		link_ptr = edesc->link_tbl;
		dma_unmap_single(pdev, edesc->link_tbl_dma,
		edesc->link_tbl_bytes, DMA_BIDIRECTIONAL);
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
		kfree(edesc->link_tbl);
	}
#endif
	dma_unmap_single(pdev, edesc->icv_dma, edesc->icv_bytes, DMA_BIDIRECTIONAL);
	if (edesc->in_icv)
		secfp_ah_icv_free(edesc->in_icv);
	secfp_ah_icv_free(edesc->icv);
	secfp_desc_free(desc);
}
#endif
static inline unsigned int secfp_inHandleAHICVCheck(void *dsc, struct sk_buff *skb)
{
	struct ipsec_ah_edesc *edesc = (struct ipsec_ah_edesc *)dsc;

	ASFIPSEC_DEBUG("Received ICV=%x, len=%d:", edesc->in_icv, skb->cb[SECFP_ICV_LENGTH]);
	ASFIPSEC_HEXDUMP(edesc->in_icv, skb->cb[SECFP_ICV_LENGTH]);
	ASFIPSEC_DEBUG("Computed ICV: %x\n", edesc->icv);
	ASFIPSEC_HEXDUMP(edesc->icv, skb->cb[SECFP_ICV_LENGTH]);
	if (!memcmp(edesc->in_icv, edesc->icv, skb->cb[SECFP_ICV_LENGTH])) {
		ASFIPSEC_DEBUG("exit ");
		return 0;
	}
	ASFIPSEC_DEBUG("exit failure");
	return -1;
}

static inline void secfp_copyAHIcv(struct sk_buff *skb, void *desc, outSA_t *pSA)
{
	u8 ii;
	struct ipsec_ah_edesc *edesc = (struct ipsec_ah_edesc *)desc;
	ASFIPSEC_DEBUG("copying ICV len=%d", pSA->SAParams.uICVSize);
#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii]
				= edesc->icv[ii];
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii]
				= edesc->icv[ii];
	}
#endif
}

#ifdef ASF_QMAN_IPSEC
static inline unsigned int secfp_inHandleAHQmanICVCheck(struct sk_buff *skb,
					struct ses_pkt_info *pInfo)
{

	ASFIPSEC_DEBUG("Received ICV=%x, len=%d:", pInfo->in_icv, skb->cb[SECFP_ICV_LENGTH]);
	ASFIPSEC_HEXDUMP(pInfo->in_icv, skb->cb[SECFP_ICV_LENGTH]);
	ASFIPSEC_DEBUG("Computed ICV: %x\n", skb->data[-(pInfo->dynamic)]);
	ASFIPSEC_HEXDUMP((skb->data - pInfo->dynamic), skb->cb[SECFP_ICV_LENGTH]);
	if (!memcmp(pInfo->in_icv, (skb->data - pInfo->dynamic),
				skb->cb[SECFP_ICV_LENGTH])) {
		ASFIPSEC_DEBUG("exit ");
		return 0;
	}
	ASFIPSEC_DEBUG("exit failure");
	return -1;
}

static inline void secfp_copyAHIcvQman(struct sk_buff *skb, outSA_t *pSA)
{
	u8 ii;
	ASFIPSEC_DEBUG("copying ICV len=%d", pSA->SAParams.uICVSize);
#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii]
				= skb->data[ii - pSA->ctx.split_key_len];
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii]
				= skb->data[ii - pSA->ctx.split_key_len];
	}
#endif
}
#endif

int secfp_updateAHInSA(inSA_t *pSA, SAParams_t *pSAParams)
{

	unsigned char mdpadlen[] = { 16, 20, 32, 32, 64, 64 };
	unsigned char ucRemainder;

	ASFIPSEC_DEBUG("Secfp_updateAHInSA entry: ");
	/* if AH is configured, encryption alg should not be passed */
	if (pSAParams->ucCipherAlgo) {
		ASFIPSEC_WARN("If AH protocol selected,encryption alg should not be "
			"passed");
		return -1;
	}

	memcpy(&pSA->SAParams, pSAParams, sizeof(SAParams_t));

	if (pSA->SAParams.bAuth) {
			switch (pSA->SAParams.ucAuthAlgo) {
			case SECFP_HMAC_MD5:
				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_MD5 |
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_MD5|
						OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);

				ASFIPSEC_DEBUG("AuthAlgo = %d\n", pSA->SAParams.ucAuthAlgo);
				break;
			case SECFP_HMAC_SHA1:
				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA1 |
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA1 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);

				ASFIPSEC_DEBUG("AuthAlgo = %d\n", pSA->SAParams.ucAuthAlgo);
				break;
			case SECFP_HMAC_AES_XCBC_MAC:
				pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
						OP_ALG_AAI_XCBC_MAC;
				pSA->ctx.alg_op = OP_TYPE_CLASS1_ALG |
							OP_ALG_ALGSEL_AES;
				pSA->ctx.split_key_pad_len = pSA->SAParams.AuthKeyLen;
				pSA->ctx.split_key_len = pSA->SAParams.AuthKeyLen;

				ASFIPSEC_DEBUG("AuthAlgo = %d \n", pSA->SAParams.ucAuthAlgo);
				break;
			case SECFP_HMAC_SHA256:
				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA256 |
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA256 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);
				ASFIPSEC_DEBUG("AuthAlgo = %d\n", pSA->SAParams.ucAuthAlgo);
				break;
			case SECFP_HMAC_SHA384:
				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA384 |
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA384 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);
				ASFIPSEC_DEBUG("AuthAlgo = %d\n", pSA->SAParams.ucAuthAlgo);
				break;
			case SECFP_HMAC_SHA512:
				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA512|
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA512 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);
				break;
			default:
				ASFIPSEC_WARN("unsupported ucAuthAlgo %d\n", pSA->SAParams.ucAuthAlgo);
			return -1;
		}
	} else {
			ASFIPSEC_WARN("AuthAlgo not configured for AH mode\n");
			return -1;
	}

	/* compute AH padding length */
#ifdef ASF_IPV6_FP_SUPPORT
	if (pSAParams->tunnelInfo.bIPv4OrIPv6) {
		ucRemainder = ((pSA->SAParams.uICVSize + SECFP_AH_FIXED_HDR_LEN) % 8);
		if (ucRemainder > 0)
			pSA->SAParams.ucAHPaddingLen = 8 - ucRemainder;
	} else
#endif
	{
		ucRemainder = ((pSA->SAParams.uICVSize + SECFP_AH_FIXED_HDR_LEN) % 4);
		if (ucRemainder > 0)
			pSA->SAParams.ucAHPaddingLen = 4 - ucRemainder;
	}

	pSA->ulSecHdrLen = SECFP_AH_FIXED_HDR_LEN + pSA->SAParams.uICVSize + pSA->SAParams.ucAHPaddingLen;

	pSA->ulReqTailRoom = 0;
	if (pSA->SAParams.bUseExtendedSequenceNumber)
		pSA->ulReqTailRoom += SECFP_HO_SEQNUM_LEN;

	pSA->option[1] = SECFP_NONE;

	pSA->inComplete = secfp_inAHComplete;
#ifdef SECFP_SG_SUPPORT
	pSA->inCompleteWithFrags = secfp_inAHComplete;
#endif

	if (secfp_createAHInCaamCtx(pSA)) {
		ASFIPSEC_DEBUG("secfp_createAHInCaamCtx returnfailure");
		return SECFP_FAILURE;
	}

	ASFIPSEC_DEBUG("Secfp_updateAHInSA exit: ");
	return 0;
}


int secfp_updateAHOutSA(outSA_t *pSA, void *buff)
{
	SAParams_t *pSAParams = (SAParams_t *)(buff);
	unsigned char mdpadlen[] = { 16, 20, 32, 32, 64, 64 };
	unsigned char ucRemainder;

	ASFIPSEC_DEBUG("Secfp_updateAHOutSA entry: ");
	/* if AH is configured, encryption alg should not be passed */
	if (pSAParams->ucCipherAlgo) {
		ASFIPSEC_WARN("If AH protocol selected,encryption alg should not be "
			"passed");
		return -1;
	}
	memcpy(&pSA->SAParams, pSAParams, sizeof(SAParams_t));
	if (pSA->SAParams.bAuth) {
			switch (pSAParams->ucAuthAlgo) {
			case SECFP_HMAC_MD5:

				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_MD5 |
							OP_ALG_AAI_HMAC_PRECOMP;

				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
						OP_ALG_ALGSEL_MD5 |
						OP_ALG_AAI_HMAC;

				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
						OP_ALG_ALGSEL_SUBMASK) >>
						OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);

			ASFIPSEC_DEBUG("ucAuthAlgo %d\n", pSAParams->ucAuthAlgo);
				break;
			case SECFP_HMAC_SHA1:

				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA1 |
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA1 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);

				ASFIPSEC_DEBUG("ucAuthAlgo %d\n", pSAParams->ucAuthAlgo);
			break;
			case SECFP_HMAC_AES_XCBC_MAC:

				pSA->ctx.class1_alg_type = OP_TYPE_CLASS1_ALG |
							OP_ALG_AAI_XCBC_MAC;
				pSA->ctx.alg_op = OP_TYPE_CLASS1_ALG |
						OP_ALG_ALGSEL_AES;
				pSA->ctx.split_key_len = pSA->SAParams.AuthKeyLen;
				pSA->ctx.split_key_pad_len = pSA->SAParams.AuthKeyLen;

				ASFIPSEC_DEBUG("ucAuthAlgo %d\n", pSAParams->ucAuthAlgo);
			break;
			case SECFP_HMAC_SHA256:

				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA256 |
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA256 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);

				ASFIPSEC_DEBUG("ucAuthAlgo %d\n", pSAParams->ucAuthAlgo);
			break;
			case SECFP_HMAC_SHA384:

				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA384 |
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA384 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);

				ASFIPSEC_DEBUG("ucAuthAlgo %d\n", pSAParams->ucAuthAlgo);
			break;
			case SECFP_HMAC_SHA512:

				pSA->ctx.class2_alg_type = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA512|
							OP_ALG_AAI_HMAC_PRECOMP;
				pSA->ctx.alg_op = OP_TYPE_CLASS2_ALG |
							OP_ALG_ALGSEL_SHA512 |
							OP_ALG_AAI_HMAC;
				pSA->ctx.split_key_len = mdpadlen[(pSA->ctx.alg_op &
							OP_ALG_ALGSEL_SUBMASK) >>
							OP_ALG_ALGSEL_SHIFT] * 2;
				pSA->ctx.split_key_pad_len =
						ALIGN(pSA->ctx.split_key_len, 16);

				ASFIPSEC_DEBUG("ucAuthAlgo %d\n", pSAParams->ucAuthAlgo);
			break;
			default:
				ASFIPSEC_WARN("unsupported ucAuthAlgo %d\n",
				pSAParams->ucAuthAlgo);
			return -1;
		}

	} else{
		ASFIPSEC_WARN("AuthAlgo Not configured for AH mode!\n");
		return -1;
	}

	pSA->ipHdrInfo.bIpVersion =
			pSA->SAParams.tunnelInfo.bIPv4OrIPv6;
	/* Prepare the IP header and keep it for reuse */
	if (!pSA->ipHdrInfo.bIpVersion) { /* IPv4 */
		pSA->ipHdrInfo.hdrdata.iphv4.version = 4;
		pSA->ipHdrInfo.hdrdata.iphv4.ihl = 5;
		if (!pSA->SAParams.bCopyDscp)
			pSA->ipHdrInfo.hdrdata.iphv4.tos =
					pSA->SAParams.ucDscp;
		else
			pSA->ipHdrInfo.hdrdata.iphv4.tos = 0;
		pSA->ipHdrInfo.hdrdata.iphv4.tot_len = 0;
		pSA->ipHdrInfo.hdrdata.iphv4.id = 0;
		pSA->ipHdrInfo.hdrdata.iphv4.protocol = SECFP_PROTO_AH;
		pSA->ipHdrInfo.hdrdata.iphv4.check = 0;
		pSA->ipHdrInfo.hdrdata.iphv4.saddr =
			pSA->SAParams.tunnelInfo.addr.iphv4.saddr;
		pSA->ipHdrInfo.hdrdata.iphv4.daddr =
			pSA->SAParams.tunnelInfo.addr.iphv4.daddr;

		/* mutable fields are set to zero */
		pSA->ipHdrInfo.hdrdata.iphv4.frag_off = 0;
		pSA->ipHdrInfo.hdrdata.iphv4.ttl = 0;
		pSA->ipHdrInfo.hdrdata.iphv4.tos = 0;

		/* compute AH padding length */
		ucRemainder = ((pSAParams->uICVSize + SECFP_AH_FIXED_HDR_LEN) % 4);
		if (ucRemainder > 0)
			 pSA->SAParams.ucAHPaddingLen = 4 - ucRemainder;

		pSA->ulSecOverHead = SECFP_IPV4_HDR_LEN
			+ SECFP_AH_FIXED_HDR_LEN + pSA->SAParams.uICVSize + pSAParams->ucAHPaddingLen;
		pSA->ulSecLenIncrease = SECFP_IPV4_HDR_LEN;
		ASFIPSEC_DEBUG("pSA->ulSecOverHead=%d", pSA->ulSecOverHead);
	} else { /* Handle IPv6 case */
#ifdef ASF_IPV6_FP_SUPPORT
		pSA->ipHdrInfo.hdrdata.iphv6.version = 6;
		pSA->ipHdrInfo.hdrdata.iphv6.priority = 0;
		memset(pSA->ipHdrInfo.hdrdata.iphv6.flow_lbl, 0, 3);
		pSA->ipHdrInfo.hdrdata.iphv6.payload_len = 0;

		pSA->ipHdrInfo.hdrdata.iphv6.nexthdr = SECFP_PROTO_AH;
		pSA->ipHdrInfo.hdrdata.iphv6.hop_limit = SECFP_IP_TTL;
		memcpy(pSA->ipHdrInfo.hdrdata.iphv6.saddr.s6_addr32,
			pSA->SAParams.tunnelInfo.addr.iphv6.saddr, 16);
		memcpy(pSA->ipHdrInfo.hdrdata.iphv6.daddr.s6_addr32,
			pSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
		/* compute AH padding length */
		ucRemainder = ((pSAParams->uICVSize + SECFP_AH_FIXED_HDR_LEN) % 8);
		if (ucRemainder > 0)
			pSA->SAParams.ucAHPaddingLen = 8 - ucRemainder;

		pSA->ulSecOverHead = SECFP_IPV6_HDR_LEN
			+ SECFP_AH_FIXED_HDR_LEN + pSA->SAParams.uICVSize + pSAParams->ucAHPaddingLen;
		pSA->ulSecLenIncrease = SECFP_IPV6_HDR_LEN;
#endif
	}
	pSA->prepareOutPktFnPtr = secfp_prepareOutAHPacket;
	pSA->finishOutPktFnPtr = secfp_finishOutAHPacket;
	pSA->outComplete = secfp_outAHComplete;
#ifndef ASF_QMAN_IPSEC
	pSA->prepareOutDescriptor = secfp_prepareAHOutDescriptor;
	pSA->prepareOutDescriptorWithFrags = secfp_prepareAHOutDescriptor;
#endif
	pSA->ulSecHdrLen = SECFP_AH_FIXED_HDR_LEN + pSA->SAParams.uICVSize + pSA->SAParams.ucAHPaddingLen;
	ASFIPSEC_DEBUG("pSA->ulSecHdrLen = %d, pSA->SAParams.uICVSiz=%d, pSA->SAParams.ucAHPaddingLen=%d",
			pSA->ulSecHdrLen, pSA->SAParams.uICVSize, pSA->SAParams.ucAHPaddingLen);
	pSA->bSoftExpiry = 0;
	/* starting the seq number from 2 to avoid the conflict
	with the Networking Stack seq number */
	atomic_set(&pSA->ulLoSeqNum, 2);


	pSA->ulCompleteOverHead = pSA->ulSecOverHead;
	pSA->ulCompleteOverHead += pSA->SAParams.ulBlockSize;

	ASFIPSEC_DEBUG(" Overhead = %d", pSA->ulCompleteOverHead);

	ASFIPSEC_DEBUG("IV=%d, Overhead=%d block=%d iMtu=%d secOH=%d, NAT=%d",
		pSA->SAParams.ulIvSize, pSA->ulCompleteOverHead,
		pSA->SAParams.ulBlockSize, pSA->ulInnerPathMTU,
		pSA->ulSecOverHead, pSA->usNatHdrSize);


	pSA->option[1] = SECFP_NONE;

	if (secfp_createAHOutCaamCtx(pSA)) {
			ASFIPSEC_DEBUG("secfp_createAHOutCaamCtx"\
					"Failed");
			secfp_freeOutSA((struct rcu_head *)pSA);
			return SECFP_FAILURE;
	}

	ASFIPSEC_FPRINT("split_key_len %d split_key_pad_len %d",
		pSA->ctx.split_key_len, pSA->ctx.split_key_pad_len);
	ASFIPSEC_HEXDUMP(pSA->ctx.key, pSA->SAParams.AuthKeyLen);

	ASFIPSEC_DEBUG("Secfp_updateAHOutSA exit: ");

	return 0;
}



/*
 * Outbound packet processing is split as follows -
 * Lookup SA
 * prepare the packet sufficiently for SEC processing such as SEC header
 * addition, padding etc. This is done in prepareOutPacket function. Also required
 * information is copied from the inner IP header to the outer IP header
 * Then prepareOutDescriptor is called to prepare the descriptor. Then
 * descriptor is submitted to caam driver for SEC processing.
 * While SEC is processing, finishOutAHPacket is called by core. This will finish
 * the remaining processing including updating the outer IP header, adjusting
 * the length, skb data, preparing the ethernet header etc.
 * when SEC completes, it calls outComplete, which will call the ethernet
 * driver transmit.
 *
 */

void
secfp_finishOutAHPacket(struct sk_buff *skb, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int *pOuterIpHdr,
		unsigned int ulVSGId,
		unsigned int ulSPDContainerIndex)
{
	AsfSPDPolicyPPStats_t *pIPSecPolicyPPStats;


	/* Update SA Statistics */
	pSA->ulPkts[smp_processor_id()]++;
	pSA->ulBytes[smp_processor_id()] += skb->len - SECFP_IPV4_HDR_LEN - pSA->ulSecHdrLen;
	pIPSecPolicyPPStats = &(pSA->PolicyPPStats[smp_processor_id()]);
	pIPSecPolicyPPStats->NumOutBoundOutPkts++;

	return;
}

/*
 * Prepares packet for SEC submission: including setting up AH header, sequence
 * number etc.
 */

void
secfp_prepareOutAHPacket(struct sk_buff *skb1, outSA_t *pSA,
		SPDOutContainer_t *pContainer,
		unsigned int **pOuterIpHdr)
{
	struct iphdr *iph, *org_iphdr;
	unsigned short usNxtProto;
	unsigned short orig_pktlen;
	unsigned int ulLoSeqNum, ulHiSeqNum;
	struct sk_buff *pHeadSkb, *pTailSkb;
	unsigned char tos;

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

	ASFIPSEC_DEBUG("Org IpHeader Total Len = %d ", org_iphdr->tot_len);


	/* skb->data is at the Original IP header */

#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->ipHdrInfo.bIpVersion) {
#endif
		*pOuterIpHdr = (unsigned int *)
			(pHeadSkb->data - SECFP_IPV4_HDR_LEN - pSA->ulSecHdrLen);

		ASFIPSEC_DEBUG("(Pointer update:)pOuterIpHdr = 0x%x pSA->ulSecHdrLen = %d",
				(int)*pOuterIpHdr, pSA->ulSecHdrLen);

		iph = (struct iphdr *)(*pOuterIpHdr);
		iph->version = pSA->ipHdrInfo.hdrdata.iphv4.version;
		iph->ihl = (unsigned char)5;
		iph->id = secfp_getNextId();
		iph->protocol = SECFP_PROTO_AH;
		/* Total length = Outer IP hdr + Sec hdr len (AH Header) + payload len */
		iph->tot_len = orig_pktlen + (unsigned short)pSA->ulSecHdrLen +
				(unsigned short)pSA->ulSecLenIncrease ;
		iph->saddr = pSA->ipHdrInfo.hdrdata.iphv4.saddr;
		iph->daddr = pSA->ipHdrInfo.hdrdata.iphv4.daddr;

		/*Mutable fields set to zero */
		iph->tos = 0;
		iph->ttl = 0;
		iph->frag_off = 0;
		iph->check = 0;

		ASFIPSEC_DEBUG("ulSecHdrLen = %d, uICVSiz=%d, AHPaddingLen=%d, iph->tot_len=%d",
		 pSA->ulSecHdrLen, pSA->SAParams.uICVSize, pSA->SAParams.ucAHPaddingLen, iph->tot_len);

#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		struct ipv6hdr *ipv6h;
		*pOuterIpHdr = (unsigned int *)
			(pHeadSkb->data - SECFP_IPV6_HDR_LEN - pSA->ulSecHdrLen);

		ASFIPSEC_DEBUG("(Pointer update:)pOuterIpHdr = 0x%x pSA->ulSecHdrLen = %d",
				(int)*pOuterIpHdr, pSA->ulSecHdrLen);
		ipv6h = (struct ipv6hdr *) (*pOuterIpHdr);


		ipv6h->version = pSA->ipHdrInfo.hdrdata.iphv6.version;
		ipv6h->nexthdr = SECFP_PROTO_AH;
		ipv6h->saddr = pSA->ipHdrInfo.hdrdata.iphv6.saddr;
		ipv6h->daddr = pSA->ipHdrInfo.hdrdata.iphv6.daddr;
		ipv6h->payload_len = orig_pktlen +
			(unsigned short)pSA->ulSecHdrLen +
			(unsigned short)pSA->ulSecLenIncrease - SECFP_IPV6_HDR_LEN;
		ASFIPSEC_DBGL2("New payload len %d", ipv6h->payload_len);

		ipv6h->priority = 0;
		ipv6h->hop_limit = 0;
		memset(ipv6h->flow_lbl, 0, 3);
	}
#endif

	/* Now get into AH header construction */
	/* data pointer at the beginning of the AH header */
	pHeadSkb->data -= pSA->ulSecHdrLen;

	*(unsigned char *) &(pHeadSkb->data[0]) = usNxtProto;

	ASFIPSEC_PRINT("NextProto = 0x%x", pHeadSkb->data[0]);
	*(unsigned char *) &(pHeadSkb->data[1]) = ((SECFP_AH_FIXED_HDR_LEN + pSA->SAParams.uICVSize +
				pSA->SAParams.ucAHPaddingLen) >> 2) - 2;

	*(unsigned short *) &(pHeadSkb->data[2]) = 0;

	*(unsigned int *) &(pHeadSkb->data[4]) = pSA->SAParams.ulSPI;

	ulHiSeqNum = 0;

	if (pSA->SAParams.bDoAntiReplayCheck) {
	ASFIPSEC_PRINT("AntiReplayCheck");
		if (pSA->SAParams.bUseExtendedSequenceNumber) {
	ASFIPSEC_PRINT("ESN");
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
	*(unsigned int *) &(pHeadSkb->data[8]) = ulLoSeqNum;

	/* Alright sequence number will be either the right one in extended sequence number
		support or it will be set to 0 */

	if (pSA->SAParams.bUseExtendedSequenceNumber)
		*(unsigned int *) (skb_tail_pointer(pTailSkb)) = ulHiSeqNum;

	ASFIPSEC_PRINT("setting ICV to zero");
	/* Setting ICV and padding to zero*/
	memset((unsigned char *)(pHeadSkb->data + SECFP_AH_FIXED_HDR_LEN)
		, 0, pSA->ulSecHdrLen - SECFP_AH_FIXED_HDR_LEN);

	/* Finished handling the SEC Header */
	/* Now update data pointer*/

#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->ipHdrInfo.bIpVersion) {
#endif
		pHeadSkb->data -= SECFP_IPV4_HDR_LEN; /* outer Ip header */
		pHeadSkb->protocol = ETH_P_IP;
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		pHeadSkb->data -= SECFP_IPV6_HDR_LEN; /* outer Ip header */
		pHeadSkb->protocol = ETH_P_IPV6;
	}
#endif

	if (skb_shinfo(pHeadSkb)->nr_frags) {
		pHeadSkb->data_len += pSA->ulSecHdrLen + pSA->ulSecLenIncrease;
		ASFIPSEC_DEBUG("pHeadSkb->data_len:%d\n", pHeadSkb->data_len);
		pHeadSkb->len = orig_pktlen + pSA->ulSecHdrLen + SECFP_IPV4_HDR_LEN;
		ASFIPSEC_DEBUG("pHeadSkb->len:%d pHeadSkb->len1:%d\n",
					pHeadSkb->len, org_iphdr->tot_len);
	} else {
		/* Update skb->len */
		pHeadSkb->len += pSA->ulSecHdrLen + pSA->ulSecLenIncrease;
	}
	return;
}

void secfp_inAHComplete(struct device *dev,
		u32 *pdesc,
		u32 err, void *context
		)
{
	struct sk_buff *skb = (struct sk_buff *) context;
	struct sk_buff *pHeadSkb, *pTailSkb;
	unsigned char ucNextProto;
	unsigned int /*ulTempLen,*/ iRetVal;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	inSA_t *pSA;
	struct iphdr *iph = (struct iphdr *)*(uintptr_t *)
				&(skb->cb[SECFP_IPHDR_INDEX]);
	ASFLogInfo_t AsfLogInfo;
	char aMsg[ASF_MAX_MESG_LEN + 1];
	ASFIPSecOpqueInfo_t IPSecOpque = {};
	ASFBuffer_t Buffer;
	unsigned int ulCommonInterfaceId ;
#ifndef ASF_QMAN_IPSEC
	struct ipsec_ah_edesc *desc;
#else
	struct ses_pkt_info *pInfo;
#endif
	struct iphdr *inneriph;
	unsigned int ulFragCnt;

	ASFIPSEC_FENTRY;
#ifndef ASF_QMAN_IPSEC
	desc = (struct ipsec_ah_edesc *)((char *)pdesc -
			offsetof(struct ipsec_ah_edesc, hw_desc));
	ASFIPSEC_DEBUG("icv=%p, in_icv=%p, dma_icv=%p \n",
		desc->icv, desc->in_icv, desc->icv_dma);
#else
	pInfo = (struct ses_pkt_info *)pdesc;
#endif

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

	skb->cb[SECFP_REF_INDEX] = 0;

	if (unlikely(err)) {

		char tmp[SECFP_ERROR_STR_MAX];
		ASFIPSEC_DPERR("%08x: %s\n", err, caam_jr_strstatus(tmp, err));
#ifndef ASF_QMAN_IPSEC
		secfp_ahdesc_free_frags(desc, skb);
#endif
		rcu_read_lock();
		pSA = secfp_findInSA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
					SECFP_PROTO_AH,
					*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
					IPSecOpque.DestAddr,
					(unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
		if (pSA) {
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "Digest Operation Failed for AH");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID3;
			asfFillLogInfo(&AsfLogInfo, pSA);
			/* TBD - length being deducted is not
				same as lengh added*/
			pSA->ulBytes[smp_processor_id()] -= skb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();
		skb->data_len = 0;
		skb->next = NULL;
#ifndef ASF_QMAN_IPSEC
		ASFSkbFree(skb);
#endif
		return;
	}

	if (skb_shinfo(skb)->frag_list) {
		pHeadSkb = skb;
		if ((unsigned int)(skb->prev) == SECFP_IN_GATHER_NO_SCATTER) {
		/* Using this as a hint, this means output buffer is single */
			pTailSkb = skb;
		} else {
			for (ulFragCnt = 1, pTailSkb = skb_shinfo(skb)->frag_list;
				pTailSkb->next != NULL;
				pTailSkb = pTailSkb->next, ulFragCnt++)
				;
		}
	} else {
		pHeadSkb = pTailSkb = skb;
	}

#ifndef ASF_SECFP_PROTO_OFFLOAD
	if (secfp_inHandleAHICVCheck(desc, pHeadSkb)) {

#ifndef ASF_QMAN_IPSEC
		secfp_ahdesc_free_frags(desc, skb);
#endif
		rcu_read_lock();
		pSA = secfp_findInSA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
					SECFP_PROTO_AH,
					*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
					IPSecOpque.DestAddr,
					(unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));
		ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
		if (pSA) {
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "ICV comparison Failed");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID8;

			asfFillLogInfo(&AsfLogInfo, pSA);
			pSA->ulBytes[smp_processor_id()] -= skb->len;
			pSA->ulPkts[smp_processor_id()]--;
		}
		rcu_read_unlock();
		ASFIPSEC_DEBUG("ICV error dropping packet");
		skb->data_len = 0;
		skb->next = NULL;
#ifndef ASF_QMAN_IPSEC
		ASFSkbFree(skb);
#endif
		return;
	}
#endif

#ifdef ASF_QMAN_IPSEC
	rcu_read_lock();
	pSA = secfp_findInSA(*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
				SECFP_PROTO_AH,
				*(unsigned int *)&(skb->cb[SECFP_SPI_INDEX]),
				IPSecOpque.DestAddr,
				(unsigned int *)&(skb->cb[SECFP_HASH_VALUE_INDEX]));

	if (pSA) {
		if (secfp_inHandleAHQmanICVCheck(skb, pInfo)) {
	ASF_IPSEC_PPS_ATOMIC_INC(IPSec4GblPPStats_g.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT18]);
			ASF_IPSEC_INC_POL_PPSTATS_CNT(pSA, ASF_IPSEC_PP_POL_CNT18);
			snprintf(aMsg, ASF_MAX_MESG_LEN - 1, "ICV comparison Failed");
			AsfLogInfo.aMsg = aMsg;
			AsfLogInfo.ulMsgId = ASF_IPSEC_LOG_MSG_ID8;

			asfFillLogInfo(&AsfLogInfo, pSA);
			pSA->ulBytes[smp_processor_id()] -= skb->len;
			pSA->ulPkts[smp_processor_id()]--;

			rcu_read_unlock();
			kfree(pInfo->in_icv);
			ASFIPSEC_DEBUG("ICV error dropping packet");
			skb->data_len = 0;
			skb->next = NULL;
			return;
		}
	} else {
		rcu_read_unlock();
		kfree(pInfo->in_icv);
		skb->data_len = 0;
		skb->next = NULL;
		return;
	}
	rcu_read_unlock();
	kfree(pInfo->in_icv);
#endif

#ifndef ASF_QMAN_IPSEC
	secfp_ahdesc_free_frags(desc, skb);
#endif
	ASFIPSEC_DEBUG("ICV success");

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
#ifndef ASF_QMAN_IPSEC
		ASFSkbFree(skb);
#endif
		return;
	}
	ASFIPSEC_FPRINT("skb->data = 0x%x, skb->data - 20 - 16 =0x%x,"\
		"skb->len = %d",
		skb->data, skb->data - 20 - 16, skb->len);

	if (skb_shinfo(skb)->nr_frags == 0)
		skb->data_len = 0;
	skb->next = NULL;

	/* Look at the Next protocol field */
#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 6)
		ucNextProto = skb->data[SECFP_IPV6_HDR_LEN];
	else
#endif
		ucNextProto = skb->data[SECFP_IPV4_HDR_LEN];

	ASFIPSEC_DEBUG("\n NextProto=%d", ucNextProto);
#ifdef ASF_IPV6_FP_SUPPORT
	if (ucNextProto == SECFP_PROTO_IP) {
#endif
		skb->data += SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + skb->cb[SECFP_ICV_LENGTH];
		skb->len -= SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + skb->cb[SECFP_ICV_LENGTH];
		inneriph = (struct iphdr *)(skb->data);
		ip_decrease_ttl(inneriph);
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		skb->data += SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN
					+ skb->cb[SECFP_ICV_LENGTH];
		skb->len -= SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN
					+ skb->cb[SECFP_ICV_LENGTH];
	}
#endif

	iRetVal = secfp_inCompleteSAProcess(&skb, &IPSecOpque,
		SECFP_PROTO_AH, &ulCommonInterfaceId);
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

		/* Homogenous buffer */
		Buffer.nativeBuffer = skb;
#ifdef ASF_TERM_FP_SUPPORT
		if (skb->mapped && pTermProcessPkt) {
			pTermProcessPkt(
			*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
			ulCommonInterfaceId, Buffer, secfp_SkbFree,
			skb, &IPSecOpque, ASF_FALSE);
		} else
#endif
		{

			ASFFFPProcessAndSendPkt(
				*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
				ulCommonInterfaceId, Buffer, secfp_SkbFree,
				skb, &IPSecOpque);
		}
		pIPSecPPGlobalStats->ulTotInProcPkts++;
#ifdef ASF_IPV6_FP_SUPPORT
	} else if (ucNextProto == SECFP_PROTO_IPV6) {
		ASFIPSEC_DEBUG("\n ipv6 packet decrypted successfully"
				" need to send it to ipv6stack");
		skb_reset_network_header(skb);
		skb->protocol = ETH_P_IPV6;
		/* Homogenous buffer */
		Buffer.nativeBuffer = skb;
#ifdef ASF_TERM_FP_SUPPORT
		if (skb->mapped && pTermProcessPkt) {
			pTermProcessPkt(
			*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
			ulCommonInterfaceId, Buffer, secfp_SkbFree,
			skb, &IPSecOpque, ASF_FALSE);
		} else
#endif
		{
			if (ASFFFPIPv6ProcessAndSendPkt(
				*(unsigned int *)&(skb->cb[SECFP_VSG_ID_INDEX]),
				ulCommonInterfaceId, Buffer, secfp_SkbFree,
				skb, &IPSecOpque) == ASF_RTS) {
				ASFIPSEC_DEBUG("Sending Decrypted Packet Up");
				netif_receive_skb(skb);
				return;
			}
		}


		pIPSecPPGlobalStats->ulTotInProcPkts++;
#endif
	} else {
		ASFIPSEC_WARN("Protocol not supported 0x%x", ucNextProto);
#ifndef ASF_QMAN_IPSEC
		ASFSkbFree(skb);
#endif
		return;
	}
}


void secfp_outAHComplete(struct device *dev,
		u32 *pdesc,
		u32 error, void *context
		)
{
	struct sk_buff *skb = (struct sk_buff *) context;
	struct sk_buff *pOutSkb = skb, *pTempSkb;
	outSA_t *pSA;
	struct iphdr *iph;
	AsfIPSecPPGlobalStats_t *pIPSecPPGlobalStats;
	unsigned int ulVSGId, ulSPDContainerIndex;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int cpu;
	unsigned long uPacket = 0;
	ASF_IPSecTunEndAddr_t TunAddress;
	unsigned short	bl2blobRefresh = 0;
#endif
#ifdef CONFIG_DPA
	struct dpa_percpu_priv_s *percpu_priv;
	struct dpa_priv_s       *priv = netdev_priv(skb->dev);
	percpu_priv = per_cpu_ptr(priv->percpu_priv, smp_processor_id());
#endif
	unsigned short tot_len = 0;
	unsigned short ipHdrLen = 0;
#ifndef ASF_QMAN_IPSEC
	struct ipsec_ah_edesc *desc;
	desc = (struct ipsec_ah_edesc *)((char *)pdesc -
			offsetof(struct ipsec_ah_edesc, hw_desc));
#endif
	pIPSecPPGlobalStats = asfPerCpuPtr(pIPSecPPGlobalStats_g, smp_processor_id());
	pIPSecPPGlobalStats->ulTotOutPktsSecAppled++;

	ASFIPSEC_DEBUG(" Entry");

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

	if (unlikely(error || skb->cb[SECFP_ACTION_INDEX] == SECFP_DROP)) {
		if (error) {
			char tmp[SECFP_ERROR_STR_MAX];
			ASFIPSEC_DPERR("Dropping the packet %08x: %s\n", error,
				caam_jr_strstatus(tmp, error));
#ifndef ASF_QMAN_IPSEC
			secfp_ahdesc_free_frags(desc, skb);
#endif
			if ((error & SEQ_NO_OVERFLOW) == SEQ_NO_OVERFLOW) {
				ASF_IPAddr_t DestAddr;
				ASF_uint32_t ulVSGId = skb->cb[SECFP_VSG_ID_INDEX];
				ASFIPSEC_PRINT("Going for re-keying");
				pSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
					*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]));
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
#ifndef ASF_QMAN_IPSEC
		ASFSkbFree(skb);
#endif
		return;
	}

	pSA = (outSA_t *)ptrIArray_getData(&secFP_OutSATable,
				*(unsigned int *)&(skb->cb[SECFP_SAD_SAI_INDEX]));

	/* Copy ICV into the AH header */
#ifndef ASF_QMAN_IPSEC
	secfp_copyAHIcv(skb, desc, pSA);
	secfp_ahdesc_free_frags(desc, skb);
#else
	secfp_copyAHIcvQman(skb, pSA);
#endif

	if (skb->prev) {
		/* Put the prev pointer in the frag list and release frag list
			some dirty work
		*/
		skb_shinfo(skb)->frag_list = skb->prev;
		skb->len -= skb->prev->len;
		skb->prev = NULL;
	}


	iph = (struct iphdr *) skb->data;
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {

		/*Update the Mutable fields of the outer IP header */
		iph->tos = pSA->ipHdrInfo.hdrdata.iphv4.tos;
		iph->ttl = 64;
		iph->frag_off = IP_DF;

		iph->check = ip_fast_csum((u8 *)(skb->data), iph->ihl);
	} else {
		struct ipv6hdr *ip6hdr;
		ip6hdr = (struct ipv6hdr *)skb->data;
		ip6hdr->hop_limit = SECFP_IP_TTL;
	}


/*	ASFIPSEC_DEBUG("Sending packet to: skb = 0x%x, skb->data = 0x%x,"
		" skb->dev = 0x%x, skb->len = %d , nr_frags = %d, checksum=%x",
		skb, skb->data, skb->dev, skb->len, skb_shinfo(skb)->nr_frags,iph->check);*/
	if (skb_shinfo(skb)->nr_frags) {
		skb_frag_t *frag;
		unsigned char *charp;
		unsigned int total_frags;
		total_frags = skb_shinfo(skb)->nr_frags;
		frag = &(skb_shinfo(skb)->frags[total_frags - 1]);
		charp = (u8 *)(page_address((const struct page *)frag->page.p) +
					frag->page_offset);
	} else {
		skb->data_len = 0; /* No req for this field anymore */
	}



	ulVSGId = skb->cb[SECFP_VSG_ID_INDEX];
	ulSPDContainerIndex = skb->cb[SECFP_SPD_CI_INDEX];
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
/*		ASFIPSEC_DEBUG("skb->network_header = 0x%x,"
			"skb->transport_header = 0x%x\r\n",
			(unsigned int)skb_network_header(skb),
			(unsigned int)skb_transport_header(skb));
		skb_set_network_header(skb, pSA->ulL2BlobLen);*/
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
				"SA Expired KB=%u (hard=%d) SPI=0x%x",
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
				DestAddr.ipv4addr = pSA->
					SAParams.tunnelInfo.addr.iphv4.daddr;
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

	if (!skb->cb[SECFP_OUTB_FRAG_REQD]) {
		/* FASTROUTE is required for selective recycling*/
		skb->pkt_type = PACKET_FASTROUTE;
#ifdef ASF_QOS
#ifdef ASF_IPV6_FP_SUPPORT
		if (iph->version == 6) {
			struct ipv6_redef *hdr;
			hdr = (struct ipv6_redef *) iph;
			asf_set_queue_mapping(skb,hdr->tc);
		} else
#endif
			asf_set_queue_mapping(skb,iph->tos);
#ifdef CONFIG_DPA
		if (skb->cb[BUF_INDOMAIN_INDEX])
			(*percpu_priv->dpa_bp_count)--;
#endif

		/* Enqueue the packet in Linux QoS framework */
		asf_qos_handling(skb,&pSA->tc_filter_res);
#else
		txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
		if (asfDevHardXmit(skb->dev, skb) != 0) {
			ASFSkbFree(skb);
			return;
		} else
			skb->dev->trans_start = txq->trans_start = jiffies;
#endif
		pIPSecPPGlobalStats->ulTotOutProcPkts++;
	} else {
		ASFIPSEC_DEBUG("Need to call fragmentation module ");
		/* Need to do dma unmapping for rest of the fragments */
		if (skb_shinfo(skb)->frag_list) {
#ifndef ASF_QMAN_IPSEC
			secfp_ahdesc_free_frags(desc, skb);
#endif
		}
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

				skb->data += pSA->ulL2BlobLen;
				skb->len -= pSA->ulL2BlobLen;
				ASFIPSEC_FPRINT("Before Fragmentation");

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

					pOutSkb->data -= pSA->ulL2BlobLen;
					pOutSkb->len += pSA->ulL2BlobLen;

					skb_set_tail_pointer(pOutSkb, pOutSkb->len);
					pOutSkb->dev = pSA->odev;
					pOutSkb->pkt_type = PACKET_FASTROUTE;
#ifdef ASF_IPV6_FP_SUPPORT
					if (iph->version == 6) {
						struct ipv6_redef *hdr;
						hdr = (struct ipv6_redef *) iph;
						asf_set_queue_mapping(pOutSkb, hdr->tc);
					} else
#endif
						asf_set_queue_mapping(pOutSkb, iph->tos);

					ASFIPSEC_FPRINT("Next skb = 0x%x", pTempSkb);
					ASFIPSEC_FPRINT("Frag : skb = 0x%x, skb->data = 0x%x, skb->dev = 0x%x, skb->len = %d*****",
						pOutSkb, pOutSkb->data, pOutSkb->dev, pOutSkb->len);

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
						(*percpu_priv->dpa_bp_count)--;
#endif
#ifdef ASF_QOS
					/* Enqueue the packet in Linux
					   QoS framework */
					asf_qos_handling(pOutSkb, &pSA->tc_filter_res);
#else
					txq = netdev_get_tx_queue(pOutSkb->dev, pOutSkb->queue_mapping);
					if (asfDevHardXmit(pOutSkb->dev, pOutSkb) != 0) {
						ASFIPSEC_WARN("Error in transmit: Should not happen");
						ASFSkbFree(pOutSkb);
					} else
						pOutSkb->dev->trans_start = txq->trans_start = jiffies;
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
#ifdef ASF_QMAN_IPSEC
int secfp_buildAHQMANSharedDesc(struct caam_ctx *ctx, u32 *sh_desc,
				void *pSA, uint8_t bDir)
{
	int ret = 0;
	unsigned short usDescSize = 0;
	unsigned char ucAuthAlgo;
	enum key_dest keydest;
	enum key_cover keycover;

	if (bDir == SECFP_AH_DIR_IN)
		ucAuthAlgo = ((inSA_t *)pSA)->SAParams.ucAuthAlgo;
	else
		ucAuthAlgo = ((outSA_t *)pSA)->SAParams.ucAuthAlgo;


	if (ucAuthAlgo != SECFP_HMAC_AES_XCBC_MAC) {
		keydest = KEYDST_MD_SPLIT;
		keycover = KEY_COVERED;
	} else {
		keydest = KEYDST_KEYREG;
		keycover = 0;
	}

	ASFIPSEC_DEBUG("KeyDest= %d, key Covered = %d, splitkey=%x, splitkeylen=%d",
				keydest, keycover, ctx->key, ctx->split_key_len);
	{
		if (keydest == KEYDST_MD_SPLIT)
			ret = secfp_cnstr_shdsc_hmac(sh_desc, &usDescSize,
					(void *)&ctx->key_phys,
					ctx->class2_alg_type, ctx->split_key_len, 0,
					0, keydest, keycover);
		else
			/*TBD*/
			ret = secfp_cnstr_shdsc_xcbc(sh_desc, &usDescSize,
				(void *)&ctx->key_phys,
				(ctx->class1_alg_type | ctx->alg_op),
				ctx->split_key_len, 0, 0, keydest, keycover);

		if (ret < 0) {
			ASFIPSEC_WARN("Shared Desc Creation Failed. Error = %d", ret);
			kfree(ctx->sh_desc_mem);
			return ASF_FAILURE;
		}
	}
	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
/*		usDescSize, DMA_TO_DEVICE);*/
		desc_bytes(ctx->sh_desc), DMA_TO_DEVICE);
	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_WARN("unable to map shared descriptor");
		kfree(ctx->sh_desc_mem);
		return -ENOMEM;
	}
	return 0;

}
#endif

int secfp_buildAHSharedDesc(struct caam_ctx *ctx, void *pSA, uint8_t bDir)
{
	int ret = 0;
	unsigned short usDescSize = 0;
	unsigned char ucAuthAlgo;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	enum key_dest keydest;
	enum key_cover keycover;

	if (bDir == SECFP_AH_DIR_IN)
		ucAuthAlgo = ((inSA_t *)pSA)->SAParams.ucAuthAlgo;
	else
		ucAuthAlgo = ((outSA_t *)pSA)->SAParams.ucAuthAlgo;


	/* build shared descriptor for this session */
	ctx->sh_desc_mem = kzalloc(ASF_IPSEC_SEC_SA_SHDESC_SIZE + L1_CACHE_BYTES
		- 1, GFP_DMA | flags);
	if (!ctx->sh_desc_mem) {
		ASFIPSEC_WARN("Could not allocate shared descriptor");
		return -ENOMEM;
	}
	ctx->sh_desc = (u32 *)(((dma_addr_t)ctx->sh_desc_mem
			+ (L1_CACHE_BYTES - 1)) & ~(L1_CACHE_BYTES - 1));
	if (ucAuthAlgo != SECFP_HMAC_AES_XCBC_MAC) {
		keydest = KEYDST_MD_SPLIT;
		keycover = KEY_COVERED;
	} else {
		keydest = KEYDST_KEYREG;
		keycover = 0;
	}

	ASFIPSEC_DEBUG("KeyDest= %d, key Covered = %d, splitkey=%x, splitkeylen=%d",
				keydest, keycover, ctx->key, ctx->split_key_len);
	{
		if (keydest == KEYDST_MD_SPLIT)
			ret = secfp_cnstr_shdsc_hmac(ctx->sh_desc, &usDescSize,
					(void *)&ctx->key_phys,
					ctx->class2_alg_type, ctx->split_key_len, 0,
					0, keydest, keycover);
		else
			/*TBD*/
			ret = secfp_cnstr_shdsc_xcbc(ctx->sh_desc, &usDescSize,
				(void *)&ctx->key_phys,
				(ctx->class1_alg_type | ctx->alg_op),
				ctx->split_key_len, 0, 0, keydest, keycover);

		if (ret < 0) {
			ASFIPSEC_WARN("Shared Desc Creation Failed. Error = %d", ret);
			kfree(ctx->sh_desc_mem);
			return ASF_FAILURE;
		}
	}
	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
		usDescSize, DMA_TO_DEVICE);

	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_WARN("unable to map shared descriptor");
		kfree(ctx->sh_desc_mem);
		return -ENOMEM;
	}
	return 0;
}

int secfp_createAHInCaamCtx(inSA_t *pSA)
{
	int ret = 0;

	if (pSA) {
		struct caam_drv_private *priv = dev_get_drvdata(pdev);
		int tgt_jr = atomic_inc_return(&priv->tfm_count);
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
		/*
		* distribute tfms across job rings to ensure in-order
		* crypto request processing per tfm
		*/
		pSA->ctx.jrdev = priv->jrdev[(tgt_jr / 2) %
				priv->total_jobrs];
		pSA->ctx.key = kzalloc(pSA->ctx.split_key_pad_len,
					GFP_DMA | flags);

		if (!pSA->ctx.key) {
			ASFIPSEC_DEBUG("Could not allocate"\
					"Caam key output memory\n");
			return -ENOMEM;
		}

		pSA->ctx.enckeylen = 0;
		if (pSA->SAParams.bAuth) {
			if (SECFP_HMAC_AES_XCBC_MAC ==
				pSA->SAParams.ucAuthAlgo) {
				ASFIPSEC_DEBUG("for AES_XCBC_MAC, no need for"\
					"splitkey generated\n");
				memcpy(pSA->ctx.key, &pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen);
				pSA->ctx.split_key_pad_len =
					pSA->SAParams.AuthKeyLen;
				pSA->ctx.split_key_len =
					pSA->SAParams.AuthKeyLen;
			} else {
				ret = secfp_genCaamSplitKey(&pSA->ctx,
						(u8 *)&pSA->SAParams.ucAuthKey,
						pSA->SAParams.AuthKeyLen);
				if (ret) {
					ASFIPSEC_DEBUG("Failed\n");
					kfree(pSA->ctx.key);

					return ret;
				}
			}
		}


		pSA->ctx.key_phys = dma_map_single(pSA->ctx.jrdev, pSA->ctx.key,
						pSA->ctx.split_key_pad_len,
							DMA_TO_DEVICE);
		if (dma_mapping_error(pSA->ctx.jrdev, pSA->ctx.key_phys)) {
			ASFIPSEC_DEBUG("Unable to map key"\
					"i/o memory\n");
			kfree(pSA->ctx.key);
			return -ENOMEM;
		}
		pSA->ctx.authsize = pSA->SAParams.uICVSize;
#ifdef ASF_QMAN_IPSEC
		ret = secfp_buildAHProtocolDesc(&pSA->ctx, pSA, SECFP_AH_DIR_IN);
#else
		ret = secfp_buildAHSharedDesc(&pSA->ctx, pSA, SECFP_AH_DIR_IN);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			kfree(pSA->ctx.key);
			dma_unmap_single(pSA->ctx.jrdev, pSA->ctx.key_phys,
			pSA->ctx.split_key_pad_len, DMA_TO_DEVICE);

			return ret;
		}
#endif
	} else
		ret = -EINVAL;

	return ret;
}


int secfp_createAHOutCaamCtx(outSA_t *pSA)
{
	int ret = 0;

	if (pSA) {
		struct caam_drv_private *priv = dev_get_drvdata(pdev);
		int tgt_jr = atomic_inc_return(&priv->tfm_count);
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
		/*
		* distribute tfms across job rings to ensure in-order
		* crypto request processing per tfm
		*/
		pSA->ctx.jrdev = priv->jrdev[(tgt_jr / 2) %
				priv->total_jobrs];

		pSA->ctx.key = kzalloc(pSA->ctx.split_key_pad_len,
					GFP_DMA | flags);

		if (!pSA->ctx.key) {
			ASFIPSEC_DEBUG("Could not allocate"\
					"Caam key output memory\n");
			return -ENOMEM;
		}

		pSA->ctx.enckeylen = 0;
		if (pSA->SAParams.bAuth) {
			if (SECFP_HMAC_AES_XCBC_MAC ==
				pSA->SAParams.ucAuthAlgo) {
				ASFIPSEC_DEBUG("for AES_XCBC_MAC, no need for"\
					"splitkey generated\n");
				memcpy(pSA->ctx.key, &pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen);
				pSA->ctx.split_key_pad_len =
					pSA->SAParams.AuthKeyLen;
				pSA->ctx.split_key_len =
					pSA->SAParams.AuthKeyLen;
			} else {
				ret = secfp_genCaamSplitKey(&pSA->ctx,
						(u8 *)&pSA->SAParams.ucAuthKey,
						pSA->SAParams.AuthKeyLen);
				if (ret) {
					ASFIPSEC_DEBUG("Failed\n");
					kfree(pSA->ctx.key);

					return ret;
				}
			}
		}


		pSA->ctx.key_phys = dma_map_single(pSA->ctx.jrdev, pSA->ctx.key,
						pSA->ctx.split_key_pad_len,
						DMA_TO_DEVICE);
		if (dma_mapping_error(pSA->ctx.jrdev, pSA->ctx.key_phys)) {
			ASFIPSEC_DEBUG("Unable to map key"\
					"i/o memory\n");
			kfree(pSA->ctx.key);
			return -ENOMEM;
		}
		pSA->ctx.authsize = pSA->SAParams.uICVSize;
#ifdef ASF_QMAN_IPSEC
		ret = secfp_buildAHProtocolDesc(&pSA->ctx, pSA, SECFP_AH_DIR_OUT);
#else
		ret = secfp_buildAHSharedDesc(&pSA->ctx, pSA, SECFP_AH_DIR_OUT);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			kfree(pSA->ctx.key);
			dma_unmap_single(pSA->ctx.jrdev, pSA->ctx.key_phys,
			pSA->ctx.split_key_pad_len, DMA_TO_DEVICE);

			return ret;
		}
#endif
	} else
		ret = -EINVAL;

	return ret;
}


#ifndef ASF_QMAN_IPSEC
void secfp_prepareAHInDescriptor(struct sk_buff *skb,
			void *pData, void *descriptor,
			unsigned int ulIndex)
{
	inSA_t *pSA = (inSA_t *)pData;
	struct ipsec_ah_edesc *edesc = descriptor;
	u8 *in_icv, *icv;
	unsigned short descSize = 0, ii;
	dma_addr_t icv_phys;
	struct iphdr *iph;

	in_icv = (u8 *)secfp_ah_icv_alloc();
	if (!in_icv) {
		ASFIPSEC_WARN("Icv allocation failed!");
		/* Free the packet */
		return;
	}

	/* Assuming that AH header is always in the first fragment*/
	/*Storing the original ICV*/
	ASFIPSEC_DEBUG("Incoming ICV");
#ifdef ASF_IPV6_FP_SUPPORT
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
#endif
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			in_icv[ii] = skb->data[SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii];

		/*setting icv to zero before computing new ICV*/
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV4_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii] = 0;
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			in_icv[ii] = skb->data[SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii];

		/*setting icv to zero before computing new ICV*/
		for (ii = 0; ii < pSA->SAParams.uICVSize; ii++)
			skb->data[SECFP_IPV6_HDR_LEN + SECFP_AH_FIXED_HDR_LEN + ii] = 0;
	}
#endif
	/*Storing the icv received for post-crypto comparison */
	edesc->in_icv = in_icv;

	icv = (u8 *)secfp_ah_icv_alloc();
	if (!icv) {
		ASFIPSEC_WARN("Icv allocation failed!");
		secfp_ah_icv_free(in_icv);
		edesc->in_icv = NULL;
		/* Free the packet */
		return;
	}

	edesc->icv_bytes = pSA->ctx.split_key_len;
	icv_phys = dma_map_single(pSA->ctx.jrdev, icv,
		edesc->icv_bytes, DMA_BIDIRECTIONAL);

	edesc->icv_dma = icv_phys;

	edesc->icv = icv;
	/*setting mutable fields to zero */
	if (!pSA->SAParams.tunnelInfo.bIPv4OrIPv6) {
		iph = (struct iphdr *)skb->data;
		iph->frag_off = 0;
		iph->ttl = 0;
		iph->tos = 0;
		iph->check = 0;
	} else {
		struct ipv6hdr *ipv6h;
		ipv6h = (struct ipv6hdr *)skb->data;
		ipv6h->hop_limit = 0;
		ipv6h->priority = 0;
		memset(ipv6h->flow_lbl, 0, 3);
	}

	ASFIPSEC_DEBUG("desc=%p,icv=%p, in_icv=%p, dma_icv=%p \n",
		edesc, edesc->icv, edesc->in_icv, edesc->icv_dma);
	ASFIPSEC_DEBUG("Check for the NR_Frags\n");
	/* Check for the NR_Frags */
	if (unlikely(skb_shinfo(skb)->nr_frags)) {

		struct link_tbl_entry *link_tbl_entry;
		dma_addr_t ptr_in, ptr1 = (dma_addr_t)NULL;
		int i, total_frags, dma_len, len_to_caam = 0;
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

		total_frags = skb_shinfo(skb)->nr_frags;
		dma_len = sizeof(struct link_tbl_entry) * (total_frags + 1);
		ptr1 = dma_map_single(pSA->ctx.jrdev, skb->data,
			skb_headlen(skb) ,
			DMA_BIDIRECTIONAL);

		ASFIPSEC_DEBUG("skb_headlen(skb)=%d ", skb_headlen(skb));
		link_tbl_entry = kzalloc(dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr1;
		link_tbl_entry->len = skb_headlen(skb);
		len_to_caam = link_tbl_entry->len;

		ASFIPSEC_DEBUG("link_tbl_entry->len=%d len_to_caam=%d, total_frags=%d",\
			link_tbl_entry->len, len_to_caam, total_frags);
		/* Parse the NR_FRAGS */
		/* Prepare the scatter list for SEC */
		for (i = 0; i < total_frags; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			int frag_size = 0;
			if (pSA->SAParams.bUseExtendedSequenceNumber) {
				if (i == total_frags - 1)
					frag_size = frag->size + SECFP_APPEND_BUF_LEN_FIELD;
			} else
				frag_size = frag->size;
			(link_tbl_entry + i + 1)->ptr =
					dma_map_single(pSA->ctx.jrdev,
					(void *)page_address((const struct page *)frag->page.p) +
					frag->page_offset,
					frag_size ,
					 DMA_BIDIRECTIONAL);

			ASFIPSEC_DEBUG("Frag dump i=%d:,len = %d,frag_size=%d", i, frag->size, frag_size);
			/*ASFIPSEC_HEXDUMP((void *)page_address(frag->page) +
					frag->page_offset , frag->size);*/

			(link_tbl_entry + i + 1)->len = frag_size ;
			len_to_caam += frag_size;
			if (i == total_frags - 1)
				(link_tbl_entry + i + 1)->len |=
						cpu_to_be32(0x40000000);
		}

		/* Go ahead and Submit to SEC */
		ptr_in = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		edesc->link_tbl_dma = ptr_in;
		edesc->link_tbl = link_tbl_entry;

		edesc->link_tbl_bytes = dma_len;


		ASFIPSEC_DEBUG("len_to_caam =%d, icv=%p, dma_len=%d\n", len_to_caam, icv, dma_len);
		{
			secfp_cnstr_seq_jobdesc(edesc->hw_desc, &descSize,
			(void *)&pSA->ctx.shared_desc_phys, desc_len(pSA->ctx.sh_desc),
			(void *)&ptr_in, len_to_caam, (void *)&icv_phys, edesc->icv_bytes, PTR_SGLIST);
		}

#ifdef ASF_IPSEC_DESC_DEBUG
		caam_desc_disasm(edesc->hw_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif

	} else {
		dma_addr_t ptr;
		int hdr_len, len;
#ifdef ASF_IPV6_FP_SUPPORT
		if (pSA->SAParams.tunnelInfo.bIPv4OrIPv6)
			hdr_len = SECFP_IPV6_HDR_LEN;
		else
#endif
			hdr_len = SECFP_IPV4_HDR_LEN;

		if (pSA->SAParams.bUseExtendedSequenceNumber)
			len = skb->len + SECFP_APPEND_BUF_LEN_FIELD;
		else
			len = skb->len;

		ptr = dma_map_single(pSA->ctx.jrdev, skb->data,
			len, DMA_BIDIRECTIONAL);

		if (!ptr) {
			ASFIPSEC_ERR("DMA MAP FAILED\n");
			return;
		}
		secfp_cnstr_seq_jobdesc(edesc->hw_desc, &descSize,
		(void *)&pSA->ctx.shared_desc_phys, desc_len(pSA->ctx.sh_desc),
		(void *)&ptr, len, (void *)&icv_phys, edesc->icv_bytes, PTR_DIRECT);
#ifdef ASF_IPSEC_DESC_DEBUG
		caam_desc_disasm(edesc->hw_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif
	}
	return;
}

/*
 * Function prepares the descriptors based on the authentication
 * algorithm. The prepared descriptor is submitted to SEC.
 */

void secfp_prepareAHOutDescriptor(struct sk_buff *skb, void *pData,
				void *descriptor, unsigned int ulOptionIndex)
{
	outSA_t *pSA = (outSA_t *) (pData);
	struct ipsec_ah_edesc *edesc =
			(struct ipsec_ah_edesc *)descriptor;
	u8 *pIcv;
	dma_addr_t icv_phys;
	uint16_t descSize;

	pIcv = (u8 *)secfp_ah_icv_alloc();
	if (!pIcv) {
		ASFIPSEC_WARN("Icv allocation failed!");
		/* Free the packet */
		return;
	}

	icv_phys = dma_map_single(pSA->ctx.jrdev, pIcv,
		pSA->ctx.split_key_len, DMA_BIDIRECTIONAL);

	edesc->icv = pIcv;
	edesc->in_icv = NULL;
	edesc->icv_bytes = pSA->ctx.split_key_len;
	edesc->icv_dma = icv_phys;

	/* Check for the NR_Frags */
	if (!(skb_shinfo(skb)->nr_frags)) {
		dma_addr_t ptr ;
		int len;

		if (pSA->SAParams.bUseExtendedSequenceNumber)
			len = skb_headlen(skb) + SECFP_APPEND_BUF_LEN_FIELD;
		else
			len = skb_headlen(skb);

		ptr = dma_map_single(pSA->ctx.jrdev, skb->data,
			len, DMA_BIDIRECTIONAL);

		/* construct job descriptor */
		secfp_cnstr_seq_jobdesc(edesc->hw_desc, &descSize,
			 (void *)&(pSA->ctx.shared_desc_phys), desc_len(pSA->ctx.sh_desc),
			(void *)&ptr, len, (void *)&icv_phys, edesc->icv_bytes, PTR_DIRECT);

#ifdef ASF_IPSEC_DESC_DEBUG
		caam_desc_disasm(edesc->hw_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif
	} else {
		struct link_tbl_entry *link_tbl_entry;
		dma_addr_t ptr_in, ptr1;
		int i, total_frags, dma_len, len_to_caam = 0;
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

		total_frags = skb_shinfo(skb)->nr_frags;
		dma_len = sizeof(struct link_tbl_entry) * (total_frags + 1);
		ptr1 = dma_map_single(pSA->ctx.jrdev, skb->data,
			skb_headlen(skb) ,
			DMA_BIDIRECTIONAL);

		link_tbl_entry = kzalloc(dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr1;
		link_tbl_entry->len = skb_headlen(skb);
		len_to_caam = link_tbl_entry->len;

		ASFIPSEC_DEBUG("link_tbl_entry->len=%d len_to_caam=%d",
			link_tbl_entry->len, len_to_caam);
		/* Parse the NR_FRAGS */
		/* Prepare the scatter list for SEC */

		for (i = 0; i < total_frags; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			int frag_size = 0;

			if (pSA->SAParams.bUseExtendedSequenceNumber) {
				if (i == total_frags - 1)
					frag_size = frag->size + SECFP_APPEND_BUF_LEN_FIELD;
			} else
				frag_size = frag->size;
			(link_tbl_entry + i + 1)->ptr =
					dma_map_single(pSA->ctx.jrdev,
					(void *)page_address((const struct page *)frag->page.p) +
					frag->page_offset ,
					frag_size,
					 DMA_BIDIRECTIONAL);

			ASFIPSEC_DEBUG("Frag dump i=%d:,len = %d", i, frag_size);
			/*ASFIPSEC_HEXDUMP((void *)page_address(frag->page) +
					frag->page_offset , frag->size);*/

			(link_tbl_entry + i + 1)->len = frag_size;
			len_to_caam += frag_size;
			if (i == total_frags - 1)
				(link_tbl_entry + i + 1)->len |=
						cpu_to_be32(0x40000000);
		}

		/* Go ahead and Submit to SEC */
		ptr_in = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		edesc->link_tbl_dma = ptr_in;
		edesc->link_tbl = link_tbl_entry;

		edesc->link_tbl_bytes = dma_len;


		ASFIPSEC_DEBUG("len_to_caam =%d, dma_len=%d\n", len_to_caam, dma_len);

			secfp_cnstr_seq_jobdesc(edesc->hw_desc, &descSize,
			(void *)&pSA->ctx.shared_desc_phys, desc_len(pSA->ctx.sh_desc),
			(void *)&ptr_in, len_to_caam, (void *)&icv_phys, edesc->icv_bytes, PTR_SGLIST);

#ifdef ASF_IPSEC_DESC_DEBUG
		caam_desc_disasm(edesc->hw_desc, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif
	}

	return;
}
#endif

/**
 *  * HMAC shared
 *   * @descbuf - descriptor buffer
 *   * @bufsize - limit/returned descriptor buffer size
 *   * @key     - key data to inline (length based on cipher)
 *   * @cipher  - OP_ALG_ALGSEL_MD5/SHA1-512
 *   * @icv     - HMAC comparison for ICV, NULL if no check desired
 *   * @clear   - clear buffer before writing
 *   **/
int32_t secfp_cnstr_shdsc_hmac(uint32_t *descbuf, uint16_t *bufsize,
	uint8_t *algkey, uint32_t cipher, u_int8_t keylen, uint8_t *icv,
	uint8_t clear, enum key_dest keydest,
	enum key_cover keycover)
{
	u_int32_t *start;
	u_int16_t startidx, endidx;
	u_int32_t mval;

	if (!descbuf) {
		return -1;
	}

	start = descbuf++;
	startidx = descbuf - start;

	if (clear)
		memset(start, 0, (*bufsize * sizeof(u_int32_t)));

	ASFIPSEC_DEBUG("cipher = %x, keylen=%d", cipher, keylen);

	if (likely(algkey && keylen)) {
		descbuf = cmd_insert_bkey(descbuf, algkey, keylen, PTR_DIRECT,
			keydest, keycover, ITEM_REFERENCE, ITEM_CLASS2);
	}

	/* compute sequences */
	mval = 0;
	descbuf = cmd_insert_math(descbuf, MATH_FUN_SUB, MATH_SRC0_SEQINLEN,
	MATH_SRC1_REG2, MATH_DEST_VARSEQINLEN, 4, 0, 0, 0, &mval);


	/* Do operation */
	descbuf = cmd_insert_alg_op(descbuf, OP_TYPE_CLASS2_ALG,
	cipher, 0, MDSTATE_COMPLETE, ICV_CHECK_OFF, DIR_ENCRYPT);

	/* Do load (variable length) */
	descbuf = cmd_insert_seq_fifo_load(descbuf, LDST_CLASS_2_CCB,
	FIFOLDST_VLF, (FIFOLD_TYPE_MSG | FIFOLD_TYPE_LASTBOTH), 0);


	descbuf = cmd_insert_seq_store(descbuf, LDST_CLASS_2_CCB, 0,
	LDST_SRCDST_BYTE_CONTEXT, 0, keylen);


	endidx = descbuf - start;

	cmd_insert_shared_hdr(start, startidx, endidx, CTX_ERASE, SHR_ALWAYS);

#ifdef ASF_IPSEC_DESC_DEBUG
	caam_desc_disasm(start, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif

	*bufsize = endidx;

	return endidx;
}

/**
 *  * xcbc shared
 *   * @descbuf - descriptor buffer
 *   * @bufsize - limit/returned descriptor buffer size
 *   * @key     - key data (length based on cipher)
 *   * @cipher  - OP_ALG_ALGSEL_AES_XCBC_MAC
 *   * @icv     - MAC comparison for ICV, NULL if no check desired
 *   * @clear   - clear buffer before writing
 *   **/
int32_t secfp_cnstr_shdsc_xcbc(uint32_t *descbuf, uint16_t *bufsize,
	uint8_t *algkey, uint32_t cipher, u_int8_t keylen, uint8_t *icv,
	uint8_t clear, enum key_dest keydest,
	enum key_cover keycover)
{
	u_int32_t *start;
	u_int16_t startidx, endidx;
	u_int32_t mval;

	if (!descbuf) {
		return -1;
	}

	start = descbuf++;
	startidx = descbuf - start;

	if (clear)
		memset(start, 0, (*bufsize * sizeof(u_int32_t)));

	ASFIPSEC_DEBUG("cipher = %x, keylen=%d", cipher, keylen);

	if (likely(algkey && keylen)) {
		descbuf = cmd_insert_bkey(descbuf, algkey, keylen, PTR_DIRECT,
			keydest, keycover, ITEM_REFERENCE, ITEM_CLASS1);
	}

	/* compute sequences */
	mval = 0;
	descbuf = cmd_insert_math(descbuf, MATH_FUN_SUB, MATH_SRC0_SEQINLEN,
	MATH_SRC1_REG2, MATH_DEST_VARSEQINLEN, 4, 0, 0, 0, &mval);


	/* Do operation */
	descbuf = cmd_insert_alg_op(descbuf, OP_TYPE_CLASS1_ALG,
	cipher, 0, MDSTATE_COMPLETE, ICV_CHECK_OFF, DIR_ENCRYPT);

	/* Do load (variable length) */
	descbuf = cmd_insert_seq_fifo_load(descbuf, LDST_CLASS_1_CCB,
	FIFOLDST_VLF, (FIFOLD_TYPE_MSG | FIFOLD_TYPE_LASTBOTH), 0);


	descbuf = cmd_insert_seq_store(descbuf, LDST_CLASS_1_CCB, 0,
	LDST_SRCDST_BYTE_CONTEXT, 0, keylen);


	endidx = descbuf - start;

	cmd_insert_shared_hdr(start, startidx, endidx, CTX_ERASE, SHR_ALWAYS);

#ifdef ASF_IPSEC_DESC_DEBUG
	caam_desc_disasm(start, DISASM_SHOW_OFFSETS | DISASM_SHOW_RAW);
#endif

	*bufsize = endidx;

	return endidx;
}


static inline dma_addr_t dma_mem_vtop(void *v)
{
	return *(dma_addr_t *) v;
}

uint32_t *cmd_insert_math(uint32_t *descwd, uint32_t func,
			uint32_t src0, uint32_t src1,
			uint32_t dest, uint32_t len,
			uint32_t flagupd, uint32_t stall,
			uint32_t immediate, uint32_t *data)
{

	*descwd++ = CMD_MATH | func | src0 | src1 | dest |
		(len & MATH_LEN_MASK) | flagupd | stall | immediate;

	/*
	 * If IFB, add 4 byte immediate, else if one of two sources
	 * are immediate, add data by length
	 */
	if (immediate == MATH_IFB) {
		memcpy(descwd, data, 4);
		descwd++;
	} else
		if (((src0 & MATH_SRC0_MASK) == MATH_SRC0_IMM) ||
		((src1 & MATH_SRC1_MASK) == MATH_SRC1_IMM)) {
			memcpy(descwd, data, len);
			descwd += len >> 2;
		}

	return descwd;
}

uint32_t *cmd_insert_shared_hdr(uint32_t *descwd, uint8_t startidx,
				 uint8_t desclen, enum ctxsave ctxsave,
				 enum shrst share)
{
	*descwd = CMD_SHARED_DESC_HDR | HDR_ONE |
		((startidx & HDR_START_IDX_MASK) << HDR_START_IDX_SHIFT) |
		(desclen & HDR_DESCLEN_SHR_MASK) |
		(share << HDR_SD_SHARE_SHIFT) |
		((ctxsave == CTX_SAVE) ? HDR_SAVECTX : 0);

	return descwd + 1;
}


uint32_t *cmd_insert_seq_key(uint32_t *descwd, uint32_t keylen,
		enum ref_type sgref, enum key_dest dest,
		enum key_cover cover, enum item_purpose purpose)
{
	uint32_t *nextwd, keysz;

	if (!descwd)
		return 0;

	/* If PK 'e' or AF SBOX load, can't be class 2 key */
	if (((dest == KEYDST_PK_E) || (dest == KEYDST_AF_SBOX)) &&
			(purpose == ITEM_CLASS2))
		return 0;

	nextwd = descwd;

	/* Convert size (in bits) to adequate byte length */
	keysz = ((keylen & KEY_LENGTH_MASK) >> 3);
	if (keylen & 0x00000007)
		keysz++;

	/* Build command word */
	*nextwd = CMD_SEQ_KEY;
	switch (dest) {
	case KEYDST_KEYREG:
		*nextwd |= KEY_DEST_CLASS_REG;
		break;

	case KEYDST_PK_E:
		*nextwd |= KEY_DEST_PKHA_E;
		break;

	case KEYDST_AF_SBOX:
		*nextwd |= KEY_DEST_AFHA_SBOX;
		break;

	case KEYDST_MD_SPLIT:
		*nextwd |= KEY_DEST_MDHA_SPLIT;
		break;
	}

	if (cover == KEY_COVERED)
		*nextwd |= KEY_ENC;

	switch (purpose) {
	case ITEM_CLASS1:
		*nextwd |= CLASS_1;
		break;

	case ITEM_CLASS2:
		*nextwd |= CLASS_2;
		break;

	default:
		return 0;
	};
	if (sgref == PTR_SGLIST)
		*nextwd |= KEY_SGF;

	*nextwd++ |= keysz;

	return nextwd;
}


uint32_t *cmd_insert_alg_op(uint32_t *descwd, uint32_t optype,
		uint32_t algtype, uint32_t algmode,
		enum mdstatesel mdstate, enum icvsel icv,
		enum algdir dir)
{
	*descwd = CMD_OPERATION | optype | algtype | algmode |
		mdstate << OP_ALG_AS_SHIFT |
		icv << OP_ALG_ICV_SHIFT |
		(dir ? OP_ALG_DECRYPT : OP_ALG_ENCRYPT);

	return ++descwd;
}

int secfp_cnstr_seq_jobdesc(uint32_t *jobdesc, uint16_t *jobdescsz,
		uint32_t *shrdesc, uint16_t shrdescsz,
		void *inbuf, uint32_t insize,
		void *outbuf, uint32_t outsize, uint32_t flag)
{
	uint32_t *next;

	/*
	* Basic structure is
	* - header (assume sharing, reverse order)
	* - SEQ_OUT_PTR
	* - SEQ_IN_PTR
	*/

	/* Make running pointer past where header will go */
	next = jobdesc;
	next++;

	/* Insert sharedesc */

	if (sizeof(dma_addr_t) == sizeof(u32)) {
		*next++ = dma_mem_vtop(shrdesc);
	} else {
		*next++ = upper_32_bits(dma_mem_vtop(shrdesc));
		*next++ = lower_32_bits(dma_mem_vtop(shrdesc));
	}

	/* Sequence pointers */
	if (flag == PTR_DIRECT) {
		next = cmd_insert_seq_out_ptr(next, outbuf, outsize, PTR_DIRECT);
		next = cmd_insert_seq_in_ptr(next, inbuf, insize, PTR_DIRECT);
	} else {
		next = cmd_insert_seq_out_ptr(next, outbuf, outsize, PTR_DIRECT);
		next = cmd_insert_seq_in_ptr(next, inbuf, insize, PTR_SGLIST);
	}

		/* Now update header */
	*jobdescsz = next - jobdesc;	/* add 1 to include header */
	cmd_insert_hdr(jobdesc, shrdescsz, *jobdescsz, SHR_ALWAYS,
			SHRNXT_SHARED, ORDER_REVERSE, DESC_STD);

	return 0;
}

uint32_t *cmd_insert_hdr(uint32_t *descwd, uint8_t startidx,
			uint8_t desclen, enum shrst share,
			enum shrnext sharenext, enum execorder reverse,
			enum mktrust mktrusted)
{
	*descwd = CMD_DESC_HDR | HDR_ONE |
		((startidx & HDR_START_IDX_MASK) << HDR_START_IDX_SHIFT) |
		(desclen & HDR_DESCLEN_MASK) |
		(share << HDR_SD_SHARE_SHIFT) |
		((sharenext == SHRNXT_SHARED) ? HDR_SHARED : 0) |
		((reverse == ORDER_REVERSE) ? HDR_REVERSE : 0) |
		((mktrusted = DESC_SIGN) ? HDR_MAKE_TRUSTED : 0);

	return descwd + 1;
}

uint32_t *cmd_insert_seq_out_ptr(uint32_t *descwd, void *ptr,
				uint32_t len, enum ref_type sgref)
{
	*descwd = CMD_SEQ_OUT_PTR | ((sgref == PTR_SGLIST) ? SQOUT_SGF : 0) |
			len;

	if (sizeof(dma_addr_t) == sizeof(u32)) {
		*(descwd + 1) = dma_mem_vtop(ptr);
	} else {
		*(descwd + 1) = upper_32_bits(dma_mem_vtop(ptr));
		*(descwd + 2) = lower_32_bits(dma_mem_vtop(ptr));
	}

	if (len > 0xffff) {
		*descwd |= SQOUT_EXT;
		*(descwd + 1 + sizeof(dma_addr_t) / sizeof(u32)) = len;
		return descwd + 2 + sizeof(dma_addr_t) / sizeof(u32);
	}

	return descwd + 1 + sizeof(dma_addr_t) / sizeof(u32);
}

uint32_t *cmd_insert_seq_in_ptr(uint32_t *descwd, void *ptr,
				 uint32_t len, enum ref_type sgref)
{
	*descwd = CMD_SEQ_IN_PTR | ((sgref == PTR_SGLIST) ? SQIN_SGF : 0) | len;

	if (sizeof(dma_addr_t) == sizeof(u32)) {
		*(descwd + 1) = dma_mem_vtop(ptr);
	} else {
		*(descwd + 1) = upper_32_bits(dma_mem_vtop(ptr));
		*(descwd + 2) = lower_32_bits(dma_mem_vtop(ptr));
	}

	if (len > 0xffff) {
		*descwd |= SQIN_EXT;
		*(descwd + 1 + sizeof(dma_addr_t) / sizeof(u32)) = len;
		return descwd + 2 + sizeof(dma_addr_t) / sizeof(u32);
	}

	return descwd + 1 + sizeof(dma_addr_t) / sizeof(u32);
}

static inline uint32_t *cmd_insert_bkey(
	uint32_t	*descwd,
	uint8_t		*key,
	uint32_t	keylen,
	enum ref_type	sgref,
	enum key_dest	dest,
	enum key_cover	cover,
	enum item_inline	imm,
	enum item_purpose	purpose)
{
	uint32_t *nextwd;

	if ((!descwd) || (!key))
		return 0;

	/* If PK 'e' or AF SBOX load, can't be class 2 key */
	if (((dest == KEYDST_PK_E) || (dest == KEYDST_AF_SBOX)) &&
		(purpose == ITEM_CLASS2))
		return 0;

	/* sg table can't be inlined */
	if ((sgref == PTR_SGLIST) && (imm == ITEM_INLINE))
		return 0;

	nextwd = descwd;

	/* Build command word */
	*nextwd = CMD_KEY;
	switch (dest) {
	case KEYDST_KEYREG:
		*nextwd |= KEY_DEST_CLASS_REG;
		break;

	case KEYDST_PK_E:
		*nextwd |= KEY_DEST_PKHA_E;
		break;

	case KEYDST_AF_SBOX:
		*nextwd |= KEY_DEST_AFHA_SBOX;
		break;

	case KEYDST_MD_SPLIT:
		*nextwd |= KEY_DEST_MDHA_SPLIT;
		break;
	}

	if (cover == KEY_COVERED)
		*nextwd |= KEY_ENC;

	if (imm == ITEM_INLINE)
		*nextwd |= KEY_IMM;

	switch (purpose) {
	case ITEM_CLASS1:
		*nextwd |= CLASS_1;
		break;

	case ITEM_CLASS2:
		*nextwd |= CLASS_2;
		break;

	default:
		return 0;
	};
	if (sgref == PTR_SGLIST)
		*nextwd |= KEY_SGF;

	*nextwd++ |= keylen;

	if (imm == ITEM_INLINE) {
		memcpy(nextwd, (void *)key, keylen);
		nextwd += keylen / sizeof(*nextwd);
	} else
		if (sizeof(dma_addr_t) == sizeof(u32)) {
			*nextwd++ = dma_mem_vtop(key);
		} else {
			*nextwd++ = upper_32_bits(dma_mem_vtop(key));
			*nextwd++ = lower_32_bits(dma_mem_vtop(key));
		}
	return nextwd;
}

uint32_t *cmd_insert_seq_store(uint32_t *descwd, uint32_t class_access,
				uint32_t variable_len_flag, uint32_t src,
				uint8_t offset, uint8_t len)
{
	*descwd = CMD_SEQ_STORE | (class_access & CLASS_MASK) |
		(variable_len_flag ? LDST_SGF : 0) |
		src | ((offset << LDST_OFFSET_SHIFT) & LDST_OFFSET_MASK) |
		((len << LDST_LEN_SHIFT) & LDST_LEN_MASK);

	return descwd + 1;
}

uint32_t *cmd_insert_seq_fifo_load(uint32_t *descwd, uint32_t class_access,
				uint32_t variable_len_flag,
				uint32_t data_type, uint32_t len)
{
	*descwd = CMD_SEQ_FIFO_LOAD | (class_access & CLASS_MASK) |
		(variable_len_flag ? FIFOLDST_SGF : 0) |
		data_type | ((len & FIFOLDST_LEN_MASK) << LDST_LEN_SHIFT);

	if (len > 0xffff) {
		*descwd |= FIFOLDST_EXT;
		*(descwd + 1) = len;
		return descwd + 2;
	}

	return descwd + 1;
}
