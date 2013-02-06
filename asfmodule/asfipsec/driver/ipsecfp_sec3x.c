/**************************************************************************
 * Copyright 2011-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecfp_sec3x.c
 * Description: Contains the optimized routines for accessing SEC3X
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *		Sandeep Malik <sandeep.malik@freescale.com>
 *
 */
/* History
 * Version	Date		Author		Change Description
 *
*/
/****************************************************************************/
#ifdef CONFIG_ASF_SEC3x

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
#include <linux/inetdevice.h>
#include "ipseccmn.h"
#include "../../asfffp/driver/asfreasm.h"

extern struct device *pdev;

#ifdef ASFIPSEC_DEBUG_FRAME
void print_desc(struct talitos_desc *desc)
{
	int ii;
	ASFIPSEC_PRINT("Hdr: 0x%x", desc->hdr);
	ASFIPSEC_PRINT("hdr_lo: 0x%x", desc->hdr_lo);
	for (ii = 0; ii < 7; ii++) {
		ASFIPSEC_PRINT("PrtrIndex %d: Ptr[].len = %d,"
			"ptr[].extent=%d, ptr[].eptr=0x%x, ptr[].ptr=0x%x\n",
			ii, desc->ptr[ii].len, desc->ptr[ii].j_extent,
			desc->ptr[ii].eptr, desc->ptr[ii].ptr);
	}
}
#else
#define print_desc(a)
#endif

int secfp_createInSATalitosDesc(inSA_t *pSA)
{
	int iphdrlen = SECFP_IPV4_HDR_LEN;
#ifdef ASF_IPV6_FP_SUPPORT
	iphdrlen = pSA->SAParams.tunnelInfo.bIPv4OrIPv6 ? SECFP_IPV6_HDR_LEN :
		SECFP_IPV4_HDR_LEN;
#endif
	pSA->desc_hdr_template |= DESC_HDR_DIR_INBOUND;
	if ((pSA->SAParams.bUseExtendedSequenceNumber) ||
		((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBC_MAC)
		== DESC_HDR_MODE0_AES_XCBC_MAC)) {
		if (pSA->SAParams.bEncrypt) {
			if (pSA->SAParams.bAuth) {
				pSA->option[0] = SECFP_AUTH;
				/* Need to check this */
				pSA->hdr_Auth_template_0 |=
					DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU |
					DESC_HDR_DIR_INBOUND;
				if ((pSA->hdr_Auth_template_0 &
					DESC_HDR_MODE0_AES_XCBC_MAC)
					== DESC_HDR_MODE0_AES_XCBC_MAC) {
				/*pSA->hdr_Auth_template_0 |=
					DESC_HDR_MODE0_AES_XCBC_CICV;*/
				} else
					pSA->hdr_Auth_template_0 |= DESC_HDR_MODE0_MDEU_CICV;

				pSA->option[1] = SECFP_CIPHER;
				if (!((pSA->desc_hdr_template &
					(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)))
					pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
				else
					pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_NONSNOOP;

				pSA->validIpPktLen = (SECFP_ESP_HDR_LEN +
							iphdrlen) +
							pSA->SAParams.ulIvSize + pSA->SAParams.uICVSize;
			} else {
				pSA->option[0] = SECFP_CIPHER;
				if (!((pSA->desc_hdr_template &
					(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
					== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)))
					pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
				else
					pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_NONSNOOP;

				pSA->option[1] = SECFP_NONE;
				pSA->validIpPktLen = (SECFP_ESP_HDR_LEN +
							iphdrlen) +
							pSA->SAParams.ulIvSize;
			}
		} else {
			pSA->option[0] = SECFP_AUTH;
			/* Need to check this */
			pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU |
							DESC_HDR_DIR_INBOUND;
			if (((pSA->hdr_Auth_template_0 &
					DESC_HDR_MODE0_AES_XCBC_MAC)
					== DESC_HDR_MODE0_AES_XCBC_MAC)) {
				/*pSA->hdr_Auth_template_0 |=
					DESC_HDR_MODE0_AES_XCBC_CICV; */
			} else
				pSA->hdr_Auth_template_0 |= DESC_HDR_MODE0_MDEU_CICV;

			pSA->option[1] = SECFP_NONE;
			pSA->validIpPktLen = SECFP_ESP_HDR_LEN +
						iphdrlen +
						pSA->SAParams.uICVSize;
		}
	} else {
		pSA->option[1] = SECFP_NONE;
		if (pSA->SAParams.bEncrypt && pSA->SAParams.bAuth) {
			/* In the case of ESP_NULL, IV Size will be 0 */
			pSA->validIpPktLen = (SECFP_ESP_HDR_LEN	+ iphdrlen) +
						pSA->SAParams.ulIvSize + pSA->SAParams.uICVSize;

			if (((pSA->desc_hdr_template &
				(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
				== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
				pSA->option[0] = SECFP_AESCTR_BOTH;
				pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_HMAC;
			} else {
				pSA->option[0] = SECFP_BOTH;
				pSA->desc_hdr_template |= DESC_HDR_TYPE_IPSEC_ESP;
				pSA->desc_hdr_template |= DESC_HDR_MODE1_MDEU_CICV;
				pSA->desc_hdr_template |= pSA->hdr_Auth_template_1;
			}
		} else if (pSA->SAParams.bEncrypt && (!pSA->SAParams.bAuth)) {
			pSA->option[0] = SECFP_CIPHER;
			if (!((pSA->desc_hdr_template &
				(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
				== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
				pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
			} else {
				pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
			}
			pSA->validIpPktLen = (SECFP_ESP_HDR_LEN + iphdrlen) +
						pSA->SAParams.ulIvSize;
		} else { /* This is the case of NULL Encryption */
			pSA->option[0] = SECFP_AUTH;
			/* Need to check this */
			pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU|
							DESC_HDR_MODE0_MDEU_CICV |
							DESC_HDR_DIR_INBOUND;
			pSA->validIpPktLen = SECFP_ESP_HDR_LEN +
					iphdrlen + pSA->SAParams.uICVSize;
		}
	}
	if (pSA->SAParams.bAuth)
		pSA->AuthKeyDmaAddr = dma_map_single(pdev,
					&pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen,
					DMA_TO_DEVICE);
	if (pSA->SAParams.bEncrypt)
		pSA->EncKeyDmaAddr = dma_map_single(pdev,
					&pSA->SAParams.ucEncKey,
					pSA->SAParams.EncKeyLen,
					DMA_TO_DEVICE);
	return 0;
}

int secfp_createOutSATalitosDesc(outSA_t *pSA)
{
	if ((pSA->SAParams.bUseExtendedSequenceNumber) ||
		((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBC_MAC)
		== DESC_HDR_MODE0_AES_XCBC_MAC)) {
		if (pSA->SAParams.bEncrypt) {
			pSA->option[0] = SECFP_CIPHER;
			pSA->bIVDataPresent = ASF_TRUE;
			if (!((pSA->desc_hdr_template &
				(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
				== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
				pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU
						| DESC_HDR_MODE0_ENCRYPT;
			} else {
				pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
			}
			if (pSA->SAParams.bAuth) {
				/* Prepare the header for performing the cryptographic operation */
				pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
				pSA->option[1] = SECFP_AUTH;
			}
		} else {
			pSA->option[0] = SECFP_AUTH;
			/* Prepare the header for performing the cryptographic operation */
			pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
			pSA->option[1] = SECFP_NONE;
		}
	} else {
		pSA->option[1] = SECFP_NONE;
		if (pSA->SAParams.bEncrypt && pSA->SAParams.bAuth) {
			pSA->bIVDataPresent = ASF_TRUE;
			if (((pSA->desc_hdr_template &
				(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
				== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
				pSA->option[0] = SECFP_AESCTR_BOTH;
				pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_HMAC;
			} else {
				pSA->option[0] = SECFP_BOTH;
				pSA->desc_hdr_template |= DESC_HDR_TYPE_IPSEC_ESP |
							DESC_HDR_MODE0_ENCRYPT;
				pSA->desc_hdr_template |= pSA->hdr_Auth_template_1;
			}
		} else if (pSA->SAParams.bEncrypt && (!pSA->SAParams.bAuth)) {
			pSA->option[0] = SECFP_CIPHER;
			pSA->bIVDataPresent = ASF_TRUE;
			if (!((pSA->desc_hdr_template &
				(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
				== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
				pSA->desc_hdr_template |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU
							| DESC_HDR_MODE0_ENCRYPT;
			} else {
				pSA->desc_hdr_template |= DESC_HDR_TYPE_AESU_CTR_NONSNOOP;
			}
		} else {
			pSA->option[0] = SECFP_AUTH;
			if (pSA->SAParams.bAuth) {
				/* Prepare the header for performing the cryptographic operation */
				pSA->hdr_Auth_template_0 |= DESC_HDR_TYPE_COMMON_NONSNOOP_NO_AFEU;
			}
		}
	}
	if (pSA->SAParams.bAuth)
		pSA->AuthKeyDmaAddr =
			dma_map_single(pdev, &pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen,
					DMA_TO_DEVICE);

	if (pSA->SAParams.bEncrypt)
		pSA->EncKeyDmaAddr =
			dma_map_single(pdev, &pSA->SAParams.ucEncKey,
					pSA->SAParams.EncKeyLen,
					DMA_TO_DEVICE);

	return 0;
}
/*
 * Function prepares the descriptors based on the encryption and authentication
 * algorithm. The prepared descriptor is submitted to SEC.
 */
void secfp_prepareOutDescriptor(struct sk_buff *skb, void *pData,
		void *descriptor, unsigned int ulOptionIndex)
{
	dma_addr_t ptr;
	unsigned int *src, *tgt;
	unsigned char *pNounceIVCounter;
	outSA_t *pSA = (outSA_t *) (pData);
	int iDword, iDword1;
	unsigned int *ptr1;
	struct talitos_desc *desc = (struct talitos_desc *)descriptor;

	if (!ulOptionIndex) {		/* 1st iteration */
		ASFIPSEC_DBGL2("prepareOutDescriptor: Doing DMA mapping");
		ptr = dma_map_single(pdev, skb->data, (skb->len+12 +
			SECFP_APPEND_BUF_LEN_FIELD+SECFP_NOUNCE_IV_LEN),
			DMA_TO_DEVICE);
		ptr1 = (unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		*ptr1 = ptr;
	} else {
		/* Take it from the skb->cb */
		ptr = *(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);

		ASFIPSEC_DBGL2("ptr = 0x%x", ptr);
	}
	desc->hdr_lo = 0;
	switch (pSA->option[ulOptionIndex]) {
	case SECFP_AUTH:
	{
		desc->hdr = pSA->hdr_Auth_template_0;

		SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);
		SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0);
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr,
				0);

		if (pSA->SAParams.bUseExtendedSequenceNumber) {
			/* To be checked */
			SECFP_SET_DESC_PTR(desc->ptr[3],
				skb->len + SECFP_APPEND_BUF_LEN_FIELD,
				ptr , 0);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[3],
				skb->len, ptr, 0);
		}
		SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0);
		if (!((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBC_MAC)
			== DESC_HDR_MODE0_AES_XCBC_MAC)) {
			iDword = 5;
			iDword1 = 6;
		} else {
			iDword = 6;
			iDword1 = 5;
		}
		SECFP_SET_DESC_PTR(desc->ptr[iDword],
				pSA->SAParams.uICVSize,
				ptr+skb->len , 0);

		SECFP_SET_DESC_PTR(desc->ptr[iDword1],
				0, 0, 0);
		print_desc(desc);
		break;
	}
	case SECFP_CIPHER:
	{
		desc->hdr = pSA->desc_hdr_template;

		SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);

		if (((pSA->desc_hdr_template &
			(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
			== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)))
		/* Set up the AES Context field */
		{
			src = (unsigned int *) pSA->SAParams.ucNounceIVCounter;
			pNounceIVCounter = skb->data + skb->len
				+ SECFP_APPEND_BUF_LEN_FIELD + 12;
			tgt = (unsigned int *) pNounceIVCounter;

			/* Copying 2 integers of IV, Assumes that the first
				4 bytes of Nounce is valid and the 16th byte
				is set to 128; not sure why though? */
			*(tgt) = *src;
			*(tgt + 3) = src[3];
			src = (unsigned int *) (skb->data + SECFP_ESP_HDR_LEN);
			*(tgt+1) = src[0];
			*(tgt+2) = src[1];

			/* todo-verify why we are setting COUNTER_BLK_LEN + 8 */
			SECFP_SET_DESC_PTR(desc->ptr[1],
				SECFP_COUNTER_BLK_LEN,
				ptr + skb->len +
					SECFP_APPEND_BUF_LEN_FIELD + 12,
				0);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[1],
				pSA->SAParams.ulIvSize,
				ptr + SECFP_ESP_HDR_LEN,
				0);
		}

		/* Copy the prepared encryption key */
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr,
				0);

		SECFP_SET_DESC_PTR(desc->ptr[3],
				skb->len - pSA->ulSecHdrLen,
				ptr + pSA->ulSecHdrLen,
				0);


		SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->len - pSA->ulSecHdrLen,
				ptr + pSA->ulSecHdrLen,
				0);

		/* removed 12 for extent */

		SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
		print_desc(desc);

		break;
	}
	case SECFP_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template;
		ASFIPSEC_PRINT("Desc->hdr = 0x%x", desc->hdr);
		/* Set up Auth Key */
		/* Copy the prepared authentication key */
		SECFP_SET_DESC_PTR(desc->ptr[0],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr,
				0);
		ASFIPSEC_DBGL2("AuthkeyLen %d AuthKeyDmaAddr 0x%x\n",
			pSA->SAParams.AuthKeyLen, pSA->AuthKeyDmaAddr);
		ASFIPSEC_DBGL2("ulSecHdrLen = %d Auth Only data :"
			"data ptr=0x%x", pSA->ulSecHdrLen, ptr);
		SECFP_SET_DESC_PTR(desc->ptr[1],
				pSA->ulSecHdrLen,
				ptr,
				0);
		ASFIPSEC_DBGL2("ulSecHdrLen %d ptr 0c%x\n",
			pSA->ulSecHdrLen, ptr);
		ASFIPSEC_DBGL2("IVSize = %d, IVdataptr=0x%x, ",
			pSA->SAParams.ulIvSize, ptr+SECFP_ESP_HDR_LEN);
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.ulIvSize,
				ptr + SECFP_ESP_HDR_LEN,
				0);

		/* Copy the prepared encryption key */
		SECFP_SET_DESC_PTR(desc->ptr[3],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr,
				0);
		ASFIPSEC_DBGL2("EnckeyLen %d EncKeyDmaAddr 0c%x\n",
			pSA->SAParams.EncKeyLen, pSA->EncKeyDmaAddr);

		ASFIPSEC_DBGL2("Input data setup at 0x%x: len = %d",
			ptr + pSA->ulSecHdrLen,
			skb->len - pSA->ulSecHdrLen);

		SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->len - pSA->ulSecHdrLen,
				ptr + pSA->ulSecHdrLen,
				0);

		ASFIPSEC_DBGL2("Output data setup at 0x%x: len = %d",
			ptr + pSA->ulSecHdrLen,
			skb->len - pSA->ulSecHdrLen);

		SECFP_SET_DESC_PTR(desc->ptr[5],
				skb->len - pSA->ulSecHdrLen,
				ptr + pSA->ulSecHdrLen,
				12);
		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
		print_desc(desc);
		break;
	}
	case SECFP_AESCTR_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template | pSA->hdr_Auth_template_1;
		/* Set up Auth Key */
		/* Copy the prepared authentication key */
		SECFP_SET_DESC_PTR(desc->ptr[0],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr,
				0);

		SECFP_SET_DESC_PTR(desc->ptr[1],
				pSA->ulSecHdrLen,
				ptr ,
				0);

		/* Copy the prepared encryption key */
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr,
				0);


		/* Set up the AES Context field - todo- validate it */

		src = (unsigned int *) pSA->SAParams.ucNounceIVCounter;
		pNounceIVCounter = skb->data + skb->len
				+ SECFP_APPEND_BUF_LEN_FIELD + 12;

		tgt = (unsigned int *) pNounceIVCounter;

		/* Copying 2 integers of IV, Assumes that the
			first 4 bytes of Nounce is valid and the 16th byte
			is set to 128; not sure why though? */
		*(tgt) = *src;
		*(tgt + 3) = src[3];
		src = (unsigned int *) (skb->data + SECFP_ESP_HDR_LEN);
		*(tgt+1) = src[0];
		*(tgt+2) = src[1];

		/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
		SECFP_SET_DESC_PTR(desc->ptr[3],
			SECFP_COUNTER_BLK_LEN,
			ptr + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12,
			0);

		SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->len - pSA->ulSecHdrLen,
				ptr + pSA->ulSecHdrLen ,
				0);

		SECFP_SET_DESC_PTR(desc->ptr[5],
				skb->len - pSA->ulSecHdrLen,
				ptr + pSA->ulSecHdrLen,
				0);

		/* Where to put the ICV */
		SECFP_SET_DESC_PTR(desc->ptr[6],
				12,
				ptr + skb->len ,
				0);

		break;
	}
	default:
		ASFIPSEC_WARN("Unknown Option :: Index = %d ",
			pSA->option[ulOptionIndex]);
		break;

	}
	desc->hdr |= DESC_HDR_DONE_NOTIFY;
}

void secfp_dump_sg(secfp_sgEntry_t *pSgEntry)
{
	ASFIPSEC_PRINT("pSgEntry->len = %d, pSgentry->flags = %d,"\
		"pSgEntry->eptr = 0x%x, pSgEntry->ptr = 0x%x",
		pSgEntry->len, pSgEntry->flags, pSgEntry->eptr, pSgEntry->ptr);
}

void secfp_dump_sg_in_skb(struct sk_buff *skb)
{
	int ii;
	secfp_sgEntry_t *pSgEntry =
		(secfp_sgEntry_t *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX+4]);

	ASFIPSEC_DEBUG("Printing from Cb fields to check consistency");
	for (ii = 0; ii < 3; ii++, pSgEntry++) {
		ASFIPSEC_PRINT("pSgEntry = 0x%x", (unsigned int) pSgEntry);
		secfp_dump_sg(pSgEntry);
	}
}

void secfp_dma_unmap_sglist(struct sk_buff *skb)
{
	struct sk_buff *pSgSkb = NULL;
	secfp_sgEntry_t *pSgEntry;
	if (skb_shinfo(skb)->frag_list) {
		/* where to start for the link table ptrs */
		pSgSkb = skb_shinfo(skb)->frag_list;
	} else if (skb->prev) {
		pSgSkb = skb->prev;
	}
	if (pSgSkb) {
		pSgEntry = (secfp_sgEntry_t *) &(pSgSkb->cb
				[SECFP_SKB_DATA_DMA_INDEX + 4]);
		SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t) *(unsigned int *)
			&(skb->cb[SECFP_SKB_SG_DMA_INDEX]), 32);
		while (1) {
			if (pSgEntry->flags == DESC_PTR_LNKTBL_RETURN) {
				/* Last one to unmap */
				break;
			}
			if (pSgEntry->flags == DESC_PTR_LNKTBL_NEXT) {
				SECFP_UNMAP_SINGLE_DESC(pdev,
						(dma_addr_t) pSgEntry->ptr, 32);
				pSgSkb = pSgSkb->next;
				pSgEntry = (secfp_sgEntry_t *) &(pSgSkb->cb
						[SECFP_SKB_DATA_DMA_INDEX+4]);
			} else
				pSgEntry++;
		}
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
unsigned int secfp_inHandleICVCheck3x(void *dsc, struct sk_buff *skb)
{
	int ii;
	struct talitos_desc *desc = (struct talitos_desc *)dsc;

	if (skb->cb[SECFP_3X_SA_OPTION_INDEX] == SECFP_BOTH) {
		ASFIPSEC_DEBUG("desc->hdr_lo = 0x%x, desc->hdr = 0x%x",
			desc->hdr_lo, desc->hdr);

		if ((desc->hdr_lo & DESC_HDR_LO_ICCR1_MASK) !=
			DESC_HDR_LO_ICCR1_PASS) {
			ASFIPSEC_WARN("hw cmp: ICV Verification failed");
			return 1;
		} else {
			skb->len -= skb->cb[SECFP_ICV_LENGTH];
		}
	} else if (skb->cb[SECFP_3X_SA_OPTION_INDEX] == SECFP_AUTH) {
	/* In the two submission case, only first time around,
		we need to do the ICV comparison, hence using the REF_INDEX
		to find out first or second time */
		ASFIPSEC_DEBUG("desc->hdr_lo = 0x%x, desc->hdr = 0x%x",
			desc->hdr_lo, desc->hdr);

		/* In the 2 submission case,
			it will not hit the ICV verification again */
		if (skb->cb[SECFP_REF_INDEX])
			skb->cb[SECFP_3X_SA_OPTION_INDEX] = 0;

		if (desc->hdr_lo & DESC_HDR_LO_ICCR0_MASK) {
			/* If ICV verification was done in h/w */
			if ((desc->hdr_lo & DESC_HDR_LO_ICCR0_MASK) !=
				DESC_HDR_LO_ICCR0_PASS) {
				ASFIPSEC_WARN("hw comparison ICV Verification"
					"failed desc->hdr_lo = 0x%x",
					desc->hdr_lo);
				return 1;
			} else {
				skb->len -= skb->cb[SECFP_ICV_LENGTH];
				return 0;
			}
		} else {
			unsigned long int ulESNLen;
			if (*((unsigned int *)(skb->data + skb->len
				+ SECFP_ESN_MARKER_POSITION)) == 0xAAAAAAAA) {
				ulESNLen = SECFP_APPEND_BUF_LEN_FIELD;
			} else {
				ulESNLen = 0;
			}

#ifdef ASF_IPSEC_DEBUG
			for (ii = 0; ii < 3; ii++) {
				ASFIPSEC_DEBUG("Computed ICV = 0x%8x,"
					"Received ICV =0x%8x",
					*(unsigned int *)&(skb->data[skb->len
						+ (ii*4) + ulESNLen]),
					*(unsigned int *)&skb->data[skb->len
						- 12 + (ii*4) + ulESNLen]);
			}
#endif

			for (ii = 0; ii < 3; ii++) {
				if (*(unsigned int *)&(skb->data[skb->len
						+ (ii*4) + ulESNLen])
					!= *(unsigned int *)&(skb->data[skb->len
						- 12 + (ii*4) + ulESNLen])) {
					break;
				}
			}
			if (ii != 3) {
				ASFIPSEC_WARN("Byte comparison ICV failed");
				return 1;
			}
			skb->len -= skb->cb[SECFP_ICV_LENGTH];
			return 0;
		}
	} else if (skb->cb[SECFP_3X_SA_OPTION_INDEX] == SECFP_AESCTR_BOTH) {
	/* SECFP_AESCTR_BOTH */

		ASFIPSEC_DEBUG("desc->hdr_lo = 0x%x", desc->hdr_lo);
		for (ii = 0; ii < 3; ii++) {
			if (*(unsigned int *)&(skb->data[skb->len + (ii*4)])
				!= *(unsigned int *)&(skb->data[skb->len - 12
								+ (ii*4)]))
				break;
		}
		if (ii != 3) {
			ASFIPSEC_WARN("ICV Comparison failed");
			return 1;
		}
		skb->len -= skb->cb[SECFP_ICV_LENGTH];
	}
	return 0;
}

/*
 * This function prepares the In descriptor.
 * Prepares the descriptor based on the SA encryption/authentication
 * algorithms.
 */
void secfp_prepareInDescriptor(struct sk_buff *skb,
					void *pData, void *descriptor,
					unsigned int ulIndex)
{
	unsigned int *tgt, *src;
	dma_addr_t addr;
	inSA_t *pSA = (inSA_t *)pData;
	unsigned char *pNounceIVCounter;
	unsigned int *ptr1;
	int len;
	struct talitos_desc *desc = (struct talitos_desc *)descriptor;

	if (!ulIndex) {	/* first iteration */
		addr = dma_map_single(pdev, skb->data,
				(skb->len + 12 +
				SECFP_APPEND_BUF_LEN_FIELD +
				SECFP_NOUNCE_IV_LEN), DMA_TO_DEVICE);
		ptr1 = (unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		*ptr1 = addr;
		ASFIPSEC_DEBUG("ulIndex = %d: addr = 0x%x",
			ulIndex, addr);
	} else {
		/* Take information from the cb field */
		addr = *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		ASFIPSEC_DEBUG("ulIndex= %d: addr = 0x%x",
			ulIndex, addr);
	}
	desc->hdr_lo = 0;
	switch (pSA->option[ulIndex]) {
	case SECFP_AUTH:
	{
		desc->hdr = pSA->hdr_Auth_template_0;

		ASFIPSEC_DEBUG("skb->len = %d, addr = 0x%x, pSA->SAParams.uICVSize =%d",
			skb->len, addr, pSA->SAParams.uICVSize);

		SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0)
		SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0)
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.AuthKeyLen,
			pSA->AuthKeyDmaAddr, 0)
		if (pSA->SAParams.bUseExtendedSequenceNumber) {
			len = skb->len + SECFP_APPEND_BUF_LEN_FIELD;
		} else {
			len = skb->len;
		}
		/* Setting up data */
		SECFP_SET_DESC_PTR(desc->ptr[3], len - 12, addr, 0)

		/* Setting up ICV Check :
			Only when AES_XCBC_MAC is not programmed */
		if (pSA->SAParams.ucAuthAlgo != SECFP_HMAC_AES_XCBC_MAC) {
			SECFP_SET_DESC_PTR(desc->ptr[4], pSA->SAParams.uICVSize,
				addr + len - pSA->SAParams.uICVSize, 0)
			SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0)
			SECFP_SET_DESC_PTR(desc->ptr[6], pSA->SAParams.uICVSize,
				addr + len, 0);
#ifdef ASF_IPSEC_DEBUG
		{
			int ii;
			for (int ii = 0; ii < 3; ii++)
				ASFIPSEC_DEBUG("Offset ii=%d 0x%8x", ii,
				*(unsigned int *)&(skb->data[skb->len + ii*4]));
		}
#endif
		}
		SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
		print_desc(desc);
		break;
	}
	case SECFP_CIPHER:
	{
		desc->hdr = pSA->desc_hdr_template;

		if ((pSA->desc_hdr_template &
			(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
			== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)) {
			/* Set up the AES Context field
			- Need to validate this with soft crypto */

			src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
			pNounceIVCounter = skb->data + skb->len
				+ SECFP_APPEND_BUF_LEN_FIELD + 12;
			tgt = (unsigned int *)pNounceIVCounter;

			/* Copying 2 integers of IV, Assumes that the first
				4 bytes of Nounce is valid and the 16th byte
				is set to 128; not sure why though? */
			*(tgt) = *src;
			*(tgt+3) = src[3];
			src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
			*(tgt+1) = src[0];
			*(tgt+2) = src[1];

			SECFP_SET_DESC_PTR(desc->ptr[1], SECFP_COUNTER_BLK_LEN,
				addr + skb->len
				+ SECFP_APPEND_BUF_LEN_FIELD + 12, 0)
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[1], pSA->SAParams.ulIvSize,
				addr + SECFP_ESP_HDR_LEN, 0)
		}

		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr, 0)

		if ((ulIndex) && (skb->cb[SECFP_REF_INDEX] == 3)) {
			/* We have queued the packet and
				c/b has not yet triggered */
			/* if 2nd iteration is encryption, then we need to
				reduce the length by ICV Length */
			SECFP_SET_DESC_PTR(desc->ptr[3],
					skb->len - pSA->ulSecHdrLen - 12,
					addr + pSA->ulSecHdrLen,
					0)

			SECFP_SET_DESC_PTR(desc->ptr[4],
					skb->len - pSA->ulSecHdrLen - 12,
					addr + pSA->ulSecHdrLen,
					0)
		} else {
			/* In the 2 descriptor case, callback has triggered,
				so we need not to reduce by the ICV length
			*/
			SECFP_SET_DESC_PTR(desc->ptr[3],
					skb->len - pSA->ulSecHdrLen,
					addr + pSA->ulSecHdrLen,
					0);
			SECFP_SET_DESC_PTR(desc->ptr[4],
					skb->len - pSA->ulSecHdrLen,
					addr + pSA->ulSecHdrLen,
					0);
		}
		/* Set the descriptors 5 and 6 and 6 to 0 */
		SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0)
		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0)
		print_desc(desc);
		break;
	}
	case SECFP_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template;

		SECFP_SET_DESC_PTR(desc->ptr[0],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr, 0)
		SECFP_SET_DESC_PTR(desc->ptr[1], pSA->ulSecHdrLen, addr, 0)
		SECFP_SET_DESC_PTR(desc->ptr[2], pSA->SAParams.ulIvSize,
					addr+SECFP_ESP_HDR_LEN, 0)
		SECFP_SET_DESC_PTR(desc->ptr[3],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr, 0)

		SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->len - pSA->ulSecHdrLen - 12,
				addr + pSA->ulSecHdrLen,
				12);

		SECFP_SET_DESC_PTR(desc->ptr[5],
				skb->len - pSA->ulSecHdrLen - 12,
				addr + pSA->ulSecHdrLen,
				0);

		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
	}
	break;
	case SECFP_AESCTR_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template |
				pSA->hdr_Auth_template_1 ;

		SECFP_SET_DESC_PTR(desc->ptr[0],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr,
				0);

		SECFP_SET_DESC_PTR(desc->ptr[1],
				pSA->ulSecHdrLen,
				addr,
				0);

		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr,
				0);

		/* Set up the AES Context field
			- Need to validate this with soft crypto */

		src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
		pNounceIVCounter = skb->data + skb->len
				+ SECFP_APPEND_BUF_LEN_FIELD + 12;
		tgt = (unsigned int *)pNounceIVCounter;

		/* Copying 2 integers of IV, Assumes that the first 4 bytes
			of Nounce is valid and the 16th byte
			is set to 128; not sure why though? */
		*(tgt) = *src;
		*(tgt + 3) = src[3];
		src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
		*(tgt+1) = src[0];
		*(tgt+2) = src[1];

		/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
		SECFP_SET_DESC_PTR(desc->ptr[3], SECFP_COUNTER_BLK_LEN,
			addr + skb->len + SECFP_APPEND_BUF_LEN_FIELD + 12, 0)

		SECFP_SET_DESC_PTR(desc->ptr[4],
				(skb->len - pSA->ulSecHdrLen - 12),
				(addr + pSA->ulSecHdrLen),
				0);

		SECFP_SET_DESC_PTR(desc->ptr[5],
				(skb->len - pSA->ulSecHdrLen - 12),
				(addr + pSA->ulSecHdrLen),
				0);

		/* Not sure about this
			talitosDescriptor->bRecvICV = T_TRUE;


			memcpy(desc->aRecvICV, (skb->tail - 12), 12);
		*/
		/* Having extra length in the buffer to hold the
			calculated ICV value */
		/* Looks like in this case,
			ICV is calculated and supplied always */
		SECFP_SET_DESC_PTR(desc->ptr[6],
				12,
				addr + skb->len,
				0);
	}
		break;
	default:
		ASFIPSEC_DEBUG("SECFP: Not supported");
		SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t)addr, (skb->len + 12 +
			SECFP_APPEND_BUF_LEN_FIELD +
			SECFP_NOUNCE_IV_LEN));
		break;
	}

	/* Correcting this: Only for the first time ,
		ICV check, this option needs to be recorded */
	if (ulIndex == 0)
		skb->cb[SECFP_3X_SA_OPTION_INDEX] = pSA->option[ulIndex];

	desc->hdr |= DESC_HDR_DONE_NOTIFY;

	return;
}

#ifdef SECFP_SG_SUPPORT
static inline void SECFP_SG_MAP(secfp_sgEntry_t *pSgEntry,
	unsigned int len, u8 flags, u8 eptr, u32 ptr)
{
	pSgEntry->len = cpu_to_be16(len);
	pSgEntry->flags = flags;
	pSgEntry->eptr = eptr;
	pSgEntry->ptr = cpu_to_be32(ptr);
}

dma_addr_t secfp_prepareGatherList(
		struct sk_buff *skb, struct sk_buff **pTailSkb,
		unsigned int ulOffsetHeadLen, unsigned int ulExtraTailLen)
{
	/* Use the skb->frag_list->cb[8] onwards for a scatter gather list [3]
		followed by a link pointer, if more fragments are present */
	/* where to start for the link table ptrs */
	struct sk_buff *pSgSkb = skb_shinfo(skb)->frag_list;
	struct sk_buff *pTempSkb;
	secfp_sgEntry_t *pSgEntry = (secfp_sgEntry_t *)
			&(pSgSkb->cb[SECFP_SKB_DATA_DMA_INDEX + 4]);
	secfp_sgEntry_t *pNextSgEntry, *pFirstSgEntry;
	unsigned int ulNumIteration;


	pFirstSgEntry = pSgEntry;
	*(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) =
			dma_map_single(pdev, skb->data + ulOffsetHeadLen,
				(skb->end - skb->data), DMA_TO_DEVICE);

	SECFP_SG_MAP(pSgEntry, (skb->len - ulOffsetHeadLen), 0, 0,
		(*(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX])));
	secfp_dump_sg(pSgEntry);

	ASFIPSEC_PRINT("pFirstSgEntry =0x%x", (unsigned int) pFirstSgEntry);
	ASFIPSEC_PRINT("pSGEntry->len = %d", pSgEntry->len);

	for (ulNumIteration = 1, pSgEntry++,
		pTempSkb = skb_shinfo(skb)->frag_list;
		pTempSkb != NULL;
		pTempSkb = pTempSkb->next, ulNumIteration++) {

		*(unsigned int *) &(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX]) =
				dma_map_single(pdev, pTempSkb->data,
					pTempSkb->end - pTempSkb->data,
					DMA_TO_DEVICE);

		if (pTempSkb->next == NULL) {
			SECFP_SG_MAP(pSgEntry, (pTempSkb->len + ulExtraTailLen),
				DESC_PTR_LNKTBL_RETURN, 0,
				*(unsigned int *)
				&(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX]));
			secfp_dump_sg(pSgEntry);
			*pTailSkb = pTempSkb;
		} else {
			if (ulNumIteration == 3) {
				/* Need to arrange the next link table */
				/* Need to allocate a new link table
					from next buffer to pSgskb */
				ASFIPSEC_PRINT("Set up Link to NextLinkTable");
				pSgSkb = pSgSkb->next;
				pNextSgEntry = (secfp_sgEntry_t *)
					&(pSgSkb->cb[SECFP_SKB_DATA_DMA_INDEX + 4]);
				*(unsigned int *) &(pSgSkb->cb
					[SECFP_SKB_SG_DMA_INDEX]) =
					dma_map_single(pdev, pNextSgEntry,
							32, DMA_TO_DEVICE);
				SECFP_SG_MAP(pSgEntry, 0, DESC_PTR_LNKTBL_NEXT,
					0, *(unsigned int *)
					&(pSgSkb->cb[SECFP_SKB_SG_DMA_INDEX]));
				secfp_dump_sg(pSgEntry);
				ulNumIteration = 0;
				pSgEntry = pNextSgEntry;
			} else {
				ASFIPSEC_PRINT("Setting up next entry"
					" within same link table");
				SECFP_SG_MAP(pSgEntry, pTempSkb->len,
					0, 0, *(unsigned int *)
					&(pTempSkb->cb[SECFP_SKB_DATA_DMA_INDEX]));
				secfp_dump_sg(pSgEntry);
				pSgEntry++;
			}
		}
	}
	secfp_dump_sg_in_skb(skb_shinfo(skb)->frag_list);
	*(unsigned int *) &(skb->cb[SECFP_SKB_SG_DMA_INDEX]) =
			dma_map_single(pdev, pFirstSgEntry, 32, DMA_TO_DEVICE);
	ASFIPSEC_PRINT("pFirstSgEntry = 0x%x, *(unsigned int *)"
			" &(skb->cb[SECFP_SKB_SG_DMA_INDEX]) = 0x%x",
		(unsigned int) pFirstSgEntry,
		*(unsigned int *) &(skb->cb[SECFP_SKB_SG_DMA_INDEX]));
	return *(unsigned int *) (&skb->cb[SECFP_SKB_SG_DMA_INDEX]);
}

dma_addr_t secfp_prepareScatterList(struct sk_buff *skb,
		unsigned int ulOffsetFromHead, unsigned int ulExtraTailLen)
{
	/* In all cases, we atmost prepare a scatter list for 2 fragments only,
	the second fragment is in skb->prev */
	/* where to start for the link table ptrs */
	struct sk_buff *pSgSkb = skb->prev;
	secfp_sgEntry_t *pSgEntry = (secfp_sgEntry_t *)
			&(pSgSkb->cb[SECFP_SKB_DATA_DMA_INDEX + 4]);
	secfp_sgEntry_t *pFirstSgEntry = pSgEntry;

	*(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) =
		dma_map_single(pdev, (skb->data + ulOffsetFromHead),
			(skb->end - skb->data), DMA_TO_DEVICE);
	SECFP_SG_MAP(pSgEntry, (skb->len - ulOffsetFromHead
		- (skb->prev->len + ulExtraTailLen)), 0, 0,
		(*(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX])));
	secfp_dump_sg(pSgEntry);

	pSgEntry++;
	*(unsigned int *) &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX]) =
		dma_map_single(pdev, skb->prev->data,
			(skb->prev->end - skb->prev->data), DMA_TO_DEVICE);
	SECFP_SG_MAP(pSgEntry, (skb->prev->len + ulExtraTailLen),
		DESC_PTR_LNKTBL_RETURN, 0,
		(*(unsigned int *) &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX])));
	secfp_dump_sg(pSgEntry);

	secfp_dump_sg_in_skb(skb->prev);

	return *(unsigned int *) &(skb->cb[SECFP_SKB_SG_DMA_INDEX]) =
			dma_map_single(pdev, pFirstSgEntry, 32, DMA_TO_DEVICE);
}

void secfp_prepareOutDescriptorWithFrags(struct sk_buff *skb, void *pData,
			void *descriptor, unsigned int ulOptionIndex)
{
	dma_addr_t ptr = 0, ptr2 = 0;
	unsigned int *src, *tgt;
	unsigned char *pNounceIVCounter;
	outSA_t *pSA = (outSA_t *) (pData);
	int iDword, iDword1;
	unsigned int ulAppendLen;
	struct sk_buff *pTailSkb;
	struct talitos_desc *desc = (struct talitos_desc *)descriptor;

	desc->hdr_lo = 0;
	if (!ulOptionIndex) {	/* 1st iteration */
		ASFIPSEC_DEBUG("Doing DMA mapping");
		if (!skb_shinfo(skb)->frag_list) {
			ptr = *(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
				= dma_map_single(pdev, skb->data, skb->tail -
						skb->head, DMA_TO_DEVICE);
		}
	} else {
		/* Take it from the skb->cb */
		if (skb_shinfo(skb)->frag_list) {
			ptr = *(unsigned int *)
				&(skb->cb[SECFP_SKB_SG_DMA_INDEX]);
		} else {
			ptr = *(unsigned int *)
				&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
			/*if (skb->prev) {
				ptr2 = *(unsigned int *)
					&(skb->cb[SECFP_SKB_SG_DMA_INDEX]);
			} todo Commented for klocwork warning*/
		}
	}
	ASFIPSEC_PRINT("ptr = 0x%x", ptr);
	switch (pSA->option[ulOptionIndex]) {
	case SECFP_AUTH:
	{
		desc->hdr = pSA->hdr_Auth_template_0;

		SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);
		SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0);
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr,
				0);

		if (pSA->SAParams.bUseExtendedSequenceNumber) {
			ulAppendLen = SECFP_APPEND_BUF_LEN_FIELD;
		} else {
			ulAppendLen = 0;
		}

		if (!((pSA->hdr_Auth_template_0 & DESC_HDR_MODE0_AES_XCBC_MAC)
			== DESC_HDR_MODE0_AES_XCBC_MAC)) {
			iDword = 5;
			iDword1 = 6;
		} else {
			iDword = 6;
			iDword1 = 5;
		}

		if (skb_shinfo(skb)->frag_list) {
			ptr = secfp_prepareGatherList(skb, &pTailSkb, 0, ulAppendLen);
			SECFP_SET_DESC_PTR(desc->ptr[3],
				skb->data_len + ulAppendLen, ptr,
				DESC_PTR_LNKTBL_JUMP);
			SECFP_SET_DESC_PTR(desc->ptr[iDword],
				pSA->SAParams.uICVSize,
				*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX]) +
					pTailSkb->len - pSA->SAParams.uICVSize,
				0);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[3],
					skb->len + ulAppendLen, ptr, 0);
			if (skb->prev) {
				SECFP_SET_DESC_PTR(desc->ptr[iDword],
					pSA->SAParams.uICVSize,
					*(unsigned int *) &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX]) +
						skb->prev->len - pSA->SAParams.uICVSize,
					0);
			} else {
				ASFIPSEC_DEBUG("Not prev and Not frag lst"
					": Error : Outdesc");
			}
		}

		SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0)
		SECFP_SET_DESC_PTR(desc->ptr[iDword1],
				0, 0, 0);
		print_desc(desc);
		break;
	}
	case SECFP_CIPHER:
	{
		desc->hdr = pSA->desc_hdr_template;

		SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0);

		if (skb_shinfo(skb)->frag_list) {
			ptr = secfp_prepareGatherList(skb, &pTailSkb,
				pSA->ulSecHdrLen, 0);

			SECFP_SET_DESC_PTR(desc->ptr[1],
				pSA->SAParams.ulIvSize,
				*(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]) +
				+ SECFP_ESP_HDR_LEN,
				0);

			SECFP_SET_DESC_PTR(desc->ptr[3],
					skb->data_len - pSA->ulSecHdrLen,
					ptr, DESC_PTR_LNKTBL_JUMP);

			SECFP_SET_DESC_PTR(desc->ptr[4],
					skb->data_len - pSA->ulSecHdrLen,
					ptr, DESC_PTR_LNKTBL_JUMP);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[1],
					pSA->SAParams.ulIvSize,
					ptr + SECFP_ESP_HDR_LEN,
					0);

			SECFP_SET_DESC_PTR(desc->ptr[3],
					skb->len - pSA->ulSecHdrLen,
					ptr + pSA->ulSecHdrLen,
					0);

			if (skb->prev) {
				pTailSkb = skb->prev;

				ptr2 = secfp_prepareScatterList(skb,
					pSA->ulSecHdrLen, 0);

				SECFP_SET_DESC_PTR(desc->ptr[4],
					skb->data_len - pSA->ulSecHdrLen,
					ptr2, DESC_PTR_LNKTBL_JUMP);
			} else {
				ASFIPSEC_DEBUG("Not prev and Not frag"
					"lst: Error : Outdesc");
			}
		}


		if (((pSA->desc_hdr_template &
			(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
			== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))) {
		/* Set up the AES Context field -
			Need to validate this with soft crypto */
			src = (unsigned int *) pSA->SAParams.ucNounceIVCounter;

			pNounceIVCounter = (unsigned char *)
				(*(unsigned int *) &(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
				+ pTailSkb->len + (SECFP_APPEND_BUF_LEN_FIELD) + 12);
			tgt = (unsigned int *) pNounceIVCounter;

			/* Copying 2 integers of IV, Assumes that the first"
				4 bytes of Nounce is valid and the 16th byte
				is set to 128; not sure why though? */
			*(tgt) = *src;
			src = (unsigned int *) (skb->data + SECFP_ESP_HDR_LEN);
			*(tgt+1) = src[0];
			*(tgt+2) = src[1];

			/*Need to verify why we are
				setting COUNTER_BLK_LEN + 8 */
			SECFP_SET_DESC_PTR(desc->ptr[1],
				SECFP_COUNTER_BLK_LEN,
				(dma_addr_t)pNounceIVCounter,
				0);
		}

		/* Copy the prepared encryption key */
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr,
				0);

		/* removed 12 for extent */
		SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
		print_desc(desc);

		break;
	}
	case SECFP_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template;
		ASFIPSEC_DEBUG("Desc->hdr = 0x%x", desc->hdr);

		/* Set up Auth Key */
		/* Copy the prepared authentication key */
		SECFP_SET_DESC_PTR(desc->ptr[0],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr,
				0);

		ASFIPSEC_DEBUG("ulSecHdrLen = %d Auth Onlydata"\
			": data ptr=0x%x skb->data_len = %d",
			pSA->ulSecHdrLen, ptr, skb->data_len);
		if (skb_shinfo(skb)->frag_list) {
			ASFIPSEC_DEBUG("Fragment list present for SG ");
			ptr = secfp_prepareGatherList(skb, &pTailSkb,
				pSA->ulSecHdrLen, 12);
			SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->data_len - pSA->ulSecHdrLen,
				ptr, DESC_PTR_LNKTBL_JUMP);

		SECFP_SET_DESC_PTR(desc->ptr[5],
				skb->data_len - pSA->ulSecHdrLen,
				ptr, 12 | DESC_PTR_LNKTBL_JUMP);

		} else {
			ASFIPSEC_DEBUG("Single buffer for gather;"
				"scatter for output");
			SECFP_SET_DESC_PTR(desc->ptr[4],
					skb->len - pSA->ulSecHdrLen,
					ptr + pSA->ulSecHdrLen,
					0);

			if (skb->prev) {
				pTailSkb = skb->prev;
				ptr2 = secfp_prepareScatterList(skb,
					pSA->ulSecHdrLen, 0);
				SECFP_SET_DESC_PTR(desc->ptr[5],
					skb->data_len - pSA->ulSecHdrLen,
					ptr2, 12 | DESC_PTR_LNKTBL_JUMP);
			} else {
				ASFIPSEC_WARN("Not prev and Not frag lst"
					": Error : Outdesc");
			}
		}

		SECFP_SET_DESC_PTR(desc->ptr[1],
			pSA->ulSecHdrLen,
			*(unsigned int *) &skb->cb[SECFP_SKB_DATA_DMA_INDEX],
			0);
		ASFIPSEC_DBGL2("IVSize = %d, IVdataptr=0x%x, ",
			pSA->SAParams.ulIvSize,
			ptr+SECFP_ESP_HDR_LEN);
		SECFP_SET_DESC_PTR(desc->ptr[2],
			pSA->SAParams.ulIvSize,
			*(unsigned int *) &skb->cb[SECFP_SKB_DATA_DMA_INDEX]
				+ SECFP_ESP_HDR_LEN,
			0);

		/* Copy the prepared encryption key */
		SECFP_SET_DESC_PTR(desc->ptr[3],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr,
				0);

		ASFIPSEC_DEBUG("Input data setup at 0x%x:"\
			"len = %d", ptr + pSA->ulSecHdrLen,
			skb->len - pSA->ulSecHdrLen);

		ASFIPSEC_DEBUG("Output data setup at 0x%x:"\
			"len = %d", ptr + pSA->ulSecHdrLen,
			skb->len - pSA->ulSecHdrLen);

		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
		print_desc(desc);
		break;
	}
	case SECFP_AESCTR_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template | pSA->hdr_Auth_template_1;
		/* Set up Auth Key */
		/* Copy the prepared authentication key */
		SECFP_SET_DESC_PTR(desc->ptr[0],
				pSA->SAParams.AuthKeyLen,
				pSA->AuthKeyDmaAddr,
				0);

		if (skb_shinfo(skb)->frag_list) {
			ptr = secfp_prepareGatherList(skb,
				&pTailSkb, pSA->ulSecHdrLen, 0);

			SECFP_SET_DESC_PTR(desc->ptr[4],
					skb->data_len - pSA->ulSecHdrLen,
					ptr, DESC_PTR_LNKTBL_JUMP);

			SECFP_SET_DESC_PTR(desc->ptr[5],
					skb->data_len - pSA->ulSecHdrLen,
					ptr, DESC_PTR_LNKTBL_JUMP);

			/* Where to put the ICV */
			SECFP_SET_DESC_PTR(desc->ptr[6],
				12,
				(*(unsigned int *) &(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
					+ pTailSkb->len - pSA->SAParams.uICVSize),
				0);

		} else {
			SECFP_SET_DESC_PTR(desc->ptr[4],
					skb->len - pSA->ulSecHdrLen,
					ptr + pSA->ulSecHdrLen ,
					0);

			if (skb->prev) {
				pTailSkb = skb->prev;
				ptr2 = secfp_prepareScatterList(skb,
					pSA->ulSecHdrLen, 0);
				SECFP_SET_DESC_PTR(desc->ptr[5],
					skb->data_len - pSA->ulSecHdrLen,
					ptr2, DESC_PTR_LNKTBL_JUMP);

				/* Where to put the ICV */
				SECFP_SET_DESC_PTR(desc->ptr[6],
					12,
					(*(unsigned int *) &(skb->prev->cb[SECFP_SKB_DATA_DMA_INDEX])
						+ skb->prev->len - pSA->SAParams.uICVSize),
					0);
			} else {
				ASFIPSEC_WARN("Not frag list and skb->prev");
			}
		}


		SECFP_SET_DESC_PTR(desc->ptr[1],
			pSA->ulSecHdrLen,
			*(unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]),
			0);

		/* Copy the prepared encryption key */
		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr,
				0);

		src = (unsigned int *) pSA->SAParams.ucNounceIVCounter;

		pNounceIVCounter = (unsigned char *)
			(*(unsigned int *) &(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
				+ pTailSkb->len + (SECFP_APPEND_BUF_LEN_FIELD) + 12);
		tgt = (unsigned int *) pNounceIVCounter;

		/* Copying 2 integers of IV, Assumes that the first 4 bytes
			of Nounce is valid and the 16th byte
			is set to 128; not sure why though? */
		*(tgt) = *src;
		src = (unsigned int *) (skb->data + SECFP_ESP_HDR_LEN);
		*(tgt+1) = src[0];
		*(tgt+2) = src[1];


		/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
		SECFP_SET_DESC_PTR(desc->ptr[3],
			SECFP_COUNTER_BLK_LEN,
			(dma_addr_t)pNounceIVCounter,
			0);

		break;
	}
	default:
		ASFIPSEC_WARN("Unknown Option ");
		break;

	}
	desc->hdr |= DESC_HDR_DONE_NOTIFY;
}

void secfp_prepareInDescriptorWithFrags(struct sk_buff *skb,
				void *pData, void *descriptor,
				unsigned int ulIndex)
{
	unsigned int *tgt, *src;
	dma_addr_t addr;
	inSA_t *pSA = (inSA_t *)pData;
	unsigned char *pNounceIVCounter;
	unsigned int *ptr1;
	int len;
	struct sk_buff *pTailSkb;
	unsigned int ulOffsetIcvLen;
	struct talitos_desc *desc = (struct talitos_desc *)descriptor;

	if (!desc) {
		ASFIPSEC_WARN("NULL Descriptor");
		return;
	}

	if (!ulIndex) {	/* first iteration */
		if (!skb_shinfo(skb)->frag_list) {
			addr = *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
				= dma_map_single(pdev, skb->data,
					skb->tail - skb->head,
					DMA_TO_DEVICE);
		} else {
			addr = dma_map_single(pdev, skb->data,
					skb->tail - skb->head,
					DMA_TO_DEVICE);
			ptr1 = (unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
			*ptr1 = addr;
		}
		ASFIPSEC_DEBUG("ulIndex = %d: addr = 0x%x",
			ulIndex, addr);
	} else {
		/* Take information from the cb field */
		addr = *(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		ASFIPSEC_DEBUG("ulIndex= %d: addr = 0x%x",
			ulIndex, addr);
	}
	desc->hdr_lo = 0;
	switch (pSA->option[ulIndex]) {
	case SECFP_AUTH:
	{
		desc->hdr = pSA->hdr_Auth_template_0;

		ASFIPSEC_DEBUG("skb->len = %d, addr = "\
			"0x%x, pSA->SAParams.uICVSize =%d",
			skb->len, addr, pSA->SAParams.uICVSize);
		SECFP_SET_DESC_PTR(desc->ptr[0], 0, 0, 0)
		SECFP_SET_DESC_PTR(desc->ptr[1], 0, 0, 0)
		SECFP_SET_DESC_PTR(desc->ptr[2],
			pSA->SAParams.AuthKeyLen,
			pSA->AuthKeyDmaAddr, 0)

		if (pSA->SAParams.bUseExtendedSequenceNumber) {
			len = SECFP_APPEND_BUF_LEN_FIELD;
		} else {
			len = 0;
		}

		addr = secfp_prepareGatherList(skb, &pTailSkb, 0, (12+len));
		/* Setting up data */
		SECFP_SET_DESC_PTR(desc->ptr[3],
			skb->data_len - 12, addr, DESC_PTR_LNKTBL_JUMP);


		/* Setting up ICV Check : Only when AES_XCBC_MAC is not programmed */
		if (pSA->SAParams.ucAuthAlgo != SECFP_HMAC_AES_XCBC_MAC) {
			SECFP_SET_DESC_PTR(desc->ptr[4],
				pSA->SAParams.uICVSize,
				(*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
					+ len - pSA->SAParams.uICVSize), 0)

			SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[4], 0, 0, 0)

			SECFP_SET_DESC_PTR(desc->ptr[6],
				pSA->SAParams.uICVSize,
				(*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
				+ len - pSA->SAParams.uICVSize), 0)

#ifdef ASF_IPSEC_DEBUG
			{
			int ii;
			for (ii = 0; ii < 3; ii++)
				ASFIPSEC_DEBUG("Offset ii=%d 0x%8x", ii,
				*(unsigned int *)&(skb->data[skb->len + ii*4]));
			}
#endif
		}
		SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0);
		print_desc(desc);
		break;
	}
	case SECFP_CIPHER:
	{
		desc->hdr = pSA->desc_hdr_template;

		addr = secfp_prepareGatherList(skb, &pTailSkb,
			pSA->ulSecHdrLen, 0);

		if ((pSA->desc_hdr_template &
			(DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU))
			== (DESC_HDR_MODE0_AES_CTR | DESC_HDR_SEL0_AESU)) {
			/* Set up the AES Context field
				- Need to validate this with soft crypto */

			src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
			/* To be verified
			tgt = *(unsigned int *)desc->ucNounceIVCounter;
			*/
			pNounceIVCounter = (unsigned char *)
				(*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
					+ pTailSkb->len
					+ (SECFP_APPEND_BUF_LEN_FIELD * 2)
					+ 12);

			tgt = (unsigned int *)pNounceIVCounter;

			/* Copying 2 integers of IV, Assumes that the first 4
				bytes of Nounce is valid and the 16th byte
				is set to 128; not sure why though? */
			*(tgt) = *src;
			src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
			*(tgt+1) = src[0];
			*(tgt+2) = src[1];

			/* Need to verify
				why we are setting COUNTER_BLK_LEN + 8 */
			SECFP_SET_DESC_PTR(desc->ptr[1],
				SECFP_COUNTER_BLK_LEN,
			(dma_addr_t)pNounceIVCounter,
			0);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[1], pSA->SAParams.ulIvSize,
				(*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
				+ SECFP_ESP_HDR_LEN), 0)
		}

		SECFP_SET_DESC_PTR(desc->ptr[2],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr, 0)

		if ((ulIndex) && (skb->cb[SECFP_REF_INDEX] == 3)) {
			/* We have queued the packet and
				c/b has not yet triggered */
			/* if 2nd iteration is encryption, then we need to
				reduce the length by ICV Length */
			ulOffsetIcvLen = 12;
		} else {
			/* In the 2 descriptor case, callback has triggered,
				so we need not to reduce by the ICV length
			*/
			ulOffsetIcvLen = 0;
		}

		SECFP_SET_DESC_PTR(desc->ptr[3],
				skb->data_len - pSA->ulSecHdrLen-ulOffsetIcvLen,
				addr,
				DESC_PTR_LNKTBL_JUMP)

		if ((unsigned int)skb->prev == SECFP_IN_GATHER_NO_SCATTER) {
			SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->data_len - pSA->ulSecHdrLen-ulOffsetIcvLen,
				addr + pSA->ulSecHdrLen,
				0)
		} else { /* skb->prev = SECFP_IN_GATHER_SCATTER */
			SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->data_len - pSA->ulSecHdrLen-ulOffsetIcvLen,
				addr,
				DESC_PTR_LNKTBL_JUMP)
		}
		/* Set the descriptors 5 and 6 and 6 to 0 */
		SECFP_SET_DESC_PTR(desc->ptr[5], 0, 0, 0)
		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0)
		print_desc(desc);
		break;
	}
	case SECFP_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template;

		addr = secfp_prepareGatherList(skb,
			&pTailSkb, pSA->ulSecHdrLen, 12);

		SECFP_SET_DESC_PTR(desc->ptr[0],
			pSA->SAParams.AuthKeyLen,
			pSA->AuthKeyDmaAddr, 0)
		SECFP_SET_DESC_PTR(desc->ptr[1], pSA->ulSecHdrLen,
			*(unsigned int *)(&skb->cb[SECFP_SKB_DATA_DMA_INDEX]),
			0)
		SECFP_SET_DESC_PTR(desc->ptr[2], pSA->SAParams.ulIvSize,
			*(unsigned int *)(&skb->cb[SECFP_SKB_DATA_DMA_INDEX])
				+ SECFP_ESP_HDR_LEN,
			0)
		SECFP_SET_DESC_PTR(desc->ptr[3],
				pSA->SAParams.EncKeyLen,
				pSA->EncKeyDmaAddr, 0)

		SECFP_SET_DESC_PTR(desc->ptr[4],
				skb->data_len - pSA->ulSecHdrLen - 12,
				addr ,
				(12 | DESC_PTR_LNKTBL_JUMP))

		if (skb->prev == SECFP_IN_GATHER_SCATTER) {
			SECFP_SET_DESC_PTR(desc->ptr[5],
					skb->data_len - pSA->ulSecHdrLen - 12,
					addr ,
					DESC_PTR_LNKTBL_JUMP);
		} else {
			SECFP_SET_DESC_PTR(desc->ptr[5],
				skb->data_len - pSA->ulSecHdrLen - 12,
				*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
					+ pSA->ulSecHdrLen,
				0);
		}

		SECFP_SET_DESC_PTR(desc->ptr[6], 0, 0, 0);
	}
	break;
	case SECFP_AESCTR_BOTH:
	{
		desc->hdr = pSA->desc_hdr_template |
				pSA->hdr_Auth_template_1 ;

		addr = secfp_prepareGatherList(skb, &pTailSkb,
			pSA->ulSecHdrLen, 12);

		SECFP_SET_DESC_PTR(desc->ptr[0],
			pSA->SAParams.AuthKeyLen,
			pSA->AuthKeyDmaAddr,
			0);

		SECFP_SET_DESC_PTR(desc->ptr[1],
			pSA->ulSecHdrLen,
			*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX]),
			0);

		SECFP_SET_DESC_PTR(desc->ptr[2],
			pSA->SAParams.EncKeyLen,
			pSA->EncKeyDmaAddr,
			0);

		/* Set up the AES Context field
			- Need to validate this with soft crypto */

		src = (unsigned int *)&(pSA->SAParams.ucNounceIVCounter);
		/* To be verified
		tgt = *(unsigned int *)desc->ucNounceIVCounter;
		*/
		pNounceIVCounter = (unsigned char *)
			(*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
				+ pTailSkb->len
				+ (SECFP_APPEND_BUF_LEN_FIELD * 2) + 12);

		tgt = (unsigned int *)pNounceIVCounter;

		/* Copying 2 integers of IV, Assumes that the first 4 bytes
			of Nounce is valid and the 16th byte
			is set to 128; not sure why though? */
		*(tgt) = *src;
		src = (unsigned int *)(skb->data + SECFP_ESP_HDR_LEN);
		*(tgt+1) = src[0];
		*(tgt+2) = src[1];

		/* Need to verify why we are setting COUNTER_BLK_LEN + 8 */
		SECFP_SET_DESC_PTR(desc->ptr[3],
				SECFP_COUNTER_BLK_LEN,
			(dma_addr_t)pNounceIVCounter,
			0);

		SECFP_SET_DESC_PTR(desc->ptr[4],
				(skb->data_len - pSA->ulSecHdrLen - 12),
				(addr),
				DESC_PTR_LNKTBL_JUMP);

		if (skb->prev == SECFP_IN_GATHER_SCATTER) {
			SECFP_SET_DESC_PTR(desc->ptr[5],
					(skb->data_len - pSA->ulSecHdrLen - 12),
					(addr),
					DESC_PTR_LNKTBL_JUMP);

			/* Not sure about this
				talitosDescriptor->bRecvICV = T_TRUE;

				memcpy(desc->aRecvICV, (skb->tail - 12), 12);
			*/
			/*Having extra length in the buffer to
				hold the calculated ICV value */

			/* Looks like in this case,
				ICV is calculated and supplied always */

			SECFP_SET_DESC_PTR(desc->ptr[6],
				12,
				*(unsigned int *)&(pTailSkb->cb[SECFP_SKB_DATA_DMA_INDEX])
					+ pTailSkb->len,
				0);
		} else {
			/* In Gather, Out No scatter */
			SECFP_SET_DESC_PTR(desc->ptr[5],
				(skb->data_len - pSA->ulSecHdrLen - 12),
				(*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
					+ pSA->ulSecHdrLen),
				0)

			/* Not sure about this
			talitosDescriptor->bRecvICV = T_TRUE;

			memcpy(desc->aRecvICV, (skb->tail - 12), 12);
		*/
			/*Having extra length in the buffer to
				hold the calculated ICV value */

			/* Looks like in this case, ICV is calculated
				and supplied always */

			SECFP_SET_DESC_PTR(desc->ptr[6],
				12,
				*(unsigned int *)&(skb->cb[SECFP_SKB_DATA_DMA_INDEX])
					+ skb->data_len,
				0);
		}

	}
	break;
	default:
		ASFIPSEC_WARN("SECFP: Not supported");
		SECFP_UNMAP_SINGLE_DESC(pdev, (dma_addr_t) addr,
				(skb->len + 12 +
				SECFP_APPEND_BUF_LEN_FIELD +
				SECFP_NOUNCE_IV_LEN));
		break;
	}

	/* Correcting this: Only for the first time ,
		ICV check, this option needs to be recorded */
	if (ulIndex == 0)
		skb->cb[SECFP_3X_SA_OPTION_INDEX] = pSA->option[ulIndex];

	desc->hdr |= DESC_HDR_DONE_NOTIFY;

	return;
}
#endif /*SECFP_SG_MAP*/
#endif /*defined(CONFIG_ASF_SEC3x)*/
