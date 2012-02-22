/**************************************************************************
 * Copyright 2011-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecfp_sec4x.c
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
#ifdef CONFIG_ASF_SEC4x

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

#define xstr(s) str(s)
#define str(s) #s

/* length of descriptors text */
#define DESC_AEAD_SHARED_TEXT_LEN 4
#define DESC_AEAD_ENCRYPT_TEXT_LEN 21
#define DESC_AEAD_DECRYPT_TEXT_LEN 24
#define DESC_AEAD_GIVENCRYPT_TEXT_LEN 27


static void secfp_splitKeyDone(struct device *dev, void *desc, u32 error,
				void *context)
{
#ifdef ASF_IPSEC_DEBUG
	if (error) {
		char tmp[SECFP_ERROR_STR_MAX];
		ASFIPSEC_DEBUG("%08x: %s\n", error,
			caam_jr_strstatus(tmp, error));
	}
#endif
	kfree(desc);
}
/*
get a split ipad/opad key

Split key generation-----------------------------------------------

[00] 0xb0810008 jobdesc: stidx=1 share=never len=8
[01] 0x04000014 key: class2->keyreg len=20
			@0xffe01000
[03] 0x84410014 operation: cls2-op sha1 hmac init dec
[04] 0x24940000 fifold: class2 msgdata-last2 len=0 imm
[05] 0xa4000001 jump: class2 local all ->1 [06]
[06] 0x64260028 fifostr: class2 mdsplit-jdk len=40
			@0xffe04000
*/
static unsigned int secfp_genCaamSplitKey(struct caam_ctx *ctx,
					const u8 *key_in, u32 authkeylen)
{
	u32 *desc;
	dma_addr_t dma_addr_in, dma_addr_out;
	int ret = 0;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

	desc = kzalloc(CAAM_CMD_SZ * 6 + CAAM_PTR_SZ * 2, GFP_DMA | flags);

	init_job_desc(desc, 0);

	dma_addr_in = dma_map_single(ctx->jrdev, (void *)key_in, authkeylen,
				DMA_TO_DEVICE);
	if (dma_mapping_error(ctx->jrdev, dma_addr_in)) {
		ASFIPSEC_DEBUG("secfp_genCaamSplitKey: Unable to map key"\
				"input memory\n");
		kfree(desc);
		return -ENOMEM;
	}

	append_key(desc, dma_addr_in, authkeylen, CLASS_2 |
		KEY_DEST_CLASS_REG);

	/* Sets MDHA up into an HMAC-INIT */
	append_operation(desc, ctx->alg_op | OP_ALG_DECRYPT |
			OP_ALG_AS_INIT);

	/*
	* do a FIFO_LOAD of zero, this will trigger the internal key expansion
	into both pads inside MDHA
	*/
	append_fifo_load_as_imm(desc, NULL, 0, LDST_CLASS_2_CCB |
				FIFOLD_TYPE_MSG | FIFOLD_TYPE_LAST2);

	/*
	* FIFO_STORE with the explicit split-key content store
	* (0x26 output type)
	*/
	dma_addr_out = dma_map_single(ctx->jrdev, ctx->key,
				ctx->split_key_pad_len, DMA_FROM_DEVICE);
	if (dma_mapping_error(ctx->jrdev, dma_addr_out)) {
		ASFIPSEC_DEBUG("secfp_genCaamSplitKey: Unable to map key"\
				"input memory\n");
		kfree(desc);
		return -ENOMEM;
	}

	append_fifo_store(desc, dma_addr_out, ctx->split_key_len,
			LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);

#ifdef ASFIPSEC_DEBUG_FRAME
	printk(KERN_ERR "\nDMA_ADDR_IN: %x authkeylen %d flags %x",
			dma_addr_in, authkeylen, CLASS_2 | KEY_DEST_CLASS_REG);
	printk(KERN_ERR "\nCTX ALG OP %x",
				ctx->alg_op | OP_ALG_DECRYPT | OP_ALG_AS_INIT);
	printk(KERN_ERR "\nDMA_ADDR_OUT: %x flags %x", dma_addr_out,
				LDST_CLASS_2_CCB | FIFOST_TYPE_SPLIT_KEK);
	printk(KERN_ERR "\nsplit_key_len %d split_key_pad_len %d",
				ctx->split_key_len, ctx->split_key_pad_len);
	print_hex_dump(KERN_ERR, "ctx.key@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, key_in, authkeylen, 1);
	print_hex_dump(KERN_ERR, "jobdesc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif

	ret = secfp_caam_submit(ctx->jrdev, desc, secfp_splitKeyDone, NULL);
	if (ret) {
		ASFIPSEC_DEBUG("secfp_caam_submit failed ");
		kfree(desc);
	}

	return ret;
}

static inline u32 alg_to_caamdesc(u8 cipheralg, u8 authalg)
{
	u32 descwd = 0;

	/*
	* Note that these cipher selectors match the PFKEY selectors
	* almost 1 for 1, so this is really little more than an error
	* check
	*/
	switch (cipheralg) {
	case SECFP_DES:
		descwd |= OP_PCL_IPSEC_DES;
		break;

	case SECFP_3DES:
		descwd |= OP_PCL_IPSEC_3DES;
		break;

	case SECFP_AES:
		descwd |= OP_PCL_IPSEC_AES_CBC;
		break;

	case SECFP_AESCTR:
		descwd |= OP_PCL_IPSEC_AES_CTR;
		break;

	case SECFP_AES_CCM_ICV8:
		descwd |= OP_PCL_IPSEC_AES_CCM8;
		break;

	case SECFP_AES_CCM_ICV12:
		descwd |= OP_PCL_IPSEC_AES_CCM12;
		break;

	case SECFP_AES_CCM_ICV16:
		descwd |= OP_PCL_IPSEC_AES_CCM16;
		break;

	case SECFP_AES_GCM_ICV8:
		descwd |= OP_PCL_IPSEC_AES_GCM8;
		break;

	case SECFP_AES_GCM_ICV12:
		descwd |= OP_PCL_IPSEC_AES_GCM12;
		break;

	case SECFP_AES_GCM_ICV16:
		descwd |= OP_PCL_IPSEC_AES_GCM16;
		break;
	}

	/*
	* Authentication selectors. These do not match the PFKEY
	* selectors
	*/
	switch (authalg) {
	case SECFP_HMAC_MD5:
		descwd |= OP_PCL_IPSEC_HMAC_MD5_96;
		break;

	case SECFP_HMAC_SHA1:
		descwd |= OP_PCL_IPSEC_HMAC_SHA1_96;
		break;

	case SECFP_HMAC_AES_XCBC_MAC:
		descwd |= OP_PCL_IPSEC_AES_XCBC_MAC_96;
		break;

	case SECFP_HMAC_SHA1_160:
		descwd |= OP_PCL_IPSEC_HMAC_SHA1_160;
		break;

	case SECFP_HMAC_SHA256:
		descwd |= OP_PCL_IPSEC_HMAC_SHA2_256_128;
		break;

	case SECFP_HMAC_SHA384:
		descwd |= OP_PCL_IPSEC_HMAC_SHA2_384_192;
		break;

	case SECFP_HMAC_SHA512:
		descwd |= OP_PCL_IPSEC_HMAC_SHA2_512_256;
		break;
	}
	return descwd;
}
int secfp_prepareDecapShareDesc(struct caam_ctx *ctx, u32 *sh_desc,
		inSA_t *pSA, bool keys_fit_inline)
{
	u32 *jump_cmd;
	struct ipsec_decap_pdb *pdb;

	init_sh_desc(sh_desc, HDR_SAVECTX | HDR_SHARE_SERIAL);

	jump_cmd = append_jump(sh_desc,
		CLASS_BOTH | JUMP_TEST_ALL | JUMP_COND_SHRD | JUMP_COND_SELF);

	/* process keys, starting with class 2/authentication */
	append_key(sh_desc, ctx->key_phys, ctx->split_key_len,
			CLASS_2 | KEY_DEST_MDHA_SPLIT | KEY_ENC);

	/* Now the class 1/cipher key */
	if (keys_fit_inline)
		append_key_as_imm(sh_desc, (void *)ctx->key +
				ctx->split_key_pad_len, ctx->enckeylen,
				ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	else
		append_key(sh_desc, ctx->key_phys + ctx->split_key_pad_len,
			ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);


	/* update jump cmd now that we are at the jump target */
	set_jump_tgt_here(sh_desc, jump_cmd);

	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
					desc_bytes(ctx->sh_desc),
					DMA_BIDIRECTIONAL);
	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_DPERR("unable to map shared descriptor");
		return -ENOMEM;
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	printk(KERN_ERR "\n");
	print_hex_dump(KERN_ERR, "shrdesc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, sh_desc,
			desc_bytes(sh_desc), 1);
#endif
	return 0;
}

int secfp_prepareEncapShareDesc(struct caam_ctx *ctx, u32 *sh_desc,
	outSA_t *pSA, bool keys_fit_inline)
{
	u32 *jump_cmd;

	init_sh_desc(sh_desc, HDR_SAVECTX | HDR_SHARE_SERIAL);


	jump_cmd = append_jump(sh_desc,
		CLASS_BOTH | JUMP_TEST_ALL | JUMP_COND_SHRD | JUMP_COND_SELF);

	/* process keys, starting with class 2/authentication */
	append_key(sh_desc, ctx->key_phys, ctx->split_key_len,
			CLASS_2 | KEY_DEST_MDHA_SPLIT | KEY_ENC);

	/* Now the class 1/cipher key */
	if (keys_fit_inline)
		append_key_as_imm(sh_desc, (void *)ctx->key +
				ctx->split_key_pad_len, ctx->enckeylen,
				ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);
	else
		append_key(sh_desc, ctx->key_phys + ctx->split_key_pad_len,
			ctx->enckeylen, CLASS_1 | KEY_DEST_CLASS_REG);

	/* update jump cmd now that we are at the jump target */
	set_jump_tgt_here(sh_desc, jump_cmd);

	ASFIPSEC_DEBUG("Enc Algorithm is %d Auth Algorithm is %d",
		pSA->SAParams.ucCipherAlgo, pSA->SAParams.ucAuthAlgo);

	ctx->shared_desc_phys = dma_map_single(ctx->jrdev, ctx->sh_desc,
					desc_bytes(ctx->sh_desc),
					DMA_TO_DEVICE);
	if (dma_mapping_error(ctx->jrdev, ctx->shared_desc_phys)) {
		ASFIPSEC_DPERR("unable to map shared descriptor");
		return -ENOMEM;
	}

#ifdef ASFIPSEC_DEBUG_FRAME
	printk(KERN_ERR "\n");
	print_hex_dump(KERN_ERR, "shrdesc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, sh_desc,
			desc_bytes(sh_desc), 1);
#endif
	return 0;
}

int secfp_buildProtocolDesc(struct caam_ctx *ctx, void *pSA, int dir)
{
	struct device *jrdev = ctx->jrdev;
	u32 *sh_desc;
	int ret = 0;
	bool keys_fit_inline = 0;
	gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;
	/*
	* largest Job Descriptor and its Shared Descriptor
	* must both fit into the 64-word Descriptor h/w Buffer
	*/
	if ((DESC_AEAD_GIVENCRYPT_TEXT_LEN +
	DESC_AEAD_SHARED_TEXT_LEN) * CAAM_CMD_SZ +
	ctx->enckeylen + CAAM_PTR_SZ <= CAAM_DESC_BYTES_MAX)
		keys_fit_inline = 1;

	/* build shared descriptor for this session */
	ctx->sh_desc_mem = kzalloc(CAAM_CMD_SZ * DESC_AEAD_SHARED_TEXT_LEN +
			L1_CACHE_BYTES - 1 + (keys_fit_inline ?
			CAAM_PTR_SZ + ctx->enckeylen : CAAM_PTR_SZ * 2),
			GFP_DMA | flags);
	if (!ctx->sh_desc_mem) {
		ASFIPSEC_DPERR("Could not allocate shared descriptor");
		return -ENOMEM;
	}

	sh_desc = (u32 *)(((int)ctx->sh_desc_mem
			+ (L1_CACHE_BYTES - 1)) & ~(L1_CACHE_BYTES - 1));

	ctx->sh_desc = sh_desc;

	/* Shared Descriptor Creation */
	if (dir == SECFP_OUT)
		ret = secfp_prepareEncapShareDesc(ctx, sh_desc,
					(outSA_t *)pSA, keys_fit_inline);
	else
		ret = secfp_prepareDecapShareDesc(ctx, sh_desc,
					(inSA_t *)pSA, keys_fit_inline);
	if (ret) {
		ASFIPSEC_DPERR("error in secfp_prepare ShareDesc dir=%d", dir);
		kfree(ctx->sh_desc_mem);
		return ret;
	}

	return 0;
}

int secfp_createOutSACaamCtx(outSA_t *pSA)
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
		pSA->ctx.jrdev = priv->algapi_jr[(tgt_jr / 2) %
					priv->num_jrs_for_algapi];
		pSA->ctx.key = kzalloc(pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen,
					GFP_DMA | flags);

		if (!pSA->ctx.key) {
			ASFIPSEC_DEBUG("Could not"\
				"allocate CAAM key output memory\n");
			return -ENOMEM;
		}

		pSA->ctx.enckeylen = pSA->SAParams.EncKeyLen;
		ret = secfp_genCaamSplitKey(&pSA->ctx,
					(u8 *)&pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			kfree(pSA->ctx.key);
			return ret;
		}

		memcpy(pSA->ctx.key + pSA->ctx.split_key_pad_len,
			&pSA->SAParams.ucEncKey, pSA->SAParams.EncKeyLen);

		pSA->ctx.key_phys = dma_map_single(pSA->ctx.jrdev, pSA->ctx.key,
						pSA->ctx.split_key_pad_len +
						pSA->SAParams.EncKeyLen,
						DMA_TO_DEVICE);
		if (dma_mapping_error(pSA->ctx.jrdev, pSA->ctx.key_phys)) {
			ASFIPSEC_DEBUG(" Unable to map key"\
						"i/o memory\n");
			kfree(pSA->ctx.key);
			return -ENOMEM;
		}

		pSA->ctx.authsize = SECFP_ICV_LEN;
		ret = secfp_buildProtocolDesc(&pSA->ctx, pSA, SECFP_OUT);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			dma_unmap_single(pSA->ctx.jrdev, pSA->ctx.key_phys,
				pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen, DMA_TO_DEVICE);
			kfree(pSA->ctx.key);
			return ret;
		}

	} else
		ret = -EINVAL;

	return ret;
}

int secfp_createInSACaamCtx(inSA_t *pSA)
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
		pSA->ctx.jrdev = priv->algapi_jr[(tgt_jr / 2) %
						priv->num_jrs_for_algapi];

		pSA->ctx.key = kzalloc(pSA->ctx.split_key_pad_len +
					pSA->SAParams.EncKeyLen,
					GFP_DMA | flags);

		if (!pSA->ctx.key) {
			ASFIPSEC_DEBUG("Could not allocate"\
					"Caam key output memory\n");
			return -ENOMEM;
		}

		pSA->ctx.enckeylen = pSA->SAParams.EncKeyLen;
		ret = secfp_genCaamSplitKey(&pSA->ctx,
					(u8 *)&pSA->SAParams.ucAuthKey,
					pSA->SAParams.AuthKeyLen);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			kfree(pSA->ctx.key);

			return ret;
		}

		memcpy(pSA->ctx.key + pSA->ctx.split_key_pad_len,
			&pSA->SAParams.ucEncKey, pSA->SAParams.EncKeyLen);

		pSA->ctx.key_phys = dma_map_single(pSA->ctx.jrdev, pSA->ctx.key,
						pSA->ctx.split_key_pad_len +
						pSA->SAParams.EncKeyLen,
							DMA_TO_DEVICE);
		if (dma_mapping_error(pSA->ctx.jrdev, pSA->ctx.key_phys)) {
			ASFIPSEC_DEBUG("Unable to map key"\
					"i/o memory\n");
			kfree(pSA->ctx.key);
			return -ENOMEM;
		}
		pSA->ctx.authsize = SECFP_ICV_LEN;
		ret = secfp_buildProtocolDesc(&pSA->ctx, pSA, SECFP_IN);
		if (ret) {
			ASFIPSEC_DEBUG("Failed\n");
			kfree(pSA->ctx.key);
			dma_unmap_single(pSA->ctx.jrdev, pSA->ctx.key_phys,
			pSA->ctx.split_key_pad_len +
			pSA->SAParams.EncKeyLen, DMA_TO_DEVICE);

			return ret;
		}
	} else
		ret = -EINVAL;

	return ret;
}


static void secfp_prepareCaamJobDescriptor(struct ipsec_esp_edesc *edesc,
					struct caam_ctx *ctx,
					dma_addr_t data_in, int data_in_len,
					dma_addr_t data_out, int data_out_len)
{
	u32 *desc, options;
	int authsize = ctx->authsize;
	int ivsize;
	outSA_t *pSA = container_of(ctx, outSA_t, ctx);

	ivsize = pSA->SAParams.ulIvSize;

	ASFIPSEC_DEBUG("ivsize=%d authsize=%d", ivsize, authsize);

	desc = edesc->hw_desc;

	/* insert shared descriptor pointer */
	init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_SHARE_DEFER);

	/*
	* LOAD IMM Info FIFO
	* to DECO, Last, Padding, Random, Message, 16 bytes
	*/
	append_load_imm_u32(desc, NFIFOENTRY_DEST_DECO | NFIFOENTRY_LC1 |
			NFIFOENTRY_STYPE_PAD | NFIFOENTRY_DTYPE_MSG |
			NFIFOENTRY_PTYPE_INCREMENT | ivsize,
			LDST_SRCDST_WORD_INFO_FIFO);

	/*
	* disable info fifo entries since the above serves as the entry
	* this way, the MOVE command won't generate an entry.
	* Note that this isn't required in more recent versions of
	* SEC as a MOVE that doesn't do info FIFO entries is available.
	*/
	append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

	/* MOVE DECO Alignment -> C1 Context 16 bytes */
	append_move(desc, MOVE_SRC_INFIFO | MOVE_DEST_CLASS1CTX | ivsize);

	/* re-enable info fifo entries */
	append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

	/* MOVE C1 Context -> OFIFO 16 bytes */
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_OUTFIFO | ivsize);

	append_fifo_store(desc, data_in + SECFP_ESP_HDR_LEN, ivsize,
					FIFOST_TYPE_MESSAGE_DATA);

	/* start auth operation */
	append_operation(desc, ctx->class2_alg_type | OP_ALG_AS_INITFINAL);

	/* Load FIFO with data for Class 2 CHA */
	options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

	append_fifo_load(desc, data_in, SECFP_ESP_HDR_LEN, options);

	/* copy iv from cipher/class1 input context to class2 infifo */
	/* Need to know the IV size */
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO | ivsize);

	append_operation(desc, ctx->class1_alg_type |
			OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);


	/* load payload & instruct to class2 to snoop class 1 if encrypting */
	options = 0;
	append_seq_in_ptr(desc, data_in + pSA->ulSecHdrLen,
				data_in_len - pSA->ulSecHdrLen, options);

	if (pSA->SAParams.bUseExtendedSequenceNumber) {
		/* The ESN higher bytes are at tail which will be at data_in_len
		offset from data_in ptr. Here we are instructing the CAAM to do
		CLASS1 operation for data_in_len - ESP Hdr - ICV_LEN. The DMA is
		being done for extra 12 bytes which will include the space for
		ICV and also has 4 bytes of ESN higher seq num. CAAM will use
		IP pkt for encryption and snoop that data to CLASS2 for Auth.
		Before finishing the authentication; load FIFO with 4 bytes
		of ESN HO so that CLASS2 can be performed on the same. ICV will
		get appended at the same place as in case of NON ESN data.
		*/
		append_seq_fifo_load(desc, data_in_len - (pSA->ulSecHdrLen +
			SECFP_ICV_LEN), FIFOLD_CLASS_BOTH
			| FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_MSG1OUT2);

		options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_LAST2
				| FIFOLD_TYPE_MSG;
		append_fifo_load(desc, data_in + (data_in_len -
				SECFP_ICV_LEN),
				SECFP_HO_SEQNUM_LEN, options);
		options = 0;
		append_seq_out_ptr(desc, data_out + pSA->ulSecHdrLen,
				data_in_len - pSA->ulSecHdrLen, options);
		append_seq_fifo_store(desc, data_in_len - (pSA->ulSecHdrLen +
				SECFP_ICV_LEN), FIFOST_TYPE_MESSAGE_DATA);
	} else {
		append_seq_fifo_load(desc, data_in_len - (pSA->ulSecHdrLen +
			SECFP_ICV_LEN), FIFOLD_CLASS_BOTH |
			FIFOLD_TYPE_LASTBOTH | FIFOLD_TYPE_MSG1OUT2);
		append_seq_out_ptr(desc, data_out + pSA->ulSecHdrLen,
				data_in_len - pSA->ulSecHdrLen, options);
		append_seq_fifo_store(desc, data_in_len - (pSA->ulSecHdrLen +
				SECFP_ICV_LEN), FIFOST_TYPE_MESSAGE_DATA);
	}
	/* ICV */
	append_seq_store(desc, authsize, LDST_CLASS_2_CCB |
				LDST_SRCDST_BYTE_CONTEXT);
#ifdef ASFIPSEC_DEBUG_FRAME
	printk(KERN_INFO "job_desc_len %d\n", desc_len(desc));
	printk(KERN_ERR "\n Data In Len %d Data Out Len %d Auth Size: %d\n",
				data_in_len, data_out_len, authsize);
	print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
					DUMP_PREFIX_ADDRESS, 16, 4, desc,
					desc_bytes(desc), 1);
#endif
}

/*
 * Function prepares the descriptors based on the encryption and authentication
 * algorithm. The prepared descriptor is submitted to SEC.
 */

void secfp_prepareOutDescriptor(struct sk_buff *skb, void *pData,
				void *descriptor, unsigned int ulOptionIndex)
{
	/* Check for the NR_Frags */
	if (!(skb_shinfo(skb)->nr_frags)) {
		dma_addr_t ptr;
		outSA_t *pSA = (outSA_t *) (pData);

		ptr = dma_map_single(pSA->ctx.jrdev, skb->data,
			skb->len + SECFP_ICV_LEN, DMA_BIDIRECTIONAL);
		ASFIPSEC_FPRINT("ulSecHdrLen %d skb->len %d",
			pSA->ulSecHdrLen, skb->len);
		ASFIPSEC_FPRINT("asso@:");
		ASFIPSEC_HEXDUMP(skb->data, 8);
		ASFIPSEC_FPRINT("presciv@:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen - 8, 8);
		ASFIPSEC_FPRINT("src @:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen, 60);

		secfp_prepareCaamJobDescriptor(descriptor, &pSA->ctx,
					ptr, skb->len + SECFP_ICV_LEN,
					ptr, skb->len + SECFP_ICV_LEN);
	} else {
		skb_frag_t *frag = 0;
		outSA_t *pSA = (outSA_t *) (pData);
		struct ipsec_esp_edesc *edesc =
				(struct ipsec_esp_edesc *)descriptor;
		unsigned short usPadLen = 0;
		struct link_tbl_entry *link_tbl_entry;
		dma_addr_t ptr, ptr1, ptr2 = (dma_addr_t) NULL;
		int i, total_frags, dma_len, len_to_caam = 0;
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

		total_frags = skb_shinfo(skb)->nr_frags;
		dma_len = sizeof(struct link_tbl_entry) * (total_frags + 1);
		ptr1 = dma_map_single(pSA->ctx.jrdev, skb->data,
				skb_headlen(skb), DMA_BIDIRECTIONAL);

		link_tbl_entry = kzalloc(dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr1 + pSA->ulSecHdrLen;
		link_tbl_entry->len = skb_headlen(skb) - pSA->ulSecHdrLen;
		len_to_caam = link_tbl_entry->len;

		/* Parse the NR_FRAGS */
		/* Prepare the scatter list for SEC */
		for (i = 0; i < total_frags; i++) {
			frag = &skb_shinfo(skb)->frags[i];
			if (i == total_frags - 1) {
				usPadLen = *(u8 *)
				(((u8 *)(page_address(frag->page) +
				frag->page_offset)) + frag->size - 2);

				ptr2 = dma_map_single(pSA->ctx.jrdev,
					(void *)page_address(frag->page)
					+ frag->page_offset, frag->size
					+ SECFP_ICV_LEN, DMA_BIDIRECTIONAL);

				(link_tbl_entry + i + 1)->ptr = ptr2;
				(link_tbl_entry + i + 1)->len = frag->size;
				len_to_caam += frag->size;
				(link_tbl_entry + i + 1)->len |=
					cpu_to_be32(0x40000000);

				break;
			}

			(link_tbl_entry + i + 1)->ptr =
				dma_map_single(pSA->ctx.jrdev,
				(void *)page_address(frag->page) +
				frag->page_offset, frag->size,
				DMA_BIDIRECTIONAL);
			(link_tbl_entry + i + 1)->len = frag->size;
			len_to_caam += (link_tbl_entry + i + 1)->len;

		}
		/* Go ahead and Submit to SEC */
		ptr = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		edesc->link_tbl_dma = ptr;
		edesc->link_tbl_bytes = dma_len;
		edesc->link_tbl = link_tbl_entry;

		{
		u32 *desc = edesc->hw_desc, options;
		int ivsize = pSA->SAParams.ulIvSize;
		int authsize = pSA->ctx.authsize;
		desc = edesc->hw_desc;

		/* insert shared descriptor pointer */
		init_job_desc_shared(desc, pSA->ctx.shared_desc_phys,
			desc_len(pSA->ctx.sh_desc), HDR_SHARE_DEFER);

		/*
		* LOAD IMM Info FIFO
		* to DECO, Last, Padding, Random, Message, 16 bytes
		*/
		append_load_imm_u32(desc, NFIFOENTRY_DEST_DECO |
			NFIFOENTRY_LC1 | NFIFOENTRY_STYPE_PAD |
			NFIFOENTRY_DTYPE_MSG | NFIFOENTRY_PTYPE_INCREMENT |
			ivsize, LDST_SRCDST_WORD_INFO_FIFO);

		/*
		* disable info fifo entries since the above serves as
		* the entry this way, the MOVE command won't generate an
		* entry. Note that this isn't required in more recent
		* versions of SEC as a MOVE that doesn't do info FIFO
		* entries is available.
		*/
		append_cmd(desc, CMD_LOAD | DISABLE_AUTO_INFO_FIFO);

		/* MOVE DECO Alignment -> C1 Context 16 bytes */
		append_move(desc, MOVE_SRC_INFIFO |
				MOVE_DEST_CLASS1CTX | ivsize);

		/* re-enable info fifo entries */
		append_cmd(desc, CMD_LOAD | ENABLE_AUTO_INFO_FIFO);

		/* MOVE C1 Context -> OFIFO 16 bytes */
		append_move(desc, MOVE_SRC_CLASS1CTX |
				MOVE_DEST_OUTFIFO | ivsize);

		append_fifo_store(desc, ptr1 + SECFP_ESP_HDR_LEN,
				ivsize, FIFOST_TYPE_MESSAGE_DATA);

		/* start auth operation */
		append_operation(desc, pSA->ctx.class2_alg_type |
				OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);

		/* Load FIFO with data for Class 2 CHA */
		options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

		append_fifo_load(desc, ptr1, SECFP_ESP_HDR_LEN,	options);

		/* copy iv from cipher/class1 input
			context to class2 infifo */
		/* Need to know the IV size */
		append_move(desc, MOVE_SRC_CLASS1CTX |
				MOVE_DEST_CLASS2INFIFO | ivsize);

		append_operation(desc, pSA->ctx.class1_alg_type |
			OP_ALG_AS_INITFINAL | OP_ALG_ENCRYPT);


		/* load payload & instruct to class2 to
			snoop class 1 if encrypting */
		options = 0;
		options |= LDST_SGF;

		append_seq_in_ptr(desc, ptr, len_to_caam + SECFP_ICV_LEN,
					options);

		append_seq_fifo_load(desc, len_to_caam,
				FIFOLD_CLASS_BOTH |
				FIFOLD_TYPE_LASTBOTH |
				FIFOLD_TYPE_MSG1OUT2);

		append_seq_out_ptr(desc, ptr, len_to_caam + SECFP_ICV_LEN,
							options);
		append_seq_fifo_store(desc, len_to_caam,
					FIFOST_TYPE_MESSAGE_DATA);

		/* ICV */
		append_store(desc, ptr2 + frag->size,
			authsize, LDST_CLASS_2_CCB |
			LDST_SRCDST_BYTE_CONTEXT);
#ifdef ASFIPSEC_DEBUG_FRAME
	printk(KERN_INFO "\nData In Len %d Data Out Len %d Auth Size: %d\n",
			len_to_caam + 12, len_to_caam, authsize);
	print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
				DUMP_PREFIX_ADDRESS, 16, 4, desc,
				desc_bytes(desc), 1);
#endif
		}
	}
}
void secfp_prepareOutDescriptorWithFrags(struct sk_buff *skb, void *pData,
			void *descriptor, unsigned int ulOptionIndex)
{
	secfp_prepareOutDescriptor(skb, pData, descriptor, ulOptionIndex);
}

static void secfp_prepareInCaamJobDescriptor(struct ipsec_esp_edesc *edesc,
					struct caam_ctx *ctx,
					dma_addr_t data_in, int data_in_len,
					dma_addr_t data_out, int data_out_len)
{
	u32 *desc, options;
	int authsize = ctx->authsize;
	int ivsize;
	inSA_t *pSA = container_of(ctx, inSA_t, ctx);

	ivsize = pSA->SAParams.ulIvSize;

	ASFIPSEC_DEBUG("ivsize=%d authsize=%d", ivsize, authsize);

	desc = edesc->hw_desc;

	/* insert shared descriptor pointer */
	init_job_desc_shared(desc, ctx->shared_desc_phys,
			desc_len(ctx->sh_desc), HDR_SHARE_DEFER);

	append_load(desc, data_in + SECFP_ESP_HDR_LEN, ivsize,
		LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

	/* start auth operation */
	append_operation(desc, ctx->class2_alg_type | OP_ALG_AS_INITFINAL |
			OP_ALG_ICV_ON);

	/* Load FIFO with data for Class 2 CHA */
	options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

	append_fifo_load(desc, data_in, SECFP_ESP_HDR_LEN, options);
	/* copy iv from cipher/class1 input context to class2 infifo */
	/* Need to know the IV size */
	append_move(desc, MOVE_SRC_CLASS1CTX | MOVE_DEST_CLASS2INFIFO | ivsize);

	{
		u32 *jump_cmd, *uncond_jump_cmd;

		/* JUMP if shared */
		jump_cmd = append_jump(desc, JUMP_TEST_ALL | JUMP_COND_SHRD);

		/* start class 1 (cipher) operation, non-shared version */
		append_operation(desc, ctx->class1_alg_type |
				OP_ALG_AS_INITFINAL);

		uncond_jump_cmd = append_jump(desc, 0);

		set_jump_tgt_here(desc, jump_cmd);

		/* start class 1 (cipher) operation, shared version */
		append_operation(desc, ctx->class1_alg_type |
				OP_ALG_AS_INITFINAL | OP_ALG_AAI_DK);
		set_jump_tgt_here(desc, uncond_jump_cmd);
	}

	/* load payload & instruct to class2 to snoop class 1 if encrypting */
	options = 0;

	if (pSA->SAParams.bUseExtendedSequenceNumber) {
		append_seq_in_ptr(desc, data_in + (SECFP_ESP_HDR_LEN + ivsize),
			data_in_len + SECFP_HO_SEQNUM_LEN -
			(SECFP_ESP_HDR_LEN + ivsize), options);
		append_seq_fifo_load(desc, data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + SECFP_ICV_LEN) + SECFP_HO_SEQNUM_LEN,
			FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_LAST2 |
			FIFOLD_TYPE_MSG);

		append_fifo_load(desc, data_in + (SECFP_ESP_HDR_LEN + ivsize),
			data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + SECFP_ICV_LEN), FIFOLD_CLASS_CLASS1 |
			FIFOLD_TYPE_LAST1 | FIFOLD_TYPE_MSG);

		append_seq_out_ptr(desc, data_out + (SECFP_ESP_HDR_LEN +
			ivsize), data_in_len - (SECFP_ESP_HDR_LEN + ivsize),
			options);
		append_seq_fifo_store(desc, data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + SECFP_ICV_LEN), FIFOST_TYPE_MESSAGE_DATA);
	} else {
		append_seq_in_ptr(desc, data_in + (SECFP_ESP_HDR_LEN + ivsize),
			data_in_len - (SECFP_ESP_HDR_LEN + ivsize), options);
		append_seq_fifo_load(desc, data_in_len - (SECFP_ESP_HDR_LEN +
				ivsize + SECFP_ICV_LEN), FIFOLD_CLASS_BOTH |
			FIFOLD_TYPE_LASTBOTH | FIFOLD_TYPE_MSG);

		append_seq_out_ptr(desc, data_out + (SECFP_ESP_HDR_LEN +
			ivsize), data_in_len - (SECFP_ESP_HDR_LEN + ivsize),
			options);
		append_seq_fifo_store(desc, data_in_len - (SECFP_ESP_HDR_LEN +
			ivsize + SECFP_ICV_LEN), FIFOST_TYPE_MESSAGE_DATA);
	}

	append_seq_fifo_load(desc, authsize, FIFOLD_CLASS_CLASS2 |
			FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);

#ifdef ASFIPSEC_DEBUG_FRAME
	printk(KERN_ERR "\n Data In Len %d Data Out Len %d Auth Size: %d\n",
					data_in_len, data_out_len, authsize);
	print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
			DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif
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
	/* Check for the NR_Frags */
	if (unlikely(skb_shinfo(skb)->nr_frags)) {
		struct ipsec_esp_edesc *edesc = descriptor;
		inSA_t *pSA = (inSA_t *)pData;
		static struct link_tbl_entry *link_tbl_entry;
		dma_addr_t ptr, ptr2;
		unsigned int *ptr1;
		int i, total_frags, dma_len, len_to_caam = 0;
		gfp_t flags = in_interrupt() ? GFP_ATOMIC : GFP_KERNEL;

		total_frags = skb_shinfo(skb)->nr_frags;
		dma_len = sizeof(struct link_tbl_entry) * (total_frags + 1);
		ptr1 = (unsigned int *) &(skb->cb[SECFP_SKB_DATA_DMA_INDEX]);
		*ptr1 = (unsigned int) link_tbl_entry;
		ptr2 = dma_map_single(pSA->ctx.jrdev, skb->data,
				skb_headlen(skb), DMA_BIDIRECTIONAL);

		link_tbl_entry = kzalloc(dma_len, GFP_DMA | flags);
		link_tbl_entry->ptr = ptr2 + pSA->ulSecHdrLen;
		link_tbl_entry->len = skb_headlen(skb) - pSA->ulSecHdrLen;
		len_to_caam = link_tbl_entry->len;

		ASFIPSEC_FPRINT("\nskb->len:%d skb->data_len:%d"
				" skb_headlen(skb):%d, total_frags:%d",
				skb->len, skb->data_len,
				skb_headlen(skb), total_frags);
		ASFIPSEC_HEXDUMP(skb->data, 48);

		/* Parse the NR_FRAGS */
		/* Prepare the scatter list for SEC */
		for (i = 0; i < total_frags; i++) {
			skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
			(link_tbl_entry + i + 1)->ptr =
					dma_map_single(pSA->ctx.jrdev,
					(void *)page_address(frag->page) +
					frag->page_offset,
					frag->size, DMA_BIDIRECTIONAL);

			ASFIPSEC_HEXDUMP((void *)page_address(frag->page) +
					frag->page_offset , 64);

			(link_tbl_entry + i + 1)->len = frag->size;
			len_to_caam += frag->size;
			if (i == total_frags - 1)
				(link_tbl_entry + i + 1)->len |=
						cpu_to_be32(0x40000000);
		}
		/* Go ahead and Submit to SEC */
		ptr = dma_map_single(pSA->ctx.jrdev, link_tbl_entry,
					dma_len, DMA_BIDIRECTIONAL);
		edesc->link_tbl_dma = ptr;
		edesc->link_tbl_bytes = dma_len;
		edesc->link_tbl = link_tbl_entry;

		{
		u32 *desc, options;
		int ivsize = pSA->SAParams.ulIvSize;
		int authsize = pSA->ctx.authsize;

		desc = edesc->hw_desc;

		/* insert shared descriptor pointer */
		init_job_desc_shared(desc, pSA->ctx.shared_desc_phys,
			desc_len(pSA->ctx.sh_desc), HDR_SHARE_DEFER);

		append_load(desc, ptr2 + SECFP_ESP_HDR_LEN, ivsize,
			LDST_CLASS_1_CCB | LDST_SRCDST_BYTE_CONTEXT);

		/* start auth operation */
		append_operation(desc, pSA->ctx.class2_alg_type |
					OP_ALG_AS_INITFINAL | OP_ALG_ICV_ON);

		/* Load FIFO with data for Class 2 CHA */
		options = FIFOLD_CLASS_CLASS2 | FIFOLD_TYPE_MSG;

		append_fifo_load(desc, ptr2, SECFP_ESP_HDR_LEN, options);

		/* copy iv from cipher/class1 input
			context to class2 infifo */
		/* Need to know the IV size */
		append_move(desc, MOVE_SRC_CLASS1CTX |
				MOVE_DEST_CLASS2INFIFO | ivsize);

		{
			u32 *jump_cmd, *uncond_jump_cmd;

			/* JUMP if shared */
			jump_cmd = append_jump(desc, JUMP_TEST_ALL |
						JUMP_COND_SHRD);

			/* start class 1 (cipher) operation,
					non-shared version */
			append_operation(desc, pSA->ctx.class1_alg_type
					| OP_ALG_AS_INITFINAL);

			uncond_jump_cmd = append_jump(desc, 0);

			set_jump_tgt_here(desc, jump_cmd);

			/* start class 1 (cipher) operation,
				shared version */
			append_operation(desc, pSA->ctx.class1_alg_type
				| OP_ALG_AS_INITFINAL | OP_ALG_AAI_DK);

			set_jump_tgt_here(desc, uncond_jump_cmd);
		}

		/* load payload & instruct class2 to
			snoop class 1 if encrypting */
		options = 0;
		options |= LDST_SGF;

		append_seq_in_ptr(desc, ptr, len_to_caam, options);

		append_seq_fifo_load(desc, len_to_caam - authsize,
				FIFOLD_CLASS_BOTH | FIFOLD_TYPE_LASTBOTH |
				FIFOLD_TYPE_MSG);

		append_seq_out_ptr(desc, ptr, len_to_caam, options);

		append_seq_fifo_store(desc, len_to_caam - authsize,
					FIFOST_TYPE_MESSAGE_DATA);

		/* ICV */
		append_seq_fifo_load(desc, authsize, FIFOLD_CLASS_CLASS2 |
					FIFOLD_TYPE_LAST2 | FIFOLD_TYPE_ICV);
#ifdef ASFIPSEC_DEBUG_FRAME
		ASFIPSEC_DEBUG("\nData In Len:%d Data Out Len:%d Auth Size:%d",
			len_to_caam, len_to_caam - 12, authsize);
		print_hex_dump(KERN_ERR, "desc@"xstr(__LINE__)": ",
		DUMP_PREFIX_ADDRESS, 16, 4, desc, desc_bytes(desc), 1);
#endif
		}
	} else {
		dma_addr_t ptr;
		inSA_t *pSA = (inSA_t *)pData;

		ptr = dma_map_single(pSA->ctx.jrdev, skb->data,
			skb->len + SECFP_HO_SEQNUM_LEN, DMA_BIDIRECTIONAL);

		ASFIPSEC_FPRINT("ulSecHdrLen %d skb->len %d",
			pSA->ulSecHdrLen, skb->len);
		ASFIPSEC_FPRINT(" asso@:");
		ASFIPSEC_HEXDUMP(skb->data, 8);
		ASFIPSEC_FPRINT(" presciv@:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen - 8, 8);
		ASFIPSEC_FPRINT(" src @:");
		ASFIPSEC_HEXDUMP(skb->data + pSA->ulSecHdrLen, 80);

		if (!ptr) {
			ASFIPSEC_ERR("DMA MAP FAILED\n");
			return;
		}
		secfp_prepareInCaamJobDescriptor(descriptor, &pSA->ctx,
				ptr , skb->len, ptr, skb->len);
	}

}

#endif /*defined(CONFIG_ASF_SEC4x)*/
