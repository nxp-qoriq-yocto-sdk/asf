/**************************************************************************
 * Copyright 2011-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipseccaam.h
 * Description: Contains macros and type defintions for CAAM block.
 * Authors:	Naveen Burmi <B16502@freescale.com>
 *
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/****************************************************************************/

#ifndef __IPSEC_CAAM_H
#define __IPSEC_CAAM_H

#include <desc_constr.h>
#include <linux/debugfs.h>
#include <intern.h>

#define AES_MAX_KEY_SIZE       32
#define SHA512_DIGEST_SIZE     64
#define CAAM_MAX_KEY_SIZE      (AES_MAX_KEY_SIZE + SHA512_DIGEST_SIZE * 2)
/* max IV is max of AES_BLOCK_SIZE, DES3_EDE_BLOCK_SIZE */
#define CAAM_MAX_IV_LENGTH     16

/* length of descriptors text */
#define DESC_JOB_IO_LEN			(CAAM_CMD_SZ * 5 + CAAM_PTR_SZ * 3)

#define DESC_AEAD_BASE			(4 * CAAM_CMD_SZ)
#define DESC_AEAD_ENC_LEN		(DESC_AEAD_BASE + 16 * CAAM_CMD_SZ)
#define DESC_AEAD_DEC_LEN		(DESC_AEAD_BASE + 21 * CAAM_CMD_SZ)
#define DESC_AEAD_GIVENC_LEN		(DESC_AEAD_ENC_LEN + 7 * CAAM_CMD_SZ)

#define DESC_ABLKCIPHER_BASE		(3 * CAAM_CMD_SZ)
#define DESC_ABLKCIPHER_ENC_LEN		(DESC_ABLKCIPHER_BASE + \
					20 * CAAM_CMD_SZ)
#define DESC_ABLKCIPHER_DEC_LEN		(DESC_ABLKCIPHER_BASE + \
					15 * CAAM_CMD_SZ)

#define DESC_MAX_USED_BYTES		(DESC_AEAD_GIVENC_LEN + \
					CAAM_MAX_KEY_SIZE)
#define DESC_MAX_USED_LEN		(DESC_MAX_USED_BYTES / CAAM_CMD_SZ)

/*
 * per-session context
 */
struct caam_ctx {
	struct device *jrdev;
	u32 sh_desc_enc[DESC_MAX_USED_LEN];
	u32 sh_desc_dec[DESC_MAX_USED_LEN];
	u32 sh_desc_givenc[DESC_MAX_USED_LEN];
	dma_addr_t sh_desc_enc_dma;
	dma_addr_t sh_desc_dec_dma;
	dma_addr_t sh_desc_givenc_dma;
	u32 class1_alg_type;
	u32 class2_alg_type;
	u32 alg_op;
	u8 key[CAAM_MAX_KEY_SIZE];
	dma_addr_t key_dma;
	u32 enckeylen;
	u32 split_key_len;
	u32 split_key_pad_len;
	u32 authsize;
};

struct aead_edesc {
	int assoc_nents;
	bool assoc_chained;
	int src_nents;
	bool src_chained;
	int dst_nents;
	bool dst_chained;
	dma_addr_t iv_dma;
	int sec4_sg_bytes;
	dma_addr_t sec4_sg_dma;
	struct sec4_sg_entry *sec4_sg;
	u32 hw_desc[0];
};

extern struct device *asf_caam_device(void);
extern char *caam_jr_strstatus(char *outstr, u32 status);
extern int caam_jr_enqueue(struct device *dev, void *desc,
			void (*callback) (struct device *dev, u32 *desc,
			u32 error, void *context), void *context);

#endif
