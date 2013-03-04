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
#include <linux/interrupt.h>
#include <intern.h>
#ifdef ASF_QMAN_IPSEC
#include "linux/fsl_qman.h"
#include "linux/fsl_bman.h"
#endif

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

#ifdef ASF_QMAN_IPSEC
struct secfp_fq_link_node_s {
	struct qman_fq qman_fq;
	unsigned int fq_uses;
	struct secfp_fq_link_node_s *pPrev;
	struct secfp_fq_link_node_s *pNext;
};

typedef struct scatter_gather_entry_s {
	u32 reserved_zero:28;
	u32 addr_hi:4; /**< Memory Address of the start of the buffer - hi*/
	u32 addr_lo; /**< Memory Address - lo*/
	u32 extension:1;
	u32 final:1;
	u32 length:30; /**< Length of the data in the frame */
	u8 reserved_zero2;
	u8 bpid; /**< Buffer Pool Id */
	u16 reserved_offset:3;
	u16 offset:13;
} scatter_gather_entry_t;

struct ses_pkt_info {
	scatter_gather_entry_t cb_SG[2];
	struct sk_buff	*cb_skb;
	struct device	*cb_pDev;
	u8 dir;
	u8 dynamic;
};

struct preheader_t {
	union {
		uint32_t word;
		struct {
			uint16_t rsvd63_48;
			unsigned int rsvd47_39:9;
			unsigned int idlen:7;
		} field;
	} __packed hi;

	union {
		uint32_t word;
		struct {
			unsigned int rsvd31_30:2;
			unsigned int fsgt:1;
			unsigned int lng:1;
			unsigned int offset:2;
			unsigned int abs:1;
			unsigned int add_buf:1;
			uint8_t pool_id;
			uint16_t pool_buffer_size;
		} field;
	} __packed lo;
} __packed;

typedef enum {
	ASF_QMAN_MIN_SEC_FQ = 1,
	ASF_QMAN_OUT_SEC_FQ = 1,
	ASF_QMAN_OUT_RECV_FQ = 2,
	ASF_QMAN_IN_SEC_FQ = 3,
	ASF_QMAN_IN_RECV_FQ = 4,
	ASF_QMAN_OUT_FRAG_RECV_FQ = 5,
	ASF_QMAN_MAX_SEC_FQ = ASF_QMAN_OUT_FRAG_RECV_FQ
} asf_qman_sec_fq_t;

#endif /* #ASF_QMAN_IPSEC */


/*
 * per-session context
 */
struct caam_ctx {
	struct device *jrdev;
	u32 *sh_desc;
	u32 *sh_desc_mem;
	dma_addr_t shared_desc_phys;
	u32 class1_alg_type;
	u32 class2_alg_type;
	u32 alg_op;
	u8 *key;
	dma_addr_t key_phys;
	u32 enckeylen;
	u32 split_key_len;
	u32 split_key_pad_len;
	u32 authsize;
#ifdef ASF_QMAN_IPSEC
	struct secfp_fq_link_node_s *SecFq;
	struct secfp_fq_link_node_s *RecvFq;
#endif
};

struct link_tbl_entry {
	u64 ptr;
	u32 len;
	u8 reserved;
	u8 buf_pool_id;
	u16 offset;
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
