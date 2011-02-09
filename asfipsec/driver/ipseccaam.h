/**************************************************************************
 * Copyright 2011 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
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

#include <pdb.h>
#include <desc.h>
#include <dcl/dcl.h>

struct caam_ctx {
	struct device *dev;
	int class1_alg_type;
	int class2_alg_type;
	int alg_op;
	u8 *key;
	dma_addr_t key_phys;
	unsigned int keylen;
	unsigned int enckeylen;
	unsigned int authkeylen;
	unsigned int split_key_len;
	unsigned int split_key_pad_len;
	unsigned int authsize;
	union {
		struct ipsec_encap_pdb *shared_encap;
		struct ipsec_decap_pdb *shared_decap;
	};
	dma_addr_t shared_desc_phys;
	int shared_desc_len;
	spinlock_t first_lock;
};

struct link_tbl_entry {
	__be64 ptr;
	__be32 len;
	u8 reserved;
	u8 buf_pool_id;
	__be16 offset;
};

struct ipsec_esp_edesc {
	u32 hw_desc[MAX_CAAM_DESCSIZE];
	int src_nents;
	int dst_nents;
	int assoc_nents;
	int dma_len;
	dma_addr_t link_tbl_phys;
	struct link_tbl_entry link_tbl[0];
};

extern struct device *asf_caam_device(void);
extern char *caam_jq_strstatus(char *outstr, u32 status);
extern int secfp_caam_submit(struct device *dev, void *desc,
			void (*callback) (struct device *dev, void *desc,
			int error, void *context), void *context);

#endif
