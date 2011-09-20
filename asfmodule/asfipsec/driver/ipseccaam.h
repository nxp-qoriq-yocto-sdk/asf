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

#include <desc_constr.h>
#include <intern.h>
/*
 * per-session context
 */
struct caam_ctx {
	struct device *jrdev;
	u32 *sh_desc;
	dma_addr_t shared_desc_phys;
	u32 class1_alg_type;
	u32 class2_alg_type;
	u32 alg_op;
	u8 *key;
	dma_addr_t key_phys;
	unsigned int enckeylen;
	unsigned int split_key_len;
	unsigned int split_key_pad_len;
	unsigned int authsize;
};

struct link_tbl_entry {
	u64 ptr;
	u32 len;
	u8 reserved;
	u8 buf_pool_id;
	u16 offset;
};

struct ipsec_esp_edesc {
	int assoc_nents;
	int src_nents;
	int dst_nents;
	int link_tbl_bytes;
	dma_addr_t link_tbl_dma;
	struct link_tbl_entry *link_tbl;
	u32 hw_desc[0];
};

extern struct device *asf_caam_device(void);
extern char *caam_jr_strstatus(char *outstr, u32 status);
extern int secfp_caam_submit(struct device *dev, void *desc,
			void (*callback) (struct device *dev, void *desc,
			u32 error, void *context), void *context);

#endif
