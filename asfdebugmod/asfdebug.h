/**************************************************************************
 * Copyright 2013, Freescale Semiconductor, Inc. All rights reserved.
 *************************************************************************/
/*
 * File:	asfdebug.h
 * Description: ASF debug related declarations.
 * Authors:	Sunil Kumar Kori <B42948@freescale.com>
 *
 */
/* History
 *
 */
/**************************************************************************/
#include <linux/netdevice.h>
#include <dpa/dpaa_eth_common.h>
#include <linux/skbuff.h>
#include <linux/fsl_qman.h>
#include <linux/types.h>

/*Structure definitions*/
#ifdef CONFIG_FSL_DPAA_ETH
struct annotations_t {
	struct sk_buff *skbh;
	struct qm_fd *fd;	/**< Pointer to frame descriptor*/
	uint32_t flag;		/**< All flags like ip_summed will reside here*/
#ifdef __LP64__
	uint32_t reserved[15];	/**<May be used in future */
#else
	uint32_t reserved[17];	/**<May be used in future */
#endif
	t_FmPrsResult parse_result;	/**<Parsed result*/
	uint64_t timestamp;		/**< TimeStamp */
	union {
		uint64_t hash_result;		/**< Hash Result */
		struct {
			uint32_t hiHash;
			uint32_t loHash;
		} hr_hilo;
	};
} __attribute__((packed));
#endif

typedef union ASFDebugBuffer_u {
	struct {
		void     *buffer;
		unsigned int ulBufLen;
	} linearBuffer;
#ifdef CONFIG_FSL_DPAA_ETH
	struct {
		struct ethhdr		*ethh;
		struct annotations_t	*pAnnot;
		struct iphdr		*iph;
		/* what this ptr means:
		if ASF_DO_INC_CHECKSUM is defined, then it just a
		placeholder for transp hdr cksum ptr.
		if not defined, then in addition to being a placeholder.
		if this ptr is NULL, then pkt did not change or S/W
		updated cksum; so there is no need to enable hw cksum
		if this ptr is not NULL, then pkt changed;
		S/W expects hw to update cksum */
		unsigned short		*pCsum;
		struct net_device	*ndev;
		/* if this field is NULL then, skb is not yet setup and the
		data buffer has not been deducted from
		percpu_priv->dpa_bp_count; if not NULL, then skb is already
		formed and the count decremented  */
		void			*nativeBuffer;
		void			*flow;
		unsigned int		frag_list;
		unsigned char		bbuffInDomain;
	};
#else
	void     *nativeBuffer;
#endif
} ASFDebugBuffer_t;
/*Function Declarations used in Debug module*/
int asf_debug_devfp_rx(void *ptr, struct net_device *real_dev,
		unsigned int  fqid);
static int __init asf_debug_init(void);
static void __exit asf_debug_exit(void);

#define ASF_ETH_HDR_DEF_SIZE	14
#define ASF_MAX_TX_TRY_COUNT	32

#ifdef CONFIG_FSL_DPAA_ETH
#define devfp_debug_register_hook(rx_hook, tx_hook) {			\
	struct dpaa_eth_hooks_s hooks = {};				\
	hooks.rx_default = (dpaa_eth_ingress_hook_t)rx_hook;		\
	hooks.tx =  (dpaa_eth_egress_hook_t)tx_hook;			\
	fsl_dpaa_eth_set_hooks(&hooks);					\
}

#define AS_FP_PROCEED	DPAA_ETH_CONTINUE
#define AS_FP_STOLEN	DPAA_ETH_STOLEN
#endif
