/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	ipsecproc.c
 * Description: ASF IPSEC proc interface implementation
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
 /* History
 *  Version	Date		Author		Change Description
 *  0.1		12/10/2010    Hemant Agrawal	Initial Development
 *
*/
/***************************************************************************/

#include <linux/version.h>
#include <linux/skbuff.h>
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/gplcode.h"
#include "../../asfffp/driver/asfcmn.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include "ipseccmn.h"
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/fs.h>
/*
 * Implement following proc
 *	/proc/asf/ipsec/flows
 *	/proc/asf/ipsec/stats
 */

struct algo_info {
	const char *alg_name;
	int alg_type;
};

#define IPSEC_PROC_MAX_ALGO 8

static const struct algo_info algo_types[2][IPSEC_PROC_MAX_ALGO] = {
	{
		{"cbc(aes)", SECFP_AES},
		{"cbc(des3_ede)", SECFP_3DES},
		{"cbc(des)", SECFP_DES},
		{"null", SECFP_ESP_NULL},
		{"aes-ctr)", SECFP_AESCTR},
		{NULL, -1}
	},
	{
		{"hmac(sha1)", SECFP_HMAC_SHA1},
		{"hmac(sha256)", SECFP_HMAC_SHA256},
		{"hmac(sha384)", SECFP_HMAC_SHA384},
		{"hmac(sha512)", SECFP_HMAC_SHA512},
		{"hmac(md5)", SECFP_HMAC_MD5},
		{"aes-xcbc-mac)", SECFP_HMAC_AES_XCBC_MAC},
		{"null", SECFP_HMAC_NULL},
		{NULL, -1}
	}
};

const char *algo_getname(int type, int algo)
{
	int i;
	for (i = 0; i < IPSEC_PROC_MAX_ALGO; i++) {
		if (algo == algo_types[type][i].alg_type)
			return algo_types[type][i].alg_name;
	}
	return "NULL";
}


static struct ctl_table secfp_proc_table[] = {
	{
		.procname       = "ulMaxTunnels_g",
		.data	   = &ulMaxTunnels_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ulMaxVSGs_g",
		.data	   = &ulMaxVSGs_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ulMaxSPDContainers_g",
		.data	   = &ulMaxSPDContainers_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname	= "ulMaxSupportedIPSecSAs_g",
		.data	   = &ulMaxSupportedIPSecSAs_g,
		.maxlen  = sizeof(int),
		.mode	   = 0444,
		.proc_handler	= proc_dointvec,
	} ,
	{
		.procname       = "ulL2BlobRefreshPktCnt_g",
		.data	   = &ulL2BlobRefreshPktCnt_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ulL2BlobRefreshTimeInSec_g",
		.data	   = &ulL2BlobRefreshTimeInSec_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{}
} ;

static struct ctl_table secfp_proc_root_table[] = {
	{
		.procname       = "asfipsec",
		.mode	   = 0555,
		.child	  = secfp_proc_table,
	} ,
	{}
} ;

static struct ctl_table_header *secfp_proc_header;


static struct proc_dir_entry *secfp_dir;
#define SECFP_PROC_GLOBAL_STATS_NAME	"global_stats"
#define SECFP_PROC_RESET_STATS_NAME	"reset_stats"
#define SECFP_PROC_GLOBAL_ERROR_NAME	"global_error"
#define SECFP_PROC_OUT_SPD		"out_spd"
#define SECFP_PROC_IN_SPD		"in_spd"
#define SECFP_PROC_OUT_SA		"out_sa"
#define SECFP_PROC_IN_SA		"in_sa"
#define SECFP_PROC_SA_LIST		"sa_list"

#define GSTATS_SUM(a) (total.ul##a += gstats->ul##a)
#define GSTATS_TOTAL(a) (unsigned long) total.ul##a

static int display_secfp_proc_global_stats(struct seq_file *f, void *v)
{
	AsfIPSecPPGlobalStats_t total;
	int cpu;
	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu) {
		AsfIPSecPPGlobalStats_t *gstats;
		gstats = asfPerCpuPtr(pIPSecPPGlobalStats_g, cpu);
		GSTATS_SUM(TotInRecvPkts);
		GSTATS_SUM(TotInProcPkts);
		GSTATS_SUM(TotOutRecvPkts);
		GSTATS_SUM(TotOutProcPkts);
		GSTATS_SUM(TotInRecvSecPkts);
		GSTATS_SUM(TotInProcSecPkts);
		GSTATS_SUM(TotOutRecvPktsSecApply);
		GSTATS_SUM(TotOutPktsSecAppled);
	}
	seq_printf(f, "\n    InRcv %lu\tInProc %lu\tOutRcv %lu OutProc %lu\n",
		GSTATS_TOTAL(TotInRecvPkts), GSTATS_TOTAL(TotInProcPkts),
		GSTATS_TOTAL(TotOutRecvPkts), GSTATS_TOTAL(TotOutProcPkts));

	seq_printf(f, "\nSEC-InRcv %lu\tInProc %lu\tOutRcv %lu OutProc %lu\n",
		GSTATS_TOTAL(TotInRecvSecPkts),
		GSTATS_TOTAL(TotInProcSecPkts),
		GSTATS_TOTAL(TotOutRecvPktsSecApply),
		GSTATS_TOTAL(TotOutPktsSecAppled));

	return 0;
}

static int reset_secfp_proc_global_stats(struct seq_file *f, void *v)
{
	ASFIPSec4GlobalPPStats_t Outparams;

	ASFIPSecGlobalQueryStats(&Outparams, ASF_TRUE);
	memset(&GlobalErrors, 0, sizeof(ASFIPSecGlobalErrorCounters_t));

	seq_printf(f, "\n    InRcv %u \t InProc %u \tOutRcv %u OutProc %u\n",
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT1],
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT2],
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT3],
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT4]);

	seq_printf(f, "\nSEC-InRcv %u \t InProc %u \tOutRcv %u OutProc %u\n",
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT5],
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT6],
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT7],
		Outparams.IPSec4GblPPStat[ASF_IPSEC_PP_GBL_CNT8]);

	seq_printf(f, "Resetting IPSEC Global Stats\n");

	return 0;
}

#define GLBERR_DISP(a) do {\
	if (total->ul##a)\
		seq_printf(f, "%10u (" #a ")\n", total->ul##a);\
	} while (0)

#define GLPPPSTATS_DISP(s, a) seq_printf(f, "%10u (%s)\n",\
					Outparams.IPSec4GblPPStat[a], s)

static int display_secfp_proc_global_errors(struct seq_file *f, void *v)
{
	ASFIPSecGlobalErrorCounters_t *total;
	ASFIPSec4GlobalPPStats_t Outparams;
	total = &GlobalErrors;

	seq_printf(f, " \nIPSEC ERRORS:\n");
	GLBERR_DISP(InvalidVSGId);
	GLBERR_DISP(InvalidTunnelId);
	GLBERR_DISP(InvalidMagicNumber);
	GLBERR_DISP(InvalidInSPDContainerId);
	GLBERR_DISP(InvalidOutSPDContainerId);
	GLBERR_DISP(InSPDContainerAlreadyPresent);
	GLBERR_DISP(OutSPDContainerAlreadyPresent);
	GLBERR_DISP(ResourceNotAvailable);
	GLBERR_DISP(TunnelIdNotInUse);
	GLBERR_DISP(TunnelIfaceFull);
	GLBERR_DISP(OutSPDContainersFull);
	GLBERR_DISP(InSPDContainersFull);
	GLBERR_DISP(SPDOutContainerNotFound);
	GLBERR_DISP(SPDInContainerNotFound);
	GLBERR_DISP(OutDuplicateSA);
	GLBERR_DISP(InDuplicateSA);
	GLBERR_DISP(InvalidAuthEncAlgo);
	GLBERR_DISP(OutSAFull);
	GLBERR_DISP(OutSANotFound);
	GLBERR_DISP(InSAFull);
	GLBERR_DISP(InSANotFound);
	GLBERR_DISP(InSASPDContainerMisMatch);
	GLBERR_DISP(OutSASPDContainerMisMatch);

	ASFIPSecGlobalQueryStats(&Outparams, ASF_FALSE);
	GLPPPSTATS_DISP("Not enough tail room", ASF_IPSEC_PP_GBL_CNT9);
	GLPPPSTATS_DISP("No of packets Invalid ESP", ASF_IPSEC_PP_GBL_CNT10);
	GLPPPSTATS_DISP("Decrypted Protocol != IPV4", ASF_IPSEC_PP_GBL_CNT11);
	GLPPPSTATS_DISP("Invalid Pad length", ASF_IPSEC_PP_GBL_CNT12);
	GLPPPSTATS_DISP("Submission to SEC failed", ASF_IPSEC_PP_GBL_CNT13);
	GLPPPSTATS_DISP("Invalid sequence number", ASF_IPSEC_PP_GBL_CNT14);
	GLPPPSTATS_DISP("Anti-replay window check failed",
		ASF_IPSEC_PP_GBL_CNT15);
	GLPPPSTATS_DISP("Replay packet", ASF_IPSEC_PP_GBL_CNT16);
	GLPPPSTATS_DISP("ICV Comp Failed", ASF_IPSEC_PP_GBL_CNT17);
	GLPPPSTATS_DISP("Crypto Operation Failed", ASF_IPSEC_PP_GBL_CNT18);
	GLPPPSTATS_DISP("Anti Replay window -- Drop the packet",
		ASF_IPSEC_PP_GBL_CNT19);
	GLPPPSTATS_DISP("Verification of SA Selectross Failed",
		ASF_IPSEC_PP_GBL_CNT20);
	GLPPPSTATS_DISP("Packet size is > Path MTU and"\
		"fragment bit set in SA or packet", ASF_IPSEC_PP_GBL_CNT21);
	GLPPPSTATS_DISP("Fragmentation Failed", ASF_IPSEC_PP_GBL_CNT22);
	GLPPPSTATS_DISP("IN SA Not Found", ASF_IPSEC_PP_GBL_CNT23);
	GLPPPSTATS_DISP("OUT SA Not Found", ASF_IPSEC_PP_GBL_CNT24);
	GLPPPSTATS_DISP("L2blob Not Found", ASF_IPSEC_PP_GBL_CNT25);
	GLPPPSTATS_DISP("Desc Alloc Error", ASF_IPSEC_PP_GBL_CNT26);
	GLPPPSTATS_DISP("SA Expired ", ASF_IPSEC_PP_GBL_CNT27);
	return 0;
}

static void print_SPDPolPPStats(AsfSPDPolPPStats_t PPStats)
{
	return;
}

static int display_secfp_proc_out_spd(struct seq_file *f, void *v)
{
	ASF_uint32_t ulVSGId = 0;
	ASF_uint32_t ulTunnelId = 0;
	struct SPDCILinkNode_s *pCINode;
	SPDOutContainer_t *pOutContainer = NULL;
	SPDOutSALinkNode_t *pOutSALinkNode;

	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		seq_printf(f, "Tunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	seq_printf(f, "\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d\n",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(
					&(secfp_OutDB),
					pCINode->ulIndex));
		if (!pOutContainer)
			continue;
		seq_printf(f, "=========OUT Policy==================\n");
		seq_printf(f, "Id=%d, Proto 0x%x, Dscp 0x%x"\
			"Flags:Udp(%d) RED(%d),ESN(%d),DSCP(%d),DF(%d)\n",
		pCINode->ulIndex,
		pOutContainer->SPDParams.ucProto,
		pOutContainer->SPDParams.ucDscp,
		pOutContainer->SPDParams.bUdpEncap,
		pOutContainer->SPDParams.bRedSideFrag,
		pOutContainer->SPDParams.bESN,
		pOutContainer->SPDParams.bCopyDscp,
		pOutContainer->SPDParams.handleDf);

		print_SPDPolPPStats(pOutContainer->PPStats);

		seq_printf(f, "List SA IDs:");
		for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
			pOutSALinkNode != NULL;
			pOutSALinkNode = pOutSALinkNode->pNext) {
			seq_printf(f, " %d ", pOutSALinkNode->ulSAIndex);
			if (pOutSALinkNode->ulSAIndex % 10)
				seq_printf(f, "\n\t");
		}
		seq_printf(f, "\n");
	}
	if (!bVal)
		local_bh_enable();
	return 0;
}

static int display_secfp_proc_in_spd(struct seq_file *f,  void *v)
{
	int ulSAIndex;
	ASF_uint32_t ulVSGId = 0;
	ASF_uint32_t ulTunnelId = 0;
	struct SPDCILinkNode_s *pCINode;
	SPDInContainer_t *pInContainer = NULL;
	SPDInSPIValLinkNode_t *pSPILinkNode;

	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		seq_printf(f, "\nTunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	seq_printf(f, "\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pInContainer = (SPDInContainer_t *)(ptrIArray_getData(
					&(secfp_InDB),
					pCINode->ulIndex));
		if (!pInContainer)
			continue;
		seq_printf(f, "=========IN Policy==================\n");
		seq_printf(f, "Id=%d, Proto 0x%x, Dscp 0x%x "\
			"Flags:Udp(%d) ESN(%d),DSCP(%d),ECN(%d)\n",
		pCINode->ulIndex,
		pInContainer->SPDParams.ucProto,
		pInContainer->SPDParams.ucDscp,
		pInContainer->SPDParams.bUdpEncap,
		pInContainer->SPDParams.bESN,
		pInContainer->SPDParams.bCopyDscp,
		pInContainer->SPDParams.bCopyEcn);

		print_SPDPolPPStats(pInContainer->PPStats);

		seq_printf(f, "List IN SA -SPI Val:");

		for (pSPILinkNode = pInContainer->pSPIValList, ulSAIndex = 0;
			pSPILinkNode != NULL;
			pSPILinkNode = pSPILinkNode->pNext, ulSAIndex++) {

			seq_printf(f, "0x%x ", pSPILinkNode->ulSPIVal);
			if (ulSAIndex % 10)
				seq_printf(f, "\n");
		}
		seq_printf(f, "\n");
	}
	if (!bVal)
		local_bh_enable();
	return 0;
}

static void print_SAParams(struct seq_file *f,  SAParams_t *SAParams)
{

	if (!SAParams->tunnelInfo.bIPv4OrIPv6)
		seq_printf(f, "CId = %d TunnelInfo src = %d.%d.%d.%d, "\
			"dst = %d.%d.%d.%d SPI=0x%x", SAParams->ulCId,
			NIPQUAD(SAParams->tunnelInfo.addr.iphv4.saddr),
			NIPQUAD(SAParams->tunnelInfo.addr.iphv4.daddr),
			ASF_NTOHL(SAParams->ulSPI));
	else {
		int i;
		seq_printf(f, "CId = %d SPI=0x%x",
			SAParams->ulCId, ASF_NTOHL(SAParams->ulSPI));

		seq_printf(f, " TunnelInfo src = 0x");
		seq_printf(f, "%x:%x", (ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.saddr[0]) & 0xffff0000) >> 16,
					ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.saddr[0]) & 0x0000ffff);
		for (i = 1; i <= 3; i++)
			seq_printf(f, ":%x:%x", (ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.saddr[i]) & 0xffff0000) >> 16,
						ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.saddr[i]) & 0x0000ffff);

		seq_printf(f, ", dst = 0x");
		seq_printf(f, "%x:%x", (ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.daddr[0]) & 0xffff0000) >> 16,
						ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.daddr[0]) & 0x0000ffff);
		for (i = 1; i <= 3; i++)
			seq_printf(f, ":%x:%x", (ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.daddr[i]) & 0xffff0000) >> 16,
						ASF_NTOHL(SAParams->tunnelInfo.addr.iphv6.daddr[i]) & 0x0000ffff);
	}
	seq_printf(f, "\nProtocol = 0x%x, Dscp = 0x%x,"\
		"AuthAlgo =%s(%d)(Len=%d), CipherAlgo = %s(%d) (Len=%d) ",
		SAParams->ucProtocol, SAParams->ucDscp,
		algo_getname(1, SAParams->ucAuthAlgo),
		SAParams->ucAuthAlgo, SAParams->AuthKeyLen,
		algo_getname(0, SAParams->ucCipherAlgo),
		SAParams->ucCipherAlgo, SAParams->EncKeyLen);

	seq_printf(f, "AntiReplay = %d, UDPEncap(NAT-T) = %d\n",
		SAParams->bDoAntiReplayCheck,
		SAParams->bDoUDPEncapsulationForNATTraversal);

	seq_printf(f, "LifeKBytes Soft = %lu - Hard = %lu:",
		SAParams->softKbyteLimit,
		SAParams->hardKbyteLimit);

	seq_printf(f, "LifePacket Soft = %lu - Hard = %lu:",
		SAParams->softPacketLimit,
		SAParams->hardPacketLimit);
}

static int display_secfp_proc_out_sa(struct seq_file *f,  void *v)
{
	ASF_uint32_t ulVSGId = 0;
	ASF_uint32_t ulTunnelId = 0;
	struct SPDCILinkNode_s *pCINode;
	SPDOutContainer_t *pOutContainer = NULL;
	SPDOutSALinkNode_t *pOutSALinkNode;
	outSA_t *pOutSA = NULL;

	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		seq_printf(f, "Tunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	seq_printf(f, "\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d\n",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(
					&(secfp_OutDB),
					pCINode->ulIndex));
		if (!pOutContainer)
			continue;
		seq_printf(f, "=========OUT Policy==================\n");
		seq_printf(f, "Id=%d, Proto %d, Dscp %d "\
			"Flags:Udp(%d) RED(%d),ESN(%d),DSCP(%d),DF(%d)\n",
		pCINode->ulIndex,
		pOutContainer->SPDParams.ucProto,
		pOutContainer->SPDParams.ucDscp,
		pOutContainer->SPDParams.bUdpEncap,
		pOutContainer->SPDParams.bRedSideFrag,
		pOutContainer->SPDParams.bESN,
		pOutContainer->SPDParams.bCopyDscp,
		pOutContainer->SPDParams.handleDf);

		print_SPDPolPPStats(pOutContainer->PPStats);
		seq_printf(f, "--------------SA_LIST--------------------");
		for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
			pOutSALinkNode != NULL;
			pOutSALinkNode = pOutSALinkNode->pNext) {
			seq_printf(f, "\nSA-ID= %d ", pOutSALinkNode->ulSAIndex);
			pOutSA =
				(outSA_t *) ptrIArray_getData(&secFP_OutSATable,
					pOutSALinkNode->ulSAIndex);
			if (pOutSA) {
				ASFSAStats_t outParams = {0, 0};
				ASFIPSecGetSAQueryParams_t inParams;

				print_SAParams(f, &pOutSA->SAParams);

				inParams.ulVSGId = ulVSGId;
				inParams.ulTunnelId = ulTunnelId;
				inParams.ulSPDContainerIndex = pCINode->ulIndex;
				inParams.ulSPI = pOutSA->SAParams.ulSPI;
				inParams.gwAddr.bIPv4OrIPv6 = pOutSA->SAParams.tunnelInfo.bIPv4OrIPv6;
				if (pOutSA->SAParams.tunnelInfo.bIPv4OrIPv6)
					memcpy(inParams.gwAddr.ipv6addr, pOutSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
				else
					inParams.gwAddr.ipv4addr =
						pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr;

				inParams.ucProtocol =
						pOutSA->SAParams.ucProtocol;
				inParams.bDir = SECFP_OUT;
				ASFIPSecSAQueryStats(&inParams, &outParams);
				seq_printf(f, "Stats:ulBytes=%llu, ulPkts=%llu",
					outParams.ulBytes, outParams.ulPkts);

				seq_printf(f, "L2BlobLen = %d, Magic = %d\n",
					pOutSA->ulL2BlobLen,
				pOutSA->l2blobConfig.ulL2blobMagicNumber);
#ifdef ASF_QMAN_IPSEC
				seq_printf(f, "SecFQ=%d, RecvFQ=%d\n",
					pOutSA->ctx.SecFq->qman_fq.fqid,
					pOutSA->ctx.RecvFq->qman_fq.fqid);
#endif
			}
		}
		seq_printf(f, "\n");
	}
	if (!bVal)
		local_bh_enable();

	return 0;
}
static int display_secfp_proc_in_sa(struct seq_file *f, void *v)
{
	int ulSAIndex;
	ASF_uint32_t ulVSGId = 0;
	ASF_uint32_t ulTunnelId = 0;
	struct SPDCILinkNode_s *pCINode;
	SPDInContainer_t *pInContainer = NULL;
	SPDInSPIValLinkNode_t *pSPILinkNode;
	inSA_t  *pInSA =  NULL;
	unsigned int ulHashVal;

	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0) {
		seq_printf(f, "Tunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	seq_printf(f, "\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d\n",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pInContainer = (SPDInContainer_t *)(ptrIArray_getData(
					&(secfp_InDB),
					pCINode->ulIndex));
		if (!pInContainer)
			continue;

		seq_printf(f, "=========IN Policy==================\n");
		seq_printf(f, "Id=%d, Proto %d, Dscp %d "\
			"Flags:Udp(%d) ESN(%d),DSCP(%d),ECN(%d)\n",
		pCINode->ulIndex,
		pInContainer->SPDParams.ucProto,
		pInContainer->SPDParams.ucDscp,
		pInContainer->SPDParams.bUdpEncap,
		pInContainer->SPDParams.bESN,
		pInContainer->SPDParams.bCopyDscp,
		pInContainer->SPDParams.bCopyEcn);

		print_SPDPolPPStats(pInContainer->PPStats);
		seq_printf(f, "--------------SA_LIST--------------------");
		for (pSPILinkNode = pInContainer->pSPIValList, ulSAIndex = 0;
			pSPILinkNode != NULL;
			pSPILinkNode = pSPILinkNode->pNext, ulSAIndex++) {
			seq_printf(f, "\nSPI = 0x%x", pSPILinkNode->ulSPIVal);
			ulHashVal = secfp_compute_hash(pSPILinkNode->ulSPIVal);
			for (pInSA = secFP_SPIHashTable[ulHashVal].pHeadSA;
				pInSA != NULL; pInSA = pInSA->pNext) {
				ASFIPSecGetSAQueryParams_t inParams;
				ASFSAStats_t outParams = {0, 0};

				if (pSPILinkNode->ulSPIVal !=
					pInSA->SAParams.ulSPI)
					continue;


				seq_printf(f, "SpdContId =%d",
					pInSA->pSASPDMapNode->ulSPDInContainerIndex);
				print_SAParams(f, &pInSA->SAParams);

				inParams.ulVSGId = ulVSGId;
				inParams.ulTunnelId = ulTunnelId;
				inParams.ulSPDContainerIndex = pCINode->ulIndex;
				inParams.ulSPI = pInSA->SAParams.ulSPI;
				inParams.gwAddr.bIPv4OrIPv6 = pInSA->SAParams.tunnelInfo.bIPv4OrIPv6;
				if (pInSA->SAParams.tunnelInfo.bIPv4OrIPv6)
					memcpy(inParams.gwAddr.ipv6addr, pInSA->SAParams.tunnelInfo.addr.iphv6.daddr, 16);
				else
					inParams.gwAddr.ipv4addr =
						pInSA->SAParams.tunnelInfo.addr.iphv4.daddr;

				inParams.ucProtocol =
					pInSA->SAParams.ucProtocol;
				inParams.bDir = SECFP_IN;
				ASFIPSecSAQueryStats(&inParams, &outParams);
				seq_printf(f, "Stats:ulBytes=%llu,ulPkts= %llu",
					outParams.ulBytes, outParams.ulPkts);
#ifdef ASF_QMAN_IPSEC
				seq_printf(f, "SecFQ=%d, RecvFQ=%d\n",
					pInSA->ctx.SecFq->qman_fq.fqid,
					pInSA->ctx.RecvFq->qman_fq.fqid);
#endif
			}
		}
		seq_printf(f, "\n");
	}
	if (!bVal)
		local_bh_enable();
	return 0;
}
static int display_secfp_proc_sa_list(struct seq_file *f, void *v)
{
	ASF_uint32_t ulVSGId = 0;
	ASF_uint32_t ulTunnelId = 0;
	struct SPDCILinkNode_s *pCINode;
	SPDOutContainer_t *pOutContainer = NULL;
	SPDOutSALinkNode_t *pOutSALinkNode;
	outSA_t *pOutSA = NULL;
	SPDInContainer_t *pInContainer = NULL;
	SPDInSPIValLinkNode_t *pSPILinkNode;
	inSA_t *pInSA = NULL;
	int out_pol = 0, out_num = 0, in_num = 0;
	unsigned int ulHashVal, ulSAIndex;
	int bVal = in_softirq();
	if (!bVal)
		local_bh_disable();
	for (ulTunnelId = 0; ulTunnelId < ulMaxTunnels_g; ulTunnelId++) {
		seq_printf(f, "\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d",
			ulVSGId, ulTunnelId,
			secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);
		if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 0)
			continue;
		seq_printf(f, "=========OUT Table==================\n");
		pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
		for (; pCINode != NULL; pCINode = pCINode->pNext) {
			pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(
						&(secfp_OutDB),
						pCINode->ulIndex));
			if (!pOutContainer)
				continue;
			out_pol++;
			for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
				pOutSALinkNode != NULL;
				pOutSALinkNode = pOutSALinkNode->pNext) {
				pOutSA = (outSA_t *) ptrIArray_getData(
						&secFP_OutSATable,
						pOutSALinkNode->ulSAIndex);
				if (!pOutSA) {
					seq_printf(f, "\n Pol-ID=%d SAID= %d SA=NULL",
					pCINode->ulIndex, pOutSALinkNode->ulSAIndex);
					continue;
				}
				if (!pOutSA->SAParams.tunnelInfo.bIPv4OrIPv6)
					seq_printf(f,
					"\nPol-ID=%03d SA-ID=%03d CId:%03d SPI:0x%x\t"
					"src:0x%x,dst:0x%x Auth: %s Ciph: %s L2-blob=%d",
					pCINode->ulIndex,
					pOutSALinkNode->ulSAIndex,
					pOutSA->SAParams.ulCId,
					pOutSA->SAParams.ulSPI,
					pOutSA->SAParams.tunnelInfo.addr.iphv4.saddr,
					pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr,
					algo_getname(1, pOutSA->SAParams.ucAuthAlgo),
					algo_getname(0, pOutSA->SAParams.ucCipherAlgo),
					pOutSA->ulL2BlobLen);
				else
					seq_printf(f,
					"\nPol-ID=%03d SA-ID=%03d CId:%03d SPI:0x%x\t"
					"src:%x:%x:%x:%x, dst:%x:%x:%x:%x"
					"Auth: %s Ciph: %s L2-blob=%d",
					pCINode->ulIndex,
					pOutSALinkNode->ulSAIndex,
					pOutSA->SAParams.ulCId,
					pOutSA->SAParams.ulSPI,
					pOutSA->SAParams.tunnelInfo.addr.iphv6.saddr[0],
					pOutSA->SAParams.tunnelInfo.addr.iphv6.saddr[1],
					pOutSA->SAParams.tunnelInfo.addr.iphv6.saddr[2],
					pOutSA->SAParams.tunnelInfo.addr.iphv6.saddr[3],
					pOutSA->SAParams.tunnelInfo.addr.iphv6.daddr[0],
					pOutSA->SAParams.tunnelInfo.addr.iphv6.daddr[1],
					pOutSA->SAParams.tunnelInfo.addr.iphv6.daddr[2],
					pOutSA->SAParams.tunnelInfo.addr.iphv6.daddr[3],
					algo_getname(1, pOutSA->SAParams.ucAuthAlgo),
					algo_getname(0, pOutSA->SAParams.ucCipherAlgo),
					pOutSA->ulL2BlobLen);
				out_num++;
			}
		}
		seq_printf(f, "=========IN Table==================\n");
		pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
		for (; pCINode != NULL; pCINode = pCINode->pNext) {
			pInContainer = (SPDInContainer_t *)(ptrIArray_getData(
						&(secfp_InDB),
						pCINode->ulIndex));
			if (!pInContainer)
				continue;
			for (pSPILinkNode = pInContainer->pSPIValList,
				ulSAIndex = 0;
				pSPILinkNode != NULL;
				pSPILinkNode = pSPILinkNode->pNext, ulSAIndex++) {
				ulHashVal = secfp_compute_hash(pSPILinkNode->ulSPIVal);
				for (pInSA = secFP_SPIHashTable[ulHashVal].pHeadSA;
					pInSA != NULL; pInSA = pInSA->pNext) {
					if (!pInSA->SAParams.tunnelInfo.bIPv4OrIPv6)
						seq_printf(f,
						"\nPol-ID=%03d CId:%03d SPI:0x%x\t"
						"src:0x%x,dst:0x%x Auth:%s Ciph: %s",
						pInSA->pSASPDMapNode->ulSPDInContainerIndex,
						pInSA->SAParams.ulCId,
						pSPILinkNode->ulSPIVal,
						pInSA->SAParams.tunnelInfo.addr.iphv4.saddr,
						pInSA->SAParams.tunnelInfo.addr.iphv4.daddr,
						algo_getname(1, pInSA->SAParams.ucAuthAlgo),
						algo_getname(0, pInSA->SAParams.ucCipherAlgo));
					else
						seq_printf(f,
						"\nPol-ID=%03d CId:%03d SPI:0x%x\t"
						"src:%x:%x:%x:%x, dst:%x:%x:%x:%x"
						"Auth: %s Ciph: %s",
						pInSA->pSASPDMapNode->ulSPDInContainerIndex,
						pInSA->SAParams.ulCId,
						pSPILinkNode->ulSPIVal,
						pInSA->SAParams.tunnelInfo.addr.iphv6.saddr[0],
						pInSA->SAParams.tunnelInfo.addr.iphv6.saddr[1],
						pInSA->SAParams.tunnelInfo.addr.iphv6.saddr[2],
						pInSA->SAParams.tunnelInfo.addr.iphv6.saddr[3],
						pInSA->SAParams.tunnelInfo.addr.iphv6.daddr[0],
						pInSA->SAParams.tunnelInfo.addr.iphv6.daddr[1],
						pInSA->SAParams.tunnelInfo.addr.iphv6.daddr[2],
						pInSA->SAParams.tunnelInfo.addr.iphv6.daddr[3],
						algo_getname(1, pInSA->SAParams.ucAuthAlgo),
						algo_getname(0, pInSA->SAParams.ucCipherAlgo));
					in_num++;
				}
			}
		}
	}
	if (!bVal)
		local_bh_enable();
	seq_printf(f, "\n Total IPSEC OUT Policy =%d OUTSA =%d, INSA = %d\n",
		out_pol, out_num, in_num);
	return 0;
}
static void *int_seq_start(struct seq_file *f, loff_t *pos)
{
		return (*pos < 1) ? pos : NULL;
}

static void *int_seq_next(struct seq_file *f, void *v, loff_t *pos)
{
	return NULL;
}

static void int_seq_stop(struct seq_file *f, void *v)
{
		/* Nothing to do */
}

static const struct seq_operations int_seq_ops[] = {
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_secfp_proc_global_stats
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = reset_secfp_proc_global_stats
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_secfp_proc_global_errors
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_secfp_proc_out_spd
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_secfp_proc_in_spd
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_secfp_proc_out_sa
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_secfp_proc_in_sa
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_secfp_proc_sa_list
	}
};

static int ipsec_gbl_stats_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[0]);
}

static int ipsec_gbl_reset_stats_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[1]);
}

static int ipsec_gbl_error_stats_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[2]);
}

static int ipsec_gbl_out_spd_stats_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[3]);
}

static int ipsec_gbl_in_spd_stats_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[4]);
}

static int ipsec_gbl_out_sa_stats_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[5]);
}
static int ipsec_gbl_in_sa_stats_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[6]);
}
static int ipsec_gbl_sa_list_open(struct inode *inode, struct file *filp)
{
		return seq_open(filp, &int_seq_ops[7]);
}


static const struct file_operations proc_asfipsec_stats_operations[] = {
	{
		.open	   = ipsec_gbl_stats_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = ipsec_gbl_reset_stats_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = ipsec_gbl_error_stats_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = ipsec_gbl_out_spd_stats_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = ipsec_gbl_in_spd_stats_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = ipsec_gbl_out_sa_stats_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = ipsec_gbl_in_sa_stats_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = ipsec_gbl_sa_list_open,
		.read	   = seq_read,
		.llseek	 = seq_lseek,
		.release	= seq_release,
	}
};


int secfp_register_proc(void)
{

	/* register sysctl tree */
	secfp_proc_header = register_sysctl_table(secfp_proc_root_table);
	if (!secfp_proc_header)
		return -ENOMEM;

	/* register other under /proc/asfipsec */
	secfp_dir =  proc_mkdir("asfipsec", NULL);

	if (secfp_dir == NULL)
		return -ENOMEM;
	proc_create(SECFP_PROC_GLOBAL_STATS_NAME,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[0]);
	proc_create(SECFP_PROC_RESET_STATS_NAME,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[1]);
	proc_create(SECFP_PROC_GLOBAL_ERROR_NAME,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[2]);
	proc_create(SECFP_PROC_OUT_SPD,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[3]);
	proc_create(SECFP_PROC_IN_SPD,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[4]);
	proc_create(SECFP_PROC_OUT_SA,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[5]);
	proc_create(SECFP_PROC_IN_SA,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[6]);
	proc_create(SECFP_PROC_SA_LIST,
					0444, secfp_dir,
					&proc_asfipsec_stats_operations[7]);
	return 0;
}


int secfp_unregister_proc(void)
{
	if (secfp_proc_header)
		unregister_sysctl_table(secfp_proc_header);

	remove_proc_entry(SECFP_PROC_GLOBAL_STATS_NAME, secfp_dir);
	remove_proc_entry(SECFP_PROC_RESET_STATS_NAME, secfp_dir);
	remove_proc_entry(SECFP_PROC_GLOBAL_ERROR_NAME, secfp_dir);
	remove_proc_entry(SECFP_PROC_OUT_SPD, secfp_dir);
	remove_proc_entry(SECFP_PROC_IN_SPD, secfp_dir);
	remove_proc_entry(SECFP_PROC_OUT_SA, secfp_dir);
	remove_proc_entry(SECFP_PROC_IN_SA, secfp_dir);
	remove_proc_entry(SECFP_PROC_SA_LIST, secfp_dir);
	remove_proc_entry("asfipsec", NULL);

	return 0;
}
