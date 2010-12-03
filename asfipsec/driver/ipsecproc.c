/* Copyright (C) 2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	ipsecproc.c
 *
 * ASF IPSEC proc interface implementation
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the  GNU General Public License along
 * with this program; if not, write  to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */
/****************************************************************************
Revision History:
*  Version	Date		Author		Change Description
*  0.1		12/10/2010    Hemant Agrawal	Initial Development
***************************************************************************/

#include <linux/skbuff.h>
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asftmr.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"
#include "ipseccmn.h"

/*
 * Implement following proc
 *	/proc/asf/ipsec/flows
 *	/proc/asf/ipsec/stats
 */

enum {
	SECFP_PROC_COMMAND = 1,
	SECFP_MAX_TUNNELS,
	SECFP_MAX_VSGS,
	SECFP_MAX_SPD,
	SECFP_MAX_SA,
	SECFP_L2BLOB_REFRESH_NPKTS,
	SECFP_L2BLOB_REFRESH_INTERVAL
} ;

char secfp_proc_cmdbuf[1024] = "";

void secfp_exec_cmd_clear_stats(void)
{
	int cpu;

	printk(KERN_INFO"Clearing Global Stats & errors\n");

	for_each_online_cpu(cpu)
	{
		memset(&IPSecPPGlobalStats_g[cpu], 0,
			sizeof(AsfIPSecPPGlobalStats_t));
	}
	memset(&GlobalErrors, 0, sizeof(ASFIPSecGlobalErrorCounters_t));
}


void secfp_exec_cmd(void)
{
	char *cmd = secfp_proc_cmdbuf;

	printk(KERN_INFO"SECFP_EXEC_CMD: '%s'\n", secfp_proc_cmdbuf);
	/* fixed string commands for now .. enhance it to parse words */
	if (!strcasecmp(cmd, "clear stats"))
		secfp_exec_cmd_clear_stats();
}

static int proc_secfp_proc_exec_cmd(ctl_table *ctl, int write,
				void __user *buffer,
				size_t *lenp, loff_t *ppos)
{
	int ret;
	ret = proc_dostring(ctl, write, buffer, lenp, ppos);

	if (write) {
		secfp_exec_cmd();
		memset(secfp_proc_cmdbuf, 0, sizeof(secfp_proc_cmdbuf));
	}
	return ret;
}

static struct ctl_table secfp_proc_table[] = {
	{
		.ctl_name       = SECFP_PROC_COMMAND,
		.procname       = "command",
		.data	   = secfp_proc_cmdbuf,
		.maxlen	 = sizeof(secfp_proc_cmdbuf),
		.mode	   = 0644,
		.proc_handler   = proc_secfp_proc_exec_cmd,
		.strategy       = &sysctl_string
	} ,
	{
		.ctl_name       = SECFP_MAX_TUNNELS,
		.procname       = "ulMaxTunnels_g",
		.data	   = &ulMaxTunnels_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	} ,
	{
		.ctl_name       = SECFP_MAX_VSGS,
		.procname       = "ulMaxVSGs_g",
		.data	   = &ulMaxVSGs_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	} ,
	{
		.ctl_name       = SECFP_MAX_SPD,
		.procname       = "ulMaxSPDContainers_g",
		.data	   = &ulMaxSPDContainers_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	} ,
	{
		.ctl_name	= SECFP_MAX_SA,
		.procname	= "ulMaxSupportedIPSecSAs_g",
		.data	   = &ulMaxSupportedIPSecSAs_g,
		.maxlen  = sizeof(int),
		.mode	   = 0444,
		.proc_handler	= proc_dointvec,
		.strategy	= sysctl_intvec,
	} ,
	{
		.ctl_name       = SECFP_L2BLOB_REFRESH_NPKTS,
		.procname       = "ulL2BlobRefreshPktCnt_g",
		.data	   = &ulL2BlobRefreshPktCnt_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	} ,
	{
		.ctl_name       = SECFP_L2BLOB_REFRESH_INTERVAL,
		.procname       = "ulL2BlobRefreshTimeInSec_g",
		.data	   = &ulL2BlobRefreshTimeInSec_g,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
		.strategy       = sysctl_intvec,
	} ,
	{}
} ;

static struct ctl_table secfp_proc_root_table[] = {
	{
		.ctl_name       = 2222,
		.procname       = "asfipsec",
		.mode	   = 0555,
		.child	  = secfp_proc_table,
	} ,
	{}
} ;

static struct ctl_table_header *secfp_proc_header;


static struct proc_dir_entry *secfp_dir;
#define SECFP_PROC_GLOBAL_STATS_NAME	"global_stats"
#define SECFP_PROC_GLOBAL_ERROR_NAME	"global_error"
#define SECFP_PROC_OUT_SPD		"out_spd"
#define SECFP_PROC_IN_SPD		"in_spd"
#define SECFP_PROC_OUT_SA		"out_sa"
#define SECFP_PROC_IN_SA		"in_sa"

#define GSTATS_SUM(a) (total.ul##a += gstats->ul##a)
#define GSTATS_TOTAL(a) (unsigned long) total.ul##a
static int display_secfp_proc_global_stats(char *page, char **start,
					 off_t off, int count,
					 int *eof, void *data)
{
	AsfIPSecPPGlobalStats_t total;
	int cpu;

	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu)
	{
		AsfIPSecPPGlobalStats_t *gstats;
		gstats = &IPSecPPGlobalStats_g[cpu];
		GSTATS_SUM(TotInRecvPkts);
		GSTATS_SUM(TotInProcPkts);
		GSTATS_SUM(TotOutRecvPkts);
		GSTATS_SUM(TotOutProcPkts);
		GSTATS_SUM(TotInRecvSecPkts);
		GSTATS_SUM(TotInProcSecPkts);
		GSTATS_SUM(TotOutRecvPktsSecApply);
		GSTATS_SUM(TotOutPktsSecAppled);
	}

	printk(KERN_INFO"\n    InRcv %lu \t InProc %lu \tOutRcv %lu OutProc %lu\n",
		GSTATS_TOTAL(TotInRecvPkts), GSTATS_TOTAL(TotInProcPkts),
		GSTATS_TOTAL(TotOutRecvPkts), GSTATS_TOTAL(TotOutProcPkts));

	printk(KERN_INFO"\nSEC-InRcv %lu \t InProc %lu \tOutRcv %lu OutProc %lu\n",
		GSTATS_TOTAL(TotInRecvSecPkts),
		GSTATS_TOTAL(TotInProcSecPkts),
		GSTATS_TOTAL(TotOutRecvPktsSecApply),
		GSTATS_TOTAL(TotOutPktsSecAppled));

	return 0;
}

#define GLBERR_DISP(a) printk(KERN_INFO" " #a " = %u\n", total->ul##a)
static int display_secfp_proc_global_errors(char *page, char **start,
					off_t off, int count,
					int *eof, void *data)
{
	ASFIPSecGlobalErrorCounters_t *total;
	total = &GlobalErrors;

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

	return 0;
}

static void print_SPDPolPPStats(AsfSPDPolPPStats_t PPStats)
{
/*tbd - implement it */
	return;
}

static int display_secfp_proc_out_spd(char *page, char **start,
				off_t off, int count,
				int *eof, void *data)
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
		printk(KERN_INFO"Tunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	printk(KERN_INFO"\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d\n",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(
					&(secfp_OutDB),
					pCINode->ulIndex));
		if (!pOutContainer)
			continue;
		printk(KERN_INFO"=========OUT Policy==================\n");
		printk(KERN_INFO"Id=%d, Proto 0x%x, Dscp 0x%x"\
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

		printk(KERN_INFO"List SA IDs:");
		for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
			pOutSALinkNode != NULL;
			pOutSALinkNode = pOutSALinkNode->pNext) {
			printk(KERN_INFO" %d ", pOutSALinkNode->ulSAIndex);
			if (pOutSALinkNode->ulSAIndex % 10)
				printk(KERN_INFO"\n\t");
		}
		printk(KERN_INFO"\n");
	}
	if (!bVal)
		local_bh_enable();
	return 0;
}

static int display_secfp_proc_in_spd(char *page, char **start,
				off_t off, int count,
				int *eof, void *data)
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
		printk(KERN_INFO"\nTunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	printk(KERN_INFO"\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pInContainer = (SPDInContainer_t *)(ptrIArray_getData(
					&(secfp_InDB),
					pCINode->ulIndex));
		if (!pInContainer)
			continue;
		printk(KERN_INFO"=========IN Policy==================\n");
		printk(KERN_INFO"Id=%d, Proto 0x%x, Dscp 0x%x "\
			"Flags:Udp(%d) ESN(%d),DSCP(%d),ECN(%d)\n",
		pCINode->ulIndex,
		pInContainer->SPDParams.ucProto,
		pInContainer->SPDParams.ucDscp,
		pInContainer->SPDParams.bUdpEncap,
		pInContainer->SPDParams.bESN,
		pInContainer->SPDParams.bCopyDscp,
		pInContainer->SPDParams.bCopyEcn);

		print_SPDPolPPStats(pInContainer->PPStats);

		printk(KERN_INFO"List IN SA -SPI Val:");

		for (pSPILinkNode = pInContainer->pSPIValList, ulSAIndex = 0;
			pSPILinkNode != NULL;
			pSPILinkNode = pSPILinkNode->pNext, ulSAIndex++) {

			printk(KERN_INFO"0x%x ", pSPILinkNode->ulSPIVal);
			if (ulSAIndex % 10)
				printk(KERN_INFO"\n");
		}
		printk(KERN_INFO"\n");
	}
	if (!bVal)
		local_bh_enable();
	return 0;
}

static void print_SAParams(SAParams_t *SAParams)
{
	printk(KERN_INFO"CId = %d Tunnel Info saddr = 0x%x, daddr = 0x%x SPI=0x%x",
		SAParams->ulCId,
		SAParams->tunnelInfo.addr.iphv4.saddr,
		SAParams->tunnelInfo.addr.iphv4.daddr,
		SAParams->ulSPI);

	printk(KERN_INFO"\nProtocol = 0x%x, Dscp = 0x%x,"\
		"AuthAlgo =%d(Len=%d), CipherAlgo = %d (Len=%d) ",
		SAParams->ucProtocol, SAParams->ucDscp,
		SAParams->ucAuthAlgo, SAParams->AuthKeyLen,
		SAParams->ucCipherAlgo, SAParams->EncKeyLen);

	printk(KERN_INFO"AntiReplay = %d, UDPEncap(NAT-T) = %d\n",
		SAParams->bDoAntiReplayCheck,
		SAParams->bDoUDPEncapsulationForNATTraversal);

}

static int display_secfp_proc_out_sa(char *page, char **start,
				off_t off, int count,
				int *eof, void *data)
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
		printk(KERN_INFO"Tunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	printk(KERN_INFO"\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d\n",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIOutList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pOutContainer = (SPDOutContainer_t *)(ptrIArray_getData(
					&(secfp_OutDB),
					pCINode->ulIndex));
		if (!pOutContainer)
			continue;
		printk(KERN_INFO"=========OUT Policy==================\n");
		printk(KERN_INFO"Id=%d, Proto %d, Dscp %d "\
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
		printk(KERN_INFO"--------------SA_LIST--------------------");
		for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
			pOutSALinkNode != NULL;
			pOutSALinkNode = pOutSALinkNode->pNext) {
			printk(KERN_INFO"\nSA-ID= %d ", pOutSALinkNode->ulSAIndex);
			pOutSA =
				(outSA_t *) ptrIArray_getData(&secFP_OutSATable,
					pOutSALinkNode->ulSAIndex);
			if (pOutSA)
				print_SAParams(&pOutSA->SAParams);
		}
		printk(KERN_INFO"\n");
	}
	if (!bVal)
		local_bh_enable();

	return 0;
}
static int display_secfp_proc_in_sa(char *page, char **start,
				off_t off, int count,
				int *eof, void *data)
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
		printk(KERN_INFO"Tunnel Interface is not in use"\
			".TunnelId=%u, VSGId=%u\n",
			ulTunnelId, ulVSGId);
		if (!bVal)
			local_bh_enable();
		return ASF_IPSEC_TUNNEL_NOT_FOUND;
	}
	printk(KERN_INFO"\nVSGID= %d TUNNELID= %d, MAGIC NUM = %d\n",
		ulVSGId, ulTunnelId,
		secFP_TunnelIfaces[ulVSGId][ulTunnelId].ulTunnelMagicNumber);

	pCINode = secFP_TunnelIfaces[ulVSGId][ulTunnelId].pSPDCIInList;
	for (; pCINode != NULL; pCINode = pCINode->pNext) {

		pInContainer = (SPDInContainer_t *)(ptrIArray_getData(
					&(secfp_InDB),
					pCINode->ulIndex));
		if (!pInContainer)
			continue;

		printk(KERN_INFO"=========IN Policy==================\n");
		printk(KERN_INFO"Id=%d, Proto %d, Dscp %d "\
			"Flags:Udp(%d) ESN(%d),DSCP(%d),ECN(%d)\n",
		pCINode->ulIndex,
		pInContainer->SPDParams.ucProto,
		pInContainer->SPDParams.ucDscp,
		pInContainer->SPDParams.bUdpEncap,
		pInContainer->SPDParams.bESN,
		pInContainer->SPDParams.bCopyDscp,
		pInContainer->SPDParams.bCopyEcn);

		print_SPDPolPPStats(pInContainer->PPStats);
		printk(KERN_INFO"--------------SA_LIST--------------------");
		for (pSPILinkNode = pInContainer->pSPIValList, ulSAIndex = 0;
			pSPILinkNode != NULL;
			pSPILinkNode = pSPILinkNode->pNext, ulSAIndex++) {
			printk(KERN_INFO"\nSPI = 0x%x", pSPILinkNode->ulSPIVal);
			ulHashVal = secfp_compute_hash(pSPILinkNode->ulSPIVal);
			for (pInSA = secFP_SPIHashTable[ulHashVal].pHeadSA;
				pInSA != NULL; pInSA = pInSA->pNext) {
				printk(KERN_INFO"SpdContId =%d",
					pInSA->ulSPDInContainerIndex);
				print_SAParams(&pInSA->SAParams);
			}
		}
		printk(KERN_INFO"\n");
	}
	if (!bVal)
		local_bh_enable();
	return 0;

}

int secfp_register_proc(void)
{
	struct proc_dir_entry   *proc_file;

	/* register sysctl tree */
	secfp_proc_header = register_sysctl_table(secfp_proc_root_table);
	if (!secfp_proc_header)
		return -ENOMEM;

	/* register other under /proc/asfipsec */
	secfp_dir =  proc_mkdir("asfipsec", NULL);

	if (secfp_dir == NULL)
		return -ENOMEM;

	proc_file = create_proc_read_entry(
					SECFP_PROC_GLOBAL_STATS_NAME,
					0444, secfp_dir,
					display_secfp_proc_global_stats,
					NULL);

	proc_file = create_proc_read_entry(
					SECFP_PROC_GLOBAL_ERROR_NAME,
					0444, secfp_dir,
					display_secfp_proc_global_errors,
					NULL);

	proc_file = create_proc_read_entry(
					SECFP_PROC_OUT_SPD,
					0444, secfp_dir,
					display_secfp_proc_out_spd,
					NULL);

	proc_file = create_proc_read_entry(
					SECFP_PROC_IN_SPD,
					0444, secfp_dir,
					display_secfp_proc_in_spd,
					NULL);

	proc_file = create_proc_read_entry(
					SECFP_PROC_OUT_SA,
					0444, secfp_dir,
					display_secfp_proc_out_sa,
					NULL);

	proc_file = create_proc_read_entry(
					SECFP_PROC_IN_SA,
					0444, secfp_dir,
					display_secfp_proc_in_sa,
					NULL);

	return 0;
}


int secfp_unregister_proc(void)
{
	if (secfp_proc_header)
		unregister_sysctl_table(secfp_proc_header);

	remove_proc_entry(SECFP_PROC_GLOBAL_STATS_NAME, secfp_dir);
	remove_proc_entry(SECFP_PROC_GLOBAL_ERROR_NAME, secfp_dir);
	remove_proc_entry(SECFP_PROC_OUT_SPD, secfp_dir);
	remove_proc_entry(SECFP_PROC_IN_SPD, secfp_dir);
	remove_proc_entry(SECFP_PROC_OUT_SA, secfp_dir);
	remove_proc_entry(SECFP_PROC_IN_SA, secfp_dir);
	remove_proc_entry("asfipsec", NULL);

	return 0;
}
