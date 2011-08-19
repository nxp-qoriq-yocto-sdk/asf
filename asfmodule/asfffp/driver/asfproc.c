/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfproc.c
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/sysctl.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif

#include <linux/version.h>
#include <linux/proc_fs.h>
#include "gplcode.h"
#include "asf.h"
#include "asfcmn.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfpvt.h"
#include "asftcp.h"

/*
 * Implement following proc
 *	/proc/asf/flows
 *	/proc/asf/stats
 */
enum {
	ASF_PROC_COMMAND = 1,
	ASF_ENABLE,
	ASF_AUTO_MODE,
	ASF_FFP_MAX_FLOWS,
	ASF_FFP_MAX_VSGS,
	ASF_FFP_HASH_BUCKETS,
	ASF_L2BLOB_REFRESH_NPKTS,
	ASF_L2BLOB_REFRESH_INTERVAL,
	ASF_FFP_DEBUG_SKIP_FIRST,
	ASF_FFP_DEBUG_SHOW_COUNT
} ;

static int ffp_debug_show_index;
static int ffp_debug_show_count = 50;

extern void asf_register_devfp(void);
extern void asf_unregister_devfp(void);
extern void asf_ffp_cleanup_all_flows(void);


char asf_proc_cmdbuf[1024] = "";

extern ffp_bucket_t *ffp_flow_table;
extern ASFFFPGlobalStats_t *asf_gstats;
#ifdef ASF_FFP_XTRA_STATS
extern ASFFFPXtraGlobalStats_t *asf_xgstats;
#endif
extern ASFFFPVsgStats_t *asf_vsg_stats; /* per cpu vsg stats */
extern int asf_max_vsgs;
extern int asf_enable;
extern int asf_l2blob_refresh_npkts;
extern int asf_l2blob_refresh_interval;


void asf_exec_cmd_clear_stats(void)
{
	int vsg, cpu;

	printk("Clearing Global%s Stats\n",
#ifdef ASF_FFP_XTRA_STATS
	       " and XtraGlobal"
#else
	       ""
#endif
	    );

	for_each_online_cpu(cpu)
	{
		ASFFFPGlobalStats_t *gstats;
#ifdef ASF_FFP_XTRA_STATS
		ASFFFPXtraGlobalStats_t *xgstats;
#endif
		gstats = asfPerCpuPtr(asf_gstats, cpu);
		memset(gstats, 0, sizeof(*gstats));

#ifdef ASF_FFP_XTRA_STATS
		xgstats = asfPerCpuPtr(asf_xgstats, cpu);
		memset(xgstats, 0, sizeof(*xgstats));
#endif
	}

	printk("Clearing VSG Stats\n");
	for (vsg = 0 ; vsg < asf_max_vsgs ; vsg++) {
		for_each_online_cpu(cpu)
		{
			ASFFFPVsgStats_t *vstats;
			vstats = asfPerCpuPtr(asf_vsg_stats, cpu)+vsg;
			memset(vstats, 0, sizeof(*vstats));
		}
	}

}


void asf_exec_cmd(void)
{
	char *cmd = asf_proc_cmdbuf;

	printk("ASF_EXEC_CMD: '%s'\n", asf_proc_cmdbuf);
	/* fixed string commands for now .. enhance it to parse words */
	if (!strcasecmp(cmd, "clear stats")) {
		asf_exec_cmd_clear_stats();
	}
}

static int proc_asf_proc_exec_cmd(ctl_table *ctl, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
				  struct file *filp,
#endif
				  void __user *buffer,
				  size_t *lenp, loff_t *ppos)
{
	int ret;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
	ret = proc_dostring(ctl, write, filp, buffer, lenp, ppos);
#else
	ret = proc_dostring(ctl, write, buffer, lenp, ppos);
#endif

	if (write) {
		asf_exec_cmd();
		memset(asf_proc_cmdbuf, 0, sizeof(asf_proc_cmdbuf));
	}
	return ret;
}

static int proc_asf_enable(ctl_table *ctl, int write,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
			   struct file *filp,
#endif
			   void __user *buffer,
			   size_t *lenp, loff_t *ppos)
{
	int old_state = asf_enable, ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
	ret = proc_dointvec(ctl, write, filp, buffer, lenp, ppos);
#else
	ret = proc_dointvec(ctl, write, buffer, lenp, ppos);
#endif

	/* reset the value to 0 or 1 */
	if (asf_enable != 0)
		asf_enable = 1;

	if (asf_enable != old_state) {
		if (asf_enable) {
			printk("ASF State changed from Disable to Enable\n");
			asf_register_devfp();
		} else {
			asf_unregister_devfp();
			printk("ASF State changed from Enable to Disable (cleanup flows)\n");
			asf_ffp_cleanup_all_flows();
		}
	}

	return ret;
}

static struct ctl_table asf_proc_table[] = {
	{
		.procname       = "command",
		.data	   = asf_proc_cmdbuf,
		.maxlen	 = sizeof(asf_proc_cmdbuf),
		.mode	   = 0644,
		.proc_handler   = proc_asf_proc_exec_cmd,
	} ,
	{
		.procname       = "enable",
		.data	   = &asf_enable,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_asf_enable,
	} ,
	{
		.procname       = "ffp_max_flows",
		.data	   = &ffp_max_flows,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_max_vsgs",
		.data	   = &asf_max_vsgs,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_hash_buckets",
		.data	   = &ffp_hash_buckets,
		.maxlen	 = sizeof(int),
		.mode	   = 0444,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "l2blob_refresh_npkts",
		.data	   = &asf_l2blob_refresh_npkts,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "l2blob_refresh_interval",
		.data	   = &asf_l2blob_refresh_interval,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_debug_show_index",
		.data	   = &ffp_debug_show_index,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{
		.procname       = "ffp_debug_show_count",
		.data	   = &ffp_debug_show_count,
		.maxlen	 = sizeof(int),
		.mode	   = 0644,
		.proc_handler   = proc_dointvec,
	} ,
	{}
} ;

static struct ctl_table asf_proc_root_table[] = {
	{
		.procname       = "asf",
		.mode	   = 0555,
		.child	  = asf_proc_table,
	} ,
	{}
} ;

/* Will be used by FWD module */
struct ctl_table_header *asf_proc_header;
EXPORT_SYMBOL(asf_proc_header);
struct proc_dir_entry *asf_dir;
EXPORT_SYMBOL(asf_dir);

#define ASF_PROC_GLOBAL_STATS_NAME	"global_stats"
#ifdef ASF_FFP_XTRA_STATS
#define ASF_PROC_XTRA_GLOBAL_STATS_NAME	"xglobal_stats"
#define ASF_PROC_XTRA_FLOW_STATS_NAME	"xflow_stats"
#endif
#define ASF_PROC_VSG_STATS_NAME		"vsg_stats"
#define ASF_PROC_IFACE_MAPS		"ifaces"
#define ASF_PROC_FLOW_STATS_NAME	"flow_stats"
#define ASF_PROC_FLOW_DEBUG_NAME	"flow_debug"

#define GSTATS_SUM(a) (total.ul##a += gstats->ul##a)
#define GSTATS_TOTAL(a) (unsigned long) total.ul##a
static int display_asf_proc_global_stats(char *page, char **start,
					 off_t off, int count,
					 int *eof, void *data)
{
	ASFFFPGlobalStats_t total;
	int cpu;

	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu)
	{
		ASFFFPGlobalStats_t *gstats;
		gstats = asfPerCpuPtr(asf_gstats, cpu);
		GSTATS_SUM(InPkts);
		GSTATS_SUM(InPktFlowMatches);
		GSTATS_SUM(OutPkts);
		GSTATS_SUM(OutBytes);
		GSTATS_SUM(FlowAllocs);
		GSTATS_SUM(FlowFrees);
		GSTATS_SUM(FlowAllocFailures);
		GSTATS_SUM(FlowFreeFailures);
		GSTATS_SUM(ErrCsum);
		GSTATS_SUM(ErrIpHdr);
		GSTATS_SUM(ErrIpProtoHdr);
		GSTATS_SUM(ErrAllocFailures);
		GSTATS_SUM(MiscFailures);
		GSTATS_SUM(ErrTTL);
		GSTATS_SUM(PktsToFNP);
	}

	printk("IN %lu IN-MATCH %lu OUT %lu OUT-BYTES %lu\n",
	       GSTATS_TOTAL(InPkts), GSTATS_TOTAL(InPktFlowMatches), GSTATS_TOTAL(OutPkts), GSTATS_TOTAL(OutBytes));

	printk("FLOW: ALLOC %lu FREE %lu ALLOC-FAIL %lu FREE-FAIL %lu\n",
	       GSTATS_TOTAL(FlowAllocs), GSTATS_TOTAL(FlowFrees),
	       GSTATS_TOTAL(FlowAllocFailures), GSTATS_TOTAL(FlowFreeFailures));

	printk("ERR: CSUM %lu IPH %lu IPPH %lu AllocFail %lu MiscFail %lu TTL %lu\n",
	       GSTATS_TOTAL(ErrCsum), GSTATS_TOTAL(ErrIpHdr),
	       GSTATS_TOTAL(ErrIpProtoHdr), GSTATS_TOTAL(ErrAllocFailures),
	       GSTATS_TOTAL(MiscFailures), GSTATS_TOTAL(ErrTTL));

	printk("MISC: TO-FNP %lu\n", GSTATS_TOTAL(PktsToFNP));

	return 0;
}

#ifdef ASF_FFP_XTRA_STATS
#define XGSTATS_SUM(a) (total.ul##a += xgstats->ul##a)
#define XGSTATS_TOTAL(a) total.ul##a
#define XGSTATS_DISP(a) printk(" " #a " = %lu\n", total.ul##a)
static int display_asf_proc_xtra_global_stats(char *page, char **start,
					      off_t off, int count,
					      int *eof, void *data)
{
	ASFFFPXtraGlobalStats_t total;
	int cpu;

	memset(&total, 0, sizeof(total));

	for_each_online_cpu(cpu)
	{
		ASFFFPXtraGlobalStats_t *xgstats;
		xgstats = asfPerCpuPtr(asf_xgstats, cpu);

		XGSTATS_SUM(BridgePkts);
		XGSTATS_SUM(InvalidBridgeDev);
		XGSTATS_SUM(VlanPkts);
		XGSTATS_SUM(InvalidVlanDev);
		XGSTATS_SUM(PPPoEPkts);
		XGSTATS_SUM(PPPoEUnkPkts);
		XGSTATS_SUM(InvalidPPPoEDev);
		XGSTATS_SUM(NonIpPkts);
		XGSTATS_SUM(NonTcpUdpPkts);
		XGSTATS_SUM(VsgSzoneUnk);
		XGSTATS_SUM(InvalidCsum);
		XGSTATS_SUM(IpOptPkts);
		XGSTATS_SUM(LocalCsumVerify);
		XGSTATS_SUM(LocalBadCsum);
		XGSTATS_SUM(UdpBlankCsum);
		XGSTATS_SUM(IpOptProcFail);
		XGSTATS_SUM(IpFragPkts);
		XGSTATS_SUM(bDropPkts);
		XGSTATS_SUM(Condition1);
		XGSTATS_SUM(Condition2);
		XGSTATS_SUM(UdpPkts);
		XGSTATS_SUM(TcpPkts);
		XGSTATS_SUM(TcpHdrLenErr);
		XGSTATS_SUM(TcpTimeStampErr);
		XGSTATS_SUM(TcpOutOfSequenceErr);
		XGSTATS_SUM(TcpProcessErr);
		XGSTATS_SUM(NatPkts);
		XGSTATS_SUM(BlankL2blobInd);
		XGSTATS_SUM(FragAndXmit);
		XGSTATS_SUM(NormalXmit);
		XGSTATS_SUM(L2hdrAdjust);
		XGSTATS_SUM(DevXmitErr);
		XGSTATS_SUM(FlowEndInd);
		XGSTATS_SUM(PktCtxInacRefreshInd);
		XGSTATS_SUM(PktCtxL2blobInd);
		XGSTATS_SUM(NetIfQStopped);
		XGSTATS_SUM(CreateFlowsCmd);
		XGSTATS_SUM(CreateFlowsCmdVsgErr);
		XGSTATS_SUM(CreateFlowsCmdErrDown);
		XGSTATS_SUM(CreateFlowsCmdErrDown1);
		XGSTATS_SUM(CreateFlowsCmdErrDown2);
		XGSTATS_SUM(CreateFlowsCmdFailures);
		XGSTATS_SUM(DeleteFlowsCmd);
		XGSTATS_SUM(DeleteFlowsCmdFailures);
		XGSTATS_SUM(ModifyFlowsCmd);
		XGSTATS_SUM(ModifyFlowsCmdFailures);
		XGSTATS_SUM(BlobTmrCalls);
		XGSTATS_SUM(TmrCtxL2blobInd);
		XGSTATS_SUM(BlobTmrCtxBadFlow);
		XGSTATS_SUM(InacTmrCalls);
		XGSTATS_SUM(TmrCtxInacInd);
		XGSTATS_SUM(InacTmrCtxBadFlow1);
		XGSTATS_SUM(InacTmrCtxBadFlow2);
		XGSTATS_SUM(InacTmrCtxAutoFlowDel);
		XGSTATS_SUM(PktCmdTxInPkts);
		XGSTATS_SUM(PktCmdTxBlobRefresh);
		XGSTATS_SUM(PktCmdTxAutoFlowCreate);
		XGSTATS_SUM(PktCmdTxAutoFlowBlobRefresh);
		XGSTATS_SUM(PktCmdTxLogicalDevErr);
		XGSTATS_SUM(PktCmdTxNonIpErr);
		XGSTATS_SUM(PktCmdTxDummyPkt);
		XGSTATS_SUM(PktCmdTxValidPkt);
		XGSTATS_SUM(PktCmdTxFlowFound);
		XGSTATS_SUM(PktCmdTxBlobInitialUpdates);
		XGSTATS_SUM(PktCmdTxBlobTmrErr);
		XGSTATS_SUM(PktCmdTxInacTmrErr);
		XGSTATS_SUM(PktCmdTxVlanTag);
		XGSTATS_SUM(PktCmdTxSkbFrees);
		XGSTATS_SUM(PktCmdTxInvalidFlowErr);
		XGSTATS_SUM(PktCtxAutoFlowDel);
		XGSTATS_SUM(AutoFlowBlobRefreshSentUp);
		XGSTATS_SUM(AutoFlowCreateSentUp);
		XGSTATS_SUM(PktCmdTxHdrSizeErr);
		XGSTATS_SUM(PktCmdBlobSkbFrees);
		XGSTATS_SUM(PktCmdTxAutoDelFlows);
		XGSTATS_SUM(PktCmdTxAutoFlowCreateErr);
	}
	XGSTATS_DISP(BridgePkts);
	XGSTATS_DISP(InvalidBridgeDev);
	XGSTATS_DISP(VlanPkts);
	XGSTATS_DISP(InvalidVlanDev);
	XGSTATS_DISP(PPPoEPkts);
	XGSTATS_DISP(PPPoEUnkPkts);
	XGSTATS_DISP(InvalidPPPoEDev);
	XGSTATS_DISP(NonIpPkts);
	XGSTATS_DISP(NonTcpUdpPkts);
	XGSTATS_DISP(VsgSzoneUnk);
	XGSTATS_DISP(InvalidCsum);
	XGSTATS_DISP(IpOptPkts);
	XGSTATS_DISP(LocalCsumVerify);
	XGSTATS_DISP(LocalBadCsum);
	XGSTATS_DISP(UdpBlankCsum);
	XGSTATS_DISP(IpOptProcFail);
	XGSTATS_DISP(IpFragPkts);
	XGSTATS_DISP(bDropPkts);
	XGSTATS_DISP(Condition1);
	XGSTATS_DISP(Condition2);
	XGSTATS_DISP(UdpPkts);
	XGSTATS_DISP(TcpPkts);
	XGSTATS_DISP(TcpHdrLenErr);
	XGSTATS_DISP(TcpTimeStampErr);
	XGSTATS_DISP(TcpOutOfSequenceErr);
	XGSTATS_DISP(TcpProcessErr);
	XGSTATS_DISP(NatPkts);
	XGSTATS_DISP(BlankL2blobInd);
	XGSTATS_DISP(FragAndXmit);
	XGSTATS_DISP(NormalXmit);
	XGSTATS_DISP(L2hdrAdjust);
	XGSTATS_DISP(DevXmitErr);
	XGSTATS_DISP(FlowEndInd);
	XGSTATS_DISP(PktCtxInacRefreshInd);
	XGSTATS_DISP(PktCtxL2blobInd);
	XGSTATS_DISP(NetIfQStopped);
	XGSTATS_DISP(CreateFlowsCmd);
	XGSTATS_DISP(CreateFlowsCmdVsgErr);
	XGSTATS_DISP(CreateFlowsCmdErrDown);
	XGSTATS_DISP(CreateFlowsCmdErrDown1);
	XGSTATS_DISP(CreateFlowsCmdErrDown2);
	XGSTATS_DISP(CreateFlowsCmdFailures);
	XGSTATS_DISP(DeleteFlowsCmd);
	XGSTATS_DISP(DeleteFlowsCmdFailures);
	XGSTATS_DISP(ModifyFlowsCmd);
	XGSTATS_DISP(ModifyFlowsCmdFailures);
	XGSTATS_DISP(BlobTmrCalls);
	XGSTATS_DISP(TmrCtxL2blobInd);
	XGSTATS_DISP(BlobTmrCtxBadFlow);
	XGSTATS_DISP(InacTmrCalls);
	XGSTATS_DISP(TmrCtxInacInd);
	XGSTATS_DISP(InacTmrCtxBadFlow1);
	XGSTATS_DISP(InacTmrCtxBadFlow2);
	XGSTATS_DISP(InacTmrCtxAutoFlowDel);
	XGSTATS_DISP(PktCmdTxInPkts);
	XGSTATS_DISP(PktCmdTxBlobRefresh);
	XGSTATS_DISP(PktCmdTxAutoFlowCreate);
	XGSTATS_DISP(PktCmdTxAutoFlowBlobRefresh);
	XGSTATS_DISP(PktCmdTxLogicalDevErr);
	XGSTATS_DISP(PktCmdTxNonIpErr);
	XGSTATS_DISP(PktCmdTxDummyPkt);
	XGSTATS_DISP(PktCmdTxValidPkt);
	XGSTATS_DISP(PktCmdTxFlowFound);
	XGSTATS_DISP(PktCmdTxBlobInitialUpdates);
	XGSTATS_DISP(PktCmdTxBlobTmrErr);
	XGSTATS_DISP(PktCmdTxInacTmrErr);
	XGSTATS_DISP(PktCmdTxVlanTag);
	XGSTATS_DISP(PktCmdTxSkbFrees);
	XGSTATS_DISP(PktCmdTxInvalidFlowErr);
	XGSTATS_DISP(PktCtxAutoFlowDel);
	XGSTATS_DISP(AutoFlowBlobRefreshSentUp);
	XGSTATS_DISP(AutoFlowCreateSentUp);
	XGSTATS_DISP(PktCmdTxHdrSizeErr);
	XGSTATS_DISP(PktCmdBlobSkbFrees);
	XGSTATS_DISP(PktCmdTxAutoDelFlows);
	XGSTATS_DISP(PktCmdTxAutoFlowCreateErr);

	return 0;
}
#endif


#define VSTATS_SUM(a) (total.ul##a += vstats->ul##a)
#define VSTATS_TOTAL(a) (unsigned long)total.ul##a
static int display_asf_proc_vsg_stats(char *page, char **start,
				      off_t off, int count,
				      int *eof, void *data)
{
	ASFFFPVsgStats_t total;
	int cpu, vsg;

	local_bh_disable();
	for (vsg = 0; vsg < asf_max_vsgs; vsg++) {
		memset(&total, 0, sizeof(total));
		for_each_online_cpu(cpu)
		{
			ASFFFPVsgStats_t *vstats;
			vstats = asfPerCpuPtr(asf_vsg_stats, cpu)+vsg;
			VSTATS_SUM(InPkts);
			VSTATS_SUM(InPktFlowMatches);
			VSTATS_SUM(OutPkts);
			VSTATS_SUM(OutBytes);
		}
		if (VSTATS_TOTAL(InPkts)) {
			printk("%d: IN %lu FLOW_MATCHES %lu OUT %lu OUT-BYTES %lu\n", vsg,
			       VSTATS_TOTAL(InPkts),
			       VSTATS_TOTAL(InPktFlowMatches),
			       VSTATS_TOTAL(OutPkts),
			       VSTATS_TOTAL(OutBytes));
		}
	}
	local_bh_enable();
	return 0;
}


extern int asf_max_ifaces;
extern ASFNetDevEntry_t **asf_ifaces; /* array of strcuture pointers indexed by common interface id */
static inline char *__asf_get_dev_type(ASF_uint32_t ulDevType)
{
	if (ulDevType == ASF_IFACE_TYPE_ETHER)
		return "ETHER";
	else if (ulDevType == ASF_IFACE_TYPE_BRIDGE)
		return "BRIDGE";
	else if (ulDevType == ASF_IFACE_TYPE_VLAN)
		return "VLAN";
	else if (ulDevType == ASF_IFACE_TYPE_PPPOE)
		return "PPPOE";
	else
		return "INVALID";
}
static int display_asf_proc_iface_maps(char *page, char **start,
				       off_t off, int count,
				       int *eof, void *data)
{
	int i;
	ASFNetDevEntry_t *dev;

	printk("CII\tNAME\tTYPE\tVSG\tZONE\tID\tPAR-CII\tBR-CII\n");
	for (i = 0; i < asf_max_ifaces; i++) {
		dev = asf_ifaces[i];
		if (!dev)
			continue;
		printk("%u\t%s\t%s\t%d\t%d\t0x%x\t%u\t%u\n",
		       dev->ulCommonInterfaceId,
		       dev->ndev ? dev->ndev->name : "-",
		       __asf_get_dev_type(dev->ulDevType),
		       (dev->ulVSGId != ASF_INVALID_VSG) ? dev->ulVSGId : -1,
		       (dev->ulZoneId != ASF_INVALID_ZONE) ? dev->ulZoneId : -1,
		       dev->usId,
		       dev->pParentDev ? dev->pParentDev->ulCommonInterfaceId : 0,
		       dev->pBridgeDev ? dev->pBridgeDev->ulCommonInterfaceId : 0);
	}
	return 0;
}


void print_bigbuf(char *s)
{
	/* printk appears to truncate the buffer if > 2k.
	 * so print 1 line at a time
	 */
	char *c;

	while (*s && (c = strchr(s, '\n'))) {
		*c = '\0';
		printk("%s\n", s);
		s = c+1;
	}
	printk(s);
}


static int display_asf_proc_flow_stats(char *page, char **start,
				       off_t off, int count,
				       int *eof, void *data)
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	char	    *buf, *p;
	unsigned int    min_entr = ~1, max_entr = 0, max_entr_idx = ~1, cur_entr = 0, empty_entr = 0;
	unsigned int    empty_l2blob = 0;
	unsigned int    disp_cnt = 0, display = 0;

	buf = (char *)  kmalloc(300*(ffp_debug_show_count+2), GFP_KERNEL);
	if (!buf) {
		printk("ffp_debug_show_count is too large : couldn't allocate memory!\n");
		return 0;
	}

	printk("HIDX {ID}\tDST\tV/Z/P\tSIP:SPORT\tDIP:DPORT\tSNIP:SNPORT\tDNIP:DNPORT\tPKTS\n");
	p = buf;
	*p = '\0';
	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_flow_table[i];

		if (head == head->pNext)
			empty_entr++;

		if (i == ffp_debug_show_index)
			display = 1;

		cur_entr = 0;
		spin_lock_bh(&ffp_flow_table[i].lock);
		for (flow = head->pNext; flow != head; flow = flow->pNext) {

			total++;
			cur_entr++;
			if (flow->l2blob_len == 0)
				empty_l2blob++;
			if (flow == flow->pNext) {
				printk("possible infinite loop.. exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;
			p += sprintf(p, "%d {%lu, %lu}\t%s\t%u/%u/%s\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t%u\n",
				     i,
				     flow->id.ulArg1, flow->id.ulArg2,
				     flow->odev ? flow->odev->name : "UNK",
				     flow->ulVsgId,
				     flow->ulZoneId,
				     (flow->ucProtocol == 6) ? "TCP" : "UDP",

				     NIPQUAD(flow->ulSrcIp),
				     ntohs((flow->ulPorts&0xffff0000) >> 16),
				     NIPQUAD(flow->ulDestIp),
				     ntohs(flow->ulPorts&0xffff),

				     NIPQUAD(flow->ulSrcNATIp),
				     ntohs((flow->ulNATPorts&0xffff0000) >> 16),
				     NIPQUAD(flow->ulDestNATIp),
				     ntohs(flow->ulNATPorts&0xffff),
				     flow->stats.ulOutPkts);
			disp_cnt++;
			if (disp_cnt >= ffp_debug_show_count) {
				display = 0;
			}
		}
		spin_unlock_bh(&ffp_flow_table[i].lock);

		if (min_entr > cur_entr)
			min_entr = cur_entr;
		if (max_entr < cur_entr) {
			max_entr = cur_entr;
			max_entr_idx = i;
		}
	}
	if ((p-buf) > (200*(ffp_debug_show_count+2))) {
		printk("Ooops! buffer is overwriten! allocated %u and required %u to display %d items\n",
		       200*(ffp_debug_show_count+2), (p-buf), ffp_debug_show_count);
	}
	print_bigbuf(buf);
	printk("\nTotal %d (empty_l2blob %u)\n(max/bkt %u max-bkt-idx %u min/bkt %u empty-bkts %u)\n",
	       total, empty_l2blob, max_entr, max_entr_idx, min_entr, empty_entr);
	kfree(buf);
	return 0;
}

static int display_asf_proc_flow_debug(char *page, char **start,
				       off_t off, int count,
				       int *eof, void *data)
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	char	    *buf, *p;
	unsigned int    disp_cnt = 0, display = 0;
	unsigned long curTime = jiffies, last_in, ulIdleTime;

	buf = (char *)  kmalloc(300*(ffp_debug_show_count+2), GFP_KERNEL);
	if (!buf) {
		printk("ffp_debug_show_count is too large : couldn't allocate memory!\n");
		return 0;
	}

	/* display private information for each for debugging */

	printk("{ID}\t{OTH-ID}\tFLAGS\tPMTU\tSEQDLT\tBLEN\tTXVID\tIDLE/INAC\t{BLOB}\n");
	p = buf;
	*p = '\0';
	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_flow_table[i];
		if (i == ffp_debug_show_index)
			display = 1;

		spin_lock_bh(&ffp_flow_table[i].lock);
		for (flow = head->pNext; flow != head; flow = flow->pNext) {
			total++;
			if (flow == flow->pNext) {
				printk("possible infinite loop.. exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;

			last_in = flow->ulLastPktInAt;
			if (curTime > last_in) {
				ulIdleTime = curTime - last_in;
			} else {
				ulIdleTime = (((2^32)-1) - (last_in) + curTime);
			}
			ulIdleTime = ulIdleTime/HZ;


			p += sprintf(p, "{%lu, %lu}\t{%lu, %lu}\t%c%c%c%c%c%c%c%c\t%u\t%c%u\t%u\t%u\t%lu/%lu\t%pM:%pM..%02x%02x\n",
				     flow->id.ulArg1, flow->id.ulArg2,
				     flow->other_id.ulArg1, flow->other_id.ulArg2,

				     flow->bDrop ? 'D' : '-',  /* drop all packets */
				     flow->l2blob_len ? 'B' : '-', /* valid l2blob or not */
				     flow->bNat ? 'N' : '-',
				     flow->bVLAN ? 'V' : '-',
				     flow->bPPPoE ? 'P' : '-',
				     flow->bIPsecIn ? 'I' : '-',
				     flow->bIPsecOut ? 'O' : '-',
				     ASF_TCP_IS_BIT_SET(flow, FIN_RCVD) ? 'F' : (ASF_TCP_IS_BIT_SET(flow, RST_RCVD) ? 'R' : '-'),

				     flow->pmtu,
				     flow->tcpState.bPositiveDelta ? '+' : '-',
				     flow->tcpState.ulSeqDelta,
				     flow->l2blob_len,
				     flow->tx_vlan_id,
				     ulIdleTime,
				     flow->ulInacTime,
				     flow->l2blob,
				     flow->l2blob+6,
				     flow->l2blob[flow->l2blob_len-2],
				     flow->l2blob[flow->l2blob_len-1]);

			disp_cnt++;
			if (disp_cnt >= ffp_debug_show_count) {
				display = 0;
			}
		}
		spin_unlock_bh(&ffp_flow_table[i].lock);
	}
	print_bigbuf(buf);
	printk("\nTotal %d\n", total);
	kfree(buf);
	return 0;
}

#ifdef ASF_FFP_XTRA_STATS
static int display_asf_proc_xtra_flow_stats(char *page, char **start,
					    off_t off, int count,
					    int *eof, void *data)
{
	printk("No xtra flow stats for now!\n");
	return 0;
}
#endif

int asf_register_proc(void)
{
	struct proc_dir_entry   *proc_file;

	/* register sysctl tree */
	asf_proc_header = register_sysctl_table(asf_proc_root_table);
	if (!asf_proc_header)
		return -ENOMEM;
	/* register other under /proc/asf */
	asf_dir =  proc_mkdir("asf", NULL);

	if (asf_dir == NULL)
		return -ENOMEM;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	asf_dir->owner = THIS_MODULE;
#endif

	proc_file = create_proc_read_entry(
					  ASF_PROC_GLOBAL_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_global_stats,
					  NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#ifdef ASF_FFP_XTRA_STATS
	proc_file = create_proc_read_entry(
					  ASF_PROC_XTRA_GLOBAL_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_xtra_global_stats,
					  NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

	proc_file = create_proc_read_entry(
					  ASF_PROC_VSG_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_vsg_stats,
					  NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

	proc_file = create_proc_read_entry(
					  ASF_PROC_IFACE_MAPS,
					  0444, asf_dir,
					  display_asf_proc_iface_maps,
					  NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif


	proc_file = create_proc_read_entry(
					  ASF_PROC_FLOW_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_flow_stats,
					  NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#ifdef ASF_FFP_XTRA_STATS
	proc_file = create_proc_read_entry(
					  ASF_PROC_XTRA_FLOW_STATS_NAME,
					  0444, asf_dir,
					  display_asf_proc_xtra_flow_stats,
					  NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

	proc_file = create_proc_read_entry(
					  ASF_PROC_FLOW_DEBUG_NAME,
					  0444, asf_dir,
					  display_asf_proc_flow_debug,
					  NULL);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
	return 0;
}


int asf_unregister_proc(void)
{
	if (asf_proc_header)
		unregister_sysctl_table(asf_proc_header);
#ifdef ASF_FFP_XTRA_STATS
	remove_proc_entry(ASF_PROC_XTRA_GLOBAL_STATS_NAME, asf_dir);
#endif
	remove_proc_entry(ASF_PROC_GLOBAL_STATS_NAME, asf_dir);
	remove_proc_entry(ASF_PROC_VSG_STATS_NAME, asf_dir);
#ifdef ASF_FFP_XTRA_STATS
	remove_proc_entry(ASF_PROC_XTRA_FLOW_STATS_NAME, asf_dir);
#endif
	remove_proc_entry(ASF_PROC_IFACE_MAPS, asf_dir);
	remove_proc_entry(ASF_PROC_FLOW_STATS_NAME, asf_dir);
	remove_proc_entry(ASF_PROC_FLOW_DEBUG_NAME, asf_dir);
	remove_proc_entry("asf", NULL);

	return 0;
}
