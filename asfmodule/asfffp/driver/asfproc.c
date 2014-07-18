/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
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
#include <linux/seq_file.h>
#include <linux/fs.h>
#include "gplcode.h"
#include "asf.h"
#include "asfcmn.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfpvt.h"
#include "asfipv6pvt.h"
#include "asftcp.h"

/*
 * Implement following proc
 *	/proc/asf/flows
 *	/proc/asf/stats
 */

static int ffp_debug_show_index;
static int ffp_debug_show_count = 50;

extern void asf_ffp_cleanup_all_flows(void);

extern ffp_bucket_t *ffp_flow_table;
extern ASFFFPGlobalStats_t *asf_gstats;
#ifdef ASF_FFP_XTRA_STATS
extern ASFFFPXtraGlobalStats_t *asf_xgstats;
#endif
extern ASFFFPVsgStats_t *asf_vsg_stats; /* per cpu vsg stats */
extern int asf_max_vsgs;
extern int asf_l2blob_refresh_npkts;
extern int asf_l2blob_refresh_interval;

enum {
       ASF_FLOW_DEBUG = 0,
       ASF_FLOW_STATS,
       ASF_SHOW_IFACES,
       ASF_SHOW_GLOBAL_STATS,
       ASF_RESET_STATS,
       ASF_DISPLAY_VSG_STATS,
       #ifdef ASF_IPV6_FP_SUPPORT
       ASF_DISPLAY_IPV6_FLOW_STATS,
       #endif
       #ifdef ASF_FFP_XTRA_STATS
       ASF_DISPLAY_XTRA_GLOBAL_STATS
       #endif
};

static int asf_exec_cmd_clear_stats(struct seq_file *f, void *v)
{
	int vsg, cpu, i;
	ffp_flow_t *head, *flow;

	pr_info("Clearing Global%s Stats\n",
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

	pr_info("Clearing VSG Stats\n");
	for (vsg = 0 ; vsg < asf_max_vsgs ; vsg++) {
		for_each_online_cpu(cpu)
		{
			ASFFFPVsgStats_t *vstats;
			vstats = asfPerCpuPtr(asf_vsg_stats, cpu)+vsg;
			memset(vstats, 0, sizeof(*vstats));
		}
	}

	pr_info("Clearing Flow Stats\n");
	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_flow_table[i];
		for (flow = head->pNext; flow != head; flow = flow->pNext) {
			if (flow == flow->pNext)
				break;
			flow->stats.ulInPkts = 0;
			flow->stats.ulInBytes = 0;
			flow->stats.ulOutPkts = 0;
			flow->stats.ulOutBytes = 0;
		}
	}
	return 0;
}

static struct ctl_table asf_proc_table[] = {
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
#define ASF_PROC_RESET_STATS_NAME	"reset_stats"
#define ASF_PROC_IFACE_MAPS		"ifaces"
#define ASF_PROC_FLOW_STATS_NAME	"flow_stats"
#ifdef ASF_IPV6_FP_SUPPORT
#define ASF_PROC_FLOW_IPV6_STATS_NAME	"flow_ipv6_stats"
#endif
#define ASF_PROC_FLOW_DEBUG_NAME	"flow_debug"

#define GSTATS_SUM(a) (total.ul##a += gstats->ul##a)
#define GSTATS_TOTAL(a) (unsigned long) total.ul##a
static int show_globalstats(struct seq_file *f, void *v)
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

	seq_printf(f, "IN %lu IN-MATCH %lu OUT %lu OUT-BYTES %lu\n",
	       GSTATS_TOTAL(InPkts), GSTATS_TOTAL(InPktFlowMatches),
		GSTATS_TOTAL(OutPkts), GSTATS_TOTAL(OutBytes));

	seq_printf(f, "FLOW: ALLOC %lu FREE %lu ALLOC-FAIL %lu FREE-FAIL %lu\n",
	       GSTATS_TOTAL(FlowAllocs), GSTATS_TOTAL(FlowFrees),
	       GSTATS_TOTAL(FlowAllocFailures), GSTATS_TOTAL(FlowFreeFailures));

	seq_printf(f, "ERR: CSUM %lu IPH %lu IPPH %lu AllocFail %lu"
		"MiscFail %lu TTL %lu\n",
	       GSTATS_TOTAL(ErrCsum), GSTATS_TOTAL(ErrIpHdr),
	       GSTATS_TOTAL(ErrIpProtoHdr), GSTATS_TOTAL(ErrAllocFailures),
	       GSTATS_TOTAL(MiscFailures), GSTATS_TOTAL(ErrTTL));

	seq_printf(f, "MISC: TO-FNP %lu\n", GSTATS_TOTAL(PktsToFNP));

	return 0;
}

#ifdef ASF_FFP_XTRA_STATS
#define XGSTATS_SUM(a) (total.ul##a += xgstats->ul##a)
#define XGSTATS_TOTAL(a) total.ul##a
#define XGSTATS_DISP(a) do {\
	if (total.ul##a)\
		seq_printf(f, " " #a " = %lu\n", total.ul##a);\
	} while (0)

static int display_asfproc_xtra_global_stats(struct seq_file *f, void *v)
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
		XGSTATS_SUM(TmrProcCalls);
		XGSTATS_SUM(TmrProcReclCalls);
		XGSTATS_SUM(TmrStarts);
		XGSTATS_SUM(TmrStopExpireSoon);
		XGSTATS_SUM(TmrStopSameCore);
		XGSTATS_SUM(TmrStopOtherCore);
		XGSTATS_SUM(TmrStopOtherCoreReclaimQFull);
		XGSTATS_SUM(TmrProcTimerRestart);
		XGSTATS_SUM(TmrProcTimerDelete);
		XGSTATS_SUM(TmrProcReclaimQTimerDelete);
		XGSTATS_SUM(DefragCalls);
		XGSTATS_SUM(DefragCallsTcp);
		XGSTATS_SUM(DefragCallsUdp);
		XGSTATS_SUM(DefragCallsOther);
		XGSTATS_SUM(DefragIntegrityErr);
		XGSTATS_SUM(DefragTotLenExceedErr);
		XGSTATS_SUM(DefragCompleted);
		XGSTATS_SUM(DefragFragHandleErr);
		XGSTATS_SUM(DefragCbAllocErr);
		XGSTATS_SUM(DefragCbMatches);
		XGSTATS_SUM(DefragCbAllocs);
		XGSTATS_SUM(DefragCbDeletes);
		XGSTATS_SUM(DefragCbTimerStart);
		XGSTATS_SUM(DefragCbTimerStartErr);
		XGSTATS_SUM(DefragCbAllocIndexArrayErr);
		XGSTATS_SUM(DefragCbTimerCalls);
		XGSTATS_SUM(DefragCbTimerMagicMatched);
		XGSTATS_SUM(DefragCbTimerTimeout);
		XGSTATS_SUM(DefragCbTimerWillRestart);
		XGSTATS_SUM(DefragCbTimerMagicMatchErr);
		XGSTATS_SUM(FragHandleCalls);
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
	XGSTATS_DISP(TmrProcCalls);
	XGSTATS_DISP(TmrProcReclCalls);
	XGSTATS_DISP(TmrStarts);
	XGSTATS_DISP(TmrStopExpireSoon);
	XGSTATS_DISP(TmrStopSameCore);
	XGSTATS_DISP(TmrStopOtherCore);
	XGSTATS_DISP(TmrStopOtherCoreReclaimQFull);
	XGSTATS_DISP(TmrProcTimerRestart);
	XGSTATS_DISP(TmrProcTimerDelete);
	XGSTATS_DISP(TmrProcReclaimQTimerDelete);
	XGSTATS_DISP(DefragCalls);
	XGSTATS_DISP(DefragCallsTcp);
	XGSTATS_DISP(DefragCallsUdp);
	XGSTATS_DISP(DefragCallsOther);
	XGSTATS_DISP(DefragIntegrityErr);
	XGSTATS_DISP(DefragTotLenExceedErr);
	XGSTATS_DISP(DefragCompleted);
	XGSTATS_DISP(DefragFragHandleErr);
	XGSTATS_DISP(DefragCbAllocErr);
	XGSTATS_DISP(DefragCbMatches);
	XGSTATS_DISP(DefragCbAllocs);
	XGSTATS_DISP(DefragCbDeletes);
	XGSTATS_DISP(DefragCbTimerStart);
	XGSTATS_DISP(DefragCbTimerStartErr);
	XGSTATS_DISP(DefragCbAllocIndexArrayErr);
	XGSTATS_DISP(DefragCbTimerCalls);
	XGSTATS_DISP(DefragCbTimerMagicMatched);
	XGSTATS_DISP(DefragCbTimerTimeout);
	XGSTATS_DISP(DefragCbTimerWillRestart);
	XGSTATS_DISP(DefragCbTimerMagicMatchErr);
	XGSTATS_DISP(FragHandleCalls);

	return 0;
}
#endif


#define VSTATS_SUM(a) (total.ul##a += vstats->ul##a)
#define VSTATS_TOTAL(a) (unsigned long)total.ul##a
static int display_asf_proc_vsg_stats(struct seq_file *f, void *v)
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
			seq_printf(f, "%d: IN %lu FLOW_MATCHES %lu "
				"OUT %lu OUT-BYTES %lu\n", vsg,
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
static int show_iface(struct seq_file *f, void *v)
{
	int i;
	ASFNetDevEntry_t *dev;

	seq_printf(f, "CII\tNAME\tTYPE\tVSG\tZONE\tID\tPAR-CII\tBR-CII\n");
	for (i = 0; i < asf_max_ifaces; i++) {
		dev = asf_ifaces[i];
		if (!dev)
			continue;
		seq_printf(f, "%u\t%s\t%s\t%d\t%d\t0x%x\t%u\t%u\n",
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

static int display_asf_proc_flow_stats(struct seq_file *f, void *v)
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	unsigned int    min_entr = ~1, max_entr = 0, max_entr_idx = ~1, cur_entr = 0, empty_entr = 0;
	unsigned int    empty_l2blob = 0;
	unsigned int    disp_cnt = 0, display = 0;

	seq_printf(f, "HIDX {ID}\tDST\tV/Z/P\tSIP:SPORT\tDIP:DPORT\t"
		"SNIP:SNPORT\tDNIP:DNPORT\tPKTS IN-OUT\n");
	for (i = 0; i < ffp_hash_buckets; i++) {
		spin_lock_bh(&ffp_flow_table[i].lock);
		head = (ffp_flow_t *)  &ffp_flow_table[i];

		if (head == head->pNext)
			empty_entr++;

		if (i == ffp_debug_show_index)
			display = 1;

		cur_entr = 0;
		for (flow = head->pNext; flow != head; flow = flow->pNext) {

			total++;
			cur_entr++;
			if (flow->l2blob_len == 0)
				empty_l2blob++;
			if (flow == flow->pNext) {
				seq_printf(f, "possible infinite loop.."
						" exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;
			seq_printf(f, "%d {%u, %u}\t%s\t%u/%u/%s\t"
			"%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t"
			"%d.%d.%d.%d:%d\t%d.%d.%d.%d:%d\t%lu-%lu\n",
			i,
			flow->id.ulArg1, flow->id.ulArg2,
			flow->odev ? flow->odev->name : "UNK",
			flow->ulVsgId,
			flow->ulZoneId,
				(flow->ucProtocol == 6) ? "TCP" :
				(flow->ucProtocol == 17) ? "UDP" : "SCTP",

			NIPQUAD(flow->ulSrcIp),
			ntohs((flow->ulPorts&0xffff0000) >> 16),
			NIPQUAD(flow->ulDestIp),
			ntohs(flow->ulPorts&0xffff),
			NIPQUAD(flow->ulSrcNATIp),
			ntohs((flow->ulNATPorts&0xffff0000) >> 16),
			NIPQUAD(flow->ulDestNATIp),
			ntohs(flow->ulNATPorts&0xffff),
			(unsigned long)flow->stats.ulInPkts,
			(unsigned long)flow->stats.ulOutPkts);
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
	seq_printf(f, "\nTotal %d (empty_l2blob %u)\n(max/bkt %u max-bkt-idx %u"
		" min/bkt %u empty-bkts %u)\n",
	       total, empty_l2blob, max_entr, max_entr_idx, min_entr, empty_entr);
	return 0;
}

#ifdef ASF_IPV6_FP_SUPPORT
static int display_asf_proc_flow_ipv6_stats(struct seq_file *f, void *v)
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	unsigned int    min_entr = ~1, max_entr = 0, max_entr_idx = ~1, cur_entr = 0, empty_entr = 0;
	unsigned int    empty_l2blob = 0;
	unsigned int    disp_cnt = 0, display = 0;

	seq_printf(f, "\n==================================="
		"===================================\n");
	for (i = 0; i < ffp_ipv6_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_ipv6_flow_table[i];

		if (head == head->pNext)
			empty_entr++;

		if (i == ffp_debug_show_index)
			display = 1;

		cur_entr = 0;
		spin_lock_bh(&ffp_ipv6_flow_table[i].lock);
		for (flow = head->pNext; flow != head; flow = flow->pNext) {

			total++;
			cur_entr++;
			if (flow->l2blob_len == 0)
				empty_l2blob++;
			if (flow == flow->pNext) {
				seq_printf(f, "possible infinite loop.."
					" exiting this bucket!\n");
				break;
			}

			if (!display)
				continue;
			seq_printf(f, "Src IP      = %x:%x:%x:%x:%x:%x:%x:%x"
			"	Port = %u\n",
			PRINT_IPV6_OTH(flow->ipv6SrcIp),
			ntohs((flow->ulPorts&0xffff0000) >> 16));
			seq_printf(f, "Dest IP     = %x:%x:%x:%x:%x:%x:%x:%x"
			"	Port = %u\n", PRINT_IPV6_OTH(flow->ipv6DestIp),
			ntohs(flow->ulPorts&0xffff));
			seq_printf(f, "NAT Src IP  = %x:%x:%x:%x:%x:%x:%x:%x"
			"	Port = %u\n", PRINT_IPV6_OTH(flow->ipv6SrcNATIp),
			ntohs((flow->ulNATPorts&0xffff0000) >> 16));
			seq_printf(f, "NAT Dest IP = %x:%x:%x:%x:%x:%x:%x:%x"
			"	Port = %u\n", PRINT_IPV6_OTH(flow->ipv6DestNATIp),
			ntohs(flow->ulNATPorts&0xffff));
			seq_printf(f, "Proto = %s  Out dev = %s   l2blob len = %u"
			"   VSG = %u  Zone = %u\n",
			((flow->ucProtocol == 6) ? "TCP" : "UDP"),
			(flow->odev ? flow->odev->name : "UNK"),
			flow->l2blob_len,
			flow->ulVsgId,
			flow->ulZoneId);
			seq_printf(f, "In pkts = %u	Out pkts = %u\n",
				flow->stats.ulInPkts, flow->stats.ulOutPkts);
			seq_printf(f, "===================================="
				"==================================\n\n");
			disp_cnt++;
			if (disp_cnt >= ffp_debug_show_count)
				display = 0;
		}
		spin_unlock_bh(&ffp_ipv6_flow_table[i].lock);

		if (min_entr > cur_entr)
			min_entr = cur_entr;
		if (max_entr < cur_entr) {
			max_entr = cur_entr;
			max_entr_idx = i;
		}
	}
	seq_printf(f, "\nTotal %d (empty_l2blob %u)\n(max/bkt %u"
			" max-bkt-idx %u min/bkt %u empty-bkts %u)\n",
	       total, empty_l2blob, max_entr, max_entr_idx, min_entr, empty_entr);
	return 0;
}
#endif
static int display_asf_proc_flow_debug(struct seq_file *f, void *v)
{
	int i, total = 0;
	ffp_flow_t      *head, *flow;
	unsigned int    disp_cnt = 0, display = 0;
	unsigned long curTime = jiffies, last_in, ulIdleTime;

	/* display private information for each for debugging */

	seq_printf(f, "{ID}\t{OTH-ID}\tFLAGS\tPMTU\tSEQDLT\tBLEN"
			"\tTXVID\tIDLE/INAC\t{BLOB}\n");
	for (i = 0; i < ffp_hash_buckets; i++) {
		head = (ffp_flow_t *)  &ffp_flow_table[i];
		if (i == ffp_debug_show_index)
			display = 1;

		spin_lock_bh(&ffp_flow_table[i].lock);
		for (flow = head->pNext; flow != head; flow = flow->pNext) {
			total++;
			if (flow == flow->pNext) {
				seq_printf(f, "possible infinite loop.."
					" exiting this bucket!\n");
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


			seq_printf(f, "{%u, %u}\t{%u, %u}\t"
				"%c%c%c%c%c%c%c%c\t%u\t%c%u\t%u\t%u"
				"\t%lu/%lu\t%pM:%pM..%02x%02x\n",
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
	seq_printf(f, "\nTotal %d\n", total);
	return 0;
}

#ifdef ASF_FFP_XTRA_STATS
static int display_asf_proc_xtra_flow_stats(char *page, char **start,
					    off_t off, int count,
					    int *eof, void *data)
{
	pr_info("No xtra flow stats for now!\n");
	return 0;
}
#endif

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
		.show  = display_asf_proc_flow_debug
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_asf_proc_flow_stats
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = show_iface
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = show_globalstats
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = asf_exec_cmd_clear_stats
	},
	{
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_asf_proc_vsg_stats
	}
	#ifdef ASF_IPV6_FP_SUPPORT
	, {
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_asf_proc_flow_ipv6_stats
	}
	#endif
	#ifdef ASF_FFP_XTRA_STATS
	, {
		.start = int_seq_start,
		.next  = int_seq_next,
		.stop  = int_seq_stop,
		.show  = display_asfproc_xtra_global_stats
	}
	#endif
};

static int flowdebug_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_FLOW_DEBUG]);
}
static int flowstats_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_FLOW_STATS]);
}

static int iface_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_SHOW_IFACES]);
}

static int globalstats_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_SHOW_GLOBAL_STATS]);
}

static int reset_stats(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_RESET_STATS]);
}
static int display_vsg_stats_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_DISPLAY_VSG_STATS]);
}
#ifdef ASF_IPV6_FP_SUPPORT
static int ipv6_flow_stats_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_DISPLAY_IPV6_FLOW_STATS]);
}
#endif
#ifdef ASF_FFP_XTRA_STATS
static int xtra_globalstats_open(struct inode *inode, struct file *filp)
{
	return seq_open(filp, &int_seq_ops[ASF_DISPLAY_XTRA_GLOBAL_STATS]);
}
#endif

static const struct file_operations proc_asf_stats_operations[] = {
	{
		.open	   = flowdebug_open,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = flowstats_open,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = iface_open,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = globalstats_open,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = reset_stats,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	},
	{
		.open	   = display_vsg_stats_open,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	}
	#ifdef ASF_IPV6_FP_SUPPORT
	,
	{
		.open	   = ipv6_flow_stats_open,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	}
	#endif
	#ifdef ASF_FFP_XTRA_STATS
	,
	{
		.open	   = xtra_globalstats_open,
		.read	   = seq_read,
		.llseek	 	= seq_lseek,
		.release	= seq_release,
	}
	#endif
};

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

	proc_file = proc_create(ASF_PROC_GLOBAL_STATS_NAME,
				0444, asf_dir,
		&proc_asf_stats_operations[ASF_SHOW_GLOBAL_STATS]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#ifdef ASF_FFP_XTRA_STATS
	proc_file = proc_create(ASF_PROC_XTRA_GLOBAL_STATS_NAME,
				0444, asf_dir,
		&proc_asf_stats_operations[ASF_DISPLAY_XTRA_GLOBAL_STATS]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

	proc_file = proc_create(ASF_PROC_VSG_STATS_NAME,
			0444, asf_dir,
		&proc_asf_stats_operations[ASF_DISPLAY_VSG_STATS]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

	proc_file = proc_create(ASF_PROC_RESET_STATS_NAME,
			0444, asf_dir,
		&proc_asf_stats_operations[ASF_RESET_STATS]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

	proc_file = proc_create(ASF_PROC_IFACE_MAPS,
			0444, asf_dir,
		&proc_asf_stats_operations[ASF_SHOW_IFACES]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

	proc_file = proc_create(ASF_PROC_FLOW_STATS_NAME,
			0444, asf_dir,
		&proc_asf_stats_operations[ASF_FLOW_STATS]);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif

#ifdef ASF_IPV6_FP_SUPPORT
	proc_file = proc_create(ASF_PROC_FLOW_IPV6_STATS_NAME,
			0444, asf_dir,
		&proc_asf_stats_operations[ASF_DISPLAY_IPV6_FLOW_STATS]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

#ifdef ASF_FFP_XTRA_STATS
	proc_file = proc_create(ASF_PROC_XTRA_FLOW_STATS_NAME,
			  0444, asf_dir,
		&proc_asf_stats_operations[ASF_FLOW_DEBUG]);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 30)
	if (proc_file)
		proc_file->owner = THIS_MODULE;
#endif
#endif

	proc_file = proc_create(ASF_PROC_FLOW_DEBUG_NAME,
			  0444, asf_dir,
			&proc_asf_stats_operations[ASF_FLOW_DEBUG]);
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
	remove_proc_entry(ASF_PROC_RESET_STATS_NAME, asf_dir);
	remove_proc_entry(ASF_PROC_IFACE_MAPS, asf_dir);
	remove_proc_entry(ASF_PROC_FLOW_STATS_NAME, asf_dir);
#ifdef ASF_IPV6_FP_SUPPORT
	remove_proc_entry(ASF_PROC_FLOW_IPV6_STATS_NAME, asf_dir);
#endif
	remove_proc_entry(ASF_PROC_FLOW_DEBUG_NAME, asf_dir);
	remove_proc_entry("asf", NULL);

	return 0;
}
