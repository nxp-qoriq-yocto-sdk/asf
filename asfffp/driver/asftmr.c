/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	asftmr.c
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
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
/*
 * History
 *
 */
/******************************************************************************/

/******************************************************************************
 * File Name : asftmr.c
 * Description: Contains application specific fast path timer
 * Version  : 0.1
 * Author : Subha
 * Date : October 2009
 * TBD: Add appropriate Freescale header template
      : Adapted from LWE Timer of P4080
 ******************************************************************************/
/*******************Include files ************************************************/
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/in.h>
#include <linux/netdevice.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include "gplcode.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asf.h"
#include "asfcmn.h"
#include "asfparry.h"
#include "asfpvt.h"

#define ASF_TMR_MAX_APPS  ASF_NUM_OF_TIMERS
#define ASF_TMR_MAX_INSTANCES 1

#ifdef ASF_TIMER_DEBUG
#define asf_timer_debug(fmt, args...) printk("[CPU %d line %d %s] " fmt, smp_processor_id(), __LINE__, __FUNCTION__, ##args)
#else
#define asf_timer_debug(fmt, args...)
#endif

#define ASF_TMR_STARTED		1
#define ASF_TMR_STOPPED		2
#define ASF_TMR_RESTARTED	3
#define ASF_TMR_Q_IN_PROCESS (1 << 15)

#define ASF_TMR_NEXT_FEW_BUCKETS 4

extern ASFFFPGlobalStats_t *asf_gstats;
static void asfTimerProc(unsigned long data);

struct asfTmrAppInstanceInfo_s {
	asfTmrCbFn pFn;
	unsigned int ulTmrPoolId;
} ;

struct asfTmrAppInfo_s {
	struct asfTmrAppInstanceInfo_s *pInstance;
	unsigned int ulNumInstances;
} ;

struct asfTmrRQ_s {
	unsigned int ulWrIndex;
	asfTmr_t **pQueue;
} ;

struct asfTmrWheelPerCore_s {
	unsigned int ulCurBucketIndex;
	unsigned int ulLastTimerExpiry;
	unsigned int ulMaxBuckets;
	struct asfTmr_s **pBuckets;
	unsigned int ulMaxRqEntries;
	unsigned int ulRqRdIndex[NR_CPUS];
	struct asfTmrRQ_s *pQs;
	struct timer_list timer;
	bool bStarted;
} ;

struct asfTmrWheelInstance_s {
	unsigned int ulTmrType;
	unsigned int ulInterBucketGap;
	unsigned int ulHalfInterBucketGap;
	unsigned int ulTimerInterval; /* In jiffies */
	struct asfTmrWheelPerCore_s *pTmrWheel;
} ;

struct asfTmrWheelInfo_s {
	struct asfTmrWheelInstance_s *pWheel;
	unsigned int ulNumEntries;
} ;

static struct
asfTmrAppInfo_s *pAsfTmrAppInfo;

static struct
asfTmrWheelInfo_s *pAsfTmrWheelInstances;

static unsigned int ulASFTmrMaxApps_g;

#define ASF_TMR_SUCCESS 0
#define ASF_TMR_FAILURE 1

/*
 * Function name: asfTimerInit
 * Input: ulMaxApps, ulMaxTmrWheelInstancePerApp
 * [pAsfTmrAppInfo[0]]
   [pAsfTmrAppInfo[1]]
   [pAsfTmrAppInfo[MAX_APPS]

   Each AppInfo[App] can hold multiple instances (asfTmrAppInstanceInfo)
   Each App and Instance holds the timer memory pool associated with it and the callback function

   [pAsfTmrWheelInstance[0]
   [pAsfTmrWheelInstance[1]
   [pAsfTmrWheelInstance[MAX_APPS]

   Each Timer Wheel Instance holds Instance array of asfTmrWheelInstance_s

   Application Id and instance Id should be decided among applications at design time.
*/
unsigned int asfTimerInit(unsigned short int ulMaxApps,
			  unsigned short int ulMaxTmrWheelInstancePerApp)
{
	int ii;

	ulASFTmrMaxApps_g = ulMaxApps;

	pAsfTmrAppInfo = kzalloc(ulMaxApps *  sizeof(struct asfTmrAppInfo_s), GFP_KERNEL);
	if (!pAsfTmrAppInfo) {
		asf_timer_debug("asfTimerInit Returned failure\r\n");
		return ASF_TMR_FAILURE;
	}

	for (ii = 0; ii < ulMaxApps; ii++) {
		pAsfTmrAppInfo[ii].pInstance = kzalloc(ulMaxTmrWheelInstancePerApp * sizeof(struct asfTmrAppInstanceInfo_s), GFP_KERNEL);
		if (!pAsfTmrAppInfo[ii].pInstance) {
			asf_timer_debug("asfTimerInit: kzalloc of Per Instance App Info failed\r\n");
			return ASF_TMR_FAILURE;
		}
		pAsfTmrAppInfo[ii].ulNumInstances = ulMaxTmrWheelInstancePerApp;
	}

	pAsfTmrWheelInstances = kzalloc(ulMaxApps  * sizeof(struct asfTmrWheelInfo_s), GFP_KERNEL);
	if (!pAsfTmrWheelInstances) {
		asf_timer_debug(KERN_INFO "asfTimerInit: Allocation for TmrWheelInstances failed\r\n");
		return ASF_TMR_FAILURE;
	}

	for (ii = 0; ii < ulMaxApps; ii++) {
		pAsfTmrWheelInstances[ii].pWheel =
		kzalloc(ulMaxTmrWheelInstancePerApp * sizeof(struct asfTmrWheelInstance_s), GFP_KERNEL);
		if (!pAsfTmrWheelInstances[ii].pWheel) {
			asf_timer_debug("asfTimerInit: kzalloc of per Instance App Info failed\r\n");
			return ASF_TMR_FAILURE;
		}
		pAsfTmrWheelInstances[ii].ulNumEntries = ulMaxTmrWheelInstancePerApp;
	}
	return ASF_TMR_SUCCESS;
}


/*
 * Description: For a given application and instance, register the callback
 * function and the memory pool that holds the timers
 */
unsigned int asfTimerAppRegister(unsigned short int ulAppId,
				 unsigned short int ulTmrInstanceId, asfTmrCbFn pFn,
				 unsigned int ulPoolId)
{
	if (pAsfTmrAppInfo[ulAppId].pInstance[ulTmrInstanceId].pFn == NULL) {
		pAsfTmrAppInfo[ulAppId].pInstance[ulTmrInstanceId].pFn = pFn;
		pAsfTmrAppInfo[ulAppId].pInstance[ulTmrInstanceId].ulTmrPoolId = ulPoolId;
		return ASF_TMR_SUCCESS;
	}
	return ASF_TMR_FAILURE;
}
EXPORT_SYMBOL(asfTimerAppRegister);


/* set the interval to zero so that current timer don't invoke add_timer()
 * This function is used while removing the kernel module using rmmod
 */

void asfTimerDisableKernelTimers(void)
{
	unsigned short int ulAppId;
	unsigned short int ulInstanceId;
	struct asfTmrWheelInstance_s *pWheel;
	struct asfTmrWheelPerCore_s *pTmrWheel;
	int     iRetVal, ii;

	for (ulAppId = 0; ulAppId < ASF_TMR_MAX_APPS; ulAppId++) {
		for (ulInstanceId = 0; ulInstanceId < ASF_TMR_MAX_INSTANCES; ulInstanceId++) {
			pWheel = &(pAsfTmrWheelInstances[ulAppId].pWheel[ulInstanceId]);
			if (pWheel) {
				asf_timer_debug("DisKernTimers: appId %d"\
					"instId %d .. SET interval = 0\n",
					ulAppId, ulInstanceId);
				pWheel->ulTimerInterval = 0;
				if (pWheel->pTmrWheel) {
					for_each_possible_cpu(ii)
					{
						pTmrWheel = per_cpu_ptr(pWheel->pTmrWheel, ii);

						if (timer_pending(&(pTmrWheel->timer))) {
							iRetVal = del_timer_sync(&(pTmrWheel->timer));
							asf_timer_debug("DisKernTimers: del_timer_sync appId %d instId %d cpuId %d result %d\n",
							       ulAppId, ulInstanceId, ii, iRetVal);
						}
					}
				}
			}
		}
	}
}

/* This route is not general purpose one. It is indtended for
** rmmod functionality */
void asfTimerFreeNodeMemory(asfTmr_t *tmr)
{
	if (tmr && tmr->bHeap) {
		kfree(tmr);
	}
}
EXPORT_SYMBOL(asfTimerFreeNodeMemory);

/* DeInit routine: TBD */
void  asfTimerDeInit(void)
{
	int ii;
	/* Need to check if anything else needs to be added here */
	if (pAsfTmrAppInfo) {
		for (ii = 0; ii < ulASFTmrMaxApps_g; ii++) {
			if (pAsfTmrAppInfo[ii].pInstance) {
				kfree(pAsfTmrAppInfo[ii].pInstance);
			}
		}
		kfree(pAsfTmrAppInfo);
	}
	if (pAsfTmrWheelInstances) {
		for (ii = 0; ii < ulASFTmrMaxApps_g; ii++) {
			if (pAsfTmrWheelInstances[ii].pWheel) {
				kfree(pAsfTmrWheelInstances[ii].pWheel);
			}
		}
		kfree(pAsfTmrWheelInstances);
	}
}

void asfAddTimerOn(void *tmr)
{
	add_timer(tmr);
}

void asfDelTimerOn(void *tmr)
{
	del_timer(tmr);
}


/*
 * Input :
      ulAppId = Application Id
      ulInstanceId = Instance Id
      ulNumBuckets = Number of buckets that this
		timer wheel should support.
		(Should be some 2^x value,
		no check being done currently)
      ucTmrType = SECS or MS;
      ulInterBucketGap = difference between buckets in terms of
		ucTmrType,
      So, if one specified ucTmrType = MS (millisecs) and
       ulInterBucketGap = 100 and ulNumBuckets as 16, the
      max timeout possible = 1600 ms

      ulNumRQEntries = Number of reclaim queue entries. More
      explanation to follow on this

  Description:
      When this function is invoked, for each core, one timer
      bucket list is created.

      i.e.
      [Core 0]-[b0][b1][b2]....[bn]
      [Core 1]-[b0][b1][b2]....[bn]

      So when a timer, is started, it is added to the the
      current core (core on which it is started) at the
      appropriate bucket.


     Also for each core a reclaim array is created for every
     other core in the system (one for itself, though not
     used)

     [Core 0]-
	    [Core0] [Not used currently][Rq0][Rq1][Rq3][Rq4]...[Rqn]
	    [Core1] [Rq0][Rq1][Rq3][Rq4]...[Rqn]

     [Core 1]-
	    [Core0] [Not used currently][Rq0][Rq1][Rq3][Rq4]...[Rqn]
	    [Core1] [Rq0][Rq1][Rq3][Rq4]...[Rqn]

     Rqx stand for Request queue index. Rq comes into picture, when
     timer stop is invoked in core x, but the timer exists in core y's
     timer list.  In this case, core x adds the timer to the Rq entry
     in Core y. Core y, upon the next periodic wakeup will remove
     the Rq entry.

     The required data structures are setup. Timer is started by calling
     add_timer() function in linux.
*/

unsigned int asfTimerWheelInit(unsigned short int ulAppId,
			       unsigned short int ulInstanceId,  unsigned int ulNumBuckets,
			       unsigned char ucTmrType, unsigned int ulInterBucketTmrGap,
			       unsigned int ulNumRQEntries)
{
	struct asfTmrWheelInstance_s *pWheel;
	struct asfTmrWheelPerCore_s *pTmrWheel;
	int ii, jj;
	struct asfTmrRQ_s *pTempRq;

	if ((ulAppId > ASF_TMR_MAX_APPS) || (ulInstanceId > ASF_TMR_MAX_INSTANCES)) {
		asf_timer_debug("Invalid instance Id: App Id \r\n");
		return ASF_TMR_FAILURE;
	}

	asf_timer_debug("ptr %x\n", pAsfTmrWheelInstances[ulAppId].pWheel);
	pWheel = &(pAsfTmrWheelInstances[ulAppId].pWheel[ulInstanceId]);

	/* Initialize the wheel information */
	pWheel->ulInterBucketGap = ulInterBucketTmrGap;
	pWheel->ulHalfInterBucketGap = (ulInterBucketTmrGap >> 1);

	asf_timer_debug("Wheel parameters initialized\r\n");

	switch (ucTmrType) {
	case ASF_TMR_TYPE_MS_TMR:
		pWheel->ulTimerInterval = msecs_to_jiffies(ulInterBucketTmrGap);
		break;
	case ASF_TMR_TYPE_SEC_TMR:
		pWheel->ulTimerInterval  = msecs_to_jiffies(1000 * ulInterBucketTmrGap);
		break;
	default:
		asf_timer_debug("Timer type unknown: Return T_FAILURE\r\n");
		break;
	}

	pWheel->ulTmrType = ucTmrType;

	pWheel->pTmrWheel = asfAllocPerCpu(sizeof(struct asfTmrWheelPerCore_s) +
					   (sizeof(struct asfTmr_s **) * ulNumBuckets));
	if (pWheel->pTmrWheel) {
		for_each_possible_cpu(ii)
		{
			asf_timer_debug("Initializing pTmrWheel\r\n");
			pTmrWheel = per_cpu_ptr(pWheel->pTmrWheel, ii);
			pTmrWheel->ulMaxBuckets = ulNumBuckets;
			pTmrWheel->pBuckets = (pTmrWheel + 1);
			asf_timer_debug("Initialized pBuckets\r\n");
			pTmrWheel->ulMaxRqEntries = ulNumRQEntries;

			asf_timer_debug("Initialized pQs\r\n");
			pTmrWheel->pQs = asfAllocPerCpu(sizeof(struct asfTmrRQ_s)
							+ (sizeof(asfTmr_t *) * ulNumRQEntries));
			if (pTmrWheel->pQs) {
				for_each_possible_cpu(jj)
				{
					pTempRq = per_cpu_ptr(pTmrWheel->pQs, jj);
					pTempRq->pQueue = pTempRq + 1;
				}
			} else {
				asf_timer_debug("Allocation of Per CPU RQ Entries failed\r\n");
				return ASF_TMR_FAILURE;
			}
			asf_timer_debug("Queues initialized\r\n");

			init_timer(&(pTmrWheel->timer));
			pTmrWheel->timer.function = asfTimerProc;
			pTmrWheel->timer.expires = jiffies + pWheel->ulTimerInterval;
			pTmrWheel->timer.data = (ulAppId << 16 | ulInstanceId);	/* Passing the application wheel reference as callback data */

			asf_timer_debug("Timer data = 0x%x\r\n", pTmrWheel->timer.data);
			if (ii == smp_processor_id()) {
				add_timer(&(pTmrWheel->timer));
			} else {
				smp_call_function_single(ii, asfAddTimerOn, &pTmrWheel->timer, 1);
			}
			asf_timer_debug("Timers Added to Linux\r\n");
		}
		/* Timer will be started when the first timer object gets added */
		return ASF_TMR_SUCCESS;
	}
	asf_timer_debug("wheel init for app-id %d inst-id %d failed!\n",
			ulAppId, ulInstanceId);
	return ASF_TMR_FAILURE;
}
EXPORT_SYMBOL(asfTimerWheelInit);

/*
 * Deinit Function
 */
unsigned int asfTimerWheelDeInit(unsigned short int ulAppId, unsigned  short int ulInstanceId)
{
	struct asfTmrWheelInstance_s *pWheel;
	struct asfTmrWheelPerCore_s *pTmrWheel;
	int ii, iRetVal;

	if (ulAppId > ASF_TMR_MAX_APPS) {
		asf_timer_debug("Invalid instance Id: App Id \r\n");
		return ASF_TMR_FAILURE;
	}

	pWheel = &(pAsfTmrWheelInstances[ulAppId].pWheel[ulInstanceId]);

	if (pWheel->pTmrWheel) {
		for_each_possible_cpu(ii)
		{
			pTmrWheel = per_cpu_ptr(pWheel->pTmrWheel, ii);

			if (timer_pending(&(pTmrWheel->timer))) {
				iRetVal = del_timer_sync(&(pTmrWheel->timer));
				asf_timer_debug("del_timer_sync: appId %d instId %d cpuId %d result %d\n",
				       ulAppId, ulInstanceId, ii, iRetVal);
			}

			/* TODO: Need to clean up the reclamation queue */

			/* Need to clean up the buckets */
			asfFreePerCpu(pTmrWheel->pQs);
		}
		asfFreePerCpu(pWheel->pTmrWheel);
	}
	pAsfTmrAppInfo[ulAppId].pInstance[ulInstanceId].pFn = NULL;
	return ASF_TMR_SUCCESS;
}

EXPORT_SYMBOL(asfTimerWheelDeInit);
/*
 * Small inline function to add timer to the bucket. Called from
   Timer start and asfProcTimer
 */
static inline void asfAddTmrToBucket(struct asfTmrWheelPerCore_s *pTmrWheel,
				     asfTmr_t *ptmr)
{

	ptmr->pPrev = NULL;
	if (pTmrWheel->pBuckets[ptmr->ulBucketIndex]) {
		pTmrWheel->pBuckets[ptmr->ulBucketIndex]->pPrev = ptmr;
	}
	ptmr->pNext = pTmrWheel->pBuckets[ptmr->ulBucketIndex];

	pTmrWheel->pBuckets[ptmr->ulBucketIndex] = ptmr;
}

/* Small inline function to remove timer from bucket
 * called from TimerStop or Proc timer
 */
static inline void asfRemoveTmrFromBucket(struct asfTmrWheelPerCore_s *pTmrWheel,
					  asfTmr_t *ptmr)
{
	if (ptmr->pPrev) {
		ptmr->pPrev->pNext = ptmr->pNext;
	}
	if (ptmr->pNext) {
		ptmr->pNext->pPrev = ptmr->pPrev;
	}
	if (ptmr == pTmrWheel->pBuckets[ptmr->ulBucketIndex]) {
		pTmrWheel->pBuckets[ptmr->ulBucketIndex] = ptmr->pNext;
	}
}

/*
 * Starts the timer, finds the bucket to add
 * allocates timer using pool Id for that application/instance
 * adds into the bucket
 * all timers are assumed to be periodic timers
 */
asfTmr_t *asfTimerStart(unsigned short int ulAppId, unsigned short int ulInstanceId,
			 unsigned int ulTmOutVal, unsigned int ulCbArg1, unsigned int ulCbArg2,
			 unsigned int ulCbArg3, unsigned int ulCbArg4)
{
	struct asfTmrWheelInstance_s *pWheel;
	struct asfTmrWheelPerCore_s *pTmrWheel;
	asfTmr_t *ptmr;
	char bHeap;
	bool bInInterrupt = in_softirq();
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());

	asf_timer_debug("TimerStart AppId %d InstId %d TOut %d carg1 %d carg2 %d\n",
			ulAppId, ulInstanceId, ulTmOutVal, ulCbArg1, ulCbArg2);

	if (!bInInterrupt)
		local_bh_disable();

	/* Allocate the timer object */
	ptmr = asfGetNode(pAsfTmrAppInfo[ulAppId].pInstance[ulInstanceId].ulTmrPoolId, &bHeap);
	if (ptmr) {
		ptmr->bHeap = bHeap;
	} else {
		asf_timer_debug("Timer allocation failed\r\n");
		if (!bInInterrupt)
			local_bh_enable();
		gstats->ulErrAllocFailures++;
		return NULL;
	}

	/* Timer Object initialization */
	ptmr->bHeap = bHeap;
	ptmr->ulState = ASF_TMR_STARTED;
	ptmr->ulCoreId = smp_processor_id();
	ptmr->ulCbInfo[0] = ulCbArg1;
	ptmr->ulCbInfo[1] = ulCbArg2;
	ptmr->ulCbInfo[2] = ulCbArg3;
	ptmr->ulCbInfo[3] = ulCbArg4;
	ptmr->ulPoolId = pAsfTmrAppInfo[ulAppId].pInstance[ulInstanceId].ulTmrPoolId;
	ptmr->ulTmOutVal = ulTmOutVal;

	pWheel = &(pAsfTmrWheelInstances[ulAppId].pWheel[ulInstanceId]);
	pTmrWheel = per_cpu_ptr(pWheel->pTmrWheel, smp_processor_id());

	ptmr->ulTmOutVal = (ptmr->ulTmOutVal + pWheel->ulHalfInterBucketGap)/pWheel->ulInterBucketGap;
	asf_timer_debug("ptmr->ulTmOutVal = %d\r\n", ptmr->ulTmOutVal);
#if 1
	if (ptmr->ulTmOutVal >= pTmrWheel->ulMaxBuckets) {
		asf_timer_debug("Given timer value %d does not fit into any bucket: Using Max %d possible!\n",
				ptmr->ulTmOutVal, pTmrWheel->ulMaxBuckets);
		ptmr->ulTmOutVal = pTmrWheel->ulMaxBuckets-1;
		gstats->ulMiscFailures++;
	}
#else
	if (ptmr->ulTmOutVal > pTmrWheel->ulMaxBuckets) {
		asf_timer_debug("Given timer value does not fit into any bucket: ulTmOutVal =%d, \r\n",
				ptmr->ulTmOutVal);
		asfReleaseNode(pAsfTmrAppInfo[ulAppId].pInstance[ulInstanceId].ulTmrPoolId, ptmr, bHeap);
		if (!bInInterrupt)
			local_bh_enable();
		gstats->ulMiscFailures++;
		return NULL;
	}
#endif
	ptmr->ulBucketIndex  = (pTmrWheel->ulCurBucketIndex + 1 + ptmr->ulTmOutVal) & (pTmrWheel->ulMaxBuckets - 1);
	asf_timer_debug("ulBucketIndex = %d\r\n", ptmr->ulBucketIndex);

	/* Add timer to the bucket  */
	asfAddTmrToBucket(pTmrWheel,  ptmr);
	if (!bInInterrupt)
		local_bh_enable();
	return ptmr;
}
EXPORT_SYMBOL(asfTimerStart);

/*
 * Stops the given timer if it can be stopped. Cases where it can't be stopped
  - Timer about to expire, In this case, bStopPeriodic is set
  - In case it can be stopped, if it is the same core context, it will be removed from queue.
  - Else, it is added to the appropriate core's reclaim queue
 */

unsigned int asfTimerStop(unsigned int ulAppId, unsigned int ulInstanceId,
			  asfTmr_t *ptmr)
{
	struct asfTmrWheelInstance_s *pWheel;
	struct asfTmrWheelPerCore_s *pTmrWheel;
	struct asfTmrRQ_s *pRq;
	unsigned int ulDiff;
	bool bInProcess;
	bool bInInterrupt = in_softirq();

	asf_timer_debug("TimerStop: AppId %d InstId %d ptmr 0x%x\n", ulAppId, ulInstanceId, ptmr);

	if (!bInInterrupt)
		local_bh_disable();

	if (ptmr->ulState == ASF_TMR_STOPPED) {
		asf_timer_debug("Timer already stopped\n");
		if (!bInInterrupt)
			local_bh_enable();
		return ASF_TMR_FAILURE;
	}

	pWheel = &(pAsfTmrWheelInstances[ulAppId].pWheel[ulInstanceId]);
	pTmrWheel = per_cpu_ptr(pWheel->pTmrWheel, ptmr->ulCoreId);

	ulDiff = (ptmr->ulBucketIndex >= pTmrWheel->ulCurBucketIndex) ?
		 (ptmr->ulBucketIndex - pTmrWheel->ulCurBucketIndex) :
		 (pTmrWheel->ulMaxBuckets - pTmrWheel->ulCurBucketIndex) + ptmr->ulBucketIndex;

	bInProcess = ptmr->ulState & ASF_TMR_Q_IN_PROCESS;

	if ((ulDiff < ASF_TMR_NEXT_FEW_BUCKETS) || (bInProcess)) {
		asf_timer_debug("Timer to expire soon\n");
		ptmr->bStopPeriodic  = 1;
		if (!bInInterrupt)
			local_bh_enable();
		return ASF_TMR_FAILURE;
	}

	/* Else check if the the bucket belongs to this CPU */
	if (ptmr->ulCoreId == smp_processor_id()) {
		/* Feel free to fix the list */
		asfRemoveTmrFromBucket(pTmrWheel,  ptmr);
		asf_timer_debug("Removed timer from bucket... Calling asfReleaseNode\n");
		asfReleaseNode(pAsfTmrAppInfo[ulAppId].pInstance[ulInstanceId].ulTmrPoolId, ptmr, ptmr->bHeap);

	} else {
		/* Push into the reclaim queue if there is space */
		/* Find my core's Rq in the pTmrWheel pTmWheel is already the wheel used
		   by core that owns this timer */
		pRq = per_cpu_ptr(pTmrWheel->pQs, smp_processor_id());

		if (unlikely(pRq->pQueue[pRq->ulWrIndex] != NULL)) {
			asf_timer_debug("******* No space in reclaim queue; letting timer expire by itself\r\n");
			ptmr->bStopPeriodic = 1; /* avoid callback function call upon expiry */
			if (!bInInterrupt)
				local_bh_enable();
			return ASF_TMR_FAILURE;
		}
		pRq->pQueue[pRq->ulWrIndex] = ptmr;
		pRq->ulWrIndex = (pRq->ulWrIndex + 1) & (pTmrWheel->ulMaxRqEntries - 1);
	}
	if (!bInInterrupt)
		local_bh_enable();
	return ASF_TMR_SUCCESS;
}

EXPORT_SYMBOL(asfTimerStop);

#if 0 /* Currently we don't support restart  */
unsigned int asfTimerRestart(unsigned int ulAppId,
			     unsigned int ulInstanceId, asfTmr_t *ptmr)
{

	struct asfTmrWheelInstance_s *pWheel;
	struct asfTmrWheelPerCore_s *pTmrWheel;
	struct asfTmrRQ_s *pRq;
	unsigned int ulDiff;
	bool bInProcess;
	bool bInInterrupt = in_softirq();
	unsigned int ulTmrVal = (ptmr->ulTimeOutVal + pWheel->ulHalfInterBucketGap)/pWheel->ulInterBucketGap;

	if (!bInInterrupt)
		local_bh_disable();

	if (ulTmrVal > pTmrWheel->ulMaxBuckets) {
		asf_timer_debug("Restart failed: as tmr value exceeds time span in the timer\r\n");
		if (!bInInterrupt)
			local_bh_enable();
		return ASF_TMR_FAILURE;
	}

	pWheel = &(pAsfTmrWheelInstances[ulAppId].pWheel[ulInstanceId]);
	pTmrWheel = per_cpu_ptr(pWheel->pTmrWheel, ptmr->ulCoreId);

	ulDiff = (ptmr->ulBucket > pTmrWheel->ulCurBucketIndex) ?
		 (ptmr->ulBucket - pTmrWheel->ulCurBucketIndex) :
		 (pTmrWheel->ulNumBuckets - pTmrWheel->ulCurBucketIndex) + ptmr->ulBucket;

	bInProcess = ptmr->ulState & ASF_TMR_Q_IN_PROCESS;

	if (bInProcess) {
		asf_timer_debug("Timer expiry under progress soon\r\n");

		if ((ulDiff < ASF_TMR_NEXT_BUCKET) || (bInProcess)) {
			asf_timer_debug("Timer to expire soon\r\n");
			ptmr->ulState = (ptmr->ulState & (ASF_TMR_Q_IN_PROCESS) | ASF_TMR_STOPPED);
			if (!bInInterrupt)
				local_bh_enable();
			return ASF_TMR_FAILURE;
		} else {
			ptmr->ulState = (bInProcess | ASF_TMR_RESTARTED);
			ptmr->ulNextBucketIndex  = (pTmrWheel->ulCurBucketIndex + ptmr->ulTmOutVal) & (pTmrWheel->ulMaxBuckets - 1);
		}
		if (!bInInterrupt)
			local_bh_enable();
		return ASF_TMR_SUCCESS;

	}
}
#endif

/*
 * Function Name : asfTimerDelete
 * Input: pData - pointer to tmr data structure
 * Description: This routine is called from rcu callbacks after suff. time, to actually free the node
 *	RCU is used so that, if there is any race condition between callback issued and at the
 *	same time, timer is stopped.
 */

void asfTimerDelete(struct rcu_head *pData)
{
	asfTmr_t *ptmr;
	ptmr = (asfTmr_t *)  pData;
	asfReleaseNode(ptmr->ulPoolId, ptmr, ptmr->bHeap);
}

/*
 * Actual processing function:
 * Input: data : MSB 16 bits = AppId, LSB 16 bits = Instance Id
 * Find the wheel based on that, and current core ID
 * Update the bucket index
 * For expired entires, call the callback function, restart the timer
 * go through the Reclaim queue that may have been filled by other cores and clean up
 * restart its timer by calling add_timer
 */
unsigned int ulLastTimerExpiry[NR_CPUS];
static void asfTimerProc(unsigned long data)
{
	unsigned short int ulAppId = ((unsigned int)(data) & 0xffff0000) >> 16;
	unsigned short int ulInstanceId = (unsigned int)data & 0xffff;
	struct asfTmrWheelInstance_s *pWheel =
		&(pAsfTmrWheelInstances[ulAppId].pWheel[ulInstanceId]);
	struct asfTmrWheelPerCore_s *pTmrWheel;
	struct asfTmrRQ_s *pRq;
	unsigned long old_state, new_state;
	asfTmr_t *pNextTmr, *ptmr;
	int ii;

	asf_timer_debug("Entering CPU %d ulAppId=%d, ulInstanceId =%d data=%d",
			smp_processor_id(), ulAppId, ulInstanceId, data);

	pTmrWheel = per_cpu_ptr(pWheel->pTmrWheel, smp_processor_id());

	pTmrWheel->ulCurBucketIndex =
		(pTmrWheel->ulCurBucketIndex + 1) & (pTmrWheel->ulMaxBuckets - 1);

#ifdef ASF_TIMER_DEBUG
	asf_timer_debug("Current jiffies = %d, next expiry = %d, ulCurBucketIndex=%d",
		jiffies, jiffies+pWheel->ulTimerInterval, pTmrWheel->ulCurBucketIndex);

	if (ulLastTimerExpiry[smp_processor_id()] == 0) {
		ulLastTimerExpiry[smp_processor_id()] = jiffies;
	} else {
		asf_timer_debug("Last Timer expiry = %d, Time Now in jiffies = %d"\
			": Next time expiry interval = %d",
			ulLastTimerExpiry[smp_processor_id()],
			jiffies, pWheel->ulTimerInterval);
		ulLastTimerExpiry[smp_processor_id()] = jiffies;
	}
#endif

	asf_timer_debug("Timer Bucket processing: ulCurBucketIndex = %d",
		pTmrWheel->ulCurBucketIndex);
	ptmr = pTmrWheel->pBuckets[pTmrWheel->ulCurBucketIndex];

#ifdef ASF_TIMER_DEBUG
	if (ptmr != NULL)
		asf_timer_debug("ptmr = 0x%x, pTmrWheel->pBuckets["\
		"pTmrWheel->ulCurBucketIndex] = 0x%x, bucket_index = %d",
		ptmr, pTmrWheel->pBuckets[pTmrWheel->ulCurBucketIndex],
		pTmrWheel->ulCurBucketIndex);
#endif
	pTmrWheel->pBuckets[pTmrWheel->ulCurBucketIndex] = NULL;
	for (pNextTmr = NULL; ptmr != NULL; ptmr = pNextTmr) {
		pNextTmr = ptmr->pNext;
		while (1) {
			old_state = ptmr->ulState;
			new_state = old_state | (ASF_TMR_Q_IN_PROCESS);
			if (unlikely(cmpxchg(&(ptmr->ulState), old_state, new_state)
				!= old_state)) {
				continue;
			} else
				break;
		}

		asf_timer_debug("About to invoke timer cbk. in_progress? %d",
			(ptmr->ulState & ASF_TMR_Q_IN_PROCESS));

		asf_timer_debug("Calling Callback function 0x%x",
			pAsfTmrAppInfo[ulAppId].pInstance[ulInstanceId].pFn);
		/* If this function returns 1, then stop the periodic tmr */
		if (!(ptmr->bStopPeriodic) &&
			(!pAsfTmrAppInfo[ulAppId].pInstance[ulInstanceId].pFn(
				ptmr->ulCbInfo[0], ptmr->ulCbInfo[1],
				ptmr->ulCbInfo[2], ptmr->ulCbInfo[3])) &&
				!(ptmr->bStopPeriodic)) {
			asf_timer_debug("Restarting timer 0x%x, stop-periodic %d",
					ptmr, ptmr->bStopPeriodic);
			ptmr->ulBucketIndex =
				(pTmrWheel->ulCurBucketIndex + ptmr->ulTmOutVal)
				& (pTmrWheel->ulMaxBuckets - 1);
			asfAddTmrToBucket(pTmrWheel, ptmr);

			while (1) {
				old_state = ptmr->ulState;
				new_state = ASF_TMR_STARTED;
				if (unlikely(cmpxchg(&(ptmr->ulState),
					old_state, new_state) != old_state)) {
					continue;
				} else
					break;
			}
		} else {
			asf_timer_debug("ptmr 0x%x free: either tmr cbk asked for "/
				"deletion or deletion occurred on another cpu (stop %d)",
				ptmr, ptmr->bStopPeriodic);
			/* Release to the memory pool */
			/* invoke call_rcu, it can be released later */
			call_rcu((struct rcu_head *)  ptmr,  asfTimerDelete);


		}
	}
	asf_timer_debug("Reclamation Q processing:\r\n");
	/* Process the reclamation queue */
	for_each_possible_cpu(ii)
	{
		pRq = per_cpu_ptr(pTmrWheel->pQs, ii);

		while (1) {
			ptmr = pRq->pQueue[pTmrWheel->ulRqRdIndex[ii]];
			if (ptmr != NULL) {
				asfRemoveTmrFromBucket(pTmrWheel, ptmr);
				asfReleaseNode(pAsfTmrAppInfo[ulAppId].pInstance[
					ulInstanceId].ulTmrPoolId, ptmr, ptmr->bHeap);
				pRq->pQueue[pTmrWheel->ulRqRdIndex[ii]] = NULL;
				pTmrWheel->ulRqRdIndex[ii] =
					(pTmrWheel->ulRqRdIndex[ii] + 1)
					& (pTmrWheel->ulMaxRqEntries - 1);
			} else
				break;
		}
	}
	/* this interval is set to zero while ASF is being removed */
	if (pWheel->ulTimerInterval) {
		pTmrWheel->timer.expires = jiffies + pWheel->ulTimerInterval;
		add_timer(&pTmrWheel->timer);
	} else {
		asf_timer_debug("Not rescheduling timer. cpu=%d, appId %d instId %d",
		smp_processor_id(), ulAppId, ulInstanceId);
	}
}


