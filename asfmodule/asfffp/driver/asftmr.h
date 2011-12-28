/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asftmr.h
 * Description: Contains application specific fast path timer definations
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
 /****************************************************************************/

#ifndef _ASF_TMR_H
#define _ASF_TMR_H

#define NUM_APP_CB_INFO	5

typedef unsigned int (*asfTmrCbFn)(unsigned int , unsigned int, unsigned int , unsigned int, unsigned int);


struct asfTmr_s {
	struct rcu_head rcu;
	struct asfTmr_s *pNext;
	struct asfTmr_s *pPrev;
	unsigned long ulState;
	unsigned short int ulCoreId;
	unsigned int ulBucketIndex;
	unsigned int ulPoolId;
	unsigned int ulTmOutVal;
	char bHeap;
	bool bStopPeriodic ; /* 0 - by default, all timers are periodic, 1 means stop the periodic timer */
	unsigned int ulCbInfo[NUM_APP_CB_INFO];
} ;

typedef struct asfTmr_s asfTmr_t;

#define ASF_TMR_TYPE_MS_TMR	0
#define ASF_TMR_TYPE_SEC_TMR	1
#define ASF_TMR_TYPE_MIN_TMR	2


unsigned int asfTimerInit(unsigned short int ulMaxApps,
			  unsigned short int ulMaxTmrWheelInstancePerApp);

unsigned int asfTimerAppRegister(unsigned short int ulAppId,
				 unsigned short int ulTmrInstanceId, asfTmrCbFn pFn,
				 unsigned int ulPoolId);

void asfTimerDisableKernelTimers(void);
void asfTimerFreeNodeMemory(asfTmr_t *tmr);
void  asfTimerDeInit(void);

unsigned int asfTimerWheelInit(unsigned short int ulAppId,
			       unsigned short int ulInstanceId,  unsigned int ulNumBuckets,
			       unsigned char ucTmrType, unsigned int ulInterBucketTmrGap,
			       unsigned int ulNumRQEntries);

unsigned int asfTimerWheelDeInit(unsigned short int ulAppId, unsigned  short int ulInstanceId);

asfTmr_t  *asfTimerStart(unsigned short int ulAppId, unsigned short int ulInstanceId,
			 unsigned int ulTmOutVal, unsigned int ulCbArg1, unsigned int ulCbArg2,
			 unsigned int ulCbArg3, unsigned int ulCbArg4, unsigned int ulCbArg5);

unsigned int asfTimerStop(unsigned int ulAppId, unsigned int ulInstanceId,
			  asfTmr_t *ptmr);
#endif
