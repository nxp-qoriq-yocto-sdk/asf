/**************************************************************************
 * Copyright 2009-2010 by Freescale Semiconductor, Inc.
 * All modifications are confidential and proprietary information
 * of Freescale Semiconductor, Inc. ALL RIGHTS RESERVED.
 ***************************************************************************/
/*
 * File:	asfreasm.c
 * Description: Contains the reassembly/fragmentation function
 * and macro definations for ASF
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/

/*******************Include files ************************************************/
#ifndef _ASF_REASM_H
#define _ASF_REASM_H


int asfReasmInit(void);
void asfReasmDeInit(void);

void asfReasmInitConfig(void);

#endif
