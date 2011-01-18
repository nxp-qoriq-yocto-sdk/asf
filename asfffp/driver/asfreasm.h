/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
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
