/* Copyright (C) 2009-2010 Freescale Semiconductor, Inc. All Rights Reserved.
 *
 * File:	ipsfpapi.c
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

#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <linux/if_bridge.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include "../../asfffp/driver/asf.h"
#include "../../asfffp/driver/asfparry.h"
#include "../../asfffp/driver/asftmr.h"
#include "../../asfffp/driver/asfcmn.h"
#include "ipsfpapi.h"
#include "ipsecfp.h"

int  ulMaxVSGs_g = ASF_MAX_VSGS;
int  ulMaxTunnels_g = SECFP_MAX_NUM_TUNNEL_IFACES;
int  ulMaxSPDContainers_g = SECFP_MAX_SPD_CONTAINERS;
int  ulMaxSupportedIPSecSAs_g = SECFP_MAX_SAS;
int  usMaxInSAHashTaleSize_g = SECFP_INSA_HASH_TABLE_SZE;
int  ulL2BlobRefreshPktCnt_g = ASF_MAX_L2BLOB_REFRESH_PKT_CNT;
int  ulL2BlobRefreshTimeInSec_g = ASF_MAX_L2BLOB_REFRESH_TIME;
int  bFirewallCoExistence_g = ASF_TRUE;
int  bTightlyIntegrated_g = ASF_TRUE;
ASF_boolean_t  bNotifyPreference_g = ASF_FALSE;

ASFIPSecGlobalErrorCounters_t  GlobalErrors;
ASFIPSecCbFn_t     ASFIPSecCbFn;

/* Macro to validate VSGId*/
#define SECFP_IS_VSG_ID_INVALID(ulVSGId) \
	if (ulVSGId >= ulMaxVSGs_g)

/* Macro to validate Tunnel Id */
#define SECFP_IS_TUNNEL_ID_INVALID(ulTunnelId) \
	if (ulTunnelId >= ulMaxTunnels_g)

/* Macro to validate SPD Container Id */
#define SECFP_IS_SPD_CONTAINER_ID_INVALID(ulSDContainerId) \
	if (ulSDContainerId >= ulMaxSPDContainers_g)

/* Macro to validate Magic Number */
#define SECFP_IS_MAGICNUMBER_INVALID(ulMagicNumber) \
	if (ulMagicNumber == 0)


extern ptrIArry_tbl_t secfp_InDB;
extern ptrIArry_tbl_t secfp_OutDB;
extern ptrIArry_tbl_t secFP_OutSATable;
extern AsfIPSecPPGlobalStats_t IPSecPPGlobalStats_g[];
extern AsfIPSec4GlobalPPStats_t IPSec4GblPPStats_g;
extern   inSAList_t *secFP_SPIHashTable;
extern SecTunnelIface_t **secFP_TunnelIfaces;
extern spinlock_t secfp_TunnelIfaceCIIndexListLock;

extern unsigned int    *pulVSGMagicNumber;
extern unsigned int  **pulTunnelMagicNumber;
extern unsigned int ulTimeStamp_g;
extern void secfp_removeCINodeFromTunnelList(unsigned int ulVSGId,
					     unsigned int ulTunnelId,  struct SPDCILinkNode_s *pCINode, bool bDir);
static unsigned int secfp_copySAParams(ASF_IPSecSA_t *pASFSAParams,
				       SAParams_t    *pSAParams);
unsigned int secfp_copySrcAndDestSelSet(
				       SASel_t	       **pSrcSel,
				       SASel_t	       **pDstSel,
				       ASF_IPSecSASelector_t   *pSASel,
				       unsigned char	   *pucSelFlags);

void secfp_freeSelSet(SASel_t  *pSel);

ASF_void_t ASFIPSecConfig(ASF_uint32_t   ulVSGId,
			  int	    cmd,
			  ASF_void_t    *pArgs,
			  ASF_uint32_t   ulArgsLen,
			  ASF_void_t    *pReqIdentifier,
			  ASF_uint32_t   ulReqIdentifierlen)
{
	int ret;

	/* Validate input parameters */
	if (pArgs == NULL) {
		ASFIPSEC_DEBUG("Input argument is null");
		return ;
	}

	SECFP_IS_VSG_ID_INVALID(ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", ulVSGId);
		ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
				       pReqIdentifier,
				       ulReqIdentifierlen,
				       ASF_IPSEC_INVALID_VSG_ID);
		return;
	}


	switch (cmd) {
	case ASF_IPSEC_CONFIG_ADD_OUTSPDCONTAINER: /* Adding Out SPD Container*/
		{
			ASFIPSecConfigAddOutSPDContainerArgs_t *pAddSPDContainer;
			SPDOutParams_t SPDParams;

			pAddSPDContainer = (ASFIPSecConfigAddOutSPDContainerArgs_t *)  pArgs;
			memset(&SPDParams, 0, sizeof(SPDOutParams_t));

			SECFP_IS_TUNNEL_ID_INVALID(pAddSPDContainer->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n",
					       pAddSPDContainer->ulTunnelId);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_TUNNEL_ID);
				return;
			}

			SECFP_IS_SPD_CONTAINER_ID_INVALID(pAddSPDContainer->ulSPDContainerIndex)
			{
				GlobalErrors.ulInvalidOutSPDContainerId++;
				ASFIPSEC_DEBUG("Invalid Container Id = %u\r\n",
					       pAddSPDContainer->ulSPDContainerIndex);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_CONTAINER_ID);
				return;
			}

			SECFP_IS_MAGICNUMBER_INVALID(pAddSPDContainer->ulMagicNumber)
			{
				GlobalErrors.ulInvalidMagicNumber++;
				ASFIPSEC_DEBUG("Invalid Magic Number = %u\r\n",
					       pAddSPDContainer->ulMagicNumber);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd,
					SECFP_FAILURE, pReqIdentifier,
					ulReqIdentifierlen,
					ASF_IPSEC_INVALID_MAGIC_NUMBER);
				return;
			}
			if (pAddSPDContainer->pSPDParams &&
			pAddSPDContainer->pSPDParams->dscpRange)
					SPDParams.bOnlySaPerDSCP = 1;

			ret = secfp_SPDOutContainerCreate(ulVSGId,
					pAddSPDContainer->ulTunnelId,
					pAddSPDContainer->ulSPDContainerIndex,
					pAddSPDContainer->ulMagicNumber,
					&SPDParams);
			if (ret != SECFP_SUCCESS) {
				ASFIPSEC_DEBUG("secfp_SPDOutContainerCreate"\
					"returned failure - ret = %d\r\n", ret);
				ASFIPSecCbFn.pFnConfig(ulVSGId,
					cmd, SECFP_FAILURE, pReqIdentifier,
					ulReqIdentifierlen, ret);
				return;
			} else {
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd,
					SECFP_SUCCESS, pReqIdentifier,
					ulReqIdentifierlen, 0);
				ASFIPSEC_DEBUG("secfp_SPDOutContainerCreate"\
					"returned success");
				return;
			}
		}
		break;
	case ASF_IPSEC_CONFIG_ADD_INSPDCONTAINER: /* Adding In SPD Container*/
		{
			ASFIPSecConfigAddInSPDContainerArgs_t *pAddSPDContainer;
			SPDInParams_t SPDParams;

			pAddSPDContainer = (ASFIPSecConfigAddInSPDContainerArgs_t *)  pArgs;
			memset(&SPDParams, 0, sizeof(SPDParams));

			SECFP_IS_TUNNEL_ID_INVALID(pAddSPDContainer->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n",
					       pAddSPDContainer->ulTunnelId);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_TUNNEL_ID);
				return;
			}

			SECFP_IS_SPD_CONTAINER_ID_INVALID(pAddSPDContainer->ulSPDContainerIndex)
			{
				GlobalErrors.ulInvalidOutSPDContainerId++;
				ASFIPSEC_DEBUG("Invalid Container Id = %u\r\n",
					       pAddSPDContainer->ulSPDContainerIndex);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_CONTAINER_ID);
				return;
			}

			SECFP_IS_MAGICNUMBER_INVALID(pAddSPDContainer->ulMagicNumber)
			{
				GlobalErrors.ulInvalidMagicNumber++;
				ASFIPSEC_DEBUG("Invalid Magic Number = %u\r\n",
					       pAddSPDContainer->ulMagicNumber);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_MAGIC_NUMBER);
				return;
			}

			ret = secfp_SPDInContainerCreate(ulVSGId,
							 pAddSPDContainer->ulTunnelId,
							 pAddSPDContainer->ulSPDContainerIndex,
							 pAddSPDContainer->ulMagicNumber,
							 &SPDParams);
			if (ret != SECFP_SUCCESS) {
				ASFIPSEC_WARN("secfp_SPDInContainerCreate returned failure - ret = %d\r\n", ret);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen, ret);
				return;
			} else {
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_SUCCESS,
						       pReqIdentifier, ulReqIdentifierlen, 0);
				ASFIPSEC_DEBUG("secfp_SPDInContainerCreate returned success");
				return;
			}
		}
		break;
	case ASF_IPSEC_CONFIG_DEL_OUTSPDCONTAINER: /* Deleting Out SPD Container*/
		{
			ASFIPSecConfigDelOutSPDContainerArgs_t *pDelSPDContainer;

			pDelSPDContainer = (ASFIPSecConfigDelOutSPDContainerArgs_t *)  pArgs;

			SECFP_IS_TUNNEL_ID_INVALID(pDelSPDContainer->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n",
					       pDelSPDContainer->ulTunnelId);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier,
						       ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_TUNNEL_ID);
				return;
			}

			SECFP_IS_SPD_CONTAINER_ID_INVALID(pDelSPDContainer->ulContainerIndex)
			{
				GlobalErrors.ulInvalidOutSPDContainerId++;
				ASFIPSEC_DEBUG("Invalid Container Id = %u\r\n",
					       pDelSPDContainer->ulContainerIndex);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier,
						       ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_CONTAINER_ID);
				return;
			}

			SECFP_IS_MAGICNUMBER_INVALID(pDelSPDContainer->ulMagicNumber)
			{
				GlobalErrors.ulInvalidMagicNumber++;
				ASFIPSEC_DEBUG("Invalid Magic Number = %u\r\n",
					       pDelSPDContainer->ulMagicNumber);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_MAGIC_NUMBER);
				return;
			}

			ret = secfp_SPDOutContainerDelete(ulVSGId,
							  pDelSPDContainer->ulTunnelId,
							  pDelSPDContainer->ulContainerIndex,
							  pDelSPDContainer->ulMagicNumber);
			if (ret != SECFP_SUCCESS) {
				ASFIPSEC_DEBUG("secfp_SPDOutContainerDelete returned failure - ret = %d\r\n", ret);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier, ulReqIdentifierlen, ret);
				return;
			} else {
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_SUCCESS,
						       pReqIdentifier, ulReqIdentifierlen, 0);
				ASFIPSEC_DEBUG("secfp_SPDOutContainerDelete returned success");
				return;
			}
		}
		break;
	case ASF_IPSEC_CONFIG_DEL_INSPDCONTAINER: /* Deleting In SPD Container*/
		{
			ASFIPSecConfigDelInSPDContainerArgs_t *pDelSPDContainer;

			pDelSPDContainer = (ASFIPSecConfigDelInSPDContainerArgs_t *)  pArgs;

			SECFP_IS_TUNNEL_ID_INVALID(pDelSPDContainer->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n",
					       pDelSPDContainer->ulTunnelId);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier,
						       ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_TUNNEL_ID);
				return;

			}

			SECFP_IS_SPD_CONTAINER_ID_INVALID(pDelSPDContainer->ulContainerIndex)
			{
				GlobalErrors.ulInvalidOutSPDContainerId++;
				ASFIPSEC_DEBUG("Invalid Container Id = %u\r\n",
					       pDelSPDContainer->ulContainerIndex);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier,
						       ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_CONTAINER_ID);
				return;

			}

			SECFP_IS_MAGICNUMBER_INVALID(pDelSPDContainer->ulMagicNumber)
			{
				GlobalErrors.ulInvalidMagicNumber++;
				ASFIPSEC_DEBUG("Invalid Magic Number = %u\r\n",
					       pDelSPDContainer->ulMagicNumber);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier,
						       ulReqIdentifierlen,
						       ASF_IPSEC_INVALID_MAGIC_NUMBER);
				return;
			}

			ret = secfp_SPDInContainerDelete(ulVSGId,
							 pDelSPDContainer->ulTunnelId,
							 pDelSPDContainer->ulContainerIndex,
							 pDelSPDContainer->ulMagicNumber);
			if (ret != SECFP_SUCCESS) {
				ASFIPSEC_DEBUG("secfp_SPDInContainerDelete returned failure - ret = %d\r\n", ret);
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_FAILURE,
						       pReqIdentifier,
						       ulReqIdentifierlen, ret);
				return;

			} else {
				ASFIPSecCbFn.pFnConfig(ulVSGId, cmd, SECFP_SUCCESS,
						       pReqIdentifier, ulReqIdentifierlen, 0);
				ASFIPSEC_DEBUG("secfp_SPDInContainerDelete returned success");
				return;
			}
		}
		break;

	default:
		{
			ASFIPSEC_DEBUG("Invalid Command receivedi : Cmd = %d\r\n", cmd);

		}
	}
}

ASF_void_t ASFIPSecRuntime(ASF_uint32_t   ulVSGId,
			   int	      cmd,
			   ASF_void_t      *pArgs,
			   ASF_uint32_t     ulArgslen,
			   ASF_void_t    *pReqIdentifier,
			   ASF_uint32_t   ulReqIdentifierlen)
{
	ASFIPSEC_FENTRY;
	/* Validate input parameters */
	if (pArgs == NULL) {
		ASFIPSEC_DEBUG("Input argument is null");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", ulVSGId);
		return;
	}

	switch (cmd) {
	case ASF_IPSEC_RUNTIME_ADD_OUTSA: /* Adding OutSA */
		{
			ASFIPSecRuntimeAddOutSAArgs_t *pAddSA;
			SASel_t *pSrcSel, *pDstSel;
			SAParams_t SAParams;
			unsigned short int usDscpStart, usDscpEnd;
			unsigned char ucSelFlag = 0;

			pAddSA = (ASFIPSecRuntimeAddOutSAArgs_t *)  pArgs;
			memset(&SAParams, 0, sizeof(SAParams));
			SECFP_IS_TUNNEL_ID_INVALID(pAddSA->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u",
					pAddSA->ulTunnelId);
				return;
			}

			if (secfp_copySAParams(pAddSA->pSAParams,
					&SAParams) == SECFP_FAILURE) {
				ASFIPSEC_WARN("secfp_copySAParams returned failure");
				return;
			}

			if (secfp_copySrcAndDestSelSet(&pSrcSel, &pDstSel,
						       pAddSA->pSASelector,
						       &ucSelFlag) == SECFP_FAILURE) {
				ASFIPSEC_WARN("secfp_copySrcAndDestSelSet returned failure");
				return;
			}

			if (pAddSA->usDscpEnd) {
				ucSelFlag |= SECFP_SA_DSCP_SELECTOR;
				usDscpStart = pAddSA->usDscpStart;
				usDscpEnd = pAddSA->usDscpEnd;
			} else {
				usDscpStart = 0;
				usDscpEnd = 0;
			}

			if (secfp_createOutSA(ulVSGId, pAddSA->ulTunnelId,
					      pAddSA->ulSPDContainerIndex,
					      pAddSA->ulMagicNumber,
					      pSrcSel, pDstSel, ucSelFlag, &SAParams,
					      usDscpStart,
					      usDscpEnd, pAddSA->pSAParams->ulMtu) != SECFP_SUCCESS) {
				ASFIPSEC_WARN("secfp_createOutSA returned failure");
			}
			secfp_freeSelSet(pSrcSel);
			secfp_freeSelSet(pDstSel);
		}
		break;
	case ASF_IPSEC_RUNTIME_DEL_OUTSA: /* Deleting OutSA */
		{
			ASFIPSecRuntimeDelOutSAArgs_t *pDelSA;
			pDelSA = (ASFIPSecRuntimeDelOutSAArgs_t *)  pArgs;
			SECFP_IS_TUNNEL_ID_INVALID(pDelSA->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u", pDelSA->ulTunnelId);
				return;
			}
			if (secfp_DeleteOutSA(pDelSA->ulSPDContainerIndex,
					pDelSA->ulSPDMagicNumber,
					pDelSA->DestAddr.ipv4addr,
					pDelSA->ucProtocol,
					pDelSA->ulSPI,
					pDelSA->usDscpStart,
					pDelSA->usDscpEnd) !=
						SECFP_SUCCESS) {
				ASFIPSEC_WARN("secfp_DeleteOutSA returned failure");
			}
		}
		break;
	case ASF_IPSEC_RUNTIME_ADD_INSA: /* Adding InSA */
		{
			ASFIPSecRuntimeAddInSAArgs_t *pAddSA;
			SASel_t *pSrcSel, *pDstSel;
			SAParams_t SAParams;
			unsigned char ucSelFlag = 0;

			pAddSA = (ASFIPSecRuntimeAddInSAArgs_t *)  pArgs;
			SECFP_IS_TUNNEL_ID_INVALID(pAddSA->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pAddSA->ulTunnelId);
				return;
			}

			memset(&SAParams, 0, sizeof(SAParams));
			if (secfp_copySAParams(pAddSA->pSAParams,
					&SAParams) == SECFP_FAILURE) {
				ASFIPSEC_WARN("secfp_copySAParams returned failure");
				return;
			}

			if (secfp_copySrcAndDestSelSet(&pSrcSel, &pDstSel,
						       pAddSA->pSASelector,
						       &ucSelFlag) == SECFP_FAILURE) {
				ASFIPSEC_WARN("secfp_copySrcAndDestSelSet returned failure");
				return;
			}

			if (secfp_CreateInSA(ulVSGId,
					     pAddSA->ulTunnelId,
					     pAddSA->ulInSPDContainerIndex,
					     pAddSA->ulInSPDMagicNumber,
					     pSrcSel, pDstSel, ucSelFlag, &SAParams,
					     pAddSA->ulOutSPDContainerIndex,
					     pAddSA->ulOutSPI) != SECFP_SUCCESS) {
				ASFIPSEC_WARN("secfp_CreateInSA returned failure");
			}
			secfp_freeSelSet(pSrcSel);
			secfp_freeSelSet(pDstSel);
		}
		break;
	case ASF_IPSEC_RUNTIME_DEL_INSA: /* Deleting InSA */
		{
			ASFIPSecRuntimeDelInSAArgs_t *pDelSA;
			pDelSA = (ASFIPSecRuntimeDelInSAArgs_t *)  pArgs;
			SECFP_IS_TUNNEL_ID_INVALID(pDelSA->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pDelSA->ulTunnelId);
				return;
			}

			if (secfp_DeleteInSA(ulVSGId,
					     pDelSA->ulSPDContainerIndex,
					     pDelSA->ulSPDMagicNumber,
					     pDelSA->DestAddr.ipv4addr,
					     pDelSA->ucProtocol,
					     pDelSA->ulSPI) != SECFP_SUCCESS) {
				ASFIPSEC_WARN("secfp_DeleteInSA returned failure");
			}
		}
		break;
	case ASF_IPSEC_RUNTIME_MOD_OUTSA:
		{
			ASFIPSecRuntimeModOutSAArgs_t *pModSA;
			pModSA = (ASFIPSecRuntimeModOutSAArgs_t *)  pArgs;
			SECFP_IS_TUNNEL_ID_INVALID(pModSA->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pModSA->ulTunnelId);
				return;
			}
			if (secfp_ModifyOutSA(ulVSGId, pModSA) == SECFP_FAILURE) {
				ASFIPSEC_WARN("secfp_ModifyOutSA returned failure");
			}
		}
		break;
	case ASF_IPSEC_RUNTIME_MOD_INSA:
		{
			ASFIPSecRuntimeModInSAArgs_t *pModSA;
			pModSA = (ASFIPSecRuntimeModInSAArgs_t *)  pArgs;
			SECFP_IS_TUNNEL_ID_INVALID(pModSA->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pModSA->ulTunnelId);
				return;
			}
			if (secfp_ModifyInSA(ulVSGId, pModSA) != SECFP_SUCCESS) {
				ASFIPSEC_WARN("secfp_ModifyInSA returned failure");
			}
		}
		break;
	case ASF_IPSEC_RUNTIME_SET_DPD_INSA: /* Setting DPD in InSA */
		{
			ASFIPSecRuntimeSetDPDArgs_t *pSetDPD;
			pSetDPD = (ASFIPSecRuntimeSetDPDArgs_t *) pArgs;
			SECFP_IS_TUNNEL_ID_INVALID(pSetDPD->ulTunnelId)
			{
				GlobalErrors.ulInvalidTunnelId++;
				ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pSetDPD->ulTunnelId);
				return;
			}

			if (secfp_SetDPDInSA(ulVSGId, pSetDPD) != SECFP_SUCCESS) {
				ASFIPSEC_WARN("secfp_SetDPD returned failure");
			}
		}
		break;
	default:
		{
			ASFIPSEC_DEBUG("Invalid Command = %d\r\n", cmd);
		}
	}
	ASFIPSEC_FEXIT;
	return;
}

ASF_void_t ASFIPSecGetCapabilities(ASFIPSecCap_t *pCap)
{
	ASFIPSEC_FENTRY;

	if (pCap) {

		pCap->bSelStoreInSPD = 0; /* Selector storage in SPD not supported */

		pCap->bAH = 0; /* AH protocol not supported */
		pCap->bESP = 1;	/* ESP protocol supported */
		pCap->bIpComp = 0; /* IP Compression not supported */

		pCap->bTunnelMode = 1; /* Tunnel mode supported */
		pCap->bTransportMode = 0; /* Transport mode not supported */

		pCap->bEsn = 1;	/* ESN feature supported */
		pCap->bMultiSecProto = 0; /* Multi security protocol not supported */
		pCap->bLifeTimeKB = 0; /* Life Time in Kilo bytes not supported */
		pCap->bLifeTimeSec = 1;	/* Life Time in Seconds supported */
		pCap->bNATTraversal = 1; /* Nat traversal supported */
		pCap->bRedSideFragmentation = 1; /* Redside fragmentation supported */
		pCap->bPeerGWAdoption = 1; /* Peer gateway change adaption supported */
		pCap->bLocalGWAdoption = 1; /* Local gateway cghange adaption supported */

		pCap->ulFragOptions = 0; /* Fragmentation options not handled */

		/* Authentication algorithms MD5, SHA1 and AES_XBC are supported */
		pCap->AuthAlgoCap.bMD5 = 1;
		pCap->AuthAlgoCap.bSHA1 = 1;
		pCap->AuthAlgoCap.bAES_XBC = 1;

		/* Encryption algorithm DES, 3DES, AES and AES CTR are supported */
		pCap->EncryptAlgoCap.bDES = 1;
		pCap->EncryptAlgoCap.b3DES = 1;
		pCap->EncryptAlgoCap.bAES = 1;
		pCap->EncryptAlgoCap.bAES_CTR = 1;

		/* Modules parameters */
		pCap->ulMaxVSGs = ulMaxVSGs_g;
		pCap->ulMaxTunnels = ulMaxTunnels_g;
		pCap->ulMaxSPDContainers = ulMaxSPDContainers_g;
		pCap->ulMaxSupportedIPSecSAs = ulMaxSupportedIPSecSAs_g;

		pCap->bBufferHomogenous = 1; /* Homogenous buffer supported */

		ASFIPSEC_FEXIT;
		return;
	}
	ASFIPSEC_ERR("Invalid input arguments");
	return;
}

ASF_void_t  ASFIPSecUpdateVSGMagicNumber(ASFIPSecUpdateVSGMagicNumber_t *pVSGMagicInfo)
{
	if (pVSGMagicInfo == NULL) {
		ASFIPSEC_DEBUG("Input argument is null");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pVSGMagicInfo->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pVSGMagicInfo->ulVSGId);
		return;
	}
	pulVSGMagicNumber[pVSGMagicInfo->ulVSGId] = pVSGMagicInfo->ulVSGMagicNumber;
	ulTimeStamp_g++;
}

ASF_void_t  ASFIPSecUpdateTunnelMagicNumber(ASFIPSecUpdateTunnelMagicNumber_t *pTunnelMagicInfo)
{
	if (pTunnelMagicInfo == NULL) {
		ASFIPSEC_DEBUG("Input argument is null");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pTunnelMagicInfo->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pTunnelMagicInfo->ulVSGId);
		return;
	}

	SECFP_IS_TUNNEL_ID_INVALID(pTunnelMagicInfo->ulTunnelId)
	{
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pTunnelMagicInfo->ulTunnelId);
		return;
	}
	secFP_TunnelIfaces[pTunnelMagicInfo->ulVSGId][pTunnelMagicInfo->ulTunnelId].ulTunnelMagicNumber =
	pTunnelMagicInfo->ulTunnelMagicNumber;

	ulTimeStamp_g++;

}
/* Registering Callback functions */
ASF_uint32_t ASFIPSecRegisterCallbacks(ASFIPSecCbFn_t *pFnPtr)
{
	ASFIPSEC_DEBUG("Entry");
	if (pFnPtr) {
		ASFIPSecCbFn = *pFnPtr;
		ASFIPSEC_DEBUG("Exit");
		return SECFP_SUCCESS;
	}
	ASFIPSEC_DEBUG("pFnPtr is null");
	return SECFP_FAILURE;
}

static unsigned int secfp_copySAParams(ASF_IPSecSA_t *pASFSAParams,
				       SAParams_t    *pSAParams)
{
	if (pASFSAParams->authKey) {
		pSAParams->bAuth = TRUE;
		if (pASFSAParams->authAlgo == ASF_IPSEC_AALG_MD5HMAC) {
			pSAParams->ucAuthAlgo = SECFP_HMAC_MD5;
		} else if (pASFSAParams->authAlgo == ASF_IPSEC_AALG_SHA1HMAC) {
			pSAParams->ucAuthAlgo = SECFP_HMAC_SHA1;
		} else {
			pSAParams->ucAuthAlgo = SECFP_HMAC_AES_XCBC_MAC;
		}
		pSAParams->AuthKeyLen = pASFSAParams->authKeyLenBits/8;
		memcpy(pSAParams->ucAuthKey, pASFSAParams->authKey,
				pSAParams->AuthKeyLen);
	} else {
		pSAParams->ucAuthAlgo = SECFP_HMAC_NULL;
		pSAParams->bAuth = FALSE;
	}

	if (pASFSAParams->encDecKey) {
		pSAParams->bEncrypt = TRUE;
		if (pASFSAParams->encAlgo == ASF_IPSEC_EALG_DESCBC) {
			pSAParams->ucCipherAlgo = SECFP_DES;
			pSAParams->ulBlockSize = DES_CBC_BLOCK_SIZE;
			pSAParams->ulIvSize = DES_IV_LEN;
		} else if (pASFSAParams->encAlgo == ASF_IPSEC_EALG_3DESCBC) {
			pSAParams->ucCipherAlgo = SECFP_3DES;
			pSAParams->ulBlockSize = TDES_CBC_BLOCK_SIZE;
			pSAParams->ulIvSize = TDES_IV_LEN;
		} else if (pASFSAParams->encAlgo == ASF_IPSEC_EALG_AES) {
			pSAParams->ucCipherAlgo = SECFP_AES;
			pSAParams->ulBlockSize = AES_CBC_BLOCK_SIZE;
			pSAParams->ulIvSize = AES_CBC_IV_LEN;
		} else {
			pSAParams->ucCipherAlgo = SECFP_AESCTR;
			pSAParams->ulBlockSize = AES_CTR_BLOCK_SIZE;
			pSAParams->ulIvSize = AES_CTR_IV_LEN;
			memcpy(pSAParams->ucNounceIVCounter,
			       pASFSAParams->aesCtrCounterBlock, 16);
		}
		pSAParams->EncKeyLen = pASFSAParams->encDecKeyLenBits/8;
		memcpy(pSAParams->ucEncKey, pASFSAParams->encDecKey,
					pSAParams->EncKeyLen);
	} else {
		pSAParams->ucCipherAlgo = SECFP_ESP_NULL;
		pSAParams->bEncrypt = FALSE;
		pSAParams->ulBlockSize = 0;
		pSAParams->ulIvSize = 0;
	}

	pSAParams->bRedSideFragment = pASFSAParams->bRedSideFragment;

	pSAParams->bVerifyInPktWithSASelectors = pASFSAParams->bVerifyInPktWithSASelectors;
	pSAParams->bDoPeerGWIPAddressChangeAdaptation = pASFSAParams->bDoPeerGWIPAddressChangeAdaptation;
	pSAParams->bDoUDPEncapsulationForNATTraversal = pASFSAParams->bDoUDPEncapsulationForNATTraversal;
	pSAParams->bUseExtendedSequenceNumber = pASFSAParams->bUseExtendedSequenceNumber;
	pSAParams->bPropogateECN = pASFSAParams->bPropogateECN;
	pSAParams->bDoAntiReplayCheck = pASFSAParams->bDoAntiReplayCheck;
	pSAParams->bEncapsulationMode = pASFSAParams->bEncapsulationMode;
	pSAParams->ulSPI = pASFSAParams->spi;

	if (pASFSAParams->TE_Addr.IP_Version == 4) {
		pSAParams->tunnelInfo.bIPv4OrIPv6 = 0;
		pSAParams->tunnelInfo.addr.iphv4.saddr = pASFSAParams->TE_Addr.srcIP.ipv4addr;
		pSAParams->tunnelInfo.addr.iphv4.daddr = pASFSAParams->TE_Addr.dstIP.ipv4addr;
	} else {
		pSAParams->tunnelInfo.bIPv4OrIPv6 = 1;
	}

	if (pASFSAParams->handleToSOrDSCPAndFlowLabel == ASF_IPSEC_QOS_DSCP_COPY) {
		pSAParams->bCopyDscp = 1;
	} else if (pASFSAParams->handleToSOrDSCPAndFlowLabel == ASF_IPSEC_QOS_DSCP_SET) {
		pSAParams->bCopyDscp = 0;
		pSAParams->ucDscp =  pASFSAParams->qos;
	}

	if (pASFSAParams->protocol == ASF_IPSEC_PROTOCOL_ESP) {
		pSAParams->ucProtocol = SECFP_PROTO_ESP;
	} else {
		return SECFP_FAILURE;
	}
	pSAParams->AntiReplayWin = pASFSAParams->replayWindowSize;
	if (pASFSAParams->handleDFBit == ASF_IPSEC_DF_COPY) {
		pSAParams->handleDf = SECFP_DF_COPY;
	} else if (pASFSAParams->handleDFBit == ASF_IPSEC_DF_SET) {
		pSAParams->handleDf = SECFP_DF_SET;
	} else {
		pSAParams->handleDf = SECFP_DF_CLEAR;
	}
	pSAParams->ulCId = pASFSAParams->ulCommonInterfaceId;
	if (pASFSAParams->bDoUDPEncapsulationForNATTraversal) {
		pSAParams->IPsecNatInfo.ulNATt =  pASFSAParams->IPsecNatInfo.ulNATt;
		pSAParams->IPsecNatInfo.usSrcPort = pASFSAParams->IPsecNatInfo.usSrcPort;
		pSAParams->IPsecNatInfo.usDstPort = pASFSAParams->IPsecNatInfo.usDstPort;
	}
	return SECFP_SUCCESS;
}

ASF_void_t ASFIPSecSetNotifyPreference(ASF_boolean_t  bEnable)
{
	bNotifyPreference_g = bEnable;
	ASFIPSEC_DEBUG("NotifyPreference = %c\r\n", bNotifyPreference_g);
	return;
}
EXPORT_SYMBOL(ASFIPSecSetNotifyPreference);

ASF_void_t  ASFIPSecv4MapFlowToContainer(ASF_uint32_t ulVSGId,
					 ASF_IPAddr_t   srcAddr,
					 ASF_IPAddr_t   destAddr,
					 ASF_uint8_t ucProtocol,
					 ASF_uint16_t  srcPort,
					 ASF_uint16_t destPort,
					 ASF_uint32_t ulTunnelId,
					 ASF_uint8_t ucActionFlag, /*bIpsecInProcess:1, bIPsecOutProcess:1 */
					 ASFIPSecContainerInfo_t outContainer,
					 ASFIPSecContainerInfo_t inContainer
					)
{
	ASFIPSEC_WARN("Function not implemented");
}
EXPORT_SYMBOL(ASFIPSecv4MapFlowToContainer);

ASF_void_t ASFIPSecSPDContainerQueryStats(ASFIPSecGetContainerQueryParams_t *pInParams,
					  ASFSPDPolPPStats_t *pOutParams)
{
	ASF_uint32_t ii, Index;
	SPDOutContainer_t *pOutContainer = NULL;
	SPDInContainer_t  *pInContainer = NULL;
	SPDOutSALinkNode_t *pOutSALinkNode;
	SPDInSPIValLinkNode_t *pNode;
	outSA_t *pOutSA, *pOldSA = NULL;
	inSA_t *pSA;
	SECFP_IS_VSG_ID_INVALID(pInParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pInParams->ulVSGId);
		return;
	}
	if (pInParams->bDir == SECFP_IN) {
		pInContainer  = (SPDInContainer_t *)  (ptrIArray_getData(&(secfp_InDB),
								       pInParams->ulSPDContainerIndex));
		if (!pInContainer)
			return;
		for (pNode = pInContainer->pSPIValList; pNode != NULL; pNode = pNode->pNext) {
			ASF_uint32_t  hashVal = secfp_compute_hash(pNode->ulSPIVal);
			for (pSA = secFP_SPIHashTable[hashVal].pHeadSA;
			    pSA != NULL; pSA = pSA->pNext) {
				rcu_read_lock();
				for (Index = 0; Index < NR_CPUS; Index++) {
					ASF_IPSEC_ATOMIC_ADD(pInContainer->PPStats.IPSecPolPPStats[0], pSA->PolicyPPStats[Index].NumInBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pInContainer->PPStats.IPSecPolPPStats[1], pSA->PolicyPPStats[Index].NumInBoundOutPkts);
					ASF_IPSEC_ATOMIC_ADD(pInContainer->PPStats.IPSecPolPPStats[2], pSA->PolicyPPStats[Index].NumOutBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pInContainer->PPStats.IPSecPolPPStats[3], pSA->PolicyPPStats[Index].NumOutBoundOutPkts);
				}
				for (Index = 0; Index < 4; Index++) {
					ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(pInContainer->PPStats.IPSecPolPPStats[Index + 4], pInContainer->PPStats.IPSecPolPPStats[Index]);
				}
				memset(&pSA->PolicyPPStats, 0x0, sizeof(pSA->PolicyPPStats));
				for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
					ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(pInContainer->PPStats.IPSecPolPPStats[Index], pSA->PPStats.IPSecPolPPStats[Index]);
					ASF_IPSEC_ATOMIC_SET(pSA->PPStats.IPSecPolPPStats[Index], 0);
				}
				rcu_read_unlock();
			}
		}
		for (Index = 0; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
			pOutParams->IPSecPolPPStats[Index] = ASF_IPSEC_ATOMIC_READ(pInContainer->PPStats.IPSecPolPPStats[Index]);
		}
		return;
	}
	pOutContainer  = (SPDOutContainer_t *)  (ptrIArray_getData(&(secfp_OutDB),
								 pInParams->ulSPDContainerIndex));
	if (!pOutContainer)
		return;
	if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
		for (ii = 0; ii < SECFP_MAX_DSCP_SA; ii++) {
			if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
				pOutSA = (outSA_t *)  ptrIArray_getData(
								     &secFP_OutSATable, pOutContainer->SAHolder.ulSAIndex[ii]);
				if (!pOutSA)
					continue;

				if (pOldSA  && (pOldSA->SAParams.ulSPI == pOutSA->SAParams.ulSPI))
					continue;

				pOldSA = pOutSA;
				rcu_read_lock();
				for (Index = 0; Index < NR_CPUS; Index++) {
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[0], pOutSA->PolicyPPStats[Index].NumInBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[1], pOutSA->PolicyPPStats[Index].NumInBoundOutPkts);
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[2], pOutSA->PolicyPPStats[Index].NumOutBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[3], pOutSA->PolicyPPStats[Index].NumOutBoundOutPkts);
				}
				for (Index = 0; Index < 4; Index++) {
					ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(pOutContainer->PPStats.IPSecPolPPStats[Index + 4], pOutContainer->PPStats.IPSecPolPPStats[Index]);
				}
				memset(&pOutSA->PolicyPPStats, 0x0, sizeof(pOutSA->PolicyPPStats));
				for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
					ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(pOutContainer->PPStats.IPSecPolPPStats[Index], pOutSA->PPStats.IPSecPolPPStats[Index]);
					ASF_IPSEC_ATOMIC_SET(pOutSA->PPStats.IPSecPolPPStats[Index], 0);
				}
				rcu_read_unlock();
			}
		}
	} else {
		for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
		    pOutSALinkNode != NULL; pOutSALinkNode = pOutSALinkNode->pNext) {
			pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
			rcu_read_lock();
			if (pOutSA) {
				for (Index = 0; Index < NR_CPUS; Index++) {
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[0], pOutSA->PolicyPPStats[Index].NumInBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[1], pOutSA->PolicyPPStats[Index].NumInBoundOutPkts);
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[2], pOutSA->PolicyPPStats[Index].NumOutBoundInPkts);
					ASF_IPSEC_ATOMIC_ADD(pOutContainer->PPStats.IPSecPolPPStats[3], pOutSA->PolicyPPStats[Index].NumOutBoundOutPkts);
				}
				for (Index = 0; Index < 4; Index++) {
					ASF_IPSEC_COPY_ATOMIC_FROM_ATOMIC(pOutContainer->PPStats.IPSecPolPPStats[Index + 4],
									  pOutContainer->PPStats.IPSecPolPPStats[Index]);
				}
				for (Index = 8; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
					ASF_IPSEC_ADD_ATOMIC_AND_ATOMIC(pOutContainer->PPStats.IPSecPolPPStats[Index], pOutSA->PPStats.IPSecPolPPStats[Index]);
					ASF_IPSEC_ATOMIC_SET(pOutSA->PPStats.IPSecPolPPStats[Index], 0);
				}
				memset(&pOutSA->PolicyPPStats, 0x0, sizeof(pOutSA->PolicyPPStats));
			}
			rcu_read_unlock();
		}
	}
	for (Index = 0; Index < ASF_IPSEC_PP_POL_CNT_MAX; Index++) {
		pOutParams->IPSecPolPPStats[Index] = ASF_IPSEC_ATOMIC_READ(pOutContainer->PPStats.IPSecPolPPStats[Index]);
	}
	return;
}


ASF_void_t ASFIPSecGlobalQueryStats(ASFIPSec4GlobalPPStats_t *pOutparams)
{
	ASF_uint32_t Index;
	for (Index = 0; Index < 8; Index++) {
		pOutparams->IPSec4GblPPStat[Index]  = 0;
	}
	for (Index = 0; Index < NR_CPUS; Index++) {
		pOutparams->IPSec4GblPPStat[0] += IPSecPPGlobalStats_g[Index].ulTotInRecvPkts;
		pOutparams->IPSec4GblPPStat[1] += IPSecPPGlobalStats_g[Index].ulTotInProcPkts;
		pOutparams->IPSec4GblPPStat[2] += IPSecPPGlobalStats_g[Index].ulTotOutRecvPkts;
		pOutparams->IPSec4GblPPStat[3] += IPSecPPGlobalStats_g[Index].ulTotOutProcPkts;
		pOutparams->IPSec4GblPPStat[4] += IPSecPPGlobalStats_g[Index].ulTotInRecvSecPkts;
		pOutparams->IPSec4GblPPStat[5] += IPSecPPGlobalStats_g[Index].ulTotInProcSecPkts;
		pOutparams->IPSec4GblPPStat[6] += IPSecPPGlobalStats_g[Index].ulTotOutRecvPktsSecApply;
		pOutparams->IPSec4GblPPStat[7] += IPSecPPGlobalStats_g[Index].ulTotOutPktsSecAppled;
	}
	for (Index = 8; Index < ASF_IPSEC4_PP_GBL_CNT_MAX; Index++) {
		pOutparams->IPSec4GblPPStat[Index] = ASF_IPSEC_ATOMIC_READ(IPSec4GblPPStats_g.IPSec4GblPPStat[Index]);
	}
	return;
}
ASF_void_t ASFIPSecSAQueryStats(ASFIPSecGetSAQueryParams_t *pInParams,
				ASFSAStats_t *pOutParams)
{
	ASF_uint32_t hashVal = usMaxInSAHashTaleSize_g, Index, ii;
	SPDOutContainer_t *pOutContainer;
	outSA_t *pOutSA;
	inSA_t *pInSA;
	SPDOutSALinkNode_t *pOutSALinkNode;
	SECFP_IS_VSG_ID_INVALID(pInParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pInParams->ulVSGId);
		return;
	}
	if (pInParams->bDir == SECFP_IN) {
		rcu_read_lock();
		pInSA = ASF_findInv4SA(pInParams->ulVSGId, pInParams->ucProtocol,
				       pInParams->ulSPI, pInParams->gwAddr.ipv4addr, &hashVal);
		if (pInSA) {
			for (Index = 0; Index < NR_CPUS; Index++) {
				pOutParams->ulPkts += pInSA->ulPkts[Index];
				pOutParams->ulBytes += pInSA->ulBytes[Index];
			}
		}
		rcu_read_unlock();
		return;
	}
	pOutContainer  = (SPDOutContainer_t *)  (ptrIArray_getData(&(secfp_OutDB),
								 pInParams->ulSPDContainerIndex));
	if (!pOutContainer)
		return;

	if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
		for (ii = 0; ii < SECFP_MAX_DSCP_SA ; ii++) {
			if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
				pOutSA = (outSA_t *)  ptrIArray_getData(
								     &secFP_OutSATable, pOutContainer->SAHolder.
								     ulSAIndex[ii]);
				rcu_read_lock();
				if (pOutSA && (pOutSA->SAParams.ulSPI == pInParams->ulSPI) &&
				    (pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr ==  pInParams->gwAddr.ipv4addr) &&
				    (pOutSA->SAParams.ucProtocol == pInParams->ucProtocol)) {
					for (Index = 0; Index < NR_CPUS; Index++) {
						pOutParams->ulPkts += pOutSA->ulPkts[Index];
						pOutParams->ulBytes += pOutSA->ulBytes[Index];
					}
					rcu_read_unlock();
					return;
				}
				rcu_read_unlock();
			}
		}
	} else {
		for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
		    pOutSALinkNode != NULL; pOutSALinkNode = pOutSALinkNode->pNext) {
			pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
							      pOutSALinkNode->ulSAIndex);
			rcu_read_lock();
			if (pOutSA && (pOutSA->SAParams.ulSPI == pInParams->ulSPI &&
				       pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr == pInParams->gwAddr.ipv4addr &&
				       pOutSA->SAParams.ucProtocol == pInParams->ucProtocol)) {
				for (Index = 0; Index < NR_CPUS; Index++) {
					pOutParams->ulPkts += pOutSA->ulPkts[Index];
					pOutParams->ulBytes += pOutSA->ulBytes[Index];
				}
				rcu_read_unlock();
				return;
			}
			rcu_read_unlock();
		}
	}
	return;
}

ASF_void_t ASFIPSecGetFirstNSPDContainers(ASFIPSecGetContainerParams_t *pParams,
					  ASFIPSecContainers_t  *pSPDContainers)
{
	struct SPDCILinkNode_s  *pCINode;
	struct SPDCILinkNode_s **pList;
	SPDOutContainer_t *pOutContainer;
	SPDInContainer_t   *pInContainer;
	int ulCount = 0;
	int bVal = in_softirq();

	if ((!pParams->ulNumSPDContainers) || (!pSPDContainers->containerData)) {
		ASFIPSEC_DEBUG("Supplied NULL as input ");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pParams->ulVSGId);
		return;
	}

	SECFP_IS_TUNNEL_ID_INVALID(pParams->ulTunnelId)
	{
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pParams->ulTunnelId);
		return;
	}
	if (!bVal)
		local_bh_disable();

	spin_lock(&secfp_TunnelIfaceCIIndexListLock);
	if (secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].bInUse == 0) {
		ASFIPSEC_DEBUG("Tunnel Interface is not in use.\
	 TunnelId=%u, VSGId=%u\r\n", pParams->ulTunnelId, pParams->ulVSGId);
		if (!bVal)
			local_bh_enable();
		spin_unlock(&secfp_TunnelIfaceCIIndexListLock);
		return;
	}

	if (pParams->containerInfo.ucDirection == SECFP_OUT) {
		pList = &secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].pSPDCIOutList;
	} else { /* for Inbound */
		pList = &secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].pSPDCIInList;
	}

	if (*pList) {
		for (pCINode = *pList; pCINode != NULL;  pCINode = pCINode->pNext) {
			if (pParams->containerInfo.ucDirection == SECFP_OUT) {
				pOutContainer = (SPDOutContainer_t *) ptrIArray_getData(&(secfp_OutDB), pCINode->ulIndex);
				/* Filling of SPD Details */
				pSPDContainers->containerData[ulCount].ulSPDContainerIndex = pCINode->ulIndex;
				pSPDContainers->containerData[ulCount].pSPDDetails->policyAction = pOutContainer->action;
				/*  pSPDContainers->containerData[ulCount].pSPDDetails = pOutContainer; */
			} else {
				pInContainer = (SPDInContainer_t *) ptrIArray_getData(&(secfp_InDB), pCINode->ulIndex);
				/* Filling of SPD Details */
				pSPDContainers->containerData[ulCount].ulSPDContainerIndex = pCINode->ulIndex;
			/*pSPDContainers->containerData[ulCount].pSPDDetails->
					policyAction = pInContainer->action; */
			/*	pSPDContainers->containerData[ulCount].
					pSPDDetails = pInContainer; */
			}
			ulCount++;
			if (ulCount == pParams->ulNumSPDContainers) {
				pSPDContainers->ulNumSPDContainers = ulCount;
				if (pCINode->pNext != NULL)
					pSPDContainers->ucMoreSPDs = TRUE;
				break;
			}
		}
	}
	spin_unlock(&secfp_TunnelIfaceCIIndexListLock);

	if (ulCount == 0) {
		ASFIPSEC_DEBUG("Container list is empty for the given VSG/Tunnel Id ");
	}
	if (!bVal)
		local_bh_enable();
	return;
}

ASF_void_t  ASFIPSecGetNextNSPDContainers(ASFIPSecGetContainerParams_t *pParams,
					  ASFIPSecContainers_t		*pSPDContainers)
{
	struct SPDCILinkNode_s  *pCINode;
	struct SPDCILinkNode_s **pList;
	SPDOutContainer_t *pOutContainer;
	SPDInContainer_t   *pInContainer;
	int ulCount = 0;
	int bVal = in_softirq();

	if ((!pParams->ulNumSPDContainers) || (!pSPDContainers->containerData)) {
		ASFIPSEC_DEBUG("Supplied NULL as input ");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pParams->ulVSGId);
		return;
	}

	SECFP_IS_TUNNEL_ID_INVALID(pParams->ulTunnelId)
	{
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pParams->ulTunnelId);
		return;
	}

	if (!bVal)
		local_bh_disable();

	spin_lock(&secfp_TunnelIfaceCIIndexListLock);
	if (secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].bInUse == 0) {
		ASFIPSEC_DEBUG("Tunnel Interface is not in use. TunnelId=%u, VSGId=%u\r\n", pParams->ulTunnelId, pParams->ulVSGId);
		if (!bVal)
			local_bh_enable();
		spin_unlock(&secfp_TunnelIfaceCIIndexListLock);
		return;
	}

	if (pParams->containerInfo.ucDirection == SECFP_OUT) {
		pList = &secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].pSPDCIOutList;
	} else { /* for Inbound */
		pList = &secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].pSPDCIInList;
	}

	if (*pList) {
		pCINode = *pList;
		for (; pCINode != NULL; pCINode = pCINode->pNext) {
			if (pCINode->ulIndex == pParams->containerInfo.ulSPDContainerIndex) {
				break;
			}
		}
		if (pCINode)
			pCINode = pCINode->pNext;
		for (; pCINode != NULL;  pCINode = pCINode->pNext) {
			if (pParams->containerInfo.ucDirection == SECFP_OUT) {
				pOutContainer = (SPDOutContainer_t *) ptrIArray_getData(&(secfp_OutDB), pCINode->ulIndex);
				/* Filling of SPD Details */
				pSPDContainers->containerData[ulCount].ulSPDContainerIndex = pCINode->ulIndex;
				pSPDContainers->containerData[ulCount].pSPDDetails->policyAction = pOutContainer->action;
				/*  pSPDContainers->containerData[ulCount].pSPDDetails = pOutContainer; */
			} else {
				pInContainer = (SPDInContainer_t *) ptrIArray_getData(&(secfp_InDB), pCINode->ulIndex);
				/* Filling of SPD Details */
				pSPDContainers->containerData[ulCount].ulSPDContainerIndex = pCINode->ulIndex;
			/*pSPDContainers->containerData[ulCount].pSPDDetails->
					policyAction = pInContainer->action; */
			/*	pSPDContainers->containerData[ulCount].
					pSPDDetails = pInContainer; */
			}
			ulCount++;
			if (ulCount == pParams->ulNumSPDContainers) {
				pSPDContainers->ulNumSPDContainers = ulCount;
				if (pCINode->pNext != NULL)
					pSPDContainers->ucMoreSPDs = TRUE;
				break;
			}
		}
	}
	spin_unlock(&secfp_TunnelIfaceCIIndexListLock);

	if (ulCount == 0) {
		ASFIPSEC_DEBUG("No Containers present in the list after the given container Id in VSG/Tunnel Id ");
	}

	if (!bVal)
		local_bh_enable();

	return;
}

ASF_void_t ASFGetExactSPDContainers(ASFIPSecGetContainerParams_t   *pParams,
				    ASFIPSecContainers_t  *pSPDContainers)
{
	struct SPDCILinkNode_s  *pCINode;
	struct SPDCILinkNode_s **pList;
	SPDOutContainer_t *pOutContainer;
	SPDInContainer_t   *pInContainer;
	int ulCount = 0;
	int bVal = in_softirq();

	if ((!pParams->ulNumSPDContainers) || (!pSPDContainers->containerData)) {
		ASFIPSEC_DEBUG("Supplied NULL as input ");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pParams->ulVSGId);
		return;
	}

	SECFP_IS_TUNNEL_ID_INVALID(pParams->ulTunnelId)
	{
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pParams->ulTunnelId);
		return;
	}

	if (!bVal)
		local_bh_disable();

	spin_lock(&secfp_TunnelIfaceCIIndexListLock);
	if (secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].bInUse == 0) {
		ASFIPSEC_DEBUG("Tunnel Interface is not in use. TunnelId=%u, VSGId=%u\r\n", pParams->ulTunnelId, pParams->ulVSGId);
		if (!bVal)
			local_bh_enable();
		spin_unlock(&secfp_TunnelIfaceCIIndexListLock);
		return;
	}

	if (pParams->containerInfo.ucDirection == SECFP_OUT) {
		pList = &secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].pSPDCIOutList;
	} else { /* for Inbound */
		pList = &secFP_TunnelIfaces[pParams->ulVSGId][pParams->ulTunnelId].pSPDCIInList;
	}

	if (*pList) {
		pCINode = *pList;
		for (; pCINode != NULL; pCINode = pCINode->pNext) {
			if (pCINode->ulIndex == pParams->containerInfo.ulSPDContainerIndex) {
				break;
			}
		}
		/* Retrieving the Node(s) from the specified Container Index till the No Of Requested containers */
		for (; pCINode != NULL;  pCINode = pCINode->pNext) {
			if (pParams->containerInfo.ucDirection == SECFP_OUT) {
				pOutContainer = (SPDOutContainer_t *) ptrIArray_getData(&(secfp_OutDB), pCINode->ulIndex);
				/* Filling of SPD Details */
				pSPDContainers->containerData[ulCount].ulSPDContainerIndex = pCINode->ulIndex;
				pSPDContainers->containerData[ulCount].pSPDDetails->policyAction = pOutContainer->action;
				/*  pSPDContainers->containerData[ulCount].pSPDDetails = pOutContainer; */
			} else {
				pInContainer = (SPDInContainer_t *) ptrIArray_getData(&(secfp_InDB), pCINode->ulIndex);
				/* Filling of SPD Details */
				pSPDContainers->containerData[ulCount].ulSPDContainerIndex = pCINode->ulIndex;
			/*pSPDContainers->containerData[ulCount].pSPDDetails->
					policyAction = pInContainer->action; */
			/*	pSPDContainers->containerData[ulCount].
					pSPDDetails = pInContainer; */
			}
			ulCount++;
			if (ulCount == pParams->ulNumSPDContainers) {
				pSPDContainers->ulNumSPDContainers = ulCount;
				break;
			}
		}
	}
	spin_unlock(&secfp_TunnelIfaceCIIndexListLock);

	if (ulCount == 0) {
		ASFIPSEC_DEBUG("No Containers present in the list from/after the given container Id in VSG/Tunnel Id ");
	}

	if (!bVal)
		local_bh_enable();

	return;
}

static unsigned int asf_FillSAParams(ASF_IPSecSA_t *pASFSAParams,
				     SAParams_t    *pSAParams)
{
	if (pSAParams->AuthKeyLen) {
		if (pSAParams->ucAuthAlgo == SECFP_HMAC_MD5) {
			pASFSAParams->authAlgo = ASF_IPSEC_AALG_MD5HMAC;
		} else if (pSAParams->ucAuthAlgo == SECFP_HMAC_SHA1) {
			pASFSAParams->authAlgo = ASF_IPSEC_AALG_SHA1HMAC;
		} else {
			pASFSAParams->authAlgo = ASF_IPSEC_AALG_AESXCBC;
		}
		pASFSAParams->authKeyLenBits = pSAParams->AuthKeyLen/8;
		memcpy(pASFSAParams->authKey, pSAParams->ucAuthKey, pASFSAParams->authKeyLenBits);
	} else {
		pASFSAParams->authAlgo = 0;
	}

	if (pSAParams->bEncrypt) {
		if (pSAParams->ucCipherAlgo == SECFP_DES) {
			pASFSAParams->encAlgo = ASF_IPSEC_EALG_DESCBC;
		} else if (pSAParams->ucCipherAlgo == SECFP_3DES) {
			pASFSAParams->encAlgo = ASF_IPSEC_EALG_3DESCBC;
		} else if (pSAParams->ucCipherAlgo == SECFP_AES) {
			pASFSAParams->encAlgo = ASF_IPSEC_EALG_AES;
		} else {
			pASFSAParams->authAlgo = ASF_IPSEC_EALG_AES_CTR;
			memcpy(pASFSAParams->aesCtrCounterBlock,
			       pSAParams->ucNounceIVCounter, 16);
		}
		pASFSAParams->encDecKeyLenBits = pSAParams->EncKeyLen/8;
		memcpy(pASFSAParams->encDecKey, pSAParams->ucEncKey, pASFSAParams->encDecKeyLenBits);
	} else {
		pASFSAParams->encAlgo = ASF_IPSEC_EALG_NULL;
	}

	pASFSAParams->bRedSideFragment = pSAParams->bRedSideFragment;
	pASFSAParams->bVerifyInPktWithSASelectors = pSAParams->bVerifyInPktWithSASelectors;
	pASFSAParams->bDoPeerGWIPAddressChangeAdaptation = pSAParams->bDoPeerGWIPAddressChangeAdaptation;
	pASFSAParams->bDoUDPEncapsulationForNATTraversal = pSAParams->bDoUDPEncapsulationForNATTraversal;
	pASFSAParams->bUseExtendedSequenceNumber = pSAParams->bUseExtendedSequenceNumber;
	pASFSAParams->bPropogateECN = pSAParams->bPropogateECN;
	pASFSAParams->bDoAntiReplayCheck = pSAParams->bDoAntiReplayCheck;
	pASFSAParams->bEncapsulationMode = pSAParams->bEncapsulationMode;

	pASFSAParams->spi = pSAParams->ulSPI;

	if (pSAParams->tunnelInfo.bIPv4OrIPv6 == 0) {
		pASFSAParams->TE_Addr.IP_Version = 4;
		pASFSAParams->TE_Addr.srcIP.ipv4addr = pSAParams->tunnelInfo.addr.iphv4.saddr;
		pASFSAParams->TE_Addr.dstIP.ipv4addr =  pSAParams->tunnelInfo.addr.iphv4.daddr;
	} else {
		pASFSAParams->TE_Addr.IP_Version = 6;
	}

	if (pSAParams->bCopyDscp  == ASF_IPSEC_QOS_DSCP_COPY) {
		pASFSAParams->handleToSOrDSCPAndFlowLabel = 1;
	} else if (pSAParams->bCopyDscp == ASF_IPSEC_QOS_DSCP_SET) {
		pASFSAParams->handleToSOrDSCPAndFlowLabel = 0;
		pASFSAParams->qos = pSAParams->ucDscp;
	}

	if (pSAParams->ucProtocol == SECFP_PROTO_ESP) {
		pASFSAParams->protocol = ASF_IPSEC_PROTOCOL_ESP;
	} else {
		return SECFP_FAILURE;
	}
	pASFSAParams->replayWindowSize = pSAParams->AntiReplayWin  ;
	if (pSAParams->handleDf == SECFP_DF_COPY) {
		pASFSAParams->handleDFBit = ASF_IPSEC_DF_COPY;
	} else if (pSAParams->handleDf == SECFP_DF_SET) {
		pASFSAParams->handleDFBit = ASF_IPSEC_DF_SET;
	} else {
		pASFSAParams->handleDFBit = ASF_IPSEC_DF_CLEAR;
	}
	return SECFP_SUCCESS;
}

ASF_void_t ASFIPSecGetFirstNSAs(ASFIPSecGetSAParams_t  *pSAParams,
				ASFIPSecSAsData_t *pSAs)
{
	SPDOutContainer_t *pOutContainer;
	SPDInContainer_t   *pInContainer;
	int ulCount = 0, ii;
	int bVal = in_softirq();
	SPDOutSALinkNode_t *pOutSALinkNode;
	SPDInSPIValLinkNode_t  *pSPILinkNode;
	outSA_t *pOutSA  = NULL, *pOldSA = NULL;
	inSA_t  *pInSA =  NULL;
	unsigned int ulHashVal;

	if ((!pSAParams->ulNumSAs) || (!pSAs->SA)) {
		ASFIPSEC_DEBUG("Supplied NULL as input ");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pSAParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pSAParams->ulVSGId);
		return;
	}

	SECFP_IS_TUNNEL_ID_INVALID(pSAParams->ulTunnelId)
	{
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pSAParams->ulTunnelId);
		return;
	}

	SECFP_IS_MAGICNUMBER_INVALID(pSAParams->SPDContainer.ulMagicNumber)
	{
		GlobalErrors.ulInvalidMagicNumber++;;
		ASFIPSEC_DEBUG("Invalid Magic Number = %u\r\n", pSAParams->SPDContainer.ulMagicNumber);
		return;
	}

	if (!bVal)
		local_bh_disable();

	if (pSAParams->SPDContainer.bDir == SECFP_OUT) {
		pOutContainer = (SPDOutContainer_t *) ptrIArray_getData(&(secfp_OutDB),
								      pSAParams->SPDContainer.ulContainerId);
		if (!pOutContainer) {
			GlobalErrors.ulSPDOutContainerNotFound++;
			ASFIPSEC_DEBUG("OUT SPDContainer not found");
			if (!bVal)
				local_bh_enable();
			return;
		}

		if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
			for (ii = 0; ii < SECFP_MAX_DSCP_SA ; ii++) {
				if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
					pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
									      pOutContainer->SAHolder.ulSAIndex[ii]);
					if (pOldSA && (!pOutSA || pOldSA->SAParams.ulSPI == pOutSA->SAParams.ulSPI)) {
						continue;
					}
					pSAs->SA[ulCount].ulSPI = pOutSA->SAParams.ulSPI;
					pSAs->SA[ulCount].gwAddr.ipv4addr = pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr;
					pSAs->SA[ulCount].ucProtocol = pOutSA->SAParams.ucProtocol;
					if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pOutSA->SAParams) == SECFP_FAILURE) {
						ASFIPSEC_DEBUG("asf_FillSAParams returned failure for Out Container ");
						if (!bVal)
							local_bh_enable();
						return;
					}
					pOldSA = pOutSA;
					ulCount++;
					if (ulCount ==  pSAParams->ulNumSAs)
						break;
				}
			}
			pSAs->ulNumSAs = ulCount;
			if (ii < SECFP_MAX_DSCP_SA) {
				for (ii = ii + 1; ii < SECFP_MAX_DSCP_SA; ii++) {
					if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
						pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
										      pOutContainer->SAHolder.ulSAIndex[ii]);
						if (pOutSA) {
							pSAs->ucMoreSAs = TRUE;
							break;
						}
					}
				}
			}
		} else {
			for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
			    pOutSALinkNode != NULL;
			    pOutSALinkNode = pOutSALinkNode->pNext) {
				pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
				if (pOutSA) {
					pSAs->SA[ulCount].ulSPI = pOutSA->SAParams.ulSPI;
					pSAs->SA[ulCount].gwAddr.ipv4addr = pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr;
					pSAs->SA[ulCount].ucProtocol = pOutSA->SAParams.ucProtocol;

					if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pOutSA->SAParams) == SECFP_FAILURE) {
						ASFIPSEC_DEBUG("asf_FillSAParams returned failure");
						if (!bVal)
							local_bh_enable();
						return;
					}
					ulCount++;
					if (ulCount == pSAs->ulNumSAs) {
						pOutSALinkNode = pOutSALinkNode->pNext;
						break;
					}
				}
			}
			pSAs->ulNumSAs = ulCount;
			for (; pOutSALinkNode != NULL; pOutSALinkNode = pOutSALinkNode->pNext) {
				pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
								      pOutSALinkNode->ulSAIndex);
				if ((pOutSA)) {
					pSAs->ucMoreSAs = TRUE;
					break;
				}
			}
		}
	} else {   /* InSAs Retrieval From InContainer  */
		pInContainer = (SPDInContainer_t *) ptrIArray_getData(&(secfp_InDB),
								    pSAParams->SPDContainer.ulContainerId);
		if (!pInContainer) {
			GlobalErrors.ulSPDInContainerNotFound++;
			ASFIPSEC_DEBUG("IN SPDContainer not found");
			if (!bVal)
				local_bh_enable();
			return;
		}
		for (pSPILinkNode = pInContainer->pSPIValList; pSPILinkNode != NULL; pSPILinkNode = pSPILinkNode->pNext) {
			ulHashVal = secfp_compute_hash(pSPILinkNode->ulSPIVal);
			for (pInSA = secFP_SPIHashTable[ulHashVal].pHeadSA;
			    pInSA != NULL; pInSA = pInSA->pNext) {
				if ((pInSA->ulSPDInContainerIndex == pSAParams->SPDContainer.ulContainerId)
				    && (pInSA->SAParams.ulSPI == pSPILinkNode->ulSPIVal)) {
					pSAs->SA[ulCount].ulSPI = pInSA->SAParams.ulSPI;
					pSAs->SA[ulCount].gwAddr.ipv4addr = pInSA->SAParams.tunnelInfo.addr.iphv4.daddr;
					pSAs->SA[ulCount].ucProtocol = pInSA->SAParams.ucProtocol;
					if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pInSA->SAParams) == SECFP_FAILURE) {
						ASFIPSEC_DEBUG("asf_FillSAParams returned failure for IN SAs ");
						if (!bVal)
							local_bh_enable();
						return;
					}
					ulCount++;
					if (ulCount == pSAs->ulNumSAs) {
						pInSA = pInSA->pNext;
						break;
					}
				}
			}
		}
		pSAs->ulNumSAs = ulCount;
		if ((pInSA)) {
			pSAs->ucMoreSAs = TRUE;
		}
	}
	if (!bVal)
		local_bh_enable();
	return;
}
ASF_void_t ASFIPSecGetNextNSAs(ASFIPSecGetSAParams_t  *pSAParams,
			       ASFIPSecSAsData_t *pSAs)
{
	SPDOutContainer_t *pOutContainer;
	SPDInContainer_t   *pInContainer;
	int ulCount = 0, ii;
	int bVal = in_softirq();
	SPDOutSALinkNode_t *pOutSALinkNode;
	SPDInSPIValLinkNode_t  *pSPILinkNode;
	outSA_t *pOutSA  = NULL, *pOldSA = NULL;
	inSA_t  *pInSA =  NULL;
	unsigned int ulHashVal;
	ASF_boolean_t  bMark = FALSE;

	if ((!pSAParams->ulNumSAs) || (!pSAs->SA)) {
		ASFIPSEC_DEBUG("Supplied NULL as input ");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pSAParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pSAParams->ulVSGId);
		return;
	}

	SECFP_IS_TUNNEL_ID_INVALID(pSAParams->ulTunnelId)
	{
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pSAParams->ulTunnelId);
		return;
	}

	SECFP_IS_MAGICNUMBER_INVALID(pSAParams->SPDContainer.ulMagicNumber)
	{
		GlobalErrors.ulInvalidMagicNumber++;;
		ASFIPSEC_DEBUG("Invalid Magic Number = %u\r\n", pSAParams->SPDContainer.ulMagicNumber);
		return;
	}

	if (!bVal)
		local_bh_disable();

	if (pSAParams->SPDContainer.bDir == SECFP_OUT) {
		pOutContainer = (SPDOutContainer_t *) ptrIArray_getData(&(secfp_OutDB),
								      pSAParams->SPDContainer.ulContainerId);
		if (!pOutContainer) {
			GlobalErrors.ulSPDOutContainerNotFound++;
			ASFIPSEC_DEBUG("OUT SPDContainer not found");
			if (!bVal)
				local_bh_enable();
			return;
		}

		if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
			for (ii = 0; ii < SECFP_MAX_DSCP_SA ; ii++) {
				if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
					pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
									      pOutContainer->SAHolder.ulSAIndex[ii]);
					if (pOldSA && (!pOutSA || pOldSA->SAParams.ulSPI == pOutSA->SAParams.ulSPI)) {
						continue;
					}
					if (pOutSA->SAParams.ulSPI == pSAs->SA[ulCount].ulSPI &&
					    pOutSA->SAParams.ucProtocol == pSAs->SA[ulCount].ucProtocol &&
					    pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr  == pSAs->SA[ulCount].gwAddr.ipv4addr) {
						bMark = TRUE;
						continue;
					}
					if (bMark == TRUE) {
						pSAs->SA[ulCount].ulSPI = pOutSA->SAParams.ulSPI;
						pSAs->SA[ulCount].gwAddr.ipv4addr = pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr;
						pSAs->SA[ulCount].ucProtocol = pOutSA->SAParams.ucProtocol;
						if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pOutSA->SAParams) == SECFP_FAILURE) {
							ASFIPSEC_DEBUG("asf_FillSAParams returned failure for Out Container ");
							if (!bVal)
								local_bh_enable();
							return;
						}
						pOldSA = pOutSA;
						ulCount++;
						if (ulCount ==  pSAParams->ulNumSAs)
							break;
					}
				}
			}
			pSAs->ulNumSAs = ulCount;
			if (ii < SECFP_MAX_DSCP_SA) {
				for (ii = ii + 1; ii < SECFP_MAX_DSCP_SA; ii++) {
					if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
						pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
										      pOutContainer->SAHolder.ulSAIndex[ii]);
						if (pOutSA) {
							pSAs->ucMoreSAs = TRUE;
							break;
						}
					}
				}
			}
		} else {
			for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
			    pOutSALinkNode != NULL; pOutSALinkNode = pOutSALinkNode->pNext) {
				pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
				if (pOutSA) {
					if (pOutSA->SAParams.ulSPI == pSAs->SA[ulCount].ulSPI &&
					    pOutSA->SAParams.ucProtocol == pSAs->SA[ulCount].ucProtocol &&
					    pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr  == pSAs->SA[ulCount].gwAddr.ipv4addr) {
						bMark = TRUE;
						continue;
					}
					if (bMark == TRUE) {
						pSAs->SA[ulCount].ulSPI = pOutSA->SAParams.ulSPI;
						pSAs->SA[ulCount].gwAddr.ipv4addr = pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr;
						pSAs->SA[ulCount].ucProtocol = pOutSA->SAParams.ucProtocol;
						if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pOutSA->SAParams) == SECFP_FAILURE) {
							ASFIPSEC_DEBUG("asf_FillSAParams returned failure");
							if (!bVal)
								local_bh_enable();
							return;
						}
						ulCount++;
						if (ulCount == pSAs->ulNumSAs) {
							pOutSALinkNode = pOutSALinkNode->pNext;
							break;
						}
					}
				}
			}
			pSAs->ulNumSAs = ulCount;
			for (; pOutSALinkNode != NULL; pOutSALinkNode = pOutSALinkNode->pNext) {
				pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
								      pOutSALinkNode->ulSAIndex);
				if ((pOutSA)) {
					pSAs->ucMoreSAs = TRUE;
					break;
				}
			}
		}
	} else {   /* InSAs Retrieval From InContainer  */
		pInContainer = (SPDInContainer_t *) ptrIArray_getData(&(secfp_InDB),
								    pSAParams->SPDContainer.ulContainerId);
		if (!pInContainer) {
			GlobalErrors.ulSPDInContainerNotFound++;
			ASFIPSEC_DEBUG("IN SPDContainer not found");
			if (!bVal)
				local_bh_enable();
			return;
		}
		for (pSPILinkNode = pInContainer->pSPIValList; pSPILinkNode != NULL; pSPILinkNode = pSPILinkNode->pNext) {
			ulHashVal = secfp_compute_hash(pSPILinkNode->ulSPIVal);
			for (pInSA = secFP_SPIHashTable[ulHashVal].pHeadSA;
			    pInSA != NULL; pInSA = pInSA->pNext) {
				if ((pInSA->SAParams.ucProtocol == pSAParams->SPDContainer.SAInfo[ulCount].ucProtocol)
				    && (pInSA->SAParams.ulSPI == pSAParams->SPDContainer.SAInfo[ulCount].ulSPI)
				    && (pInSA->SAParams.tunnelInfo.addr.iphv4.daddr == pSAParams->SPDContainer.SAInfo[ulCount].gwAddr.ipv4addr)) {
					bMark = TRUE;
					continue;
				}
				if (bMark == TRUE) {
					if ((pInSA->ulSPDInContainerIndex == pSAParams->SPDContainer.ulContainerId)
					    && (pInSA->SAParams.ulSPI == pSPILinkNode->ulSPIVal)) {
						pSAs->SA[ulCount].ulSPI = pInSA->SAParams.ulSPI;
						pSAs->SA[ulCount].gwAddr.ipv4addr = pInSA->SAParams.tunnelInfo.addr.iphv4.daddr;
						pSAs->SA[ulCount].ucProtocol = pInSA->SAParams.ucProtocol;
						if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pInSA->SAParams) == SECFP_FAILURE) {
							ASFIPSEC_DEBUG("asf_FillSAParams returned failure for IN SAs ");
							if (!bVal)
								local_bh_enable();
							return;
						}
						ulCount++;
						if (ulCount == pSAs->ulNumSAs) {
							pInSA = pInSA->pNext;
							break;
						}
					}
				}
			}
		}
		pSAs->ulNumSAs = ulCount;
		if ((pInSA)) {
			pSAs->ucMoreSAs = TRUE;
		}
	}
	if (!bVal)
		local_bh_enable();
	return;
}

ASF_void_t ASFIPSecGetExactSAs(ASFIPSecGetSAParams_t  *pSAParams,
			       ASFIPSecSAsData_t *pSAs)
{
	SPDOutContainer_t *pOutContainer;
	SPDInContainer_t   *pInContainer;
	int ulCount = 0, ii;
	int bVal = in_softirq();
	SPDOutSALinkNode_t *pOutSALinkNode;
	SPDInSPIValLinkNode_t  *pSPILinkNode;
	outSA_t *pOutSA  = NULL;
	inSA_t  *pInSA =  NULL;
	unsigned int ulHashVal;

	if ((!pSAParams->ulNumSAs) || (!pSAs->SA)) {
		ASFIPSEC_DEBUG("Supplied NULL as input ");
		return;
	}

	SECFP_IS_VSG_ID_INVALID(pSAParams->ulVSGId)
	{
		GlobalErrors.ulInvalidVSGId++;
		ASFIPSEC_DEBUG("Invalid VSG Id = %u\r\n", pSAParams->ulVSGId);
		return;
	}

	SECFP_IS_TUNNEL_ID_INVALID(pSAParams->ulTunnelId)
	{
		GlobalErrors.ulInvalidTunnelId++;
		ASFIPSEC_DEBUG("Invalid Tunnel Id = %u\r\n", pSAParams->ulTunnelId);
		return;
	}

	SECFP_IS_MAGICNUMBER_INVALID(pSAParams->SPDContainer.ulMagicNumber)
	{
		GlobalErrors.ulInvalidMagicNumber++;;
		ASFIPSEC_DEBUG("Invalid Magic Number = %u\r\n", pSAParams->SPDContainer.ulMagicNumber);
		return;
	}

	if (!bVal)
		local_bh_disable();

	if (pSAParams->SPDContainer.bDir == SECFP_OUT) {
		pOutContainer = (SPDOutContainer_t *) ptrIArray_getData(&(secfp_OutDB),
								      pSAParams->SPDContainer.ulContainerId);
		if (!pOutContainer) {
			GlobalErrors.ulSPDOutContainerNotFound++;
			ASFIPSEC_DEBUG("OUT SPDContainer not found");
			if (!bVal)
				local_bh_enable();
			return;
		}

		if (pOutContainer->SPDParams.bOnlySaPerDSCP) {
			for (ii = 0; ii < SECFP_MAX_DSCP_SA ; ii++) {
				if (pOutContainer->SAHolder.ulSAIndex[ii] != ulMaxSupportedIPSecSAs_g) {
					pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable,
									      pOutContainer->SAHolder.ulSAIndex[ii]);
					if (pOutSA) {
						if (pOutSA->SAParams.ulSPI == pSAs->SA[ulCount].ulSPI &&
						    pOutSA->SAParams.ucProtocol == pSAs->SA[ulCount].ucProtocol &&
						    pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr  == pSAs->SA[ulCount].gwAddr.ipv4addr) {
							pSAs->SA[ulCount].ulSPI = pOutSA->SAParams.ulSPI;
							pSAs->SA[ulCount].gwAddr.ipv4addr = pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr;
							pSAs->SA[ulCount].ucProtocol = pOutSA->SAParams.ucProtocol;
							if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pOutSA->SAParams) == SECFP_FAILURE) {
								ASFIPSEC_DEBUG("asf_FillSAParams returned failure for Out Container ");
								if (!bVal)
									local_bh_enable();
								return;
							}
							ulCount++;
						}
					}
				}
			}
			pSAs->ulNumSAs = ulCount;
		} else {
			for (pOutSALinkNode = pOutContainer->SAHolder.pSAList;
			    pOutSALinkNode != NULL; pOutSALinkNode = pOutSALinkNode->pNext) {
				pOutSA = (outSA_t *)  ptrIArray_getData(&secFP_OutSATable, pOutSALinkNode->ulSAIndex);
				if (pOutSA) {
					if (pOutSA->SAParams.ulSPI == pSAs->SA[ulCount].ulSPI &&
					    pOutSA->SAParams.ucProtocol == pSAs->SA[ulCount].ucProtocol &&
					    pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr  == pSAs->SA[ulCount].gwAddr.ipv4addr) {
						pSAs->SA[ulCount].ulSPI = pOutSA->SAParams.ulSPI;
						pSAs->SA[ulCount].gwAddr.ipv4addr = pOutSA->SAParams.tunnelInfo.addr.iphv4.daddr;
						pSAs->SA[ulCount].ucProtocol = pOutSA->SAParams.ucProtocol;
						if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pOutSA->SAParams) == SECFP_FAILURE) {
							ASFIPSEC_DEBUG("asf_FillSAParams returned failure");
							if (!bVal)
								local_bh_enable();
							return;
						}
						ulCount++;
						break;
					}
				}
			}
			pSAs->ulNumSAs = ulCount; /* Count is always 1 */
		}
	} else {   /* InSAs Retrieval From InContainer  */
		pInContainer = (SPDInContainer_t *) ptrIArray_getData(&(secfp_InDB),
								    pSAParams->SPDContainer.ulContainerId);
		if (!pInContainer) {
			GlobalErrors.ulSPDInContainerNotFound++;
			ASFIPSEC_DEBUG("IN SPDContainer not found");
			if (!bVal)
				local_bh_enable();
			return;
		}
		for (pSPILinkNode = pInContainer->pSPIValList; pSPILinkNode != NULL; pSPILinkNode = pSPILinkNode->pNext) {
			ulHashVal = secfp_compute_hash(pSPILinkNode->ulSPIVal);
			for (pInSA = secFP_SPIHashTable[ulHashVal].pHeadSA;
			    pInSA != NULL; pInSA = pInSA->pNext) {
				if ((pInSA->SAParams.ucProtocol == pSAParams->SPDContainer.SAInfo[ulCount].ucProtocol)
				    && (pInSA->SAParams.ulSPI == pSAParams->SPDContainer.SAInfo[ulCount].ulSPI)
				    && (pInSA->SAParams.tunnelInfo.addr.iphv4.daddr == pSAParams->SPDContainer.SAInfo[ulCount].gwAddr.ipv4addr)) {
					if ((pInSA->ulSPDInContainerIndex == pSAParams->SPDContainer.ulContainerId)
					    && (pInSA->SAParams.ulSPI == pSPILinkNode->ulSPIVal)) {
						pSAs->SA[ulCount].ulSPI = pInSA->SAParams.ulSPI;
						pSAs->SA[ulCount].gwAddr.ipv4addr = pInSA->SAParams.tunnelInfo.addr.iphv4.daddr;
						pSAs->SA[ulCount].ucProtocol = pInSA->SAParams.ucProtocol;
						if (asf_FillSAParams(pSAs->SA[ulCount].pSA, &pInSA->SAParams) == SECFP_FAILURE) {
							ASFIPSEC_DEBUG("asf_FillSAParams returned failure for IN SAs ");
							if (!bVal)
								local_bh_enable();
							return;
						}
						ulCount++;
						break;
					}
				}
			}
			pSAs->ulNumSAs = ulCount;  /* Count is always 1 */
		}
	}
	if (!bVal)
		local_bh_enable();
	return;
}

ASF_uint32_t ASFFWIPSecRemove(ASF_void_t)
{
	ASF_uint32_t ulVSGId, ulTunnelId, iRetVal = SECFP_FAILURE;

	/* To CleanUp all the IPSec Containers and SAs with in the containter in all VSGs */
	for (ulVSGId = 0, ulTunnelId = 0;
	    (ulVSGId < ulMaxVSGs_g && ulTunnelId < ulMaxTunnels_g);
	    ulVSGId++, ulTunnelId++) {
		if (secFP_TunnelIfaces[ulVSGId][ulTunnelId].bInUse == 1)
			iRetVal = ASFIPSecFlushContainers(ulVSGId, ulTunnelId);
	}

	if (iRetVal != SECFP_SUCCESS)
		return SECFP_FAILURE;

	/* To CleanUp all the existing flows and their timers in the firewall */
	ASFRemove();
	return SECFP_SUCCESS;
}

ASF_void_t  ASFIPSecInitConfigIdentity(ASFIPSecInitConfigIdentity_t  *pConfigIdentity)
{
	ASF_uint32_t ii, kk;

	if (pConfigIdentity &&
	    (pConfigIdentity->ulMaxVSGs <= ulMaxVSGs_g) &&
	    (pConfigIdentity->ulMaxTunnels <= ulMaxTunnels_g)) {
		if (pConfigIdentity->pulVSGMagicNumber)
			for (ii = 0; ii < pConfigIdentity->ulMaxVSGs; ii++)
				pulVSGMagicNumber[ii] =
					pConfigIdentity->pulVSGMagicNumber[ii];
		if (pConfigIdentity->pulTunnelMagicNumber)
			for (ii = 0; ii < pConfigIdentity->ulMaxVSGs; ii++)
				if (pConfigIdentity->pulTunnelMagicNumber[ii])
					for (kk = 0; kk < pConfigIdentity->ulMaxTunnels; kk++)
						secFP_TunnelIfaces[ii][kk].
							ulTunnelMagicNumber =
						pConfigIdentity->
						pulTunnelMagicNumber[ii][kk];
	}
}

MODULE_AUTHOR("Freescale Semiconductor, Inc");
MODULE_DESCRIPTION("Application Specific FastPath IPSec");
MODULE_LICENSE("GPL");

/* ASF-IPSec Modules parameters */
/* It should be driven from the ASF core module */
module_param(ulMaxVSGs_g, int, 0444);
MODULE_PARM_DESC(ulMaxVSGs_g, "Integer - Maximum number of VSGs supported");

module_param(bTightlyIntegrated_g, bool, 0444);
MODULE_PARM_DESC(bTightlyIntegrated_g, "Bool - Application stacks communicating"
	"with ASF are tightly integrated or loosely integrate");

module_param(ulMaxTunnels_g, int, 0444);
MODULE_PARM_DESC(ulMaxTunnels_g,
	"Integer - Maximum number of Tunnels supported");

module_param(ulMaxSPDContainers_g, int, 0444);
MODULE_PARM_DESC(ulMaxSPDContainers_g,
	"Integer - Maximum number of SPD Containers supported");

module_param(ulMaxSupportedIPSecSAs_g, int, 0444);
MODULE_PARM_DESC(ulMaxSupportedIPSecSAs_g,
	"Integer - Maximum number of SAs Containers supported");

module_param(ulL2BlobRefreshPktCnt_g, int, 0644);
MODULE_PARM_DESC(ulL2BlobRefreshPktCnt_g, "Integer - Freq with respect to "\
	"number of packets with which the L2 blob for a given SA");

module_param(ulL2BlobRefreshTimeInSec_g, int, 0644);
MODULE_PARM_DESC(ulL2BlobRefreshTimeInSec_g, "Unsigned Integer - Frequency "\
	"with respect to time with which the L2 blob for a given SA");

module_param(bFirewallCoExistence_g, bool, 0444);
MODULE_PARM_DESC(bFirewallCoExistence_g, "Bool - Whether ASF-IPsec co-exists "\
	"with ASF-Firewall or is in independent state");

static int __init ASFIPSec_Init(void)
{
	int  err = -EINVAL;
	ASFCap_t	asf_cap;

	ASFIPSEC_DEBUG("Entry");

	/* Get ASF Capabilities and store them for future use. */
	ASFGetCapabilities(&asf_cap);
	if (!asf_cap.mode[fwdMode]) {
		asf_err("ASF not configured in FWD mode.... Exiting\n");
		return err;
	} else if (!asf_cap.bBufferHomogenous) {
		asf_err("No Support for Hetrogenous Buffer, ...Exiting\n");
		return err;
	}

	if (!ulMaxTunnels_g || ulMaxTunnels_g > SECFP_MAX_NUM_TUNNEL_IFACES) {
		asf_err("Invalid value set for ulMaxTunnels_g =%d,'"\
			"...Exiting\n", ulMaxTunnels_g);
		return err;
	}

	if (!ulMaxSPDContainers_g
		|| ulMaxSPDContainers_g > SECFP_MAX_SPD_CONTAINERS) {
		asf_err("Invalid value set for ulMaxSPDContainers_g =%d,'"\
			"...Exiting\n", ulMaxSPDContainers_g);
		return err;
	}

	if (!ulMaxSupportedIPSecSAs_g
		|| ulMaxSupportedIPSecSAs_g > SECFP_MAX_SAS) {
		asf_err("Invalid value set for ulMaxSupportedIPSecSAs_g =%d,'"\
			"...Exiting\n", ulMaxSupportedIPSecSAs_g);
		return err;
	}

	ulMaxVSGs_g = asf_cap.ulNumVSGs;

	ASFIPSEC_DEBUG("Max VSGs = %u\r\n", ulMaxVSGs_g);
	ASFIPSEC_DEBUG("Max Tunnels = %u\r\n", ulMaxTunnels_g);
	ASFIPSEC_DEBUG("Max SPD containers = %u\r\n", ulMaxSPDContainers_g);
	ASFIPSEC_DEBUG("Max SAs = %u\r\n", ulMaxSupportedIPSecSAs_g);
	ASFIPSEC_DEBUG("Max InSA Hash Table Size = %u\r\n",
					usMaxInSAHashTaleSize_g);
	ASFIPSEC_DEBUG("Max L2Blob RefreshCnt = %u\r\n",
					ulL2BlobRefreshPktCnt_g);
	ASFIPSEC_DEBUG("Max L2Blob RefreshTime = %u\r\n",
					ulL2BlobRefreshTimeInSec_g);

	if (bFirewallCoExistence_g) {
		ASFIPSEC_DEBUG("Firewall Co-Existence : YES");
	} else {
		ASFIPSEC_DEBUG("Firewall Co-Existence : NO");
	}

	if (bTightlyIntegrated_g) {
		ASFIPSEC_DEBUG("Application and ASF tightly coupled");
	} else {
		ASFIPSEC_DEBUG("Application and ASF loosly coupled");
	}

	if (SECFP_FAILURE == secfp_init()) {
		asf_err("Failure in secfp_init.... Exiting\n");
		return err;
	}

	if (secfp_register_proc())
		ASFIPSEC_WARN("Unable to register IPSEC proc");

	ASFIPSEC_DEBUG("Exit");
	return 0;

}
static void __exit ASFIPSec_Exit(void)
{
	secfp_unregister_proc();
	secfp_deInit();
}

module_init(ASFIPSec_Init);
module_exit(ASFIPSec_Exit);

EXPORT_SYMBOL(ASFIPSecConfig);
EXPORT_SYMBOL(ASFIPSecRegisterCallbacks);
EXPORT_SYMBOL(ASFIPSecGetCapabilities);
EXPORT_SYMBOL(ASFIPSecRuntime);
EXPORT_SYMBOL(ASFIPSecSAQueryStats);
EXPORT_SYMBOL(ASFIPSecGlobalQueryStats);
EXPORT_SYMBOL(ASFIPSecSPDContainerQueryStats);
EXPORT_SYMBOL(ASFIPSecUpdateVSGMagicNumber);
EXPORT_SYMBOL(ASFIPSecUpdateTunnelMagicNumber);
EXPORT_SYMBOL(ASFIPSecInitConfigIdentity);
