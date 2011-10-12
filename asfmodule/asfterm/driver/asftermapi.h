/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asf_termapi.h
 *
 * Description: Header file for ASF Termination API Definations.
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/*
 * History
 * Version	Date		Author		Change Description *
 * 1.0		01 Feb 2010	Hemant Agrawal	Initial Version.
 *
 */
/****************************************************************************/

#ifndef __ASFTERMAPI_H
#define __ASFTERMAPI_H

/****** Termination API (Term API) **********/
typedef struct ASFTERMCacheEntryStats_s {
	/* Number of Received Packets */
	ASF_uint32_t ulInPkts;

	/* Number of Received Bytes */
	ASF_uint32_t ulInBytes;

	/* Number of Packets Sent out */
	ASF_uint32_t ulOutPkts;

	/* Number of bytes Sent out. */
	ASF_uint32_t ulOutBytes;
} ASFTERMCacheEntryStats_t;

typedef enum {
	ASFTERM_RESPONSE_SUCCESS = 0,	/* Success */
	ASFTERM_RESPONSE_FAILURE,	/* Failure */
	ASFTERM_RESPONSE_TIMEOUT,	/* Time out */
} ASFTERMRespCode_t;


typedef struct ASFTERMCap_s {

	/* Indicates the maximum number of supported VSGs. */
	ASF_uint32_t ulMaxVSGs;

	/*
	TRUE indicates the buffer format supported by
	ASF and AS are homogenous
	FALSE indicates the buffer format supported
	by ASF and AS are heterogenous
	*/
	ASF_boolean_t bBufferHomogenous;

	ASF_boolean_t bHomogenousHashAlgorithm;

	ASF_uint32_t ulHashAlgoInitVal;

	/* Maximum number of Cache Entries that can be offloaded to ASF. */
	ASF_uint32_t ulMaxCacheEntries;

} ASFTERMCap_t;

ASF_void_t ASFTERMGetCapabilities(ASFTERMCap_t *pCap);

/*
	bEnable When set to TRUE, ASF will
	invoke all AS optional callback functions.
	- When set to FALSE, ASF will not invoke AS
	optional callback notification functions
*/
ASF_void_t ASFTERMSetNotifyPreference(ASF_boolean_t bEnable);

typedef ASF_void_t (*pASFTERMCbFnInterfaceInfoNotFound_f)(
	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t *freeArg
);

typedef ASF_void_t (*pASFTERMCbFnVSGMappingNotFound_f)(
	ASF_uint32_t ulCommonInterfaceId,
	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t *freeArg
);

typedef ASF_void_t (*pASFTERMCbFnCacheEntryNotFound_f)(
	ASF_uint32_t ulVSGId,
	ASF_uint32_t ulCommonInterfaceId,
	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t *freeArg,
	ASF_void_t	*pIpsecOpaque,
	ASF_boolean_t	sendOut);


typedef ASF_void_t (*pASFTERMCbFnRuntime_f)(
	ASF_uint32_t ulVSGId,
	ASF_uint32_t cmd,
	ASF_void_t *pReqIdentifier,
	ASF_uint32_t ulReqIdentifierlen,
	ASF_void_t *pResp,
	ASF_uint32_t ulRespLen);


typedef struct ASFTERMCacheEntryExpiryCbInfo_s {
	ASFTERMCacheEntryTuple_t tuple; /*7 tuple information of the
					forwarding cache entry. */
	ASF_uint32_t ulHashVal;	/* Hash value */
	ASFTERMCacheEntryStats_t stats;	/* Stats information pertaining to this
					forwarding cache entry */
	ASF_uint32_t *ASFTermInfo; /* Information provided by AS at the time
					of cache entry creation */
} ASFTERMCacheEntryExpiryCbInfo_t;

typedef ASF_void_t (*pASFTERMCbFnCacheEntryExpiry_f)(
	ASF_uint32_t ulVSGId,
	ASFTERMCacheEntryExpiryCbInfo_t *pCacheEntryExpiryCbArg);


typedef struct ASFTERMCreateCacheEntryResp_s {
	/* tuple of the first CacheEntry */
	ASFTERMCacheEntryTuple_t tuple;

	/* Hash value */
	ASF_uint32_t ulHashVal;

	/* Indicates whether the API succeeded or not */
	ASFTERMRespCode_t iResult;
} ASFTERMCreateCacheEntryResp_t;



typedef struct ASFTERMDeleteCacheEntryResp_s {
	/* tuple */
	ASFTERMCacheEntryTuple_t tuple;

	/* Hash value */
	ASF_uint32_t ulHashVal;

	/* Indicates whether the CacheEntry deletion succeeded or not. */
	ASFTERMRespCode_t iResult;

	/* CacheEntry statistics */
	ASFTERMCacheEntryStats_t stats;

	/*Any optional AS context information stored in ASF by AS.*/
	ASF_uint32_t *ASFTermInfo;

} ASFTERMDeleteCacheEntryResp_t;

typedef struct ASFTERMCacheEntryL2BlobRefreshCbInfo_s {
	/* 3 tuple information of the packet whose L2 blob has to be resolved.*/
	ASFTERMCacheEntryTuple_t	packetTuple;

	/* Hash value */
	ASF_uint32_t			ulHashVal;

	/* Optional Parameter */
	ASFBuffer_t 			Buffer;

	/* Information provided by AS at the time of CacheEntry creation */
	ASF_uint32_t			*ASFTermInfo;

} ASFTERMCacheEntryL2BlobRefreshCbInfo_t;

typedef ASF_void_t (*pASFTERMCbFnCacheEntryRefreshL2Blob_f)(
	ASF_uint32_t ulVSGId,
	ASFTERMCacheEntryL2BlobRefreshCbInfo_t *pCacheEntryRefreshCbArg);

typedef ASF_void_t (*pASFTERMCbFnCacheRcvPkt_f)(
	/* The VSG Id for which the flow was created */
	ASF_uint32_t ulVSGId,
	/* Interface (Physical or Logical on which the packet arrived). */
	ASF_uint32_t ulCommonInterfaceId,
	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t *freeArg);

typedef struct ASFTERMCacheValidateCbInfo_s {
	/* 7 tuple information identifying the cache */
	ASFTERMCacheEntryTuple_t	tuple;

	/* Hash value calculated for the flow */
	ASF_uint32_t ulHashVal;

	ASF_uint32_t	bLocalTerm:1;

	/* Information provided by AS at the time of Flow creation */
	ASF_uint32_t	*ASTermInfo;

} ASFTERMCacheValidateCbInfo_t;

typedef ASF_void_t (*pASFTERMCbFnCacheValidate_f) (
	ASF_uint32_t ulVSGId,
	ASFTERMCacheValidateCbInfo_t *pInfo);

typedef ASF_void_t (*pASFTERMCbFnAuditLog_f)(ASFLogInfo_t *pLogInfo);

/*
 * Helper Callback Functions Registration API
 */

typedef struct ASFTERMCallbackFns_s {
	pASFTERMCbFnInterfaceInfoNotFound_f	pFnInterfaceNotFound;
	pASFTERMCbFnVSGMappingNotFound_f	pFnVSGMappingNotFound;
	pASFTERMCbFnCacheEntryNotFound_f	pFnCacheEntryNotFound;
	pASFTERMCbFnRuntime_f			pFnRuntime;
	pASFTERMCbFnCacheEntryExpiry_f		pFnCacheEntryExpiry;
	pASFTERMCbFnCacheEntryRefreshL2Blob_f	pFnCacheEntryRefreshL2Blob;
	pASFTERMCbFnCacheRcvPkt_f		pFnRcvPkt;
	pASFTERMCbFnCacheValidate_f		pFnValidate;
	pASFTERMCbFnAuditLog_f			pFnAuditLog;
} ASFTERMCallbackFns_t;


enum ASFTERMConfigCommands {
	/* Command for creating CacheEntry in ASF. */
	ASF_TERM_CREATE_CACHE_ENTRY = 1,
	/* Command for modifying CacheEntry in ASF. */
	ASF_TERM_UPDATE_CACHE_ENTRY,
	/* Command for deleting CacheEntry in ASF. - L2 blob update */
	ASF_TERM_DELETE_CACHE_ENTRY,
	/* Command for flushing CacheEntry Table in ASF. */
	ASF_TERM_FLUSH_CACHE_TABLE
};


ASF_uint32_t ASFTERMRuntime(
	ASF_uint32_t ulVSGId,
	ASF_uint32_t cmd,
	ASF_void_t *args,
	ASF_uint32_t ulArgslen,
	ASF_void_t *pReqIdentifier,
	ASF_uint32_t ulReqIdentifierlen);


/*
 * delay = 0: The cache is flushed right away.
 * delay > 0: The cache is flushed after the specified amount of time.
 */

ASF_uint32_t ASFTERMFlushCache(
	ASF_uint32_t ulVSGId,
	ASF_uint32_t delay,
	ASF_void_t *pReqIdentifier,
	ASF_uint32_t ulReqIdentifierlen);


ASF_void_t ASFTERMRegisterCallbackFns(ASFTERMCallbackFns_t *pFnList);


typedef struct ASFTERMConfigIdentityInfo_s {
	/* VSG configuration magic number that
	needs to be associated for the CacheEntry. */
	ASF_uint32_t ulConfigMagicNumber;

} ASFTERMConfigIdentity_t;


typedef struct ASFTERMCacheEntry_s {
	/* Original tuple. */
	ASFTERMCacheEntryTuple_t tuple;

	/* Expirty timeout of the CacheEntry in seconds */
	ASF_uint32_t ulExpTimeout;

	ASF_uint32_t /*flags */
		/* TRUE or FALSE: indicates if IPsec Inbound processing needs
			to happen on the flow */
		bIPsecIn : 1,

		/* TRUE or FALSE; indicates if IPsec Outbound Processing needs
			to happen on the flow */
		bIPsecOut:1,

		/* TRUE or FALSE; indicates if the route terminates locally */
		bLocalTerm:1;
	/*
		This holds the IPsec Inbound and Outbound processing
		information for the flow. They are valid when bIpsecIn
		and bIpsecOut set to TRUE respectively;
	*/
	ASFFFPIpsecInfo_t ipsecInInfo;
} ASFTERMCacheEntry_t;

typedef struct ASFTERMCreateCacheEntry_s {
	/* CacheEntry in Forward Side*/
	ASFTERMCacheEntry_t entry1;

	/* CacheEntry in Reverse Side*/
	ASFTERMCacheEntry_t entry2;
	/*
	Information private to AS, that AS would like ASF to cache
	with the CacheEntry. This information is sent back upon any
	non-response callback notifications with respect to the CacheEntry
	*/
	ASF_uint32_t *ASFTermInfo;
	/*
		Config identification that needs to be associated to the flow.
		Helps in revalidation upon policy change
	*/
	ASFFFPConfigIdentity_t configIdentity;
} ASFTERMCreateCacheEntry_t;

typedef struct ASFTERMDeleteCacheEntry_s {
	/* tuple of one of the CacheEntry */
	ASFTERMCacheEntryTuple_t tuple;
} ASFTERMDeleteCacheEntry_t;

typedef struct ASFTERMUpdateCacheEntry_s {
	/* 5 tuple to identify the CacheEntry */
	ASFTERMCacheEntryTuple_t tuple;

	ASF_uint8_t
		bL2blobUpdate : 1,
		bTERMConfigIdentityUpdate:1,
		bIPsecConfigIdentityUpdate:1;
	union {
		/* Valid when bL2blob is set */
		struct {
			/* Common device Id to identify a specific device */
			ASF_uint32_t ulDeviceId;

			/* L2 blob data */
			ASF_uint8_t l2blob[ASF_MAX_L2BLOB_LEN];

			/* L2 blob len */
			ASF_uint16_t l2blobLen;

			/* Path MTU to be used for packets for the CacheEntry.*/
			ASF_uint16_t ulPathMTU;

			ASF_uint32_t ulL2blobMagicNumber;

			ASF_uint16_t bTxVlan:1, bUpdatePPPoELen:1;

			ASF_uint16_t usTxVlanId;

		} l2blob;

		/* Valid when bTERMConfigIdentityChange is set */
		ASFFFPConfigIdentity_t termConfigIdentity;

		struct {
			ASF_uint32_t
			/* TRUE or FALSE: indicates if IPsec Inbound Identity
				to be updated*/
			bIn : 1,

			/* TRUE or FALSE: indicates if IPsec Inbound processing
				needs to happen on the flow */
			bIPsecIn:1,

			/* TRUE or FALSE: indicates if IPsec outbound Identity
				to be updated*/
			bOut:1,

			/* TRUE or FALSE: indicates if IPsec outbound processing
				needs to happen on the flow */
			bIPsecOut:1;

			/* Valid when bIPsecConfigIdentity is set */
			ASFFFPIpsecInfo_t ipsecInfo;
		} ipsec;
	} u;
} ASFTERMUpdateCacheEntry_t;

ASF_void_t ASFTERMProcessPkt(
	ASF_uint32_t	ulVsgId,
	ASF_uint32_t	ulCommonInterfaceId,
	ASFBuffer_t	Buffer,
	genericFreeFn_t	pFreeFn,
	ASF_void_t	*freeArg,
	ASF_void_t	*pIpsecOpaque,
	/* Recvd from VPN In Hook */
	ASF_boolean_t	sendOut);

ASF_void_t ASFTERMUpdateConfigIdentity(
	ASF_uint32_t ulVSGId,
	ASFTERMConfigIdentity_t configIdentity);

/*** Extended ***/
typedef struct ASFTERMQueryCacheEntryStatsInfo_s {
	/* input */
	ASFTERMCacheEntryTuple_t tuple;
	/* output */
	ASFTERMCacheEntryStats_t stats;	/* Statistics of given CacheEntry */
	ASFTERMCacheEntryStats_t other_stats;	/* Statistics of other flow */
} ASFTERMQueryCacheEntryStatsInfo_t;

int ASFTERMQueryCacheEntryStats(
	ASF_uint32_t ulVsgId,
	ASFTERMQueryCacheEntryStatsInfo_t *p);
#endif
