/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asffwdapi.h
 *
 * Description: Header file for ASF IPv4 Forwarding API Definations.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *			Hemant Agrawal <hemant@freescale.com>
 *
 */
/*
 * History
 *  Version     Date         	Author			Change Description *
 *  1.0		01 Aug 2010   Hemant Agrawal  	Initial Version.
 *  1.1		22 Sep 2010  Sachin Saxena
 *
 */
/****************************************************************************/

#ifndef __ASFFWDAPI_H
#define __ASFFWDAPI_H

/* ASF Forwarding MAX Capacity */
#define ASF_FWD_MAX_ENTRY (8*1024)
#define ASF_FWD_MAX_HASH_BKT ASF_FWD_MAX_ENTRY

/****** Forwarding API (FFP API) **********/
typedef struct ASFFWDCacheEntryStats_s {
	/* Number of Received Packets */
	ASF_uint32_t    ulInPkts;

	/* Number of Received  Bytes */
	ASF_uint32_t    ulInBytes;

	/* Number of Packets Sent out */
	ASF_uint32_t    ulOutPkts;

	/* Number of bytes Sent out. */
	ASF_uint32_t    ulOutBytes;
} ASFFWDCacheEntryStats_t;

typedef enum {
	ASFFWD_RESPONSE_SUCCESS = 0,	/* Success */
	ASFFWD_RESPONSE_FAILURE,	/* Failure */
	ASFFWD_RESPONSE_TIMEOUT,	/* Time out */
} ASFFWDRespCode_t;


typedef struct ASFFWDCap_s {

	/* Indicates the maximum number of supported VSGs. */
	ASF_uint32_t    ulMaxVSGs;

	/*
	TRUE indicates the buffer format supported by
	ASF and AS are homogenous
	FALSE indicates the buffer format supported
	by ASF and AS are heterogenous
	*/
	ASF_boolean_t  bBufferHomogenous;

	ASF_boolean_t  bHomogenousHashAlgorithm;

	ASF_uint32_t    ulHashAlgoInitVal;

	/* Maximum number of Cache Entries that can be offloaded to ASF. */
	ASF_uint32_t ulMaxCacheEntries;

} ASFFWDCap_t;

ASF_void_t  ASFFWDGetCapabilities(ASFFWDCap_t *pCap);

/*
	bEnable When set to TRUE, ASF will
	invoke all AS optional callback functions.
	- When set to FALSE,  ASF will not invoke AS
	optional callback notification functions
*/
ASF_void_t  ASFFWDSetNotifyPreference(ASF_boolean_t bEnable);

typedef struct ASFFWDExpiryParams_s {
	ASF_uint32_t    ulExpiryInterval;
	/* Threshold in terms of Time interval in secs? */
} ASFFWDExpiryParams_t;


ASF_uint32_t ASFFWDSetCacheEntryExpiryParams(ASFFWDExpiryParams_t *info);

typedef ASF_void_t   (*pASFFWDCbFnInterfaceInfoNotFound_f)(
	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t    *freeArg
);


typedef ASF_void_t   (*pASFFWDCbFnVSGMappingNotFound_f)(
	ASF_uint32_t ulCommonInterfaceId,
	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t    *freeArg
);

typedef ASF_void_t (*pASFFWDCbFnCacheEntryNotFound_f)(
				ASF_uint32_t ulVSGId,
				ASF_uint32_t ulCommonInterfaceId,
				ASFBuffer_t Buffer,
				genericFreeFn_t pFreeFn,
				ASF_void_t *freeArg
				);


typedef ASF_void_t (*pASFFWDCbFnRuntime_f)(
				ASF_uint32_t ulVSGId,
				ASF_uint32_t cmd,
				ASF_void_t *pReqIdentifier,
				ASF_uint32_t ulReqIdentifierlen,
				ASF_void_t *pResp,
				ASF_uint32_t ulRespLen);


typedef struct ASFFWDCacheEntryExpiryCbInfo_s {
	ASFFWDCacheEntryTuple_t  tuple; /*3 tuple information of the
					forwarding cache entry. */

	ASF_uint32_t ulHashVal;	/* Hash value */
	ASFFWDCacheEntryStats_t stats;	/* Stats information pertaining to this
					forwarding cache entry */
	ASF_uint8_t     *ASFFwdInfo; /* Information provided by AS at the time
					of cache entry creation */

} ASFFWDCacheEntryExpiryCbInfo_t;

typedef  ASF_void_t (*pASFFWDCbFnCacheEntryExpiry_f)(
			ASF_uint32_t ulVSGId,
			ASFFWDCacheEntryExpiryCbInfo_t *pCacheEntryExpiryCbArg);


typedef struct ASFFWDCreateCacheEntryResp_s {
	/* tuple of the first CacheEntry */
	ASFFWDCacheEntryTuple_t  tuple;

	/* Hash value */
	ASF_uint32_t     ulHashVal;

	/* Indicates whether the API succeeded or not */
	ASFFWDRespCode_t  iResult;
} ASFFWDCreateCacheEntryResp_t;



typedef struct ASFFWDDeleteCacheEntryResp_s {
	/* tuple */
	ASFFWDCacheEntryTuple_t  tuple;

	/* Hash value */
	ASF_uint32_t ulHashVal;

	/* Indicates whether the CacheEntry deletion succeeded or not. */
	ASFFWDRespCode_t  iResult;

	/* CacheEntry statistics */
	ASFFWDCacheEntryStats_t  stats;

	/*Any optional AS context information stored in ASF by AS.*/
	ASF_uint8_t     *ASFFwdInfo;

} ASFFWDDeleteCacheEntryResp_t;


typedef struct ASFFWDCacheEntryL2BlobRefreshCbInfo_s {
	/* 3 tuple information of the packet whose L2 blob has to be resolved.*/
	ASFFWDCacheEntryTuple_t		packetTuple;

	/* Hash value */
	ASF_uint32_t			ulHashVal;

	/* Optional Parameter */
	ASFBuffer_t 			Buffer;

	/* Information provided by AS at the time of CacheEntry creation */
	ASF_uint8_t			*ASFFwdInfo;

} ASFFWDCacheEntryL2BlobRefreshCbInfo_t;

typedef  ASF_void_t (*pASFFWDCbFnCacheEntryRefreshL2Blob_f)(
		ASF_uint32_t ulVSGId,
		ASFFWDCacheEntryL2BlobRefreshCbInfo_t *pCacheEntryRefreshCbArg
		);

/*
 * Helper Callback Functions Registrationa API
 */

typedef ASF_void_t (*pASFFWDCbFnAuditLog_f)(ASFLogInfo_t *pLogInfo);


typedef struct ASFFWDCallbackFns_s {
	pASFFWDCbFnInterfaceInfoNotFound_f      pFnInterfaceNotFound;
	pASFFWDCbFnVSGMappingNotFound_f		pFnVSGMappingNotFound;
	pASFFWDCbFnCacheEntryNotFound_f		pFnCacheEntryNotFound;
	pASFFWDCbFnRuntime_f			pFnRuntime;
	pASFFWDCbFnCacheEntryExpiry_f		pFnCacheEntryExpiry;
	pASFFWDCbFnCacheEntryRefreshL2Blob_f	pFnCacheEntryRefreshL2Blob;
	pASFFWDCbFnAuditLog_f			pFnAuditLog;
} ASFFWDCallbackFns_t;


enum ASFFWDConfigCommands {
	/* Command for creating CacheEntry in ASF. */
	ASF_FWD_CREATE_CACHE_ENTRY = 1,
	/* Command for modifying CacheEntry in ASF. */
	ASF_FWD_UPDATE_CACHE_ENTRY,
	/* Command for deleting CacheEntry in ASF. - L2 blob update */
	ASF_FWD_DELETE_CACHE_ENTRY,
	/* Command for flushing CacheEntry Table in ASF. */
	ASF_FWD_FLUSH_CACHE_TABLE
};


ASF_uint32_t ASFFWDRuntime(
		ASF_uint32_t ulVSGId,
		ASF_uint32_t cmd,
		ASF_void_t *args,
		ASF_uint32_t ulArgslen,
		ASF_void_t *pReqIdentifier,
		ASF_uint32_t ulReqIdentifierlen);


/*
 * delay = 0:  The cache is flushed right away.
 * delay > 0:  The cache is flushed after the specified amount of time.
 */

ASF_uint32_t ASFFWDFlushCache(
			ASF_uint32_t ulVSGId,
			ASF_uint32_t delay,
			ASF_void_t *pReqIdentifier,
			ASF_uint32_t ulReqIdentifierlen);


ASF_void_t ASFFWDRegisterCallbackFns(ASFFWDCallbackFns_t *pFnList);


typedef struct ASFFWDConfigIdentityInfo_s {
	/* VSG configuration magic number that
	needs to be associated for the CacheEntry. */
	ASF_uint32_t    ulConfigMagicNumber;

} ASFFWDConfigIdentity_t;


typedef struct ASFFWDCacheEntry_s {
	/* Original tuple. */
	ASFFWDCacheEntryTuple_t tuple;

	/* Expirty timeout of the CacheEntry in seconds */
	ASF_uint32_t   ulExpTimeout;

} ASFFWDCacheEntry_t;

typedef struct ASFFWDCreateCacheEntry_s {
	/* CacheEntry */
	ASFFWDCacheEntry_t  CacheEntry;
	/*
	Information private to AS, that AS would like ASF to cache
	with the CacheEntry. This information is sent back upon any
	non-response callback notifications with respect to the CacheEntry
	*/
	ASF_uint8_t *ASFFwdInfo;

} ASFFWDCreateCacheEntry_t;

typedef struct ASFFWDDeleteCacheEntry_s {
	/* tuple of one of the CacheEntry */
	ASFFWDCacheEntryTuple_t tuple;
} ASFFWDDeleteCacheEntry_t;


typedef struct ASFFWDUpdateCacheEntry_s {
	/* 5 tuple to identify the CacheEntry */
	ASFFWDCacheEntryTuple_t tuple;

	ASF_uint8_t bL2blobUpdate:1;
	union {
		/* Valid when bL2blob is set */
		struct {
			/* Common  device Id to identify a specific device */
			ASF_uint32_t ulDeviceId;

			/* L2 blob data */
			ASF_uint8_t l2blob[ASF_MAX_L2BLOB_LEN];

			/* L2 blob len */
			ASF_uint16_t l2blobLen;

			/* Path MTU to be used for packets for the CacheEntry.*/
			ASF_uint16_t ulPathMTU;

			ASF_uint16_t bTxVlan:1, bUpdatePPPoELen:1;

			ASF_uint16_t usTxVlanId;

		} l2blob;

	} u;
} ASFFWDUpdateCacheEntry_t;

ASF_void_t ASFFWDProcessPkt(
			ASF_uint32_t    ulVsgId,
			ASF_uint32_t    ulCommonInterfaceId,
			ASFBuffer_t     Buffer,
			genericFreeFn_t pFreeFn,
			ASF_void_t *freeArg);

ASF_void_t ASFFWDUpdateConfigIdentity(
	ASF_uint32_t ulVSGId,
	ASFFWDConfigIdentity_t configIdentity);

/*** Extended ***/

typedef struct ASFFWDQueryCacheEntryStatsInfo_s {
	/* input */
	ASFFWDCacheEntryTuple_t tuple;
	/* output */
	ASFFWDCacheEntryStats_t stats;	/* Statistics of given CacheEntry */
} ASFFWDQueryCacheEntryStatsInfo_t;

int ASFFWDQueryCacheEntryStats(
			ASF_uint32_t ulVsgId,
			ASFFWDQueryCacheEntryStatsInfo_t *p);

#endif
