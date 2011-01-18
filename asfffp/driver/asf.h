/***************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ****************************************************************************/
/*
 * File:	asf.h
 *
 * Authors:	Venkataraman Subhashini <B22166@freescale.com>
 *
 */
/****************************************************************************/
#ifndef __ASFAPI_H
#define __ASFAPI_H

#include "asfhash.h"

#define ASF_MINIMUM 1
#define ASF_LINUX 2
#define ASF_FULL 3
enum {
	ASF_SUCCESS = 0,
	ASF_FAILURE = -1
};


/****** Common API ********/
#define ASF_MAX_VSGS		(2)
#define ASF_MAX_IFACES		(16)
#define ASF_MAX_L2BLOB_LEN	(28)

#define ASF_MAX_L2BLOB_REFRESH_PKT_CNT	(0)
#define ASF_MAX_L2BLOB_REFRESH_TIME	(3*60)

#define	ASF_MAX_OLD_L2BLOB_JIFFIES_TIMEOUT	(10*HZ)


#define ASF_L2BLOB_REFRESH_NORMAL	(1)
#define ASF_L2BLOB_REFRESH_RET_PKT_STK	(2)
#define ASF_L2BLOB_REFRESH_DROP_PKT	(3)

typedef char     ASF_char8_t;
typedef unsigned int ASF_uint32_t;
typedef unsigned char ASF_uchar8_t;
typedef unsigned char ASF_uint8_t;
typedef unsigned char ASF_boolean_t;
typedef unsigned short int ASF_uint16_t;

#define ASF_TRUE	((ASF_boolean_t)1)
#define ASF_FALSE	((ASF_boolean_t)0)

typedef void ASF_void_t;

typedef ASF_uint32_t ASF_IPv4Addr_t;

/*
 * ASF_Modes_t mode - indicates the basic mode of operations such
 * as firewall , forwarding
*/
typedef enum {
	fwMode = 0,	/* Firewall mode */
	fwdMode = 1,	/* Forwarding mode */
	numModes = 2, /*number of modes being supported */
} ASF_Modes_t;

typedef struct ASF_Funcs_s {
	ASF_uint32_t
		bIPsec : 1; /*IPsec function */
} ASF_Functions_t;

typedef struct ASFCap_s {

	ASF_uint32_t ulNumVSGs;	/* Maximum number of VSGs supported by ASF */

	ASF_uint32_t ulNumIfaces; /*Maxium Number of Interfaces supported by ASF*/

	/* TRUE indicates the buffer format supported by ASF and AS are homogenous
	   FALSE indicates the buffer format supported by ASF and AS are heterogenous
	*/

	ASF_boolean_t  bBufferHomogenous;

	ASF_Modes_t mode[numModes];
	 /* Basic Modes available such as Firewall, forwarding etc. */
	ASF_Functions_t func; /* Offloadable functions in ASF. */
} ASFCap_t;

ASF_void_t ASFGetCapabilities(ASFCap_t *pCap);



enum {
	ASF_IFACE_TYPE_ETHER = 0,
	ASF_IFACE_TYPE_BRIDGE,
	ASF_IFACE_TYPE_VLAN,
	ASF_IFACE_TYPE_PPPOE,
	ASF_IFACE_TYPE_MAX
} ;


typedef struct ASFInterfaceInfo_s {
	ASF_uint32_t    ulDevType;
	ASF_uint32_t    ulMTU;
	ASF_uint8_t     *ucDevIdentifierInPkt;
	ASF_uint32_t    ulDevIdentiferInPktLen;
	ASF_uint32_t *ulRelatedIDs;
	ASF_uint32_t    ulNumRelatedIDs;
	/* TODO: Integrate with underlying Common Interface Id- when required*/
} ASFInterfaceInfo_t;

ASF_uint32_t ASFMapInterface(ASF_uint32_t ulCommonInterfaceId,
	ASFInterfaceInfo_t *asfInterface);

ASF_uint32_t ASFUnMapInterface(ASF_uint32_t ulCommonInterfaceId);


ASF_uint32_t ASFBindDeviceToVSG(ASF_uint32_t ulVSGId,
	ASF_uint32_t ulCommonInterfaceId);

ASF_uint32_t ASFUnBindDeviceToVSG(ASF_uint32_t ulVSGId,
	ASF_uint32_t ulDeviceId);

ASF_uint32_t ASFRemove(ASF_void_t);

ASF_uint32_t ASFDeploy(ASF_void_t);

ASF_uint32_t ASFSetVSGMode(ASF_uint32_t ulVSGId, ASF_Modes_t  mode);

ASF_uint32_t ASFGetVSGMode(ASF_uint32_t ulVSGId, ASF_Modes_t *mode);

ASF_uint32_t ASFEnableVSGFunctions(ASF_uint32_t ulVSGId, ASF_Functions_t funcs);

ASF_uint32_t ASFDisableVSGFunctions(ASF_uint32_t ulVSGId, ASF_Functions_t funcs);

ASF_uint32_t ASFGetVSGFunctions(ASF_uint32_t ulVSGId, ASF_Functions_t *funcs);

int ASFGetStatus(ASF_void_t);

ASF_uint32_t ASFGetAPIVersion(ASF_uint8_t Ver[]);

typedef struct ASFReasmParams_s {
	/* indicates the time, in seconds, for which ASF should wait for all IP fragments to arrive. */
	ASF_uint32_t    ulReasmTimeout;

	/* indicates Max number of fragments of a given IP Packet */
	ASF_uint32_t    ulReasmMaxFrags;

	/* Minimum size that non-final fragments should be */
	ASF_uint32_t    ulReasmMinFragSize;

} ASFReasmParams_t;


ASF_uint32_t ASFSetReasmParams(ASF_uint32_t ulVSGId, ASFReasmParams_t *pInfo);

typedef struct ASFFWDCacheEntryTuple_s {
	ASF_IPv4Addr_t	ulSrcIp; /* Source IP Address */
	ASF_IPv4Addr_t	ulDestIp; /* Destination IP Address */
	ASF_uint8_t 	ucDscp;   /* DSCP Value */
} ASFFWDCacheEntryTuple_t;


typedef struct ASFFFPL2blobConfig_s {
	ASF_uint32_t	ulL2blobMagicNumber;
	ASF_uint32_t	ulOldL2blobJiffies;
	ASF_boolean_t	bl2blobRefreshSent;
} ASFFFPL2blobConfig_t;

/****** Firewall API (FFP API) **********/




typedef enum {
	ASFFFP_RESPONSE_SUCCESS = 0,	/* Success */
	ASFFFP_RESPONSE_FAILURE,	/* Failure */
	ASFFFP_RESPONSE_TIMEOUT,	/* Time out */
} ASFFFPRespCode_t;


typedef struct ASFFFPFlowTuple_s {
	ASF_IPv4Addr_t    ulSrcIp; /* Source IP Address */
	ASF_IPv4Addr_t    ulDestIp; /* Destination IP Address */
	ASF_uint16_t usSrcPort;	/* Source Port */
	ASF_uint16_t usDestPort; /* Destination Port */
	ASF_uint8_t ucProtocol;	/* IP Protocol */

} ASFFFPFlowTuple_t;



typedef struct ASFFFPCap_s {

	/* Indicates the maximum number of supported VSGs. */
	ASF_uint32_t    ulMaxVSGs;

	/*
		TRUE indicates the buffer format supported by ASF and AS are homogenous
		FALSE indicates the buffer format supported by ASF and AS are heterogenous
	*/
	ASF_boolean_t  bBufferHomogenous ;

	/* Maximum number of flows that can be offloaded to ASF. */
	ASF_uint32_t    ulMaxFlows ;


	ASF_boolean_t  bHomogenousHashAlgorithm ; /* TODO: ?? */

	ASF_uint32_t    ulHashAlgoInitVal;


} ASFFFPCap_t;

ASF_void_t  ASFFFPGetCapabilities(ASFFFPCap_t *pCap);




/*
	bEnable When set to TRUE, ASF will invoke all AS's optional callback functions.
	- When set to FALSE,  ASF will not invoke AS's optional callback notification functions
*/
ASF_void_t  ASFFFPSetNotifyPreference(ASF_boolean_t bEnable);





ASF_uint32_t ASFFFPBindInterfaceToZone(ASF_uint32_t ulVSGId, ASF_uint32_t ulDeviceId, ASF_uint32_t ulZoneId);

ASF_uint32_t ASFFFPUnBindInterfaceToZone(ASF_uint32_t ulVSGId,  ASF_uint32_t ulDeviceId, ASF_uint32_t ulZoneId);


typedef struct ASFFFPL2blobParams_s {
	/* Threshold in terms of number of packets */
	ASF_uint32_t    ulL2blobNumPkts;

	/* Threshold in terms of Time interval in secs? */
	ASF_uint32_t    ulL2blobInterval;

} ASFFFPL2blobParams_t;


ASF_uint32_t ASFFFPSetL2blobParams(ASFFFPL2blobParams_t *pInfo);




typedef struct ASFFFPInacRefreshParams_s {
	/* number of times a refresh inactivity refresh indication
	   is sent with in inactivity time out of a flow */
	ASF_uint32_t    ulDivisor;
} ASFFFPInacRefreshParams_t;


ASF_uint32_t  ASFFFPSetInacRefreshParams(ASFFFPInacRefreshParams_t *pInfo);





typedef struct ASFFFPTcpCtrlParams_s {
	/*
		 TRUE indicates that Out of Sequence TCP packets will be dropped.
		 FALSE indicates no action needs to be taken.
	*/

	ASF_boolean_t   bDropOutOfSeq;
} ASFFFPTcpCtrlParams_t;

ASF_uint32_t ASFFFPSetTcpCtrlParams(ASF_uint32_t  ulVSGId,
			ASFFFPTcpCtrlParams_t *pInfo);



typedef union ASFBuffer_u {
	struct {
		ASF_void_t     *buffer;
		ASF_uint32_t ulBufLen;
	} linearBuffer;
	ASF_void_t     *nativeBuffer;
} ASFBuffer_t;
typedef ASF_void_t (*genericFreeFn_t)(ASF_void_t   *freeArg);

typedef ASF_void_t (*pASFFFPCbFnInterfaceInfoNotFound_f) (
				ASFBuffer_t Buffer,
				genericFreeFn_t pFreeFn,
				ASF_void_t *freeArg
				);


typedef ASF_void_t (*pASFFFPCbFnVSGMappingNotFound_f) (
				ASF_uint32_t ulCommonInterfaceId,
				ASFBuffer_t Buffer,
				genericFreeFn_t pFreeFn,
				ASF_void_t *freeArg
				);



typedef ASF_void_t (*pASFFFPCbFnZoneMappingNotFound_f) (
	/* The VSG Id identified for the flow */
	ASF_uint32_t ulVSGId,

	/* Interface on which the packet arrived can be logical or physical. */
	ASF_uint32_t ulCommonInterfaceId,

	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t *freeArg
	);



typedef ASF_void_t (*pASFFFPCbFnNoFlowFound_f)(
	/* The VSG Id for which the flow has to be created */
	ASF_uint32_t ulVSGId,

	/* Interface (Physical or Logical on which the packet arrived). */
	ASF_uint32_t ulCommonInterfaceId,

	/* Zone ID as identified by ASF. */
	ASF_uint32_t ulZoneId,

	ASFBuffer_t Buffer,
	genericFreeFn_t pFreeFn,
	ASF_void_t *freeArg
	);


typedef ASF_void_t (*pASFFFPCbFnRuntime_f)(
	ASF_uint32_t ulVSGId,
	ASF_uint32_t cmd,
	ASF_void_t *pReqIdentifier,
	ASF_uint32_t ulReqIdentifierlen,
	ASF_void_t *pResp,
	ASF_uint32_t ulRespLen
	);


typedef struct ASFFFPCreateFlowsResp_s {
	/* tuple of the first flow */
	ASFFFPFlowTuple_t	       tuple;
	ASF_uint32_t		    ulZoneId;

	/* Hash value */
	ASF_uint32_t	    ulHashVal;

	/* Indicates whether the API succeeded or not */
	ASFFFPRespCode_t		iResult;

} ASFFFPCreateFlowsResp_t;


typedef struct ASFFFPFlowStats_s {
	/* Number of Received Packets */
	ASF_uint32_t    ulInPkts;

	/* Number of Received  Bytes */
	ASF_uint32_t    ulInBytes;

	/* Number of Packets Sent out */
	ASF_uint32_t    ulOutPkts;

	/* Number of bytes Sent out. */
	ASF_uint32_t    ulOutBytes;
} ASFFFPFlowStats_t;


typedef struct ASFFFPDeleteFlowsResp_s {
	/* tuple */
	ASFFFPFlowTuple_t	       tuple;
	ASF_uint32_t		    ulZoneId;

	/* Hash value */
	ASF_uint32_t ulHashVal;

	/* Indicates whether the flow deletion succeeded or not. */
	ASFFFPRespCode_t		iResult;

	/* Client to server flow statistics */
	ASFFFPFlowStats_t	       flow1Stats;

	/* Server to client flow statistics */
	ASFFFPFlowStats_t	       flow2Stats;

} ASFFFPDeleteFlowsResp_t;




typedef struct AFSFFFPFlowL2BlobRefreshCbInfo_s {
	/* 5 tuple information of the packet whose L2 blob has to be resolved.*/
	ASFFFPFlowTuple_t	packetTuple;
	ASF_uint32_t		ulZoneId;

	/* Optional -  5 tuple information identifying the flow;
	Valid for cases where packetTuple is transformed information. */
	ASFFFPFlowTuple_t	flowTuple;

	/* Hash value */
	ASF_uint32_t		ulHashVal;

	/* Optional Parameter */
	ASFBuffer_t		Buffer;

	/* Information provided by AS at the time of Flow creation */
	ASF_uint8_t		*ASFwInfo;

} ASFFFPFlowL2BlobRefreshCbInfo_t;

typedef  ASF_void_t (*pASFFFPCbFnFlowRefreshL2Blob_f)(ASF_uint32_t ulVSGId,
	ASFFFPFlowL2BlobRefreshCbInfo_t *pFlowRefreshCbArg);





typedef struct ASFFFPFlowRefreshInfo_s {
	/* 5 tuple identifying the flow */
	ASFFFPFlowTuple_t       tuple;
	ASF_uint32_t	    ulZoneId;

	/* time in seconds , where there has been no activity on the flow */
	ASF_uint32_t	    ulInactiveTime;

	/* Hash value computed off the flow tuples */
	ASF_uint32_t    ulHashVal;

	/* Information provided by AS at the time of Flow creation */
	ASF_uint8_t     *ASFwInfo;

	/* Flow statistics */
	ASFFFPFlowStats_t      flow_stats;

} ASFFFPFlowRefreshInfo_t;



typedef ASF_void_t (*pASFFFPCbFnFlowActivityRefresh_f)(ASF_uint32_t ulVSGId, ASFFFPFlowRefreshInfo_t *pRefreshInfo);




enum {
	ASF_FFP_TCP_STATE_RST_RCVD = 1,
	ASF_FFP_TCP_STATE_FIN_RCVD,
	ASF_FFP_TCP_STATE_FIN_COMP
} ;

typedef struct ASFFFPFlowSpecialPacketsInfo_s {
	/* 5 tuple information identified for the flow */
	ASFFFPFlowTuple_t       tuple;
	ASF_uint32_t	    ulZoneId;

	/* Hash value calculated for the flow */
	ASF_uint32_t    ulHashVal;

	/* Information provided by AS at the time of Flow creation */
	ASF_uint8_t     *ASFwInfo;

	/* indication if TCP FIN or RST packets are received */
	ASF_uint32_t	    ulTcpState;
/*					bRSTRecvd:1,
					bFINRecvd:1,
					bFINExchangeComplete:1 */

	ASFFFPFlowStats_t       flow_stats;
	ASFFFPFlowStats_t       other_stats;
} ASFFFPFlowSpecialPacketsInfo_t;


typedef ASF_void_t (*pASFFFPCbFnTCPSpecialPkts_f) (ASF_uint32_t ulVSGId, ASFFFPFlowSpecialPacketsInfo_t *pPktInfo);




typedef struct ASFFFPFlowValidateCbInfo_s {
	/* 5 tuple information identifying the flow */
	ASFFFPFlowTuple_t       tuple;
	ASF_uint32_t	    ulZoneId;

	/* Hash value calculated for the flow */
	ASF_uint32_t ulHashVal;

	/* Information provided by AS at the time of Flow creation  */
	ASF_uint8_t     *ASFwInfo;

} ASFFFPFlowValidateCbInfo_t;

typedef  ASF_void_t (*pASFFFPCbFnFlowValidate_f) (ASF_uint32_t ulVSGId, ASFFFPFlowValidateCbInfo_t *pInfo);




/*
 * Helper Callback Functions Registrationa API
 */


enum {
	ASF_LOG_ID_DUMMY = 0, /* This is reserved and no log gets geerated with this ID */

	ASF_LOG_ID_SHORT_IP_HDR,
	ASF_LOG_ID_TRUNCATED_IP_PKT,
	ASF_LOG_ID_SHORT_UDP_HDR,
	ASF_LOG_ID_SHORT_TCP_HDR,

	ASF_LOG_ID_INVALID_UDP_HDRLEN,
	ASF_LOG_ID_INVALID_TCP_HDRLEN,

	/* TCP State processing related */
	ASF_LOG_ID_TCP_BAD_SEQ_NO,
	ASF_LOG_ID_TCP_BAD_ACK_SEQ,
	ASF_LOG_ID_TCP_BAD_RST_SEQ,
	ASF_LOG_ID_TCP_BAD_RST_ACK_SEQ,
	ASF_LOG_ID_TCP_BAD_URG_PTR,
	ASF_LOG_ID_TCP_BAD_URG_PTR_BUT_NO_DATA,
	ASF_LOG_ID_TCP_NO_URG_BIT,

	ASF_LOG_ID_MAX
} ;

typedef struct ASF_IPAddr_st {
	ASF_boolean_t bIPv4OrIPv6;
	union {
		ASF_uint32_t ipv4addr;
		ASF_uint32_t ipv6addr[4];
	} ;
} ASF_IPAddr_t;

typedef struct {
	ASF_uint8_t  IP_Version; /* 4 = IPv4, 6 = IPv6 */
	ASF_IPAddr_t srcIP;
	ASF_IPAddr_t dstIP;
} ASF_IPSecTunEndAddr_t;
#define ASF_MAX_MESG_LEN 200

typedef struct ASFLogInfo_s {
	ASF_uint32_t ulVSGId;
	ASF_uint32_t ulMsgId; /* Message Id. */
	ASF_char8_t *aMsg; /* Message to be logged. */
	union {
		struct {
			ASFFFPFlowTuple_t tuple;
			ASF_uint32_t ulZoneId;
			ASF_uint32_t ulHashVal;
		} fwInfo;
		struct {
			ASFFWDCacheEntryTuple_t tuple;
			ASF_uint32_t ulHashVal;
		} fwdInfo;
		struct {
			ASF_uchar8_t ucDirection;
			ASF_uint32_t ulSPDContainerIndex;
			ASF_uint32_t TunnelId;
			ASF_IPSecTunEndAddr_t Address;
			ASF_uint8_t ucProtocol;
			ASF_uint32_t ulSPI;
			ASF_uint32_t ulSeqNumber;
			ASF_uint32_t ulPathMTU;
			ASF_uint32_t ulNumOfPktsProcessed;
			ASF_uint32_t ulNumOfBytesProcessed;
		} IPSecInfo;
	} u;
} ASFLogInfo_t;


typedef ASF_void_t (*pASFFFPCbFnAuditLog_f)(ASFLogInfo_t  *pLogInfo);


typedef struct ASFFFPCallbackFns_s      {
	pASFFFPCbFnInterfaceInfoNotFound_f      pFnInterfaceNotFound;
	pASFFFPCbFnVSGMappingNotFound_f	 pFnVSGMappingNotFound;
	pASFFFPCbFnZoneMappingNotFound_f	pFnZoneMappingNotFound;
	pASFFFPCbFnNoFlowFound_f		pFnNoFlowFound;
	pASFFFPCbFnRuntime_f		    pFnRuntime;
	pASFFFPCbFnFlowRefreshL2Blob_f	  pFnFlowRefreshL2Blob;
	pASFFFPCbFnFlowActivityRefresh_f	pFnFlowActivityRefresh;
	pASFFFPCbFnTCPSpecialPkts_f	     pFnFlowTcpSpecialPkts;
	pASFFFPCbFnFlowValidate_f	       pFnFlowValidate;
	pASFFFPCbFnAuditLog_f		   pFnAuditLog;
} ASFFFPCallbackFns_t;


enum ASFFFPConfigCommands {
	ASF_FFP_CREATE_FLOWS = 1,	/* Command for creating flows in ASF. */
	ASF_FFP_DELETE_FLOWS, /* Command for deleting flows in ASF. */
	ASF_FFP_MODIFY_FLOWS /* Command for modifying flow in ASF. */
} ;


ASF_uint32_t ASFFFPRuntime (
			   ASF_uint32_t ulVSGId,
			   ASF_uint32_t cmd,
			   ASF_void_t *args,
			   ASF_uint32_t ulArgslen,
			   ASF_void_t *pReqIdentifier,
			   ASF_uint32_t ulReqIdentifierlen) ;



ASF_void_t ASFFFPRegisterCallbackFns(ASFFFPCallbackFns_t *pFnList);

typedef struct ASFFFPConfigIdentityInfo_s {
	ASF_uint32_t bL2blobMagicNumber:1;
	/* VSG configuration magic number that needs to be associated for the flow. */
	ASF_uint32_t    ulConfigMagicNumber;
	ASFFFPL2blobConfig_t	l2blobConfig;
} ASFFFPConfigIdentity_t;


typedef struct ASFFFPNATInfo_s {
	/* Source IP Address */
	ASF_IPv4Addr_t    ulSrcNATIp;

	/* Destination IP Address */
	ASF_IPv4Addr_t    ulDestNATIp;

	/* Source NAT Port */
	ASF_uint16_t usSrcNATPort;

	/* Destination NAT Port */
	ASF_uint16_t usDestNATPort;

} ASFFFPNATInfo_t;

typedef struct ASFFFPIpsecConfigIdentity_s {
	/* VSG Configuration Magic Number to be associated to the SPD containers for the flow */
	ASF_uint32_t ulVSGConfigMagicNumber;

	/* Tunnel Configuration Magic Number to be associated to the Tunnel */
	ASF_uint32_t  ulTunnelConfigMagicNumber;

} ASFFFPIpsecConfigIdentity_t;

typedef struct ASFFFPIpsecContainerInfo_s {
	ASF_uint32_t    ulTunnelId;
	ASF_uint32_t ulSPDContainerId;
	ASF_uint32_t ulSPDMagicNumber;
	ASF_uint32_t		 ulTimeStamp;
	ASFFFPIpsecConfigIdentity_t  configIdentity;
} ASFFFPIpsecContainerInfo_t;

typedef struct ASFFFPIpsecSAInfo_s {
	ASF_uint32_t ulSAMagicNumber;
	ASF_uint32_t ulSAIndex;
} ASFFFPIpsecSAInfo_t;




typedef struct ASFFFPIpsecInfo_s {
	ASFFFPIpsecContainerInfo_t   outContainerInfo;
	ASFFFPIpsecContainerInfo_t   inContainerInfo;
	ASFFFPIpsecSAInfo_t	  outSAInfo;
} ASFFFPIpsecInfo_t;



typedef struct ASFFFPTcpState_s {
	/* Current Seq Num + Segment Length */
	ASF_uint32_t    ulHighSeqNum;

	/* Current Sequence Delta in case of SynCookie. Otherwise 0 */
	ASF_uint32_t    ulSeqDelta;

	/* Nature of ulSeqDelta. Positive or Negative */
	ASF_boolean_t   bPositiveDelta;

	ASF_uchar8_t    ucWinScaleFactor;

	/* Reserved field. MUST be zero */
	ASF_uint16_t    usReserved;

	/* Expected incoming sequence number */
	ASF_uint32_t    ulRcvNext;

	/* Size of offered receive window */
	ASF_uint32_t    ulRcvWin;

	/* Max size of offered receive window */
	ASF_uint32_t    ulMaxRcvWin;

} ASFFFPTcpState_t;



typedef struct ASFFFPFlowInfo_s {
	/* Security Zone ID */
	ASF_uint32_t   ulZoneId;


	/* Original tuple. */
	ASFFFPFlowTuple_t       tuple;

	/* Inactivity timeout of the flow in seconds */
	ASF_uint32_t   ulInacTimeout;

	ASF_uint32_t   /*flags  */
	/* TRUE or FALSE Indicates if TCP state processing is enabled for the flow */
	bTcpOutOfSeqCheck : 1 ,

	/* TRUE or FALSE indicates if TCP Time Stamp Check is enabled for the flow */
	bTcpTimeStampCheck:1,

	/* TUE or FALSE; indicate if NAT is enabled on the flow */
	bNAT:1,

	/* TRUE or FALSE:  indicates if IPsec Inbound processing needs to happen on the flow */
	bIPsecIn:1,

	/* TRUE or FALSE; indicates if IPsec Outbound Processing needs to happen on the flow */
	bIPsecOut:1;

	/* Current time stamp value.
		Valid only if Time Stamp check is enabled */

	ASF_uint32_t	    ulTcpTimeStamp;

	/* Current TCP state of this flow. */
	ASFFFPTcpState_t	tcpState;


	/*
		This holds the NAT information for the flow
		Valid only when bNAT is set to TRUE
	*/
	ASFFFPNATInfo_t natInfo;


	/*
		This holds the IPsec Inbound and Outbound processing information for the flow
		They are valid when bIpsecIn and bIpsecOut set to TRUE respectively;
	*/
	ASFFFPIpsecInfo_t ipsecInInfo;

} ASFFFPFlowInfo_t;




typedef struct ASFFFPCreateFlowsInfo_s {
	/*
		Config identification that needs to be associated to the flow.
		Helps in revalidation upon policy change
	*/
	ASFFFPConfigIdentity_t configIdentity;


	/*
		Information private to AS, that AS would like ASF to cache with the flow
		This information is sent back upon any non-response callback notifications with
		respect to the flow
	*/
	ASF_uint8_t *ASFWInfo;

	/* Client to Server Flow */
	ASFFFPFlowInfo_t  flow1;


	/* Server to client flow */
	ASFFFPFlowInfo_t  flow2;

} ASFFFPCreateFlowsInfo_t;



typedef struct ASFFFPDeleteFlowsInfo_s {
	/* tuple of one of the flows */
	ASFFFPFlowTuple_t       tuple;
	ASF_uint32_t	    ulZoneId;

} ASFFFPDeleteFlowsInfo_t;


typedef struct ASFFFPUpdateFlowParams_s {
	/* 5 tuple to identify the flow */
	ASFFFPFlowTuple_t       tuple;
	ASF_uint32_t	    ulZoneId;

	ASF_uint8_t
	bL2blobUpdate : 1,
	bFFPConfigIdentityUpdate:1,
	bIPsecConfigIdentityUpdate:1;
	union {
		/* Valid when bL2blob is set */
		struct {
			/* Common  device Id to identify a specific device */
			ASF_uint32_t ulDeviceId;

			/* L2 blob data */
			ASF_uint8_t l2blob[ASF_MAX_L2BLOB_LEN];

			/* L2 blob len */
			ASF_uint32_t l2blobLen;

			/* Path MTU to be used for packets for the flow. */
			ASF_uint32_t ulPathMTU;

			ASF_uint32_t    ulL2blobMagicNumber;

			ASF_uint16_t bTxVlan:1, bUpdatePPPoELen:1;

			ASF_uint16_t usTxVlanId;

		} l2blob;

		/* Valid when bFFPConfigIdentityChange is set */
		ASFFFPConfigIdentity_t fwConfigIdentity;

		struct {
			ASF_uint32_t
			/* TRUE or FALSE:  indicates if IPsec Inbound Identity  to be updated*/
			bIn : 1,
			/* TRUE or FALSE:  indicates if IPsec Inbound processing needs to happen on the flow */
			bIPsecIn:1,

			/* TRUE or FALSE:  indicates if IPsec outbound Identity  to be updated*/
			bOut:1,
			/* TRUE or FALSE:  indicates if IPsec outbound processing needs to happen on the flow */
			bIPsecOut:1;
			/* Valid when bIPsecConfigIdentity is set */
			ASFFFPIpsecInfo_t ipsecInfo;
		} ipsec;
	} u;
} ASFFFPUpdateFlowParams_t;




ASF_void_t    ASFFFPProcessAndSendPkt(
				     ASF_uint32_t    ulVsgId,
				     ASF_uint32_t    ulCommonInterfaceId,
				     ASFBuffer_t     Buffer,
				     genericFreeFn_t pFreeFn,
				     ASF_void_t      *freeArg,
				     ASF_void_t      *pIpsecOpaque);

ASF_void_t ASFFFPUpdateConfigIdentity(ASF_uint32_t ulVSGId, ASFFFPConfigIdentity_t configIdentity);

ASF_void_t ASFFFPUpdateL2blobConfig(ASF_uint32_t ulVSGId, ASFFFPConfigIdentity_t configIdentity);



/*** Extended ***/

typedef struct ASFFFPQueryFlowStatsInfo_s {
	/* input */
	ASFFFPFlowTuple_t       tuple;
	ASF_uint32_t	    ulZoneId;

	/* output */
	ASFFFPFlowStats_t       stats;	/* Statistics of given flow */
	ASFFFPFlowStats_t       other_stats;	/* Statistics of other flow */

} ASFFFPQueryFlowStatsInfo_t;



int ASFFFPQueryFlowStats(ASF_uint32_t ulVsgId, ASFFFPQueryFlowStatsInfo_t *p);

typedef struct ASFFFPVsgStats_s {
	ASF_uint32_t    ulInPkts;
	ASF_uint32_t    ulInPktFlowMatches;	/* Total number of packets found a matching flow */
	ASF_uint32_t    ulOutPkts;
	ASF_uint32_t    ulOutBytes;
} ASFFFPVsgStats_t;


int ASFFFPQueryVsgStats(ASF_uint32_t ulVsgId, ASFFFPVsgStats_t *pStats);


typedef struct ASFFFPGlobalStats_s {
	ASF_uint32_t    ulInPkts;	/* Total number of packets received */
	ASF_uint32_t    ulInPktFlowMatches;	/* Total number of packets found a matching flow */
	ASF_uint32_t    ulOutPkts;	/* Total number of packets transmitted */
	ASF_uint32_t    ulOutBytes;	/* Total number of bytes transmitted */

	ASF_uint32_t    ulFlowAllocs;
	ASF_uint32_t    ulFlowFrees;
	ASF_uint32_t    ulFlowAllocFailures;
	ASF_uint32_t    ulFlowFreeFailures; /* Invalid flow delete requests */

	ASF_uint32_t    ulErrCsum;	/* checksum verification errors */
	ASF_uint32_t    ulErrIpHdr;		/* IP header validation  errors */
	ASF_uint32_t    ulErrIpProtoHdr;	/* TCP/UDP header errors */
	ASF_uint32_t    ulErrTTL;	/* Packet drops due to TTL */
	ASF_uint32_t    ulErrAllocFailures;
	ASF_uint32_t    ulMiscFailures;
	ASF_uint32_t    ulPktsToFNP;	/* Number of packets sent o FNP. Typically FIN/RST packets */

} ASFFFPGlobalStats_t;


int ASFFFPQueryGlobalStats(ASFFFPGlobalStats_t *pStats);


/*
 * Utility API
 */

/* compute hash index based on maximum number of buckets */
#define ASF_HINDEX(hval, hmax) (hval&(hmax-1))


#endif
