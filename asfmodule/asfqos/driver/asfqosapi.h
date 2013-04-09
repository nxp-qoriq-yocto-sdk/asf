/**************************************************************************
 * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfqosapi.h
 *
 * Description: Header file for ASF QOS API Definations.
 *
 * Authors:	Sachin Saxena <sachin.saxena@freescale.com>
 *
 */
/*
 * History
 *  Version	Date         	Author		Change Description *
 *  1.0		20 JUL 2012   Sachin Saxena	Initial Version.
 *  1.1		20 FEB 2013   Sachin Saxena	Adding support for
 *						DPAA HW based QoS.
 *
 */
/****************************************************************************/
/*!
    \file asfqosapi.h
    \brief
	This file describes the ASF QOS API.
*/
#ifndef __ASFQOSAPI_H
#define __ASFQOSAPI_H

#include <linux/netfilter.h>

/****** Quality Of Service Module API (QOS API) **********/
/*!	\brief	Defining ASF Max priority */
#define	ASF_PRIO_MAX	8     /*  0-7 Priority bands */
/*!	\brief	Definition for Root Id*/
#define ROOT_ID		0xFFFFFFFF
/*!	\brief	Definition for Major Id*/
#define MAJOR_ID	0xFFFF0000
/*!	\brief	Definition for Minor Id*/
#define MINOR_ID	0x0000FFFF

/*!
  ASF Marker DataBase rules configuration information.
*/
typedef enum {
	PROTO_UDP = 17,
	PROTO_TCP = 6,
	PROTO_IPV4 = 4,
	PROTO_IPV6 = 41,
	PROTO_SCTP = 132,
	PROTO_INVALID = 0
} enum_proto_t;

/*!	\brief	Enum defining QoS Queue discipline type. */
typedef enum {
	/*!	\brief	Queue discipline is based on priority.*/
	ASF_QDISC_PRIO = 0,
	/*!	\brief	Queue discipline is combination of priority
	and deficit round robin.*/
	ASF_QDISC_PRIO_DRR,
	/*!	\brief	Queue discipline is token buffer filter.*/
	ASF_QDISC_TBF,
#ifdef CONFIG_DPA
	/*!	\brief	Queue discipline is Deficit Round robin.*/
	ASF_QDISC_DRR,
	/*!	\brief	Queue discipline is Weighted Round robin.*/
	ASF_QDISC_WRR,
#endif
	/*!	\brief	Maximum number of Queue disciplines for QoS.*/
	ASF_QDISC_NUM
} ASFQOSQdiscType_t;

/*!	\brief	This data structure holds the information for creating
	Scheduler Queue discipline. */
typedef struct ASFQOSCreateQdisc_s {
	/*!	\brief	It represents the type of Queue Disicpline which
	we wish to created.\n
	More info can be found ::ASFQOSQdiscType_t
	*/
	ASFQOSQdiscType_t	qdisc_type;
	/*!	\brief	It represents the network device on which QDISC
	need to be created.*/
	struct net_device	*dev;
	/*!	\brief	It is own Identification number of QDISC.
		Handle will be in format of MAJOR & MINOR,
		where,\n
		\li MAJOR_ID represent 0xFFFF0000  AND
		\li MINOR_ID represent 0x0000FFFF
	*/
	ASF_uint32_t		handle; /* Qdisc Own ID: */
	/*!	\brief	It is Identification number of PARENT QDISC.
		parent will be in format of MAJOR & MINOR,
		where,\n
		\li	MAJOR_ID represent 0xFFFF0000  AND
		\li	MINOR_ID represent 0x0000FFFF
		\n In case of Priority Scheduler Queue Discipline creation,
		which is a ROOT QDISC on a device, parent ID must be
		0xFFFFFFFF.\n
		In case of Shaper Queue Discipline creation, parent ID
		is equal to handle value of required PRIORITY QUEUE,
		on which shaper is attached.
	*/
	ASF_uint32_t		parent; /* Parent ID */
	/*!	\brief	Union */
	union {
		/*!	\brief	Structure defining fields for priority QDisc*/
		struct {
			/*!	\brief Number of Priority Queues.This parameter
			is required to be set exactly as "8" when creating
			Priority Schduler. Value less or greater than 8 is
			not support for NON-DPAA. For DPAA this parameter is
			required to set "4"*/
			ASF_uint32_t	bands;
		} prio;
#ifdef CONFIG_DPA

#define DPA_MAX_PRIO_QUEUES	4
#define DPA_MAX_DRR_QUEUES	8
#define DPA_MAX_WRR_QUEUES	3
		/*!	\brief	Structure defining fields for
			deficit round robin QDisc*/
		struct {
			/*!	\brief It represents the value of Wieght given
			to a given Queue when DRR Scheduling is
			configured.\n
			We need to provide quantum/weight in Number of BYTES
			for each queue. */
			ASF_uint32_t	quantum;
		} drr;
		/*!	\brief	Structure defining fields for
			Weighted round robin QDisc*/
		struct {
			/*!	\brief It represents the value of Wieght given
			to a given Queue when WRR Scheduling is
			configured.\n
			We need to provide weight in Number 0-8
			for each queue of the 3 Queues. */
			ASF_uint32_t	weight[DPA_MAX_WRR_QUEUES];
		} wrr;
#else
		/*!	\brief	Structure defining fields for priority
			and deficit round robin QDisc*/
		struct {
			/* Number of Priority Queues */
			ASF_uint32_t	bands;
			/*!	\brief It represents the value of Wieght given
			to a given Queue when PRIO-DRR Scheduling is
			configured.\n
			We need to provide quantum/weight in Number of BYTES
			for each queue. If Quantum is given as '0', the given
			queue will behave as PRIORITY Queue.*/
			ASF_uint32_t	quantum[ASF_PRIO_MAX];
		} prio_drr;
#endif
		/*!	\brief	Structure defining fields for token
		buffer filter QDisc*/
		struct {
			/*!	\brief	It represents value of bandwidth limit.
				Unused for Scheduler. */
			ASF_uint16_t	maxBurst;
			ASF_uint32_t	rate; /* in Byte/sec */
		} tbf;
	} u;

} ASFQOSCreateQdisc_t;

/*!	\brief	This data structure holds the information for
	Deleting shaper Queue discipline.*/
typedef struct ASFQOSDeleteQdisc_s {
	/*!	\brief	It represents the type of Queue Disicpline which
	we wish to delete.\n
	More info can be found ::ASFQOSQdiscType_t
	*/
	ASFQOSQdiscType_t	qdisc_type;
	/*!	\brief	It represents the network device on which QDISC
	need to be deleted.*/
	struct net_device	*dev;
	/*!	\brief	It is own Identification number of QDISC.
		Handle will be in format of MAJOR & MINOR,
		where,\n
		\li MAJOR_ID represent 0xFFFF0000  AND
		\li MINOR_ID represent 0x0000FFFF
	*/
	ASF_uint32_t		handle;
	/*!	\brief	It is Identification number of PARENT QDISC.
		parent will be in format of MAJOR & MINOR,
		where,\n
		\li	MAJOR_ID represent 0xFFFF0000  AND
		\li	MINOR_ID represent 0x0000FFFF
	\n In case of Shaper Queue Discipline, parent ID is equal
	to handle value of required PRIORITY QUEUE, on which
	shaper is attached.
	*/
	ASF_uint32_t		parent;

} ASFQOSDeleteQdisc_t;
/*!	\brief	Enum defining Codes for ASF Codes */
typedef enum {
	/*!	\brief	ASF QOS Success Code*/
	ASFQOS_SUCCESS = 0,	/* Success */
	/*!	\brief	ASF QOS Failure Code */
	ASFQOS_FAILURE,		/* Failure */
	/*!	\brief	ASF QOS Time Out */
	ASFQOS_TIMEOUT,		/* Time out */
} ASFQOSRespCode_t;

/*
 * Helper Callback Functions Registrationa API
 */
/*!	\addtogroup Functions
	\{
*/
/*!	\addtogroup	Callbacks
	\{
*/
/*!	\brief	This callback function is invoked by ASF when
	mapped interface in the received packet is not found.*/
/*!	This callback function is invoked by ASF when
	mapped interface in the received packet is not found.
	\param	cmd
	It is of type ::ASFQOSCreateQdisc_s
	\param	pFreeFn
	ASF needs to invoke the free function with the freeArg when
	it has no longer any use for the buffer.
	\param	freeArg
	Arguement that is passed with pFreeFn when ASF has no longer any
	use for the buffer.
	\return	It returns nothing.
*/
typedef ASF_void_t   (*pASFQOSCbFnInterfaceInfoNotFound_f)(
				ASFQOSCreateQdisc_t cmd,
				genericFreeFn_t pFreeFn,
				ASF_void_t    *freeArg
);
/*!	\brief	This callback function is invoked by ASF when
	QOS queue discipline is not found.*/
/*!	This callback function is invoked by ASF when
	QOS queue discipline is not found.
	\param	cmd
	It is of type ::ASFQOSCreateQdisc_s
	\param	pFreeFn
	ASF needs to invoke the free function with the freeArg when
	it has no longer any use for the buffer.
	\param	freeArg
	Arguement that is passed with pFreeFn when ASF has no longer any
	use for the buffer.
	\return	It returns nothing.
*/
typedef ASF_void_t (*pASFQOSCbFnQdiscNotFound_f)(
				ASFQOSCreateQdisc_t cmd,
				genericFreeFn_t pFreeFn,
				ASF_void_t *freeArg
				);

/*!	\brief	This callback function is invoked by ASF when
	making any configuration changes.*/
/*!	This callback function is invoked by ASF when
	making any configuration changes.
	\param	cmd
	It is of type ::ASFQOSConfigCommands.
	\param	pResp
	Pointer to Response when any command is executed.
	\param	ulRespLen
	Length of Response in bytes.
	\return	It returns nothing.
*/
typedef ASF_void_t (*pASFQOSCbFnRuntime_f)(
				ASF_uint32_t cmd,
				ASF_void_t *pResp,
				ASF_uint32_t ulRespLen);
/*!	\}	end Callbacks */
/*!	\}	end Functions */

/*!	\brief	Structure defining ASF Qos Callback functions */
typedef struct ASFQOSCallbackFns_s {
	/*!	\brief	This callback function is invoked by ASF when
	mapped interface in the received packet is not found.*/
	pASFQOSCbFnInterfaceInfoNotFound_f      pFnInterfaceNotFound;
	/*!	\brief	This callback function is invoked by ASF when
	QOS queue discipline is not found.*/
	pASFQOSCbFnQdiscNotFound_f		pFnQdiscNotFound;
	/*!	\brief	This callback function is invoked by ASF when
	making any configuration changes.*/
	pASFQOSCbFnRuntime_f			pFnRuntime;
} ASFQOSCallbackFns_t;

/*!	\brief	This enum uniquely identifies the command that
	needs to be processed by ASF.*/
enum ASFQOSConfigCommands {
	/*!	\brief Command for creating QDISC on a device in ASF. */
	ASF_QOS_CREATE_QDISC = 1,
	/*!	\brief Command for Adding QDISC on a existing Qdisc in ASF. */
	ASF_QOS_ADD_QDISC,
	/*!	\brief Command for deleting QDISC of a device in ASF.*/
	ASF_QOS_DELETE_QDISC,
	/*!	\brief Command for flushing all QDISCs of a device in ASF . */
	ASF_QOS_FLUSH
};
/*!	\addtogroup Functions
	\{
*/
/*!	\addtogroup	API
	\{
*/
/*!	\brief	AS uses this API to create, delete or flush Scheduler,
	Shaper Queue disciplines in ASF QoS.*/
/*!	AS uses this API to create, delete or flush Scheduler,
	Shaper Queue disciplines in ASF QoS.
	\param ulVsgId
	This parameter holds the VSG Id corresponding to the flow.
	\param	cmd
	This variable uniquely identifies the command that needs
	to be processed by ASF.\n
	Possible values can be from enum ::ASFQOSConfigCommands.
	\param	*args
	AS (Normal Path) sends the command specific parameters
	in args.
	\return	SUCCESS or FAILURE
	\n \li SUCCESS = 0
	\li FAILURE = -1
	*/
ASF_uint32_t ASFQOSRuntime(ASF_uint32_t  ulVsgId,
				ASF_uint32_t  cmd,
				ASF_void_t    *args);


/*!	\brief	AS registers two callback functions that need
	to be called when marking information is required by
	ASF for a packet.*/
/*!	AS registers two callback functions that need
	to be called when marking information is required by
	ASF for a packet.
	\param	pFnList
	Pointer to Callback function list.
	\return It returns nothing.
*/
ASF_void_t ASFQOSRegisterCallbackFns(ASFQOSCallbackFns_t *pFnList);
/*!	\} end API */
/*!	\} end Functions */
/*!	\brief	This data structure contains the information
	required in stats.*/
struct ASFQOSQueueStats_s {
	/*!	\brief	Total number or packets received */
	uint32_t    ulEnqueuePkts;	/* Total number of packets received */
	/*!	\brief	Total number of packets dropped */
	uint32_t    ulDroppedPkts;	/* Total number of packets dropped
						due to Buffer overflow */
	/*!	\brief	Total number of Dequeued packets */
	uint32_t    ulDequeuePkts;	/* Total number of Dequeued packets */
	/*!	\brief	Total number of packets dropped */
	uint32_t    ulTxErrorPkts;	/* Total number of packets dropped */
};
/*!	\brief	This data strucutre contains ASF QOS query stats Parameter*/
typedef struct ASFQOSQueryStatsInfo_s {
	/*!	\brief	Pointer to device for which QoS statistics required.*/
	struct net_device	*dev;	/* Input Arg */
	/*!	\brief	This gives whether to reset stats or not .
	If value is not '0', this will indicate to reset all
	QoS stats.*/
	ASF_uint8_t		b_reset; /* Input Arg to Reset Stats */
	/*!	\brief	Structure giving the Stats. */
	struct ASFQOSQueueStats_s stats[ASF_PRIO_MAX]; /* Out result */
} ASFQOSQueryStatsInfo_t;
/*!	\addtogroup	Functions
	\{
*/
/*!	\addtogroup	API
	\{
*/
/*!	\brief	AS uses this API to get  per Queue Statistics
	from ASF QoS.*/
/*!	AS uses this API to get  per Queue Statistics
	from ASF QoS.
	\param ulVsgId
	This parameter holds the VSG Id corresponding to the flow.
	\param p
	Pointer to structure ::ASFQOSQueryStatsInfo_t
	\return	SUCCESS or FAILURE
	\n \li SUCCESS = 0
	\li FAILURE = -1
*/
ASF_int32_t ASFQOSQueryQueueStats(ASF_uint32_t ulVsgId,
				ASFQOSQueryStatsInfo_t *p);
/*!	\} end API */
/*!	\} end Functions */
/*!	\brief	This data structure defines parameters for
	ASF QOS configuraation */
typedef struct ASFQOSQueryConfig_s {
	/*!	\brief	Pointer to device for which QoS
	statistics required.*/
	struct net_device	*dev; /* Input Arg */
	/* Out: Configuration details */
	/*!	\brief	Type of Scheduler: Strict Priority
	or PRIO-DRR */
	ASFQOSQdiscType_t	sch_type;
	/*!	\brief	ID of scheduler */
	ASF_uint32_t		handle; /* Qdisc Own ID: */
	/*!	\brief	Weight of each queue in BYTES,
	IF Scheduler is PRIO-DRR, DRR or WRR */
	ASF_uint32_t		quantum[ASF_PRIO_MAX];
	/*!	\brief	Flag to indicate that Port shaper
	is configured. Applicable only if scheduler
	type is PRIO-DRR.*/
	ASF_boolean_t		b_port_shaper;
	/*!	\brief	Port shaper rate. Applicable only if
	scheduler type is PRIO-DRR.*/
	ASF_uint32_t		pShaper_rate;
#ifndef CONFIG_DPA
	/*!	\brief	Number of bands/queues configured
	for the scheduling. */
	ASF_uint32_t		bands;
	/*!	\brief	Maximum number of packets that may wait
	inside the each queue.*/
	ASF_uint32_t		queue_max_size;
	/*!	\brief	Per Queue Flag to indicate that Queue
	shaper is configured.Applicable only if scheduler
	type is PRIO.*/
	ASF_boolean_t		b_queue_shaper[ASF_PRIO_MAX];
	/*!	\brief	Queue shaper rate. Applicable only if
	scheduler type is PRIO.*/
	ASF_uint32_t		qShaper_rate[ASF_PRIO_MAX];
#endif
} ASFQOSQueryConfig_t;
/*!	\addtogroup	Functions
	\{
*/
/*!	\addtogroup	API
	\{
*/
/*!	\brief	AS uses this API to get current ASF QoS
	configuration details.*/
/*!	AS uses this API to get current ASF QoS
	configuration details.
	\param	ulVsgId
	This parameter holds the VSG Id corresponding to
	the flow.
	\param	p
	Pointer to struct ::ASFQOSQueryConfig_t
	\return	SUCCESS or FAILURE
	\n \li SUCCESS = 0
	\li FAILURE = -1
*/
ASF_int32_t ASFQOSQueryConfig(ASF_uint32_t ulVsgId,
				ASFQOSQueryConfig_t *p);
/*!	\} end API */
/*!	\} end Functions */
/*** Extended ***/
#endif
