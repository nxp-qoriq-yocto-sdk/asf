/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asftoolkit.h
 *
 * Description: This file includes all defines and declarations used for
 *		ASF Toolkit
 *
 * Authors:	Sachin Saxena <b32168@freescale.com>
 */
/* History
 *  Version	Date		Author		Change Description
*/
/******************************************************************************/

#ifndef INCLUDE_ASF_TOOL_KIT_H__
#define INCLUDE_ASF_TOOL_KIT_H__

#include "asf.h"

/*! Filename used to access HLD device by Linux */
#define HLD_MOUNT_PATH   "/dev/asf_hld"


typedef ASF_uint8_t		BOOLE;	/*!<  used for booleans */

#ifndef FALSE
#define     FALSE	0	 /*!<  Boolean false, non-true, zero */
#define     TRUE      	(!FALSE) /*!<  Boolean true, non-false, non-zero */
#endif


/*!
  Defines for constructs with fixed number of items.
*/
#define LAN_NUM_QUEUES		8	/*!< Number of LAN priority queues. */
#define LAN_NUM_FILER_RULES	256	/*!< Number of eTSEC filer Rules */
/*!
  Device identifier

  Used to indicates a device connected to a Bridge channel
  and for identifying a device for control operations.
*/
typedef enum {
    Dev_NONE,	/*!< No device */
    Dev_LAN0, 	/*!< LAN0 (eTSEC0) device */
    Dev_LAN1, 	/*!< LAN0 (eTSEC0) device */
    Dev_LAN2 	/*!< LAN1 (eTSEC1) device */
} enum_dev_t;
/*!
  Indicates whether an arbitraty field is extracted from a received frame buffer
  and from where it is extracted.
*/
typedef enum {
    AFX_NONE,	/*!< No extraction. */
    AFX_Frame,	/*!< Extracted at offset from frame buffer. */
    AFX_L3hdr,	/*!< Extracted at offset from Layer 3 header. */
    AFX_L4hdr	/*!< Extracted at offset from Layer 4 header. */
} enum_afx_ctrl_t;
/*!
  Defines for arbitray field extraction.
*/
#define MAX_AFX_OFFSET	0x3F
/*!< Maximum offset in bytes for arbitrary field extraction. */
#define AFX_NUM_FIELDS	4
/*!< Number of arbitrary fields for extraction. */
/*!
  Specifies the arbitrary field extraction for a single byte used by the LAN
  and Bridge's parser filer FT_ARB_PROP property.
*/
typedef struct {
    enum_afx_ctrl_t	control;
    /*!< Indicates from where the arbitrary field is extracted. */
    ASF_uint8_t		offset;	/*!< The offset to the arbitraty field.
				Maximum value is MAX_AFX_OFFSET.
				*/
} filer_afx_t;
/*!
  Specifies the depth to which the Bridge's parser/filer will
  parse incoming packets.
*/
typedef enum {
    BPD_LAYER_2  = 1,    /*!< Only Layer 2 protocols are parsed. */
    BPD_LAYER_3  = 2,    /*!< Only Layer 2 and Layer 3 protocols are parsed. */
    BPD_LAYER_4  = 3     /*!< Layer 2, 3 and 4 protocols are parsed. */
} enum_bpd_t;
/*!
  Specifies the depth to which the LAN's parser/filer
  will parse incoming packets.
*/
typedef enum {
    LPD_LAYER_2  = 1,    /*!< Only Layer 2 protocols are parsed. */
    LPD_LAYER_3  = 2,    /*!< Only Layer 2 and Layer 3 protocols are parsed. */
    LPD_LAYER_4  = 3     /*!< Layer 2, 3 and 4 protocols are parsed. */
} enum_lpd_t;
/*!
  Specifies the comparison operation used when comparing the property used in a
  Bridge or LAN filer table rule.
*/
typedef enum {
    FT_ALWAYS_MATCH 	= 0, 	/*!< Always matches. */
    FT_ALWAYS_FAIL	= 3,	/*!< Always fails. */
    FT_EQUAL 		= 0,	/*!< == Equal. */
    FT_GREATER_EQUAL 	= 1,	/*!< >= Greater than or equal. */
    FT_NOT_EQUAL 	= 2,	/*!< != Not equal. */
    FT_LESS 		= 3	/*!< < Less than. */
} enum_ft_cmp_t;
/*!
  Specifies the property id used in a bridge filer table rule.
*/
typedef enum {
    FT_MASK_PROP	= 0,	/*!< Mask bits to be written to
				property mask register. */
    FT_MISC_PROP	= 1,	/*!< Miscellaneous single bit properties.
				Ethernet broadcast address.
				VLAN tag seen.
				Canonical Format Indicator set.
				Jumbo ethernet frame.
				fragmented IPv4 or IPv6 frame.
				IPv4 header.
				IPv6 header.
				IPv4 checksum checked.
				IPv4 checksum correct.
				TCP header.
				UDP header.
				Parse error.
				Ethernet framing error.
				*/
    FT_ARB_PROP		= 2,	/*!< Arbitrary bit field. */
    FT_DAH_PROP		= 3,	/*!< Destination MAC address,
				most significant 24 bits. */
    FT_DAL_PROP		= 4,	/*!< Destination MAC address,
				least significant 24 bits. */
    FT_SAH_PROP		= 5,	/*!< Source MAC address,
				most significant 24 bits. */
    FT_SAL_PROP		= 6,	/*!< Source MAC address,
				least significant 24 bits. */
    FT_ETY_PROP		= 7,	/*!< Ethertype of next layer protocol. */
    FT_VID_PROP		= 8,	/*!< VLAN network identifier. */
    FT_PRI_PROP		= 9,	/*!< VLAN user priority. */
    FT_TOS_PROP		= 10,	/*!< IPv4 header type of service field
				or IPv6 traffic class field. */
    FT_L4P_PROP		= 11,	/*!< Layer 4 protocol identifier. */
    FT_DIA_PROP		= 12,	/*!< Destination IP address, all of IPv4,
				most significant 32 bits of IPv6. */
    FT_SIA_PROP		= 13,	/*!< Source IP address, all of IPv4, most
				significant 32 bits of IPv6. */
    FT_DPT_PROP		= 14,	/*!< Destination port number for
				TCP and UDP headers. */
    FT_SPT_PROP		= 15	/*!< Source port number for
				TCP and UDP headers. */
} enum_ft_pid_t;
/*!  \} end Enum */
/*!

  Defines for masks for manipulating bit fields within the
  prop_val (filer table property) fields of brg_ftr_t and lan_ftr_t.
*/
/* These are used with the PID 0001 (FT_MISC_PROP). */
#define FTP_EBC		0x00008000	/*!< Destination Ethernet address
					is a broadcast address. */
#define FPT_VLN		0x00004000	/*!< VLAN tag (Ethertype 0x8100) was
					seen in the frame. */
#define FTP_CFI		0x00002000	/*!< Value of the Canonical Format
					Indicator if VLN is set. */
#define FTP_JUM		0x00001000	/*!< Jumbo frame was parsed. */
#define FTP_IPF		0x00000800	/*!< Fragmented IPv4 or IPv6 header
					was encountered. */
#define FTP_IP4		0x00000200	/*!< IPv4 header was parsed. */
#define FTP_IP6		0x00000100	/*!< IPv6 header was parsed. */
#define FTP_ICC		0x00000080	/*!< IPv4 header checksum was checked.*/
#define FTP_ICV		0x00000040	/*!< IPv4 header checksum was
					verified correct. */
#define FTP_TCP		0x00000020	/*!< TCP header was parsed. */
#define FTP_UDP		0x00000010	/*!< UDP header was parsed. */
#define FTP_PER		0x00000002	/*!< Parse error, such as header
					inconsistency. */
#define FTP_EER		0x00000001	/*!< Ethernet framing error that
					prevents parsing, such as
					premature end of frame. */
/*!
  LAN filer table rules configuration information.
*/
typedef struct {
    ASF_uint8_t		index;		/*!<
					Rule index.

		Specifies to which entry in the filer table this rule applies.
		Valid values range from 0 to LAN_NUM_FILER_RULES - 1.
					*/
    ASF_uint8_t		queue;		/*!<
					Queue [ RQFCRn.Q ]

		When a match occurs this indicates the priority queue.
		Maximum value is MAX_LAN_FILER_QUEUE.
		Written in the frame control block's QT field.
		The frame is sent to priority queue of (queue mod 8)
		unless the LAN devices is configured for single queue operation.
					*/
    BOOLE		cluster;	/*!< Cluster entry, exit
					indicator. [ RQFCRn.CLE ] */
    BOOLE		reject;		/*!< Reject on match.
					[ RQFCRn.REJ ] */
    BOOLE		and_next;	/*!< And with following rule.
					[ RQFCRn.AND ] */
    enum_ft_cmp_t	cmp;		/*!< Property comparison operation.
					[ RQFCRn.CMP ] */
    enum_ft_pid_t	pid; 		/*!< Identifies the property to be
					examined.	[ RQFCRn.PID ] */
    ASF_uint32_t		prop_val;/*!< The value to be compared with the
					property found in the frame. [ RQFPR ]*/
} lan_ftr_t;
/*!
  Specifies LAN VLAN tag handling.
*/
typedef struct {
    BOOLE	extract;	/*!<
				VLAN extraction enable. [ RCTRL.VLEX ]

  Indicates whether VLAN tags are to be extracted (removed) on frame reception.
  The VLAN extraction setting is set to be enabled by default.
  Changing the setting requires the eTSEC device to perform a graceful stop
  after which the setting is changed, and then performing a graceful start
  of the device. During this time frame traffic is not conveyed by the device.
				*/
    BOOLE	insert;		/*!<
				VLAN insertion enable. [ TCTRL.VLINS ]

  Indicates whether a VLAN tag is to be inserted on transmission of a frame.
  If the frame FCB has a valid VLAN field, the FCB.VLCTL field is used,otherwise
  the VLAN tag is taken from the default vlan value (default_vlctl).
  The VLAN insertion setting is disabled by default.
				*/
    ASF_uint16_t      default_vtpi;   /*!<
  The default VLAN Tag Protocol Inidcator used to tag VLAN frames
  when inserted. [ DFVLAN.TAG]

  On transmissin this value is inserted as the frame's VLAN TAG when VLAN
  insertion is enabled.  On reception this value, as well as 0x8100, is used
  to recognize VLAN tagged frames.  A value of 0 indicates that the 0x8100
  used for IEEE 802.1Q VLAN tagging is to be used.

  Note: values other that 0 or 0x8100 have side effects in the eTSECs RMON
  counters.  */
    ASF_uint16_t	default_vlctl;	/*!<
  The default VLAN control word portion of the inserted VLAN tag. [ DFVLAN ]

  The vlan control value is inserted into the frame's VLCTL field
  when VLAN insertion is enabled. it is comprised of:
  802.1Q frame priority -- the 3 most significant bits (0-2),
  Canonical Frame Indicator -- the 4th most significant bit (3),
  Virtual-LAN identifier -- the 12 least significant bits (4-15).  */
} lan_vlan_t;
/*!
  Specifies LAN pause configuration.
*/
typedef struct {
    BOOLE	tx_pause;	/*!<
				Transmit pause enable. [ MACCFG1.TX_FLOW ]
				*/
    BOOLE	rx_pause;		/*!<
				Receive pause enable. [ MACCFG1.RX_FLOW ]
				*/
    ASF_uint16_t      rx_pause_value;  /*!<
				Pause time value. [ PTV.PT ]
				*/
    ASF_uint8_t	rx_threshold;	/*!<
				Receive pause threshold.
				[ FIFO_RX_PAUSE.PAUSE_START ]
				*/
    ASF_uint8_t	rx_shutoff;	/*!<
				Receive pause shutoff.
				[ FIFO_RX_PAUSE_SHUTOFF.PAUSE_SHUTOFF ]
				*/
} lan_pause_t;
/*!
  LAN (eTSEC) status.

  Refer to the PX0X0 eTSEC manual section for a description of these fields.
*/
typedef struct {
    struct {
	BOOLE	babbling_receive_error;			/*!< [ IEVENT.BABR ] */
	BOOLE	receive_control_interrupt;		/*!< [ IEVENT.RXC ] */
	BOOLE	busy_condition_interrupt;		/*!< [ IEVENT.BSY ] */
	BOOLE	internal_bus_error;			/*!< [ IEVENT.EBERR ] */
	BOOLE	mib_counter_overflow;			/*!< [ IEVENT.MSRO ] */
	BOOLE	graceful_transmission_stop_complete;	/*!< [ IEVENT.GTSC ] */
	BOOLE	babbling_transmit_error;		/*!< [ IEVENT.BABT ] */
	BOOLE	transmit_control_interrupt;		/*!< [ IEVENT.TXC ] */
	BOOLE	transmit_error;				/*!< [ IEVENT.TXE ] */
	BOOLE	transmit_buffer;			/*!< [ IEVENT.TXB ] */
	BOOLE	transmit_frame_interrupt;		/*!< [ IEVENT.TXF ] */
	BOOLE	late_collision;				/*!< [ IEVENT.LC ] */
	BOOLE	collision_retry_limit;			/*!< [ IEVENT.CRL ] */
	BOOLE	transmit_fifo_underrun;			/*!< [ IEVENT.XFUN ] */
	BOOLE	receive_buffer;				/*!< [ IEVENT.RXB ] */
	BOOLE	magic_packet_detected;			/*!< [ IEVENT.MAG ] */
	BOOLE	mii_management_read_completion;		/*!< [ IEVENT.MMRD ] */
	BOOLE	mii_management_write_completion;	/*!< [ IEVENT.MMWR ] */
	BOOLE	graceful_receive_stop_complete;		/*!< [ IEVENT.GRSC ] */
	BOOLE	receive_frame_interrupt;		/*!< [ IEVENT.RXF ] */
	BOOLE	receive_queue_filer_result_invalid;	/*!< [ IEVENT.FIR ] */
	BOOLE	filed_frame_to_invalid_receive_queue;	/*!< [ IEVENT.FIQ ] */
	BOOLE	internal_data_parity_error;		/*!< [ IEVENT.DPE ] */
	BOOLE	receive_frame_parse_error;		/*!< [ IEVENT.PERR ] */
    } interrupt_event;
    struct {
	BOOLE	halt_ring;		/*!< [ TSTAT.THLT0-7 ] */
	BOOLE	frame_event;		/*!< [ TSTAT.TXF0-7 ] */
	BOOLE	ring_configured;	/*<! Indicates whether a ring is
					configured for this queue. */
	BOOLE	ring_enabled;		/*<! Indicates whether use of th
					ring by the device is disabled. */
	BOOLE	ring_quiescent;		/*!< A TRUE value indicates that th
					transmit (Bridge egress) ring is in a
					quiescent state, i.e., all the buffer
					descriptors in the ring are empty. */
    } transmit[LAN_NUM_QUEUES];
    struct {
	BOOLE	halt_queue;		/*!< [ RSTAT.QHLT0-7 ] */
	BOOLE	frame_event;		/*!< [ RSTAT.RXF0-7 ] */
	BOOLE	ring_configured;	/*<! Indicates whether a ring is
					configured for this queue. */
	BOOLE	ring_enabled;		/*<! Indicates whether use of the rin
					by the device is disabled. */
	BOOLE	ring_quiescent;		/*!< A TRUE value indicates that th
					receive (Bridge ingress) ring is in a
					quiescent state, i.e., all the buffer
					descriptors in the ring are empty. */
    } receive[LAN_NUM_QUEUES];
} lan_status_t;
/*!
  Provides a named index into the LAN/eTSEC counter array.
*/
typedef enum {
    Lctr_Tr64,	/*!< TX and Rx 64-byte frame counter [ TR64 ] */
    Lctr_Tr127,	/*!< TX and Rx 65 to 127-byte frame counter [ TR127 ] */
    Lctr_Tr255,	/*!< TX and Rx 128 to 255-byte frame counter [ TR255 ] */
    Lctr_Tr511,	/*!< TX and Rx 256 to 511-byte frame counter [ TR511 ] */
    Lctr_Tr1k,	/*!< TX and Rx 512 to 1023-byte frame counter [ TR1K ] */
    Lctr_Trmax,	/*!< TX and Rx 1024 to 1518-byte frame counter [ TRMAX ] */
    Lctr_Trmgv,	/*!< TX and Rx 1519 to 1522-byte VLAN frame count [ TRMGV ] */
    /* eTSEC Receive Counters */
    Lctr_Rbyt,	/*!< Receive byte counter [ RBYT ] */
    Lctr_Rpkt,	/*!< Receive packet counter [ RPKT ] */
    Lctr_Rfcs,	/*!< Receive FCS error counter [ RFCS ] */
    Lctr_Rmca,	/*!< Receive multicast packet counter [ RMCA ] */
    Lctr_Rbca,	/*!< Receive broadcast packet counter [ RBCA ] */
    Lctr_Rxcf,	/*!< Receive control frame packet counter [ RXCF ] */
    Lctr_Rxpf,	/*!< Receive PAUSE frame packet counter [ RXPF ] */
    Lctr_Rxuo,	/*!< Receive unknown OP code counter [ RXUO ] */
    Lctr_Raln,	/*!< Receive alignment error counter [ RALN ] */
    Lctr_Rflr,	/*!< Receive frame length error counter [ RFLR ] */
    Lctr_Rcde,	/*!< Receive code error counter [ RCDE ] */
    Lctr_Rcse,	/*!< Receive carrier sense error counter [ RCSE ] */
    Lctr_Rund,	/*!< Receive undersize packet counter [ RUND ] */
    Lctr_Rovr,	/*!< Receive oversize packet counter [ ROVR ] */
    Lctr_Rfrg,	/*!< Receive fragments counter [ RFRG ] */
    Lctr_Rjbr,	/*!< Receive jabber counter [ RJBR ] */
    Lctr_Rdrp,	/*!< Receive drop counter [ RDRP ] */
    Lctr_Rrej,	/*!< Receive filer reject counter [ RREJ ] */
    /* eTSEC Transmit Counters */
    Lctr_Tbyt,	/*!< Transmit byte counter [ TBYT ] */
    Lctr_Tpkt,	/*!< Transmit packet counter [ TPKT ] */
    Lctr_Tmca,	/*!< Transmit multicast packet counter [ TMCA ] */
    Lctr_Tbca,	/*!< Transmit broadcast packet counter [ TBCA ] */
    Lctr_Txpf,	/*!< Transmit PAUSE control frame counter [ TXPF ] */
    Lctr_Tdfr,	/*!< Transmit deferral packet counter [ TDFR ] */
    Lctr_Tedf,	/*!< Transmit excessive deferral packet counter [ TEDF ] */
    Lctr_Tscl,	/*!< Transmit single collision packet counter [ TSCL ] */
    Lctr_Tmcl,	/*!< Transmit multiple collision packet counter [ TMCL ] */
    Lctr_Tlcl,	/*!< Transmit late collision packet counter [ TLCL ] */
    Lctr_Txcl,	/*!< Transmit excessive collision packet counter [ TXCL ] */
    Lctr_Tncl,	/*!< Transmit total collision counter [ TNCL ] */
    Lctr_Tdrp,	/*!< Transmit drop frame counter [ TDRP ] */
    Lctr_Tjbr,	/*!< Transmit jabber frame counter [ TJBR ] */
    Lctr_Tfcs,	/*!< Transmit FCS error counter [ TFCS ] */
    Lctr_Txcf,	/*!< Transmit control frame counter [ TXCF ] */
    Lctr_Tovr,	/*!< Transmit oversize frame counter [ TOVR ] */
    Lctr_Tund,	/*!< Transmit undersize frame counter [ TUND ] */
    Lctr_Tfrg,	/*!< Transmit fragments frame counter [ TFRG ] */
    Lctr_Count	/*!< The size of counter array. */
} enum_lan_counter_t;
/*!
  LAN counters.
*/
typedef struct {
    BOOLE	reset;	/*!< Reset counters. */
    ASF_uint64_t	counter[Lctr_Count]; /*!< eTSEC counter values. This
				array is indexed by the values of
				enum_lan_counter_t and strings containing
				the register name and a long
				description of the counter are found in
				lan_counter_name. */
} lan_counter_t;

/*!
  LAN counter register names and descriptions.
*/
const static struct {
    char	desc[64];	/*!< LAN/eTSEC counter description. */
    char	reg[16];	/*!< LAN/eTSEC register name. */
} lan_counter_name[Lctr_Count] = {
    /* These MUST be in the same order as in enum_lan_counter_t */
    { "Tx and Rx 64-byte frame", "TR64" },
    { "Tx and Rx 65 to 127-byte frame", "TR127" },
    { "Tx and Rx 128 to 255-byte frame", "TR255" },
    { "Tx and Rx 256 to 511-byte frame", "TR511" },
    { "Tx and Rx 512 to 1023-byte frame", "TR1K" },
    { "Tx and Rx 1024 to 1518-byte frame", "TRMAX" },
    { "Tx and Rx 1519 to 1522-byte good VLAN frame count", "TRMGV" },
    /* eTSEC Rx Counters */
    { "Rx byte", "RBYT" },
    { "Rx packet", "RPKT" },
    { "Rx FCS error", "RFCS" },
    { "Rx multicast packet", "RMCA" },
    { "Rx broadcast packet", "RBCA" },
    { "Rx control frame packet", "RXCF" },
    { "Rx PAUSE frame packet", "RXPF" },
    { "Rx unknown OP code", "RXUO" },
    { "Rx alignment error", "RALN" },
    { "Rx frame length error", "RFLR" },
    { "Rx code error", "RCDE" },
    { "Rx carrier sense error", "RCSE" },
    { "Rx undersize packet", "RUND" },
    { "Rx oversize packet", "ROVR" },
    { "Rx fragments", "RFRG" },
    { "Rx jabber", "RJBR" },
    { "Rx drop", "RDRP" },
    { "Rx filer reject", "RREJ" },
    /* eTSEC Tx Counters */
    { "Tx byte", "TBYT" },
    { "Tx packet", "TPKT" },
    { "Tx multicast packet", "TMCA" },
    { "Tx broadcast packet", "TBCA" },
    { "Tx PAUSE control frame", "TXPF" },
    { "Tx deferral packet", "TDFR" },
    { "Tx excessive deferral packet", "TEDF" },
    { "Tx single collision packet", "TSCL" },
    { "Tx multiple collision packet", "TMCL" },
    { "Tx late collision packet", "TLCL" },
    { "Tx excessive collision packet", "TXCL" },
    { "Tx total collision", "TNCL" },
    { "Tx drop frame", "TDRP" },
    { "Tx jabber frame", "TJBR" },
    { "Tx FCS error", "TFCS" },
    { "Tx control frame", "TXCF" },
    { "Tx oversize frame", "TOVR" },
    { "Tx undersize frame", "TUND" },
    { "Tx fragments frame", "TFRG" }
};

/* Function Prototypes */
/* Access */
extern int asf_open(void);

extern int asf_close(void);

extern int asf_write_lan_pause(
    ASF_uint8_t	lan,
    lan_pause_t	*pause
    );
extern int asf_write_lan_vlan(
    ASF_uint8_t	lan,
    lan_vlan_t	*vlan
    );
extern int asf_write_lan_filer(
    ASF_uint8_t	lan,
    ASF_uint32_t	num_rules,
    lan_ftr_t	*filer_rule,
    ASF_uint32_t	*error_index
    );
extern int asf_write_lan_parse_depth(
    ASF_uint8_t       lan,
    enum_lpd_t  parse_depth
    );
extern int asf_write_lan_padcrc(
    ASF_uint8_t       lan,
    BOOLE       padcrc,
    BOOLE       crc
    );
extern int asf_read_lan_filer(ASF_uint8_t lan);

extern int asf_write_lan_afx(
    ASF_uint8_t	lan,
    ASF_uint8_t	field,
    filer_afx_t	*lan_afx
    );
extern int asf_control_enable(void);
extern int asf_control_disable(
    ASF_uint8_t	quiesce_timeout,
    BOOLE	force
    );

extern int asf_read_counters(
    lan_counter_t	*lan0,
    lan_counter_t	*lan1
    );

/* Debug */
extern int asf_lan_status(
    ASF_uint8_t		lan,
    lan_status_t	*lan_status
    );
extern void asf_verbose(
    ASF_uint32_t	verbose
    );

extern char *asf_error_name(
    int error,
    char **description
    );

/* Used by Application */
extern int		optind;
extern char		*optarg;
extern int		opterr;

/*!	ioctl commands to be used by ASF API
	to call the Linux HLD driver
 */
typedef enum {
  HLD_ERROR_STR		= 0, /*!< return the error string from inside the HLD */
  HLD_CONFIG_LAN_PAUSE,
  HLD_CONFIG_LAN_VLAN,
  HLD_CONFIG_LAN_FILER,
  HLD_CONFIG_LAN_AFX,
  HLD_CONFIG_LAN_PARSE_DEPTH,
  HLD_CONFIG_LAN_PADCRC,
  HLD_CONTROL_ENABLE,
  HLD_CONTROL_DISABLE,
  HLD_TEST_0,
  HLD_TEST_1,
  HLD_TEST_2,
  HLD_TEST_3,
  HLD_TEST_4,
  HLD_TEST_5,
  HLD_TEST_6,
  HLD_TEST_7,
  HLD_TEST_8,
  HLD_TEST_9,
  HLD_PRINT_FILER,
  HLD_IOCTL_CMD_CNT
} enum_ioctl_cmd_t;


typedef enum {
    HLD_Dev_Processor 	= 0,
    HLD_Dev_eTSEC0 	= 1,
    HLD_Dev_eTSEC1 	= 2,
    HLD_Dev_Cnt		= 4
} enum_hld_device_t;


typedef struct {
    ASF_uint8_t		lan;
    lan_vlan_t		*vlan;
} ioctl_config_lan_vlan_t;

typedef struct {
    ASF_uint8_t		lan;
    lan_pause_t		*pause;
} ioctl_config_lan_pause_t;

typedef struct {
    ASF_uint8_t		lan;
    ASF_uint32_t		num_rules;
    lan_ftr_t		*filer_rule;
} ioctl_config_lan_filer_t;

typedef struct {
    ASF_uint8_t		lan;
    ASF_uint8_t		field;
    filer_afx_t		*lan_afx;
} ioctl_config_lan_afx_t;

typedef struct {
    ASF_uint8_t		lan;
    enum_lpd_t          parse_depth;
} ioctl_config_lan_parse_depth_t;

typedef struct {
    ASF_uint8_t		lan;
    BOOLE               padcrc;
    BOOLE               crc;
} ioctl_config_lan_padcrc_t;


typedef struct {
    ASF_uint8_t		quiesce_timeout;
    BOOLE		force;
    BOOLE		clean;
} ioctl_control_disable_t;

typedef struct {
    ASF_uint8_t		lan;
    lan_status_t	*status;
} ioctl_status_lan_t;

/* External functions */
#endif /* ifndef INCLUDE_ASF_TOOL_KIT_H__ */
