/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	pmal.h
 *
 * Description: PMAL_API Definations
 * *
 * Authors:	Hemant Agrawal <b10814@freescale.com>
 *		Himanshu Seth <b21215@freescale.com>
 */
/******************************************************************************/

#ifndef __PMAL_H__
#define __PMAL_H__

#include <ctype.h>

#define PMAL_DEF_FRAME_SIZE 2048
#define PMAL_DEF_NUM_FRAMES 4096

#define PMAL_DEF_NUM_RING_BD	1024
#define PMAL_DEF_SEND_CALL_WT	32
#define PMAL_RX_POLL_WT		24

#define PMAL_SOCKET_TYPE	0x0001
#define PMAL_RING_SIZE		0x0002
#define PMAL_SOCK_FILTER	0x0004
#define PMAL_DYNAMIC_LEARNING	0x0008

#define PMAL_MAX_CFG_PARAMS	10

#define PMAL_SOCKET_RX		1
#define PMAL_SOCKET_TX		2

#define PMAL_KERNEL_LOOPBACK	1
#define PMAL_STATS		2
#define PMAL_BOARD_TYPE		3


#define PMAL_MAX_PORTS		PACKET_UM_MAX_FILTER_PORTS

#define PMAL_USER_HEAD_RESERVE 64
#define PMAL_USER_TAIL_RESERVE 128

#define PMAL_KERNEL_RESERVE 512
/* Default PMAL Data Buf size is 1536) */
#define PMAL_MAX_DATA_BUF_SIZE (PMAL_DEF_FRAME_SIZE - PMAL_KERNEL_RESERVE)

#define PMAL_GET_FRAME_ID_FROM_DATAFRAME(frame) \
	(*(unsigned int *)(((unsigned int)frame/PMAL_DEF_FRAME_SIZE) \
			* PMAL_DEF_FRAME_SIZE))

#define PMAL_GET_DATAFRAME_FROM_FRAME_ID(frame_id)
/* To Open a Packet Mapped Socket it returns a FD*/
/*
type:
	SOCK_RAW : Provides raw network protocol access.
	SOCK_DGRAM: Supports datagrams (connectionless, unreliable
		messages of a fixed maximum length).
*/
#define PMAL_GET_PCB_FROM_PMAL_BUF(pmal_buff)	\
	(struct pcb_s *)((char *)pmal_buff - sizeof(struct packet_buf_s))

#define PMAL_GET_DATAFRAME_FROM_PMAL_BUF(pmal_buff)   \
	((char *)pmal_buff - sizeof(struct packet_buf_s) + pmal_buff->data)

struct pmal_config_s {
	unsigned int config_bitmap;
	int type;
	int ring_size; /* Number of Buffer in User Space Ring */
	int dynamic_learing_enabled;
		/* The connections or flows shall be
		learned dynamically for the configured filters else,
		the application has to specify the connections manually.*/

	struct packet_filter_s sock_filter;
};


struct pkt_ethhdr {
	unsigned char	h_dest[6];	/* destination eth addr */
	unsigned char	h_source[6];	/* source ether addr    */
	__be16		h_proto;	/* packet type ID field */
};

struct pkt_ipudphdr {
	__u8	version:4,
		ihl:4;
	__u8	tos;
	__be16	tot_len;
	__be16	id;
	__be16	frag_off;
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
	__be32	saddr;
	__be32	daddr;
	__be16	source;
	__be16	dest;
	__be16	len;
	__sum16	udpcheck;
};

struct pmal_sock {
	struct iovec *ring;
	unsigned int head;
	unsigned int buff_list[PACKET_UM_BUFFER_STOCKPILE];
	unsigned int buff_index;
};

int pmal_init(struct pmal_config_s *cfg);

void pmal_deinit(void);

int pmal_socket(int direction, struct pmal_config_s cfg);
int pmal_close(int fd);
int pmal_getsockopt(int fd, int optname, char *optval, socklen_t *optlen);

/*Currently only Debug Option - Loopback Available*/
int pmal_setsockopt(int fd, int optname, char *optval, socklen_t optlen);

/* Poll Frames for receive */
int pmal_poll(struct pollfd *fds, nfds_t nfds, int timeout);

/* Get a frame from Network*/
int pmal_dequeue_frame_rx(int fd, struct pmal_buf **frame);


/* Add a frame for transmission*/
int pmal_enqueue_frame_tx(int fd, struct pmal_buf *frame);

/* System call to send frames after enqueue - max frame that
can be sent per send call is PMAL_DEF_SEND_CALL_WT or as configured*/
int pmal_send(int fd, struct sockaddr *peer_addr);

struct pmal_con_s {
	struct sockaddr_in saddr;
	struct sockaddr_in daddr;
	unsigned int proto;
	unsigned int conn_id;
	unsigned int ctxt;
};


int pmal_add_connection(int fd, struct pmal_con_s *conn);
int pmal_del_connection(int fd, struct pmal_con_s *conn);


/* Free the received buffer */
void pmal_free_buffer(int fd, struct pmal_buf *frame);

/* get a raw data buffer  - All frames are of fixed size (MAX) */
struct pmal_buf *pmal_alloc_buffer(int fd, int size, unsigned int flag);

/*This is used to allocate chain of 'n' buffers/ fragments for
	sending message through pmal_socket. Typically this API will be
	used to allocate the output chain of buffers when PDCP needs to
	cipher a given chain of buffers as `input to SEC block, where
	the total buffer size is greater than the single PMAL buffer size.
*/
struct pmal_buf *pmal_alloc_sg_list(int fd, int size);


/*This is used to add fragment buffer at the end current buffer or sglist. */

void pmal_add_frag(struct pmal_buf *buf, struct pmal_buf *next);


/*This is used to remove fragment buffer from the end of a  SG of buffers.*/

int pmal_remove_frag(struct pmal_buf *head, struct pmal_buf *remove);


/*This is used to walk through the chain of buffers.*/

struct pmal_buf *pmal_frag_next(struct pmal_buf *last,
			struct pmal_buf **next);


/* This is used to convert a chain of buffers into a single buffer.
	This can only work when the total data in the sg list can fit
	into a single pmal buffer. This API involves physical copy of the data.
	It is the responsibility of the calling function to allocate
	the pmal buffer before calling this API.  The API shall not free any
	of the frame buffers from the sg list of frames. It is the
	responsibility of the calling application to free the SG list.*/

void pmal_sg_to_single_frame(struct pmal_buf *sg,
		struct pmal_buf **single);

int pmal_join_frags(struct pmal_buf *first,
		struct pmal_buf *last);

void pmal_set_data_len_frag(struct pmal_buf *frag, unsigned int data_len);

#define PMAL_GET_FRAME_PHYS_ADDR(frame)


#define PMAL_ERROR(fmt, arg...)	\
	printf("\nERROR:fn %s:%d - " fmt, __func__, __LINE__, ##arg)

#ifdef PMAL_DEBUG
#define PMAL_PRINT(fmt, arg...)	\
	printf("\nfn %s:%d - " fmt, __func__, __LINE__, ##arg)

#define PMAL_FN_ENTRY()		printf("\n%s: Enter", __func__)
#define PMAL_FN_EXIT()		printf("\n%s: Exit", __func__)
#else
#define PMAL_PRINT(fmt, arg...)
#define PMAL_FN_ENTRY()
#define PMAL_FN_EXIT()
#endif


static inline void hexdump(const unsigned char *buf, unsigned short len)
{
	char str[80], octet[10];
	int ofs, i, l;

	for (ofs = 0; ofs < len; ofs += 16) {
		sprintf(str, "%03x ", ofs);

		for (i = 0; i < 16; i++) {
			if ((i + ofs) < len)
				sprintf(octet, "%02x ", buf[ofs + i]);
			else
				strcpy(octet, "   ");

			strcat(str, octet);
		}
		strcat(str, "  ");
		l = strlen(str);

		for (i = 0; (i < 16) && ((i + ofs) < len); i++)
			str[l++] = isprint(buf[ofs + i]) ? buf[ofs + i] : '.';

		str[l] = '\0';
		printf("%s\n", str);
	}
}
#endif
