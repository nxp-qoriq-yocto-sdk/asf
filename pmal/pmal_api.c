/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	pmal_api.c
 *
 * Description: Contains the PMAL Library APIs
 * *
 * Authors:	Himanshu Seth <b21215@freescale.com>
 */
/* History
 *  Version	Date		Author		Change Description
 *	0.1	20 Feb 2011	Himanshu Seth	Initial Version
*/
/******************************************************************************/
#ifndef __linux__
#error "Are you loco? This is Linux only!"
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#define __USE_XOPEN
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <features.h>
#include <linux/if_ether.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include "pmal.h"

#define PMAL_PKTMMAP_BLOCK_SIZE	(4096 * 64);

struct pmal_config_s g_pmal_conf;
struct iovec *data_tx;
struct iovec *data_rx;

unsigned int g_pmal_filter_init;
unsigned int data_tx_offset;
struct pmal_sock *ps_list[100];

/* Initial Configurations
 * This function shall be called once or more during application initialization
 * This function shall be called before calling pmal_socket
 * Any later configuration change will not be active.
 */
int pmal_init(struct pmal_config_s *cfg)
{
	unsigned int i = 0;
	unsigned int k = 0;
	for (i = 0; i < PMAL_MAX_CFG_PARAMS; i++) {
		k = (1 << i);
		if (k & cfg->config_bitmap) {
			switch (k) {

			case PMAL_SOCKET_TYPE:
				g_pmal_conf.type = cfg->type;
				break;

			case PMAL_RING_SIZE:
				g_pmal_conf.ring_size = cfg->ring_size;
				break;

			case PMAL_DYNAMIC_LEARNING:
				g_pmal_conf.dynamic_learing_enabled =
					cfg->dynamic_learing_enabled;
				break;

			}
		}
	}

	data_rx = malloc(PMAL_DEF_NUM_FRAMES* sizeof(struct iovec));
	if (data_rx == NULL) {
		PMAL_ERROR("malloc for data_rx failed");
		goto out_2;
	}

	data_tx = malloc(PMAL_DEF_NUM_FRAMES * sizeof(struct iovec));
	if (data_tx == NULL) {
		PMAL_ERROR("malloc for data_tx failed");
		goto out_3;
	}

	return 0;
out_3:
	free(data_rx);
out_2:
	return -1;
}

void pmal_deinit(void)
{
	char *map_tx = data_tx[0].iov_base;
	char *map_rx = data_rx[0].iov_base;

	if (map_rx)
		munmap(map_rx, PMAL_DEF_FRAME_SIZE* PMAL_DEF_NUM_FRAMES);

	if (map_tx)
		munmap(map_tx, PMAL_DEF_FRAME_SIZE* PMAL_DEF_NUM_FRAMES);


	if (data_rx) {
		free(data_rx);
	}

	if (data_tx) {
		free(data_tx);
	}
}

/* Returns socket id*/
int pmal_socket(int direction, struct pmal_config_s cfg)
{
	int fd = 0;
	int ret_val = 0;
	struct tpacket_req req;
	unsigned int size = 0;
	unsigned int tpkt_blk_num;
	char *map = NULL;
	struct iovec *data_dir = NULL;
	struct iovec *ring_dir = NULL;
	int optname = 0;
	struct pmal_sock *ps = NULL;
	struct pmal_config_s sock_conf;
	unsigned int i = 0;
	unsigned int k = 0;

	PMAL_FN_ENTRY();

	memcpy(&sock_conf, &g_pmal_conf, sizeof( struct pmal_config_s));

	if (cfg.config_bitmap)
	for (i = 0; i < PMAL_MAX_CFG_PARAMS; i++) {
		k = (1 << i);
		if (k & cfg.config_bitmap) {
			switch (k) {

			case PMAL_SOCKET_TYPE:
				sock_conf.type = cfg.type;
				break;

			case PMAL_RING_SIZE:
				sock_conf.ring_size = cfg.ring_size;
				break;


			case PMAL_SOCK_FILTER:
				memcpy(&sock_conf.sock_filter,
					&cfg.sock_filter,
					sizeof(struct packet_filter_s));
				break;

			case PMAL_DYNAMIC_LEARNING:
				sock_conf.dynamic_learing_enabled =
					cfg.dynamic_learing_enabled;
				break;

			}
		}
	}


	if (PMAL_SOCKET_RX == direction) {
		optname = PACKET_UM_RX_RING;
		data_dir = data_rx;
	} else {
		optname = PACKET_UM_TX_RING;
		data_dir = data_tx;
	}

	fd = socket(PF_PACKET, sock_conf.type, htons(ETH_P_ALL));
	if (fd <= 0) {
		PMAL_ERROR("socket(%d) open failed", direction);
		return -1;
	}

	ps = malloc(sizeof(struct pmal_sock));
	if (ps == NULL) {
		PMAL_ERROR("malloc for ring_tx failed");
		close(fd);
		return -1;;
	}

	ps->ring = malloc(sock_conf.ring_size * sizeof(struct iovec));
	if (ps->ring == NULL) {
		PMAL_ERROR("malloc for ring_tx failed");
		close(fd);
		free(ps);
		return -1;;
	}

	ring_dir = ps->ring;

	ps_list[fd] = ps;
	ps->head = 0;
	ps->buff_index = 0;

	req.tp_block_size = PMAL_PKTMMAP_BLOCK_SIZE;
	req.tp_frame_size = PMAL_DEF_FRAME_SIZE;
	req.tp_frame_nr = PMAL_DEF_NUM_FRAMES;
	req.tp_block_nr = (PMAL_DEF_FRAME_SIZE * PMAL_DEF_NUM_FRAMES) /
					req.tp_block_size;
	req.tp_ring_nr = sock_conf.ring_size;

	tpkt_blk_num = TPACKET_BLOCK_NUM(
		(sock_conf.ring_size * sizeof(struct tpacket_hdr)),
		req.tp_block_size);

	size = req.tp_block_size * (req.tp_block_nr + tpkt_blk_num);

	ret_val = setsockopt(fd,
			SOL_PACKET,
			optname,
			(char *)&req,
			sizeof(struct tpacket_req));
	if (ret_val) {
		PMAL_ERROR("setsockopt failed");
		close(fd);
		return -1;
	}

	//TBD - what about filters for TX direction ?
	if (PMAL_SOCKET_RX == direction) {
		ret_val = setsockopt(fd,
				SOL_PACKET,
				PACKET_UM_SOCK_FILTER,
				(char *)&sock_conf.sock_filter,
				sizeof(struct packet_filter_s));

		if (g_pmal_conf.dynamic_learing_enabled) {
			ret_val = setsockopt(fd,
				SOL_PACKET,
				PACKET_UM_DYNM_LRNING,
				(char *)&sock_conf.dynamic_learing_enabled,
				sizeof(unsigned int));
		}

		data_tx_offset = PACKET_UM_TX_HDR_RESERVE +
				PACKET_UM_HEAD_RESERVE +
				PACKET_TX_IPSEC_RESERVE;
	}

	map = mmap(NULL, size,
			PROT_READ|PROT_WRITE|PROT_EXEC,
			MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		PMAL_ERROR("mmap failed");
		close(fd);
		return -1;
	}

	for (i = 0; i < PMAL_DEF_NUM_FRAMES; i++) {
		data_dir[i].iov_base =
			(void *)((long)map) + (i*req.tp_frame_size);
		data_dir[i].iov_len = req.tp_frame_size;
	}

	ring_dir[0].iov_base = (req.tp_block_size * req.tp_block_nr) +
		(void *)((long)map);

	for (i = 1; i < sock_conf.ring_size; i++)
		ring_dir[i].iov_base = ring_dir[i-1].iov_base
			+ sizeof(struct tpacket_hdr);

	PMAL_FN_EXIT();
	return fd;
}

/* To Close a Packet Mapped Socket*/
int pmal_close(int fd)
{
	return close(fd);
}

int pmal_getsockopt(int fd, int optname, char *optval, socklen_t *optlen)
{
	switch (optname) {
	case PMAL_STATS:
		return getsockopt(fd,
				SOL_PACKET,
				PACKET_STATISTICS,
				optval,
				optlen);

	case PMAL_BOARD_TYPE:
		return getsockopt(fd,
				SOL_PACKET,
				PACKET_UM_BOARD_TYPE,
				optval,
				optlen);
	}

	return -1;
}

/*Currently only Debug Option - Loopback Available*/
int pmal_setsockopt(int fd, int optname, char *optval, socklen_t optlen)
{
	if (optname == PMAL_KERNEL_LOOPBACK) {
		return setsockopt(fd,
				SOL_PACKET,
				PACKET_UM_KERNEL_LOOPBACK,
				optval,
				optlen);
	}
	return -1;
}


/* Poll Frames for receive */
int pmal_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
	PMAL_FN_ENTRY();
	return poll(fds, nfds, timeout);
}

/* Get a frame from Network*/
int pmal_dequeue_frame_rx(int fd, struct pmal_buf **frm)
{
	unsigned int frame_id_rx = 0;
	struct pmal_sock *ps = ps_list[fd];
	struct pcb_s *frame = NULL;

	if (*(unsigned long *)ps->ring[ps->head].iov_base) {
		struct tpacket_hdr *h = ps->ring[ps->head].iov_base;

		frame_id_rx = h->tp_frame_id;
		frame = (struct pcb_s *)data_rx[frame_id_rx].iov_base;
		*frm = &frame->pmal_ext;
		ps->head = (ps->head == (g_pmal_conf.ring_size - 1)) ?
			0 : ps->head + 1;
		h->tp_status = TP_STATUS_KERNEL;
	} else
		*frm = NULL;
	return 0;
}

/* Free the received buffer */
void pmal_free_buffer(int fd, struct pmal_buf *frame)
{
	struct pmal_sock *ps = ps_list[fd];
	unsigned int num_frags = 0;
	struct pcb_s *pcb_buf = NULL;

	pcb_buf = PMAL_GET_PCB_FROM_PMAL_BUF(frame);
#ifdef PMAL_SG_SUPPORT
	num_frags = pcb_buf->pmal_ext.num_frags;
#else
	num_frags = 0;
#endif
	pcb_buf->pmal_ext.num_frags = 0;
	num_frags++;
	do {
		ps->buff_list[ps->buff_index] = pcb_buf->priv.frame_id;
		ps->buff_index++;
		if (ps->buff_index == PACKET_UM_BUFFER_STOCKPILE) {
			if ((setsockopt(fd,
				SOL_PACKET,
				PACKET_UM_FREE_BUF_LIST,
				(char *)&ps->buff_list,
				PACKET_UM_BUFFER_STOCKPILE *
				sizeof(unsigned int))
				) != 0) {
					perror("setsockopt()");
					close(fd);
			}
			ps->buff_index = 0;
		}
		pcb_buf = data_rx[pcb_buf->priv.next_fid].iov_base;
		num_frags--;
	} while (num_frags);
	return;
}

/* get a raw data buffer  - All frames are of fixed size (MAX) */
struct pmal_buf *pmal_alloc_buffer(int fd, int size, unsigned int flag)
{
	unsigned int len = 0;
	struct pmal_sock *ps = ps_list[fd];
	unsigned int frame_id = 0;
	struct pcb_s *pcb = NULL;

	if ((data_tx[0].iov_len -
		data_tx_offset - PACKET_UM_END_RESERVE) < size) {
		if (flag)
			return pmal_alloc_sg_list(fd, size);
		return NULL;
	}

	if (ps->buff_index) {
		ps->buff_index--;
		frame_id = ps->buff_list[ps->buff_index];
		pcb = (struct pcb_s *)data_tx[frame_id].iov_base;
		pcb->pmal_ext.data = data_tx_offset;
		pcb->pmal_ext.buf_len = data_tx[0].iov_len -
			data_tx_offset - PACKET_UM_END_RESERVE;
		return &pcb->pmal_ext;
	}

	len = sizeof(unsigned int) * PACKET_UM_BUFFER_STOCKPILE;
	if ((getsockopt(fd,
		SOL_PACKET,
		PACKET_UM_GET_BUF_LIST,
		(char *)&(ps->buff_list),
		 &len)) != 0) {
			perror("getsockopt()");
			 close(fd);
	}
	ps->buff_index = len / sizeof(unsigned int);
	ps->buff_index--;
	pcb = (struct pcb_s *)data_tx[ps->buff_list[ps->buff_index]].iov_base;
	pcb->pmal_ext.data = data_tx_offset;
	pcb->pmal_ext.buf_len = data_tx[0].iov_len -
		data_tx_offset - PACKET_UM_END_RESERVE;

	return &pcb->pmal_ext;
}

int pmal_join_frags(struct pmal_buf *first,
		struct pmal_buf *last)
{
#ifdef PMAL_SG_SUPPORT
	struct pcb_s *pcb_first = PMAL_GET_PCB_FROM_PMAL_BUF(first);
	struct pcb_s *pcb_last = PMAL_GET_PCB_FROM_PMAL_BUF(last);
	struct pcb_s *pcb_tmp = NULL;
	struct iovec *data_dir = NULL;
	unsigned int frags = 0;

	if (pcb_first->priv.bpool_id != pcb_last->priv.bpool_id)
		return -1;

	if (pcb_first->priv.bpool_id == PMAL_BPOOL_ID_1)
		data_dir = data_tx;
	else
		data_dir = data_rx;

	frags = pcb_first->pmal_ext.num_frags;

	pcb_tmp = pcb_first;
	while (frags) {
		pcb_tmp = (struct pcb_s *)data_dir[pcb_tmp->priv.next_fid].iov_base;
		frags--;
	}

	pcb_tmp->priv.next_fid = pcb_last->priv.frame_id;
	pcb_first->pmal_ext.total_len += pcb_last->pmal_ext.total_len;
	pcb_first->pmal_ext.num_frags += pcb_last->pmal_ext.num_frags;
	pcb_first->pmal_ext.num_frags++;
	return 0;
#else
	return -1;
#endif
}


struct pmal_buf *pmal_frag_next(struct pmal_buf *last,
		struct pmal_buf **next)
{
#ifdef PMAL_SG_SUPPORT
	struct pcb_s *pcb_last = PMAL_GET_PCB_FROM_PMAL_BUF(last);

	if (pcb_last->priv.bpool_id == PMAL_BPOOL_ID_1)
		pcb_last = (struct pcb_s *)data_tx[pcb_last->priv.next_fid].iov_base;
	else
		pcb_last = (struct pcb_s *)data_rx[pcb_last->priv.next_fid].iov_base;
	*next = &pcb_last->pmal_ext;
	return &pcb_last->pmal_ext;
#else
	*next NULL;
	return NULL;
#endif
}

int pmal_remove_frag(struct pmal_buf *head,
		struct pmal_buf *remove)
{
#ifdef PMAL_SG_SUPPORT
	struct pcb_s *pcb_first = PMAL_GET_PCB_FROM_PMAL_BUF(head);
	struct pcb_s *pcb_last = PMAL_GET_PCB_FROM_PMAL_BUF(remove);
	struct pcb_s *pcb_tmp1 = NULL;
	struct pcb_s *pcb_tmp2 = NULL;
	struct iovec *data_dir = NULL;
	unsigned int frags = 0;
	unsigned int i = 0;

	if (pcb_first->priv.bpool_id == PMAL_BPOOL_ID_1)
		data_dir = data_tx;
	else
		data_dir = data_rx;

	pcb_tmp1 = pcb_first;
	do {
		pcb_tmp2 = pcb_tmp1;
		pcb_tmp1 = (struct pcb_s *)data_dir[pcb_tmp2->priv.next_fid].iov_base;
		frags++;
	} while (pcb_tmp1->priv.frame_id != pcb_last->priv.frame_id);

	pcb_tmp2->priv.next_fid = 0;
	pcb_last->pmal_ext.num_frags = pcb_first->pmal_ext.num_frags;
	pcb_first->pmal_ext.num_frags = frags;
	pcb_last->pmal_ext.num_frags -= frags;
	pcb_last->pmal_ext.num_frags--;

	pcb_tmp1 = pcb_last;
	for (i = 0; i <= frags; i++) {
		pcb_last->pmal_ext.total_len += pcb_tmp1->pmal_ext.buf_len;
		pcb_tmp1 = (struct pcb_s *)data_dir[pcb_tmp1->priv.next_fid].iov_base;
	}

	pcb_first->pmal_ext.total_len -= pcb_last->pmal_ext.total_len;
	return 0;
#else
	return -1;
#endif
}



void *pmal_alloc_frag(int fd, struct pmal_buf *next, unsigned int size)
{
#ifdef PMAL_SG_SUPPORT
	struct pcb_s *pcb_buf = NULL;
	struct pcb_s *first_pmal_buf = NULL;
	struct pcb_s *pcb_next = PMAL_GET_PCB_FROM_PMAL_BUF(next);
	struct pmal_buf *buff = NULL;

	buff = pmal_alloc_buffer(fd, size, 0);
	if (buff == NULL)
		return NULL;

	pcb_buf = PMAL_GET_PCB_FROM_PMAL_BUF(buff);
	pcb_buf->priv.next_fid = pcb_next->priv.next_fid;
	pcb_buf->priv.first_fid = pcb_next->priv.first_fid;
	pcb_buf->pmal_ext.buf_len = data_tx[0].iov_len -
		data_tx_offset - PACKET_UM_END_RESERVE;
	pcb_next->priv.next_fid = pcb_buf->priv.frame_id;
	first_pmal_buf =
		(struct pcb_s *)(data_tx[pcb_next->priv.first_fid].iov_base);
	first_pmal_buf->pmal_ext.num_frags++;
	return pcb_buf;
#else
	return NULL;
#endif
}

void pmal_set_data_len_frag(struct pmal_buf *frag, unsigned int data_len)
{
#ifdef PMAL_SG_SUPPORT
	struct pcb_s *pcb = NULL;
	struct pmal_buf *pmal = NULL;
	unsigned int first_fid = 0;

	pcb = PMAL_GET_PCB_FROM_PMAL_BUF(frag);
	frag->buf_len = data_len;
	first_fid = pcb->priv.first_fid;
	if (pcb->priv.bpool_id == PMAL_BPOOL_ID_1)
		pcb = (struct pcb_s *)(data_tx[first_fid].iov_base);
	else
		pcb = (struct pcb_s *)(data_rx[first_fid].iov_base);
	pmal = &pcb->pmal_ext;
	pmal->total_len += data_len;
#endif
	return ;
}

struct pmal_buf *pmal_alloc_sg_list(int fd, int size)
{
#ifdef PMAL_SG_SUPPORT
	struct pmal_sock *ps = ps_list[fd];
	unsigned int nr_frags = 0;
	struct pcb_s *tmp1_pmal_buf = NULL;
	struct pcb_s *tmp2_pmal_buf = NULL;
	struct pcb_s *first_pmal_buf = NULL;
	unsigned int len = 0;
	unsigned int list_len = 0;
	len = data_tx[0].iov_len - data_tx_offset - PACKET_UM_END_RESERVE;

	nr_frags = size / len;
	if (size % len)
		nr_frags++;

	while (nr_frags) {
		if (ps->buff_index) {
			ps->buff_index--;
			tmp1_pmal_buf =
			data_tx[ps->buff_list[ps->buff_index]].iov_base;
			if (!first_pmal_buf) {
				first_pmal_buf = tmp1_pmal_buf;
				first_pmal_buf->pmal_ext.num_frags =
					nr_frags - 1;
				first_pmal_buf->pmal_ext.total_len = 0;
				tmp2_pmal_buf = tmp1_pmal_buf;
			} else {
				tmp2_pmal_buf->priv.next_fid =
					tmp1_pmal_buf->priv.frame_id;
				tmp2_pmal_buf =
					data_tx[tmp2_pmal_buf->priv.next_fid].iov_base;
			}

			tmp1_pmal_buf->pmal_ext.data = data_tx_offset;
			tmp1_pmal_buf->pmal_ext.buf_len = len;
			tmp1_pmal_buf->priv.first_fid =
				first_pmal_buf->priv.frame_id;
			tmp1_pmal_buf->priv.tail = data_tx[0].iov_len - PACKET_UM_END_RESERVE;
			nr_frags--;
		}

		if ((!ps->buff_index) && (nr_frags)) {
			list_len = sizeof(unsigned int) * PACKET_UM_BUFFER_STOCKPILE;
			if ((getsockopt(fd,
				SOL_PACKET,
				PACKET_UM_GET_BUF_LIST,
				(char *)&(ps->buff_list),
				&list_len)) != 0) {
				perror("getsockopt()");
				close(fd);
			}
			ps->buff_index = list_len / sizeof(unsigned int);
		}
	}
	return &first_pmal_buf->pmal_ext;
#else
	return NULL;
#endif
}

/* Add a frame for transmission*/
int pmal_enqueue_frame_tx(int fd, struct pmal_buf *frm)
{
	struct pmal_sock *ps = ps_list[fd];
	struct tpacket_hdr *h = ps->ring[ps->head].iov_base;
	char *frame = PMAL_GET_DATAFRAME_FROM_PMAL_BUF(frm);

	PMAL_FN_ENTRY();

	if (h->tp_status == TP_STATUS_AVAILABLE) {
		h->tp_frame_id = PMAL_GET_FRAME_ID_FROM_DATAFRAME(frame);
		h->tp_status = TP_STATUS_SEND_REQUEST;

		/* ip header total length offset */
		h->tp_len = *((unsigned short *)(frame + 2));

		ps->head = (ps->head == g_pmal_conf.ring_size - 1)
			? 0 : (ps->head) + 1;
	} else
		return -1;

	return 0;
}

/* System call to send frames after enqueue - max frame that
can be sent per send call is PMAL_DEF_SEND_CALL_WT or as configured*/
int pmal_send(int fd, struct sockaddr *peer_addr)
{
	return sendto(fd,
		NULL,
		0,
		MSG_DONTWAIT,
		(struct sockaddr *) peer_addr,
		sizeof(struct sockaddr_ll));
}

/* If dynamic learning on the configured ports is not on, static connection
configurion is required to receive/transmit the packets */

int pmal_add_connection(int fd, struct pmal_con_s *conn)
{
	return setsockopt(fd,
			SOL_PACKET,
			PACKET_UM_ADD_CONN,
			(char *)conn,
			sizeof(struct pmal_con_s));
}

int pmal_del_connection(int fd, struct pmal_con_s *conn)
{
	return setsockopt(fd,
			SOL_PACKET,
			PACKET_UM_DEL_CONN,
			(char *)conn,
			sizeof(struct pmal_con_s));
}

