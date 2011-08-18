/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	pmal_demo_select.c
 *
 * Description: Demo code for using normal socket with the PMAL Library
  * 		And using Select call
  *
 * Authors:	Hemant Agrawal <b10814@freescale.com>
 *		Himanshu Seth <b21215@freescale.com>
 */

/* History
 *  Version	Date		Author		Change Description
 *	0.1	20 Jan 2011	Hemant Agrawal	Initial Version
 *	0.2	25 Mar 2011	Himanshu Seth	Using the PMAL library
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
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <signal.h>


/*#define PMAL_DEBUG*/
#include "pmal.h"

/* Application Specific Global var, and defines */
int fd_rx;
int fd_tx;
int total_rx;
int total_tx;

int total_n_rx;
int total_n_tx;

struct pmal_con_s my_conn;

#define ASFT_PMAL_STATIC_FLOW_SRC_IP "192.168.1.5"
#define ASFT_PMAL_STATIC_FLOW_DST_IP "192.168.2.5"

#define ASFT_AF_INET_TEST_UDP_PORT 1234


static inline void pmal_copy(__u32 *dst, __u32 *src, int len)
{
	while (len >= sizeof(__u32)) {
		*dst = *src;
		dst++;
		src++;
		len -= sizeof(__u32);
	}
	if (len)
		memcpy(dst, src, len);
}

/* Dummy function to process the received frame */
void process_frame(char *frame,
	struct pkt_ipudphdr *iph_s,
	struct pkt_ethhdr **eth_s)
{
	*eth_s = (struct pkt_ethhdr *) (frame - ETH_HLEN);
}

/*	Dummy function, which copies the received
	ethernet and ip headers to the transmitted frame
*/
void fill_frame(char *frame,
	struct pkt_ipudphdr *iph_s,
	struct pkt_ethhdr *eth_s)
{
	struct pkt_ipudphdr *iph_d;
	struct pkt_ethhdr *eth_d;

	iph_d = (struct pkt_ipudphdr *)frame;

	pmal_copy((__u32 *)iph_d, (__u32 *)iph_s, 20 + 8);

	iph_d->daddr = iph_s->saddr;
	iph_d->saddr = iph_s->daddr;
	iph_d->udpcheck = 0;

	frame -= ETH_HLEN;
	eth_d = (struct pkt_ethhdr *) frame;
	memcpy(eth_d->h_dest, eth_s->h_source, 6);
	memcpy(eth_d->h_source, eth_s->h_dest, 6);
	eth_d->h_proto = eth_s->h_proto;

	PMAL_PRINT("Tx - pkt src=%x, len =%d", iph_d->saddr, iph_d->tot_len);

	return;
}

/*===== sigproc =====*/
/**
handles SIGINT signal(When the app is stopped using Ctrl C the IPC is removed)
handles SIGTERM signal(when app process is nicely killed)
handles SIGHUP signal(When the parent telnet connection is broken)

@param	signum	[IN] The received signal.
*/
static void sigproc(int signum)
{
	static volatile sig_atomic_t fatal_error_in_progress;
	struct sigaction act;
	struct tpacket_stats st;
	unsigned int len = sizeof(st);

	/* Since this handler is established for more than one kind of signal,
	it might still get invoked recursively by delivery of some other kind
	of signal.  Use a static variable to keep track of that. */
	if (fatal_error_in_progress)
		return;
	fatal_error_in_progress = 1;

	/*Since it is a process exit handler, for graceful exist from
	the current process, set the handler as default */

	act.sa_handler = SIG_DFL;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;

	/* Do all necessary cleanups here*/

	pmal_del_connection(fd_rx, &my_conn);

	if (!pmal_getsockopt(fd_rx, PMAL_STATS, (char *)&st, &len)) {
		fprintf(stderr, "\nPMAL rcvd=%u,dropped=%u, handled=%u",
			st.tp_packets, st.tp_drops, total_rx);
	}

	if (!pmal_getsockopt(fd_tx, PMAL_STATS, (char *)&st, &len)) {
		fprintf(stderr, "\nPMAL trans=%u,drop=%u,send_to call=%u\n",
			st.tp_packets, st.tp_drops, total_tx);
	}
	fprintf(stderr, "\nNon-PMAL - Rx=%u  Tx=%u", total_n_rx, total_n_tx);

	if (fd_rx >= 0)
		close(fd_rx);

	if (fd_tx >= 0)
		close(fd_tx);

	pmal_deinit();

	/* Now reraise the signal. We reactivate the signal's default handling,
	which is to terminate the process. We could just call `exit' or `abort',
	but reraising the signal sets the return status
	from the process correctly. */

	if (sigaction(signum, &act, NULL) == -1) {
		PMAL_ERROR("Registering for signal %d", signum);
		exit(EXIT_FAILURE);
	}

	if (raise(signum) != 0) {
		PMAL_ERROR("Raising the signal %d", signum);
		exit(EXIT_FAILURE);
	}
}

int main(int argc, char **argv)
{
	struct pmal_config_s s_conf;
	struct pollfd pfd[2];
	struct sockaddr_ll peer_addr;
	struct ifreq s_ifr;
	struct pkt_ipudphdr *iph_d, *iph_s;
	struct pkt_ethhdr *eth_d, *eth_s;
	unsigned int tx_wt = 0;
	unsigned int rx_wt = 0;
	unsigned int size = 4;
	unsigned int i_ifindex;
	unsigned int opt_val;
	unsigned int len = 0;
	unsigned int kernel_loopback = 0;
	int i = 0;
	char *pframe = NULL;
	char *pframe_tx = NULL;
	struct sigaction temp_action, new_action;
	int sock;
	int err;
	unsigned int addr_len, bytes_read;

#define RX_BUF_SIZE 256
	char recv_data[RX_BUF_SIZE];
	struct sockaddr_in server_addr , client_addr;

	fd_set  readfds;
	int k = 0;

	/* Set up the structure to specify the new action. */
	memset(&new_action, 0, sizeof(new_action));
	new_action.sa_handler = &sigproc;

	/* Asynchronous signals that result in attempted graceful exit */
#define CATCH_SIGNAL(signum)						\
	do {								\
		if (sigaction(signum, NULL, &temp_action) == -1) {	\
			PMAL_ERROR("Default register for "#signum"\n");	\
			exit(EXIT_FAILURE);				\
		}							\
		if (temp_action.sa_handler != SIG_IGN) {		\
			if (sigaction(signum, &new_action, NULL) == -1) {\
				PMAL_ERROR("Registering for "#signum"\n");\
				exit(EXIT_FAILURE);			\
				}					\
		}							\
	} while (0);

	CATCH_SIGNAL(SIGHUP);
	CATCH_SIGNAL(SIGINT);
	CATCH_SIGNAL(SIGTERM);
#undef CATCH_SIGNAL

	if (argc >= 2) {
		kernel_loopback = atoi(argv[1]);
		printf("\nStarting PACKET_MMAP with KERNEL_LOOPBACK = %d",
			atoi(argv[1]));
	} else
		printf("\nStarting PACKET_MMAP with USERSPACE_LOOPBACK");

/* -  Creating a normal socket to listen on ASFT_AF_INET_TEST_UDP_PORT */
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("Socket");
		exit(1);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(ASFT_AF_INET_TEST_UDP_PORT);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);

	if (bind(sock, (struct sockaddr *)&server_addr,
				sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		exit(1);
	}

/* - Configuring PMAL Library */

	memset(&s_conf, 0, sizeof(s_conf));

	s_conf.type = SOCK_RAW;
	s_conf.frame_size = PMAL_DEF_FRAME_SIZE;
	s_conf.frame_nr = PMAL_DEF_NUM_FRAMES;
	s_conf.ring_size = 4096;
	s_conf.dynamic_learing_enabled = 1;
	s_conf.udp_ports[0] = ASFT_UDP_PORT_IKE;
	s_conf.udp_ports[1] = ASFT_UDP_PORT_NATT;
	s_conf.udp_ports[2] = ASFT_UDP_PORT_GTP_U;
	s_conf.udp_ports[3] = ASFT_UDP_PORT_TEST;

	s_conf.sec_udp_ports[0] = ASFT_UDP_PORT_GTP_U;

	s_conf.config_bitmap = PMAL_SOCKET_TYPE |
			PMAL_SOCKET_FR_SIZE |
			PMAL_SOCKET_FR_NUM |
			PMAL_RING_SIZE |
			PMAL_DYNAMIC_LEARNING |
			PMAL_UDP_PORTS |
			PMAL_SEC_UDP_PORTS;
	if (pmal_init(&s_conf) < 0) {
		PMAL_ERROR("pmal_init");
		return -1;
	}

/* - Creating PMAL Sockets */

	fd_rx = pmal_socket(PMAL_SOCKET_RX);
	if (fd_rx < 0) {
		perror("socket()");
		return -1;
	}

	fd_tx = pmal_socket(PMAL_SOCKET_TX);
	if (fd_tx < 0) {
		perror("socket()");
		return -1;
	}

	len = sizeof(unsigned int);
	pmal_getsockopt(fd_tx,
			PMAL_BOARD_TYPE,
			(char *)&opt_val,
			&len);
	if (opt_val == P2020_AMC)
		strncpy(s_ifr.ifr_name, "eth0",
				sizeof(s_ifr.ifr_name));
	else
		strncpy(s_ifr.ifr_name, "eth2",
				sizeof(s_ifr.ifr_name));

	ioctl(fd_tx, SIOCGIFINDEX, &s_ifr);
	i_ifindex = s_ifr.ifr_ifindex;

	peer_addr.sll_family = PF_PACKET;
	peer_addr.sll_protocol = htons(ETH_P_IP);
	peer_addr.sll_halen = ETH_ALEN;
	peer_addr.sll_ifindex = i_ifindex;


/* - Creating static flow in the PMAL to recive the terminated packets */

	my_conn.saddr.sin_family = AF_INET;
	my_conn.saddr.sin_port = htons(ASFT_UDP_PORT_TEST);
	my_conn.saddr.sin_addr.s_addr = inet_addr(ASFT_PMAL_STATIC_FLOW_SRC_IP);

	my_conn.daddr.sin_family = AF_INET;
	my_conn.daddr.sin_port = htons(ASFT_UDP_PORT_TEST);
	my_conn.daddr.sin_addr.s_addr = inet_addr(ASFT_PMAL_STATIC_FLOW_DST_IP);

	my_conn.conn_id = 1;

	pmal_add_connection(fd_rx, &my_conn);

/* Receiving and Sending the data */
/* For every 2 packet received on PMAL socket, this code sends 1 packet*/
/* This simulates the UL/DL bw requirements, which is in 2:1 ratio */

	while (1) {
		tx_wt = 0;
		rx_wt = 0;
		FD_ZERO(&readfds);
		FD_SET(fd_rx, &readfds);
		FD_SET(sock, &readfds);

		k = fd_rx > sock ? fd_rx : sock;
		k++;
		select(k, &readfds, NULL, NULL, NULL);
/* Reading from the PMAL Socket */
		if (FD_ISSET(fd_rx, &readfds)) {
			while (rx_wt < PMAL_RX_POLL_WT)
			{
				pmal_dequeue_frame_rx(fd_rx, &pframe);
				if (pframe == NULL)
					goto _sendto;
				total_rx++;
				rx_wt++;
				iph_s = (struct pkt_ipudphdr *)pframe;
				process_frame(pframe, iph_s, &eth_s);
				pmal_free_buffer(fd_rx, pframe);

				PMAL_PRINT("RX-%d", total_rx);
				if (total_rx % 2) {
					pframe_tx = (char *)pmal_alloc_buffer(fd_tx, 1500);
					if (pframe_tx) {
						fill_frame(pframe_tx,
							iph_s, eth_s);
						pmal_enqueue_frame_tx(fd_tx,
								pframe_tx);
						tx_wt++;
						total_tx++;
					}
				}
			}
_sendto:
/* Looping back on PMAL Socket */
			if (tx_wt) {
				pmal_send(fd_tx, (struct sockaddr *)&peer_addr);
				PMAL_PRINT("TX-%d", tx_wt);
			}
		}
/* Reading from the Normal Socket */
		if (FD_ISSET(sock, &readfds)) {
			addr_len = sizeof(struct sockaddr);

			bytes_read = recvfrom(sock, recv_data,
				RX_BUF_SIZE, MSG_DONTWAIT,
				(struct sockaddr *)&client_addr,
				&addr_len);
			if (bytes_read <= 0)
				continue;
			recv_data[bytes_read] = '\0';
			total_n_rx++;

/* Looping back on Normal Socket */
			err = sendto(sock, recv_data,
				strlen(recv_data), 0,
				(struct sockaddr *)&client_addr,
				sizeof(struct sockaddr));
			if (err < 0)
				PMAL_PRINT("sendto returned err = %d", err);
			total_n_tx++;
			fflush(stdout);
		}
	}

	return 0;
}

