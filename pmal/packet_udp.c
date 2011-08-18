/**************************************************************************
 * Copyright 2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	packet_udp.c
 *
 * Description: Contains the application for recv normal udp traffic and loopback
 *
 * Authors:	Hemant Agrawal <b10814@freescale.com>
 *		Himanshu Seth <b21215@freescale.com>
 */
/* History
 *  Version	Date		Author		Change Description
 *
*/
/******************************************************************************/

#ifndef __linux__
#error "Are you loco? This is Linux only!"
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int sock;
	int err;
	unsigned int addr_len, bytes_read;
	unsigned int port = 1024;
	char recv_data[1024];
	struct sockaddr_in server_addr , client_addr;

	if (argc >= 2) {
		port = atoi(argv[1]);
		printf("\n UDP Port = %d", atoi(argv[1]));
	} else
		printf("\n UDP Port = %d", port);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("Socket");
		exit(1);
	}

	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero), 8);

	if (bind(sock, (struct sockaddr *)&server_addr,
		sizeof(struct sockaddr)) == -1) {
		perror("Bind");
		exit(1);
	}

	addr_len = sizeof(struct sockaddr);

	printf("\nUDPServer Waiting for client on port %d", port);
	fflush(stdout);

	while (1) {

		bytes_read = recvfrom(sock, recv_data, 1024, 0,
				(struct sockaddr *)&client_addr, &addr_len);

		recv_data[bytes_read] = '\0';

/*		printf("\n(%s , %d) rcvd : ", inet_ntoa(client_addr.sin_addr),
					ntohs(client_addr.sin_port));
		printf("%d - %s", bytes_read, recv_data);

		printf("\nSending Data");
*/
		err = sendto(sock, recv_data, strlen(recv_data),
			MSG_DONTROUTE | MSG_CONFIRM,
			(struct sockaddr *)&client_addr,
			sizeof(struct sockaddr));
		if (err < 0)
			printf("\n sendto returned err = %d", err);

		fflush(stdout);
	}
	return 0;
}

