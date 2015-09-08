/*
 *  Media Utility
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Yong Yeon Kim <yy9875.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/**
 * This file defines api utilities of IPC.
 *
 * @file		media-util-ipc.c
 * @author	Haejeong Kim(backto.kim@samsung.com)
 * @version	1.0
 * @brief
 */

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include "media-util-dbg.h"
#include "media-util.h"

char MEDIA_IPC_PATH[][50] ={
	{"/tmp/.media_ipc_dbbatchupdate"},
	{"/tmp/.media_ipc_scandaemon"},
	{"/tmp/.media_ipc_scanner"},
	{"/tmp/.media_ipc_dbupdate"},
	{"/tmp/.media_ipc_thumbcreator"},
	{"/tmp/.media_ipc_thumbcomm"},
	{"/tmp/.media_ipc_thumbdaemon"},
};

#define MS_SOCK_PATH_PRFX "/tmp/.media_ipc_client"
#define MS_SOCK_PATH_TEMPLATE "XXXXXX"
#define MS_SOCK_PATH MS_SOCK_PATH_PRFX MS_SOCK_PATH_TEMPLATE

static const char abc[] =
 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

static int __make_rand_sock_and_bind(int sockfd, struct sockaddr_un *serv_addr, char *sock_path)
{
	int count;
	char *rand_str = NULL;
	int len = 0;
	int ret = MS_MEDIA_ERR_NONE;
	unsigned int seed = time(NULL);

	len = strlen(sock_path);

	rand_str = &sock_path[len -strlen(MS_SOCK_PATH_TEMPLATE)];

	for (count = 0; count < TMP_MAX; count++) {

		srand((unsigned int) time(0) + getpid());

		rand_str[0] = abc[rand_r(&seed) % 62];
		rand_str[1] = abc[rand_r(&seed) % 62];
		rand_str[2] = abc[rand_r(&seed) % 62];
		rand_str[3] = abc[rand_r(&seed) % 62];
		rand_str[4] = abc[rand_r(&seed) % 62];
		rand_str[5] = abc[rand_r(&seed) % 62];

		strncpy(serv_addr->sun_path, sock_path, strlen(sock_path));

		/* Bind to the local address */
		if (bind(sockfd, (struct sockaddr *)serv_addr, sizeof(struct sockaddr_un)) < 0) {
			MSAPI_DBG_STRERROR("bind failed");
			if(errno == EADDRINUSE) {
				if (count == TMP_MAX -1) {
					MSAPI_DBG_ERR("bind failed : arrive max count %d", TMP_MAX);
					ret = MS_MEDIA_ERR_SOCKET_BIND;
					break;
				}
				MSAPI_DBG_ERR("retry bind %d", count);
				continue;
			} else {
				MSAPI_DBG_ERR("socket bind failed");
				close(sockfd);
				ret= MS_MEDIA_ERR_SOCKET_BIND;
				break;
			}
		} else {
			ret = MS_MEDIA_ERR_NONE;
			break;
		}
	}

	return ret;
}

int ms_ipc_create_client_socket(ms_protocol_e protocol, int timeout_sec, ms_sock_info_s* sock_info)
{
	int sock = -1;
	int err = MS_MEDIA_ERR_NONE;
	struct sockaddr_un serv_addr;
	char sock_path_temp[] = MS_SOCK_PATH;

	struct timeval tv_timeout = { timeout_sec, 0 };

	if(protocol == MS_PROTOCOL_UDP)
	{
		/* Create a datagram/UDP socket */
		if ((sock = socket(PF_FILE, SOCK_DGRAM, 0)) < 0) {
			MSAPI_DBG_STRERROR("socket failed");
			return MS_MEDIA_ERR_SOCKET_CONN;
		}

		memset(&serv_addr, 0, sizeof(serv_addr));
		serv_addr.sun_family = AF_UNIX;
		/* make temp file for socket*/
		err = __make_rand_sock_and_bind(sock, &serv_addr, sock_path_temp);
		if (err != MS_MEDIA_ERR_NONE) {
			MSAPI_DBG_ERR("__make_rand_sock_and_bind failed");
			return err;
		}
	}
	else
	{
		/*Create TCP Socket*/
		if ((sock = socket(PF_FILE, SOCK_STREAM, 0)) < 0) {
			MSAPI_DBG_STRERROR("socket failed");
			return MS_MEDIA_ERR_SOCKET_CONN;
		}
	}

	if (timeout_sec > 0) {
		if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof(tv_timeout)) == -1) {
			MSAPI_DBG_STRERROR("setsockopt failed");
			close(sock);
			return MS_MEDIA_ERR_SOCKET_CONN;
		}
	}

	sock_info->sock_fd = sock;
	if(protocol == MS_PROTOCOL_UDP)
		sock_info->sock_path = strdup(sock_path_temp);
	else
		sock_info->sock_path = NULL;

	return MS_MEDIA_ERR_NONE;
}

int ms_ipc_delete_client_socket(ms_sock_info_s* sock_info)
{
	int err = 0;

	close(sock_info->sock_fd);
	MSAPI_DBG("sockfd %d close", sock_info->sock_fd);
	if (sock_info->sock_path != NULL) {
		err = unlink(sock_info->sock_path);
		if (err< 0) {
			MSAPI_DBG_STRERROR("unlink failed");
		}
		free(sock_info->sock_path);
	}

	return 0;
}

int ms_ipc_create_server_socket(ms_protocol_e protocol, ms_msg_port_type_e port, int *sock_fd)
{
	int i;
	bool bind_success = false;
	int sock = -1;
	struct sockaddr_un serv_addr;
	unsigned short serv_port;

	serv_port = port;

	if(protocol == MS_PROTOCOL_UDP)
	{
		/* Create a datagram/UDP socket */
		if ((sock = socket(PF_FILE, SOCK_DGRAM, 0)) < 0) {
			MSAPI_DBG_STRERROR("socket failed");
			return MS_MEDIA_ERR_SOCKET_CONN;
		}
	}
	else
	{
		/* Create a TCP socket */
		if ((sock = socket(PF_FILE, SOCK_STREAM, 0)) < 0) {
			MSAPI_DBG_STRERROR("socket failed");
			return MS_MEDIA_ERR_SOCKET_CONN;
		}
	}

	memset(&serv_addr, 0, sizeof(serv_addr));

	serv_addr.sun_family = AF_UNIX;
//	MSAPI_DBG_SLOG("%s", MEDIA_IPC_PATH[serv_port]);
	unlink(MEDIA_IPC_PATH[serv_port]);
	strncpy(serv_addr.sun_path, MEDIA_IPC_PATH[serv_port], strlen(MEDIA_IPC_PATH[serv_port]));

	/* Bind to the local address */
	for (i = 0; i < 20; i ++) {
		if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
			bind_success = true;
			break;
		}
		MSAPI_DBG("%d",i);
		usleep(250000);
	}

	if (bind_success == false) {
		MSAPI_DBG_STRERROR("bind failed");
		close(sock);
		return MS_MEDIA_ERR_SOCKET_CONN;
	}

	MSAPI_DBG("bind success");

	/* Listening */
	if (protocol == MS_PROTOCOL_TCP) {
		if (listen(sock, SOMAXCONN) < 0) {
			MSAPI_DBG_ERR("listen failed");
			close(sock);
			return MS_MEDIA_ERR_SOCKET_CONN;
		}

		MSAPI_DBG("Listening...");
	}

	/*change permission of sock file*/
	if (chmod(MEDIA_IPC_PATH[serv_port], 0660) < 0) {
		MSAPI_DBG_STRERROR("chmod failed");
	}

	if (chown(MEDIA_IPC_PATH[serv_port], 0, 5000) < 0) {
		MSAPI_DBG_STRERROR("chown failed");
	}
	*sock_fd = sock;

	return MS_MEDIA_ERR_NONE;
}

int ms_ipc_send_msg_to_server(int sockfd, ms_msg_port_type_e port, ms_comm_msg_s *send_msg, struct sockaddr_un *serv_addr)
{
	int res = MS_MEDIA_ERR_NONE;
	struct sockaddr_un addr;

	/* Set server Address */
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, MEDIA_IPC_PATH[port], strlen(MEDIA_IPC_PATH[port]));
//	MSAPI_DBG_SLOG("%s", addr.sun_path);

	if (sendto(sockfd, send_msg, sizeof(*(send_msg)), 0, (struct sockaddr *)&addr, sizeof(addr)) != sizeof(*(send_msg))) {
		MSAPI_DBG_STRERROR("sendto failed");
		res = MS_MEDIA_ERR_SOCKET_SEND;
	} else {
		MSAPI_DBG("sent result [%d]", send_msg->result);
		MSAPI_DBG_SLOG("result message [%s]", send_msg->msg);
		if (serv_addr != NULL)
	*serv_addr = addr;
	}

	return res;
}

int ms_ipc_send_msg_to_server_tcp(int sockfd, ms_msg_port_type_e port, ms_comm_msg_s *send_msg, struct sockaddr_un *serv_addr)
{
	int res = MS_MEDIA_ERR_NONE;
	struct sockaddr_un addr;

	/* Set server Address */
	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, MEDIA_IPC_PATH[port], strlen(MEDIA_IPC_PATH[port]));
//	MSAPI_DBG("%s", addr.sun_path);

	/* Connecting to the media db server */
	if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		MSAPI_DBG_STRERROR("connect error");
		close(sockfd);
		return MS_MEDIA_ERR_SOCKET_CONN;
	}

	if (write(sockfd, send_msg, sizeof(*(send_msg))) != sizeof(*(send_msg))) {
		MSAPI_DBG_STRERROR("write failed");
		res = MS_MEDIA_ERR_SOCKET_SEND;
	} else {
		MSAPI_DBG("sent result [%d]", send_msg->result);
		MSAPI_DBG_SLOG("result message [%s]", send_msg->msg);
		if (serv_addr != NULL)
			*serv_addr = addr;
	}

	return res;
}

int ms_ipc_send_msg_to_client(int sockfd, ms_comm_msg_s *send_msg, struct sockaddr_un *client_addr)
{
	int res = MS_MEDIA_ERR_NONE;

	if (sendto(sockfd, send_msg, sizeof(*(send_msg)), 0, (struct sockaddr *)client_addr, sizeof(*(client_addr))) != sizeof(*(send_msg))) {
		MSAPI_DBG_STRERROR("sendto failed");
		res = MS_MEDIA_ERR_SOCKET_SEND;
	} else {
		MSAPI_DBG("sent result [%d]", send_msg->result);
		MSAPI_DBG_SLOG("result message [%s]", send_msg->msg);
	}

	return res;
}

int ms_ipc_send_msg_to_client_tcp(int sockfd, ms_comm_msg_s *send_msg, struct sockaddr_un *client_addr)
{
	int res = MS_MEDIA_ERR_NONE;

	if (write(sockfd, send_msg, sizeof(*(send_msg))) != sizeof(*(send_msg))) {
		MSAPI_DBG_STRERROR("sendto failed");
		res = MS_MEDIA_ERR_SOCKET_SEND;
	} else {
		MSAPI_DBG("sent result [%d]", send_msg->result);
		MSAPI_DBG_SLOG("result message [%s]", send_msg->msg);
	}

	return res;
}

int ms_ipc_receive_message(int sockfd, void *recv_msg, unsigned int msg_size, struct sockaddr_un *recv_addr, unsigned int *addr_size)
{
	int recv_msg_size;
	struct sockaddr_un addr;
	socklen_t addr_len;

	if (!recv_msg)
		return MS_MEDIA_ERR_INVALID_PARAMETER;

	addr_len = sizeof(addr);
	if ((recv_msg_size = recvfrom(sockfd, recv_msg, msg_size, 0, (struct sockaddr *)&addr, &addr_len)) < 0) {
		MSAPI_DBG_STRERROR("recvfrom failed");
		return MS_MEDIA_ERR_SOCKET_RECEIVE;
	}

	MSAPI_DBG_SLOG("the path of received client address : %s", addr.sun_path);

	if (recv_addr != NULL)
		*recv_addr = addr;
	if (addr_size != NULL)
		*addr_size  = addr_len;

	return MS_MEDIA_ERR_NONE;
}

int ms_ipc_wait_message(int sockfd, void *recv_msg, unsigned int msg_size, struct sockaddr_un *recv_addr, unsigned int *addr_size)
{
	int recv_msg_size;
	socklen_t addr_len;

	if (!recv_msg ||!recv_addr)
		return MS_MEDIA_ERR_INVALID_PARAMETER;

	addr_len = sizeof(struct sockaddr_un);
	if ((recv_msg_size = recvfrom(sockfd, recv_msg, msg_size, 0, (struct sockaddr *)recv_addr, &addr_len)) < 0) {
		MSAPI_DBG_STRERROR("recvfrom failed");
		if (errno == EWOULDBLOCK) {
			MSAPI_DBG_ERR("recvfrom Timeout.");
			return MS_MEDIA_ERR_SOCKET_RECEIVE_TIMEOUT;
		} else {
			MSAPI_DBG_STRERROR("recvfrom error");
			return MS_MEDIA_ERR_SOCKET_RECEIVE;
		}
	}

	if (addr_size != NULL)
		*addr_size  = addr_len;

	return MS_MEDIA_ERR_NONE;
}

int ms_ipc_accept_client_tcp(int serv_sock, int* client_sock)
{
	int sockfd = -1;
	struct sockaddr_un client_addr;
	socklen_t client_addr_len;

	if (client_sock == NULL)
		return MS_MEDIA_ERR_INVALID_PARAMETER;

	client_addr_len = sizeof(client_addr);
	if ((sockfd = accept(serv_sock, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
		MSAPI_DBG_STRERROR("accept failed");
		*client_sock  = -1;
		return MS_MEDIA_ERR_SOCKET_ACCEPT;
	}

	*client_sock  = sockfd;

	return MS_MEDIA_ERR_NONE;
}

int ms_ipc_receive_message_tcp(int client_sock, ms_comm_msg_s *recv_msg)
{
	int recv_msg_size = 0;

	if ((recv_msg_size = read(client_sock, recv_msg, sizeof(ms_comm_msg_s))) < 0) {
		if (errno == EWOULDBLOCK) {
			MSAPI_DBG_ERR("Timeout. Can't try any more");
			return MS_MEDIA_ERR_SOCKET_RECEIVE_TIMEOUT;
		} else {
			MSAPI_DBG_STRERROR("recv failed");
			return MS_MEDIA_ERR_SOCKET_RECEIVE;
		}
	}

	MSAPI_DBG_SLOG("receive msg from [%d] %d, %s", recv_msg->pid, recv_msg->msg_type, recv_msg->msg);

	if (!(recv_msg->msg_size > 0 && recv_msg->msg_size < MAX_FILEPATH_LEN)) {
		MSAPI_DBG_ERR("IPC message is wrong. message size is %d", recv_msg->msg_size);
		return  MS_MEDIA_ERR_INVALID_IPC_MESSAGE;
	}

	return MS_MEDIA_ERR_NONE;
}

