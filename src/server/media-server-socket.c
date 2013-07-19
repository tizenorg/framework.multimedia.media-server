/*
 *  Media Server
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
 * This file defines api utilities of contents manager engines.
 *
 * @file		media-server-thumb.c
 * @author	Yong Yeon Kim(yy9875.kim@samsung.com)
 * @version	1.0
 * @brief
 */
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef _USE_UDS_SOCKET_
#include <sys/un.h>
#else
#include <sys/socket.h>
#endif
#include <errno.h>
#include <malloc.h>
#include <vconf.h>
#include <security-server.h>

#include "media-util.h"
#include "media-util-internal.h"
#include "media-server-ipc.h"
#include "media-common-utils.h"
#include "media-server-dbg.h"
#include "media-server-scanner.h"
#include "media-server-socket.h"

extern GAsyncQueue *scan_queue;
GAsyncQueue* ret_queue;
GArray *owner_list;
extern GMutex *scanner_mutex;

typedef struct ms_req_owner_data
{
	int pid;
	int index;
	int client_sockfd;
}ms_req_owner_data;

static int __ms_add_owner(ms_req_owner_data *owner_data)
{
//	MS_DBG("the length of array : %d", owner_list->len);
//	MS_DBG("pid : %d", owner_data->pid);
//	MS_DBG("client_addr : %p", owner_data->client_addr);

	owner_data->index = -1;
	g_array_append_val(owner_list, owner_data);

	return MS_MEDIA_ERR_NONE;
}

static int __ms_find_owner(int pid, ms_req_owner_data **owner_data)
{
	int i;
	int len = owner_list->len;
	ms_req_owner_data *data = NULL;

	*owner_data = NULL;

	MS_DBG("length list :  %d", len);

	for (i=0; i < len; i++) {
		data = g_array_index(owner_list, ms_req_owner_data*, i);
		MS_DBG("%d %d", data->pid, pid);
		if (data->pid == pid) {
			data->index = i;
			*owner_data = data;
			MS_DBG("FIND OWNER");
			break;
		}
	}

	return MS_MEDIA_ERR_NONE;
}

static int __ms_delete_owner(ms_req_owner_data *owner_data)
{
	if (owner_data->index != -1) {
		g_array_remove_index(owner_list, owner_data->index);
		MS_SAFE_FREE(owner_data);
		MS_DBG("DELETE OWNER");
	}

	return MS_MEDIA_ERR_NONE;
}

static int __ms_privilege_check(const char *msg, gboolean *privilege)
{
#define operation_cnt		3
#define db_table_cnt		5

	int o_idx = 0;
	int t_idx = 0;
	gboolean is_privilege = TRUE;

	char *operation[operation_cnt] = {
		"INSERT INTO ",
		"DELETE FROM ",
		"UPDATE "
	};

	char *db_table[db_table_cnt] = {
		"playlist_map",
		"playlist",
		"tag_map",
		"tag",
		"bookmark"
	};

	if(strlen(msg) < 30) {
		MS_DBG_ERR("msg is too short!!");
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

	for(o_idx = 0; o_idx < operation_cnt; o_idx++) {
		if(strncmp(operation[o_idx], msg, strlen(operation[o_idx])) == 0) {
			for(t_idx = 0; t_idx < db_table_cnt; t_idx++) {
				if(strncmp(db_table[t_idx], msg+strlen(operation[o_idx]), strlen(db_table[t_idx])) == 0) {
					MS_DBG("Non privilege [%s][%s]", operation[o_idx], db_table[t_idx]);
					is_privilege = FALSE;
					break;
				}
			}
			break;
		}
	}

	*privilege = is_privilege;

	return MS_MEDIA_ERR_NONE;
}

static int __ms_privilege_ask(int client_sockfd)
{
	int ret = 0;
	int res = MS_MEDIA_ERR_NONE;

	MS_DBG_SLOG("CHECK PERMISSION");
	ret = security_server_check_privilege_by_sockfd(client_sockfd, "media-data::db", "w");
	if (ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
		MS_DBG_ERR("You do not have permission for this operation.");
		res = MS_MEDIA_ERR_PERMISSION_DENIED;
	} else {
		MS_DBG_SLOG("PERMISSION OK");
	}

	return res;
}

gboolean ms_read_socket(GIOChannel *src, GIOCondition condition, gpointer data)
{
#ifdef _USE_UDS_SOCKET_
	struct sockaddr_un client_addr;
#else
	struct sockaddr_in client_addr;
#endif
	socklen_t client_addr_len;
	ms_comm_msg_s recv_msg;
	ms_comm_msg_s scan_msg;
	int msg_size;
	int sockfd = MS_SOCK_NOT_ALLOCATE;
	int ret;
	int res;
	int pid;
	int req_num = -1;
	int path_size;
	int client_sock = -1;
	int recv_msg_size = 0;

	g_mutex_lock(scanner_mutex);

	sockfd = g_io_channel_unix_get_fd(src);
	if (sockfd < 0) {
		MS_DBG_ERR("sock fd is invalid!");
		g_mutex_unlock(scanner_mutex);
		return TRUE;
	}

#ifdef _USE_UDS_SOCKET_
	client_addr_len = sizeof(struct sockaddr_un);
#else
	client_addr_len = sizeof(struct sockaddr_in);
#endif

	if ((client_sock = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
		MS_DBG_ERR("accept failed : %s", strerror(errno));
		g_mutex_unlock(scanner_mutex);
		return TRUE;
	}

	if ((recv_msg_size = read(client_sock, &recv_msg, sizeof(ms_comm_msg_s))) < 0) {
		if (errno == EWOULDBLOCK) {
			MS_DBG_ERR("Timeout. Can't try any more");
			res = MS_MEDIA_ERR_SOCKET_RECEIVE_TIMEOUT;
			goto ERROR;
		} else {
			MS_DBG_ERR("recv failed : %s", strerror(errno));
			res = MS_MEDIA_ERR_SOCKET_RECEIVE;
			goto ERROR;
		}
	}

	ret = __ms_privilege_ask(client_sock);
	if (ret == MS_MEDIA_ERR_PERMISSION_DENIED) {
		res = MS_MEDIA_ERR_PERMISSION_DENIED;
		goto ERROR;
	}

	MS_DBG("receive msg from [%d] %d, %s", recv_msg.pid, recv_msg.msg_type, recv_msg.msg);

	if (recv_msg.msg_size > 0 && recv_msg.msg_size < MS_FILE_PATH_LEN_MAX) {
		msg_size = recv_msg.msg_size;
		path_size = msg_size + 1;
	} else {
		/*NEED IMPLEMETATION*/
		res = MS_MEDIA_ERR_INVALID_IPC_MESSAGE;
		goto ERROR;
	}

	/* copy received data */
	req_num = recv_msg.msg_type;
	pid = recv_msg.pid;

	/* register file request
         * media server inserts the meta data of one file into media db */
	if (req_num == MS_MSG_DIRECTORY_SCANNING
		||req_num == MS_MSG_BULK_INSERT
		||req_num == MS_MSG_DIRECTORY_SCANNING_NON_RECURSIVE
		|| req_num == MS_MSG_BURSTSHOT_INSERT) {
		/* this request process in media scanner */

		ms_req_owner_data *owner_data = NULL;

		/* If owner list is NULL, create it */
		/* pid and client address are stored in ower list */
		/* These are used for sending result of scanning */
		if (owner_list == NULL) {
			/*create array for processing overlay data*/
			owner_list = g_array_new (FALSE, FALSE, sizeof (ms_req_owner_data *));
			if (owner_list == NULL) {
				MS_DBG_ERR("g_array_new error");
				res = MS_MEDIA_ERR_ALLOCATE_MEMORY_FAIL;
		goto ERROR;
			}
		}

		/* store pid and client address */
		MS_MALLOC(owner_data, sizeof(ms_req_owner_data));
		owner_data->pid = recv_msg.pid;
		owner_data->client_sockfd = client_sock;

		__ms_add_owner(owner_data);

		/* create send message for media scanner */
		scan_msg.msg_type = req_num;
		scan_msg.pid = pid;
		scan_msg.msg_size = msg_size;
		ms_strcopy(scan_msg.msg, path_size, "%s", recv_msg.msg);

		g_mutex_unlock(scanner_mutex);

		if (ms_get_scanner_status()) {
			MS_DBG("Scanner is ready");
			ms_send_scan_request(&scan_msg);
		} else {
			MS_DBG("Scanner starts");
			ret = ms_scanner_start();
			if(ret == MS_MEDIA_ERR_NONE) {
				ms_send_scan_request(&scan_msg);
			} else {
				MS_DBG("Scanner starting failed. %d", ret);
			}
		}
	} else if ((req_num == MS_MSG_SCANNER_RESULT) ||
		(req_num == MS_MSG_SCANNER_BULK_RESULT)) {
		if (owner_list != NULL) {
			/* If the owner of result message is not media-server, media-server notify to the owner */
			/* The owner of message is distingushied by pid in received message*/
			/* find owner data */
			ms_req_owner_data *owner_data = NULL;

			__ms_find_owner(recv_msg.pid, &owner_data);
			if (owner_data != NULL) {
				MS_DBG("PID : %d", owner_data->pid);

				if (req_num == MS_MSG_SCANNER_RESULT) {
					MS_DBG("DIRECTORY SCANNING IS DONE");
				}

				/* owner data exists */
				/* send result to the owner of request */
				ms_ipc_send_msg_to_client_tcp(owner_data->client_sockfd, &recv_msg, NULL);
				close(owner_data->client_sockfd);

				/* free owner data*/
				__ms_delete_owner(owner_data);
			}
		} else {
			/* owner data does not exist*/
			/*  this is result of request of media server*/
		}
		close(client_sock);
		g_mutex_unlock(scanner_mutex);
	} else {
		/* NEED IMPLEMENTATION */
		close(client_sock);
		g_mutex_unlock(scanner_mutex);
	}

	/*Active flush */
	malloc_trim(0);

	return TRUE;
ERROR:
	{
		ms_comm_msg_s res_msg;

		memset(&res_msg, 0x0, sizeof(ms_comm_msg_s));

		if (req_num == MS_MSG_DIRECTORY_SCANNING
		||req_num == MS_MSG_DIRECTORY_SCANNING_NON_RECURSIVE) {
			res_msg.msg_type = MS_MSG_SCANNER_RESULT;
		} else if (req_num == MS_MSG_BULK_INSERT
			|| req_num == MS_MSG_BURSTSHOT_INSERT) {
			res_msg.msg_type = MS_MSG_SCANNER_BULK_RESULT;
		}

		res_msg.result = res;

		ms_ipc_send_msg_to_client_tcp(client_sock, &res_msg, NULL);
		close(client_sock);

		g_mutex_unlock(scanner_mutex);
	}

	return TRUE;
}

int ms_send_scan_request(ms_comm_msg_s *send_msg)
{
	int res = MS_MEDIA_ERR_NONE;
	int fd = -1;
	int err = -1;

	fd = open(MS_SCANNER_FIFO_PATH_REQ, O_WRONLY);
	if (fd < 0) {
		MS_DBG_ERR("fifo open failed [%s]", strerror(errno));
		return MS_MEDIA_ERR_FILE_OPEN_FAIL;
	}

	/* send message */
	err = write(fd, send_msg, sizeof(ms_comm_msg_s));
	if (err < 0) {
		MS_DBG_ERR("fifo write failed [%s]", strerror(errno));
		close(fd);
		return MS_MEDIA_ERR_FILE_READ_FAIL;
	}

	close(fd);

	return res;
}

int ms_send_storage_scan_request(ms_storage_type_t storage_type, ms_dir_scan_type_t scan_type)
{
	int ret = MS_MEDIA_ERR_NONE;
	ms_comm_msg_s scan_msg = {
		.msg_type = MS_MSG_STORAGE_INVALID,
		.pid = 0, /* pid 0 means media-server */
		.result = -1,
		.msg_size = 0,
		.msg = {0},
	};

	/* msg_type */
	switch (scan_type) {
		case MS_SCAN_PART:
			scan_msg.msg_type = MS_MSG_STORAGE_PARTIAL;
			break;
		case MS_SCAN_ALL:
			scan_msg.msg_type = MS_MSG_STORAGE_ALL;
			break;
		case MS_SCAN_INVALID:
			scan_msg.msg_type = MS_MSG_STORAGE_INVALID;
			break;
		default :
			ret = MS_MEDIA_ERR_INVALID_PARAMETER;
			MS_DBG_ERR("ms_send_storage_scan_request invalid parameter");
			goto ERROR;
			break;
	}

	/* msg_size & msg */
	switch (storage_type) {
		case MS_STORAGE_INTERNAL:
			scan_msg.msg_size = strlen(MEDIA_ROOT_PATH_INTERNAL);
			strncpy(scan_msg.msg, MEDIA_ROOT_PATH_INTERNAL, scan_msg.msg_size );
			break;
		case MS_STORAGE_EXTERNAL:
			scan_msg.msg_size = strlen(MEDIA_ROOT_PATH_SDCARD);
			strncpy(scan_msg.msg, MEDIA_ROOT_PATH_SDCARD, scan_msg.msg_size );
			break;
		default :
			ret = MS_MEDIA_ERR_INVALID_PARAMETER;
			MS_DBG_ERR("ms_send_storage_scan_request invalid parameter");
			goto ERROR;
			break;
	}

	g_mutex_lock(scanner_mutex);

	if (ms_get_scanner_status()) {
		ms_send_scan_request(&scan_msg);
		g_mutex_unlock(scanner_mutex);
	} else {
		g_mutex_unlock(scanner_mutex);

		ret = ms_scanner_start();
		if(ret == MS_MEDIA_ERR_NONE) {
			ms_send_scan_request(&scan_msg);
		} else {
			MS_DBG("Scanner starting failed. ");
		}
	}

ERROR:

	return ret;
}

gboolean ms_read_db_tcp_socket(GIOChannel *src, GIOCondition condition, gpointer data)
{
#ifdef _USE_UDS_SOCKET_
	struct sockaddr_un client_addr;
#else
	struct sockaddr_in client_addr;
#endif
	int sock = -1;
	int client_sock = -1;
	int recv_msg_size = -1;
	char * sql_query = NULL;
	ms_comm_msg_s recv_msg;
	unsigned int client_addr_len;
	int ret = MS_MEDIA_ERR_NONE;
	MediaDBHandle *db_handle = (MediaDBHandle *)data;
	int send_msg = MS_MEDIA_ERR_NONE;
	gboolean privilege = TRUE;

	sock = g_io_channel_unix_get_fd(src);
	if (sock < 0) {
		MS_DBG_ERR("sock fd is invalid!");
		return TRUE;
	}

	client_addr_len = sizeof(client_addr);
	if ((client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
		MS_DBG_ERR("accept failed : %s", strerror(errno));
		return TRUE;
	}

	if ((recv_msg_size = read(client_sock, &recv_msg, sizeof(ms_comm_msg_s))) < 0) {
		if (errno == EWOULDBLOCK) {
			MS_DBG_ERR("Timeout. Can't try any more");
			send_msg = MS_MEDIA_ERR_SOCKET_RECEIVE_TIMEOUT;
			goto ERROR;
		} else {
			MS_DBG_ERR("recv failed : %s", strerror(errno));
			send_msg = MS_MEDIA_ERR_SOCKET_RECEIVE;
			goto ERROR;
		}
	}

	if((recv_msg.msg_size <= 0) ||(recv_msg.msg_size > MAX_MSG_SIZE)  || (!MS_STRING_VALID(recv_msg.msg))) {
		MS_DBG_ERR("invalid query. size[%d]", recv_msg.msg_size);
		send_msg = MS_MEDIA_ERR_SOCKET_RECEIVE;
		goto ERROR;
	}

	/* check privileage */
	if(__ms_privilege_check(recv_msg.msg, &privilege) != MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("invalid query. size[%d]", recv_msg.msg_size);
		send_msg = MS_MEDIA_ERR_SOCKET_RECEIVE;
		goto ERROR;
	}

	if (privilege == TRUE) {
		MS_DBG_SLOG("NEED CHECKING PERMISSION");
		ret = __ms_privilege_ask(client_sock);
		if (ret == MS_MEDIA_ERR_PERMISSION_DENIED) {
			send_msg = MS_MEDIA_ERR_PERMISSION_DENIED;
			goto ERROR;
		}
	}

	sql_query = strndup(recv_msg.msg, recv_msg.msg_size);
	if (sql_query != NULL) {
		ret = media_db_update_db(db_handle, sql_query);
		if (ret != MS_MEDIA_ERR_NONE)
			MS_DBG_ERR("media_db_update_db error : %d", ret);

		send_msg = ret;
		MS_SAFE_FREE(sql_query);
	} else {
		send_msg = MS_MEDIA_ERR_ALLOCATE_MEMORY_FAIL;
	}

ERROR:
	if (write(client_sock, &send_msg, sizeof(send_msg)) != sizeof(send_msg)) {
		MS_DBG_ERR("send failed : %s", strerror(errno));
	} else {
		MS_DBG("Sent successfully");
	}

	if (close(client_sock) <0) {
		MS_DBG_ERR("close failed [%s]", strerror(errno));
	}

	return TRUE;
}


gboolean _ms_process_tcp_message(void *data)
{
	int ret = MS_MEDIA_ERR_NONE;
	int recv_msg_size = -1;
	char * sql_query = NULL;
	ms_comm_msg_s recv_msg;
	int client_sock = GPOINTER_TO_INT (data);
	int send_msg = MS_MEDIA_ERR_NONE;
	MediaDBHandle *db_handle = NULL;

	memset((void *)&recv_msg, 0, sizeof(ms_comm_msg_s));

	/* Connect Media DB*/
	if(media_db_connect(&db_handle) != MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("Failed to connect DB");
		return FALSE;
	}

	MS_DBG_ERR("client sokcet : %d", client_sock);

	while(1) {
		if ((recv_msg_size = read(client_sock, &recv_msg, sizeof(ms_comm_msg_s))) < 0) {
			MS_DBG_ERR("recv failed : %s", strerror(errno));
			if (errno == EINTR) {
				MS_DBG_ERR("interrupt system call but wait next message");
				continue;
			}

			media_db_request_update_db_batch_clear();
			if (errno == EWOULDBLOCK) {
				MS_DBG_ERR("Timeout. Can't try any more");
				break;
			} else {
				MS_DBG_ERR("recv failed : %s", strerror(errno));
				break;
			}
		}

		MS_DBG_SLOG("(%d)Received [%d] [%s]", recv_msg.pid, recv_msg.msg_type, recv_msg.msg);

		if((recv_msg.msg_size <= 0) ||(recv_msg.msg_size > MAX_MSG_SIZE)) {
			MS_DBG_ERR("invalid query. size[%d]", recv_msg.msg_size);
			MS_DBG_ERR("Received [%d](%d) [%s]", recv_msg.msg_type, recv_msg.msg_size, recv_msg.msg);
			MS_DBG_ERR("client sokcet : %d", client_sock);
			media_db_request_update_db_batch_clear();
			break;
		}

		sql_query = strndup(recv_msg.msg, recv_msg.msg_size);
		if (sql_query != NULL) {
			if (recv_msg.msg_type == MS_MSG_DB_UPDATE_BATCH_START) {
				ret = media_db_update_db_batch_start(sql_query);
			} else if(recv_msg.msg_type == MS_MSG_DB_UPDATE_BATCH_END) {
				ret = media_db_update_db_batch_end(db_handle, sql_query);
			} else if(recv_msg.msg_type == MS_MSG_DB_UPDATE_BATCH) {
				ret = media_db_update_db_batch(sql_query);
			} else {

			}

			MS_SAFE_FREE(sql_query);
			send_msg = ret;

			if (write(client_sock, &send_msg, sizeof(send_msg)) != sizeof(send_msg)) {
				MS_DBG_ERR("send failed : %s", strerror(errno));
			} else {
				MS_DBG("Sent successfully");
			}

			MS_DBG_ERR("client sokcet : %d", client_sock);
			if (recv_msg.msg_type == MS_MSG_DB_UPDATE_BATCH_END) {
				MS_DBG_WARN("Batch job is successfull!");
				MS_DBG_ERR("client sokcet : %d", client_sock);
				break;
			}

			if (ret < MS_MEDIA_ERR_NONE && recv_msg.msg_type == MS_MSG_DB_UPDATE_BATCH_START) {
				MS_DBG_ERR("Batch job start is failed!");
				MS_DBG_ERR("client sokcet : %d", client_sock);
				media_db_request_update_db_batch_clear();
				break;
			}

			memset((void *)&recv_msg, 0, sizeof(ms_comm_msg_s));
		} else {
			MS_DBG_ERR("MS_MALLOC failed");
			media_db_request_update_db_batch_clear();
			break;
		}
	}

	if (close(client_sock) <0) {
		MS_DBG_ERR("close failed [%s]", strerror(errno));
	}

	/* Disconnect DB*/
	media_db_disconnect(db_handle);

	g_thread_exit(0);
}

gboolean ms_read_db_tcp_batch_socket(GIOChannel *src, GIOCondition condition, gpointer data)
{
#ifdef _USE_UDS_SOCKET_
	struct sockaddr_un client_addr;
#else
	struct sockaddr_in client_addr;
#endif
	unsigned int client_addr_len;

	int sock = -1;
	int client_sock = -1;

	sock = g_io_channel_unix_get_fd(src);
	if (sock < 0) {
		MS_DBG_ERR("sock fd is invalid!");
		return TRUE;
	}

	client_addr_len = sizeof(client_addr);
	if ((client_sock = accept(sock, (struct sockaddr*)&client_addr, &client_addr_len)) < 0) {
		MS_DBG_ERR("accept failed : %s", strerror(errno));
		media_db_request_update_db_batch_clear();
		return TRUE;
	}

	MS_DBG_SLOG("Client[%d] is accepted", client_sock);

	g_thread_new("message_thread", (GThreadFunc)_ms_process_tcp_message, GINT_TO_POINTER(client_sock));

	return TRUE;
}
