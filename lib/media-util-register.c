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
 * This file defines api utilities of contents manager engines.
 *
 * @file		media-util-register.c
 * @author	Yong Yeon Kim(yy9875.kim@samsung.com)
 * @version	1.0
 * @brief
 */
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <vconf.h>

#include "media-server-ipc.h"
#include "media-util-internal.h"
#include "media-util-dbg.h"
#include "media-util.h"

typedef struct media_callback_data{
	GSource *source;
	scan_complete_cb user_callback;
	void *user_data;
	char *sock_path;
} media_callback_data;

static bool _is_valid_path(const char *path)
{
       if (path == NULL)
               return false;

	if (strncmp(path, MEDIA_ROOT_PATH_INTERNAL, strlen(MEDIA_ROOT_PATH_INTERNAL)) == 0) {
		return true;
	} else if (strncmp(path, MEDIA_ROOT_PATH_SDCARD, strlen(MEDIA_ROOT_PATH_SDCARD)) == 0) {
		return true;
	} else
		return false;

       return true;
}

static int _check_dir_path(const char *dir_path)
{
	struct stat sb;
	DIR *dp = NULL;

	if (!_is_valid_path(dir_path)) {
		MSAPI_DBG("Invalid path : %s", dir_path);
		return MS_MEDIA_ERR_INVALID_PATH;
	}

	if (stat(dir_path, &sb) == -1) {
		MSAPI_DBG("stat failed");
		dp = opendir(dir_path);
		if (dp == NULL) {
			/*if openning directory is failed, check it exists. */
			if (errno == ENOENT) {
				/* this directory is deleted */
				return MS_MEDIA_ERR_NONE;
			}
		} else {
			closedir(dp);
		}
		return MS_MEDIA_ERR_INTERNAL;
	} else {
		if((sb.st_mode & S_IFMT) != S_IFDIR) {
			MSAPI_DBG("Invalid path : %s is not directory", dir_path);
			return MS_MEDIA_ERR_INVALID_PATH;
		}
	}

	return MS_MEDIA_ERR_NONE;
}


/* receive message from media-server[function : ms_receive_message_from_scanner] */
gboolean _read_socket(GIOChannel *src, GIOCondition condition, gpointer data)
{
	GSource *source = NULL;
	scan_complete_cb user_callback;
	void *user_data = NULL;
	ms_comm_msg_s recv_msg;
	media_request_result_s req_result;
	int sockfd = -1;
	char *sock_path = NULL;
	int recv_msg_size = 0;

	sockfd = g_io_channel_unix_get_fd(src);
	if (sockfd < 0) {
		MSAPI_DBG("sock fd is invalid!");
		return TRUE;
	}

	memset(&recv_msg, 0x0, sizeof(ms_comm_msg_s));
	memset(&req_result, 0x0, sizeof(media_request_result_s));

	if ((recv_msg_size = read(sockfd, &recv_msg, sizeof(ms_comm_msg_s))) < 0) {
		MSAPI_DBG_ERR("recv failed : %s", strerror(errno));
		req_result.pid = -1;
		req_result.result = MS_MEDIA_ERR_SOCKET_RECEIVE;
		req_result.complete_path = NULL;
		req_result.request_type = -1;
		goto ERROR;
	}

	req_result.pid = recv_msg.pid;
	req_result.result = recv_msg.result;
	if (recv_msg.msg_type ==MS_MSG_SCANNER_RESULT) {
		req_result.complete_path = strndup(recv_msg.msg, MAX_FILEPATH_LEN);
		req_result.request_type = MEDIA_DIRECTORY_SCAN;
		MSAPI_DBG("complete_path :%d", req_result.complete_path);
	} else if (recv_msg.msg_type == MS_MSG_SCANNER_BULK_RESULT) {
		req_result.complete_path = strndup(recv_msg.msg, MAX_FILEPATH_LEN);
		req_result.request_type = MEDIA_FILES_REGISTER;
	}

	MSAPI_DBG("pid :%d", req_result.pid);
	MSAPI_DBG("result :%d", req_result.result);
	MSAPI_DBG("request_type :%d", req_result.request_type);

ERROR:
	source = ((media_callback_data *)data)->source;
	user_callback = ((media_callback_data *)data)->user_callback;
	user_data = ((media_callback_data *)data)->user_data;
	sock_path = ((media_callback_data *)data)->sock_path;

	/*call user define function*/
	user_callback(&req_result, user_data);

	MS_SAFE_FREE(req_result.complete_path);

	/*close an IO channel*/
	g_io_channel_shutdown(src,  FALSE, NULL);
	g_io_channel_unref(src);

	g_source_destroy(source);
	close(sockfd);
	if (sock_path != NULL) {
		MSAPI_DBG("delete path :%s", sock_path);
		unlink(sock_path);
		MS_SAFE_FREE(sock_path);
	}
	MS_SAFE_FREE(data);

	return TRUE;
}

static int _attach_callback(int *sockfd, char* sock_path, scan_complete_cb user_callback, void *user_data)
{
	GIOChannel *channel = NULL;
	GMainContext *context = NULL;
	GSource *source = NULL;
	media_callback_data *cb_data;

	/*get the global default main context*/
	context = g_main_context_default();

	/* Create new channel to watch udp socket */
	channel = g_io_channel_unix_new(*sockfd);
	source = g_io_create_watch(channel, G_IO_IN);

	cb_data = malloc(sizeof(media_callback_data));
	cb_data->source = source;
	cb_data->user_callback = user_callback;
	cb_data->user_data = user_data;
	cb_data->sock_path = sock_path;

	/* Set callback to be called when socket is readable */
	g_source_set_callback(source, (GSourceFunc)_read_socket, cb_data, NULL);
	g_source_attach(source, context);
	g_source_unref(source);

	return MS_MEDIA_ERR_NONE;
}

static int __media_db_request_update_async(ms_msg_type_e msg_type, const char *request_msg, scan_complete_cb user_callback, void *user_data)
{
	int ret = MS_MEDIA_ERR_NONE;
	int request_msg_size = 0;
	int sockfd = -1;
	int port = MS_SCANNER_PORT;
	ms_comm_msg_s send_msg;
	char *sock_path = NULL;
	ms_sock_info_s sock_info;

	if(!MS_STRING_VALID(request_msg))
	{
		MSAPI_DBG_ERR("invalid query");
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

	MSAPI_DBG("REQUEST DIRECTORY SCANNING");

	request_msg_size = strlen(request_msg);
	if(request_msg_size >= MAX_MSG_SIZE)
	{
		MSAPI_DBG_ERR("Query is Too long. [%d] query size limit is [%d]", request_msg_size, MAX_MSG_SIZE);
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

	MSAPI_DBG("querysize[%d] query[%s]", request_msg_size, request_msg);

	memset((void *)&send_msg, 0, sizeof(ms_comm_msg_s));
	send_msg.msg_type = msg_type;
	send_msg.pid = syscall(__NR_getpid);
	send_msg.msg_size = request_msg_size;
	strncpy(send_msg.msg, request_msg, request_msg_size);

	/*Create Socket*/
	ret = ms_ipc_create_client_socket(MS_PROTOCOL_TCP, 0, &sock_info);
	sockfd = sock_info.sock_fd;
	if (sock_info.sock_path != NULL)
		sock_path = sock_info.sock_path;

	MSAPI_RETV_IF(ret != MS_MEDIA_ERR_NONE, ret);

	ret = ms_ipc_send_msg_to_server_tcp(sockfd, port, &send_msg, NULL);
	if (ret != MS_MEDIA_ERR_NONE) {
		MSAPI_DBG_ERR("ms_ipc_send_msg_to_server failed : %d", ret);
		ms_ipc_delete_client_socket(&sock_info);
		return ret;
	}

	ret = _attach_callback(&sockfd, sock_path, user_callback ,user_data);
	if(ret != MS_MEDIA_ERR_NONE)
		return ret;

	return ret;
}


int media_directory_scanning_async(const char *directory_path, bool recursive_on, scan_complete_cb user_callback, void *user_data)
{
	int ret = MS_MEDIA_ERR_NONE;

	ret = _check_dir_path(directory_path);
	if(ret != MS_MEDIA_ERR_NONE)
		return ret;

	if (recursive_on == TRUE)
		ret = __media_db_request_update_async(MS_MSG_DIRECTORY_SCANNING, directory_path, user_callback, user_data);
	else
		ret = __media_db_request_update_async(MS_MSG_DIRECTORY_SCANNING_NON_RECURSIVE, directory_path, user_callback, user_data);

	return ret;
}

int media_files_register(const char *list_path, insert_complete_cb user_callback, void *user_data)
{
	int ret = MS_MEDIA_ERR_NONE;

	ret = __media_db_request_update_async(MS_MSG_BULK_INSERT, list_path, user_callback, user_data);

	MSAPI_DBG("client receive: %d", ret);

	return ret;
}

int media_burstshot_register(const char *list_path, insert_complete_cb user_callback, void *user_data)
{
	int ret = MS_MEDIA_ERR_NONE;

	ret = __media_db_request_update_async(MS_MSG_BURSTSHOT_INSERT, list_path, user_callback, user_data);

	MSAPI_DBG("client receive: %d", ret);

	return ret;

}

