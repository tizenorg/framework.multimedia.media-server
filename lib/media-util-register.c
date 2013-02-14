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
#include <sys/socket.h>
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
	int ret;
	int sockfd = -1;

	sockfd = g_io_channel_unix_get_fd(src);
	if (sockfd < 0) {
		MSAPI_DBG("sock fd is invalid!");
		return TRUE;
	}

	memset(&recv_msg, 0x0, sizeof(ms_comm_msg_s));

	/* Socket is readable */
	ret = ms_ipc_receive_message(sockfd, &recv_msg, sizeof(recv_msg), NULL, NULL);
	if (ret != MS_MEDIA_ERR_NONE) {
		MSAPI_DBG("ms_ipc_receive_message failed");
		return TRUE;
	}

	memset(&req_result, 0x0, sizeof(media_request_result_s));
	req_result.pid = recv_msg.pid;
	req_result.result = recv_msg.result;
	if (recv_msg.msg_type ==MS_MSG_SCANNER_RESULT) {
		req_result.complete_path = strdup(recv_msg.msg);
		req_result.request_type = MEDIA_DIRECTORY_SCAN;
		MSAPI_DBG("complete_path :%d", req_result.complete_path);
	} else if (recv_msg.msg_type == MS_MSG_SCANNER_BULK_RESULT) {
		req_result.complete_path = strdup(recv_msg.msg);
		req_result.request_type = MEDIA_FILES_REGISTER;
	}

	MSAPI_DBG("pid :%d", req_result.pid);
	MSAPI_DBG("result :%d", req_result.result);
	MSAPI_DBG("request_type :%d", req_result.request_type);

	source = ((media_callback_data *)data)->source;
	user_callback = ((media_callback_data *)data)->user_callback;
	user_data = ((media_callback_data *)data)->user_data;

	/*call user define function*/
	user_callback(&req_result, user_data);

	MS_SAFE_FREE(req_result.complete_path);

	/*close an IO channel*/
	g_io_channel_shutdown(src,  FALSE, NULL);
	g_io_channel_unref(src);

	g_source_destroy(source);
	close(sockfd);
	MS_SAFE_FREE(data);

	return TRUE;
}

static int _attach_callback(int *sockfd, scan_complete_cb user_callback, void *user_data)
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

	/* Set callback to be called when socket is readable */
	g_source_set_callback(source, (GSourceFunc)_read_socket, cb_data, NULL);
	g_source_attach(source, context);
	g_source_unref(source);

	return MS_MEDIA_ERR_NONE;
}

static int __media_db_request_update_sync(ms_msg_type_e msg_type, const char *request_msg)
{
	int ret = MS_MEDIA_ERR_NONE;
	int request_msg_size = 0;
	int sockfd = -1;
	int err = -1;
	struct sockaddr_in serv_addr;
	unsigned int serv_addr_len = -1;
	int port = MS_SCANNER_PORT;
	ms_comm_msg_s send_msg;

	if(!MS_STRING_VALID(request_msg))
	{
		MSAPI_DBG_ERR("invalid query");
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

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
	send_msg.msg_size= request_msg_size;
	strncpy(send_msg.msg, request_msg, request_msg_size);

	/*Create Socket*/
	ret = ms_ipc_create_client_socket(MS_PROTOCOL_UDP, MS_TIMEOUT_SEC_10, &sockfd);
	MSAPI_RETV_IF(ret != MS_MEDIA_ERR_NONE, ret);

	ret = ms_ipc_send_msg_to_server(sockfd, port, &send_msg, &serv_addr);
	if (ret != MS_MEDIA_ERR_NONE) {
		MSAPI_DBG_ERR("ms_ipc_send_msg_to_server failed : %d", ret);
		close(sockfd);
		return ret;
	}

	/*Receive Response*/
	ms_comm_msg_s recv_msg;
	serv_addr_len = sizeof(serv_addr);

	memset(&recv_msg, 0x0, sizeof(ms_comm_msg_s));
	err = ms_ipc_wait_message(sockfd, &recv_msg, sizeof(recv_msg), &serv_addr, NULL);
	if (err != MS_MEDIA_ERR_NONE) {
		ret = err;
	} else {
		MSAPI_DBG("RECEIVE OK [%d]", recv_msg.result);
		ret = recv_msg.result;
	}

	close(sockfd);

	return ret;
}


static int __media_db_request_update_async(ms_msg_type_e msg_type, const char *request_msg, scan_complete_cb user_callback, void *user_data)
{
	int ret = MS_MEDIA_ERR_NONE;
	int request_msg_size = 0;
	int sockfd = -1;
	int port = MS_SCANNER_PORT;
	ms_comm_msg_s send_msg;

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
	ret = ms_ipc_create_client_socket(MS_PROTOCOL_UDP, 0, &sockfd);
	MSAPI_RETV_IF(ret != MS_MEDIA_ERR_NONE, ret);

	ret = ms_ipc_send_msg_to_server(sockfd, port, &send_msg, NULL);
	if (ret != MS_MEDIA_ERR_NONE) {
		MSAPI_DBG_ERR("ms_ipc_send_msg_to_server failed : %d", ret);
		close(sockfd);
		return ret;
	}

	ret = _attach_callback(&sockfd, user_callback ,user_data);
	if(ret != MS_MEDIA_ERR_NONE)
		return ret;

	return ret;
}


int media_directory_scanning_async(const char *directory_path, bool recusive_on, scan_complete_cb user_callback, void *user_data)
{
	int ret;

	ret = _check_dir_path(directory_path);
	if(ret != MS_MEDIA_ERR_NONE)
		return ret;

	if (recusive_on == TRUE)
		ret = __media_db_request_update_async(MS_MSG_DIRECTORY_SCANNING, directory_path, user_callback, user_data);
	else
		ret = __media_db_request_update_async(MS_MSG_DIRECTORY_SCANNING_NON_RECURSIVE, directory_path, user_callback, user_data);

	return ret;
}

static int _check_file_path(const char *file_path)
{
	int exist;
	struct stat file_st;

	/* check location of file */
	/* file must exists under "/opt/usr/media" or "/opt/storage/sdcard" */
	if(!_is_valid_path(file_path)) {
		MSAPI_DBG("Invalid path : %s", file_path);
		return MS_MEDIA_ERR_INVALID_PATH;
	}

	/* check the file exits actually */
	exist = open(file_path, O_RDONLY);
	if(exist < 0) {
		MSAPI_DBG("Not exist path : %s", file_path);
		return MS_MEDIA_ERR_INVALID_PATH;
	}
	close(exist);

	/* check type of the path */
	/* It must be a regular file */
	memset(&file_st, 0, sizeof(struct stat));
	if(stat(file_path, &file_st) == 0) {
		if(!S_ISREG(file_st.st_mode)) {
			/* In this case, it is not a regula file */
			MSAPI_DBG("this path is not a file");
			return MS_MEDIA_ERR_INVALID_PATH;
		}
	} else {
		MSAPI_DBG("stat failed [%s]", strerror(errno));
		return MS_MEDIA_ERR_INTERNAL;
	}

	return MS_MEDIA_ERR_NONE;
}

int media_file_register(const char *file_full_path)
{
	int ret;

	ret = _check_file_path(file_full_path);
	if(ret != MS_MEDIA_ERR_NONE)
		return ret;

	ret = __media_db_request_update_sync(MS_MSG_DB_UPDATE, file_full_path);

	MSAPI_DBG("client receive: %d", ret);

	return ret;
}

int media_files_register(const char *list_path, insert_complete_cb user_callback, void *user_data)
{
	int ret;

	ret = __media_db_request_update_async(MS_MSG_BULK_INSERT, list_path, user_callback, user_data);

	MSAPI_DBG("client receive: %d", ret);

	return ret;
}

