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
#include <glib.h>
#include <sys/smack.h>
#include <security-server.h>

#include "media-util-err.h"

#include "media-common-dbg.h"
#include "media-common-types.h"
#include "media-common-security.h"

#define MEDIA_DB_SMACK_LABEL "media-data::db"
#define MEDIA_DB_SMACK_ACCESS_TYPE "w"

int ms_privilege_ask(int client_sockfd)
{
	int ret = 0;
	int res = MS_MEDIA_ERR_NONE;

	ret = security_server_check_privilege_by_sockfd(client_sockfd, MEDIA_DB_SMACK_LABEL, MEDIA_DB_SMACK_ACCESS_TYPE);
	if (ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
		MS_DBG_ERR("You do not have permission for this operation.");
		res = MS_MEDIA_ERR_PERMISSION_DENIED;
	} else {
		MS_DBG("PERMISSION OK");
	}

	return res;
}

int ms_get_file_smack_label(const char *path, char **label)
{
	int ret = 0;
	int res = MS_MEDIA_ERR_NONE;
	enum smack_label_type type = SMACK_LABEL_ACCESS;

	ret = smack_getlabel(path, label, type);
	if (ret == -1) {
		MS_DBG_ERR("Fail to get the label");
		res = MS_MEDIA_ERR_INTERNAL;
	}

	return res;
}

int ms_get_client_smack_label(int client_sockfd, char **label)
{
	int ret = 0;
	int res = MS_MEDIA_ERR_NONE;

	ret = smack_new_label_from_socket(client_sockfd, label);
	if (ret <= 0) {
		MS_DBG_ERR("Fail to get the client label");
		res = MS_MEDIA_ERR_INTERNAL;
	}

	return res;
}

int ms_check_smack_rule(const char *subject, const char *object, const char *access_type)
{
	int ret = 0;
	int res = MS_MEDIA_ERR_NONE;

	ret = smack_have_access(subject, object, access_type);
	if (ret != 1) {
		if (ret == -1) {
			MS_DBG_ERR("Fail to check the smack rule");
			res = MS_MEDIA_ERR_INTERNAL;
		} else {
			MS_DBG_ERR("Do not have permission");
			res = MS_MEDIA_ERR_PERMISSION_DENIED;
		}
	}

	return res;
}

int ms_check_smack_by_pid(int pid, const char *object, const char *access_type)
{
	int ret = 0;
	int res = MS_MEDIA_ERR_NONE;

	ret = security_server_check_privilege_by_pid(pid, object, access_type);
	if (ret != SECURITY_SERVER_API_SUCCESS) {
		if (ret == SECURITY_SERVER_API_ERROR_ACCESS_DENIED) {
			MS_DBG_ERR("Do not have permission");
			res = MS_MEDIA_ERR_PERMISSION_DENIED;
		} else {
			MS_DBG_ERR("Fail to check the smack rule[%d]", ret);
			res = MS_MEDIA_ERR_INTERNAL;
		}
	}

	return res;
}

int ms_check_client_permission_by_fd(int client_sockfd, const char *file_path)
{
	int ret = MS_MEDIA_ERR_NONE;
	char *dir_path = NULL;
	char *subject_label = NULL;
	char *file_object_label = NULL;
	char *dir_object_label = NULL;
	const char *dir_access = "x";
	const char *file_access = "r";

	dir_path = (char*)g_path_get_dirname(file_path);

	ret = ms_get_client_smack_label(client_sockfd, &subject_label);
	if (ret != MS_MEDIA_ERR_NONE) {
		goto ERROR;
	}

	ret = ms_get_file_smack_label(file_path, &file_object_label);
	if (ret != MS_MEDIA_ERR_NONE) {
		goto ERROR;
	}

	ret = ms_get_file_smack_label(dir_path, &dir_object_label);
	if (ret != MS_MEDIA_ERR_NONE) {
		goto ERROR;
	}

	ret = ms_check_smack_rule(subject_label, dir_object_label, dir_access);
	if (ret != MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("Err[%d] Subject[%s] Object[%s] Path[%s]", ret, subject_label, dir_object_label, dir_path);
		goto ERROR;
	}

	ret = ms_check_smack_rule(subject_label, file_object_label, file_access);
	if (ret != MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("Err[%d] Subject[%s] Object[%s] Path[%s]", ret, subject_label, file_object_label, file_path);
		goto ERROR;
	}

ERROR:

	MS_SAFE_FREE(dir_path);
	MS_SAFE_FREE(subject_label);
	MS_SAFE_FREE(file_object_label);
	MS_SAFE_FREE(dir_object_label);

	return ret;
}

int ms_check_client_permission_by_pid(int pid, const char *file_path)
{
	int ret = MS_MEDIA_ERR_NONE;
	char *dir_path = NULL;
	char *subject_label = NULL;
	char *file_object_label = NULL;
	char *dir_object_label = NULL;
	const char *dir_access = "x";
	const char *file_access = "r";

	dir_path = (char*)g_path_get_dirname(file_path);

	ret = ms_get_file_smack_label(file_path, &file_object_label);
	if (ret != MS_MEDIA_ERR_NONE) {
		goto ERROR;
	}

	ret = ms_get_file_smack_label(dir_path, &dir_object_label);
	if (ret != MS_MEDIA_ERR_NONE) {
		goto ERROR;
	}

	ret = ms_check_smack_by_pid(pid, dir_object_label, dir_access);
	if (ret != MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("Err[%d] PID[%d] Object[%s] Path[%s]", ret, pid, dir_object_label, dir_path);
		goto ERROR;
	}

	ret = ms_check_smack_by_pid(pid, file_object_label, file_access);
	if (ret != MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("Err[%d] PID[%d] Object[%s] Path[%s]", ret, pid, file_object_label, file_path);
		goto ERROR;
	}

ERROR:

	MS_SAFE_FREE(dir_path);
	MS_SAFE_FREE(subject_label);
	MS_SAFE_FREE(file_object_label);
	MS_SAFE_FREE(dir_object_label);

	return ret;
}

