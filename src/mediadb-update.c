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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>

#include <glib.h>
#include "media-util.h"

GMainLoop * mainloop = NULL;

int (*svc_connect)				(void ** handle, char ** err_msg);
int (*svc_disconnect)			(void * handle, char ** err_msg);
int (*svc_check_db)			(void * handle, char ** err_msg);
int (*svc_get_storage_id)		(void * handle, const char *path, char *storage_id, char ** err_msg);

void callback(media_request_result_s * result, void *user_data)
{
	printf("db updating done\n");

	g_main_loop_quit(mainloop);
}

void print_help()
{
	printf("=======================================================================================\n");
	printf("\n");
	printf("db-update [option] <directory path> \n");
	printf("\n");
	printf("[option]\n");
	printf("	-r : [only directory] update all directory recursivly under <directory path>\n");
	printf("\n");
	printf("db-update --help for check this messages.\n");
	printf("\n");
	printf("A file or directory must exists under /opt/usr/media or /opt/storage/sdcard.\n");
	printf("Using /opt/storage/sdcard is allowed SD card is mounted.\n");
	printf("\n");
	printf("=======================================================================================\n");
}

static void __check_media_db(void)
{
	void *funcHandle = NULL;
	void *db_handle = NULL;
	char *err_msg = NULL;
	int ret = 0;

	funcHandle = dlopen ("/usr/lib/libmedia-content-plugin.so", RTLD_LAZY);
	if(funcHandle == NULL)
	{
		printf("Error when open plug-in\n");
		return;
	}

	svc_connect			= dlsym (funcHandle, "connect_db");
	svc_disconnect		= dlsym (funcHandle, "disconnect_db");
	svc_check_db 		= dlsym (funcHandle, "check_db");

	ret = svc_connect(&db_handle, &err_msg);
	if(ret < 0)
		printf("Error svc_connect\n");

	ret = svc_check_db(db_handle, &err_msg);
	if(ret < 0)
		printf("Error svc_check_db\n");

	ret = svc_disconnect(db_handle, &err_msg);
	if(ret < 0)
		printf("Error svc_disconnect\n");

	printf("Check media db done\n");

	dlclose (funcHandle);
}

static void __get_storage_id(const char *path, char *storage_id)
{
	void *funcHandle = NULL;
	void *db_handle = NULL;
	char *err_msg = NULL;
	int ret = 0;

	funcHandle = dlopen ("/usr/lib/libmedia-content-plugin.so", RTLD_LAZY);
	if(funcHandle == NULL)
	{
		printf("Error when open plug-in\n");
		return;
	}

	svc_connect			= dlsym (funcHandle, "connect_db");
	svc_disconnect		= dlsym (funcHandle, "disconnect_db");
	svc_get_storage_id 	= dlsym (funcHandle, "get_storage_id");

	ret = svc_connect(&db_handle, &err_msg);
	if(ret < 0)
		printf("Error svc_connect\n");

	ret = svc_get_storage_id(db_handle, path, storage_id, &err_msg);
	if(ret < 0)
		printf("Error svc_get_storage_id\n");

	ret = svc_disconnect(db_handle, &err_msg);
	if(ret < 0)
		printf("Error svc_disconnect\n");

	printf("Start Scanning for [%s][%s]\n", path, storage_id);

	dlclose (funcHandle);
}

int dir_scan_non_recursive(const char *path)
{
	char storage_id[36+1] = {0,};

	__get_storage_id(path, storage_id);

	return media_directory_scanning_async(path, storage_id, FALSE, callback, NULL);
}

int dir_scan_recursive(char *path)
{
	char storage_id[36+1] = {0,};

	__get_storage_id(path, storage_id);

	return media_directory_scanning_async(path, storage_id, TRUE, callback, NULL);
}

typedef enum {
	DIRECTORY_OK,
	FILE_OK,
	NOT_OK,
}check_result;

check_result check_path(char *path)
{
	struct stat buf;
	DIR *dp = NULL;

	/*check the path directory or file*/
	if (stat(path, &buf) == 0) {
		if (S_ISDIR(buf.st_mode)) {
			printf("This is directory\n");
			return DIRECTORY_OK;
		} else {
			dp = opendir(path);
			if (dp == NULL) {
				/*if openning directory is failed, check it exists. */
				if (errno == ENOENT) {
					/* this directory is deleted */
					return DIRECTORY_OK;
				}
			} else {
				closedir(dp);
			}
			print_help();
			return NOT_OK;
		}
	} else {
		printf("stat error");
	}

	return NOT_OK;
}

int main(int argc, char **argv)
{
	int ret;
	char *argv1 = NULL;
	char *argv2 = NULL;

	if (argc > 3 ||argc < 2) {
		print_help();
		exit(1);
	}

	argv1 = strdup(argv[1]);

	mainloop = g_main_loop_new(NULL, FALSE);

	if (argc == 2) {
		if (strcmp(argv1 , "--help") == 0) {
			print_help();
			exit(1);
		}

		if (strcmp(argv1 , "check_db") == 0) {
			__check_media_db();
			exit(1);
		}

		ret = dir_scan_non_recursive(argv1);
		if (ret != 0) {
			printf("error : %d\n", ret);
			exit(1);
		}
	} else if (argc == 3) {
		argv2 = strdup(argv[2]);
		if (strcmp(argv1, "-r") == 0) {
			ret = dir_scan_recursive(argv2);
			if (ret != 0) {
				printf("error : %d\n", ret);
				exit(1);
			}
		} else {
			printf("[%d] invalide option\n", __LINE__);
			print_help();
			exit(1);
		}
	}

	g_main_loop_run(mainloop);

	exit(0);
}