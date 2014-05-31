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
 * @file		media-server-db-svc.h
 * @author	Yong Yeon Kim(yy9875.kim@samsung.com)
 * @version	1.0
 * @brief
 */
#ifndef _MEDIA_SCANNER_DB_SVC_H_
#define _MEDIA_SCANNER_DB_SVC_H_

#include "media-common-types.h"

typedef int (*CONNECT)(void**, char **);
typedef int (*DISCONNECT)(void*, char **);
typedef int (*CHECK_ITEM_EXIST)(void*, const char*, bool*, char **);
typedef int (*INSERT_ITEM_BEGIN)(void*, int, int, int, char **);
typedef int (*INSERT_ITEM_END)(void*, char **);
typedef int (*INSERT_ITEM)(void*, const char*, int, char **);
typedef int (*INSERT_ITEM_IMMEDIATELY)(void*, const char*, int, char **);
typedef int (*SET_ALL_STORAGE_ITEMS_VALIDITY)(void*, int, int, char **);
typedef int (*SET_ITEM_VALIDITY_BEGIN)(void*, int, char **);
typedef int (*SET_ITEM_VALIDITY_END)(void*, char **);
typedef int (*SET_ITEM_VALIDITY)(void*, const char*, int, int, char **);
typedef int (*DELETE_ALL_ITEMS_IN_STORAGE)(void*, int, char **);
typedef int (*DELETE_ALL_INVALID_ITMES_IN_STORAGE)(void*, int, char **);
typedef int (*UPDATE_BEGIN)(void);
typedef int (*UPDATE_END)(void);
typedef int (*SET_FOLDER_ITEM_VALIDITY)(void*, const char*, int, int, char**);
typedef int (*DELETE_ALL_INVALID_ITEMS_IN_FOLDER)(void*, const char*, char**);
typedef int (*INSERT_BURST_ITEM)(void *, const char *, int , char **);
typedef int (*SEND_DIR_UPDATE_NOTI)(void *, const char *, char **);
typedef int (*COUNT_DELETE_ITEMS_IN_FOLDER)(void *, const char *, int *, char **);
typedef int (*DELETE_ITEM)(void *, const char *, char **);
typedef int (*GET_FOLDER_LIST)(void *, char*, char ***, int **, int **, int *, char **);
typedef int (*UPDATE_FOLDER_TIME)(void *, const char *, char **);

int
msc_load_functions(void);

void
msc_unload_functions(void);

int
msc_connect_db(void ***handle);

int
msc_disconnect_db(void ***handle);

int
msc_validate_item(void **handle, const char *path);

int
msc_insert_item_batch(void **handle, const char *path);

int
msc_insert_burst_item(void **handle, const char *path);

bool
msc_delete_all_items(void **handle, ms_storage_type_t store_type);

int
msc_validaty_change_all_items(void **handle, ms_storage_type_t store_type, bool validity);

bool
msc_delete_invalid_items(void **handle, ms_storage_type_t store_type);

int
msc_set_folder_validity(void **handle, const char *path, int validity, int recursive);

int
msc_delete_invalid_items_in_folder(void **handle, const char*path);

int
msc_send_dir_update_noti(void **handle, const char*path);

int
msc_count_delete_items_in_folder(void **handle, const char*path, int *count);

typedef struct msc_dir_info_s {
	char *dir_path;
	int modified_time;
	int item_num;
} msc_dir_info_s;

int
msc_get_folder_list(void **handle, char* start_path, GArray **dir_array);

int
msc_update_folder_time(void **handle, char *folder_path);

int
msc_insert_item_immediately(void **handle, const char *path);
/****************************************************************************************************
FOR BULK COMMIT
*****************************************************************************************************/
typedef enum {
	MS_NOTI_DISABLE = 0,    /**< Stored only in phone */
	MS_NOTI_ENABLE = 1,	     /**< Stored only in MMC */
} ms_noti_status_e;

void
msc_register_start(void **handle, ms_noti_status_e noti_status, int pid);

void
msc_register_end(void **handle);

void
msc_validate_start(void **handle);

void
msc_validate_end(void **handle);

#endif /*_MEDIA_SCANNER_DB_SVC_H_*/
