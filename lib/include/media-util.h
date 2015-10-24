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

#ifndef _MEDIA_UTIL_H_
#define _MEDIA_UTIL_H_

#include <media-util-err.h>
#include <media-util-register.h>
#include <media-util-db.h>
#include <media-util-noti.h>
#include <media-util-noti-internal.h>
#include <media-util-ipc.h>

#define MOUNT_PATH "/opt/usr"
#define STORAGE_PATH "/opt/storage"

#define MEDIA_ROOT_PATH_INTERNAL	MOUNT_PATH"/media"
#define MEDIA_ROOT_PATH_EXTERNAL	STORAGE_PATH
#define MEDIA_ROOT_PATH_SDCARD	STORAGE_PATH"/sdcard"
#define MEDIA_ROOT_PATH_USB		STORAGE_PATH
#define MEDIA_ROOT_PATH_CLOUD	STORAGE_PATH"/tnfs/cloud"
#define MEDIA_THUMB_ROOT_PATH		MOUNT_PATH"/share/media"
#define MEDIA_DB_NAME				MOUNT_PATH"/dbspace/.media.db"		/**<  media db name*/
#define MEDIA_DATA_PATH			MOUNT_PATH"/apps/media-server/data"

#endif /*_MEDIA_UTIL_H_*/
