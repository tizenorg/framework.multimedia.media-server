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
 * @file		media-server-utils.c
 * @author	Yong Yeon Kim(yy9875.kim@samsung.com)
 * @version	1.0
 * @brief       This file implements main database operation.
 */

#include <errno.h>
#include <vconf.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include "media-util.h"
#include "media-server-ipc.h"
#include "media-common-dbg.h"
#include "media-common-utils.h"

#ifdef FMS_PERF
#include <sys/time.h>
#define MILLION 1000000L
struct timeval g_mmc_start_time;
struct timeval g_mmc_end_time;
#endif

#define MS_DRM_CONTENT_TYPE_LENGTH 100

#ifdef FMS_PERF
void
ms_check_start_time(struct timeval *start_time)
{
	gettimeofday(start_time, NULL);
}

void
ms_check_end_time(struct timeval *end_time)
{
	gettimeofday(end_time, NULL);
}

void
ms_check_time_diff(struct timeval *start_time, struct timeval *end_time)
{
	struct timeval time;
	long difftime;

	time.tv_sec = end_time->tv_sec - start_time->tv_sec;
	time.tv_usec = end_time->tv_usec - start_time->tv_usec;
	difftime = MILLION * time.tv_sec + time.tv_usec;
	MS_DBG("The function_to_time took %ld microseconds or %f seconds.",
	       difftime, difftime / (double)MILLION);
}
#endif

bool
ms_is_mmc_inserted(void)
{
	int data = -1;
	ms_config_get_int(VCONFKEY_SYSMAN_MMC_STATUS, &data);
	if (data != VCONFKEY_SYSMAN_MMC_MOUNTED) {
		return false;
	} else {
		return true;
	}
}

ms_storage_type_t
ms_get_storage_type_by_full(const char *path)
{
	if (strncmp(path, MEDIA_ROOT_PATH_INTERNAL, strlen(MEDIA_ROOT_PATH_INTERNAL)) == 0) {
		return MS_STORAGE_INTERNAL;
	} else if (strncmp(path, MEDIA_ROOT_PATH_SDCARD, strlen(MEDIA_ROOT_PATH_SDCARD)) == 0) {
		return MS_STORAGE_EXTERNAL;
	} else
		return MS_MEDIA_ERR_INVALID_PATH;
}

int
ms_strappend(char *res, const int size, const char *pattern,
	     const char *str1, const char *str2)
{
	int len = 0;
	int real_size = size - 1;

	if (!res ||!pattern || !str1 ||!str2 )
		return MS_MEDIA_ERR_INVALID_PARAMETER;

	if (real_size < (strlen(str1) + strlen(str2)))
		return MS_MEDIA_ERR_INVALID_PARAMETER;

	len = snprintf(res, real_size, pattern, str1, str2);
	if (len < 0) {
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

	res[len] = '\0';

	return MS_MEDIA_ERR_NONE;
}

int
ms_strcopy(char *res, const int size, const char *pattern, const char *str1)
{
	int len = 0;
	int real_size = size;

	if (!res || !pattern || !str1) {
		MS_DBG_ERR("parameta is invalid");
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

	if (real_size < strlen(str1)) {
		MS_DBG_ERR("size is wrong");
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

	len = snprintf(res, real_size, pattern, str1);
	if (len < 0) {
		MS_DBG_ERR("snprintf failed");
		return MS_MEDIA_ERR_INVALID_PARAMETER;
	}

	res[len] = '\0';

	return MS_MEDIA_ERR_NONE;
}

bool
ms_config_get_int(const char *key, int *value)
{
	int err;

	if (!key || !value) {
		MS_DBG_ERR("Arguments key or value is NULL");
		return false;
	}

	err = vconf_get_int(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		MS_DBG_ERR("Unexpected error code: %d", err);

	return false;
}

bool
ms_config_set_int(const char *key, int value)
{
	int err;

	if (!key) {
		MS_DBG_ERR("Arguments key is NULL");
		return false;
	}

	err = vconf_set_int(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		MS_DBG_ERR("Unexpected error code: %d", err);

	return false;
}

bool
ms_config_get_str(const char *key, char *value)
{
	char *res;
	if (!key || !value) {
		MS_DBG_ERR("Arguments key or value is NULL");
		return false;
	}

	res = vconf_get_str(key);
	if (res) {
		strncpy(value, res, strlen(res) + 1);
		return true;
	}

	return false;
}

bool
ms_config_set_str(const char *key, const char *value)
{
	int err;

	if (!key || !value) {
		MS_DBG_ERR("Arguments key or value is NULL");
		return false;
	}

	err = vconf_set_str(key, value);
	if (err == 0)
		return true;
	else
		MS_DBG_ERR("fail to vconf_set_str %d", err);

	return false;
}

bool
ms_config_get_bool(const char *key, int *value)
{
	int err;

	if (!key || !value) {
		MS_DBG_ERR("Arguments key or value is NULL");
		return false;
	}

	err = vconf_get_bool(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		MS_DBG_ERR("Unexpected error code: %d", err);

	return false;
}

#define SYS_DBUS_NAME "ChangeState"
#define SYS_DBUS_PATH "/Org/Tizen/System/DeviceD/PowerOff"
#define SYS_DBUS_INTERFACE "org.tizen.system.deviced.PowerOff"
#define SYS_DBUS_MATCH_RULE "type='signal',interface='org.tizen.system.deviced.PowerOff'"

typedef struct pwoff_callback_data{
	power_off_cb user_callback;
	void *user_data;
} pwoff_callback_data;

DBusHandlerResult
__get_dbus_message(DBusMessage *message, void *user_cb, void *userdata)
{
	MS_DBG("");

	/* A Ping signal on the com.burtonini.dbus.Signal interface */
	if (dbus_message_is_signal (message, SYS_DBUS_INTERFACE, SYS_DBUS_NAME)) {
		int current_type = DBUS_TYPE_INVALID;
		DBusError error;
		DBusMessageIter read_iter;
		DBusBasicValue value;
		power_off_cb cb_func = (power_off_cb)user_cb;

		dbus_error_init (&error);

		/* get data from dbus message */
		dbus_message_iter_init (message, &read_iter);
		while ((current_type = dbus_message_iter_get_arg_type (&read_iter)) != DBUS_TYPE_INVALID){
	                dbus_message_iter_get_basic (&read_iter, &value);
			switch(current_type) {
				case DBUS_TYPE_INT32:
					MS_DBG_WARN("value[%d]", value.i32);
					break;
				default:
					MS_DBG_ERR("current type : %d", current_type);
					break;
			}

			if (value.i32 == 2 || value.i32 == 3) {
				MS_DBG_WARN("PREPARE POWER OFF");
				break;
			}

			dbus_message_iter_next (&read_iter);
		}

		if (value.i32 == 2 || value.i32 == 3)
			cb_func(userdata);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

static DBusHandlerResult
__sysman_message_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	DBusHandlerResult ret;

	pwoff_callback_data *cb_data = (pwoff_callback_data *)user_data;

	MS_DBG("");

	ret = __get_dbus_message(message, cb_data->user_callback, cb_data->user_data);

	MS_DBG("");

	return ret;
}

int ms_add_poweoff_event_receiver(power_off_cb user_callback, void *user_data)
{
	DBusConnection *dbus;
	DBusError error;
	pwoff_callback_data *cb_data = NULL;

	/*add noti receiver for power off*/
	dbus_error_init (&error);

	dbus = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (!dbus) {
		MS_DBG_ERR ("Failed to connect to the D-BUS daemon: %s", error.message);
		return MS_MEDIA_ERR_DBUS_GET;
	}

	dbus_connection_setup_with_g_main (dbus, NULL);

	cb_data = malloc(sizeof(pwoff_callback_data));
	cb_data->user_callback = user_callback;
	cb_data->user_data = user_data;

	/* listening to messages from all objects as no path is specified */
	dbus_bus_add_match (dbus, SYS_DBUS_MATCH_RULE, &error);
	if( !dbus_connection_add_filter (dbus, __sysman_message_filter, cb_data, NULL)) {
		dbus_bus_remove_match (dbus, SYS_DBUS_MATCH_RULE, NULL);
		return MS_MEDIA_ERR_DBUS_ADD_FILTER;
		MS_DBG_ERR("");
	}

	return MS_MEDIA_ERR_NONE;
}