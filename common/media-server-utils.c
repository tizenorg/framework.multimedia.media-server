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

#include <pmapi.h>
#include <vconf.h>
#include <drm-service.h>
#ifdef PROGRESS
#include <quickpanel.h>
#endif
#include <aul/aul.h>
#include <mmf/mm_file.h>

#include "media-server-inotify.h"
#include "media-server-utils.h"

#ifdef FMS_PERF
#include <sys/time.h>
#define MILLION 1000000L
struct timeval g_mmc_start_time;
struct timeval g_mmc_end_time;
#endif

extern GAsyncQueue *scan_queue;

#define CONTENT_TYPE_NUM 4
#define MUSIC_MIME_NUM 28
#define SOUND_MIME_NUM 1
#define MIME_TYPE_LENGTH 255
#define MIME_LENGTH 50
#define _3GP_FILE ".3gp"
#define _MP4_FILE ".mp4"
#define MS_DRM_CONTENT_TYPE_LENGTH 100

int ums_mode = 0;
int current_usb_mode = 0;
extern int mmc_state;

typedef struct {
	char content_type[15];
	int category_by_mime;
} ms_content_table_t;

static const ms_content_table_t content_category[CONTENT_TYPE_NUM] = {
	{"audio", MS_CATEGORY_SOUND},
	{"image", MS_CATEGORY_IMAGE},
	{"video", MS_CATEGORY_VIDEO},
	{"application", MS_CATEGORY_ETC},
};

static const char music_mime_table[MUSIC_MIME_NUM][MIME_LENGTH] = {
	/*known mime types of normal files*/
	"mpeg",
	"ogg",
	"x-ms-wma",
	"x-flac",
	"mp4",
	/* known mime types of drm files*/
	"mp3",
	"x-mp3", /*alias of audio/mpeg*/
	"x-mpeg", /*alias of audio/mpeg*/
	"3gpp",
	"x-ogg", /*alias of  audio/ogg*/
	"vnd.ms-playready.media.pya:*.pya", /*playready*/
	"wma",
	"aac",
	"x-m4a", /*alias of audio/mp4*/
	/* below mimes are rare*/
	"x-vorbis+ogg",
	"x-flac+ogg",
	"x-matroska",
	"ac3",
	"mp2",
	"x-ape",
	"x-ms-asx",
	"vnd.rn-realaudio",

	"x-vorbis", /*alias of audio/x-vorbis+ogg*/
	"vorbis", /*alias of audio/x-vorbis+ogg*/
	"x-oggflac",
	"x-mp2", /*alias of audio/mp2*/
	"x-pn-realaudio", /*alias of audio/vnd.rn-realaudio*/
	"vnd.m-realaudio", /*alias of audio/vnd.rn-realaudio*/
};

static const char sound_mime_table[SOUND_MIME_NUM][MIME_LENGTH] = {
	"x-smaf",
};

static int
_ms_set_power_mode(ms_db_status_type_t status)
{
	int res = MS_ERR_NONE;
	int err;

	switch (status) {
	case MS_DB_UPDATING:
		err = pm_lock_state(LCD_OFF, STAY_CUR_STATE, 0);
		if (err != 0)
			res = MS_ERR_UNKNOWN_ERROR;
		break;
	case MS_DB_UPDATED:
		err = pm_unlock_state(LCD_OFF, STAY_CUR_STATE);
		if (err != 0)
			res = MS_ERR_UNKNOWN_ERROR;
		break;
	default:
		MS_DBG("Unacceptable type : %d", status);
		break;
	}

	return res;
}

int
ms_set_db_status(ms_db_status_type_t status)
{
	int res = MS_ERR_NONE;
	int err = 0;

	if (status == MS_DB_UPDATING) {
		if (ms_config_set_int(VCONFKEY_FILEMANAGER_DB_STATUS, VCONFKEY_FILEMANAGER_DB_UPDATING))
			  res = MS_ERR_VCONF_SET_FAIL;
	} else if (status == MS_DB_UPDATED) {
		if(ms_config_set_int(VCONFKEY_FILEMANAGER_DB_STATUS,  VCONFKEY_FILEMANAGER_DB_UPDATED))
			  res = MS_ERR_VCONF_SET_FAIL;
	}

	err = _ms_set_power_mode(status);
	if (err != MS_ERR_NONE) {
		MS_DBG("_ms_set_power_mode fail");
		res = err;
	}

	return res;
}

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

void
ms_usb_vconf_cb(void *data)
{
	MS_DBG_START();

	int status = 0;

	MS_DBG("Received usb noti from vconf : %d", status);

	if (!ms_config_get_int(VCONFKEY_USB_STORAGE_STATUS, &status)) {
		MS_DBG
		    ("........Get VCONFKEY_USB_STORAGE_STATUS failed........");
	}

	MS_DBG("ms_config_get_int : VCONFKEY_USB_STORAGE_STATUS END = %d",
	       status);
	current_usb_mode = status;

	if (current_usb_mode == VCONFKEY_USB_STORAGE_STATUS_OFF) {
		if (ums_mode != VCONFKEY_USB_STORAGE_STATUS_OFF) {
			ms_scan_data_t *int_scan;

			int_scan = malloc(sizeof(ms_scan_data_t));

			int_scan->db_type = MS_PHONE;
			int_scan->scan_type = MS_SCAN_PART;

			/*push data to fex_dir_scan_cb */
			g_async_queue_push(scan_queue, GINT_TO_POINTER(int_scan));

			if (ms_is_mmc_inserted()) {
				ms_scan_data_t *ext_scan;

				/*prepare to insert drm data and delete previous drm datas */
				if (drm_svc_insert_ext_memory() ==
				    DRM_RESULT_SUCCESS)
					MS_DBG("drm_svc_insert_ext_memory OK");

				ext_scan = malloc(sizeof(ms_scan_data_t));
				mmc_state = VCONFKEY_SYSMAN_MMC_MOUNTED;

				ext_scan->db_type = MS_MMC;
				ext_scan->scan_type = MS_SCAN_PART;

				/*push data to fex_dir_scan_cb */
				g_async_queue_push(scan_queue, GINT_TO_POINTER(ext_scan));
			}
		}
		ums_mode = VCONFKEY_USB_STORAGE_STATUS_OFF;
		ms_config_set_int(MS_USB_MODE_KEY, MS_VCONFKEY_NORMAL_MODE);
	} 
	else {
		if (ums_mode == VCONFKEY_USB_STORAGE_STATUS_OFF) {
			MS_DBG("VCONFKEY_USB_STORAGE_STATUS : %d", current_usb_mode);
			ms_scan_data_t *int_scan;

			ums_mode = current_usb_mode;

			int_scan = malloc(sizeof(ms_scan_data_t));			
			int_scan->scan_type = MS_SCAN_VALID;
			int_scan->db_type = MS_PHONE;

			g_async_queue_push(scan_queue, GINT_TO_POINTER(int_scan));

			ms_inoti_remove_watch_recursive(MS_PHONE_ROOT_PATH);

			if (ums_mode == VCONFKEY_USB_STORAGE_STATUS_UMS_MMC_ON) {

				ms_scan_data_t *ext_scan;

				ext_scan = malloc(sizeof(ms_scan_data_t));
				ext_scan->scan_type = MS_SCAN_VALID;
				ext_scan->db_type = MS_MMC;

				g_async_queue_push(scan_queue, GINT_TO_POINTER(ext_scan));
				
				ms_inoti_remove_watch_recursive(MS_MMC_ROOT_PATH);

				/*notify to drm-server */
				if (drm_svc_extract_ext_memory() == DRM_RESULT_SUCCESS)
					MS_DBG("drm_svc_extract_ext_memory OK");
			}

			/*delete all drm contect from drm server */
			if (drm_svc_unregister_all_contents() == DRM_RESULT_SUCCESS)
				MS_DBG("drm_svc_unregister_all_contents OK");

			ms_config_set_int(MS_USB_MODE_KEY, MS_VCONFKEY_MASS_STORAGE_MODE);
		}
	}

	MS_DBG_END();
	return;
}

bool
ms_is_mmc_inserted(void)
{
	int data = -1;
	ms_config_get_int(VCONFKEY_SYSMAN_MMC_STATUS, &data);
	MS_DBG("%s is  %d ", VCONFKEY_SYSMAN_MMC_STATUS, data);
	if (data != VCONFKEY_SYSMAN_MMC_MOUNTED) {
		MS_DBG("SD Card is inserted");
		return false;
	} else {
		MS_DBG("SD Card is not inserted");
		return true;
	}
}

int
ms_get_full_path_from_node(ms_dir_scan_info * const node, char *ret_path)
{
	int err = 0;
	ms_dir_scan_info *cur_node;
	char path[MS_FILE_PATH_LEN_MAX] = { 0 };
	char tmp_path[MS_FILE_PATH_LEN_MAX] = { 0 };

	cur_node = node;
	MS_DBG("%s", cur_node->name);

	while (1) {
		err = ms_strappend(path, sizeof(path), "/%s%s", cur_node->name, tmp_path);
		if (err < 0) {
			MS_DBG("ms_strappend error : %d", err);
			return err;
		}

		strncpy(tmp_path, path, MS_FILE_PATH_LEN_MAX);

		if (cur_node->parent == NULL)
			break;

		cur_node = cur_node->parent;
		memset(path, 0, MS_FILE_PATH_LEN_MAX);
	}

	strncpy(ret_path, path, MS_FILE_PATH_LEN_MAX);

	return err;
}

ms_store_type_t
ms_get_store_type_by_full(const char *path)
{
	if (strncmp(path + 1, MS_PHONE_ROOT_PATH, strlen(MS_PHONE_ROOT_PATH)) == 0) {
		return MS_PHONE;
	} else
	    if (strncmp(path + 1, MS_MMC_ROOT_PATH, strlen(MS_MMC_ROOT_PATH)) == 0) {
		return MS_MMC;
	} else
		return MS_ERR_INVALID_FILE_PATH;
}

int
ms_strappend(char *res, const int size, const char *pattern,
	     const char *str1, const char *str2)
{
	int len = 0;
	int real_size = size - 1;

	if (!res ||!pattern || !str1 ||!str2 )
		return MS_ERR_ARG_INVALID;

	if (real_size < (strlen(str1) + strlen(str2)))
		return MS_ERR_OUT_OF_RANGE;

	len = snprintf(res, real_size, pattern, str1, str2);
	if (len < 0) {
		MS_DBG("MS_ERR_ARG_INVALID");
		return MS_ERR_ARG_INVALID;
	}

	res[len] = '\0';

	return MS_ERR_NONE;
}

int
ms_strcopy(char *res, const int size, const char *pattern, const char *str1)
{
	int len = 0;
	int real_size = size - 1;

	if (!res || !pattern || !str1)
		return MS_ERR_ARG_INVALID;

	if (real_size < strlen(str1))
		return MS_ERR_OUT_OF_RANGE;

	len = snprintf(res, real_size, pattern, str1);
	if (len < 0) {
		MS_DBG("MS_ERR_ARG_INVALID");
		return MS_ERR_ARG_INVALID;
	}

	res[len] = '\0';

	return MS_ERR_NONE;
}

bool
ms_config_get_int(const char *key, int *value)
{
	int err;

	if (!key || !value) {
		MS_DBG("Arguments key or value is NULL");
		return false;
	}

	err = vconf_get_int(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		MS_DBG("Unexpected error code: %d", err);

	return false;
}

bool
ms_config_set_int(const char *key, int value)
{
	int err;

	if (!key) {
		MS_DBG("Arguments key is NULL");
		return false;
	}

	err = vconf_set_int(key, value);
	if (err == 0)
		return true;
	else if (err == -1)
		return false;
	else
		MS_DBG("Unexpected error code: %d", err);

	return false;
}

bool
ms_config_get_str(const char *key, char *value)
{
	char *res;
	if (!key || !value) {
		MS_DBG("Arguments key or value is NULL");
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
		MS_DBG("Arguments key or value is NULL");
		return false;
	}

	err = vconf_set_str(key, value);
	if (err == 0)
		return true;
	else
		MS_DBG("fail to vconf_set_str %d", err);

	return false;
}

static int
_ms_get_mime_by_drm_info(const char *path, char *mime)
{
	int res;
	drm_content_info_t contentInfo = { 0 };

	if (path == NULL || mime == NULL)
		return MS_ERR_ARG_INVALID;

	res = drm_svc_get_content_info(path, &contentInfo);
	if (res != DRM_RESULT_SUCCESS) {
		MS_DBG("drm_svc_get_content_info() fails. ");
		return MS_ERR_DB_OPERATION_FAIL;
	}

	strncpy(mime, contentInfo.contentType, MS_DRM_CONTENT_TYPE_LENGTH);
	MS_DBG("DRM contentType : %s", contentInfo.contentType);
	MS_DBG("DRM mime : %s", mime);

	return MS_ERR_NONE;
}

int
ms_get_category_from_mime(const char *path, int *category)
{
	int i = 0;
	int err = 0;
	char mimetype[MIME_TYPE_LENGTH];

	if (path == NULL || category == NULL)
		return MS_ERR_ARG_INVALID;

	*category = MS_CATEGORY_UNKNOWN;

	/*get content type and mime type from file. */
	/*in case of drm file. */
	if (drm_svc_is_drm_file(path) == DRM_TRUE) {
		DRM_FILE_TYPE drm_type = DRM_FILE_TYPE_NONE;
		drm_type = drm_svc_get_drm_type(path);
		if (drm_type == DRM_FILE_TYPE_NONE) {
			*category = MS_CATEGORY_UNKNOWN;
			return err;
		} 
		else {
			err =  _ms_get_mime_by_drm_info(path, mimetype);
			if (err < 0) {
				*category = MS_CATEGORY_UNKNOWN;
				return err;
			}
			*category |= MS_CATEGORY_DRM;
		}
	} 
	else {
		/*in case of normal files */
		if (aul_get_mime_from_file(path, mimetype, sizeof(mimetype)) < 0) {
			MS_DBG("aul_get_mime_from_file fail");
			*category = MS_CATEGORY_UNKNOWN;
			return MS_ERR_ARG_INVALID;
		}
	}

	MS_DBG("mime type : %s", mimetype);

	/*categorize from mimetype */
	for (i = 0; i < CONTENT_TYPE_NUM; i++) {
		if (strstr(mimetype, content_category[i].content_type) != NULL) {
			*category = (*category | content_category[i].category_by_mime);
			break;
		}
	}

	/*in application type, exitst sound file ex) x-smafs */
	if (*category & MS_CATEGORY_ETC) {
		int prefix_len = strlen(content_category[0].content_type);

		for (i = 0; i < SOUND_MIME_NUM; i++) {
			if (strstr(mimetype + prefix_len, sound_mime_table[i]) != NULL) {
				*category ^= MS_CATEGORY_ETC;
				*category |= MS_CATEGORY_SOUND;
				break;
			}
		}
	}

	/*check music file in soun files. */
	if (*category & MS_CATEGORY_SOUND) {
		int prefix_len = strlen(content_category[0].content_type) + 1;

		MS_DBG("mime_type : %s", mimetype + prefix_len);

		for (i = 0; i < MUSIC_MIME_NUM; i++) {
			if (strcmp(mimetype + prefix_len, music_mime_table[i]) == 0) {
				*category ^= MS_CATEGORY_SOUND;
				*category |= MS_CATEGORY_MUSIC;
				break;
			}
		}
	} else if (*category & MS_CATEGORY_VIDEO) {
		/*some video files don't have video stream. in this case it is categorize as music. */
		char *ext;
		/*"3gp" and "mp4" must check video stream and then categorize in directly. */
		ext = strrchr(path, '.');
		if (ext != NULL) {
			if ((strncasecmp(ext, _3GP_FILE, 4) == 0) || (strncasecmp(ext, _MP4_FILE, 5) == 0)) {
				int audio = 0;
				int video = 0;

				err = mm_file_get_stream_info(path, &audio, &video);
				if (err == 0) {
					if (audio > 0 && video == 0) {
						*category ^= MS_CATEGORY_VIDEO;
						*category |= MS_CATEGORY_MUSIC;
					}
				}
			}
		}
	}

	MS_DBG("category_from_ext : %d", *category);

	return err;
}

void
ms_check_db_updating(void)
{
	int vconf_value = 0;

	/*wait if phone init is not finished. */
	while (1) {
		ms_config_get_int(VCONFKEY_FILEMANAGER_DB_STATUS, &vconf_value);

		if (vconf_value != VCONFKEY_FILEMANAGER_DB_UPDATED) {
			MS_DBG("iNoti waits till init_phone finishes...");
			sleep(2);
		} else {
			return;
		}
	}
}

#ifdef PROGRESS
void
ms_create_quickpanel(struct quickpanel *ms_quickpanel)
{
	MS_DBG_START();
	int type_id;
	int ret;

	struct quickpanel_type *qp_type;

	ret = quickpanel_get_type_id(NULL,
				   "/opt/apps/com.samsung.myfile/res/icons/default/small/com.samsung.myfile.png",
				   0);
	MS_DBG("return value of quickpanel_get_type_id : %d", ret);

	ms_quickpanel->type = ret;
	ms_quickpanel->priv_id = getpid();
	ms_quickpanel->group_id = 0;
	ms_quickpanel->title = "Media scanning";
	ms_quickpanel->content = NULL;
	ms_quickpanel->progress = 0;
	ms_quickpanel->args = NULL;
	ms_quickpanel->args_group = NULL;
	ms_quickpanel->evt = QP_E_ONGOING;

	ret = quickpanel_insert(ms_quickpanel);
	MS_DBG("return value of quickpanel_insert : %d", ret);

	MS_DBG_END();
}

void
ms_update_progress(struct quickpanel *ms_quickpanel, double progress)
{
	MS_DBG_START();

	MS_DBG("%lf", progress)
	    quickpanel_update_progress(ms_quickpanel->type,
				       ms_quickpanel->priv_id, progress);

	MS_DBG_END();
}

void
ms_delete_quickpanel(struct quickpanel *ms_quickpanel)
{
	MS_DBG_START();
	int ret = 0;

	ret = quickpanel_delete(ms_quickpanel->type, ms_quickpanel->priv_id);
	MS_DBG("return value of quickpanel_delete : %d", ret);

	MS_DBG_END();
}
#endif /*PROGRESS*/
