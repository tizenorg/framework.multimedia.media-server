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
 * @file		media-server-drm.c
 * @author	Yong Yeon Kim(yy9875.kim@samsung.com)
 * @version	1.0
 * @brief       This file implements main database operation.
 */
#include <drm_client_types.h>
#include <drm_client.h>

#include "media-util.h"

#include "media-scanner-dbg.h"
#include "media-server-types.h"
#include "media-scanner-drm.h"

bool
msc_is_drm_file(const char *path)
{
	int ret;
	drm_bool_type_e is_drm_file = DRM_UNKNOWN;

	ret = drm_is_drm_file(path,&is_drm_file);
	if(DRM_RETURN_SUCCESS == ret && DRM_TRUE == is_drm_file)
		return true;

	return false;
}

int
msc_get_mime_in_drm_info(const char *path, char *mime)
{
	int ret;
	drm_content_info_s contentInfo;

	if (path == NULL || mime == NULL)
		return MS_MEDIA_ERR_INVALID_PARAMETER;

	memset(&contentInfo,0x0,sizeof(drm_content_info_s));
	ret = drm_get_content_info(path, &contentInfo);
	if (ret != DRM_RETURN_SUCCESS) {
		MSC_DBG_ERR("drm_svc_get_content_info() failed");
		MSC_DBG_ERR("%s [%d]", path, ret);
		return MS_MEDIA_ERR_DRM_GET_INFO_FAIL;
	}

	strncpy(mime, contentInfo.mime_type, 100);

	return MS_MEDIA_ERR_NONE;
}

int
msc_drm_register(const char* path)
{
	int res = MS_MEDIA_ERR_NONE;
	int ret;

	ret = drm_process_request(DRM_REQUEST_TYPE_REGISTER_FILE, (void *)path, NULL);
	if (ret != DRM_RETURN_SUCCESS) {
		MSC_DBG_ERR("drm_svc_register_file error : %d %s", ret, path);
		res = MS_MEDIA_ERR_DRM_REGISTER_FAIL;
	}

	return res;
}

void
msc_drm_unregister(const char* path)
{
	int ret;

	ret = drm_process_request(DRM_REQUEST_TYPE_UNREGISTER_FILE, (void *)path, NULL);
	if (ret != DRM_RETURN_SUCCESS)
		MSC_DBG_ERR("drm_process_request error : %d", ret);
}

void
msc_drm_unregister_all(void)
{
	if (drm_process_request(DRM_REQUEST_TYPE_UNREGISTER_ALL_FILES , NULL, NULL) == DRM_RETURN_SUCCESS)
		MSC_DBG_INFO("drm_svc_unregister_all_contents OK");
}

bool
msc_drm_insert_ext_memory(void)
{
	if (drm_process_request(DRM_REQUEST_TYPE_INSERT_EXT_MEMORY, NULL, NULL) != DRM_RETURN_SUCCESS)
		return false;

	return true;
}

bool
msc_drm_extract_ext_memory(void)
{
	if (drm_process_request(DRM_REQUEST_TYPE_EXTRACT_EXT_MEMORY , NULL, NULL)  != DRM_RETURN_SUCCESS)
		return false;

	return true;
}

