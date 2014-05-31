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
 * @file		media-util-err.h
 * @author	Yong Yeon Kim(yy9875.kim@samsung.com)
 * @version	1.0
 * @brief
 */
#ifndef _MEDIA_UTIL_ERR_H_
#define _MEDIA_UTIL_ERR_H_

#define MS_MEDIA_ERR_NONE 0

/* internal operation error*/
#define MS_MEDIA_ERR_INTERNAL 				-1
#define MS_MEDIA_ERR_INVALID_PARAMETER 			-2   /* invalid parameter(s) */
#define MS_MEDIA_ERR_INVALID_PATH 			-3   /* Invalid path */
#define MS_MEDIA_ERR_ALLOCATE_MEMORY_FAIL	 	-4   /* exception of memory allocation */
#define MS_MEDIA_ERR_NOT_ENOUGH_SPACE 			-5   /* not enough space in storage */

/* DB operation error*/
#define MS_MEDIA_ERR_DB_CONNECT_FAIL 			-11  /* connecting database fails */
#define MS_MEDIA_ERR_DB_DISCONNECT_FAIL 		-12  /* disconnecting database fails */
#define MS_MEDIA_ERR_DB_INSERT_FAIL 			-13  /* inserting record fails */
#define MS_MEDIA_ERR_DB_DELETE_FAIL 			-14  /* deleting record fails */
#define MS_MEDIA_ERR_DB_UPDATE_FAIL 			-15  /* updating record fails */
#define MS_MEDIA_ERR_DB_BUSY_FAIL 			-16  /* DB Busy */
#define MS_MEDIA_ERR_DB_CONSTRAINT_FAIL 		-17  /* DB CONSTRAINT fails - In case of insert, the record already exists */
#define MS_MEDIA_ERR_DB_BATCH_UPDATE_BUSY		-18  /* Batch update thread is full */

/* IPC operation error*/
#define MS_MEDIA_ERR_SOCKET_INTERNAL			-21  /* receive error from socket API */
#define MS_MEDIA_ERR_SOCKET_CONN			-22  /* socket connect error */
#define MS_MEDIA_ERR_SOCKET_BIND			-23  /* socket binding fails */
#define MS_MEDIA_ERR_SOCKET_SEND			-24  /* socket sending fails */
#define MS_MEDIA_ERR_SOCKET_RECEIVE			-25  /* socket receiving fails */
#define MS_MEDIA_ERR_SOCKET_RECEIVE_TIMEOUT		-26  /* socket receive timeout error */
#define MS_MEDIA_ERR_SOCKET_ACCEPT			-27  /* socket accept fails */

#define MS_MEDIA_ERR_DBUS_ADD_FILTER			-31  /* DBUS add filter fails*/
#define MS_MEDIA_ERR_DBUS_GET				-32  /* DBUS get fails */

#define MS_MEDIA_ERR_FIFO_MAKE_FAIL			-41   /* FIFO making fails */

/* DIRECTORY error*/
#define MS_MEDIA_ERR_DIR_OPEN_FAIL 			-51   /* direcotry opennig fails */
#define MS_MEDIA_ERR_DIR_CLOSE_FAIL			-53   /* directory closing fails */
#define MS_MEDIA_ERR_DIR_READ_FAIL 			-52   /* directory reading fails */

/* FILE error*/
#define MS_MEDIA_ERR_FILE_OPEN_FAIL 			-61   /* file opennig fails */
#define MS_MEDIA_ERR_FILE_CLOSE_FAIL 			-62   /* file closing fails */
#define MS_MEDIA_ERR_FILE_READ_FAIL 			-63   /* file reading fails */
#define MS_MEDIA_ERR_FILE_WRITE_FAIL 			-64   /* file writing fails */

/* MEDIA SERVER error*/
#define MS_MEDIA_ERR_DB_SERVER_BUSY_FAIL		-101  /* DB server busy */
#define MS_MEDIA_ERR_SCANNER_FORCE_STOP			-102  /* scanning is stopped forcely */
#define MS_MEDIA_ERR_PERMISSION_DENIED			-103  /* Do have permission of request */

/*ETC*/
#define MS_MEDIA_ERR_VCONF_SET_FAIL			-201  /* vconf setting fails*/
#define MS_MEDIA_ERR_VCONF_GET_FAIL			-202  /* vconf getting fails*/
#define MS_MEDIA_ERR_SCANNER_NOT_READY			-203  /* scanner is not ready */
#define MS_MEDIA_ERR_DYNAMIC_LINK			-204  /* fail to dynamic link */
#define MS_MEDIA_ERR_INVALID_IPC_MESSAGE		-205  /* received message is not valid */
#define MS_MEDIA_ERR_DATA_TAINTED			-206  /* received data is tainted */
#define MS_MEDIA_ERR_SEND_NOTI_FAIL			-207  /* sending notification is failed */

#define MS_MEDIA_ERR_MAX				-999

#endif /*_MEDIA_UTIL_ERR_H_*/
