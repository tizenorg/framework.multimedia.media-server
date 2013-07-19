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
 * @file		media-server-main.c
 * @author	Yong Yeon Kim(yy9875.kim@samsung.com)
 * @version	1.0
 * @brief
 */

#include <sys/wait.h>
#include <sys/types.h>
#include <dirent.h>
#include <errno.h>
#include <malloc.h>
#include <vconf.h>
#include <heynoti.h>

#include "media-util.h"
#include "media-common-utils.h"
#include "media-common-external-storage.h"
#include "media-server-dbg.h"
#include "media-server-db-svc.h"
#include "media-server-socket.h"
#include "media-server-db.h"
#include "media-server-thumb.h"
#include "media-server-scanner.h"

#define APP_NAME "media-server"

extern GMutex *scanner_mutex;

GMainLoop *mainloop = NULL;

bool check_process()
{
	DIR *pdir;
	struct dirent pinfo;
	struct dirent *result = NULL;
	bool ret = false;
	int find_pid = 0;
	pid_t current_pid = 0;

	current_pid = getpid();

	pdir = opendir("/proc");
	if (pdir == NULL) {
		MS_DBG_ERR("err: NO_DIR\n");
		return 0;
	}

	while (!readdir_r(pdir, &pinfo, &result)) {
		if (result == NULL)
			break;

		if (pinfo.d_type != 4 || pinfo.d_name[0] == '.'
		    || pinfo.d_name[0] > 57)
			continue;

		FILE *fp;
		char buff[128];
		char path[128];

		ms_strcopy(path, sizeof(path), "/proc/%s/status", pinfo.d_name);
		fp = fopen(path, "rt");
		if (fp) {
			if (fgets(buff, 128, fp) == NULL)
				MS_DBG_ERR("fgets failed");
			fclose(fp);

			if (strstr(buff, APP_NAME)) {
				find_pid = atoi(pinfo.d_name);
				if (find_pid == current_pid)
					ret = true;
				else {
					ret = false;
					break;
				}
			}
		} else {
			MS_DBG_ERR("Can't read file [%s]", path);
		}
	}

	closedir(pdir);

	return ret;
}

void init_process()
{

}

static void _power_off_cb(void* data)
{
	MS_DBG_ERR("POWER OFF");

	/*Quit Thumbnail Thread*/
	GMainLoop *thumb_mainloop = ms_get_thumb_thread_mainloop();
	if (thumb_mainloop && g_main_is_running(thumb_mainloop)) {
		g_main_loop_quit(thumb_mainloop);
	}

	/*Quit DB Thread*/
	GMainLoop *db_mainloop = ms_db_get_mainloop();
	if(db_mainloop && g_main_loop_is_running(db_mainloop)) {
		g_main_loop_quit(db_mainloop);
	}

	/*Quit Main Thread*/
	if (mainloop && g_main_loop_is_running(mainloop)) {
		g_main_loop_quit(mainloop);
	}

	return;
}

static void _db_clear(void)
{
	int err = MS_MEDIA_ERR_NONE;
	void **handle = NULL;

	/*load functions from plusin(s)*/
	err = ms_load_functions();
	if (err != MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("function load failed");
		exit(0);
	}

	/*connect to media db, if conneting is failed, db updating is stopped*/
	ms_connect_db(&handle);

	/*update just valid type*/
	if (ms_invalidate_all_items(handle, MS_STORAGE_EXTERNAL)  != MS_MEDIA_ERR_NONE)
		MS_DBG_ERR("ms_change_valid_type fail");

	/*disconnect form media db*/
	if (handle) ms_disconnect_db(&handle);

	/*unload functions*/
	ms_unload_functions();
}

void _ms_signal_handler(int n)
{
	int stat, pid, thumb_pid;
	int scanner_pid;

	thumb_pid = ms_thumb_get_server_pid();
	scanner_pid = ms_get_scanner_pid();

	pid = waitpid(-1, &stat, WNOHANG);
	/* check pid of child process of thumbnail thread */

	if (pid == thumb_pid) {
		MS_DBG_ERR("[%d] Thumbnail server is dead", pid);
		ms_thumb_reset_server_status();
	} else if (pid == scanner_pid) {
		MS_DBG_ERR("[%d] Scanner is dead", pid);
		ms_reset_scanner_status();
	} else if (pid == -1) {
		MS_DBG_ERR("%s", strerror(errno));
	}

	if (WIFEXITED(stat)) {
		MS_DBG_ERR("normal termination , exit status : %d", WEXITSTATUS(stat));
	} else if (WIFSIGNALED(stat)) {
		MS_DBG_ERR("abnormal termination , signal number : %d", WTERMSIG(stat));
	} else if (WIFSTOPPED(stat)) {
		MS_DBG_ERR("child process is stoped, signal number : %d", WSTOPSIG(stat));
	}

	return;
}

static void _ms_new_global_variable(void)
{
	/*Init mutex variable*/
	/*media scanner stop/start mutex*/
	if (!scanner_mutex) scanner_mutex = g_mutex_new();
}

static void _ms_free_global_variable(void)
{
	/*Clear mutex variable*/
	if (scanner_mutex) g_mutex_free(scanner_mutex);
}


void
_ms_mmc_vconf_cb(void *data)
{
	int status = 0;

	if (!ms_config_get_int(VCONFKEY_SYSMAN_MMC_STATUS, &status)) {
		MS_DBG_ERR("Get VCONFKEY_SYSMAN_MMC_STATUS failed.");
	}

	MS_DBG_ERR("CURRENT STATUS OF SD CARD[%d]", status);

	/* If scanner is not working, media server executes media scanner and sends request. */
	/* If scanner is working, it detects changing status of SD card. */
	if (status == VCONFKEY_SYSMAN_MMC_REMOVED ||
		status == VCONFKEY_SYSMAN_MMC_INSERTED_NOT_MOUNTED) {

		/*remove added watch descriptors */
		ms_present_mmc_status(MS_SDCARD_REMOVED);

		ms_send_storage_scan_request(MS_STORAGE_EXTERNAL, MS_SCAN_INVALID);
	} else if (status == VCONFKEY_SYSMAN_MMC_MOUNTED) {

		ms_make_default_path_mmc();

		ms_present_mmc_status(MS_SDCARD_INSERTED);

		ms_send_storage_scan_request(MS_STORAGE_EXTERNAL, ms_get_mmc_state());
	}

	return;
}


int main(int argc, char **argv)
{
	GThread *db_thread = NULL;
	GThread *thumb_thread = NULL;
	GSource *source = NULL;
	GIOChannel *channel = NULL;
	GMainContext *context = NULL;
	int sockfd = MS_SOCK_NOT_ALLOCATE;
	int err;
	int heynoti_id;
	bool check_result = false;
	struct sigaction sigset;

	check_result = check_process();
	if (check_result == false)
		exit(0);

	if (!g_thread_supported()) {
		g_thread_init(NULL);
	}

	/*Init main loop*/
	mainloop = g_main_loop_new(NULL, FALSE);

	/*heynoti for power off*/
	if ((heynoti_id = heynoti_init()) <0) {
		MS_DBG_ERR("heynoti_init failed");
	} else {
		err = heynoti_subscribe(heynoti_id, POWEROFF_NOTI_NAME, _power_off_cb, NULL);
		if (err < 0)
			MS_DBG_ERR("heynoti_subscribe failed");

		err = heynoti_attach_handler(heynoti_id);
		if (err < 0)
			MS_DBG_ERR("heynoti_attach_handler failed");
	}

	_ms_new_global_variable();

	/*prepare socket*/
	/* Create and bind new UDP socket */
	if (ms_ipc_create_server_socket(MS_PROTOCOL_TCP, MS_SCANNER_PORT, &sockfd)
		!= MS_MEDIA_ERR_NONE) {
		MS_DBG_ERR("Failed to create socket");
	} else {
		context = g_main_loop_get_context(mainloop);

		/* Create new channel to watch udp socket */
		channel = g_io_channel_unix_new(sockfd);
		source = g_io_create_watch(channel, G_IO_IN);

		/* Set callback to be called when socket is readable */
		g_source_set_callback(source, (GSourceFunc)ms_read_socket, NULL, NULL);
		g_source_attach(source, context);
		g_source_unref(source);
	}

	/*create each threads*/
	db_thread = g_thread_new("db_thread", (GThreadFunc)ms_db_thread, NULL);
	thumb_thread = g_thread_new("thumb_agent_thread", (GThreadFunc)ms_thumb_agent_start_thread, NULL);

	/*set vconf callback function*/
	err = vconf_notify_key_changed(VCONFKEY_SYSMAN_MMC_STATUS, (vconf_callback_fn) _ms_mmc_vconf_cb, NULL);
	if (err == -1)
		MS_DBG_ERR("add call back function for event %s fails", VCONFKEY_SYSMAN_MMC_STATUS);


	/* Add signal handler */
	sigemptyset(&sigset.sa_mask);
	sigaddset(&sigset.sa_mask, SIGCHLD);
	sigset.sa_flags = SA_RESTART;
	sigset.sa_handler = _ms_signal_handler;

	if (sigaction(SIGCHLD, &sigset, NULL) < 0) {
		MS_DBG_ERR("sigaction failed [%s]", strerror(errno));
	} 

	/*clear previous data of sdcard on media database and check db status for updating*/
	while(!ms_db_get_thread_status()) {
		MS_DBG_ERR("wait db thread");
		sleep(1);
	}

	_db_clear();

	ms_send_storage_scan_request(MS_STORAGE_INTERNAL, MS_SCAN_PART);

	if (ms_is_mmc_inserted()) {
		ms_make_default_path_mmc();
		ms_present_mmc_status(MS_SDCARD_INSERTED);

		ms_send_storage_scan_request(MS_STORAGE_EXTERNAL, ms_get_mmc_state());
	}

	/*Active flush */
	malloc_trim(0);

	MS_DBG_ERR("*** Media Server is running ***");

	g_main_loop_run(mainloop);
	g_thread_join(db_thread);
	g_thread_join(thumb_thread);

	/*close an IO channel*/
	g_io_channel_shutdown(channel,  FALSE, NULL);
	g_io_channel_unref(channel);

	heynoti_unsubscribe(heynoti_id, POWEROFF_NOTI_NAME, _power_off_cb);
	heynoti_close(heynoti_id);

	/***********
	**remove call back functions
	************/
	vconf_ignore_key_changed(VCONFKEY_SYSMAN_MMC_STATUS,
				 (vconf_callback_fn) _ms_mmc_vconf_cb);

	_ms_free_global_variable();

	/*close socket*/
	close(sockfd);

	exit(0);
}
