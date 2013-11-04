/*
 * Copyright 2013 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2013 Xiangfu <xiangfu@openmobilefree.com>
 * Copyright 2012 Luke Dashjr
 * Copyright 2012 Andrew Smith
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#include "config.h"

#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <dirent.h>
#include <unistd.h>
#ifndef WIN32
  #include <termios.h>
  #include <sys/stat.h>
  #include <fcntl.h>
  #ifndef O_CLOEXEC
    #define O_CLOEXEC 0
  #endif
#else
  #include <windows.h>
  #include <io.h>
#endif

#include "elist.h"
#include "miner.h"
#include "fpgautils.h"
#include "driver-avalon2.h"
#include "hexdump.c"

#define ASSERT1(condition) __maybe_unused static char sizeof_uint32_t_must_be_4[(condition)?1:-1]
ASSERT1(sizeof(uint32_t) == 4);

static int option_offset = -1;
struct avalon2_info **avalon2_infos;
struct device_drv avalon2_drv;

static int avalon2_init_task(struct avalon2_pkg *pkg, uint8_t type)
{
	int i;

	pkg->head[0] = AVA2_H1;
	pkg->head[1] = AVA2_H2;
	pkg->tail[0] = AVA2_T1;
	pkg->tail[1] = AVA2_T2;

	pkg->type = type;
	pkg->idx = 1;
	pkg->cnt = 1;

	for (i = 0; i < 32; i++)
		pkg->data[i] = 0;

	pkg->crc[0] = 0;
	pkg->crc[1] = 0;

	return 0;
}

static inline void avalon2_create_task(struct avalon2_task *at,
				      struct work *work)
{
}

static int avalon2_send_task(int fd, const struct avalon2_task *at,
			    struct cgpu_info *avalon)

{
}

static inline int avalon2_gets(int fd, uint8_t *buf, struct thr_info *thr,
		       struct timeval *tv_finish)
{
}

static int avalon2_get_result(int fd, struct avalon2_result *ar,
			     struct thr_info *thr, struct timeval *tv_finish)
{
}

static bool avalon2_decode_nonce(struct thr_info *thr, struct avalon2_result *ar,
				uint32_t *nonce)
{
}

static void avalon2_get_reset(int fd, struct avalon2_result *ar)
{
}

static int avalon2_reset(int fd, struct avalon2_result *ar)
{
}

static void avalon2_idle(struct cgpu_info *avalon)
{
}

static void get_options(int this_option_offset, int *baud, int *miner_count,
			int *asic_count, int *timeout, int *frequency)
{
}

static bool avalon2_detect_one(const char *devpath)
{
	struct avalon2_info *info;
	int fd, ret;
	int baud, miner_count, asic_count, timeout, frequency;

	struct cgpu_info *avalon2;

	applog(LOG_DEBUG, "Avalon2 Detect: Attempting to open %s", devpath);

	fd = avalon2_open(devpath, AVA2_IO_SPEED, true);
	if (unlikely(fd == -1)) {
		applog(LOG_ERR, "Avalon2 Detect: Failed to open %s", devpath);
		return false;
	}
	/* Send out detect pkg */

	/* We have a real Avalon! */
	avalon2 = calloc(1, sizeof(struct cgpu_info));
	avalon2->drv = &avalon2_drv;
	avalon2->device_path = strdup(devpath);
	avalon2->device_id = fd;
	avalon2->threads = AVA2_MINER_THREADS;
	add_cgpu(avalon2);


	avalon2_infos = realloc(avalon2_infos,
			       sizeof(struct avalon2_info *) *
			       (total_devices + 1));
	applog(LOG_INFO, "Avalon2 Detect: Found at %s, mark as %d",
	       devpath, avalon2->device_id);

	avalon2_infos[avalon2->device_id] = (struct avalon2_info *)
		malloc(sizeof(struct avalon2_info));
	if (unlikely(!(avalon2_infos[avalon2->device_id])))
		quit(1, "Failed to malloc avalon2_infos");
	info = avalon2_infos[avalon2->device_id];
	memset(info, 0, sizeof(struct avalon2_info));
	info->baud = baud;
	info->miner_count = miner_count;
	info->asic_count = asic_count;
	info->timeout = timeout;
	info->fan_pwm = AVA2_DEFAULT_FAN_MIN_PWM;
	info->temp_max = 0;
	info->temp_history_index = 0;
	info->temp_sum = 0;
	info->temp_old = 0;
	info->frequency = frequency;

	/* Set asic to idle mode after detect */
	avalon2->device_id = -1;
	avalon2_close(fd);

	return true;
}

static inline void avalon2_detect()
{
	serial_detect(&avalon2_drv, avalon2_detect_one);
}

static void __avalon2_init(struct cgpu_info *avalon)
{
}

static void avalon2_init(struct cgpu_info *avalon)
{
}

static bool avalon2_prepare(struct thr_info *thr)
{
}

static void avalon2_free_work(struct thr_info *thr)
{
}

static void do_avalon2_close(struct thr_info *thr)
{
}

static inline void record_temp_fan(struct avalon2_info *info, struct avalon2_result *ar, float *temp_avg)
{
}

static inline void adjust_fan(struct avalon2_info *info)
{
}

/* We use a replacement algorithm to only remove references to work done from
 * the buffer when we need the extra space for new work. */
static bool avalon2_fill(struct cgpu_info *avalon)
{
	return false;
}

static void avalon2_rotate_array(struct cgpu_info *avalon)
{
}

static int64_t avalon2_scanhash(struct thr_info *thr)
{
	return 0;
}

static struct api_data *avalon2_api_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;
	struct avalon2_info *info = avalon2_infos[cgpu->device_id];

	return root;
}

static void avalon2_shutdown(struct thr_info *thr)
{
	do_avalon2_close(thr);
}

struct device_drv avalon2_drv = {
	.drv_id = DRIVER_avalon2,
	.dname = "avalon2",
	.name = "AV2",
	.drv_detect = avalon2_detect,
	.thread_prepare = avalon2_prepare,
	.hash_work = hash_queued_work,
	.queue_full = avalon2_fill,
	.scanwork = avalon2_scanhash,
	.get_api_stats = avalon2_api_stats,
	.reinit_device = avalon2_init,
	.thread_shutdown = avalon2_shutdown,
};
