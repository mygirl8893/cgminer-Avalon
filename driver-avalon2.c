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
#include "crc.h"
#include "hexdump.c"

#define ASSERT1(condition) __maybe_unused static char sizeof_uint32_t_must_be_4[(condition)?1:-1]
ASSERT1(sizeof(uint32_t) == 4);

static int option_offset = -1;

static int avalon2_init_pkg(struct avalon2_pkg *pkg, uint8_t type, uint8_t idx, uint8_t cnt)
{
	unsigned short crc;

	pkg->head[0] = AVA2_H1;
	pkg->head[1] = AVA2_H2;

	pkg->type = type;
	pkg->idx = idx;
	pkg->cnt = cnt;

	crc = crc16(pkg->data, AVA2_P_DATA_LEN);

	pkg->crc[0] = (crc & 0xff00) >> 8;
	pkg->crc[1] = crc & 0x00ff;

	pkg->tail[0] = AVA2_T1;
	pkg->tail[1] = AVA2_T2;

	return 0;
}

static int avalon2_send_pkg(int fd, const struct avalon2_pkg *pkg, struct thr_info *thr)
{
	int ret;
	uint8_t buf[AVA2_WRITE_SIZE];
	size_t nr_len = AVA2_WRITE_SIZE;

	memcpy(buf, pkg, AVA2_WRITE_SIZE);
	if (opt_debug) {
		applog(LOG_DEBUG, "Avalon2: Sent(%d):", nr_len);
		hexdump((uint8_t *)buf, nr_len);
	}

	if (thr && thr->work_restart)
		return AVA2_SEND_RESTART;

	ret = write(fd, buf, nr_len);
	if (unlikely(ret != nr_len))
		return AVA2_SEND_ERROR;

	cgsleep_ms(40);		/* Wait the MM read all data */
	return AVA2_SEND_OK;
}

static void avalon2_stratum_pkgs(int fd, struct pool *pool, struct thr_info *thr)
{
	/* FIXME: what if new stratum arrive when writing */
	struct avalon2_pkg pkg;
	int i, a, b, tmp;

	/* Send out the first stratum message STATIC */
	applog(LOG_DEBUG, "Avalon2: Pool stratum message STATIC: %d, %d, %d, %d, %d",
	       pool->swork.cb_len,
	       pool->nonce2_offset,
	       pool->n2size,
	       pool->merkle_offset,
	       pool->swork.merkles);
	memset(pkg.data, 0, AVA2_P_DATA_LEN);
	tmp = bswap_32(pool->swork.cb_len);
	memcpy(pkg.data, &tmp, 4);

	tmp = bswap_32(pool->nonce2_offset);
	memcpy(pkg.data + 4, &tmp, 4);

	tmp = bswap_32(pool->n2size);
	memcpy(pkg.data + 8, &tmp, 4);

	tmp = bswap_32(pool->merkle_offset);
	memcpy(pkg.data + 12, &tmp, 4);

	tmp = bswap_32(pool->swork.merkles);
	memcpy(pkg.data + 16, &tmp, 4);

	avalon2_init_pkg(&pkg, AVA2_P_STATIC, 1, 1);
	if (avalon2_send_pkg(fd, &pkg, thr) == AVA2_SEND_RESTART)
		return AVA2_SEND_RESTART;


	applog(LOG_DEBUG, "Avalon2: Pool stratum message JOBS_ID: %s",
	       pool->swork.job_id);
	memset(pkg.data, 0, AVA2_P_DATA_LEN);
	strcpy(pkg.data, pool->swork.job_id);
	avalon2_init_pkg(&pkg, AVA2_P_JOB_ID, 1, 1);
	if (avalon2_send_pkg(fd, &pkg, thr) == AVA2_SEND_RESTART)
		return AVA2_SEND_RESTART;


	a = pool->swork.cb_len / AVA2_P_DATA_LEN;
	b = pool->swork.cb_len % AVA2_P_DATA_LEN;
	applog(LOG_DEBUG, "Avalon2: Pool stratum message COINBASE: %d %d", a, b);
	for (i = 0; i < a; i++) {
		memcpy(pkg.data, pool->coinbase + i * 32, 32);
		avalon2_init_pkg(&pkg, AVA2_P_COINBASE, i + 1, a + (b ? 1 : 0));
		if (avalon2_send_pkg(fd, &pkg, thr) == AVA2_SEND_RESTART)
			return AVA2_SEND_RESTART;
	}
	if (b) {
		memset(pkg.data, 0, AVA2_P_DATA_LEN);
		memcpy(pkg.data, pool->coinbase + i * 32, b);
		avalon2_init_pkg(&pkg, AVA2_P_COINBASE, i + 1, i + 1);
		if (avalon2_send_pkg(fd, &pkg, thr) == AVA2_SEND_RESTART)
			return AVA2_SEND_RESTART;
	}
	cgsleep_ms(2000);	/* Only for debug */


	b = pool->swork.merkles;
	applog(LOG_DEBUG, "Avalon2: Pool stratum message MERKLES: %d", b);
	for (i = 0; i < b; i++) {
		memset(pkg.data, 0, AVA2_P_DATA_LEN);
		memcpy(pkg.data, pool->swork.merkle_bin[i], 32);
		avalon2_init_pkg(&pkg, AVA2_P_MERKLES, i + 1, b);
		if (avalon2_send_pkg(fd, &pkg, thr) == AVA2_SEND_RESTART)
			return AVA2_SEND_RESTART;
	}

	applog(LOG_DEBUG, "Avalon2: Pool stratum message HEADER: 4");
	for (i = 0; i < 4; i++) {
		memset(pkg.data, 0, AVA2_P_HEADER);
		memcpy(pkg.data, pool->header_bin + i * 32, 32);
		avalon2_init_pkg(&pkg, AVA2_P_HEADER, i + 1, 4);
		if (avalon2_send_pkg(fd, &pkg, thr) == AVA2_SEND_RESTART)
			return AVA2_SEND_RESTART;
	}
}

static inline int avalon2_gets(int fd, uint8_t *buf)
{
	int read_amount = AVA2_READ_SIZE;
	ssize_t ret = 0;

	while (true) {
		struct timeval timeout;
		fd_set rd;

		timeout.tv_sec = 0;
		timeout.tv_usec = 100000;

		FD_ZERO(&rd);
		FD_SET(fd, &rd);
		ret = select(fd + 1, &rd, NULL, NULL, &timeout);
		if (unlikely(ret < 0)) {
			applog(LOG_ERR, "Avalon2: Error %d on select in avalon_gets", errno);
			return AVA2_GETS_ERROR;
		}
		if (ret) {
			ret = read(fd, buf, read_amount);
			if (unlikely(ret < 0)) {
				applog(LOG_ERR, "Avalon2: Error %d on read in avalon_gets", errno);
				return AVA2_GETS_ERROR;
			}
			if (likely(ret >= read_amount))
				return AVA2_GETS_OK;
			buf += ret;
			read_amount -= ret;
			continue;
		}

		return AVA2_GETS_TIMEOUT;
	}
}

static int decode_pkg(struct avalon2_ret *ar, uint8_t *pkg)
{
	int i;
	unsigned int expected_crc;
	unsigned int actual_crc;

	int type = AVA2_P_ERROR;
	memcpy((uint8_t *)ar, pkg, AVA2_READ_SIZE);

	if (ar->head[0] == AVA2_H1 &&
	    ar->head[1] == AVA2_H2 &&
	    ar->tail[0] == AVA2_T1 &&
	    ar->tail[1] == AVA2_T2) {

		expected_crc = crc16(ar->data, AVA2_P_DATA_LEN);
		actual_crc = (ar->crc[0] & 0xff) |
			((ar->crc[1] & 0xff) << 8);

		applog(LOG_DEBUG, "Avalon2: expected crc(%04x), actural_crc(%04x)", expected_crc, actual_crc);
		if (expected_crc != actual_crc)
			goto out;

		type = ar->type;
		/* TODO: decode type here */
	}

out:
	return type;
}

static int avalon2_get_result(int fd, struct avalon2_ret *ar)
{
	uint8_t result[AVA2_READ_SIZE];
	int ret;

	memset(result, 0, AVA2_READ_SIZE);

	ret = avalon2_gets(fd, result);
	if (ret != AVA2_GETS_OK)
		return AVA2_P_ERROR;

	if (opt_debug) {
		applog(LOG_DEBUG, "Avalon2: get(ret = %d):", ret);
		hexdump((uint8_t *)result, AVA2_READ_SIZE);
	}

	return decode_pkg(ar, result);
}

static bool avalon2_detect_one(const char *devpath)
{
	struct avalon2_info *info;
	int ack, ackdetect;
	int fd, ret;
	int baud, miner_count, asic_count, frequency;

	struct cgpu_info *avalon2;
	struct avalon2_pkg detect_pkg;
	struct avalon2_ret ret_pkg;

	applog(LOG_DEBUG, "Avalon2 Detect: Attempting to open %s", devpath);

	fd = avalon2_open(devpath, AVA2_IO_SPEED, true);
	if (unlikely(fd == -1)) {
		applog(LOG_ERR, "Avalon2 Detect: Failed to open %s", devpath);
		return false;
	}
	/* Send out detect pkg */
	avalon2_init_pkg(&detect_pkg, AVA2_P_DETECT, 1, 1);
	avalon2_send_pkg(fd, &detect_pkg, NULL);
	ack = avalon2_get_result(fd, &ret_pkg);
	ackdetect = avalon2_get_result(fd, &ret_pkg);
	applog(LOG_DEBUG, "Avalon2 Detect: %d %d", ack, ackdetect);
	if (ack != AVA2_P_ACK || ackdetect != AVA2_P_ACKDETECT)
		return false;

	/* We have a real Avalon! */
	avalon2 = calloc(1, sizeof(struct cgpu_info));
	avalon2->drv = &avalon2_drv;
	avalon2->device_path = strdup(devpath);
	avalon2->threads = AVA2_MINER_THREADS;
	add_cgpu(avalon2);

	applog(LOG_INFO, "Avalon2 Detect: Found at %s, mark as %d",
	       devpath, avalon2->device_id);

	avalon2->device_data = calloc(sizeof(struct avalon2_info), 1);
	if (unlikely(!(avalon2->device_data)))
		quit(1, "Failed to malloc avalon2_info");

	info = avalon2->device_data;

	info->baud = baud;
	info->miner_count = miner_count;
	info->asic_count = asic_count;
	info->frequency = frequency;
	info->fan_pwm = AVA2_DEFAULT_FAN_PWM;

	info->temp_max = 0;
	info->temp_history_index = 0;
	info->temp_sum = 0;
	info->temp_old = 0;

	info->fd = -1;
	/* Set asic to idle mode after detect */
	avalon2_close(fd);

	return true;
}

static inline void avalon2_detect()
{
	serial_detect(&avalon2_drv, avalon2_detect_one);
}

static void avalon2_init(struct cgpu_info *avalon2)
{
	int fd, ret;
	struct avalon2_info *info = avalon2->device_data;

	fd = avalon2_open(avalon2->device_path, info->baud, true);
	if (unlikely(fd == -1)) {
		applog(LOG_ERR, "Avalon2: Failed to open on %s", avalon2->device_path);
		return;
	}
	applog(LOG_DEBUG, "Avalon2: Opened on %s", avalon2->device_path);

	info->fd = fd;
}

static bool avalon2_prepare(struct thr_info *thr)
{
	struct cgpu_info *avalon2 = thr->cgpu;
	struct avalon2_info *info = avalon2->device_data;

	free(avalon2->works);
	avalon2->works = calloc(sizeof(struct work *), 2);
	if (!avalon2->works)
		quit(1, "Failed to calloc avalon2 works in avalon2_prepare");

	if (info->fd == -1)
		avalon2_init(avalon2);

	info->first = true;

	return true;
}

/* We use a replacement algorithm to only remove references to work done from
 * the buffer when we need the extra space for new work. */
static bool avalon2_fill(struct cgpu_info *avalon2)
{
	struct avalon2_info *info = avalon2->device_data;
	int slot;
	struct work *work;
	bool ret = true;

	if (avalon2->queued >= AVALON2_QUEUED_COUNT)
		goto out_unlock;
	work = get_queued(avalon2);
	if (unlikely(!work)) {
		ret = false;
		goto out_unlock;
	}
	slot = avalon2->queued++;
	work->subid = slot;
	avalon2->works[slot] = work;

	if (avalon2->queued < AVALON2_QUEUED_COUNT)
		ret = false;

out_unlock:

	return ret;
}

static int64_t avalon2_scanhash(struct thr_info *thr)
{
	unsigned char merkle_root[32], merkle_sha[64];
	uint32_t *data32, *swap32;
	int i;

	struct work *work;
	struct pool *pool;

	struct cgpu_info *avalon2 = thr->cgpu;
	struct avalon2_info *info = avalon2->device_data;

	if (thr->work_restart || info->first) {
		if (unlikely(info->first))
			info->first = false;

		do {
			cgsleep_ms(40);
		} while (avalon2->queued < AVALON2_QUEUED_COUNT);

		work = avalon2->works[AVALON2_QUEUED_COUNT - 1];
		pool = work->pool;
		if (!pool->has_stratum)
			quit(1, "Avalon2: Miner Manager have to use stratum pool");

		avalon2_stratum_pkgs(info->fd, pool, thr);
	}
	quit(1, "Avalon2: STOP");

	return 0xff;
}

static struct api_data *avalon2_api_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;

	return root;
}

static void avalon2_shutdown(struct thr_info *thr)
{
	struct cgpu_info *avalon = thr->cgpu;
	struct avalon_info *info = avalon->device_data;

	free(avalon->works);
	avalon->works = NULL;
}

struct device_drv avalon2_drv = {
	.drv_id = DRIVER_avalon2,
	.dname = "avalon2",
	.name = "AV2",
	.get_api_stats = avalon2_api_stats,
	.drv_detect = avalon2_detect,
	.reinit_device = avalon2_init,
	.thread_prepare = avalon2_prepare,
	.hash_work = hash_queued_work,
	.queue_full = avalon2_fill,
	.scanwork = avalon2_scanhash,
	.thread_shutdown = avalon2_shutdown,
};
