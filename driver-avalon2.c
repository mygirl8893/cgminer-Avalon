/*
 * Copyright 2013-2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2014 Xiangfu <xiangfu@openmobilefree.com>
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
#include "sha2.h"

#define ASSERT1(condition) __maybe_unused static char sizeof_uint32_t_must_be_4[(condition)?1:-1]
ASSERT1(sizeof(uint32_t) == 4);
int opt_avalon2_overheat = AVALON2_TEMP_OVERHEAT;
int opt_avalon2_polling_delay = AVALON2_DEFAULT_POLLING_DELAY;

enum avalon2_fan_fixed opt_avalon2_fan_fixed = FAN_AUTO;


char *set_avalon2_fan(char *arg)
{
	return NULL;
}

static void rev(unsigned char *s, size_t l)
{
	size_t i, j;
	unsigned char t;

	for (i = 0, j = l - 1; i < j; i++, j--) {
		t = s[i];
		s[i] = s[j];
		s[j] = t;
	}
}

char *set_avalon2_fixed_speed(enum avalon2_fan_fixed *f)
{
       *f = FAN_FIXED;
       return NULL;
}

char *set_avalon2_freq(char *arg)
{
	return NULL;
}

char *set_avalon2_voltage(char *arg)
{
	return NULL;
}

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
	return 0;
}

static int decode_pkg(struct thr_info *thr, struct avalon2_ret *ar, uint8_t *pkg)
{
	unsigned int expected_crc;
	unsigned int actual_crc;
	int type = AVA2_GETS_ERROR;

	memcpy((uint8_t *)ar, pkg, AVA2_READ_SIZE);

	if (ar->head[0] == AVA2_H1 && ar->head[1] == AVA2_H2) {
		expected_crc = crc16(ar->data, AVA2_P_DATA_LEN);
		actual_crc = (ar->crc[0] & 0xff) |
			((ar->crc[1] & 0xff) << 8);

		type = ar->type;
		applog(LOG_DEBUG, "Avalon2: %d: expected crc(%04x), actual_crc(%04x)",
		       type, expected_crc, actual_crc);
		if (expected_crc != actual_crc)
			goto out;

		switch(type) {
		case AVA2_P_NONCE:
			applog(LOG_DEBUG, "Avalon2: AVA2_P_NONCE");
			break;
		case AVA2_P_STATUS:
			applog(LOG_DEBUG, "Avalon2: AVA2_P_STATUS");
			break;
		case AVA2_P_ACKDETECT:
			applog(LOG_DEBUG, "Avalon2: AVA2_P_ACKDETECT");
			break;
		case AVA2_P_ACK:
			applog(LOG_DEBUG, "Avalon2: AVA2_P_ACK");
			break;
		case AVA2_P_NAK:
			applog(LOG_DEBUG, "Avalon2: AVA2_P_NAK");
			break;
		default:
			applog(LOG_DEBUG, "Avalon2: Unknown response");
			type = AVA2_GETS_ERROR;
			break;
		}
	}

out:
	return type;
}

static inline int avalon2_gets(struct cgpu_info *avalon2, uint8_t *buf)
{
	int i;
	int read_amount = AVA2_READ_SIZE;
	uint8_t buf_tmp[AVA2_READ_SIZE];
	uint8_t buf_copy[2 * AVA2_READ_SIZE];
	uint8_t *buf_back = buf;
	int ret = 0;

	while (true) {
		int err;

		do {
			memset(buf, 0, read_amount);
			err = usb_read(avalon2, (char *)buf, read_amount, &ret, C_AVA2_READ);
			if (unlikely(err && err != LIBUSB_ERROR_TIMEOUT)) {
				applog(LOG_ERR, "Avalon2: Error %d on read in avalon_gets got %d", err, ret);
				return AVA2_GETS_ERROR;
			}
			if (likely(ret >= read_amount)) {
				for (i = 1; i < read_amount; i++) {
					if (buf_back[i - 1] == AVA2_H1 && buf_back[i] == AVA2_H2)
						break;
				}
				i -= 1;
				if (i) {
					err = usb_read(avalon2, (char *)buf, read_amount, &ret, C_AVA2_READ);
					if (unlikely(err < 0 || ret != read_amount)) {
						applog(LOG_ERR, "Avalon2: Error %d on 2nd read in avalon_gets got %d", err, ret);
						return AVA2_GETS_ERROR;
					}
					memcpy(buf_copy, buf_back + i, AVA2_READ_SIZE - i);
					memcpy(buf_copy + AVA2_READ_SIZE - i, buf_tmp, i);
					memcpy(buf_back, buf_copy, AVA2_READ_SIZE);
				}
				return AVA2_GETS_OK;
			}
			buf += ret;
			read_amount -= ret;
		} while (ret > 0);

		return AVA2_GETS_TIMEOUT;
	}
}

static int avalon2_send_pkg(struct cgpu_info *avalon2, const struct avalon2_pkg *pkg)
{
	int err, amount;
	uint8_t buf[AVA2_WRITE_SIZE];
	int nr_len = AVA2_WRITE_SIZE;

	if (unlikely(avalon2->usbinfo.nodev))
		return AVA2_SEND_ERROR;

	memcpy(buf, pkg, AVA2_WRITE_SIZE);
	err = usb_write(avalon2, (char *)buf, nr_len, &amount, C_AVA2_WRITE);
	if (err || amount != nr_len) {
		applog(LOG_DEBUG, "Avalon2: Send(%d)!", amount);
		return AVA2_SEND_ERROR;
	}

	return AVA2_SEND_OK;
}

static int avalon2_send_pkgs(struct cgpu_info *avalon2, const struct avalon2_pkg *pkg)
{
	int ret;

	do {
		if (unlikely(avalon2->usbinfo.nodev))
			return -1;
		ret = avalon2_send_pkg(avalon2, pkg);
	} while (ret != AVA2_SEND_OK);

	return 0;
}

static struct cgpu_info *avalon2_detect_one(struct libusb_device *dev, struct usb_find_devices *found)
{
	struct avalon2_info *info;
	int ackdetect;
	int err, amount;
	int i;
	char mm_version[16];

	struct cgpu_info *avalon2 = usb_alloc_cgpu(&avalon2_drv, 1);
	struct avalon2_pkg detect_pkg;
	struct avalon2_ret ret_pkg;

	if (!usb_init(avalon2, dev, found)) {
		applog(LOG_ERR, "Avalon2 failed usb_init");
		avalon2 = usb_free_cgpu(avalon2);
		return NULL;
	}

	for (i = 0; i < 2; i++) {
		strcpy(mm_version, AVA2_MM_VERNULL);
		/* Send out detect pkg */
		memset(detect_pkg.data, 0, AVA2_P_DATA_LEN);

		avalon2_init_pkg(&detect_pkg, AVA2_P_DETECT, 1, 1);
		avalon2_send_pkg(avalon2, &detect_pkg);
		err = usb_read(avalon2, (char *)&ret_pkg, AVA2_READ_SIZE, &amount, C_AVA2_READ);
		if (err < 0 || amount != AVA2_READ_SIZE) {
			applog(LOG_DEBUG, "%s %d: Avalon2 failed usb_read with err %d amount %d",
			       avalon2->drv->name, avalon2->device_id, err, amount);
			continue;
		}

		ackdetect = ret_pkg.type;
		if (ackdetect != AVA2_P_ACKDETECT)
			continue;
		applog(LOG_DEBUG, "Avalon2 Detect Ver: %s", ret_pkg.data);
		memcpy(mm_version, ret_pkg.data, 15);
		mm_version[15] = '\0';
	}

	if (strncmp(mm_version, "3U", 2)) {
		applog(LOG_DEBUG, "Not an Avalon2 device");
		usb_uninit(avalon2);
		usb_free_cgpu(avalon2);
		return NULL;
	}

	/* We have a real Avalon! */
	avalon2->threads = AVA2_MINER_THREADS;
	add_cgpu(avalon2);

	update_usb_stats(avalon2);

	applog(LOG_INFO, "%s%d: Found at %s", avalon2->drv->name, avalon2->device_id,
	       avalon2->device_path);

	avalon2->device_data = calloc(sizeof(struct avalon2_info), 1);
	if (unlikely(!(avalon2->device_data)))
		quit(1, "Failed to calloc avalon2_info");

	info = avalon2->device_data;

	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		strcpy(info->mm_version[i], mm_version);
		info->modulars[i] = 1;	/* Enable modular */
		info->enable[i] = 1;
		info->dev_type[i] = AVA2_ID_AVAX;

		if (!strncmp((char *)&(info->mm_version[i]), AVA2_FW2_PREFIXSTR, 2)) {
			info->dev_type[i] = AVA2_ID_AVA2;
			info->set_voltage = AVA2_DEFAULT_VOLTAGE_MIN;
			info->set_frequency = AVA2_DEFAULT_FREQUENCY;
		}
		if (!strncmp((char *)&(info->mm_version[i]), AVA2_FW3_PREFIXSTR, 2)) {
			info->dev_type[i] = AVA2_ID_AVA3;
			info->set_voltage = AVA2_AVA3_VOLTAGE;
			info->set_frequency = AVA2_AVA3_FREQUENCY;
		}
	}

	return avalon2;
}

static inline void avalon2_detect(bool __maybe_unused hotplug)
{
	usb_detect(&avalon2_drv, avalon2_detect_one);
}

static void avalon2_update(struct cgpu_info *avalon2)
{
    struct avalon2_info *info = avalon2->device_data;

    cgtime(&info->last_stratum);
}

static int64_t avalon2_scanhash(struct thr_info *thr)
{
	struct timeval current_stratum;
	struct cgpu_info *avalon2 = thr->cgpu;
	struct avalon2_info *info = avalon2->device_data;
	struct work *work;
	struct avalon2_pkg send_pkg;
	struct avalon2_ret ar;
	uint8_t result[AVA2_READ_SIZE];
	int64_t hash_count = 0;
	uint32_t nonce;
	int ret;


	if (unlikely(avalon2->usbinfo.nodev)) {
		applog(LOG_ERR, "%s%d: Device disappeared, shutting down thread",
		       avalon2->drv->name, avalon2->device_id);
		return -1;
	}

	/* Stop polling the device if there is no stratum in 3 minutes, network is down */
	cgtime(&current_stratum);
	if (tdiff(&current_stratum, &(info->last_stratum)) > (double)(3.0 * 60.0))
		return 0;

	work = get_work(thr, thr->id);

	memset(&send_pkg, 0, sizeof(send_pkg));
	memcpy(send_pkg.data, work->midstate, 32);
	rev(send_pkg.data, 32);
	avalon2_init_pkg(&send_pkg, AVA2_P_WORK, 1, 2);
	avalon2_send_pkgs(avalon2, &send_pkg);
	applog(LOG_DEBUG, "Avalon2: send 1st work");

	memset(&send_pkg, 0, sizeof(send_pkg));
	memcpy(send_pkg.data + 20, work->data + 64, 12);
	rev(send_pkg.data + 20, 12);
	avalon2_init_pkg(&send_pkg, AVA2_P_WORK, 2, 2);
	avalon2_send_pkgs(avalon2, &send_pkg);
	applog(LOG_DEBUG, "Avalon2: send 2nd work");

	ret = avalon2_gets(avalon2, result);
	if (ret == AVA2_GETS_OK) {
		ret = decode_pkg(thr, &ar, result);
		if (ret == AVA2_P_NONCE) {
		    applog(LOG_DEBUG, "Avalon2: got nonce");
		    memcpy((char *)&nonce, ar.data, 4);
		    nonce = htobe32(nonce);
		    submit_nonce(thr, work, nonce);
		    hash_count = nonce & 0xffffffff;
		    hash_count += 1;
		}

	}
	return hash_count;
}

static struct api_data *avalon2_api_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;
	struct avalon2_info *info = cgpu->device_data;
	int i, j, a, b;
	char buf[24];
	double hwp;
	int minerindex, minercount;

	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "ID%d MM Version", i + 1);
		root = api_add_string(root, buf, (char *)&(info->mm_version[i]), false);
	}

	minerindex = 0;
	minercount = 0;
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if (info->dev_type[i] == AVA2_ID_AVAX) {
			minerindex += AVA2_DEFAULT_MINERS;
			continue;
		}

		if (info->dev_type[i] == AVA2_ID_AVA2)
			minercount = AVA2_DEFAULT_MINERS;

		if (info->dev_type[i] == AVA2_ID_AVA3)
			minercount = AVA2_AVA3_MINERS;

		for (j = minerindex; j < (minerindex + minercount); j++) {
			sprintf(buf, "Match work count%02d", j+1);
			root = api_add_int(root, buf, &(info->matching_work[j]), false);
		}
		minerindex += AVA2_DEFAULT_MINERS;
	}

	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Local works%d", i + 1);
		root = api_add_int(root, buf, &(info->local_works[i]), false);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Hardware error works%d", i + 1);
		root = api_add_int(root, buf, &(info->hw_works[i]), false);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		a = info->hw_works[i];
		b = info->local_works[i];
		hwp = b ? ((double)a / (double)b) : 0;

		sprintf(buf, "Device hardware error%d%%", i + 1);
		root = api_add_percent(root, buf, &hwp, true);
	}
	for (i = 0; i < 2 * AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i/2] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Temperature%d", i + 1);
		root = api_add_int(root, buf, &(info->temp[i]), false);
	}
	for (i = 0; i < 2 * AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i/2] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Fan%d", i + 1);
		root = api_add_int(root, buf, &(info->fan[i]), false);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Voltage%d", i + 1);
		root = api_add_int(root, buf, &(info->get_voltage[i]), false);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Frequency%d", i + 1);
		root = api_add_int(root, buf, &(info->get_frequency[i]), false);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Power good %02x", i + 1);
		root = api_add_int(root, buf, &(info->power_good[i]), false);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Led %02x", i + 1);
		root = api_add_int(root, buf, &(info->led_red[i]), false);
	}

	return root;
}

static void avalon2_statline_before(char *buf, size_t bufsiz, struct cgpu_info *avalon2)
{
	struct avalon2_info *info = avalon2->device_data;
	int temp = info->temp[0];
	float volts = (float)info->set_voltage / 10000;

	tailsprintf(buf, bufsiz, "%4dMhz %2dC %3d%% %.3fV", info->set_frequency,
		    temp, info->fan_pct, volts);
}

struct device_drv avalon2_drv = {
	.drv_id = DRIVER_avalon2,
	.dname = "avalon2",
	.name = "AV2",
	.get_api_stats = avalon2_api_stats,
	.get_statline_before = avalon2_statline_before,
	.drv_detect = avalon2_detect,
	.hash_work = hash_driver_work,
	.flush_work = avalon2_update,
	.update_work = avalon2_update,
	.scanwork = avalon2_scanhash,
};
