/*
 * Copyright 2014 Mikeqin <Fengling.Qin@gmail.com>
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
#include <math.h>

#include "elist.h"
#include "miner.h"
#include "fpgautils.h"
#include "driver-avalon2.h"
#include "crc.h"
#include "sha2.h"
#include "hexdump.c"

#define ASSERT1(condition) __maybe_unused static char sizeof_uint32_t_must_be_4[(condition)?1:-1]
ASSERT1(sizeof(uint32_t) == 4);

#define get_fan_pwm(v)	(AVA2_PWM_MAX - (v) * AVA2_PWM_MAX / 100)

int opt_avalon2_freq[3] = {0, 0, 0};

int opt_avalon2_fan_min = AVA2_DEFAULT_FAN_MIN;
int opt_avalon2_fan_max = AVA2_DEFAULT_FAN_MAX;
static int avalon2_fan_min = get_fan_pwm(AVA2_DEFAULT_FAN_MIN);
static int avalon2_fan_max = get_fan_pwm(AVA2_DEFAULT_FAN_MAX);

int opt_avalon2_voltage_min;
int opt_avalon2_voltage_max;

int opt_avalon2_overheat = AVALON2_TEMP_OVERHEAT;
int opt_avalon2_polling_delay = AVALON2_DEFAULT_POLLING_DELAY;

enum avalon2_fan_fixed opt_avalon2_fan_fixed = FAN_AUTO;

int opt_avalon2_aucspeed = AVA2_AVA4_AUCSPEED;
int opt_avalon2_aucxdelay = AVA2_AVA4_AUCXDELAY;

#define UNPACK32(x, str)			\
{						\
	*((str) + 3) = (uint8_t) ((x)      );	\
	*((str) + 2) = (uint8_t) ((x) >>  8);	\
	*((str) + 1) = (uint8_t) ((x) >> 16);	\
	*((str) + 0) = (uint8_t) ((x) >> 24);	\
}

static void sha256_prehash(const unsigned char *message, unsigned int len, unsigned char *digest)
{
	sha256_ctx ctx;
	int i;
	sha256_init(&ctx);
	sha256_update(&ctx, message, len);

	for (i = 0; i < 8; i++) {
		UNPACK32(ctx.h[i], &digest[i << 2]);
	}
}

static inline uint8_t rev8(uint8_t d)
{
	int i;
	uint8_t out = 0;

	/* (from left to right) */
	for (i = 0; i < 8; i++)
		if (d & (1 << i))
		out |= (1 << (7 - i));

	return out;
}

char *set_avalon2_fan(char *arg)
{
	int val1, val2, ret;

	ret = sscanf(arg, "%d-%d", &val1, &val2);
	if (ret < 1)
		return "No values passed to avalon2-fan";
	if (ret == 1)
		val2 = val1;

	if (val1 < 0 || val1 > 100 || val2 < 0 || val2 > 100 || val2 < val1)
		return "Invalid value passed to avalon2-fan";

	opt_avalon2_fan_min = val1;
	opt_avalon2_fan_max = val2;
	avalon2_fan_min = get_fan_pwm(val1);
	avalon2_fan_max = get_fan_pwm(val2);

	return NULL;
}

char *set_avalon2_fixed_speed(enum avalon2_fan_fixed *f)
{
	*f = FAN_FIXED;
	return NULL;
}

char *set_avalon2_freq(char *arg)
{
	char *colon1, *colon2, *colon3;
	int val1 = 0, val2 = 0, val3 = 0;

	if (!(*arg))
		return NULL;

	colon1 = strchr(arg, ':');
	if (colon1)
		*(colon1++) = '\0';

	if (*arg) {
		val1 = atoi(arg);
		if (val1 < AVA2_DEFAULT_FREQUENCY_MIN || val1 > AVA2_DEFAULT_FREQUENCY_MAX)
			return "Invalid value1 passed to avalon2-freq";
	}

	if (colon1 && *colon1) {
		colon2 = strchr(colon1, ':');
		if (colon2)
			*(colon2++) = '\0';

		if (*colon1) {
			val2 = atoi(colon1);
			if (val2 < AVA2_DEFAULT_FREQUENCY_MIN || val2 > AVA2_DEFAULT_FREQUENCY_MAX)
				return "Invalid value2 passed to avalon2-freq";
		}

		if (colon2 && *colon2) {
			val3 = atoi(colon2);
			if (val3 < AVA2_DEFAULT_FREQUENCY_MIN || val3 > AVA2_DEFAULT_FREQUENCY_MAX)
				return "Invalid value3 passed to avalon2-freq";
		}
	}

	if (!val1)
		val3 = val2 = val1 = AVA2_AVA4_FREQUENCY;

	if (!val2)
		val3 = val2 = val1;

	if (!val3)
		val3 = val2;

	opt_avalon2_freq[0] = val1;
	opt_avalon2_freq[1] = val2;
	opt_avalon2_freq[2] = val3;

	return NULL;
}

char *set_avalon2_voltage(char *arg)
{
	int val1, val2, ret;

	ret = sscanf(arg, "%d-%d", &val1, &val2);
	if (ret < 1)
		return "No values passed to avalon2-voltage";
	if (ret == 1)
		val2 = val1;

	if (val1 < AVA2_DEFAULT_VOLTAGE_MIN || val1 > AVA2_DEFAULT_VOLTAGE_MAX ||
	    val2 < AVA2_DEFAULT_VOLTAGE_MIN || val2 > AVA2_DEFAULT_VOLTAGE_MAX ||
	    val2 < val1)
		return "Invalid value passed to avalon2-voltage";

	opt_avalon2_voltage_min = val1;
	opt_avalon2_voltage_max = val2;

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

static int job_idcmp(uint8_t *job_id, char *pool_job_id)
{
	int job_id_len;
	unsigned short crc, crc_expect;

	if (!pool_job_id)
		return 1;

	job_id_len = strlen(pool_job_id);
	crc_expect = crc16((unsigned char *)pool_job_id, job_id_len);

	crc = job_id[0] << 8 | job_id[1];

	if (crc_expect == crc)
		return 0;

	applog(LOG_DEBUG, "Avalon2: job_id not match! [%04x:%04x (%s)]",
	       crc, crc_expect, pool_job_id);

	return 1;
}

static inline int get_temp_max(struct avalon2_info *info)
{
	int i;
	for (i = 0; i < 2 * AVA2_DEFAULT_MODULARS; i++) {
		if (info->temp_max <= info->temp[i])
			info->temp_max = info->temp[i];
	}
	return info->temp_max;
}

static inline int get_current_temp_max(struct avalon2_info *info)
{
	int i;
	int t = info->temp[0];

	for (i = 1; i < 2 * AVA2_DEFAULT_MODULARS; i++) {
		if (info->temp[i] > t)
			t = info->temp[i];
	}
	return t;
}

/* http://www.onsemi.com/pub_link/Collateral/ADP3208D.PDF */
static inline uint32_t encode_voltage(uint32_t v)
{
	return rev8((0x78 - v / 125) << 1 | 1) << 8;
}

static inline uint32_t decode_voltage(uint32_t v)
{
	return (0x78 - (rev8(v >> 8) >> 1)) * 125;
}

static void adjust_fan(struct avalon2_info *info)
{
	int t;

	if (opt_avalon2_fan_fixed == FAN_FIXED) {
		info->fan_pct = opt_avalon2_fan_min;
		info->fan_pwm = get_fan_pwm(info->fan_pct);
		return;
	}

	t = get_current_temp_max(info);

	/* TODO: Add options for temperature range and fan adjust function */
	if (t < 60)
		info->fan_pct = opt_avalon2_fan_min;
	else if (t > 80)
		info->fan_pct = opt_avalon2_fan_max;
	else
		info->fan_pct = (t - 60) * (opt_avalon2_fan_max - opt_avalon2_fan_min) / 20 + opt_avalon2_fan_min;

	info->fan_pwm = get_fan_pwm(info->fan_pct);
}

static void decode_pkg(struct thr_info *thr, struct avalon2_ret *ar)
{
	struct cgpu_info *avalon2 = thr->cgpu;
	struct avalon2_info *info = avalon2->device_data;
	struct pool *pool, *real_pool;
	struct pool *pool_stratum0 = &info->pool0;
	struct pool *pool_stratum1 = &info->pool1;
	struct pool *pool_stratum2 = &info->pool2;

	unsigned int expected_crc;
	unsigned int actual_crc;
	uint32_t nonce, nonce2, ntime, miner, modular_id, chip_id;
	uint8_t job_id[4];
	int pool_no, tmp;

	if (ar->head[0] != AVA2_H1 && ar->head[1] != AVA2_H2) {
		applog(LOG_DEBUG, "Avalon2: H1 %02x, H2 %02x", ar->head[0], ar->head[1]);
		hexdump(ar->data, 32);
	}

	expected_crc = crc16(ar->data, AVA2_P_DATA_LEN);
	actual_crc = (ar->crc[0] & 0xff) | ((ar->crc[1] & 0xff) << 8);

	applog(LOG_DEBUG, "Avalon2: %d: expected crc(%04x), actual_crc(%04x)",
	       ar->type, expected_crc, actual_crc);
	if (expected_crc != actual_crc)
		return;

	memcpy(&modular_id, ar->data + 28, 4);
	modular_id = be32toh(modular_id);
	applog(LOG_DEBUG, "Avalon2: decode modular id: %d", modular_id);

	switch(ar->type) {
	case AVA2_P_NONCE:
		applog(LOG_DEBUG, "Avalon2: AVA2_P_NONCE");
		memcpy(&miner, ar->data + 0, 4);
		memcpy(&pool_no, ar->data + 4, 4);
		memcpy(&nonce2, ar->data + 8, 4);
		memcpy(&ntime, ar->data + 12, 4);
		memcpy(&nonce, ar->data + 16, 4);
		memcpy(job_id, ar->data + 20, 4);

		miner = be32toh(miner);
		chip_id = (miner >> 16) & 0xffff;
		miner &= 0xffff;
		pool_no = be32toh(pool_no);
		ntime = be32toh(ntime);
		if (miner >= AVA2_DEFAULT_MINERS ||
		    modular_id >= AVA2_DEFAULT_MINERS ||
		    pool_no >= total_pools ||
		    pool_no < 0) {
			applog(LOG_DEBUG, "Avalon2: Wrong miner/pool/id no %d,%d,%d", miner, pool_no, modular_id);
			break;
		} else {
			info->matching_work[modular_id * AVA2_DEFAULT_MINERS + miner]++;
			info->chipmatching_work[modular_id * AVA2_DEFAULT_MINERS + miner][chip_id]++;
		}
		nonce2 = be32toh(nonce2);
		nonce = be32toh(nonce);
		nonce -= 0x180;

		applog(LOG_DEBUG, "Avalon2: Found! %d: (%08x) (%08x) (%d) (%d-%d-%d,%d,%d,%d)",
		       pool_no, nonce2, nonce, ntime,
		       miner, info->matching_work[modular_id * AVA2_DEFAULT_MINERS + miner],
		       info->chipmatching_work[modular_id * AVA2_DEFAULT_MINERS + miner][0],
		       info->chipmatching_work[modular_id * AVA2_DEFAULT_MINERS + miner][1],
		       info->chipmatching_work[modular_id * AVA2_DEFAULT_MINERS + miner][2],
		       info->chipmatching_work[modular_id * AVA2_DEFAULT_MINERS + miner][3]);

		real_pool = pool = pools[pool_no];
		if (job_idcmp(job_id, pool->swork.job_id)) {
			if (!job_idcmp(job_id, pool_stratum0->swork.job_id)) {
				applog(LOG_DEBUG, "Avalon2: Match to previous stratum0! (%s)", pool_stratum0->swork.job_id);
				pool = pool_stratum0;
			} else if (!job_idcmp(job_id, pool_stratum1->swork.job_id)) {
				applog(LOG_DEBUG, "Avalon2: Match to previous stratum1! (%s)", pool_stratum1->swork.job_id);
				pool = pool_stratum1;
			} else if (!job_idcmp(job_id, pool_stratum2->swork.job_id)) {
				applog(LOG_DEBUG, "Avalon2: Match to previous stratum2! (%s)", pool_stratum2->swork.job_id);
				pool = pool_stratum2;
			} else {
				applog(LOG_ERR, "Avalon2: Cannot match to any stratum! (%s)", pool->swork.job_id);
				break;
			}
		}

		submit_nonce2_nonce(thr, pool, real_pool, nonce2, nonce, ntime);
		break;
	case AVA2_P_STATUS:
		applog(LOG_DEBUG, "Avalon2: AVA2_P_STATUS");
		memcpy(&tmp, ar->data, 4);
		tmp = be32toh(tmp);
		info->temp[0 + modular_id * 2] = tmp >> 16;
		info->temp[1 + modular_id * 2] = tmp & 0xffff;

		memcpy(&tmp, ar->data + 4, 4);
		tmp = be32toh(tmp);
		info->fan[0 + modular_id * 2] = tmp >> 16;
		info->fan[1 + modular_id * 2] = tmp & 0xffff;

		memcpy(&(info->get_frequency[modular_id]), ar->data + 8, 4);
		memcpy(&(info->get_voltage[modular_id]), ar->data + 12, 4);
		memcpy(&(info->local_work[modular_id]), ar->data + 16, 4);
		memcpy(&(info->hw_work[modular_id]), ar->data + 20, 4);
		memcpy(&(info->power_good[modular_id]), ar->data + 24, 4);

		info->get_frequency[modular_id] = be32toh(info->get_frequency[modular_id]);
		if (info->dev_type[modular_id] == AVA2_ID_AVA3)
			info->get_frequency[modular_id] = info->get_frequency[modular_id] * 768 / 65;
		if (info->dev_type[modular_id] == AVA2_ID_AVA4)
			info->get_frequency[modular_id] = info->get_frequency[modular_id] * 3968 / 65;
		info->get_voltage[modular_id] = be32toh(info->get_voltage[modular_id]);
		info->local_work[modular_id] = be32toh(info->local_work[modular_id]);
		info->hw_work[modular_id] = be32toh(info->hw_work[modular_id]);

		info->local_works[modular_id] += info->local_work[modular_id];
		info->hw_works[modular_id] += info->hw_work[modular_id];

		info->get_voltage[modular_id] = decode_voltage(info->get_voltage[modular_id]);
		info->power_good[modular_id] = be32toh(info->power_good[modular_id]);

		avalon2->temp = get_temp_max(info);
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
		break;
	}
}

/*
 #  IIC packet format: length[1]+transId[1]+sesId[1]+req[1]+data[60]
 #  length: 4+len(data)
 #  transId: 0
 #  sesId: 0
 #  req: checkout the header file
 #  data:
 #    INIT: clock_rate[4] + reserved[4] + payload[52]
 #    XFER: txSz[1]+rxSz[1]+options[1]+slaveAddr[1] + payload[56]
 */
static int avalon2_iic_init_pkg(uint8_t *iic_pkg, struct avalon2_iic_info *iic_info, uint8_t *buf, int wlen, int rlen)
{
	memset(iic_pkg, 0, AVA2_IIC_P_SIZE);

	switch (iic_info->iic_op) {
	case AVA2_IIC_INIT:
		iic_pkg[0] = 12;	/* 4 bytes IIC header + 4 bytes speed + 4 bytes xfer delay */
		iic_pkg[3] = AVA2_IIC_INIT;
		iic_pkg[4] = iic_info->iic_param.aucParam[0] & 0xff;
		iic_pkg[5] = (iic_info->iic_param.aucParam[0] >> 8) & 0xff;
		iic_pkg[6] = (iic_info->iic_param.aucParam[0] >> 16) & 0xff;
		iic_pkg[7] = iic_info->iic_param.aucParam[0] >> 24;
		iic_pkg[8] = iic_info->iic_param.aucParam[1] & 0xff;
		iic_pkg[9] = (iic_info->iic_param.aucParam[1] >> 8) & 0xff;
		iic_pkg[10] = (iic_info->iic_param.aucParam[1] >> 16) & 0xff;
		iic_pkg[11] = iic_info->iic_param.aucParam[1] >> 24;
		break;
	case AVA2_IIC_XFER:
		iic_pkg[0] = 8 + wlen;
		iic_pkg[3] = AVA2_IIC_XFER;
		iic_pkg[4] = wlen;
		iic_pkg[5] = rlen;
		iic_pkg[7] = iic_info->iic_param.slave_addr;
		memcpy(iic_pkg + 8, buf, wlen);
		break;
	case AVA2_IIC_INFO:
		iic_pkg[0] = 4;
		iic_pkg[3] = AVA2_IIC_INFO;
		break;

	default:
		break;
	}

	return 0;
}

static int avalon2_iic_xfer(struct cgpu_info *avalon2,
			    uint8_t *wbuf, int wlen, int *write,
			    uint8_t *rbuf, int rlen, int *read)
{
	int err;

	err = usb_write(avalon2, (char *)wbuf, wlen, write, C_AVA2_WRITE);
	if (err || *write != wlen)
		applog(LOG_DEBUG, "Avalon2: AUC xfer %d, w(%d-%d)!", err, wlen, *write);

	cgsleep_ms(opt_avalon2_aucxdelay / 4800);

	rlen += 4; 		/* Add 4 bytes IIC header */
	err = usb_read(avalon2, (char *)rbuf, rlen, read, C_AVA2_READ);
	if (err || *read != rlen) {
		applog(LOG_DEBUG, "Avalon2: AUC xfer %d, r(%d-%d)!", err, rlen - 4, *read);
		hexdump(rbuf, rlen);
	}

	*read = rbuf[0] - 4;	/* Remove 4 bytes IIC header */

	return err;
}

static int avalon2_iic_init(struct cgpu_info *avalon2)
{
	struct avalon2_iic_info iic_info;
	int err, wlen, rlen;
	uint8_t wbuf[AVA2_IIC_P_SIZE];
	uint8_t rbuf[AVA2_IIC_P_SIZE];

	if (unlikely(avalon2->usbinfo.nodev))
		return 1;

	iic_info.iic_op = AVA2_IIC_INIT;
	iic_info.iic_param.aucParam[0] = opt_avalon2_aucspeed;
	iic_info.iic_param.aucParam[1] = opt_avalon2_aucxdelay;
	rlen = 12;		/* Version length: 12 (AUC-20140909) */
	avalon2_iic_init_pkg(wbuf, &iic_info, NULL, 0, rlen);

	memset(rbuf, 0, AVA2_IIC_P_SIZE);
	err = avalon2_iic_xfer(avalon2, wbuf, AVA2_IIC_P_SIZE, &wlen, rbuf, rlen, &rlen);
	if (err) {
		applog(LOG_ERR, "Avalon2: Failed to init Avalon USB2IIC Converter");
		return 1;
	}

	applog(LOG_DEBUG, "Avalon2: USB2IIC Converter versioin: %s", rbuf + 4);
	return 0;
}

static int avalon2_iic_getinfo(struct cgpu_info *avalon2)
{
	struct avalon2_iic_info iic_info;
	int err, wlen, rlen;
	uint8_t wbuf[AVA2_IIC_P_SIZE];
	uint8_t rbuf[AVA2_IIC_P_SIZE];
	uint8_t *pdata = rbuf + 4;
	int adc_val;
	float div_vol;
	struct avalon2_info *info = avalon2->device_data;

	if (unlikely(avalon2->usbinfo.nodev))
		return 1;

	iic_info.iic_op = AVA2_IIC_INFO;
	/* Device info: (9 bytes)
	 * tempadc(2), reqRdIndex, reqWrIndex,
	 * respRdIndex, respWrIndex, tx_flags, state
	 * */
	rlen = 7;
	avalon2_iic_init_pkg(wbuf, &iic_info, NULL, 0, rlen);

	memset(rbuf, 0, AVA2_IIC_P_SIZE);
	err = avalon2_iic_xfer(avalon2, wbuf, AVA2_IIC_P_SIZE, &wlen, rbuf, rlen, &rlen);
	if (err) {
		applog(LOG_ERR, "Avalon2: Failed to get info from Avalon USB2IIC Converter");
		return 1;
	}

	applog(LOG_DEBUG, "Avalon2: AUC tempADC(%03d), reqcnt(%d), respcnt(%d), txflag(%d), state(%d)",
			be16toh(pdata[0] << 8 | pdata[1]),
			pdata[2],
			pdata[3],
			be16toh(pdata[4] << 8 | pdata[5]),
			pdata[6]);

	adc_val = be16toh(pdata[0] << 8 | pdata[1]);
	div_vol = (1023.0 / adc_val) - 1;

	info->auc_temp = 3.3 * 10000 / div_vol;
	return 0;
}

static int avalon2_iic_xfer_pkg(struct cgpu_info *avalon2, uint8_t slave_addr,
				const struct avalon2_pkg *pkg, struct avalon2_ret *ret)
{
	struct avalon2_iic_info iic_info;
	int err, wcnt, rcnt, rlen = 0;
	uint8_t wbuf[AVA2_IIC_P_SIZE];
	uint8_t rbuf[AVA2_IIC_P_SIZE];

	if (unlikely(avalon2->usbinfo.nodev))
		return AVA2_SEND_ERROR;

	iic_info.iic_op = AVA2_IIC_XFER;
	iic_info.iic_param.slave_addr = slave_addr;
	if (ret)
		rlen = AVA2_READ_SIZE + 1;

	avalon2_iic_init_pkg(wbuf, &iic_info, (uint8_t *)pkg, AVA2_WRITE_SIZE + 1, rlen);
	err = avalon2_iic_xfer(avalon2, wbuf, wbuf[0], &wcnt, rbuf, rlen, &rcnt);
	if (err || rcnt != rlen)
		return AVA2_SEND_ERROR;

	if (ret)
		memcpy((char *)ret, rbuf + 4, AVA2_READ_SIZE);

	return AVA2_SEND_OK;
}

static int avalon2_send_bc_pkgs(struct cgpu_info *avalon2, const struct avalon2_pkg *pkg)
{
	int ret;

	do {
		if (unlikely(avalon2->usbinfo.nodev))
			return -1;
		ret = avalon2_iic_xfer_pkg(avalon2, AVA2_MODULE_BROADCAST, pkg, NULL);
	} while (ret != AVA2_SEND_OK);

	return 0;
}

static void avalon2_stratum_pkgs(struct cgpu_info *avalon2, struct pool *pool)
{
	const int merkle_offset = 36;
	struct avalon2_pkg pkg;
	int i, a, b, tmp;
	unsigned char target[32];
	int job_id_len, n2size;
	unsigned short crc;

	/* Send out the first stratum message STATIC */
	applog(LOG_DEBUG, "Avalon2: Pool stratum message STATIC: %d, %d, %d, %d, %d",
	       pool->coinbase_len,
	       pool->nonce2_offset,
	       pool->n2size,
	       merkle_offset,
	       pool->merkles);
	memset(pkg.data, 0, AVA2_P_DATA_LEN);
	tmp = be32toh(pool->coinbase_len);
	memcpy(pkg.data, &tmp, 4);

	tmp = be32toh(pool->nonce2_offset);
	memcpy(pkg.data + 4, &tmp, 4);

	n2size = pool->n2size >= 4 ? 4 : pool->n2size;
	tmp = be32toh(n2size);
	memcpy(pkg.data + 8, &tmp, 4);

	tmp = be32toh(merkle_offset);
	memcpy(pkg.data + 12, &tmp, 4);

	tmp = be32toh(pool->merkles);
	memcpy(pkg.data + 16, &tmp, 4);

	tmp = be32toh((int)pool->swork.diff);
	memcpy(pkg.data + 20, &tmp, 4);

	tmp = be32toh((int)pool->pool_no);
	memcpy(pkg.data + 24, &tmp, 4);

	avalon2_init_pkg(&pkg, AVA2_P_STATIC, 1, 1);
	if (avalon2_send_bc_pkgs(avalon2, &pkg))
		return;

	set_target(target, pool->sdiff);
	memcpy(pkg.data, target, 32);
	if (opt_debug) {
		char *target_str;
		target_str = bin2hex(target, 32);
		applog(LOG_DEBUG, "Avalon2: Pool stratum target: %s", target_str);
		free(target_str);
	}
	avalon2_init_pkg(&pkg, AVA2_P_TARGET, 1, 1);
	if (avalon2_send_bc_pkgs(avalon2, &pkg))
		return;

	memset(pkg.data, 0, AVA2_P_DATA_LEN);

	job_id_len = strlen(pool->swork.job_id);
	crc = crc16((unsigned char *)pool->swork.job_id, job_id_len);
	applog(LOG_DEBUG, "Avalon2: Pool stratum message JOBS_ID[%04x]: %s",
	       crc, pool->swork.job_id);

	pkg.data[0] = (crc & 0xff00) >> 8;
	pkg.data[1] = crc & 0x00ff;
	avalon2_init_pkg(&pkg, AVA2_P_JOB_ID, 1, 1);
	if (avalon2_send_bc_pkgs(avalon2, &pkg))
		return;

	if (pool->coinbase_len > AVA2_P_COINBASE_SIZE) {
		int coinbase_len_posthash, coinbase_len_prehash;
		uint8_t coinbase_prehash[32];
		coinbase_len_prehash = pool->nonce2_offset - (pool->nonce2_offset % SHA256_BLOCK_SIZE);
		coinbase_len_posthash = pool->coinbase_len - coinbase_len_prehash;
		sha256_prehash(pool->coinbase, coinbase_len_prehash, coinbase_prehash);

		a = (coinbase_len_posthash / AVA2_P_DATA_LEN) + 1;
		b = coinbase_len_posthash % AVA2_P_DATA_LEN;
		memcpy(pkg.data, coinbase_prehash, 32);
		avalon2_init_pkg(&pkg, AVA2_P_COINBASE, 1, a + (b ? 1 : 0));
		if (avalon2_send_bc_pkgs(avalon2, &pkg))
			return;
		applog(LOG_DEBUG, "Avalon2: Pool stratum message modified COINBASE: %d %d", a, b);
		for (i = 1; i < a; i++) {
			memcpy(pkg.data, pool->coinbase + coinbase_len_prehash + i * 32 - 32, 32);
			avalon2_init_pkg(&pkg, AVA2_P_COINBASE, i + 1, a + (b ? 1 : 0));
			if (avalon2_send_bc_pkgs(avalon2, &pkg))
				return;
		}
		if (b) {
			memset(pkg.data, 0, AVA2_P_DATA_LEN);
			memcpy(pkg.data, pool->coinbase + coinbase_len_prehash + i * 32 - 32, b);
			avalon2_init_pkg(&pkg, AVA2_P_COINBASE, i + 1, i + 1);
			if (avalon2_send_bc_pkgs(avalon2, &pkg))
				return;
		}
	} else {
		a = pool->coinbase_len / AVA2_P_DATA_LEN;
		b = pool->coinbase_len % AVA2_P_DATA_LEN;
		applog(LOG_DEBUG, "Avalon2: Pool stratum message COINBASE: %d %d", a, b);
		for (i = 0; i < a; i++) {
			memcpy(pkg.data, pool->coinbase + i * 32, 32);
			avalon2_init_pkg(&pkg, AVA2_P_COINBASE, i + 1, a + (b ? 1 : 0));
			if (avalon2_send_bc_pkgs(avalon2, &pkg))
				return;
		}
		if (b) {
			memset(pkg.data, 0, AVA2_P_DATA_LEN);
			memcpy(pkg.data, pool->coinbase + i * 32, b);
			avalon2_init_pkg(&pkg, AVA2_P_COINBASE, i + 1, i + 1);
			if (avalon2_send_bc_pkgs(avalon2, &pkg))
				return;
		}
	}


	b = pool->merkles;
	applog(LOG_DEBUG, "Avalon2: Pool stratum message MERKLES: %d", b);
	for (i = 0; i < b; i++) {
		memset(pkg.data, 0, AVA2_P_DATA_LEN);
		memcpy(pkg.data, pool->swork.merkle_bin[i], 32);
		avalon2_init_pkg(&pkg, AVA2_P_MERKLES, i + 1, b);
		if (avalon2_send_bc_pkgs(avalon2, &pkg))
			return;
	}

	applog(LOG_DEBUG, "Avalon2: Pool stratum message HEADER: 4");
	for (i = 0; i < 4; i++) {
		memset(pkg.data, 0, AVA2_P_HEADER);
		memcpy(pkg.data, pool->header_bin + i * 32, 32);
		avalon2_init_pkg(&pkg, AVA2_P_HEADER, i + 1, 4);
		if (avalon2_send_bc_pkgs(avalon2, &pkg))
			return;
	}

	avalon2_iic_getinfo(avalon2);
}

static struct cgpu_info *avalon2_detect_one(struct libusb_device *dev, struct usb_find_devices *found)
{
	struct avalon2_info *info;
	int ackdetect;
	int err;
	int tmp, i, modular[AVA2_DEFAULT_MODULARS] = {};
	char mm_version[AVA2_DEFAULT_MODULARS][16];
	char mm_dna[AVA2_DEFAULT_MODULARS][AVA2_DNA_LEN];

	struct cgpu_info *avalon2 = usb_alloc_cgpu(&avalon2_drv, 1);
	struct avalon2_pkg detect_pkg;
	struct avalon2_ret ret_pkg;

	if (!usb_init(avalon2, dev, found)) {
		applog(LOG_ERR, "Avalon2 failed usb_init");
		avalon2 = usb_free_cgpu(avalon2);
		return NULL;
	}
	avalon2_iic_init(avalon2);

	for (i = 1; i < AVA2_DEFAULT_MODULARS; i++) {
		modular[i] = 0;
		memset(detect_pkg.data, 0, AVA2_P_DATA_LEN);
		tmp = be32toh(i);
		memcpy(detect_pkg.data + 28, &tmp, 4);

		applog(LOG_DEBUG, "Avalon2: AVA2_P_DETECT");
		avalon2_init_pkg(&detect_pkg, AVA2_P_DETECT, 1, 1);
		err = avalon2_iic_xfer_pkg(avalon2, AVA2_MODULE_BROADCAST, &detect_pkg, &ret_pkg);
		if (err != AVA2_SEND_OK) {
			applog(LOG_DEBUG, "%s %d: Failed AUC xfer data with err %d",
			       avalon2->drv->name, avalon2->device_id, err);
			continue;
		}
		ackdetect = ret_pkg.type;
		applog(LOG_DEBUG, "Avalon2 Detect ID[%d]: %d", i, ackdetect);
		if (ackdetect != AVA2_P_ACKDETECT)
			continue;

		modular[i] = 1;
		memcpy(mm_version[i], ret_pkg.data, 15);
		mm_version[i][15] = '\0';
	}

	for (i = 1; i < AVA2_DEFAULT_MODULARS; i++) {
		if (modular[i])
			continue;
		strcpy(mm_version[i], AVA2_MM_VERNULL);

		/* Send out detect pkg */
		applog(LOG_DEBUG, "Avalon2: AVA2_P_DISCOVER");
		memset(detect_pkg.data, 0, AVA2_P_DATA_LEN);
		tmp = be32toh(i);
		memcpy(detect_pkg.data + 28, &tmp, 4);
		avalon2_init_pkg(&detect_pkg, AVA2_P_DISCOVER, 1, 1);
		err = avalon2_iic_xfer_pkg(avalon2, AVA2_MODULE_BROADCAST, &detect_pkg, &ret_pkg);
		if (err != AVA2_SEND_OK) {
			applog(LOG_DEBUG, "%s %d: Failed AUC xfer data with err %d",
			       avalon2->drv->name, avalon2->device_id, err);
			break;
		}

		ackdetect = ret_pkg.type;
		applog(LOG_DEBUG, "Avalon2 Discover ID[%d]: %d", i, ackdetect);
		hexdump((uint8_t *)&ret_pkg, AVA2_READ_SIZE);
		if (ackdetect != AVA2_P_ACKDISCOVER)
			break;

		modular[i] = 1;
		memcpy(mm_dna[i], ret_pkg.data, AVA2_DNA_LEN);
		memcpy(mm_version[i], ret_pkg.data + AVA2_DNA_LEN, 15);
		mm_version[i][15] = '\0';
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

	info->fan_pwm = get_fan_pwm(AVA2_DEFAULT_FAN_PWM);
	info->temp_max = 0;

	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		strcpy(info->mm_version[i], mm_version[i]);
		info->modulars[i] = modular[i];	/* Enable modular */
		info->enable[i] = modular[i];

		info->dev_type[i] = AVA2_ID_AVAX;
		memcpy(info->mm_dna[i], mm_dna, AVA2_DNA_LEN);

		if (!strncmp((char *)&(info->mm_version[i]), AVA2_FW2_PREFIXSTR, 2)) {
			info->dev_type[i] = AVA2_ID_AVA2;
			info->set_voltage = AVA2_DEFAULT_VOLTAGE_MIN;
			info->set_frequency[0] = AVA2_DEFAULT_FREQUENCY;
		}
		if (!strncmp((char *)&(info->mm_version[i]), AVA2_FW3_PREFIXSTR, 2)) {
			info->dev_type[i] = AVA2_ID_AVA3;
			info->set_voltage = AVA2_AVA3_VOLTAGE;
			info->set_frequency[0] = AVA2_AVA3_FREQUENCY;
		}
		if (!strncmp((char *)&(info->mm_version[i]), AVA2_FW35_PREFIXSTR, 2)) {
			info->dev_type[i] = AVA2_ID_AVA3;
			info->set_voltage = AVA2_AVA3_VOLTAGE;
			info->set_frequency[0] = AVA2_AVA3_FREQUENCY;
		}
		if (!strncmp((char *)&(info->mm_version[i]), AVA2_FW4_PREFIXSTR, 2)) {
			info->dev_type[i] = AVA2_ID_AVA4;
			info->set_voltage = AVA2_AVA4_VOLTAGE;
			info->set_frequency[0] = AVA2_AVA4_FREQUENCY;
			info->set_frequency[1] = AVA2_AVA4_FREQUENCY;
			info->set_frequency[2] = AVA2_AVA4_FREQUENCY;
		}
	}

	if (!opt_avalon2_voltage_min)
		opt_avalon2_voltage_min = opt_avalon2_voltage_max = info->set_voltage;
	if (!opt_avalon2_freq[0]) {
		opt_avalon2_freq[0] = info->set_frequency[0];
		opt_avalon2_freq[1] = info->set_frequency[1];
		opt_avalon2_freq[2] = info->set_frequency[2];
	}

	return avalon2;
}

static inline void avalon2_detect(bool __maybe_unused hotplug)
{
	usb_detect(&avalon2_drv, avalon2_detect_one);
}

static bool avalon2_prepare(struct thr_info *thr)
{
	struct cgpu_info *avalon2 = thr->cgpu;
	struct avalon2_info *info = avalon2->device_data;

	cglock_init(&info->update_lock);

	cglock_init(&info->pool0.data_lock);
	cglock_init(&info->pool1.data_lock);
	cglock_init(&info->pool2.data_lock);

	return true;
}

static int polling(struct thr_info *thr, struct cgpu_info *avalon2, struct avalon2_info *info)
{
	struct avalon2_pkg send_pkg;
	struct avalon2_ret ar;
	int i, tmp, ret;

	for (i = 1; i < AVA2_DEFAULT_MODULARS; i++) {
		if (info->modulars[i] && info->enable[i]) {
			cgsleep_ms(opt_avalon2_polling_delay);

			memset(send_pkg.data, 0, AVA2_P_DATA_LEN);

			tmp = be32toh(info->led_red[i]); /* RED LED */
			memcpy(send_pkg.data + 12, &tmp, 4);

			tmp = be32toh(i); /* ID */
			memcpy(send_pkg.data + 28, &tmp, 4);
			avalon2_init_pkg(&send_pkg, AVA2_P_POLLING, 1, 1);

			ret = avalon2_iic_xfer_pkg(avalon2, i, &send_pkg, &ar);
			if (ret == AVA2_SEND_OK)
				decode_pkg(thr, &ar);
		}
	}

	return 0;
}

static void copy_pool_stratum(struct pool *pool_stratum, struct pool *pool)
{
	int i;
	int merkles = pool->merkles;
	size_t coinbase_len = pool->coinbase_len;

	if (!pool->swork.job_id)
		return;

	if (!job_idcmp((unsigned char *)pool->swork.job_id, pool_stratum->swork.job_id))
		return;

	cg_wlock(&pool_stratum->data_lock);
	free(pool_stratum->swork.job_id);
	free(pool_stratum->nonce1);
	free(pool_stratum->coinbase);

	align_len(&coinbase_len);
	pool_stratum->coinbase = calloc(coinbase_len, 1);
	if (unlikely(!pool_stratum->coinbase))
		quit(1, "Failed to calloc pool_stratum coinbase in avalon2");
	memcpy(pool_stratum->coinbase, pool->coinbase, coinbase_len);


	for (i = 0; i < pool_stratum->merkles; i++)
		free(pool_stratum->swork.merkle_bin[i]);
	if (merkles) {
		pool_stratum->swork.merkle_bin = realloc(pool_stratum->swork.merkle_bin,
						 sizeof(char *) * merkles + 1);
		for (i = 0; i < merkles; i++) {
			pool_stratum->swork.merkle_bin[i] = malloc(32);
			if (unlikely(!pool_stratum->swork.merkle_bin[i]))
				quit(1, "Failed to malloc pool_stratum swork merkle_bin");
			memcpy(pool_stratum->swork.merkle_bin[i], pool->swork.merkle_bin[i], 32);
		}
	}

	pool_stratum->sdiff = pool->sdiff;
	pool_stratum->coinbase_len = pool->coinbase_len;
	pool_stratum->nonce2_offset = pool->nonce2_offset;
	pool_stratum->n2size = pool->n2size;
	pool_stratum->merkles = pool->merkles;

	pool_stratum->swork.job_id = strdup(pool->swork.job_id);
	pool_stratum->nonce1 = strdup(pool->nonce1);

	memcpy(pool_stratum->ntime, pool->ntime, sizeof(pool_stratum->ntime));
	memcpy(pool_stratum->header_bin, pool->header_bin, sizeof(pool_stratum->header_bin));
	cg_wunlock(&pool_stratum->data_lock);
}

static void avalon2_update(struct cgpu_info *avalon2)
{
	struct avalon2_info *info = avalon2->device_data;
	struct thr_info *thr = avalon2->thr[0];
	struct avalon2_pkg send_pkg;
	uint32_t tmp, range, start;
	struct work *work;
	struct pool *pool;

	applog(LOG_DEBUG, "Avalon2: New stratum: restart: %d, update: %d",
	       thr->work_restart, thr->work_update);
	thr->work_update = false;
	thr->work_restart = false;

	work = get_work(thr, thr->id); /* Make sure pool is ready */
	discard_work(work); /* Don't leak memory */

	pool = current_pool();
	if (!pool->has_stratum)
		quit(1, "Avalon2: MM have to use stratum pool");

	if (pool->coinbase_len > AVA2_P_COINBASE_SIZE) {
		applog(LOG_INFO, "Avalon2: MM pool coinbase length(%d) is more than %d",
		       pool->coinbase_len, AVA2_P_COINBASE_SIZE);
		if ((pool->coinbase_len - pool->nonce2_offset + 64) > AVA2_P_COINBASE_SIZE) {
			applog(LOG_ERR, "Avalon2: MM pool modified coinbase length(%d) is more than %d",
			       pool->coinbase_len - pool->nonce2_offset + 64, AVA2_P_COINBASE_SIZE);
			return;
		}
	}
	if (pool->merkles > AVA2_P_MERKLES_COUNT) {
		applog(LOG_ERR, "Avalon2: MM merkles have to less then %d", AVA2_P_MERKLES_COUNT);
		return;
	}
	if (pool->n2size < 3) {
		applog(LOG_ERR, "Avalon2: MM nonce2 size have to >= 3 (%d)", pool->n2size);
		return;
	}

	cg_rlock(&info->update_lock);
	cg_rlock(&pool->data_lock);

	cgtime(&info->last_stratum);
	info->pool_no = pool->pool_no;
	copy_pool_stratum(&info->pool2, &info->pool1);
	copy_pool_stratum(&info->pool1, &info->pool0);
	copy_pool_stratum(&info->pool0, pool);
	avalon2_stratum_pkgs(avalon2, pool);

	cg_runlock(&pool->data_lock);
	cg_runlock(&info->update_lock);

	/* Configuer the parameter from outside */
	adjust_fan(info);
	info->set_voltage = opt_avalon2_voltage_min;
	info->set_frequency[0] = opt_avalon2_freq[0];
	info->set_frequency[1] = opt_avalon2_freq[1];
	info->set_frequency[2] = opt_avalon2_freq[2];

	/* Set the Fan, Voltage and Frequency */
	memset(send_pkg.data, 0, AVA2_P_DATA_LEN);

	tmp = be32toh(info->fan_pwm);
	memcpy(send_pkg.data, &tmp, 4);

	applog(LOG_INFO, "Avalon2: Temp max: %d, Cut off temp: %d",
	       get_current_temp_max(info), opt_avalon2_overheat);
	if (get_current_temp_max(info) >= opt_avalon2_overheat)
		tmp = encode_voltage(0);
	else
		tmp = encode_voltage(info->set_voltage);
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + 4, &tmp, 4);

	tmp = info->set_frequency[0] | (info->set_frequency[1] << 10) | (info->set_frequency[2] << 20);
	tmp = be32toh(tmp);
	memcpy(send_pkg.data + 8, &tmp, 4);

	/* Configure the nonce2 offset and range */
	if (pool->n2size == 3)
		range = 0xffffff / (total_devices + 1);
	else
		range = 0xffffffff / (total_devices + 1);
	start = range * (avalon2->device_id + 1);

	tmp = be32toh(start);
	memcpy(send_pkg.data + 12, &tmp, 4);

	tmp = be32toh(range);
	memcpy(send_pkg.data + 16, &tmp, 4);

	/* Package the data */
	avalon2_init_pkg(&send_pkg, AVA2_P_SET, 1, 1);
	avalon2_send_bc_pkgs(avalon2, &send_pkg);
}

static int64_t avalon2_scanhash(struct thr_info *thr)
{
	struct timeval current_stratum;
	struct cgpu_info *avalon2 = thr->cgpu;
	struct avalon2_info *info = avalon2->device_data;
	int64_t h;
	int i;

	if (unlikely(avalon2->usbinfo.nodev)) {
		applog(LOG_ERR, "%s%d: Device disappeared, shutting down thread",
		       avalon2->drv->name, avalon2->device_id);
		return -1;
	}

	/* Stop polling the device if there is no stratum in 3 minutes, network is down */
	cgtime(&current_stratum);
	if (tdiff(&current_stratum, &(info->last_stratum)) > (double)(3.0 * 60.0))
		return 0;


	cg_rlock(&info->update_lock);
	polling(thr, avalon2, info);
	cg_runlock(&info->update_lock);

	h = 0;
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		h += info->enable[i] ? (info->local_work[i] - info->hw_work[i]) : 0;
	}
	return h * 0xffffffff;
}

static struct api_data *avalon2_api_stats(struct cgpu_info *cgpu)
{
	struct api_data *root = NULL;
	struct avalon2_info *info = cgpu->device_data;
	int i, j, a, b;
	char buf[40];
	double hwp;
	int minerindex, minercount;
	char statbuf[AVA2_DEFAULT_MODULARS][200];

	memset(statbuf, 0, AVA2_DEFAULT_MODULARS*200);

	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "Ver[%s]", info->mm_version[i]);
		strcat(statbuf[i], buf);
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

		if (info->dev_type[i] == AVA2_ID_AVA4)
			minercount = AVA2_AVA4_MINERS;

		strcat(statbuf[i], " MW[");
		for (j = minerindex; j < (minerindex + minercount); j++) {
			sprintf(buf, " %d", info->matching_work[j]);
			strcat(statbuf[i], buf);
		}
		strcat(statbuf[i], "]");
		minerindex += AVA2_DEFAULT_MINERS;
	}

	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " LW[%d]", info->local_works[i]);
		strcat(statbuf[i], buf);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " HW[%d]", info->hw_works[i]);
		strcat(statbuf[i], buf);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		a = info->hw_works[i];
		b = info->local_works[i];
		hwp = b ? ((double)a / (double)b) : 0;

		sprintf(buf, " DH[%.3f%%]", hwp * 100);
		strcat(statbuf[i], buf);
	}
	for (i = 0; i < 2 * AVA2_DEFAULT_MODULARS; i+=2) {
		if(info->dev_type[i/2] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " Temp[%d %d]", info->temp[i], info->temp[i+1]);
		strcat(statbuf[i/2], buf);
	}
	for (i = 0; i < 2 * AVA2_DEFAULT_MODULARS; i+=2) {
		if(info->dev_type[i/2] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " Fan[%d %d]", info->fan[i], info->fan[i+1]);
		strcat(statbuf[i/2], buf);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " Vol[%.4f]", (float)info->get_voltage[i] / 10000);
		strcat(statbuf[i], buf);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " Freq[%.2f]", (float)info->get_frequency[i] / 1000);
		strcat(statbuf[i], buf);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " PG[%d]", info->power_good[i]);
		strcat(statbuf[i], buf);
	}
	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, " Led[%d]", info->led_red[i]);
		strcat(statbuf[i], buf);
	}

	for (i = 0; i < AVA2_DEFAULT_MODULARS; i++) {
		if(info->dev_type[i] == AVA2_ID_AVAX)
			continue;
		sprintf(buf, "MM ID%d", i);
		root = api_add_string(root, buf, statbuf[i], true);
	}

	sprintf(buf, "AUC Temp");
	root = api_add_int(root, buf, &(info->auc_temp), false);

	return root;
}

static void avalon2_statline_before(char *buf, size_t bufsiz, struct cgpu_info *avalon2)
{
	struct avalon2_info *info = avalon2->device_data;
	int temp = get_current_temp_max(info);
	float volts = (float)info->set_voltage / 10000;

	tailsprintf(buf, bufsiz, "%4dMhz %2dC %3d%% %.3fV", 
		    (info->set_frequency[0] * 4 + info->set_frequency[1] * 4 + info->set_frequency[2]) / 9,
		    temp, info->fan_pct, volts);
}

struct device_drv avalon2_drv = {
	.drv_id = DRIVER_avalon2,
	.dname = "avalon2",
	.name = "AV2",
	.get_api_stats = avalon2_api_stats,
	.get_statline_before = avalon2_statline_before,
	.drv_detect = avalon2_detect,
	.thread_prepare = avalon2_prepare,
	.hash_work = hash_driver_work,
	.flush_work = avalon2_update,
	.update_work = avalon2_update,
	.scanwork = avalon2_scanhash,
};
