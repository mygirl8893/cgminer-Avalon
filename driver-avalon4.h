/*
 * Copyright 2013-2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2014 Xiangfu <xiangfu@openmobilefree.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef _AVALON4_H_
#define _AVALON4_H_

#include "util.h"

#ifdef USE_AVALON4

#define AVA4_DEFAULT_MODULARS	64

#define AVA4_PWM_MAX	0x3FF
#define AVA4_DEFAULT_FAN_MIN	10 /* % */
#define AVA4_DEFAULT_FAN_MAX	100

#define AVA4_TEMP_OVERHEAT	65
#define AVA4_DEFAULT_POLLING_DELAY	20 /* ms */

#define AVA4_DEFAULT_VOLTAGE_MIN	4000
#define AVA4_DEFAULT_VOLTAGE_MAX	9000

#define AVA4_DEFAULT_FREQUENCY_MIN	100
#define AVA4_DEFAULT_FREQUENCY_MAX	1000

#define AVA4_DEFAULT_MINERS	10
#define AVA4_DEFAULT_VOLTAGE	6750
#define AVA4_DEFAULT_FREQUENCY	200

#define AVA4_AUC_VER_LEN	12	/* Version length: 12 (AUC-YYYYMMDD) */
#define AVA4_AUC_SPEED		400000
#define AVA4_AUC_XDELAY  	9600	/* 4800 = 1ms in AUC (11U14)  */
#define AVA4_AUC_P_SIZE		64


/* Avalon4 protocol package type from MM protocol.h*/
#define AVA4_MM_VER_LEN	15
#define AVA4_MM_DNA_LEN	8
#define AVA4_H1	'A'
#define AVA4_H2	'V'

#define AVA4_P_COINBASE_SIZE	(6 * 1024 + 64)
#define AVA4_P_MERKLES_COUNT	30

#define AVA4_P_COUNT	40
#define AVA4_P_DATA_LEN 32

#define AVA4_P_DETECT	10
#define AVA4_P_STATIC	11
#define AVA4_P_JOB_ID	12
#define AVA4_P_COINBASE	13
#define AVA4_P_MERKLES	14
#define AVA4_P_HEADER	15
#define AVA4_P_POLLING	16
#define AVA4_P_TARGET	17
#define AVA4_P_REQUIRE	18
#define AVA4_P_SET	19
#define AVA4_P_TEST	20

#define AVA4_P_NONCE		23
#define AVA4_P_STATUS		24
#define AVA4_P_ACKDETECT	25
#define AVA4_P_TEST_RET		26

#define AVA4_MODULE_BROADCAST	0
/* Endof Avalon4 protocol package type */

#define AVA4_MM4_PREFIXSTR	"40"
#define AVA4_MM_VERNULL		"NONE"

#define AVA4_ID_AVA4		3222
#define AVA4_ID_AVAX		3200

#define AVA4_IIC_RESET		0xa0
#define AVA4_IIC_INIT		0xa1
#define AVA4_IIC_DEINIT		0xa2
#define AVA4_IIC_XFER		0xa5
#define AVA4_IIC_INFO		0xa6

struct avalon4_pkg {
	uint8_t head[2];
	uint8_t type;
	uint8_t opt;
	uint8_t idx;
	uint8_t cnt;
	uint8_t data[32];
	uint8_t crc[2];
};
#define avalon4_ret avalon4_pkg

struct avalon4_info {
	cglock_t update_lock;

	struct timeval last_stratum;
	struct pool pool0;
	struct pool pool1;
	struct pool pool2;
	int pool_no;

	char auc_version[AVA4_AUC_VER_LEN + 1];
	int auc_speed;
	int auc_xdelay;

	char mm_version[AVA4_DEFAULT_MODULARS][AVA4_MM_VER_LEN + 1];
	uint8_t mm_dna[AVA4_DEFAULT_MODULARS][AVA4_MM_DNA_LEN + 1];
	int dev_type[AVA4_DEFAULT_MODULARS];
	bool enable[AVA4_DEFAULT_MODULARS];

	int set_frequency[3];
	int set_voltage;

	int get_voltage[AVA4_DEFAULT_MODULARS];
	int get_frequency[AVA4_DEFAULT_MODULARS];
	int power_good[AVA4_DEFAULT_MODULARS];

	int fan_pwm;
	int fan_pct;
	int temp_max;
	int auc_temp;

	int fan[AVA4_DEFAULT_MODULARS];
	int temp[AVA4_DEFAULT_MODULARS];

	int local_works[AVA4_DEFAULT_MODULARS];
	int hw_works[AVA4_DEFAULT_MODULARS];

	int local_work[AVA4_DEFAULT_MODULARS];
	int hw_work[AVA4_DEFAULT_MODULARS];
	int matching_work[AVA4_DEFAULT_MINERS * AVA4_DEFAULT_MODULARS];
	int chipmatching_work[AVA4_DEFAULT_MINERS * AVA4_DEFAULT_MODULARS][4];

	int led_red[AVA4_DEFAULT_MODULARS];
};

struct avalon4_iic_info {
	uint8_t iic_op;
	union {
		uint32_t aucParam[2];
		uint8_t slave_addr;
	} iic_param;
};

#define AVA4_WRITE_SIZE (sizeof(struct avalon4_pkg))
#define AVA4_READ_SIZE AVA4_WRITE_SIZE

#define AVA4_SEND_OK 0
#define AVA4_SEND_ERROR -1

extern char *set_avalon4_fan(char *arg);
extern char *set_avalon4_freq(char *arg);
extern char *set_avalon4_voltage(char *arg);
extern int opt_avalon4_overheat;
extern int opt_avalon4_polling_delay;
extern int opt_avalon4_aucspeed;
extern int opt_avalon4_aucxdelay;
#endif /* USE_AVALON4 */
#endif	/* _AVALON4_H_ */
