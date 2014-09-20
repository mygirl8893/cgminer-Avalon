/*
 * Copyright 2013-2014 Con Kolivas <kernel@kolivas.org>
 * Copyright 2012-2014 Xiangfu <xiangfu@openmobilefree.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef _AVALON2_H_
#define _AVALON2_H_

#include "util.h"
#include "fpgautils.h"

#ifdef USE_AVALON2

#define AVA2_MINER_THREADS	1

#define AVA2_RESET_FAULT_DECISECONDS	10

#define AVALON2_TEMP_OVERHEAT	98
#define AVALON2_DEFAULT_POLLING_DELAY	20 /* ms */

/* Avalon2 protocol package type */
#define AVA2_H1	'A'
#define AVA2_H2	'V'

#define AVA2_P_COINBASE_SIZE	(6 * 1024)
#define AVA2_P_MERKLES_COUNT	20

#define AVA2_P_COUNT	39
#define AVA2_P_DATA_LEN		(AVA2_P_COUNT - 7)

#define AVA2_P_DETECT	10
#define AVA2_P_STATIC	11
#define AVA2_P_JOB_ID	12
#define AVA2_P_COINBASE	13
#define AVA2_P_MERKLES	14
#define AVA2_P_HEADER	15
#define AVA2_P_POLLING  16
#define AVA2_P_TARGET	17
#define AVA2_P_REQUIRE	18
#define AVA2_P_SET	19
#define AVA2_P_TEST	20

#define AVA2_P_ACK		21
#define AVA2_P_NAK		22
#define AVA2_P_NONCE		23
#define AVA2_P_STATUS		24
#define AVA2_P_ACKDETECT	25
#define AVA2_P_TEST_RET		26
#define AVA2_P_LONGCOINBASE	27
/* Avalon2 protocol package type */
#define AVA2_P_WORK		28

/* Avalon2/3 firmware prefix */
#define AVA2_FW2_PREFIXSTR	"20"
#define AVA2_FW3_PREFIXSTR	"33"

#define AVA2_MM_VERNULL		"NONE"

#define AVA2_ID_AVA2		3255
#define AVA2_ID_AVA3		3233
#define AVA2_ID_AVAX		3200

enum avalon2_fan_fixed {
	FAN_FIXED,
	FAN_AUTO,
};

struct avalon2_pkg {
	uint8_t head[2];
	uint8_t type;
	uint8_t idx;
	uint8_t cnt;
	uint8_t data[32];
	uint8_t crc[2];
};
#define avalon2_ret avalon2_pkg

struct avalon2_info {
	struct timeval last_stratum;

	char mm_version[16];
	int dev_type;

	int frequency;
	int temp;
	int hot;
};

#define AVA2_WRITE_SIZE (sizeof(struct avalon2_pkg))
#define AVA2_READ_SIZE AVA2_WRITE_SIZE

#define AVA2_GETS_OK 0
#define AVA2_GETS_TIMEOUT -1
#define AVA2_GETS_RESTART -2
#define AVA2_GETS_ERROR -3

#define AVA2_SEND_OK 0
#define AVA2_SEND_ERROR -1

#define avalon2_open(devpath, baud, purge)  serial_open(devpath, baud, AVA2_RESET_FAULT_DECISECONDS, purge)
#define avalon2_close(fd) close(fd)

extern char *set_avalon2_fan(char *arg);
extern char *set_avalon2_freq(char *arg);
extern char *set_avalon2_voltage(char *arg);
extern char *set_avalon2_fixed_speed(enum avalon2_fan_fixed *f);
extern enum avalon2_fan_fixed opt_avalon2_fan_fixed;
extern int opt_avalon2_overheat;
extern int opt_avalon2_polling_delay;
#endif /* USE_AVALON2 */
#endif	/* _AVALON2_H_ */
