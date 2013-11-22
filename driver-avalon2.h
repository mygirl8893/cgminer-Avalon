/*
 * Copyright 2013 Avalon project
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

#define AVA2_RESET_FAULT_DECISECONDS 10
#define AVA2_MINER_THREADS	1
#define AVA2_IO_SPEED	115200
#define AVA2_DEFAULT_MINER_NUM	32
#define AVA2_DEFAULT_FAN_MIN_PWM 0xff;

/* Avalon2 protocol package type */
#define AVA2_H1	'A'
#define AVA2_H2	'V'

#define AVA2_T1	'O'
#define AVA2_T2	'N'

#define AVA2_P_COUNT		41

#define AVA2_P_ERROR	0

#define AVA2_P_DETECT	10
#define AVA2_P_STATIC	11
#define AVA2_P_JOB_ID	12
#define AVA2_P_COINBASE	13
#define AVA2_P_MERKLES	14

#define AVA2_P_ACK		21
#define AVA2_P_NAK		22
#define AVA2_P_NONCE		23
#define AVA2_P_HEARTBEAT	24
#define AVA2_P_ACKDETECT	25

struct avalon2_pkg {
	uint8_t head[2];
	uint8_t type;
	uint8_t idx;
	uint8_t cnt;
	uint8_t data[32];
	uint8_t crc[2];
	uint8_t tail[2];
};
#define avalon2_ret avalon2_pkg

struct avalon2_info {
	int baud;
	int miner_count;
	int asic_count;
	int timeout;
	int frequency;

	int fan0;
	int fan1;
	int fan2;
	int fan_pwm;

	int temp0;
	int temp1;
	int temp2;

	int temp_max;
	int temp_history_count;
	int temp_history_index;
	int temp_sum;
	int temp_old;

	int no_matching_work;
	int matching_work[AVA2_DEFAULT_MINER_NUM];
};

#define AVA2_WRITE_SIZE (sizeof(struct avalon2_pkg))
#define AVA2_READ_SIZE AVA2_WRITE_SIZE

#define AVA2_GETS_ERROR -1
#define AVA2_GETS_OK 0
#define AVA2_GETS_RESTART 1
#define AVA2_GETS_TIMEOUT 2

#define AVA2_SEND_ERROR -1
#define AVA2_SEND_OK 0

#define avalon2_open(devpath, baud, purge)  serial_open(devpath, baud, AVA2_RESET_FAULT_DECISECONDS, purge)
#define avalon2_close(fd) close(fd)

extern struct avalon2_info **avalon2_info;

#endif /* USE_AVALON2 */
#endif	/* _AVALON2_H_ */
