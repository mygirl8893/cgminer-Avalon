/*
 * Copyright 2016 Mikeqin <Fengling.Qin@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */
#ifndef LIBSSPLUS_H
#define LIBSSPLUS_H

struct hasher_point {
	uint32_t nonce2;
	uint32_t tail;
};

void sorter_init(void);
int sorter_get_pair(uint32_t n2_pair[]);
void hasher_init(void);
void hasher_update_stratum(bool clean);

#endif /* LIBSSPLUS_H */
