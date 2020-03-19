// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include "config.h"
#include "hash.h"
#include "error_code.h"

#define SWAP_32(x) \
	((((x) & 0xff000000) >> 24) | \
	 (((x) & 0x00ff0000) >> 8) | \
	 (((x) & 0x0000ff00) << 8) | \
	 (((x) & 0x000000ff) << 24))

#ifdef BIG_ENDIAN
#define sfp_in32(addr)          (*(volatile unsigned int *)(addr))
#define sfp_in8(addr)           (*(volatile unsigned char *)(addr))
#else
#define sfp_in32(addr)          SWAP_32((*(volatile unsigned int *)(addr)))
#endif

#endif
