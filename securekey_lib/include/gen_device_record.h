
/*
 * Copyright 2019 NXP
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __HEADER_DEVICE_RECORD_H__
#define __HEADER_DEVICE_RECORD_H__

#define SFP_BASE_ADDRESS	0x01E80000

// Define the number of register for
// FUID: NXP UID.
// OEMID: Original equipment mfg ID.
// FSWPR: NXP section Write protect register.
// SRKH: Super root key hash.
// OSPR: OEM security policy register.
// MTAG

#define FUID_REG_NUM		2
#define OEM_ID_REG_NUM		5
#define FSPWR_REG_NUM		1
#define SRKH_REG_NUM		8
#define OSPR_REG_NUM		2
#define MPTAG_REG_NUM		8

// Define the size of a word in bytes
#define WORD_SIZE_IN_BYTES	4

#define ERROR_MALLOC		-2
#define ERROR_FILE_OPEN		-3
#define ERROR_MEMORY_PTR	-4
#define ERROR_SK_INIT_FAIL	-5

#define ERROR_SK_OEM_ID		-10
#define ERROR_SK_FUID		-11
#define ERROR_SK_MP_SIGN	-12
#define ERROR_SK_MP_TAG		-13
#define ERROR_SVR_READ_FAIL	-14

#define MAX_BUFFER_MSG_LEN	512

#define SVR_VALUE_MASK		0xffff0000
#define SVR_VAL_LS1046A		0x87070000
#define SVR_VAL_LS1088A		0x87030000
#define SVR_VAL_LS1043A		0x87920000
#define SVR_VAL_LS2088A		0x87090000
#define SVR_VAL_LS2080A		0x87010000
#define SVR_VAL_LX2160A		0x87360000

#define SWAP_32(x) \
		((((x) & 0xff000000) >> 24)  |	\
		 (((x) & 0x00ff0000) >> 8)   |	\
		 (((x) & 0x0000ff00) << 8)   |	\
		 (((x) & 0x000000ff) << 24))

struct sfp_regs {
	uint32_t res[128];
	uint32_t ospr[2];             /* 0x200 OEM Security Policy Register 0 */
	uint32_t reserved1[4];
	uint32_t fswpr[1];              /* 0x218 FSL Section Write Protect */
	uint32_t fsl_uid[2];          /* 0x21c FSL UID 0 */
	uint32_t reserved2[12];
	uint8_t srk_hash[32];        /* 0x254 Super Root Key Hash */
	uint32_t oem_uid[5];          /* 0x274 OEM UID 0*/
};
#endif
