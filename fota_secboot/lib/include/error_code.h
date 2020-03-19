// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#ifndef ERROR_CODE_H
#define ERROR_CODE_H

#include "common.h"

#define ERROR_ESBC_CLIENT_HEADER_BARKER				0x01
#define ERROR_KEY_TABLE_NOT_FOUND				0x02
#define ERROR_ESBC_CLIENT_HEADER_SIG_LEN			0x03
#define ERROR_ESBC_CLIENT_HEADER_KEY_LEN_NOT_TWICE_SIG_LEN	0x04
#define ERROR_ESBC_CLIENT_HEADER_KEY_MOD_1			0x05
#define ERROR_ESBC_CLIENT_HEADER_KEY_MOD_2			0x06
#define ERROR_ESBC_CLIENT_HEADER_SIG_KEY_MOD			0x07
#define ERROR_INVALID_BIN_HDR_PATH				0x08
#define ERROR_MEMORY_ALLOCATION_FAIL				0x09
#define ERROR_FILE_READ_FAILURE					0x0A
#define ERROR_ESBC_CLIENT_HASH_COMPARE_KEY			0x0B
#define FILE_OPENING_FAILURE					0x0C
#define ERROR_INVALID_BIN_SIZE					0x0D
#define DEV_FILE_OPENING_FAILURE				0x0E
#define ERROR_FAILED_HEADER_VALIDATION				0x0F
#define ERROR_ESBC_CLIENT_HEADER_KEY_LEN			0x10
#define ERROR_ESBC_CLIENT_HEADER_INVALID_SRK_NUM_ENTRY          0x20
#define ERROR_ESBC_CLIENT_HEADER_INVALID_KEY_NUM                0x21
#define  ERROR_ESBC_CLIENT_HEADER_KEY_REVOKED			0x22
#define ERROR_ESBC_CLIENT_HEADER_INV_SRK_ENTRY_KEYLEN		0x23
#define ERROR_NOT_AUTHENTIC_IMAGES				0x24

#define ERROR_ESBC_CLIENT_MAX					0x40

struct fota_err_code {
	int errcode;
	const char *name;
};

static struct fota_err_code err_code[] = {
	{ ERROR_ESBC_CLIENT_HEADER_BARKER,
		"Wrong barker code in header" },
	{ ERROR_KEY_TABLE_NOT_FOUND,
		"No Key/ Key Table Found in header"},
	{ ERROR_ESBC_CLIENT_HEADER_SIG_LEN,
		"Wrong signature length in header" },
	{ ERROR_ESBC_CLIENT_HEADER_KEY_LEN_NOT_TWICE_SIG_LEN,
		"Public key length not twice of signature length" },
	{ ERROR_ESBC_CLIENT_HEADER_KEY_MOD_1,
		"Public key Modulus most significant bit not set" },
	{ ERROR_ESBC_CLIENT_HEADER_KEY_MOD_2,
		"Public key Modulus in header not odd" },
	{ ERROR_ESBC_CLIENT_HEADER_SIG_KEY_MOD,
		"Signature not less than modulus" },
	{ ERROR_INVALID_BIN_HDR_PATH,
		"Header path and bin path in not valid"},
	{ ERROR_MEMORY_ALLOCATION_FAIL,
		"Failed to allocate memory"},
	{ ERROR_INVALID_BIN_SIZE,
		"Invalid image binary size"},
	{ FILE_OPENING_FAILURE,
		"Unable to open requested file"},
	{ DEV_FILE_OPENING_FAILURE,
		"Unable to open /dev/mem file"},
	{ ERROR_FAILED_HEADER_VALIDATION,
		"Invalid image binary size"},
	{ ERROR_ESBC_CLIENT_HEADER_KEY_LEN,
		"Invalid public key length"},
	{ ERROR_FILE_READ_FAILURE,
		"Failed to read data from file stram"},
	{ ERROR_ESBC_CLIENT_HASH_COMPARE_KEY,
		"Key hash comparison failed"},
	{ ERROR_ESBC_CLIENT_HEADER_INVALID_SRK_NUM_ENTRY,
		"Wrong key entry" },
	{ ERROR_ESBC_CLIENT_HEADER_INVALID_KEY_NUM,
		"Wrong key is selected" },
	{ ERROR_ESBC_CLIENT_HEADER_KEY_REVOKED,
		"Selected IE key is revoked" },
	{ ERROR_ESBC_CLIENT_HEADER_INV_SRK_ENTRY_KEYLEN,
		"Wrong IE public key len in header" },
	{ ERROR_NOT_AUTHENTIC_IMAGES,
		"Provided imaged are not authentic" },
	{ ERROR_ESBC_CLIENT_MAX, "NULL" }
};

/*Will print the error message, based on the error code received*/
static inline void fota_handle_error(int error)
{
	const struct fota_err_code *e;

	for (e = err_code; e->errcode != ERROR_ESBC_CLIENT_MAX;
			e++) {
		if (e->errcode == error)
			printf("ERROR :: %x :: %s\n", error, e->name);
	}
}

#endif
