// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#ifndef CONFIG_H
#define CONFIG_H

typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned short int u16;
typedef unsigned long u64;
typedef u32 uint32_t;
typedef unsigned long   uintptr_t;
typedef enum{true, false} bool;

#define FAIL	-1
#define PASS	 0

#define ESBC_BARKER_LEN 4
#define MAX_SG_ENTRIES  8
#define KEY_SIZE       4096
#define KEY_SIZE_BYTES (KEY_SIZE/8)
#define KEY_SIZE_WORDS (KEY_SIZE_BYTES/(WORD_SIZE))
#define SHA256_BYTES    (256/8)

#define SRK_FLAG        0x01
#define UNREVOCABLE_KEY 4
#define ALIGN_REVOC_KEY 3
#define MAX_KEY_ENTRIES 4
#define NUM_SRKH_REGS   8
#define IE_FLAG_MASK 0x01

#define MAX_HDR_SIZE            0x1000
#define CCSR_SFP_BASEADDR 0x200
#define DDR_FILE_NAME "/dev/mem"
#define CHECK_KEY_LEN(key_len)	(((key_len) == (2 * KEY_SIZE_BYTES) / 4) || \
				((key_len) == (2 * KEY_SIZE_BYTES) / 2) || \
				((key_len) == (2 * KEY_SIZE_BYTES)))

#ifdef LA1043A
#define CONFIG_SYS_SFP_ADDR	0x01E80000
#define OSPR_KEY_REVOC_SHIFT	9
#define OSPR_KEY_REVOC_MASK	0x0000fe00

struct ccsr_sfp_regs {
	u32 ospr;		/* 0x200 */
	u32 ospr1;		/* 0x204 */
	u32 reserved1[4];
	u32 fswpr;              /* 0x218 FSL Section Write Protect */
	u32 fsl_uid;            /* 0x21c FSL UID 0 */
	u32 fsl_uid_1;          /* 0x220 FSL UID 0 */
	u32 reserved2[12];
	u32 srk_hash[8];        /* 0x254 Super Root Key Hash */
	u32 oem_uid;            /* 0x274 OEM UID 0*/
	u32 oem_uid_1;          /* 0x278 OEM UID 1*/
	u32 oem_uid_2;          /* 0x27c OEM UID 2*/
	u32 oem_uid_3;          /* 0x280 OEM UID 3*/
	u32 oem_uid_4;          /* 0x284 OEM UID 4*/
	u32 reserved3[8];
};
#endif

struct srk_table {
	u32 key_len;
	u8 pkey[2 * KEY_SIZE_BYTES];
};

struct fsl_secboot_sg_table {
	u32 len;                /* length of the segment in bytes */
	u32 src_addr;           /* ptr to the data segment */
};

struct fsl_secboot_img_hdr {
	u8 barker[ESBC_BARKER_LEN];     /* 0x00 Barker code */
	union{
		u32 pkey;
		u32 srk_tbl_off;      /* SRK Table Offset */
	};

	union {
		u32 key_len;
		struct {
			u8 srk_flag;
			u8 srk_sel;
			u8 num_srk;
			u8 reserve;
		} len_kr;		/* 0x08 */
	};

	uint32_t psign;                 /* 0x0c signature offset */
	uint32_t sign_len;              /* 0x10 length of signature */

	uint32_t reserved;              /* 0x14 Reserved*/
	uint32_t img_size;              /* 0x18 Size of Image */
	uint32_t res1[2];               /* 0x1c, 0x20 Reserved */

	uint32_t uid_flag;              /* 0x24 Flag to indicate uid */

	uint32_t fsl_uid_0;             /* 0x28 Freescale unique id */
	uint32_t oem_uid_0;             /* 0x2c OEM unique id */

	uint32_t res2[2];               /* 0x30, 0x34 */

	uint32_t fsl_uid_1;             /* 0x38 Freescale unique id */
	uint32_t oem_uid_1;             /* 0x3c OEM unique id */

	uint32_t pimg_low;              /* 0x40 ptr to Image */
	uint32_t pimg_high;             /* 0x44 ptr to Image */

	uint32_t ie_flag;               /* 0x48 IE Flag */
	uint32_t ie_key_select;         /* 0x4c IE Key Select */
};

/*
 * ESBC private structure.
 * Private structure used by ESBC to store following fields
 * ESBC client key
 * ESBC client key hash
 * ESBC client Signature
 * Encoded hash recovered from signature
 * Encoded hash of ESBC client header plus ESBC client image
 */

struct fsl_secboot_img {
	u32 key_len;
	struct fsl_secboot_img_hdr hdr;

	u8 img_key[2 * KEY_SIZE_BYTES]; /* ESBC client key */
	u8 img_key_hash[32];    /* ESBC client key hash */

	struct srk_table srk_tbl[MAX_KEY_ENTRIES];
	u8 img_sign[KEY_SIZE_BYTES];            /* ESBC client signature */

	u8 img_encoded_hash[KEY_SIZE_BYTES];    /* EM wrt RSA PKCSv1.5  */
	/* Includes hash recovered after
	 * signature verification
	 */

	u8 img_encoded_hash_second[KEY_SIZE_BYTES];/* EM' wrt RSA PKCSv1.5 */
	/* Includes hash of
	 * ESBC client header plus
	 * ESBC client image
	 */

	struct fsl_secboot_sg_table sgtbl[MAX_SG_ENTRIES];      /* SG table */
	FILE *fp;
};

static inline u32 get_key_len(struct fsl_secboot_img *img)
{
	return img->key_len;
}

#endif
