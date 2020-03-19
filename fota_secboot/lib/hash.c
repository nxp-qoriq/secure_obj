// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#include "common.h"
#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>


#define CRYPTO_HASH_CTX_SIZE	0x400
#define SHA256_DIGEST_LENGTH	32

/***************************************************************************
 * Function     :       calc_img_key_hash
 * Arguments    :       img: base address of allocated struct
 *                      fsl_secboot_img
 * Return       :       0 - Success
 * Description  :       This function will calculate the srk key hash or public
 *			key hash, based on SRK flag.
 *
 ***************************************************************************/
int calc_img_key_hash(struct fsl_secboot_img *img)
{

	u8 ctx[CRYPTO_HASH_CTX_SIZE];
	SHA256_CTX *c = (SHA256_CTX *)ctx;

	SHA256_Init(c);
	if (img->hdr.len_kr.srk_flag & SRK_FLAG) {
		SHA256_Update(c, &img->srk_tbl,
			img->hdr.len_kr.num_srk * sizeof(struct srk_table));
	} else {
		SHA256_Update(c, &img->img_key,
				img->hdr.key_len);
	}
	SHA256_Final((unsigned char *)&img->img_key_hash, c);
	return 0;
}

/***************************************************************************
 * Function	:       calculate_cmp_img_sig
 * Arguments	:       img: base address of allocated struct
 *                      fsl_secboot_img
 * Return	:       0 - Success, Else return error code
 * Description	:	This function calculate hash over srk key, ESBC header,
 *			Image and decrypt the signature using public key and
 *			compare there to hash, return the result
 ***************************************************************************/
int calculate_cmp_img_sig(struct fsl_secboot_img *img, u8 *img_buf, int size)
{
	RSA *rsa_img_key = RSA_new();
	int rsa_key_size = img->key_len/2;
	u8 ctx[CRYPTO_HASH_CTX_SIZE];
	SHA256_CTX *c = (SHA256_CTX *)ctx;

	SHA256_Init(c);

	SHA256_Update(c, &img->hdr, sizeof(struct fsl_secboot_img_hdr));
	if (img->hdr.len_kr.srk_flag & SRK_FLAG) {
		SHA256_Update(c, &img->srk_tbl,
		img->hdr.len_kr.num_srk * sizeof(struct srk_table));
	} else {
		SHA256_Update(c, &img->img_key,
				img->hdr.key_len);
	}
	SHA256_Update(c, img_buf, size);

	SHA256_Final((unsigned char *)&img->img_encoded_hash_second, c);

#ifdef DEBUG
	u8 *p = (u8 *)&img->img_encoded_hash_second;
	int i;

	printf("Encoded hash val:\n");
	for (i = 0; i < 33; i++)
		printf("%x", p[i]);
	printf("\n");
#endif
	RSA_set0_key(rsa_img_key,
		BN_bin2bn((u8 *)img->img_key, rsa_key_size, NULL),
		BN_bin2bn((u8 *)&img->img_key[128], rsa_key_size, NULL),
		NULL);

	int result = RSA_verify(NID_sha256,
			(u8 *)&img->img_encoded_hash_second,
			32, (u8 *)&img->img_sign,
			img->hdr.sign_len, rsa_img_key);
#ifdef DEBUG
	printf("result: %d\n", result);
#endif
	if (!result)
		return ERROR_NOT_AUTHENTIC_IMAGES;
	else
		return 0;
}
