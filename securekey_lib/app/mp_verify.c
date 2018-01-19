/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/sha.h>

uint8_t get_data_from_file(const char *file_ptr, uint8_t *ptr, uint8_t data_len)
{
	FILE *fptr;
	void *data = (void *)ptr;
	uint8_t ncount;

	fptr = fopen(file_ptr, "rb");
	if (fptr == NULL) {
		printf("File does not exists\n");
		return -1;
	}

	ncount = fread(data, 1, data_len, fptr);
	if (ncount != data_len) {
		printf("data_len and length of data read is not same\n");
		return -1;
	}
	return 0;
}

/* This function will fill the buffers provided with data read from corresponding
  * files
  */
uint8_t fill_data_from_file(const char *pub_key_file, const char *sig_file,
		const char *mtag_file, uint8_t *pub_key, uint8_t *sign,
		uint8_t *mtag, uint8_t pub_key_len, uint8_t sign_len,
		uint8_t mtag_len)
{
	int ret, i = 0;

	/* Read Public key from pub_key file */
	ret = get_data_from_file(pub_key_file,
			pub_key, pub_key_len);
	if (ret)
		return -1;

	printf("Pub Key read from file = ");
	for (i = 0; i < pub_key_len; i++)
		printf("%02x", *(pub_key + i));

	printf("\n");

	/* Read Signature from sig_file */
	ret = get_data_from_file(sig_file,
			sign, sign_len);
	if (ret)
		return -1;

	printf("Signature read from file = ");
	for (i = 0; i < sign_len; i++)
		printf("%02x", *(sign + i));

	printf("\n");

	/* Read mtag from mtag_file */
	ret = get_data_from_file(mtag_file,
			mtag, mtag_len);
	if (ret)
		return -1;

	printf("Mtag read from file = ");
	for (i = 0; i < mtag_len; i++)
		printf("%02x", *(mtag + i));

	printf("\n");

	return 0;

}

uint8_t verify_signature(const char *pub_key_file, const char *sig_file,
		const char *mtag_file, char *msg_ptr)
{
	int ret;
	uint8_t *pub_key, *sign, *mtag, *temp, *msg;
	uint32_t *mtag_temp;
	uint8_t pub_key_len, sign_len, mtag_len, msg_len;
	int i = 0, total_sz;

	pub_key_len = 64;
	sign_len = 64;
	mtag_len = 32;
	msg_len = strlen(msg_ptr);
	msg = msg_ptr;

	total_sz = pub_key_len + sign_len + mtag_len;

	/* Allocate memory for Public key, Signature, mtag to be read from files */
	temp = (uint8_t *)malloc(total_sz);
	if (!temp) {
		printf("malloc failed\n");
		ret = -1;
		goto err;
	}

	pub_key = temp;
	sign = pub_key + pub_key_len;
	mtag = sign + sign_len;

	/* This function will fill the buffers provided with data read from corresponding
	  * files
	  */
	ret = fill_data_from_file(pub_key_file, sig_file, mtag_file,
		pub_key, sign, mtag, pub_key_len, sign_len, mtag_len);
	if (ret) {
		printf("fill_data_from_file failed\n");
		ret = -1;
		goto err1;
	}

	/* Making the OpenSSL structures to verify the signature uisng
	* OpenSSL to check the interoperability
	* Init empty OpenSSL EC keypair of prime256*/
	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	BIGNUM *X;
	BIGNUM *Y;

	/*X co-ordinate of pub key*/
	if ((X = BN_new()) == NULL) {
		printf("BN_new failed for X\n");
		ret = -1;
		goto err1;
	}

	if (NULL == BN_bin2bn(pub_key, 32, X)) {
		printf("BN_bin2bn failed for X\n");
		ret = -1;
		goto err2;
	}

	/*Y coordinate of public key*/
	if ((Y = BN_new()) == NULL) {
		printf("BN_new failed for Y\n");
		ret = -1;
		goto err2;
	}

	/* Since we saved the pub_key in format of x followed by y,
	  * so data read from file will be having first 32 bytes of x and
	  * next 32 bytes of y component of Public key.
	  */
	if (NULL == BN_bin2bn(pub_key + 32, 32, Y)) {
		printf("BN_bin2bn failed for Y\n");
		ret = -1;
		goto err3;
	}

	/* Create an OpenSSL EC key using X and Y*/
	if (EC_KEY_set_public_key_affine_coordinates(eckey, X, Y) != 1) {
		printf("EC key generation failed\n");
		ret = -1;
		goto err3;
	}

	/* Creating a new OpenSSL Signature structure from data read from
	  *  signature file.
	  */
	ECDSA_SIG *signature = ECDSA_SIG_new();

	signature->r = BN_new();
	if (signature->r == NULL) {
		printf("BN_new failed for signature->r\n");
		ret = -1;
		goto err4;
	}
	if (NULL == BN_bin2bn(sign, 32, signature->r)) {
		printf("BN_bin2bn failed for signature->r\n");
		ret = -1;
		goto err5;
	}


	if ((signature->s = BN_new()) == NULL) {
		printf("BN_new failed for signature->s\n");
		ret = -1;
		goto err5;
	}
	/* Since we saved the signature in format of r followed by s,
	  * so data read from file will be having first 32 bytes of r and
	  * next 32 bytes of r component of Signature.
	  */
	if (NULL == BN_bin2bn(sign + 32, 32, signature->s)) {
		printf("BN_bin2bn failed for signature->s\n");
		ret = -1;
		goto err6;
	}

	/* Since CAAM calculated the hash after prepending the Msg with
	  * Mtag, So here allocating a temporary buffer to copy the msg and
	  * mtag in same buffer for Hash calculation */
	uint8_t *mp_temp = malloc(mtag_len + msg_len);

	if (!mp_temp) {
		printf("malloc failed\n");
		ret = -1;
		goto err6;
	}

	/* Prepending the mtag before msg for hash calculation */
	memcpy(mp_temp, mtag, mtag_len);
	memcpy(mp_temp + mtag_len, msg, msg_len);

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;

	SHA256_Init(&sha256);
	SHA256_Update(&sha256, (void *)mp_temp, mtag_len + msg_len);
	SHA256_Final(hash, &sha256);

	/* Hash generated using the OpenSSL Library */
	printf("\nGenerated Hash = ");
	for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);

	printf("\n");

	/* Using the OpenSSL generated hash for signature verification */
	if (ECDSA_do_verify(hash, 32, signature, eckey) == 1) {
		printf("Verifed EC Signature\n");
	} else {
		printf("Not Verified EC Signature\n");
		ret = -1;
		goto err7;
	}

	ret = 0;

err7:
	free(mp_temp);
err6:
	BN_free(signature->s);
err5:
	BN_free(signature->r);
err4:
	EC_KEY_free(eckey);
err3:
	BN_free(Y);
err2:
	BN_free(X);
err1:
	free(temp);
err:
	return ret;
}

int main(int argc, char **argv)
{
	char *cvalue = NULL;
	int index;
	int c, ret = 0;
	char *pub_key_fptr, *sign_fptr, *mtag_fptr, *msg;

	opterr = 0;

	while ((c = getopt (argc, argv, "p:s:m:M:")) != -1)
		switch (c)
		{
			case 'p':
				pub_key_fptr = optarg;
				break;
			case 's':
				sign_fptr = optarg;
				break;
			case 'm':
				mtag_fptr = optarg;
				break;
			case 'M':
				msg = optarg;
				break;
			case '?':
				if (optopt == 'p' || optopt == 'd' || optopt == 's' || optopt == 'm' || optopt == 'M')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n",
							optopt);
				return 1;
			default:
				abort();
		}

	for (index = optind; index < argc; index++)
		printf("Non-option argument %s\n", argv[index]);

	printf("pub key file = %s, sign file = %s, mtag file = %s, Message = %s\n",
			pub_key_fptr, sign_fptr, mtag_fptr, msg);

	ret = verify_signature(pub_key_fptr, sign_fptr, mtag_fptr, msg);
	if (ret)
		printf("Verification failed\n");
	else
		printf("Verification successful\n");

	return ret;
}
