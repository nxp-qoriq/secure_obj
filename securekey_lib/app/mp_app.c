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

#include <securekey_api.h>

/* This function gets the MP Public key and dumps it in a file */
uint8_t get_mp_pub_key(void)
{
	int ret = 0;
	uint8_t *temp;
	enum sk_status_code ret_status;
	struct sk_EC_point pub_key_req;
	uint8_t pub_key_len;
	FILE *fptr;

	pub_key_len = sk_mp_get_pub_key_len();
	temp = (uint8_t *)malloc(2 * pub_key_len);
	if (!temp) {
		printf("%s, %d malloc failed\n", __func__, __LINE__);
		ret = -1;
		goto temp_malloc_fail;
	}

	pub_key_req.len = pub_key_len;

	pub_key_req.x = temp;
	pub_key_req.y = temp + pub_key_req.len;

	printf("Generating the MP Public Key\n");
	ret_status = sk_mp_get_pub_key(&pub_key_req);
	if (ret_status) {
		printf("%s", sk_translate_error_code(ret_status));
		ret = ret_status;
		goto pub_key_get_failed;
	}

	fptr = fopen("pub_key", "wb");
	if (fptr == NULL) {
		printf("File does not exists\n");
		goto file_open_failed;
	}

	int i = 0;

	printf("Public key x part = ");
	for (i = 0; i < pub_key_len; i++)
		printf("%02x", *(pub_key_req.x + i));

	fwrite((void *)pub_key_req.x, 1, pub_key_len, fptr);
	fseek(fptr, 0, SEEK_END);

	printf("\n");
	printf("Public key y part = ");
	for (i = 0; i < pub_key_len; i++)
		printf("%02x", *(pub_key_req.y + i));

	printf("\n");

	fwrite((void *)pub_key_req.y, 1, pub_key_len, fptr);
	fclose(fptr);
	printf("Public key in form of x followed by y is saved in pub_key file\n");
	ret = 0;

file_open_failed:
pub_key_get_failed:
	free(temp);
temp_malloc_fail:
	return ret;
}

/* This function sign the message and dumps Signature in a file */
uint8_t sign_msg(char *msg_ptr)
{
	int i = 0, ret = 0;
	uint8_t *temp;
	enum sk_status_code ret_status;
	uint8_t *msg, *digest, *sig_r, *sig_s;
	uint8_t digest_len, sig_len, msg_len;
	struct sk_EC_sig sign_req;
	FILE *fptr;

	msg_len = strlen(msg_ptr);
	digest_len = sk_mp_get_digest_len();
	sig_len = sk_mp_get_sig_len();

	temp = (uint8_t  *)malloc(msg_len + digest_len
			+ (2 * sig_len));
	if (!temp) {
		printf("malloc failed\n");
		ret = -1;
		goto temp_malloc_fail;
	}

	msg = temp;
	digest = temp + msg_len;
	sign_req.r = digest + digest_len;
	sign_req.s = sign_req.r + sig_len;

	sign_req.len = sig_len;

	memcpy(msg, msg_ptr, msg_len);

	printf("\nSigning message  '%s' with MP Priv Key\n", msg);
	printf("%s in Hex = ", msg);
	for (i = 0; i < msg_len; i++)
		printf("%02x", msg[i]);

	ret_status = sk_mp_sign(msg, msg_len, &sign_req, digest, digest_len);
	if (ret_status) {
		printf("sk_mp_sign failed\n");
		ret = -1;
		goto mp_sign_fail;
	}

	fptr = fopen("signature", "wb");
	if (fptr == NULL) {
		printf("File does not exists\n");
		goto file_open_failed;
	}

	printf("\nGenerated Hash = ");
	for (i = 0; i < digest_len; i++)
		printf("%02x", *(digest + i));

	printf("\n");
	printf("Signature part r = ");
	for (i = 0; i < sig_len; i++)
		printf("%02x", *(sign_req.r + i));

	fwrite((void *)sign_req.r, 1, sig_len, fptr);
	fseek(fptr, 0, SEEK_END);

	printf("\n");
	printf("Signature part s = ");
	for (i = 0; i < sig_len; i++)
		printf("%02x", *(sign_req.s + i));

	fwrite((void *)sign_req.s, 1, sig_len, fptr);
	printf("\n");
	fclose(fptr);

	printf("Signature in form of r followed by s is saved in signature file\n");
	ret = 0;

file_open_failed:
mp_sign_fail:
	free(temp);
temp_malloc_fail:
	return ret;
}

/* OEMID Length varies from board to board, So keeping it max of 32 bytes*/
#define OEM_ID_BUF_LEN	32
/* This function gets the OEMID and dumps it in a file */
uint8_t get_oemid(void)
{
	uint8_t ret = 0, i;
	uint8_t *oem_id;
	uint8_t oem_id_len;
	FILE *fptr;

	oem_id = (uint8_t *)malloc(OEM_ID_BUF_LEN);
	if (!oem_id) {
		printf("malloc failed\n");
		ret = -1;
		goto mp_tag_malloc_fail;
	}

	memset((void *)oem_id, 0, OEM_ID_BUF_LEN);

	/* sk_get_oemid will fill the oem_id_len with actual length filled
	*  in oem_id buffer */
	if (sk_get_oemid(oem_id, &oem_id_len)) {
		printf("sk_get_fuid failed\n");
		goto sk_get_oemid_fail;
	}

	fptr = fopen("oemid", "wb");
	if (fptr == NULL) {
		printf("File does not exists\n");
		goto file_open_failed;
	}

	printf("\nOEM ID = ");
	for (i = 0; i < oem_id_len; i++)
		printf("%02x", oem_id[i]);
	printf("\n");

	fwrite(oem_id, 1,  oem_id_len, fptr);
	fclose(fptr);

	printf("OEM ID is saved in oemid file\n");
	ret = 0;

file_open_failed:
sk_get_oemid_fail:
	free(oem_id);
mp_tag_malloc_fail:
	return ret;
}

/* This function gets the FUID and dumps it in a file */
uint8_t get_fuid(void)
{
	uint8_t ret = 0, i;
	uint8_t *fuid;
	uint8_t fuid_len;
	FILE *fptr;

	fuid_len = sk_get_fuid_len();
	fuid = (uint8_t *)malloc(fuid_len);
	if (!fuid) {
		printf("malloc failed\n");
		ret = -1;
		goto fuid_malloc_fail;
	}

	memset((void *)fuid, 0, fuid_len);

	if (sk_get_fuid(fuid)) {
		printf("sk_get_fuid failed\n");
		goto sk_get_fuid_fail;
	}

	fptr = fopen("fuid", "wb");
	if (fptr == NULL) {
		printf("File does not exists\n");
		goto file_open_failed;
	}

	printf("\nFUID = ");
	for (i = 0; i < fuid_len; i++)
		printf("%02x", fuid[i]);
	printf("\n");

	fwrite(fuid, 1, fuid_len, fptr);
	fclose(fptr);

	printf("FUID is saved in fuid file\n");
	ret = 0;

file_open_failed:
sk_get_fuid_fail:
	free(fuid);
fuid_malloc_fail:
	return ret;
}

/* This function gets the MP Message and dumps it in a file */
uint8_t get_mp_tag(void)
{
	uint8_t ret = 0, i;
	uint8_t *mp_tag;
	uint8_t mp_tag_len;
	FILE *fptr;

	mp_tag_len = sk_mp_get_tag_len();
	mp_tag = (uint8_t *)malloc(mp_tag_len);
	if (!mp_tag) {
		printf("malloc failed\n");
		ret = -1;
		goto mp_tag_malloc_fail;
	}

	memset((void *)mp_tag, 0, mp_tag_len);

	if (sk_mp_get_mp_tag(mp_tag, mp_tag_len)) {
		printf("sk_mp_get_mp_tag failed\n");
		goto sk_mp_get_mp_tag_fail;
	}

	fptr = fopen("mtag", "wb");
	if (fptr == NULL) {
		printf("File does not exists\n");
		goto file_open_failed;
	}

	printf("\nMP Tag = ");
	for (i = 0; i < mp_tag_len; i++)
		printf("%02x", mp_tag[i]);
	printf("\n");

	fwrite(mp_tag, 1, mp_tag_len, fptr);
	fclose(fptr);

	printf("MP Tag is saved in mptag file\n");
	ret = 0;

file_open_failed:
sk_mp_get_mp_tag_fail:
	free(mp_tag);
mp_tag_malloc_fail:
	return ret;
}

int main(int argc, char **argv)
{
	enum sk_status_code ret_status;
	char *cvalue = NULL;
	int index;
	int c, ret = 0;

	opterr = 0;

	ret_status = sk_lib_init();
	if (ret_status == SK_FAILURE) {
		printf("sk_lib_init failed\n");
		return -1;
	}

	while((c = getopt (argc, argv, "pms:fo")) != -1) {
		switch (c) {
			case 'p':
				ret = get_mp_pub_key();
				if (ret)
					printf("get_mp_pub_key failed\n");
				break;
			case 'm':
				ret = get_mp_tag();
				if (ret)
					printf("get_mp_tag failed\n");
				break;
			case 's':
				cvalue = optarg;
				ret = sign_msg(cvalue);
				if (ret)
					printf("sign_msg failed\n");
				break;
			case 'f':
				ret = get_fuid();
				if (ret)
					printf("get_fuid failed\n");
				break;
			case 'o':
				ret = get_oemid();
				if (ret)
					printf("get_oemid failed\n");
				break;

			case '?':
				if (optopt == 's')
					fprintf(stderr, "Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf(stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf(stderr, "Unknown option character `\\x%x'.\n",
							optopt);
				return 1;
			default:
				abort ();
		}
	}

	sk_lib_exit();

	for (index = optind; index < argc; index++)
		printf("Non-option argument %s\n", argv[index]);
	return ret;
}
