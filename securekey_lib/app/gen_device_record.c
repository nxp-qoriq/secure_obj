/*
 * Copyright 2019 NXP
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <securekey_api.h>
#include <gen_device_record.h>
#include <fcntl.h>
#include <endian.h>

char filename[50] = "device_fuse_record";

/* This function sign the message and dumps Signature in a file */
int sign_msg(char *msg_ptr, FILE *fptr)
{
	int i = 0, ret = 0;
	uint8_t *temp;
	enum sk_status_code ret_status;
	uint8_t *msg, *digest, *sig_r, *sig_s;
	uint8_t digest_len, sig_len, msg_len;
	struct sk_EC_sig sign_req;

	msg_len = strlen(msg_ptr);

	digest_len = sk_mp_get_digest_len();
	sig_len = sk_mp_get_sig_len();

	temp = (uint8_t  *)malloc(msg_len + digest_len
			+ (2 * sig_len));
	if (!temp) {
		printf("%s, %d memory failure\n", __func__, __LINE__);
		ret = ERROR_MALLOC;
		goto mp_sign_fail;
	}

	msg = temp;
	digest = temp + msg_len;
	sign_req.r = digest + digest_len;
	sign_req.s = sign_req.r + sig_len;

	sign_req.len = sig_len;

	memcpy(msg, msg_ptr, msg_len);

	ret_status = sk_mp_sign(msg, msg_len, &sign_req, digest, digest_len);
	if (ret_status) {
		printf("sk_mp_sign failed\n");
		ret = ERROR_SK_MP_SIGN;
		goto mp_sign_fail;
	}

	for (i = 0; i < sig_len; i++)
		fprintf(fptr, "%02x", *(sign_req.r + i));

	for (i = 0; i < sig_len; i++)
		fprintf(fptr, "%02x", *(sign_req.s + i));

mp_sign_fail:
	if(temp)
		free(temp);
	return ret;
}

int generate_message_from_record(char *msg, uint32_t msg_len)
{
	int idx = 0, i = 0, ret = 0;
	char temp[MAX_BUFFER_MSG_LEN];
	FILE *fptr;

	/* Read all the data from the record_file into temp buffer.
	 * Copy data from temp buffer to msg by removing all the delimiters
	 * such as :,_,' ',M
	 */

	fptr = fopen(filename, "r");
	if (!fptr) {
		printf("Unable to open the record file");
		ret = ERROR_FILE_OPEN;
		goto exit;
	}

	fread(temp, 1, MAX_BUFFER_MSG_LEN, fptr);

	for (i = 0; i < msg_len; ) {
		if (temp[idx] == ':' || temp[idx] == '_' || temp[idx] == ' ') {
			idx++;
		} else {
			msg[i] = temp[idx];
			idx++;
			i++;
		}
	}
	// Adding Null at the end of the string
	msg[i] = '\0';
exit:
	if (fptr)
		fclose(fptr);
	return ret;
}

int fill_data_in_record_file(uint32_t *value, int num, FILE *fptr,
			     int swap_flag)
{
	int ret = 0;

	if (fptr == NULL) {
		printf("File is not open to enter record data\n");
		ret = ERROR_FILE_OPEN;
		goto exit;
	}
	for (int i = 0; i < num; i++) {
		if (swap_flag == 1)
			fprintf(fptr, "%08x", SWAP_32(value[i]));
		else
			fprintf(fptr, "%08x", value[i]);

		if (i < num - 1)
			fprintf(fptr, "%s", "_");
	}

exit:
	return ret;
}

int fill_u8_data_in_record_file(uint8_t *value, int num, FILE *fptr)
{
	int ret = 0;

	if (fptr == NULL) {
		printf("File is not open to enter record data\n");
		ret = ERROR_FILE_OPEN;
		goto exit;
	}
	for (int i = 0; i < num; i++) {
		fprintf(fptr, "%02x", value[i]);

		if ((i + 1) % 4 == 0 && (i + 1) != num)
			fprintf(fptr, "%s", "_");
	}

exit:
	return ret;
}

int get_mp_tag(FILE *fptr)
{
	int ret = 0;
	uint8_t i;
	uint8_t *mp_tag;
	uint8_t mp_tag_len;

	if (fptr == NULL) {
		ret = ERROR_FILE_OPEN;
		goto mp_tag_exit;
	}

	mp_tag_len = sk_mp_get_tag_len();
	mp_tag = (uint8_t *)malloc(mp_tag_len);
	if (!mp_tag) {
		ret = ERROR_MALLOC;
		goto mp_tag_exit;
	}

	memset((void *)mp_tag, 0, mp_tag_len);

	if (sk_mp_get_mp_tag(mp_tag, mp_tag_len)) {
		ret = ERROR_SK_MP_TAG;
		goto mp_tag_exit;
	}

	for (i = 0; i < mp_tag_len; i++)
		fprintf(fptr, "%02x", mp_tag[i]);

mp_tag_exit:
	if (mp_tag)
		free(mp_tag);
	return ret;
}

int has_pattern_instart(char *line, char *pattern, char *value)
{
	size_t i = 0;
	size_t len = strlen(pattern);

	for (i = 0; i < len; i++) {
		if (line[i] != pattern[i])
			return 0;
	}

	for (i = 0; line[i] != '\0'; i++)
		value[i] = line[len + i];

	return 1;
}

void parse_pattern(char *pattern, FILE *fptr, char *value)
{
	size_t len = 0;
	size_t read_len, i;
	int pattern_found = 0;
	char *line = NULL;

	// idx to be checked first else an extra line will be read unnecessarily
	while (pattern_found == 0 && (read_len = getline(&line, &len, fptr)) != -1) {
		i = 0;
		pattern_found = has_pattern_instart(line, pattern, value);
		/*
		 * idx to store the value at the end of pattern in line or
		 * 0 if not found
		 */
	}
	if (line)
		free(line);
}

int check_device_endianness(void)
{
	FILE *ptr;
	char svr_value[18];
	int ret = 0, i = 0;
	unsigned long int svr = 0;
	char *tmp;

	ptr = fopen("/sys/devices/soc0/soc_id", "r");
	if (ptr == NULL) {
		ret = ERROR_FILE_OPEN;
		goto exit;
	}

	parse_pattern("svr:0x", ptr, svr_value);
	svr = strtoul((char *)svr_value, &tmp, 16);
	svr = svr & SVR_VALUE_MASK;

	if (svr == SVR_VAL_LS1046A || svr == SVR_VAL_LS1043A)
		ret = 1;
	else if (svr == SVR_VAL_LS2088A || svr == SVR_VAL_LS2080A ||
		 svr == SVR_VAL_LS1088A || svr == SVR_VAL_LX2160A)
		ret = 0;

exit:
	if (ptr)
		fclose(ptr);
	return ret;
}

int main(int argc, char **argv)
{
	FILE *fptr;
	enum sk_status_code ret_status;
	int ret = 0, tmp = 0;
	void *sfp_ptr;
	struct sfp_regs *sfp;
	int swap_flag = 0;
	int mem = 0;

	swap_flag = check_device_endianness();
	if (swap_flag < 0) {
		ret = ERROR_SVR_READ_FAIL;
		goto exit;
	}

	ret_status = sk_lib_init();
	if (ret_status == SK_FAILURE) {
		printf("sk_lib_init failed\n");
		ret = ERROR_SK_INIT_FAIL;
		goto exit;
	}
	/*
	 * msg_len is 2 times of complete message size because:
	 * each byte is stored as 2 charcters. ex: 0xe5 will be two characters
	 * 'e' and '5'
	 */
	uint32_t msg_len = 2 * ((FUID_REG_NUM + OEM_ID_REG_NUM +
				FSPWR_REG_NUM + SRKH_REG_NUM +
				OSPR_REG_NUM + MPTAG_REG_NUM) *
				WORD_SIZE_IN_BYTES);

	char *msg = (char *)malloc(msg_len);
	if (!msg) {
		printf("%s, %d memory failure\n", __func__, __LINE__);
		ret = ERROR_MALLOC;
		goto exit;
	}

	mem = open("/dev/mem", O_RDWR | O_SYNC);
	if (mem == -1) {
		printf("Cannot open /dev/mem\n");
		ret = -errno;
		goto exit;
	}

	sfp_ptr = mmap(0, 4096/*PAGE_SZ*/, PROT_READ | PROT_WRITE, MAP_SHARED, mem, SFP_BASE_ADDRESS);
	if (sfp_ptr == (void *)-1) {
		printf("Memory map failed.\n");
		ret = -errno;
		goto exit;
	}

	sfp = (struct sfp_regs *)sfp_ptr;

	/* The record file is in the format
	 * message:signature
	 * message is composed of FUID[0..1]:OEID[0..4]:FSWPR:SRKH[0..7]
	 * 			  :OSPR[0..1]:MPTAG[0..7]
	 * This message (in the same sequence as above)is signed in the
	 * same sequence
	 * Signature is added at the end of the message.
	 */

	fptr = fopen(filename, "w");
	if (fptr == NULL) {
		printf("Unable to open record_file.\n");
		ret = ERROR_FILE_OPEN;
		goto exit;
	}

	ret = fill_data_in_record_file(sfp->fsl_uid, FUID_REG_NUM, fptr, swap_flag);
	if (ret != 0)
		goto exit;

	fprintf(fptr, "%s", ":");

	ret = fill_data_in_record_file(sfp->oem_uid, OEM_ID_REG_NUM, fptr, swap_flag);
	if (ret != 0)
		goto exit;

	fprintf(fptr, "%s", ":");

	ret = fill_data_in_record_file(sfp->fswpr, FSPWR_REG_NUM, fptr, swap_flag);
	if (ret != 0)
		goto exit;

	fprintf(fptr, "%s", ":");

	ret = fill_u8_data_in_record_file((uint8_t *)sfp->srk_hash,
					  SRKH_REG_NUM * WORD_SIZE_IN_BYTES,
					  fptr);
	if (ret != 0)
		goto exit;

	fprintf(fptr, "%s", ":");

	ret = fill_data_in_record_file(sfp->ospr, OSPR_REG_NUM, fptr, swap_flag);
	if (ret != 0)
		goto exit;

	fprintf(fptr, "%s", ":");

	ret = get_mp_tag(fptr);
	if (ret != 0)
		goto exit;

	fprintf(fptr, "%s", ":");

	fclose(fptr);

	ret = generate_message_from_record(msg, msg_len);
	if (ret != 0)
		goto exit;

	fptr = fopen(filename, "a");
	if (fptr == NULL) {
		printf("Unable to open the record file");
		ret = ERROR_FILE_OPEN;
		goto exit;
	}
	// Add signature over the message and add to record file.
	ret = sign_msg(msg, fptr);
	if(ret)
		goto exit;

	printf("\n!! Record_file '%s' has been generated.\n", filename);

exit:
	if(sfp_ptr)
		munmap(sfp_ptr, 4096);
	if(fptr)
		fclose(fptr);
	if (msg)
		free(msg);
	sk_lib_exit();
	return ret;
}
