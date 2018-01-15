/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include "securekey_mp.h"
#include "securekey_driver.h"

#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

#include <sys/mman.h>
#include <endian.h>

static int32_t fd = 0xFFFF; /* for device driver fd */

/* These are the sizes on the basis of ECC Prime 256 Algo */
#define	MP_PUB_KEY_LEN		32
#define	MP_DIGEST_LEN		32
#define	MP_SIG_LEN		32
#define	MP_TAG_LEN		32
#define	FUID_LEN		8

/*
 *  Initialize the secure key library.
 *  This function must be called before using any other library function.
 */
enum sk_status_code sk_lib_init(void)
{
	fd = open("/dev/securekeydev", O_RDWR);

	if (fd < 0) {
		printf("Error open device %d\n", fd);
		return SK_FAILURE;
	}

	return SK_SUCCESS;
}

/*
 * Clean up the secure key library resources.
 * This function must be called when application done using library function.
 */
void sk_lib_exit(void)
{
	if (fd != 0xFFFF) {
		if (close(fd))
			printf("Device close failed error = %d\n", errno);
	}
}

/*
 * Translates the error codes.
 * This wil return error string corresponding to the error code.
 */
const char *sk_translate_error_code(enum sk_status_code error)
{
	switch ((int16_t)error) {
	case SK_FAILURE:
		return "Device is not initiated";
	case -EIO:
		return "Cannot map [CAAM] descriptor";
	case -EBUSY:
		return "[CAAM]: queue is full";
	case -ENOMEM:
		return "Memory allocation failed";
	case -EINVAL:
		return "Invalid argument is passed";
	case -EFAULT:
		return "Bad address passed";
	case -ENODEV:
		return "No Such device exists";
	default:
		return "No Valid error code";
	}
}

uint8_t sk_mp_get_pub_key_len(void)
{
	return MP_PUB_KEY_LEN;
}

uint8_t sk_mp_get_digest_len(void)
{
	return MP_DIGEST_LEN;
}

uint8_t sk_mp_get_sig_len(void)
{
	return MP_SIG_LEN;
}

uint8_t sk_mp_get_tag_len(void)
{
	return MP_TAG_LEN;
}

uint8_t sk_get_fuid_len(void)
{
	return FUID_LEN;
}

enum sk_status_code sk_mp_get_pub_key(struct sk_EC_point *req)
{
	uint32_t ret_status = SK_FAILURE;
	struct sk_mp_pub_key_info *mp_pub_key_req;

	if (req->x == NULL || req->y == NULL) {
		printf("[%s]: Bad Pointers\n", __func__);
		ret_status = -EFAULT;
		goto err;
	}

	if (req->len != MP_PUB_KEY_LEN) {
		ret_status = -EINVAL;
		goto err;
	}

	mp_pub_key_req = (struct sk_mp_pub_key_info *)malloc(sizeof(struct sk_mp_pub_key_info));
	if (!mp_pub_key_req) {
		ret_status = -ENOMEM;
		goto err;
	}

	mp_pub_key_req->x = req->x;
	mp_pub_key_req->x_len = req->len;
	mp_pub_key_req->y = req->y;
	mp_pub_key_req->y_len = req->len;

	ret_status = ioctl(fd, SK_MP_GET_PUB_KEY, mp_pub_key_req);
	if (ret_status) {
		printf("ioctl SK_MP_GET_PUB_KEY failed ret_status = %d\n", ret_status);
		ret_status = -errno;
	}

	free(mp_pub_key_req);
err:
	return ret_status;
}

enum sk_status_code sk_mp_sign(unsigned char *msg, uint8_t msg_len,
		struct sk_EC_sig *sig,  uint8_t *digest, uint8_t digest_len)
{
	uint32_t ret_status = SK_FAILURE;
	struct sk_mp_sign_req_info *mp_sign_req;

	if (sig->r == NULL || sig->s == NULL || msg == NULL || digest == NULL) {
		printf("[%s]: Bad Pointers\n", __func__);
		ret_status = -EFAULT;
		goto err;
	}

	if (sig->len != MP_SIG_LEN || digest_len != MP_DIGEST_LEN) {
		ret_status = -EINVAL;
		goto err;
	}

	mp_sign_req = (struct sk_mp_sign_req_info *)malloc(sizeof(struct sk_mp_sign_req_info));
	if (!mp_sign_req) {
		ret_status = -ENOMEM;
		goto err;
	}

	mp_sign_req->msg = msg;
	mp_sign_req->msg_len = msg_len;
	mp_sign_req->hash = digest;
	mp_sign_req->hash_len = digest_len;
	mp_sign_req->r = sig->r;
	mp_sign_req->r_len = sig->len;
	mp_sign_req->s = sig->s;
	mp_sign_req->s_len = sig->len;

	ret_status = ioctl(fd, SK_MP_SIGN, mp_sign_req);
	if (ret_status) {
		printf("ioctl SK_MP_SIGN failed\n");
		ret_status = -errno;
	}

	free(mp_sign_req);
err:
	return ret_status;
}

/* For LS1046/43 this is MPMR register address, may change for other SOC*/
#define MP_BASE_ADDRESS	0x01700000
enum sk_status_code sk_mp_get_mp_tag(uint8_t *mp_tag_ptr,
		uint8_t mp_tag_len)
{
	uint32_t ret = SK_FAILURE;
	int mem;
	void *ptr;
	uint32_t *data, *mp_temp;

	/* To satisfy compiler */
	mp_tag_len = mp_tag_len;

	/* Open /dev/mem */
	if ((mem = open("/dev/mem", O_RDWR | O_SYNC)) == -1) {
		printf("Cannot open /dev/mem\n");
		perror("open");
		ret = -errno;
		goto err;
	}

	ptr = mmap(0, 4096/*PAGE_SZ*/, PROT_READ|PROT_WRITE, MAP_SHARED, mem, MP_BASE_ADDRESS);
	if (ptr == (void *)-1) {
		printf("Memory map failed.\n");
		perror("mmap");
		ret = -errno;
		goto err1;
	}

	data = (uint32_t *)ptr;
	mp_temp = (uint32_t *)mp_tag_ptr;

	/* MPMR register address on LS1046/43 is 0x01700380.
	  * So 0x01700380 - MP_BASE_ADDRESS = 0x380 = 896 bytes.
	  * We are reading 4 bytes(a word), so 896/4 = 224.
	  * and need to read 8 words, so 224-231*/
	mp_temp[0] = data[224];
	mp_temp[1] = data[225];
	mp_temp[2] = data[226];
	mp_temp[3] = data[227];
	mp_temp[4] = data[228];
	mp_temp[5] = data[229];
	mp_temp[6] = data[230];
	mp_temp[7] = data[231];

#if 0
	printf("arg0 = %08x, arg1 = %08x, arg2 = %08x, arg3 = %08x\n", arg[0], arg[1], arg[2], arg[3]);
	printf("arg4 = %08x, arg5 = %08x, arg6 = %08x, arg7 = %08x\n", arg[4], arg[5], arg[6], arg[7]);
#endif

	ret = SK_SUCCESS;

	munmap(ptr, 4096);
err1:
	close(mem);
err:
	return ret;
}

#define SFP_BASE_ADDRESS	0x01E80000
enum sk_status_code sk_get_fuid(uint8_t *fuid)
{
	uint32_t ret = SK_FAILURE;
	int mem;
	void *ptr;
	uint32_t *data, *fuid_temp;

	/* Open /dev/mem */
	if ((mem = open ("/dev/mem", O_RDWR | O_SYNC)) == -1) {
		printf("Cannot open /dev/mem\n");
		perror("open");
		ret = -errno;
		goto err;
	}

	ptr = mmap (0, 4096/*PAGE_SZ*/, PROT_READ|PROT_WRITE, MAP_SHARED, mem, SFP_BASE_ADDRESS);
	if(ptr == (void *) -1) {
		printf("Memory map failed.\n");
		perror("mmap");
		ret = -errno;
		goto err1;
	}

	data = (uint32_t *)ptr;
	fuid_temp = (uint32_t *)fuid;

	/* FUID register address on LS1046 is 0x01E8021C.
	  * So 0x01E8021C - SFP_BASE_ADDRESS = 0x21C = 540 bytes.
	  * We are reading 4 bytes(a word), so 540/4 = 135.
	  * and need to read 2 words, so 135-136*/
	fuid_temp[0] = data[135];
	fuid_temp[1] = data[136];

	ret = SK_SUCCESS;
	munmap(ptr, 4096);
err1:
	close(mem);
err:
	return ret;
}

enum sk_status_code sk_get_oemid(uint8_t *oem_id,
		uint8_t* oem_id_len)
{
	uint32_t ret = SK_FAILURE;
	int mem;
	void *ptr;
	uint32_t *data, *oem_temp;
	*oem_id_len = 0;

	/* Open /dev/mem */
	if ((mem = open ("/dev/mem", O_RDWR | O_SYNC)) == -1) {
		printf("Cannot open /dev/mem\n");
		perror("open");
		ret = -errno;
		goto err;
	}

	ptr = mmap (0, 4096/*PAGE_SZ*/, PROT_READ|PROT_WRITE, MAP_SHARED, mem, SFP_BASE_ADDRESS);
	if(ptr == (void *) -1) {
		printf("Memory map failed.\n");
		perror("mmap");
		ret = -errno;
		goto err1;
	}

	data = (uint32_t *)ptr;
	oem_temp = (uint32_t *)oem_id;

	/* OEMUID register address on LS1046 is 0x01E80274.
	  * So 0x01E80274 - SFP_BASE_ADDRESS = 0x274 = 628 bytes.
	  * We are reading 4 bytes(a word), so 628/4 = 157.
	  * and need to read 5 words, so 157-161*/
	oem_temp[0] = data[157];
	oem_temp[1] = data[158];
	oem_temp[2] = data[159];
	oem_temp[3] = data[160];
	oem_temp[4] = data[161];

	ret = SK_SUCCESS;
	*oem_id_len = 20;

	munmap(ptr, 4096);
err1:
	close(mem);
err:
	return ret;
}
