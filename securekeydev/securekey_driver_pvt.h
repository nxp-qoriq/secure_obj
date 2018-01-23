/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:    GPL-2.0+
*/

#ifndef __SECUREKEY_DRIVER_PVT_H__
#define __SECUREKEY_DRIVER_PVT_H__

#include <linux/device.h>

/*
 * Defines different kinds of operations supported by this module.
*/
enum sk_req_type {
	sk_mp_get_pub_key,		/*!<  = 1 */
	sk_mp_sign,			/*!<  = 2 */
};

struct sk_mp_pub_key_info_k {
	uint8_t *pub_key;
	uint8_t pub_key_len;
};

struct sk_mp_sign_req_info_k {
	uint8_t *msg;
	size_t msg_len;
	uint8_t *hash;
	uint8_t hash_len;
	uint8_t *r;
	uint8_t r_len;
	uint8_t *s;
	uint8_t s_len;
};

struct sk_req {
	enum sk_req_type type;
	union {
		struct sk_mp_pub_key_info_k mp_pub_key_req;
		struct sk_mp_sign_req_info_k mp_sign_req;
	} req_u;
	void *arg;
	int ret;
	void *mem_pointer;
	void *ptr;
};

#endif	//__SECUREKEY_DRIVER_PVT_H__
