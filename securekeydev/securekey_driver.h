/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:    GPL-2.0+
*/

#include <linux/ioctl.h>

#ifndef __SECUREKEY_DRIVER_H__
#define __SECUREKEY_DRIVER_H__

#define	PRINT_ERROR

#ifdef PRINT_ERROR
#define print_error(msg, ...) { \
pr_err("[SECUREKEY-DRV:%s:%d] Error: ", __func__, __LINE__); \
pr_err(msg, ##__VA_ARGS__); \
}
#else
#define print_error(msg, ...)
#endif

#ifdef PRINT_INFO
#define print_info(msg, ...) { \
pr_info("[SECUREKEY-DRV:%s:%d] Info: ", __func__, __LINE__); \
pr_info(msg, ##__VA_ARGS__); \
}
#else
#define print_info(msg, ...)
#endif

struct sk_mp_pub_key_info {
	uint8_t *x;
	uint8_t x_len;
	uint8_t *y;
	uint8_t y_len;
};

struct sk_mp_sign_req_info {
	uint8_t *msg;
	uint8_t msg_len;
	uint8_t *hash;
	uint8_t hash_len;
	uint8_t *r;
	uint8_t r_len;
	uint8_t *s;
	uint8_t s_len;
};

#define SK_MP_GET_PUB_KEY	_IOWR('c', 1, struct sk_mp_pub_key_info)	/*!< Defines MP Pub key Get operation command. */
#define SK_MP_SIGN		_IOWR('c', 2, struct sk_mp_sign_req_info)	/*!< Defines MP Sign operation command. */

#endif /*__SECUREKEY_DRIVER_H__*/
