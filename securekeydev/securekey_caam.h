/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef __SECUREKEY_CAAM_H__
#define __SECUREKEY_CAAM_H__

enum caam_req_type {
	mp_get_pub_key,	/*!<  = 1 */
	mp_sign,		/*!<  = 2 */
};

struct caam_mp_pub_key_req {
	size_t pub_key_size;	/* Public Key Size */
	dma_addr_t pub_key;	/* Output Public key */
};

struct caam_mp_sign_req {
	dma_addr_t msg;
	size_t msg_len;
	dma_addr_t hash;
	size_t hash_len;
	dma_addr_t r;
	size_t r_len;
	dma_addr_t s;
	size_t s_len;
};

struct caam_req {
	enum caam_req_type type;
	union {
		struct caam_mp_pub_key_req mp_pub_key_req;
		struct caam_mp_sign_req mp_sign_req;
	} req_u;
};

int caam_job_submit(struct device *jrdev, void *ptr);

#endif	//__SECUREKEY_CAAM_H__
