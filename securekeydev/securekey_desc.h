/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:    GPL-2.0+
*/

#ifndef __SECUREKEY_DESC_H__
#define __SECUREKEY_DESC_H__

#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/bug.h>
#include <caam/desc.h>
#include <caam/desc_constr.h>

#define PDB_SGF_SIGN_SHIFT	28
#define PDB_SGF_PUB_KEY_SHIFT	31
#define PDB_CSEL_SHIFT		17

#define OP_PCLID_SHIFT		16
#define OP_PCLID_MP_PUB_KEY	(0x14 << OP_PCLID_SHIFT)
#define OP_PCLID_MP_SIGN		(0x15 << OP_PCLID_SHIFT)

#define OP_TYPE_MP_GET_PUB_KEY	(0x086 << OP_TYPE_SHIFT)
#define OP_TYPE_MP_SIGN		(0x86 << OP_TYPE_SHIFT)

/* P256 Curve */
#define MP_EC_CURVE		(0x3 << PDB_CSEL_SHIFT)

#define MP_PUB_KEY_SGF_BIT	(0x0 << PDB_SGF_PUB_KEY_SHIFT)
#define MP_SIGN_SGF_BIT		(0x0 << PDB_SGF_SIGN_SHIFT)

struct __packed  pdb_mp_public_key {
	uint32_t hdr;
	dma_addr_t out_ptr;
};

/* Descriptor to generate public key and store it at given destination address*/
static inline int build_mp_get_pubkey_desc(uint32_t *desc, const uint64_t dest)
{
	uint32_t command;

	command = (MP_PUB_KEY_SGF_BIT | MP_EC_CURVE);

	init_job_desc_pdb(desc, 0, sizeof(struct pdb_mp_public_key));
	append_cmd(desc, command);
	append_ptr(desc, dest);
	append_operation(desc, OP_TYPE_MP_GET_PUB_KEY |
		OP_PCLID_MP_PUB_KEY | 0X0000);

	return 1;
}

struct __packed  pdb_mp_sign {
	uint32_t hdr;
	dma_addr_t msg_ptr;
	dma_addr_t hash_ptr;
	dma_addr_t c_sig;
	dma_addr_t d_sig;
	uint32_t msg_len;
};

static inline int build_mp_sign_desc(uint32_t *desc, const uint64_t msg,
	uint32_t msg_len, const uint64_t hash, const uint64_t c, const uint64_t d)
{
	uint32_t command;

	command = (MP_SIGN_SGF_BIT | MP_EC_CURVE);

	init_job_desc_pdb(desc, 0, sizeof(struct pdb_mp_sign));
	append_cmd(desc, command);
	append_ptr(desc, msg);
	append_ptr(desc, hash);
	append_ptr(desc, c);
	append_ptr(desc, d);
	append_u32(desc, msg_len);
	append_operation(desc, OP_TYPE_MP_SIGN |
		OP_PCLID_MP_SIGN | 0X0000);

	return 1;
}
#endif /* __SECUREKEY_DESC_H__ */
