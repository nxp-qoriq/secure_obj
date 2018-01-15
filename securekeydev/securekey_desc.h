/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#ifndef __SECUREKEY_DESC_H__
#define __SECUREKEY_DESC_H__

#include <linux/printk.h>
#include <linux/kernel.h>
#include <linux/bug.h>

#include "flib/rta.h"

extern enum rta_sec_era rta_sec_era;

#define PDB_SGF_SIGN_SHIFT	28
#define PDB_SGF_PUB_KEY_SHIFT	31
#define PDB_CSEL_SHIFT	17

static inline int build_mp_get_pubkey_desc(uint32_t *desc, const uint64_t dest)
{
	struct program prg;
	struct program *pp = &prg;
	bool swap = true;

	LABEL(pdb_end);

	PROGRAM_CNTXT_INIT(pp, desc, 0);
	PROGRAM_SET_36BIT_ADDR(pp);
	if (swap)
		PROGRAM_SET_BSWAP(pp);

	JOB_HDR(pp, SHR_NEVER, 0, 0, 0);
	{
		{	/* MP Generate Public Key */
			WORD(pp, ((0x0 << PDB_SGF_PUB_KEY_SHIFT)
				| (0x3) << PDB_CSEL_SHIFT));
			DWORD(pp, dest);
			SET_LABEL(pp, pdb_end);
		}
		PROTOCOL(pp, OP_TYPE_MP_GET_PUB_KEY, OP_PCLID_MP_PUB_KEY, 0X0000);
	}
	PATCH_HDR(pp, 0, pdb_end);

	return PROGRAM_FINALIZE(pp);
}

static inline int build_mp_sign_desc(uint32_t *desc, const uint64_t msg,
	uint32_t msg_len, const uint64_t hash, const uint64_t c, const uint64_t d)
{
	struct program prg;
	struct program *pp = &prg;
	bool swap = true;

	LABEL(pdb_end);

	PROGRAM_CNTXT_INIT(pp, desc, 0);
	PROGRAM_SET_36BIT_ADDR(pp);
	if (swap)
		PROGRAM_SET_BSWAP(pp);

	JOB_HDR(pp, SHR_NEVER, 0, 0, 0);
	{
		{	/* MP SIGN msg using MPPriv Key */
			WORD(pp, ((0x00 << PDB_SGF_SIGN_SHIFT)
				| (0x3) << PDB_CSEL_SHIFT));
			DWORD(pp, msg);
			DWORD(pp, hash);
			DWORD(pp, c);
			DWORD(pp, d);
			WORD(pp, msg_len);
			SET_LABEL(pp, pdb_end);
		}
		PROTOCOL(pp, OP_TYPE_MP_SIGN,
			OP_PCLID_MP_SIGN, 0X0000);
	}
	PATCH_HDR(pp, 0, pdb_end);

	return PROGRAM_FINALIZE(pp);
}
#endif /* __SECUREKEY_DESC_H__ */
