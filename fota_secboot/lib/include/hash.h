// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#ifndef HASH_H
#define HASH_H
/*!
 * @brief  Function will SRK hash over the SRK table.
 * @Arguments:
 *      @1:Address of fsl_secboot_img structure
 *
 * @returns  0 on Success and error code on Failure.
 */

int calc_img_key_hash(struct fsl_secboot_img *);

/*!
 * @brief  Function will image hash, decrypt the signature
 * and retive the stored hash ans compare with run time
 * calcualted hash value ans return the result.
 * @Arguments:
 *      @1: Address of fsl_secboot_img structure
 *      @2: Buffer address of kernel.itb image
 *      @3: Size of Kernel.itb
 *
 * @returns  0 on Success and error code on Failure.
 */
int calculate_cmp_img_sig(struct fsl_secboot_img *, u8 *, int);

#endif
