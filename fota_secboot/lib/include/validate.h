// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#ifndef VALIDATE_H
#define VALIDATE_H

/*!
 * @brief  Function will check and validate whether provided images
 * are authentic or Not.
 * @Arguments:
 *	@1: Path of patched esbc header
 *	@2: Path of patched kernel.itb file
 *
 * @returns  0 on Success and error code on Failure.
 */

int fota_secboot_validate(const char *, const char *);

#endif
