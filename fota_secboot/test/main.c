// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#include <stdio.h>
#include "validate.h"

int main(int argc, char *argv[])
{
	printf("Header Path: %s\n", argv[1]);
	printf("kernel.itb Path: %s\n", argv[2]);

	printf("%s\n", fota_secboot_validate(argv[1],
				argv[2]) ? "Failure" : "Success");
	return 0;
}

