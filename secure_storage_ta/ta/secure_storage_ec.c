/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "secure_storage_common.h"

#define SUPPORTED_EC_CURVES	2

struct ec_curves {
	char *curve;
	uint32_t	curve_len;
	char	*data;
	uint32_t	data_size;
};

char P256[] = "prime256v1";
char P384[] = "secp384r1";

/* EC Curve in DER encoding */
char prime256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
char secp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };

struct ec_curves supported_ec_curves[SUPPORTED_EC_CURVES] = {
	{P256, 256, prime256, sizeof(prime256)},
	{P384, 384, secp384, sizeof(secp384)},
};

int get_ec_obj_size(SK_ATTRIBUTE *attr, uint32_t *obj_size)
{
	uint8_t i = 0, found = 0;

	for (i = 0; i < SUPPORTED_EC_CURVES; i++) {
		if (!TEE_MemCompare((char *)attr->value,
			supported_ec_curves[i].data, attr->valueLen)) {
			*obj_size = supported_ec_curves[i].curve_len;
			found = 1;
		}
	}

	if (found)
		return 0;
	else
		return 1;
}
void fill_ec_keypair_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			       TEE_Attribute *tee_attrs,
			       uint32_t *tee_attr_count, uint32_t obj_size)
{
	uint32_t attr_cnt = 0;
	SK_ATTRIBUTE *attr_key;
	uint8_t *public_key_x, *public_key_y, point_len;

	attr_key = TA_GetSKAttr(SK_ATTR_PRIV_VALUE, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[0],
				     TEE_ATTR_ECC_PRIVATE_VALUE,
				     attr_key->value, attr_key->valueLen);
		attr_cnt++;
	}

	attr_key = TA_GetSKAttr(SK_ATTR_POINT, attrs, attr_count);
	if (attr_key != NULL) {
		if (obj_size == 256)
			point_len = 32;
		else
			point_len = 48;
		public_key_x = ((uint8_t *)attr_key->value) + 1;
		public_key_y = public_key_x + point_len;
		TEE_InitRefAttribute(&tee_attrs[1],
				     TEE_ATTR_ECC_PUBLIC_VALUE_X,
				     public_key_x, point_len);
		TEE_InitRefAttribute(&tee_attrs[2],
				     TEE_ATTR_ECC_PUBLIC_VALUE_Y,
				     public_key_y, point_len);
		attr_cnt+=2;
	}

	if (obj_size == 256) {
		TEE_InitValueAttribute(&tee_attrs[3], TEE_ATTR_ECC_CURVE,
				     TEE_ECC_CURVE_NIST_P256, sizeof(int));
		attr_cnt++;
	} else {
		TEE_InitValueAttribute(&tee_attrs[3], TEE_ATTR_ECC_CURVE,
				     TEE_ECC_CURVE_NIST_P384, sizeof(int));
		attr_cnt++;
	}


	*tee_attr_count = attr_cnt;
}

void fill_ec_pubkey_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			      TEE_Attribute *tee_attrs,
			      uint32_t *tee_attr_count, uint32_t obj_size)
{
	uint32_t attr_cnt = 0;
	SK_ATTRIBUTE *attr_key;
	uint8_t *public_key_x, *public_key_y, point_len;

	if (obj_size == 256) {
		TEE_InitValueAttribute(&tee_attrs[0], TEE_ATTR_ECC_CURVE,
				     TEE_ECC_CURVE_NIST_P256, sizeof(int));
		point_len = 32;
		attr_cnt++;
	} else {
		TEE_InitValueAttribute(&tee_attrs[0], TEE_ATTR_ECC_CURVE,
				     TEE_ECC_CURVE_NIST_P384, sizeof(int));
		point_len = 48;
		attr_cnt++;
	}

	attr_key = TA_GetSKAttr(SK_ATTR_POINT, attrs, attr_count);
	if (attr_key != NULL) {
		public_key_x = ((uint8_t *)attr_key->value) + 1;
		public_key_y = public_key_x + point_len;
		TEE_InitRefAttribute(&tee_attrs[1],
				     TEE_ATTR_ECC_PUBLIC_VALUE_X,
				     public_key_x, point_len);
		TEE_InitRefAttribute(&tee_attrs[2],
				     TEE_ATTR_ECC_PUBLIC_VALUE_Y,
				     public_key_y, point_len);
		attr_cnt+=2;
	}

	*tee_attr_count = attr_cnt;
}
