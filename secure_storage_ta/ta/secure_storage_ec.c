/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "secure_storage_common.h"

const char *P256 = "prime256v1";
const char *P384 = "secp384r1";

int get_ec_obj_size(SK_ATTRIBUTE *attr, uint32_t *obj_size)
{
	if (!TEE_MemCompare((char *)attr->value,
		P256, attr->valueLen)) {
		*obj_size = 256;
		return 0;
	} else if (!TEE_MemCompare((char *)attr->value,
		P384, attr->valueLen)) {
		*obj_size = 384;
		return 0;
	} else
		return 1;
}
void fill_ec_keypair_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
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

	attr_key = TA_GetSKAttr(SK_ATTR_PRIV_VALUE, attrs, attr_count);
	if (attr_key != NULL) {
		TEE_InitRefAttribute(&tee_attrs[3],
				     TEE_ATTR_ECC_PRIVATE_VALUE,
				     attr_key->value, attr_key->valueLen);
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
