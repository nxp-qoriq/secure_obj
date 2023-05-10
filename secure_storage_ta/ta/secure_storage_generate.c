/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"

#define MAX_KEY_PAIR_ATTRS		11
#define MAX_KEY_SIZE_BYTES		512

static uint8_t modulus[MAX_KEY_SIZE_BYTES];
static uint8_t pub_exp[MAX_KEY_SIZE_BYTES];
static uint8_t ec_pub_point[MAX_KEY_SIZE_BYTES];

static TEE_Result TA_GenerateECKeyPair(TEE_ObjectHandle *privateKey,
					TEE_ObjectHandle *publicKey,
					void *in_buffer, uint32_t size,
					SK_ATTRIBUTE *privattrs,
					uint32_t *priv_attr_count,
					SK_ATTRIBUTE *pubattrs,
					uint32_t *pub_attr_count)
{
	TEE_Result res;
	SK_ATTRIBUTE *in_attrs = NULL;
	uint32_t in_attr_cnt = 0;
	SK_ATTRIBUTE *get_attr;
	TEE_Attribute curve_attr = {0};
	uint32_t obj_size, key_attr_cnt = 0;
	size_t obj_ret_size = 0;
	uint32_t ec_size;

	ec_pub_point[0] = 0x4;

	DMSG("Unpack Object attributes!\n");
	res = unpack_sk_attrs(in_buffer, size, &in_attrs, &in_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	/* Get EC key size from SK_ATTR_PARAMS attribute */
	get_attr = TA_GetSKAttr(SK_ATTR_PARAMS, in_attrs,
				in_attr_cnt);
	if (get_attr == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!get_ec_obj_size(get_attr, &ec_size)) {
		obj_size = ec_size;
	} else {
		EMSG("Algo Not Supported\n");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	privattrs[*priv_attr_count].type = get_attr->type;
	privattrs[*priv_attr_count].value = get_attr->value;
	privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
	(*priv_attr_count)++;

	pubattrs[*pub_attr_count].type = get_attr->type;
	pubattrs[*pub_attr_count].value = get_attr->value;
	pubattrs[*pub_attr_count].valueLen = get_attr->valueLen;
	(*pub_attr_count)++;

	DMSG("Allocate Transient Object ECDSA Private Key!\n");
	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR,
			obj_size, privateKey);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Allocate Transient Object ECDSA Public Key!\n");
	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY,
			obj_size, publicKey);
	if (res != TEE_SUCCESS)
		goto out;

	if (obj_size == 256) {
		TEE_InitValueAttribute(&curve_attr, TEE_ATTR_ECC_CURVE,
				     TEE_ECC_CURVE_NIST_P256, sizeof(int));
	} else if (obj_size == 384) {
		TEE_InitValueAttribute(&curve_attr, TEE_ATTR_ECC_CURVE,
				     TEE_ECC_CURVE_NIST_P384, sizeof(int));
	} else {
		EMSG("Algo Not Supported\n");
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	key_attr_cnt++;

	DMSG("Generate EC key pair!\n");
	res = TEE_GenerateKey(*privateKey, obj_size, &curve_attr, key_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Copy Public part from KeyPair\n");
	res = TEE_CopyObjectAttributes1(*publicKey, *privateKey);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Get EC key POINT attribute!\n");
	res = TEE_GetObjectBufferAttribute(*privateKey, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   NULL,
					   &obj_ret_size);
	if (res != TEE_ERROR_SHORT_BUFFER)
		goto out;

	res = TEE_GetObjectBufferAttribute(*privateKey, TEE_ATTR_ECC_PUBLIC_VALUE_X,
					   &ec_pub_point[1],
					   &obj_ret_size);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_GetObjectBufferAttribute(*privateKey, TEE_ATTR_ECC_PUBLIC_VALUE_Y,
					   &ec_pub_point[1+obj_ret_size],
					   &obj_ret_size);
	if (res != TEE_SUCCESS)
		goto out;

	privattrs[*priv_attr_count].type = SK_ATTR_POINT;
	privattrs[*priv_attr_count].value = ec_pub_point;
	privattrs[*priv_attr_count].valueLen = (2 * obj_ret_size) + 1;
	(*priv_attr_count)++;

	pubattrs[*pub_attr_count].type = SK_ATTR_POINT;
	pubattrs[*pub_attr_count].value = ec_pub_point;
	pubattrs[*pub_attr_count].valueLen = (2 * obj_ret_size) + 1;
	(*pub_attr_count)++;

	/* Check if EC key object index is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_INDEX, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		privattrs[*priv_attr_count].type = get_attr->type;
		privattrs[*priv_attr_count].value = get_attr->value;
		privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
		(*priv_attr_count)++;

		pubattrs[*pub_attr_count].type = get_attr->type;
		pubattrs[*pub_attr_count].value = get_attr->value;
		pubattrs[*pub_attr_count].valueLen = get_attr->valueLen;
		(*pub_attr_count)++;

	}

	/* Check if EC key object label is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_LABEL, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		privattrs[*priv_attr_count].type = get_attr->type;
		privattrs[*priv_attr_count].value = get_attr->value;
		privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
		(*priv_attr_count)++;

		pubattrs[*pub_attr_count].type = get_attr->type;
		pubattrs[*pub_attr_count].value = get_attr->value;
		pubattrs[*pub_attr_count].valueLen = get_attr->valueLen;
		(*pub_attr_count)++;

	}

	/* Check if PRIVATEis passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_PRIVATE, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		privattrs[*priv_attr_count].type = get_attr->type;
		privattrs[*priv_attr_count].value = get_attr->value;
		privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
		(*priv_attr_count)++;
	}

out:
	if (in_attrs)
		TEE_Free(in_attrs);

	return res;
}


static TEE_Result TA_GenerateRSAKeyPair(TEE_ObjectHandle *privateKey,
					TEE_ObjectHandle *publicKey,
					void *in_buffer, uint32_t size,
					SK_ATTRIBUTE *privattrs,
					uint32_t *priv_attr_count,
					SK_ATTRIBUTE *pubattrs,
					uint32_t *pub_attr_count)
{
	TEE_Result res;
	SK_ATTRIBUTE *in_attrs = NULL;
	uint32_t in_attr_cnt = 0;
	SK_ATTRIBUTE *get_attr;
	TEE_Attribute exp_attr = {0};
	uint32_t obj_size = 0, key_attr_cnt = 0;
	size_t mod_size = MAX_KEY_SIZE_BYTES;
	size_t pub_exp_size = MAX_KEY_SIZE_BYTES;

	DMSG("Unpack Object attributes!\n");
	res = unpack_sk_attrs(in_buffer, size, &in_attrs, &in_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	/* Get RSA key size from SK_ATTR_MODULUS_BITS attribute */
	get_attr = TA_GetSKAttr(SK_ATTR_MODULUS_BITS, in_attrs,
				in_attr_cnt);
	if (get_attr == NULL)
		return TEE_ERROR_BAD_PARAMETERS;
	obj_size = *(uint32_t *)get_attr->value;

	privattrs[*priv_attr_count].type = get_attr->type;
	privattrs[*priv_attr_count].value = get_attr->value;
	privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
	(*priv_attr_count)++;

	pubattrs[*pub_attr_count].type = get_attr->type;
	pubattrs[*pub_attr_count].value = get_attr->value;
	pubattrs[*pub_attr_count].valueLen = get_attr->valueLen;
	(*pub_attr_count)++;

	DMSG("Allocate Transient Object RSA KeyPair!\n");
	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_KEYPAIR,
			obj_size, privateKey);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Allocate Transient Object RSA Public Key!\n");
	res = TEE_AllocateTransientObject(TEE_TYPE_RSA_PUBLIC_KEY,
			obj_size, publicKey);
	if (res != TEE_SUCCESS)
		goto out;

	/* Check if RSA key exponent is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_PUBLIC_EXPONENT, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		TEE_InitRefAttribute(&exp_attr,
				TEE_ATTR_RSA_PUBLIC_EXPONENT,
				get_attr->value, get_attr->valueLen);
		key_attr_cnt++;
	}

	DMSG("Generate RSA key pair!\n");
	res = TEE_GenerateKey(*privateKey, obj_size, &exp_attr, key_attr_cnt);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Copy Public part from KeyPair\n");
	res = TEE_CopyObjectAttributes1(*publicKey, *privateKey);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Get RSA key modulus attribute!\n");
	res = TEE_GetObjectBufferAttribute(*privateKey,
				TEE_ATTR_RSA_MODULUS,
				modulus, &mod_size);
	if (res != TEE_SUCCESS)
		goto out;

	privattrs[*priv_attr_count].type = SK_ATTR_MODULUS;
	privattrs[*priv_attr_count].value = modulus;
	privattrs[*priv_attr_count].valueLen = mod_size;
	(*priv_attr_count)++;

	pubattrs[*pub_attr_count].type = SK_ATTR_MODULUS;
	pubattrs[*pub_attr_count].value = modulus;
	pubattrs[*pub_attr_count].valueLen = mod_size;
	(*pub_attr_count)++;

	DMSG("Get RSA key public exponent attribute!\n");
	res = TEE_GetObjectBufferAttribute(*privateKey,
			   TEE_ATTR_RSA_PUBLIC_EXPONENT,
			   pub_exp, &pub_exp_size);
	if (res != TEE_SUCCESS)
		goto out;

	privattrs[*priv_attr_count].type = SK_ATTR_PUBLIC_EXPONENT;
	privattrs[*priv_attr_count].value = pub_exp;
	privattrs[*priv_attr_count].valueLen = pub_exp_size;
	(*priv_attr_count)++;

	pubattrs[*pub_attr_count].type = SK_ATTR_PUBLIC_EXPONENT;
	pubattrs[*pub_attr_count].value  = pub_exp;
	pubattrs[*pub_attr_count].valueLen = pub_exp_size;
	(*pub_attr_count)++;

	/* Check if RSA key object index is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_INDEX, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		privattrs[*priv_attr_count].type = get_attr->type;
		privattrs[*priv_attr_count].value = get_attr->value;
		privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
		(*priv_attr_count)++;

		pubattrs[*pub_attr_count].type = get_attr->type;
		pubattrs[*pub_attr_count].value = get_attr->value;
		pubattrs[*pub_attr_count].valueLen = get_attr->valueLen;
		(*pub_attr_count)++;
	}

	/* Check if RSA key object label is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_OBJECT_LABEL, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		privattrs[*priv_attr_count].type = get_attr->type;
		privattrs[*priv_attr_count].value = get_attr->value;
		privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
		(*priv_attr_count)++;

		pubattrs[*pub_attr_count].type = get_attr->type;
		pubattrs[*pub_attr_count].value = get_attr->value;
		pubattrs[*pub_attr_count].valueLen = get_attr->valueLen;
		(*pub_attr_count)++;
	}

	/* Check if PRIVATE is passed in input attrs */
	get_attr = TA_GetSKAttr(SK_ATTR_PRIVATE, in_attrs,
				in_attr_cnt);
	if (get_attr) {
		privattrs[*priv_attr_count].type = get_attr->type;
		privattrs[*priv_attr_count].value = get_attr->value;
		privattrs[*priv_attr_count].valueLen = get_attr->valueLen;
		(*priv_attr_count)++;
	}

out:
	if (in_attrs)
		TEE_Free(in_attrs);

	return res;
}

/*
 * Input params:
 * param#0 : input key pair gen mechanism
 * param#1 : input serialized object attributes buffer
 * param#2 : output object ID
 * param#3 : not used
 */
TEE_Result TA_GenerateKeyPair(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle privateKey = TEE_HANDLE_NULL;
	TEE_ObjectHandle privateKeyPersistent = TEE_HANDLE_NULL;
	TEE_ObjectHandle publicKey = TEE_HANDLE_NULL;
	TEE_ObjectHandle publicKeyPersistent = TEE_HANDLE_NULL;
	SK_ATTRIBUTE privattrs[MAX_KEY_PAIR_ATTRS] = {0};
	SK_ATTRIBUTE pubattrs[MAX_KEY_PAIR_ATTRS] = {0};

	uint32_t priv_attr_count = 0, pub_attr_count = 0;
	uint32_t private_key_obj_id = 0, public_key_obj_id = 0;
	SK_OBJECT_TYPE sk_priv_obj_type = 0, sk_pub_obj_type = 0;
	SK_KEY_TYPE sk_key_type;
	uint8_t *priv_attr_data = NULL, *pub_attr_data = NULL;
	size_t priv_attr_data_len = 0, pub_attr_data_len = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("TA_GenerateKeyPair started!\n");

	switch (params[0].value.a) {
	case SKM_RSA_PKCS_KEY_PAIR_GEN:
		/* Fill SK attributes with obj type */
		sk_priv_obj_type = SK_KEY_PAIR;
		privattrs[priv_attr_count].type = SK_ATTR_OBJECT_TYPE;
		privattrs[priv_attr_count].value = &sk_priv_obj_type;
		privattrs[priv_attr_count].valueLen = sizeof(SK_OBJECT_TYPE);
		priv_attr_count++;

		sk_pub_obj_type = SK_PUBLIC_KEY;
		pubattrs[pub_attr_count].type = SK_ATTR_OBJECT_TYPE;
		pubattrs[pub_attr_count].value = &sk_pub_obj_type;
		pubattrs[pub_attr_count].valueLen = sizeof(SK_OBJECT_TYPE);
		pub_attr_count++;

		/* Fill SK attributes with key type */
		sk_key_type = SKK_RSA;
		privattrs[priv_attr_count].type = SK_ATTR_KEY_TYPE;
		privattrs[priv_attr_count].value = &sk_key_type;
		privattrs[priv_attr_count].valueLen = sizeof(SK_KEY_TYPE);
		priv_attr_count++;

		pubattrs[pub_attr_count].type = SK_ATTR_KEY_TYPE;
		pubattrs[pub_attr_count].value = &sk_key_type;
		pubattrs[pub_attr_count].valueLen = sizeof(SK_KEY_TYPE);
		pub_attr_count++;

		/* Generate RSA key pair */
		res = TA_GenerateRSAKeyPair(&privateKey, &publicKey,
					params[1].memref.buffer,
					params[1].memref.size,
					privattrs, &priv_attr_count,
					pubattrs, &pub_attr_count);
		if (res != TEE_SUCCESS)
			goto out;
		break;
	case SKM_EC_PKCS_KEY_PAIR_GEN:
		/* Fill SK attributes with obj type */
		sk_priv_obj_type = SK_KEY_PAIR;
		privattrs[priv_attr_count].type = SK_ATTR_OBJECT_TYPE;
		privattrs[priv_attr_count].value = &sk_priv_obj_type;
		privattrs[priv_attr_count].valueLen = sizeof(SK_OBJECT_TYPE);
		priv_attr_count++;

		sk_pub_obj_type = SK_PUBLIC_KEY;
		pubattrs[pub_attr_count].type = SK_ATTR_OBJECT_TYPE;
		pubattrs[pub_attr_count].value = &sk_pub_obj_type;
		pubattrs[pub_attr_count].valueLen = sizeof(SK_OBJECT_TYPE);
		pub_attr_count++;

		/* Fill SK attributes with key type */
		sk_key_type = SKK_EC;
		privattrs[priv_attr_count].type = SK_ATTR_KEY_TYPE;
		privattrs[priv_attr_count].value = &sk_key_type;
		privattrs[priv_attr_count].valueLen = sizeof(SK_KEY_TYPE);
		priv_attr_count++;

		pubattrs[pub_attr_count].type = SK_ATTR_KEY_TYPE;
		pubattrs[pub_attr_count].value = &sk_key_type;
		pubattrs[pub_attr_count].valueLen = sizeof(SK_KEY_TYPE);
		pub_attr_count++;

		/* Generate EC key pair */
		res = TA_GenerateECKeyPair(&privateKey, &publicKey,
					params[1].memref.buffer,
					params[1].memref.size,
					privattrs, &priv_attr_count,
					pubattrs, &pub_attr_count);
		if (res != TEE_SUCCESS)
			goto out;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/*
	 * Pack SK attributes in data stream of object as follows:
	 * - First 32 bit of buffer -> No of SK attributes.
	 * - Then SK attibute structure array.
	 * - Then SK attributes value buffers whose pointers are
	 *   there in SK attribute structure array.
	 */
	DMSG("Pack SK attributes!\n");
	res = pack_sk_attrs(privattrs, priv_attr_count, &priv_attr_data,
			&priv_attr_data_len);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Pack SK attributes!\n");
	res = pack_sk_attrs(pubattrs, pub_attr_count, &pub_attr_data,
			&pub_attr_data_len);
	if (res != TEE_SUCCESS)
		goto out;


	DMSG("Get Object ID for Private Key!\n");
	res = TA_GetNextObjectID(&private_key_obj_id);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Create Persistent Object for Private Key!\n");
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &private_key_obj_id,
					sizeof(private_key_obj_id),
					TEE_DATA_FLAG_ACCESS_WRITE |
					TEE_DATA_FLAG_ACCESS_READ,
					privateKey, priv_attr_data,
					priv_attr_data_len,
					&privateKeyPersistent);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_CloseObject(privateKeyPersistent);

	DMSG("Get Next Object ID for Public Key!\n");
	res = TA_GetNextObjectID(&public_key_obj_id);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Create Persistent Object Public Key!\n");
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, &public_key_obj_id,
					sizeof(public_key_obj_id),
					TEE_DATA_FLAG_ACCESS_WRITE |
					TEE_DATA_FLAG_ACCESS_READ,
					publicKey, pub_attr_data,
					pub_attr_data_len,
					&publicKeyPersistent);
	if (res != TEE_SUCCESS)
		goto out;

	TEE_CloseObject(publicKeyPersistent);
	params[2].value.a = private_key_obj_id;
	params[2].value.b = public_key_obj_id;

	DMSG("TA_GenerateKeyPair Successful!\n");
out:
	if (publicKey != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(publicKey);
	if (privateKey != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(privateKey);
	if (priv_attr_data)
		TEE_Free(priv_attr_data);
	if (pub_attr_data)
		TEE_Free(pub_attr_data);

	return res;
}
