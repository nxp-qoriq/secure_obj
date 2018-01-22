/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <crypto/evp/evp_locl.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>

#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/tls1.h>

#include "securekey_api.h"

#define	PRINT_ERROR

#ifdef PRINT_ERROR
#define print_error(msg, ...) { \
printf("[SECURE_OBJ_ENG:%s, %d] Error: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_error(msg, ...)
#endif

#ifdef PRINT_INFO
#define print_info(msg, ...) { \
printf("[SECURE_OBJ_ENG:%s, %d] Info: ", __func__, __LINE__); \
printf(msg, ##__VA_ARGS__); \
}
#else
#define print_info(msg, ...)
#endif

static const char *engine_id = "eng_secure_obj";
static const char *engine_name = "Secure Object OpenSSL Engine.";

static RSA_METHOD secureobj_rsa = {
	"Secure Object RSA method",
	NULL,                       /* rsa_pub_enc */
	NULL,                       /* rsa_pub_dec */
	NULL,                       /* rsa_priv_enc */
	NULL,                       /* rsa_priv_dec */
	NULL,
	NULL,
	NULL,                       /* init */
	NULL,                       /* finish */
	0,                          /* flags */
	NULL,                       /* app_data */
	NULL,                       /* rsa_sign */
	NULL                        /* rsa_verify */
};

int rsa_crypto_ex_data_index;

static int secure_obj_rsa_priv_enc(int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding)
{
	uint32_t byte_key_size;
	uint8_t *padded_from = NULL;
	uint16_t out_len = 0;
	int ret = 0;

	SK_RET_CODE sk_ret = SKR_OK;
	SK_MECHANISM_INFO mechType = {0};
	SK_OBJECT_HANDLE *sk_key;

	byte_key_size = RSA_size(rsa);
	print_info("byte_key_size = %d\n", byte_key_size);

	out_len = byte_key_size;

	padded_from = (uint8_t *)malloc(byte_key_size);
	if (!padded_from) {
		print_error("padded_from malloc failed\n");
		goto failure;
	}

	switch (padding) {
		case RSA_PKCS1_PADDING:
			ret = RSA_padding_add_PKCS1_type_1(padded_from,
				byte_key_size, from, flen);
			if (ret == 0) {
				print_error("RSA_padding_add_PKCS1_type_1 failed\n");
				ret = -1;
				goto failure;
			}
			break;
		default:
			print_error("Unsupported padding type, only RSA_PKCS1_PADDING is supported\n");
			ret  = -1;
			goto failure;
	}

	mechType.mechanism = SKM_RSA_PKCS_NOPAD;
	sk_key = (SK_OBJECT_HANDLE *)RSA_get_ex_data(rsa,
		rsa_crypto_ex_data_index);

	sk_ret = SK_Decrypt(&mechType, *sk_key, padded_from,
			byte_key_size, to, &out_len);
	if (sk_ret != SKR_OK) {
		print_error("SK_Decrypt failed with ret code 0x%x\n", ret);
		ret = -1;
		goto failure;
	}

	print_info("out_len = %u\n", out_len);
	ret = byte_key_size;

failure:
	if (padded_from)
		free(padded_from);

	return ret;
}

static int secure_obj_rsa_priv_dec(int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding)
{
	uint32_t byte_key_size;
	uint8_t *padded_to;
	uint16_t out_len  = 0;
	int ret;

	SK_RET_CODE sk_ret = SKR_OK;
	SK_MECHANISM_INFO mechType = {0};
	SK_OBJECT_HANDLE *sk_key;

	byte_key_size = RSA_size(rsa);
	out_len = byte_key_size;

	print_info("byte_key_size = %d, flen = %d, padding = %d\n",
		byte_key_size, flen, padding);

	padded_to = (uint8_t *)malloc(byte_key_size);
	if (padded_to == NULL) {
		print_error("padded_to malloc  failed\n");
		ret = -1;
		goto failure;
	}

	mechType.mechanism = SKM_RSA_PKCS_NOPAD;
	sk_key = (SK_OBJECT_HANDLE *)RSA_get_ex_data(rsa,
		rsa_crypto_ex_data_index);

	print_info("SK_OBJECT_HANDLE = %u\n", *sk_key);

	sk_ret = SK_Decrypt(&mechType, *sk_key, from, flen,
			padded_to, &out_len);
	if (sk_ret != SKR_OK) {
		print_error("SK_Decrypt failed with ret code 0x%x\n", sk_ret);
		ret = -1;
		goto failure;
	}

	print_info("out_len = %u\n", out_len);

	switch (padding) {
		case RSA_PKCS1_PADDING:
			ret = RSA_padding_check_PKCS1_type_2(to,
				byte_key_size, padded_to, out_len,
				byte_key_size);
			if (ret == 0) {
				print_error("RSA_padding_check_PKCS1_type_2 failed\n");
				ret = -1;
				goto failure;
			}
			break;
		default:
			print_error("Unsupported padding type, only RSA_PKCS1_PADDING is supported\n");
			ret = -1;
			goto failure;
	}

failure:
	if (padded_to)
		free(padded_to);

	return ret;
}

static EVP_PKEY *secure_obj_engine_load_priv_key(ENGINE *e,
	const char *key_file, UI_METHOD *ui, void *cb_data)
{
	RSA *rsa = NULL;
	EVP_PKEY *priv_key = NULL;
	BIGNUM *rsa_n = NULL, *rsa_e = NULL;

	SK_RET_CODE ret;
	SK_ATTRIBUTE attrs[3];
	SK_OBJECT_HANDLE *hObject;
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;
	uint32_t objCount, i = 0;

	obj_type = SK_KEY_PAIR;
	key_type = SKK_RSA;

	memset(attrs, 0, 3 * sizeof(SK_ATTRIBUTE));

	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &obj_type;
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	attrs[1].type = SK_ATTR_KEY_TYPE;
	attrs[1].value = &key_type;
	attrs[1].valueLen = sizeof(SK_KEY_TYPE);

	attrs[2].type = SK_ATTR_OBJECT_LABEL;
	attrs[2].value = (char *)key_file;
	attrs[2].valueLen = strlen(key_file);

	hObject = (SK_OBJECT_HANDLE *)malloc(sizeof(SK_OBJECT_HANDLE));
	if (!hObject) {
		print_error("malloc failed for SK_OBJECT_HANDLE\n");
		goto failure;
	}

	ret = SK_EnumerateObjects(attrs, 3, hObject, 1, 	&objCount);
	if (ret != SKR_OK) {
		print_error("SK_EnumerateObjects failed with code = 0x%x\n", ret);
		goto failure;
	}

	memset(attrs, 0, sizeof(SK_ATTRIBUTE) * 3);

	if (objCount == 0)
		goto failure;

	attrs[0].type = SK_ATTR_MODULUS;
	attrs[0].value = NULL;
	attrs[0].valueLen = 0;

	attrs[1].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[1].value = NULL;
	attrs[1].valueLen = 0;

	ret = SK_GetObjectAttribute(*hObject, attrs, 2);
	if (ret != SKR_OK) {
		if (ret == SKR_ERR_ITEM_NOT_FOUND) {
			print_error("\nObject with label %s not found.\n", key_file);
		} else {
			print_error("\nSK_GetObjectAttribute failed with code = 0x%x\n", ret);
		}
		goto failure;
	}

	for (i = 0; i < 2; i++) {
		attrs[i].value = (void *)malloc(attrs[i].valueLen);
		if (!attrs[i].value) {
			print_error("malloc failed ATTR[%d].Value\n", i);
			goto failure;
		}
	}

	ret = SK_GetObjectAttribute(*hObject, attrs, 2);
	if (ret != SKR_OK) {
		print_error("Failed to Get Attribute Values.\n");
		goto failure;
	}

	rsa_n = BN_bin2bn(attrs[0].value, attrs[0].valueLen, rsa_n);
	if (!rsa_n) {
		print_error("BN_bin2bn failed for Modulus\n");
		goto failure;
	}

	rsa_e = BN_bin2bn(attrs[1].value, attrs[1].valueLen, rsa_e);
	if (!rsa_e) {
		print_error("BN_bin2bn failed for public key exponent\n");
		goto failure;
	}

	rsa = RSA_new();
	if (!rsa)
		goto failure;

	rsa->n = rsa_n;
	rsa->e = rsa_e;

	priv_key = EVP_PKEY_new();
	if (!priv_key)
		goto failure;

	EVP_PKEY_set1_RSA(priv_key, rsa);
	RSA_set_ex_data(rsa, rsa_crypto_ex_data_index, hObject);

	goto success;

failure:
	if (rsa)
		RSA_free(rsa);
	if (rsa_n)
		BN_clear_free(rsa_n);
	if (rsa_e)
		BN_clear_free(rsa_e);
	if (hObject)
		free(hObject);
success:
	for (i = 0; i < 2; i ++) {
		if (attrs[i].value)
			free(attrs[i].value);
	}

	return priv_key;
}

static void secure_obj_crypto_ex_free(void *obj, void *item,
	CRYPTO_EX_DATA *ad, int idx, long argl, void *argp)
{
	free(item);
}

static int bind(ENGINE *engine, const char *id)
{
	int ret = 0;

	if (!ENGINE_set_id(engine, engine_id) ||
		!ENGINE_set_name(engine, engine_name)) {
		print_error("ENGINE_set_id or ENGINE_set_name or ENGINE_set_init_function failed\n");
		goto end;
	}

	if (ENGINE_set_RSA(engine, &secureobj_rsa)) {
		const RSA_METHOD *rsa_meth = RSA_PKCS1_SSLeay();

		secureobj_rsa.bn_mod_exp = rsa_meth->bn_mod_exp;
		secureobj_rsa.rsa_mod_exp = rsa_meth->rsa_mod_exp;
		secureobj_rsa.rsa_pub_enc = rsa_meth->rsa_pub_enc;
		secureobj_rsa.rsa_pub_dec = rsa_meth->rsa_pub_dec;
		secureobj_rsa.rsa_priv_enc = secure_obj_rsa_priv_enc;
		secureobj_rsa.rsa_priv_dec = secure_obj_rsa_priv_dec;
	} else {
		print_error("ENGINE_set_RSA failed\n");
		goto end;
	}

	rsa_crypto_ex_data_index = RSA_get_ex_new_index(0, "Secure Object OpenSSL Engine",
		NULL, NULL, secure_obj_crypto_ex_free);
	if (rsa_crypto_ex_data_index == -1)
		print_error("RSA_get_ex_new_index failed\n");

	if (!ENGINE_set_load_privkey_function(engine,
		secure_obj_engine_load_priv_key)) {
		print_error("ENGINE_set_load_privkey_function failed\n");
		goto end;
	}

	if (!ENGINE_set_default_RSA(engine)) {
		print_error("ENGINE_set_default_RSA failed\n");
		goto end;
	}

	ret = 1;
end:
	return ret;
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
