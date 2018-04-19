/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <securekey_api.h>
#include <openssl/pem.h>
#include <unistd.h>
#include "utils.h"

#define	SOBJ_KEY_ID	0xE1E2E3E4

struct getOptValue {
	uint32_t main_option;
	uint32_t numOfMainOpt;
	uint8_t *data;
	uint8_t *signed_data;
	uint8_t *importPrvFile;
	uint32_t key_len;
	SK_OBJECT_HANDLE hObj;
	uint32_t hObjc;
	SK_OBJECT_TYPE obj_type;
	uint32_t obj_id;
	SK_KEY_TYPE key_type;
	SK_MECHANISM_TYPE mech_type;
	char *label;
	int findCritCount;
	char *write_to_file;
};

int generate_rsa_key(rsa_3form_key_t *rsa_3form_key, struct getOptValue *getOptVal)
{
	int             ret = APP_OK;
	BIGNUM          *bne = NULL;
	BIO             *bp_public = NULL, *bp_private = NULL;

	int             bits;
	unsigned long   e;
	RSA *rsa = NULL;

	if (getOptVal->importPrvFile) {
		printf("Import Key from %s\n", getOptVal->importPrvFile);
		bp_private = BIO_new(BIO_s_file());
		if (bp_private == NULL) {
			printf("Failure Opening BIO Object.\n");
			ret = APP_PEM_READ_ERROR;
			goto cleanup;
		}
		ret = BIO_read_filename(bp_private, getOptVal->importPrvFile);
		if (ret != 1) {
			printf("Reading Private Key Pem file Failed.\n");
			ret = APP_PEM_READ_ERROR;
			goto cleanup;
		}

		ret = APP_OK;

		rsa = PEM_read_bio_RSAPrivateKey(bp_private, &rsa, NULL, NULL);
		if (rsa == NULL) {
			printf("Fetching RSA Key from Pem file Failed.\n");
			ret = APP_PEM_READ_ERROR;
			goto cleanup;
		}
		getOptVal->key_len = BN_num_bits(rsa->n);
		printf("Key Length = %d\n", getOptVal->key_len);

	} else {
		rsa = RSA_new();
		e = RSA_F4;
		bits = getOptVal->key_len;
		bne = BN_new();
		ret = BN_set_word(bne, e);
		if (ret != 1) {
			ret = APP_OPSSL_KEY_GEN_ERR;
			goto cleanup;
		}
		ret = APP_OK;
		ret = RSA_generate_key_ex(rsa, bits, bne, NULL);
		if (ret != 1) {
			ret = APP_OPSSL_KEY_GEN_ERR;
			goto cleanup;
		}
		ret = APP_OK;
		bp_public = BIO_new_file("sk_public.pem", "w+");
		ret = PEM_write_bio_RSAPublicKey(bp_public, rsa);
		if (ret != 1) {
			printf("Creating Public Key Pem file Failed.\n");
			ret = APP_OPSSL_KEY_GEN_ERR;
			goto cleanup;
		}

		ret = APP_OK;
		bp_private = BIO_new_file("sk_private.pem", "w+");
		ret = PEM_write_bio_RSAPrivateKey(bp_private, rsa, NULL, NULL, 0, NULL, NULL);
		if (ret != 1) {
			printf("Creating Private Key Pem file Failed.\n");
			ret = APP_OPSSL_KEY_GEN_ERR;
			goto cleanup;
		}
		ret = APP_OK;
	}

	BN_bn2bin(rsa->n, rsa_3form_key->rsa_modulus);
	BN_bn2bin(rsa->e, rsa_3form_key->rsa_pub_exp);
	BN_bn2bin(rsa->d, rsa_3form_key->rsa_priv_exp);
	BN_bn2bin(rsa->p, rsa_3form_key->rsa_prime1);
	BN_bn2bin(rsa->q, rsa_3form_key->rsa_prime2);
	BN_bn2bin(rsa->dmp1, rsa_3form_key->rsa_exp1);
	BN_bn2bin(rsa->dmq1, rsa_3form_key->rsa_exp2);
	BN_bn2bin(rsa->iqmp, rsa_3form_key->rsa_coeff);

cleanup:
	if (bp_public)
		BIO_free_all(bp_public);

	if (bp_private)
		BIO_free_all(bp_private);

	if (bne)
		BN_free(bne);

	if (rsa)
		RSA_free(rsa);

	return ret;
}

static void populate_attrs(SK_ATTRIBUTE *attrs, void *key, struct getOptValue *getOptVal)
{
	rsa_3form_key_t *rsa_3form_key;

	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &(getOptVal->obj_type);
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	attrs[1].type = SK_ATTR_OBJECT_INDEX;
	attrs[1].value = &(getOptVal->obj_id);
	attrs[1].valueLen = sizeof(uint32_t);

	attrs[2].type = SK_ATTR_KEY_TYPE;
	attrs[2].value = &(getOptVal->key_type);
	attrs[2].valueLen = sizeof(SK_KEY_TYPE);

	attrs[3].type = SK_ATTR_OBJECT_LABEL;
	attrs[3].value = getOptVal->label;
	attrs[3].valueLen = strlen(getOptVal->label);

	attrs[4].type = SK_ATTR_MODULUS_BITS;
	attrs[4].value = &(getOptVal->key_len);
	attrs[4].valueLen = sizeof(uint32_t);

	switch (getOptVal->key_type) {

	case SKK_RSA:
		rsa_3form_key = (rsa_3form_key_t *) key;

		attrs[5].type = SK_ATTR_MODULUS;
		attrs[5].value = (void *)(rsa_3form_key->rsa_modulus);
		attrs[5].valueLen = ((getOptVal->key_len + 7) >> 3);

		attrs[6].type = SK_ATTR_PUBLIC_EXPONENT;
		attrs[6].value = (void *)(rsa_3form_key->rsa_pub_exp);
		attrs[6].valueLen = 3;

		attrs[7].type = SK_ATTR_PRIVATE_EXPONENT;
		attrs[7].value = (void *)(rsa_3form_key->rsa_priv_exp);
		attrs[7].valueLen = ((getOptVal->key_len + 7) >> 3);

		attrs[8].type = SK_ATTR_PRIME_1;
		attrs[8].value = (void *)(rsa_3form_key->rsa_prime1);
		attrs[8].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

		attrs[9].type = SK_ATTR_PRIME_2;
		attrs[9].value = (void *)(rsa_3form_key->rsa_prime2);
		attrs[9].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

		attrs[10].type = SK_ATTR_EXPONENT_1;
		attrs[10].value = (void *)(rsa_3form_key->rsa_exp1);
		attrs[10].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

		attrs[11].type = SK_ATTR_EXPONENT_2;
		attrs[11].value = (void *)(rsa_3form_key->rsa_exp2);
		attrs[11].valueLen = ((getOptVal->key_len + 7) >> 3)/2;

		attrs[12].type = SK_ATTR_COEFFICIENT;
		attrs[12].value = (void *)(rsa_3form_key->rsa_coeff);
		attrs[12].valueLen = ((getOptVal->key_len + 7) >> 3)/2;
		break;
	default:
		printf("Un-Supported Key Format\n");
		break;
	}
}

unsigned char *copy_bio_data(BIO *out, int *data_lenp)
{
	unsigned char *data, *tdata;
	int data_len;

	data_len = BIO_get_mem_data(out, &tdata);
	data = malloc(data_len+1);
	if (data) {
		memcpy(data, tdata, data_len);
		data[data_len]='\0';  // Make sure it's \0 terminated, in case used as string
		if (data_lenp) {
			*data_lenp = data_len;
		}
	} else {
		printf("malloc failed");
	}
	return data;
}

char *generate_fake_private_RSA_key (int key_size, uint32_t obj_id,
	void *pub_exp, uint16_t pub_exp_len, void *modulus, uint16_t modulus_len)
{
	char *key_data = NULL, *priv_key_exp_temp = NULL;
	uint32_t *priv_key_exp = NULL, priv_key_len  = 0;
	int i = 0, j = 0;

	RSA *rsa = RSA_new();
	if (!rsa) {
		printf("RSA_new failed\n");
		goto end;
	}

	BIGNUM *bn = BN_new();
	if (!bn) {
		printf("BN_new failed\n");
		goto end;
	}

	BN_set_word(bn, 0x10001);
	RSA_generate_key_ex(rsa, key_size, bn, NULL);

	rsa->e = BN_bin2bn(pub_exp, pub_exp_len, rsa->e);
	if (!rsa->e) {
		printf("BN_bin2bn failed for pub exp\n");
		goto end;
	}

	rsa->n = BN_bin2bn(modulus, modulus_len, rsa->n);
	if (!rsa->n) {
		printf("BN_bin2bn failed for modulus\n");
		goto end;
	}

	priv_key_len = RSA_size(rsa);
	priv_key_exp_temp = (char *)malloc(priv_key_len);
	if (!priv_key_exp_temp) {
		printf("malloc failed for priv_key_exp_temp\n");
		goto end;
	}

	BN_bn2bin(rsa->d, priv_key_exp_temp);

	priv_key_exp_temp[0] = 0x10;

	priv_key_exp = (uint32_t *)priv_key_exp_temp;

#if 0
	for (i = 1; i < priv_key_len; i++) {
		priv_key_exp_temp[i] = 0x00;
	}
#endif

	priv_key_exp_temp[priv_key_len - 1] = obj_id;
	for (j=0; j<2; j++) {
		for (i=5; i<9; i++) {
			priv_key_exp_temp[priv_key_len-i-(j*4)] = (uint8_t)(SOBJ_KEY_ID>> 8*(i-5));
                        }
	}

#if 0
	for (i = 0; i < priv_key_len; i++) {
		printf("%02x:", priv_key_exp_temp[i]);
		if (((i+1) %16) == 0)
			printf("\n");
	}
#endif

	rsa->d = BN_bin2bn((char *)priv_key_exp, priv_key_len, rsa->d);
	if (!rsa->d) {
		printf("BN_bin2bn failed for priv exp\n");
		goto end;
	}

	BIO *out = BIO_new(BIO_s_mem());
	if (!out) {
		printf("BIO_new failed\n");
		goto end;
	}

	PEM_write_bio_RSAPrivateKey(out, rsa, NULL, NULL, 0, NULL, NULL);
	key_data = (char *)copy_bio_data(out, NULL);

end:
	if (out)
		BIO_free(out);
	if (bn)
		BN_free(bn);
	if (rsa)
		RSA_free(rsa);
	if (priv_key_exp)
		free(priv_key_exp);
	return (key_data);
}


static int do_CreateObject(struct getOptValue *getOptVal)
{
	int ret = APP_OK, i = 0;;
	SK_ATTRIBUTE *attrs = NULL;
	SK_RET_CODE sk_ret;
	uint16_t attrCount = 0;
	SK_OBJECT_HANDLE hObject;
	rsa_3form_key_t rsa_3form_key;
	uint32_t obj_id;
	FILE *fptr = NULL;
	char *key_data = NULL, *file_name = NULL;

	switch (getOptVal->key_type) {
	case SKK_RSA:
		rsa_3form_key.rsa_modulus =
			(uint8_t *) malloc(5*((getOptVal->key_len + 7) >> 3));
		if (!rsa_3form_key.rsa_modulus) {
			printf("Failure in allocating memory.\n");
			ret = APP_MALLOC_FAIL;
			goto cleanup;
		}
		rsa_3form_key.rsa_pub_exp = rsa_3form_key.rsa_modulus + ((getOptVal->key_len + 7) >> 3);
		rsa_3form_key.rsa_priv_exp = rsa_3form_key.rsa_pub_exp + sizeof(RSA_F4);
		rsa_3form_key.rsa_prime1 = rsa_3form_key.rsa_priv_exp + ((getOptVal->key_len + 7) >> 3);
		rsa_3form_key.rsa_prime2 = rsa_3form_key.rsa_prime1 + ((getOptVal->key_len + 7) >> 3)/2;
		rsa_3form_key.rsa_exp1 = rsa_3form_key.rsa_prime2 + ((getOptVal->key_len + 7) >> 3)/2;
		rsa_3form_key.rsa_exp2 = rsa_3form_key.rsa_exp1 + ((getOptVal->key_len + 7) >> 3)/2;
		rsa_3form_key.rsa_coeff = rsa_3form_key.rsa_exp2 + ((getOptVal->key_len + 7) >> 3)/2;

		ret = generate_rsa_key(&rsa_3form_key, getOptVal);
		if (ret != APP_OK) {
			printf("Failure Generating RSA Key.\n");
			goto cleanup;
		}
		/*printRSA_key(&rsa_3form_key, getOptVal->key_len);*/

		attrCount = MAX_RSA_ATTRIBUTES;
		attrs = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) * attrCount);
		if (attrs == NULL) {
			printf("malloc failed\n");
			ret = APP_MALLOC_FAIL;
			goto cleanup;
		}

		populate_attrs(attrs, &rsa_3form_key, getOptVal);
		break;
	default:
		break;
	}

	ret = SK_CreateObject(attrs, attrCount, &hObject);
	if (ret != SKR_OK) {
		printf("SK_CreateObject failed wit err code = 0x%x\n", ret);
		ret = APP_SKR_ERR;
		goto cleanup;
	} else {
		ret = APP_OK;
		printf("Object created successfully handle = %u\n", hObject);
	}

	memset(attrs, 0, sizeof(SK_ATTRIBUTE) * MAX_RSA_ATTRIBUTES);

	attrs[0].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[0].value = NULL;
	attrs[0].valueLen = 0;

	attrs[1].type = SK_ATTR_MODULUS;
	attrs[1].value = NULL;
	attrs[1].valueLen = 0;

	sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
	if (sk_ret != SKR_OK) {
		if (sk_ret == SKR_ERR_ITEM_NOT_FOUND)
			printf("\nObject Handle[%d] not found.\n", hObject);
		else
			printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", sk_ret);

		ret = APP_SKR_ERR;
		goto cleanup;
	}

	ret = APP_OK;
	for (i = 0; i < 2; i++) {
		if ((int16_t)(attrs[i].valueLen) != -1) {
			attrs[i].value =
				(void *)malloc(attrs[i].valueLen);

			if (!attrs[i].value) {
				printf("malloc failed ATTR[%d].Value\n", i);
				ret = APP_MALLOC_FAIL;
				goto cleanup;
			}
		}
	}

	sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
	if (sk_ret != SKR_OK) {
		printf("Failed to Get Attribute Values.\n");
		ret = APP_SKR_ERR;
		goto cleanup;
	}

	/* Here we are generating a fake .pem file for satisfying
	kubernetes/puppet use case */
	 if (getOptVal->write_to_file) {
		obj_id = getOptVal->obj_id;
		file_name = getOptVal->write_to_file;

		key_data = generate_fake_private_RSA_key(getOptVal->key_len, obj_id,
			attrs[0].value, attrs[0].valueLen,
			attrs[1].value, attrs[1].valueLen);
		if (!key_data) {
			printf("generate_fake_private_RSA_key failed \n");
			ret = APP_SKR_ERR;
			goto cleanup;
		}

		fptr = fopen(file_name, "wb");
		if (fptr == NULL) {
			printf("File does not exists\n");
			ret = APP_SKR_ERR;
			goto cleanup;
		}
		fwrite(key_data, sizeof(char), strlen(key_data), fptr);
	}

cleanup:
	if (attrs) {
		for (i = 0; i < 2; i++) {
			if (attrs[i].value)
				free(attrs[i].value);
		}
		free(attrs);
	}

	switch (getOptVal->key_type) {
	case SKK_RSA:
		if (rsa_3form_key.rsa_modulus)
			free(rsa_3form_key.rsa_modulus);
		break;
	default:
		break;
	}

	if (key_data)
		free(key_data);
	if (fptr)
		fclose(fptr);

	return ret;
}

static int do_GenerateKeyPair(struct getOptValue *getOptVal)
{
	int ret = APP_OK, i = 0;
	SK_RET_CODE sk_ret;
	SK_ATTRIBUTE attrs[4];
	SK_OBJECT_HANDLE hObject;
	SK_MECHANISM_INFO mechanismType = {0};
	FILE *fptr = NULL;
	char *label = NULL, *file_name = NULL;
	char *key_data = NULL;
	uint32_t obj_id;
	static const uint8_t rsa_pub_exp[] = {
		0x01, 0x00, 0x01
	};

	mechanismType.mechanism = getOptVal->mech_type;

	attrs[0].type = SK_ATTR_OBJECT_INDEX;
	attrs[0].value = &(getOptVal->obj_id);
	attrs[0].valueLen = sizeof(uint32_t);

	attrs[1].type = SK_ATTR_OBJECT_LABEL;
	attrs[1].value = getOptVal->label;
	attrs[1].valueLen = strlen(getOptVal->label);

	attrs[2].type = SK_ATTR_MODULUS_BITS;
	attrs[2].value = &(getOptVal->key_len);
	attrs[2].valueLen = sizeof(uint32_t);

	attrs[3].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[3].value = (void *)rsa_pub_exp;
	attrs[3].valueLen = sizeof(rsa_pub_exp);

	sk_ret = SK_GenerateKeyPair(&mechanismType, attrs, 4, &hObject);
	if (sk_ret != SKR_OK) {
		printf("SK_GenerateKeyPair failed wit err code = 0x%x\n", sk_ret);
		ret = APP_SKR_ERR;
		goto end;
	} else {
		ret = APP_OK;
		printf("Object generated successfully handle = %u\n", hObject);
	}

	memset(attrs, 0, sizeof(SK_ATTRIBUTE) * 4);

	attrs[0].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[0].value = NULL;
	attrs[0].valueLen = 0;

	attrs[1].type = SK_ATTR_MODULUS;
	attrs[1].value = NULL;
	attrs[1].valueLen = 0;

	sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
	if (sk_ret != SKR_OK) {
		if (sk_ret == SKR_ERR_ITEM_NOT_FOUND)
			printf("\nObject Handle[%d] not found.\n", hObject);
		else
			printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", sk_ret);

		ret = APP_SKR_ERR;
		goto end;
	}

	ret = APP_OK;
	for (i = 0; i < 2; i++) {
		if ((int16_t)(attrs[i].valueLen) != -1) {
			attrs[i].value =
				(void *)malloc(attrs[i].valueLen);

			if (!attrs[i].value) {
				printf("malloc failed ATTR[%d].Value\n", i);
				ret = APP_MALLOC_FAIL;
				goto end;
			}
		}
	}

	sk_ret = SK_GetObjectAttribute(hObject, attrs, 2);
	if (sk_ret != SKR_OK) {
		printf("Failed to Get Attribute Values.\n");
		ret = APP_SKR_ERR;
		goto end;
	}

	/* Here we are generating a fake .pem file for satisfying
	kubernetes/puppet use case */
	 if (getOptVal->write_to_file) {
		obj_id = getOptVal->obj_id;
		file_name = getOptVal->write_to_file;

		key_data = generate_fake_private_RSA_key(getOptVal->key_len, obj_id,
			attrs[0].value, attrs[0].valueLen,
			attrs[1].value, attrs[1].valueLen);
		if (!key_data) {
			printf("generate_fake_private_RSA_key failed \n");
			ret = APP_SKR_ERR;
			goto end;
		}

		fptr = fopen(file_name, "wb");
		if (fptr == NULL) {
			printf("File does not exists\n");
			ret = APP_SKR_ERR;
			goto end;
		}
		fwrite(key_data, sizeof(char), strlen(key_data), fptr);
	}

end:
	for (i = 0; i < 2; i++) {
		if (attrs[i].value)
			free(attrs[i].value);
	}

	if (key_data)
		free(key_data);
	if (fptr)
		fclose(fptr);

	return ret;
}

static int do_EraseObject(SK_OBJECT_HANDLE hObject)
{
	int ret = APP_OK, i = 0;

	ret = SK_EraseObject(hObject);

	if (ret != SKR_OK) {
		printf("SK_EraseObject failed with code = 0x%x\n", ret);
		ret = APP_SKR_ERR;
	} else {
		ret = APP_OK;
		printf("SK_EraseObject successful\n");
	}

	return ret;
}

static int do_EnumerateObject(struct getOptValue *getOptVal)
{
	int ret = APP_OK, i = 0;
	SK_ATTRIBUTE *attrs = NULL;
	SK_OBJECT_HANDLE hObject[getOptVal->hObjc];
	uint32_t objCount;

	if (getOptVal->findCritCount) {
		attrs = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) * getOptVal->findCritCount);
		if (attrs == NULL) {
			printf("Malloc Failed. Not Applying searching attributes.\n");
			goto enumerate;
		}
		if (getOptVal->obj_type != U32_UNINTZD) {
			attrs[i].type = SK_ATTR_OBJECT_TYPE;
			attrs[i].value = &(getOptVal->obj_type);
			attrs[i].valueLen = sizeof(SK_OBJECT_TYPE);
			i++;
		}
		if (getOptVal->obj_id != U32_UNINTZD) {
			attrs[i].type = SK_ATTR_OBJECT_INDEX;
			attrs[i].value = &(getOptVal->obj_id);
			attrs[i].valueLen = sizeof(SK_OBJECT_TYPE);
			i++;
		}
		if (getOptVal->key_type != U32_UNINTZD) {
			attrs[i].type = SK_ATTR_KEY_TYPE;
			attrs[i].value = &(getOptVal->key_type);
			attrs[i].valueLen = sizeof(SK_KEY_TYPE);
			i++;
		}
		if (getOptVal->label) {
			attrs[i].type = SK_ATTR_OBJECT_LABEL;
			attrs[i].value = getOptVal->label;
			attrs[i].valueLen = strlen(getOptVal->label);
			i++;
		}
		if (getOptVal->key_len != U32_UNINTZD) {
			/*
			 * Since only RSA keys are supported.
			 * Hence, setting type SK_ATTR_MODULUS_BITS
			 */
			attrs[i].type = SK_ATTR_MODULUS_BITS;
			attrs[i].value = &(getOptVal->key_len);
			attrs[i].valueLen = sizeof(uint32_t);
			i++;
		}
	}

enumerate:
	ret = SK_EnumerateObjects(attrs, i, hObject, getOptVal->hObjc,
			&objCount);
	if (ret != SKR_OK) {
		printf("SK_EnumerateObjects failed with code = 0x%x\n", ret);
		ret = APP_SKR_ERR;
	} else {
		ret = APP_OK;
		if (!objCount)
			printf("No Object Found.\n\n");
		printf("Following objects found:\n");
		for (i = 0; i < objCount; i++)
			printf("Object[%u] handle = %u\n", i, hObject[i]);
	}

	if (attrs)
		free(attrs);

	return ret;
}

static int do_GetObjectAttributes(SK_OBJECT_HANDLE hObject)
{
	int ret = APP_OK, i = 0, j = 0;
	int attrCount = 4;
	SK_ATTRIBUTE attrs[attrCount];
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;

	attrs[i].type = SK_ATTR_OBJECT_LABEL;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	attrs[i].type = SK_ATTR_OBJECT_INDEX;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	attrs[i].type = SK_ATTR_OBJECT_TYPE;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	attrs[i].type = SK_ATTR_KEY_TYPE;
	attrs[i].value = NULL;
	attrs[i].valueLen = 0;
	i++;

	ret = SK_GetObjectAttribute(hObject, attrs, i);
	if (ret != SKR_OK) {
		if (ret == SKR_ERR_ITEM_NOT_FOUND)
			printf("\nObject Handle[%d] not found.\n", hObject);
		else
			printf("\nSK_GetObjectAttribute failed with code = 0x%x\n", ret);

		ret = APP_SKR_ERR;
		goto cleanup;
	}
	ret = APP_OK;
	for (j = 0; j < i; j++) {
		if ((int16_t)(attrs[j].valueLen) != -1) {
			attrs[j].value =
				(void *)malloc(attrs[j].valueLen);

			if (!attrs[j].value) {
				printf("malloc failed ATTR[%d].Value\n", j);
				ret = APP_MALLOC_FAIL;
				goto cleanup;
			}
		}
	}
	ret = SK_GetObjectAttribute(hObject, attrs, i);
	if (ret != SKR_OK) {
		printf("Failed to Get Attribute Values.\n");
		ret = APP_SKR_ERR;
		goto cleanup;
	}
	ret = APP_OK;

	printf("Attributes of Object Handle: %u\n", hObject);
	i = 0;
	printf("\tObject Label: %s\n", ((char *)(attrs[i].value)));

	i++;
	printf("\tObject Id: %u\n", *((char *)(attrs[i].value)));

	i++;
	printf("\tObject Type: %s[0x%x]\n", getObjTypeStr(*(SK_OBJECT_TYPE *)(attrs[i].value)),
			*(SK_OBJECT_TYPE *)(attrs[i].value));

	i++;
	printf("\tObject Key Type: %s[0x%x]\n", getKeyTypeStr(*(SK_KEY_TYPE *)(attrs[i].value)),
			*(SK_KEY_TYPE *)(attrs[i].value));

cleanup:
	for (j = 0; j < i; j++) {
		if (!attrs[j].value)
			free(attrs[j].value);
	}

	return ret;
}

void print_usage(void)
{
	printf("    Only one of the below options are allowed per execution:-\n\n");
	printf("\t -C - Create Object\n");
	printf("\t -G - Generate Object\n");
	printf("\t -A - Attributes of the Object\n");
	printf("\t -L - List Object\n");
	printf("\t -R - Remove/Erase Object\n\n");
	printf("\t Use below Sub options along with Main options:-\n");
	printf("\t\t -o - Object Type (Eg: pair, pub etc.)\n");
	printf("\t\t -k - Key Type (Eg: rsa, ec etc.)\n");
	printf("\t\t -s - Key Size/Length (Supported: 1024, 2048).\n");
	printf("\t\t -f - File Name (.pem) (Private Key).\n");
	printf("\t\t -l - Object Label\n");
	printf("\t\t -i - Object Id. (In Decimal)\n");
	printf("\t\t -h - Object Handle (In Decimal)\n");
	printf("\t\t -n - Number of Objects (Default = 5)\n");
	printf("\t\t -m - Mechanism Id (Eg. rsa-pair, etc.)\n");
	printf("\t\t -w - Fake .pem file.(Optional command while generating key-pair)\n\n");
	printf("\tUsage:\n");
	printf("\t\tCreation:\n");
	printf("\t\tsobj_app -C -f <private.pem> -k <key-type> -o <obj-type> -s <key-size> -l <obj-label> -i <obj-ID> [-w <file.pem>]\n");
	printf("\t\tsobj_app -C -f sk_private.pem -k rsa -o pair -s 2048 -l \"Device_Key\" -i 1\n");
	printf("\t\tsobj_app -C -f sk_private.pem -k rsa -o pair -s 2048 -l \"Device_Key\" -i 1 -w dev_key.pem\n\n");
	printf("\t\tGeneration:\n");
	printf("\t\tsobj_app -G -m <mechanism-ID> -s <key-size> -l <key-label> -i <key-ID> [-w <file.pem>]\n");
	printf("\t\tsobj_app -G -m rsa-pair -s 2048 -l \"Device_Key\" -i 1\n");
	printf("\t\tsobj_app -G -m rsa-pair -s 2048 -l \"Device_Key\" -i 1 -w dev_key.pem\n\n");
	printf("\t\tAttributes:\n");
	printf("\t\tsobj_app -A -h <obj-handle>\n");
	printf("\t\tsobj_app -A -h 1\n\n");
	printf("\t\tList:\n");
	printf("\t\tsobj_app -L [-n <num-of-obj> -k <key-type> -l <obj-label> -s <key-size> -i <obj-id>]\n");
	printf("\t\t Objects can be listed based on combination of any above criteria.\n\n");
	printf("\t\tRemove\n");
	printf("\t\tsobj_app -R -h <obj-handle>\n");
	printf("\t\tsobj_app -R -h 1\n\n");
}

int process_sub_option(int option, char *optarg, struct getOptValue *getOptVal)
{
	int ret = APP_OK;
	FILE *file;

	switch (option) {
	case 'f':
		getOptVal->importPrvFile = optarg;
		file = fopen(getOptVal->importPrvFile, "r");
		if (!file) {
			ret = APP_IP_ERR;
			printf("Error Opening the File.\n");
		}
		if (file)
			fclose(file);
		break;
	case 's':
		getOptVal->key_len = atoi(optarg);
		if (U32_INVALID == validate_key_len(getOptVal->key_len))
			ret = APP_IP_ERR;
		getOptVal->findCritCount++;
		break;
	case 'k':
		getOptVal->key_type = getKeyType(optarg);
		if (U32_INVALID == getOptVal->key_type)
			ret = APP_IP_ERR;
		getOptVal->findCritCount++;
		break;
	case 'l':
		getOptVal->label = optarg;
		getOptVal->findCritCount++;
		break;
	case 'o':
		getOptVal->obj_type = getObjectType(optarg);
		if (U32_INVALID == getOptVal->obj_type)
			ret = APP_IP_ERR;
		getOptVal->findCritCount++;
		break;
	case 'i':
		getOptVal->obj_id = atoi(optarg);
		getOptVal->findCritCount++;
		break;
	case 'h':
		getOptVal->hObj = atoi(optarg);
		break;
	case 'n':
		getOptVal->hObjc = atoi(optarg);
		break;
	case 'm':
		getOptVal->mech_type = getMechType(optarg);
		if (U32_INVALID == getOptVal->mech_type)
			ret = APP_IP_ERR;
		break;
	case 'w':
		getOptVal->write_to_file = optarg;
		break;
	}
	return ret;
}

int process_main_option(int operation,
		int option,
		char *optarg,
		struct getOptValue *getOptVal)
{
	int ret = APP_OK;

	switch (option) {
	case 'C':
		if (operation == PERFORM) {
			printf("Creating the Object.\n");
			if ((getOptVal->key_type == U32_UNINTZD)
				|| (getOptVal->obj_type == U32_UNINTZD)
				|| (getOptVal->obj_id == U32_UNINTZD)
				|| (getOptVal->label == NULL)
				|| (getOptVal->key_len == U32_UNINTZD)
				|| (getOptVal->importPrvFile == NULL)) {
					printf("\tAbort: Missing or Invalid Value to the mandatory options [-f -k -o -i -l -s]\n");
				ret = APP_IP_ERR;
				break;
			}
			ret = do_CreateObject(getOptVal);
		} else {
			getOptVal->main_option = option;
			(getOptVal->numOfMainOpt)++;
		}
		break;
	case 'G':
		if (operation == PERFORM) {
			printf("Generating the Object.\n");
			if ((getOptVal->mech_type == U32_UNINTZD)
				|| (getOptVal->obj_id == U32_UNINTZD)
				|| (getOptVal->label == NULL)
				|| (getOptVal->key_len == U32_UNINTZD)) {
					printf("\tAbort: Missing or Invalid Value to one or more of the mandatory options [-i -l -s -m]\n");
					ret = APP_IP_ERR;
				break;
			}
			ret = do_GenerateKeyPair(getOptVal);
		} else {
			getOptVal->main_option = option;
			(getOptVal->numOfMainOpt)++;
		}
		break;
	case 'R':
		if (operation == PERFORM) {
			if (getOptVal->hObj == U32_UNINTZD) {
				printf("Object Handle is not provided to remove/erase. Missing[-h].\n");
				ret = APP_IP_ERR;
				break;
			}
			ret = do_EraseObject(getOptVal->hObj);
		} else {
			getOptVal->main_option = option;
			(getOptVal->numOfMainOpt)++;
		}
		break;
	case 'L':
		if (operation == PERFORM) {
			if (!getOptVal->findCritCount)
				printf("None of the search option (-i -o -k -s -l) is provided. Listing all Object.\n");
			if (getOptVal->hObjc == U32_UNINTZD) {
				printf("Missing Option [-n]. Listing max of 5 objects.\n");
				getOptVal->hObjc = MAX_FIND_OBJ_SIZE;
			}
			ret = do_EnumerateObject(getOptVal);
		} else {
			getOptVal->main_option = option;
			(getOptVal->numOfMainOpt)++;
		}
		break;
	case 'A':
		if (operation == PERFORM) {
			if (getOptVal->hObj == U32_UNINTZD) {
				printf("Object Handle is not provided for Attribute Listing. Missing[-h].\n");
				ret = APP_IP_ERR;
				break;
			}
			ret = do_GetObjectAttributes(getOptVal->hObj);
		} else {
			getOptVal->main_option = option;
			(getOptVal->numOfMainOpt)++;
		}
		break;
	default:
		if (getOptVal->numOfMainOpt) {
			if (option != '?')
				ret = process_sub_option(option, optarg, getOptVal);
		} else {
			print_usage();
			exit(EXIT_FAILURE);
		}
	}
	return ret;
}

int main(int argc, char *argv[])
{
	struct getOptValue getOptVal = {
		.main_option = U32_UNINTZD,
		.numOfMainOpt = 0,
		.data = NULL,
		.signed_data = NULL,
		.importPrvFile = NULL,
		.key_len = U32_UNINTZD,
		.hObj = U32_UNINTZD,
		.hObjc = U32_UNINTZD,
		.label = NULL,
		.key_type = U32_UNINTZD,
		.obj_type = U32_UNINTZD,
		.obj_id = U32_UNINTZD,
		.mech_type = U32_UNINTZD,
		.findCritCount = 0,
		.write_to_file = NULL,
	};

	int option;
	extern char *optarg; extern int optind;
	int ret = APP_OK;

	while ((option = getopt(argc, argv, "CGRLAf:i:k:gh:l:o:m:n:s:w:")) != -1) {
		ret = process_main_option(PARSE, option, optarg, &getOptVal);
		if (ret != APP_OK)
			break;
	}

	if (getOptVal.numOfMainOpt > 1) {
		printf("More than one option is given, Please check below for help.\n");
		print_usage();
		exit(EXIT_FAILURE);
	}

	/* Error Message will be printed during
	 * during parsing itself.
	 */
	if (ret != APP_OK)
		return ret;

	ret = process_main_option(PERFORM, getOptVal.main_option, optarg, &getOptVal);
	if (ret != APP_OK && ret != APP_IP_ERR) {
		if (ret == APP_SKR_ERR)
			printf("Command Failed due to SK Lib Error\n");
		else
			printf("Command Failed due to App: sobj_app error.\n");
	}
	return 0;
}

