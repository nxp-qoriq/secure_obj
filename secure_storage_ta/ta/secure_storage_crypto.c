/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <utee_defines.h>

#include "string.h"
#include "secure_storage_common.h"

/*
 * Input params:
 * param#0 : SK Digest mechanism
 * param#1 : the input data buffer
 * param#2 : the output digest buffer
 * param#3 : not used
 */
TEE_Result TA_DigestData(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t algorithm, digest_size = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	switch (params[0].value.a) {
	case SKM_MD5:
		algorithm = TEE_ALG_MD5;
		digest_size = TEE_MD5_HASH_SIZE;
		break;
	case SKM_SHA1:
		algorithm = TEE_ALG_SHA1;
		digest_size = TEE_SHA1_HASH_SIZE;
		break;
	case SKM_SHA224:
		algorithm = TEE_ALG_SHA224;
		digest_size = TEE_SHA224_HASH_SIZE;
		break;
	case SKM_SHA256:
		algorithm = TEE_ALG_SHA256;
		digest_size = TEE_SHA256_HASH_SIZE;
		break;
	case SKM_SHA384:
		algorithm = TEE_ALG_SHA384;
		digest_size = TEE_SHA384_HASH_SIZE;
		break;
	case SKM_SHA512:
		algorithm = TEE_ALG_SHA512;
		digest_size = TEE_SHA512_HASH_SIZE;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	/* Check for output digest buffer */
	if (params[2].memref.buffer == NULL) {
		params[2].memref.size = digest_size;
		res = TEE_SUCCESS;
		goto out;
	} else if (params[2].memref.size < digest_size) {
		res = TEE_ERROR_SHORT_BUFFER;
		goto out;
	}

	DMSG("Allocate Operation!\n");
	res = TEE_AllocateOperation(&operation, algorithm, TEE_MODE_DIGEST, 0);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Generate digest for input data!\n");
	res = TEE_DigestDoFinal(operation, params[1].memref.buffer,
				params[1].memref.size, params[2].memref.buffer,
				&params[2].memref.size);

	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Digest Successful!\n");
out:
	if (operation)
		TEE_FreeOperation(operation);

	return res;
}

/*
 * Input params:
 * param#0 : object ID and SK sign mechanism
 * param#1 : the input digest buffer
 * param#2 : the output signature buffer
 * param#3 : not used
 */
TEE_Result TA_SignDigest(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL, tObject = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t algorithm, obj_id;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	obj_id = params[0].value.a;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &pObject);
	if (res != TEE_SUCCESS)
		goto out;

	/* Try to get object info */
	DMSG("Get Object Info!\n");
	res = TEE_GetObjectInfo1(pObject, &objectInfo);
	if (res != TEE_SUCCESS)
		goto out;

	if (params[2].memref.buffer == NULL) {
		params[2].memref.size = objectInfo.objectSize;
		goto out;
	}

	DMSG("Allocate Transient Object!\n");
	res = TEE_AllocateTransientObject(objectInfo.objectType,
					  objectInfo.objectSize, &tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Copy Object Attributes!\n");
	res = TEE_CopyObjectAttributes1(tObject, pObject);
	if (res != TEE_SUCCESS)
		goto out;

	switch (params[0].value.b) {
	case SKM_RSASSA_PKCS1_V1_5_MD5:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_MD5;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA1:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA1;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA224:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA224;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA256:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA256;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA384:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA384;
		break;
	case SKM_RSASSA_PKCS1_V1_5_SHA512:
		algorithm = TEE_ALG_RSASSA_PKCS1_V1_5_SHA512;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("Allocate Operation!\n");
	res = TEE_AllocateOperation(&operation, algorithm, TEE_MODE_SIGN,
				    objectInfo.objectSize);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Set Operation Key!\n");
	res = TEE_SetOperationKey(operation, tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Asymetric Sign Digest!\n");
	res = TEE_AsymmetricSignDigest(operation, NULL, 0,
				       params[1].memref.buffer,
				       params[1].memref.size,
				       params[2].memref.buffer,
				       &params[2].memref.size);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Sign Digest Successful!\n");
out:
	if (pObject != TEE_HANDLE_NULL)
		TEE_CloseObject(pObject);

	if (tObject != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(tObject);

	if (operation)
		TEE_FreeOperation(operation);

	return res;
}

/*
 * Input params:
 * param#0 : object ID and SK sign mechanism
 * param#1 : the input data buffer
 * param#2 : the output data buffer
 * param#3 : not used
 */
TEE_Result TA_DecryptData(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL, tObject = TEE_HANDLE_NULL;
	TEE_ObjectInfo objectInfo;
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	uint32_t algorithm, obj_id;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	obj_id = params[0].value.a;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ,
				       &pObject);
	if (res != TEE_SUCCESS)
		goto out;

	/* Try to get object info */
	DMSG("Get Object Info!\n");
	res = TEE_GetObjectInfo1(pObject, &objectInfo);
	if (res != TEE_SUCCESS)
		goto out;

	if (params[2].memref.buffer == NULL) {
		params[2].memref.size = objectInfo.objectSize;
		goto out;
	}

	DMSG("Allocate Transient Object!\n");
	res = TEE_AllocateTransientObject(objectInfo.objectType,
					  objectInfo.objectSize, &tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Copy Object Attributes!\n");
	res = TEE_CopyObjectAttributes1(tObject, pObject);
	if (res != TEE_SUCCESS)
		goto out;

	switch (params[0].value.b) {
	case SKM_RSAES_PKCS1_V1_5:
		algorithm = TEE_ALG_RSAES_PKCS1_V1_5;
		break;
	case SKM_RSA_PKCS_NOPAD:
		algorithm = TEE_ALG_RSA_NOPAD;
		break;
	default:
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	DMSG("Allocate Operation!\n");
	res = TEE_AllocateOperation(&operation, algorithm, TEE_MODE_DECRYPT,
				    objectInfo.objectSize);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Set Operation Key!\n");
	res = TEE_SetOperationKey(operation, tObject);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Asymetric Decrypt Data!\n");
	res = TEE_AsymmetricDecrypt(operation, NULL, 0,
				    params[1].memref.buffer,
				    params[1].memref.size,
				    params[2].memref.buffer,
				    &params[2].memref.size);
	if (res != TEE_SUCCESS)
		goto out;

	DMSG("Encrypt Data Successful!\n");
out:
	if (pObject != TEE_HANDLE_NULL)
		TEE_CloseObject(pObject);

	if (tObject != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(tObject);

	if (operation)
		TEE_FreeOperation(operation);

	return res;
}
