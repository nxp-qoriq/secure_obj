#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <ta_secure_storage.h>
#include <securekey_api_types.h>
#include <securekey_api.h>

struct tee_attr_packed {
	uint32_t attr_id;
	uint32_t a;
	uint32_t b;
};

/* Round up the even multiple of size, size has to be a multiple of 2 */
#define ROUNDUP(v, size) (((v) + (size - 1)) & ~(size - 1))

SK_RET_CODE SK_CreateObject(SK_ATTRIBUTE *attr,
		uint16_t attrCount, SK_OBJECT_HANDLE *phObject);

SK_RET_CODE SK_EnumerateObjects(SK_ATTRIBUTE *pTemplate,
		uint32_t attrCount, SK_OBJECT_HANDLE *phObject,
		uint32_t maxObjects, uint32_t *pulObjectCount);

static uint32_t pack_attrs(uint8_t *buffer, size_t size,
		SK_ATTRIBUTE *attrs, uint32_t attr_cnt)
{
	uint8_t *b = buffer;
	struct tee_attr_packed *a;
	uint32_t i;

	if (b == NULL || size == 0)
		return SKR_ERR_BAD_PARAMETERS;

	*(uint32_t *)(void *)b = attr_cnt;
	b += sizeof(uint32_t);
	a = (struct tee_attr_packed *)(void *)b;
	b += sizeof(struct tee_attr_packed) * attr_cnt;

	for (i = 0; i < attr_cnt; i++) {
		a[i].attr_id = attrs[i].type;

		a[i].b = attrs[i].valueLen;

		if (attrs[i].valueLen == 0) {
			a[i].a = 0;
			continue;
		}

		memcpy(b, attrs[i].value, attrs[i].valueLen);

		/* Make buffer pointer relative to *buf */
		a[i].a = (uint32_t)(uintptr_t)(b - buffer);

		/* Round up to good alignment */
		b += ROUNDUP(attrs[i].valueLen, 4);
	}

	return SKR_OK;
}

static SK_RET_CODE map_teec_err_to_sk(TEEC_Result tee_ret,
	uint32_t err_origin)
{
	switch(err_origin) {
		case TEEC_ORIGIN_API:
			return SKR_ERR_TEE_API;
			break;
		case TEEC_ORIGIN_COMMS:
			return SKR_ERR_TEE_COMM;
			break;
		case TEEC_ORIGIN_TEE:
		case TEEC_ORIGIN_TRUSTED_APP:
		default:
		{
			switch (tee_ret) {
				case TEEC_ERROR_GENERIC:
					return SKR_ERR_GENERAL_ERROR;
					break;
				case TEEC_ERROR_ACCESS_DENIED:
					return SKR_ERR_ACCESS_DENIED;
					break;
				case TEEC_ERROR_CANCEL:
					return SKR_ERR_CANCEL;
					break;
				case TEEC_ERROR_ACCESS_CONFLICT:
					return SKR_ERR_ACCESS_CONFLICT;
					break;
				case TEEC_ERROR_EXCESS_DATA:
					return SKR_ERR_EXCESS_DATA;
					break;
				case TEEC_ERROR_BAD_FORMAT:
					return SKR_ERR_BAD_FORMAT;
					break;
				case TEEC_ERROR_BAD_PARAMETERS:
					return SKR_ERR_BAD_PARAMETERS;
					break;
				case TEEC_ERROR_BAD_STATE:
					return SKR_ERR_BAD_STATE;
					break;
				case TEEC_ERROR_ITEM_NOT_FOUND:
					return SKR_ERR_ITEM_NOT_FOUND;
					break;
				case TEEC_ERROR_NOT_IMPLEMENTED:
					return SKR_ERR_NOT_IMPLEMENTED;
					break;
				case TEEC_ERROR_NOT_SUPPORTED:
					return SKR_ERR_NOT_SUPPORTED;
					break;
				case TEEC_ERROR_NO_DATA:
					return SKR_ERR_NO_DATA;
					break;
				case TEEC_ERROR_OUT_OF_MEMORY:
					return SKR_ERR_OUT_OF_MEMORY;
					break;
				case TEEC_ERROR_BUSY:
					return SKR_ERR_BUSY;
					break;
				case TEEC_ERROR_COMMUNICATION:
					return SKR_ERR_COMMUNICATION;
					break;
				case TEEC_ERROR_SECURITY:
					return SKR_ERR_SECURITY;
					break;
				case TEEC_ERROR_SHORT_BUFFER:
					return SKR_ERR_SHORT_BUFFER;
					break;
				case TEEC_ERROR_TARGET_DEAD:
					return SKR_ERR_BAD_PARAMETERS;
					break;
				default:
					return SKR_ERR_GENERAL_ERROR;
			}
		}
	}
}

static size_t get_attr_size(SK_ATTRIBUTE *attrs, uint32_t attr_cnt)
{
	size_t size = sizeof(uint32_t);
	uint32_t i;

	if (attr_cnt == 0 || attrs == NULL)
		return size;

	size = sizeof(uint32_t) + sizeof(struct tee_attr_packed) * attr_cnt;
	for (i = 0; i < attr_cnt; i++) {
		if (attrs[i].valueLen == 0)
			continue;

		/* Make room for padding */
		size += ROUNDUP(attrs[i].valueLen, 4);
	}

	return size;
}

SK_FUNCTION_LIST global_function_list = {
	.SK_EnumerateObjects	=	SK_EnumerateObjects,
#if 0
	.SK_GetObjectAttribute	=	SK_GetObjectAttribute,
	.SK_GetSupportedMechanisms =	SK_GetSupportedMechanisms,
	.SK_Sign			=	SK_Sign,
#endif
};

SK_RET_CODE SK_CreateObject(SK_ATTRIBUTE *attr,
		uint16_t attrCount, SK_OBJECT_HANDLE *phObject)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if (attr == NULL || attrCount <= 0 || phObject == NULL)
		ret = SKR_ERR_BAD_PARAMETERS;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm.size = get_attr_size(attr, attrCount);
	shm.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	res = pack_attrs(shm.buffer, shm.size, attr, attrCount);
	if (res != SKR_OK) {
		printf("pack_attrs failed with code 0x%x\n", res);
		ret = res;
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_VALUE_OUTPUT,
			TEEC_NONE, TEEC_NONE);
	op.params[0].memref.parent = &shm;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = shm.size;

	printf("Invoking TEE_CREATE_OBJECT\n");
	res = TEEC_InvokeCommand(&sess, TEE_CREATE_OBJECT, &op,
			&err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail3;
	}
	*phObject = op.params[1].value.a;

	printf("TEE_CREATE_OBJECT successful\n");

fail3:
	TEEC_ReleaseSharedMemory(&shm);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

SK_RET_CODE SK_EraseObject(SK_OBJECT_HANDLE hObject)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].value.a = hObject;

	printf("Invoking TEE_ERASE_OBJECT\n");
	res = TEEC_InvokeCommand(&sess, TEE_ERASE_OBJECT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail2;
	}
	printf("TEE_ERASE_OBJECT successful\n");

fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

SK_RET_CODE SK_EnumerateObjects(SK_ATTRIBUTE *pTemplate,
		uint32_t attrCount, SK_OBJECT_HANDLE *phObject,
		uint32_t maxObjects, uint32_t *pulObjectCount)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_SECURE_STORAGE_UUID;
	TEEC_SharedMemory shm_in, shm_out;
	uint32_t err_origin;
	SK_RET_CODE ret = SKR_OK;

	if (pTemplate == NULL ||
		phObject == NULL || pulObjectCount == NULL)
		ret = SKR_ERR_BAD_PARAMETERS;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail1;
	}

	shm_in.size = get_attr_size(pTemplate, attrCount);
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail2;
	}

	res = pack_attrs(shm_in.buffer, shm_in.size, pTemplate, attrCount);
	if (res != SKR_OK) {
		printf("pack_attrs failed with code 0x%x\n", res);
		ret = res;
		goto fail3;
	}

	shm_out.size = sizeof(SK_OBJECT_HANDLE) * maxObjects;
	shm_out.flags = TEEC_MEM_OUTPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_out);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = map_teec_err_to_sk(res, 0);
		goto fail3;
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE,
					TEEC_VALUE_OUTPUT, TEEC_NONE);
	op.params[0].memref.parent = &shm_in;
	op.params[0].memref.offset = 0;
	op.params[0].memref.size = shm_in.size;
	op.params[1].memref.parent = &shm_out;
	op.params[1].memref.offset = 0;
	op.params[1].memref.size = shm_out.size;

	printf("Invoking TEE_FIND_OBJECTS\n");
	res = TEEC_InvokeCommand(&sess, TEE_FIND_OBJECTS, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InvokeCommand failed with code 0x%x", res);
		ret = map_teec_err_to_sk(res, err_origin);
		goto fail4;
	}

	*pulObjectCount = op.params[2].value.a;

	memcpy(phObject, shm_out.buffer,
		*pulObjectCount * sizeof(SK_OBJECT_HANDLE));
fail4:
	TEEC_ReleaseSharedMemory(&shm_out);
fail3:
	TEEC_ReleaseSharedMemory(&shm_in);
fail2:
	TEEC_CloseSession(&sess);
fail1:
	TEEC_FinalizeContext(&ctx);
end:
	return ret;
}

SK_RET_CODE SK_GetFunctionList(SK_FUNCTION_LIST_PTR_PTR  ppFuncList)
{
	if (ppFuncList == NULL)
		return SKR_ERR_BAD_PARAMETERS;

	*ppFuncList = &global_function_list;

	return SKR_OK;
}
