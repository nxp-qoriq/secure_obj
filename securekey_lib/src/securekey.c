#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <ta_secure_storage.h>
#include <securekey_api_types.h>

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
		return SKR_ERR_API_ERROR;

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
		ret = SKR_ERR_API_ERROR;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = SKR_ERR_GENERAL_ERROR;
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x\n", res);
		ret = SKR_ERR_GENERAL_ERROR;
		goto fail1;
	}

	shm.size = get_attr_size(attr, attrCount);
	shm.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = SKR_ERR_MEMORY;
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
		ret = SKR_ERR_GENERAL_ERROR;
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
		ret = SKR_ERR_API_ERROR;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_InitializeContext failed with code 0x%x\n", res);
		ret = SKR_ERR_GENERAL_ERROR;
		goto end;
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_Opensession failed with code 0x%x\n", res);
		ret = SKR_ERR_GENERAL_ERROR;
		goto fail1;
	}

	shm_in.size = get_attr_size(pTemplate, attrCount);
	shm_in.flags = TEEC_MEM_INPUT;

	res = TEEC_AllocateSharedMemory(&ctx, &shm_in);
	if (res != TEEC_SUCCESS) {
		printf("TEEC_AllocateSharedMemory failed with code 0x%x\n", res);
		ret = SKR_ERR_MEMORY;
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
		ret = SKR_ERR_MEMORY;
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
		ret = SKR_ERR_GENERAL_ERROR;
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
