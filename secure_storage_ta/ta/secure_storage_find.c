#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"

static TEE_Result TA_FindAllObjects(SK_OBJECT_HANDLE *obj, uint32_t *obj_cnt,
				    uint32_t max_obj_cnt)
{
	TEE_Result res;
	TEE_ObjectEnumHandle ehandle = TEE_HANDLE_NULL;
	uint8_t obj_id[TEE_OBJECT_ID_MAX_LEN] = {0};
	uint32_t obj_id_len = TEE_OBJECT_ID_MAX_LEN;
	uint32_t cnt = 0;

	res = TEE_AllocatePersistentObjectEnumerator(&ehandle);
	if (res != TEE_SUCCESS)
		goto out;

	res = TEE_StartPersistentObjectEnumerator(ehandle,
						  TEE_STORAGE_PRIVATE);
	if (res != TEE_SUCCESS)
		goto out;

	while (1) {
		res = TEE_GetNextPersistentObject(ehandle, NULL, obj_id,
						  &obj_id_len);
		if (res != TEE_SUCCESS)
			break;

		DMSG("obj_id_len: %d!\n", obj_id_len);
		/* Skip database object type */
		if (obj_id_len > sizeof(uint32_t))
			continue;

		memcpy(&obj[cnt], obj_id, sizeof(uint32_t));

		cnt++;
		if (cnt >= max_obj_cnt)
			break;
	}

	if (res == TEE_ERROR_ITEM_NOT_FOUND)
		res = TEE_SUCCESS;
	else if (res != TEE_SUCCESS)
		goto out;

	*obj_cnt = cnt;

out:
	if (ehandle != TEE_HANDLE_NULL)
		TEE_FreePersistentObjectEnumerator(ehandle);

	return res;
}

TEE_Result TA_FindObjects(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	SK_ATTRIBUTE *attrs = NULL;
	uint32_t attr_count = 0;
	SK_OBJECT_HANDLE *obj = NULL;
	uint32_t obj_cnt = 0, max_obj_cnt = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	obj = (SK_OBJECT_HANDLE *)params[1].memref.buffer;
	max_obj_cnt = params[1].memref.size / sizeof(SK_OBJECT_HANDLE);

	DMSG("Unpack Object attributes!\n");
	res = unpack_sk_attrs(params[0].memref.buffer, params[0].memref.size,
			      &attrs, &attr_count);
	if (res != TEE_SUCCESS)
		goto out;

	if (attr_count == 0) {
		DMSG("Enumerate all TA persistent objects!\n");
		res = TA_FindAllObjects(obj, &obj_cnt, max_obj_cnt);
		if (res != TEE_SUCCESS)
			goto out;
	} else {
		/* TODO: Support for attribute match search */
		/* TA_FindAttrMatchObjects */
	}

	params[2].value.a = obj_cnt;

	DMSG("Called TA_FindObjects, obj_cnt: %d!\n", params[2].value.a);

out:
	if (attrs)
		TEE_Free(attrs);

	return res;
}
