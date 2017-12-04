#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"

TEE_Result TA_EraseObject(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle pObject = TEE_HANDLE_NULL;
	uint32_t obj_id = 0;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types) {
		res = TEE_ERROR_BAD_PARAMETERS;
		goto out;
	}

	obj_id = params[0].value.a;

	/* Try to open object */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)&obj_id,
				       sizeof(uint32_t),
				       TEE_DATA_FLAG_ACCESS_WRITE_META,
				       &pObject);
	if (res != TEE_SUCCESS)
		goto out;

	/* Try to erase object */
	TEE_CloseAndDeletePersistentObject(pObject);

	DMSG("Called TA_EraseObject, obj_id: %d!\n", obj_id);

out:
	return res;
}

TEE_Result TA_GetObjectAttributes(uint32_t param_types, TEE_Param params[4])
{
	/* TODO */
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)params; /* Unused parameter */

	return TEE_SUCCESS;
}
