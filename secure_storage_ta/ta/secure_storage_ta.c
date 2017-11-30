#define STR_TRACE_USER_TA "SECURE_STORAGE"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "ta_secure_storage.h"
#include "secure_storage_common.h"

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param  params[4], void **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	uint32_t ret = TEE_SUCCESS;

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	ret = TA_OpenCreateDatabase();

	return ret;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	DMSG("Goodbye!\n");
}

static TEE_Result TA_GetObjectAttributes(uint32_t param_types,
					 TEE_Param params[4])
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

/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
	case TEE_CREATE_OBJECT:
		return TA_CreateObject(param_types, params);
	case TEE_FIND_OBJECTS:
		return TA_FindObjects(param_types, params);
	case TEE_GET_OBJ_ATTRIBUTES:
		return TA_GetObjectAttributes(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
