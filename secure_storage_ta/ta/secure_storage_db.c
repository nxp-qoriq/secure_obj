/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:     BSD-3-Clause
*/

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "secure_storage_common.h"

const char db_obj_id[] = "obj_db";

TEE_Result TA_OpenDatabase(void)
{
	TEE_ObjectHandle hObject = TEE_HANDLE_NULL;
	uint32_t ret = TEE_SUCCESS;
	uint32_t obj_id_init = 0;

	/* Try to open object database object */
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)db_obj_id,
					sizeof(db_obj_id),
					TEE_DATA_FLAG_SHARE_READ |
					TEE_DATA_FLAG_ACCESS_READ,
					&hObject);

	if (ret == TEE_SUCCESS) {
		DMSG("DB object already exist!!\n");
		TEE_CloseObject(hObject);
		return ret;
	}

	/*
	 * Check if return value is object not found. If yes, then create
	 * new persistent object for database.
	 */
	if (ret != TEE_ERROR_ITEM_NOT_FOUND)
		return ret;

	DMSG("Create new DB object!!\n");
	ret = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, db_obj_id,
					sizeof(db_obj_id),
					TEE_DATA_FLAG_ACCESS_WRITE,
					NULL,
					&obj_id_init, sizeof(obj_id_init),
					&hObject);
	if (ret != TEE_SUCCESS) {
                DMSG("Failed to create db object!!\n");
                return ret;
        }

	TEE_CloseObject(hObject);
	return ret;
}

TEE_Result TA_GetNextObjectID(uint32_t *next_obj_id)
{
	TEE_ObjectHandle hObject = TEE_HANDLE_NULL;
	uint32_t ret = TEE_SUCCESS;
	uint32_t obj_id = 0;
	size_t read_bytes = 0;

	/* Try to open object database object */
	ret = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, (void *)db_obj_id,
				       sizeof(db_obj_id),
				       TEE_DATA_FLAG_ACCESS_WRITE |
				       TEE_DATA_FLAG_SHARE_WRITE |
				       TEE_DATA_FLAG_ACCESS_READ |
				       TEE_DATA_FLAG_SHARE_READ, &hObject);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Try to read object database */
	ret = TEE_ReadObjectData(hObject, &obj_id, sizeof(uint32_t),
				 &read_bytes);
	if ((ret != TEE_SUCCESS) && (read_bytes != sizeof(uint32_t)))
		goto out;

	*next_obj_id = obj_id;
	obj_id++;

	/* Try to seek object database */
	ret = TEE_SeekObjectData(hObject, 0, TEE_DATA_SEEK_SET);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Try to write object database */
	ret = TEE_WriteObjectData(hObject, &obj_id, sizeof(uint32_t));
	if (ret != TEE_SUCCESS)
		goto out;

out:
	if (hObject)
		TEE_CloseObject(hObject);

	return ret;
}

uint32_t get_obj_db_id_size(void)
{
	return sizeof(db_obj_id);
}
