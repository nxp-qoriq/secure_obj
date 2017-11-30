#ifndef SECURE_STORAGE_COMMON_H
#define SECURE_STORAGE_COMMON_H

#include "securekey_api_types.h"

/* Database API's declaration */
TEE_Result TA_OpenCreateDatabase(void);
TEE_Result TA_GetNextObjectID(uint32_t *next_obj_id);

/* Create Object API */
TEE_Result TA_CreateObject(uint32_t param_types, TEE_Param params[4]);

/* Find Object API */
TEE_Result TA_FindObjects(uint32_t param_types, TEE_Param params[4]);

/* Helper API's declaration */
TEE_Result pack_sk_attrs(const SK_ATTRIBUTE *attrs, uint32_t attr_count,
			 uint8_t **buf, size_t *blen);
TEE_Result unpack_sk_attrs(const uint8_t *buf, size_t blen,
			   SK_ATTRIBUTE **attrs, uint32_t *attr_count);
SK_ATTRIBUTE *TA_GetSKAttr(SK_ATTRIBUTE_TYPE type, SK_ATTRIBUTE *attrs,
			   uint32_t attr_count);

/* RSA Specific API's declaration */
void fill_rsa_keypair_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			       TEE_Attribute *tee_attrs,
			       uint32_t *tee_attr_count);
void fill_rsa_pubkey_tee_attr(SK_ATTRIBUTE *attrs, uint32_t attr_count,
			      TEE_Attribute *tee_attrs,
			      uint32_t *tee_attr_count);
#endif /*SECURE_STORAGE_COMMON_H*/
