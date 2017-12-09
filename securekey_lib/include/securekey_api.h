/*
* securekey_api.h
*/

#ifndef _SECUREKEY_API_H_
#define _SECUREKEY_API_H_

#include "securekey_api_types.h"

/* SK stands for: Secure Key */

struct SK_FUNCTION_LIST {
	SK_RET_CODE(*SK_EnumerateObjects)(SK_ATTRIBUTE *pTemplate,
			uint32_t attrCount, SK_OBJECT_HANDLE *phObject,
			uint32_t maxObjects, uint32_t *pulObjectCount);
	SK_RET_CODE(*SK_GetObjectAttribute)(SK_OBJECT_HANDLE hObject,
			SK_ATTRIBUTE *attribute, uint32_t attrCount);
	SK_RET_CODE(*SK_GetSupportedMechanisms)(SK_MECHANISM_TYPE *mechanism,
			uint16_t *mechanismLen);
	SK_RET_CODE(*SK_Sign)(SK_MECHANISM_INFO *pMechanismType,
			SK_OBJECT_HANDLE hObject, uint8_t *inData,
			uint16_t inDataLen, uint8_t *outSignature,
			uint16_t *outSignatureLen);
};

typedef struct SK_FUNCTION_LIST SK_FUNCTION_LIST;

typedef SK_FUNCTION_LIST * SK_FUNCTION_LIST_PTR;

typedef SK_FUNCTION_LIST_PTR * SK_FUNCTION_LIST_PTR_PTR;

SK_RET_CODE SK_GetFunctionList(SK_FUNCTION_LIST_PTR_PTR  ppFuncList);

/*******************************************************************/
/* Object Operations*/
/*******************************************************************/
SK_RET_CODE	SK_EnumerateObjects(SK_ATTRIBUTE *pTemplate,
		uint32_t attrCount, SK_OBJECT_HANDLE *phObject,
		uint32_t maxObjects, uint32_t *pulObjectCount);

SK_RET_CODE	SK_CreateObject(SK_ATTRIBUTE *attr,
		uint16_t attrCount, SK_OBJECT_HANDLE *phObject);

SK_RET_CODE	SK_EraseObject(SK_OBJECT_HANDLE hObject);

SK_RET_CODE	SK_GetObjectAttribute(SK_OBJECT_HANDLE hObject,
		SK_ATTRIBUTE *attribute, uint32_t attrCount);

/*******************************************************************/
/* Cryptographic Operations*/
/*******************************************************************/
SK_RET_CODE	SK_GetSupportedMechanisms(SK_MECHANISM_TYPE *mechanism,
		uint16_t *mechanismLen);

SK_RET_CODE	SK_Sign(SK_MECHANISM_INFO *pMechanismType,
		SK_OBJECT_HANDLE hObject, uint8_t *inData, uint16_t inDataLen,
		uint8_t *outSignature, uint16_t *outSignatureLen);

#endif /* _SECUREKEY_API_H_*/
