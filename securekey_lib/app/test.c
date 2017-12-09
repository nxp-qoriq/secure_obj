#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <securekey_api.h>
#include "rsa_data.h"

#define MAX_RSA_ATTRIBUTES	13
#define MAX_FIND_OBJ_SIZE	50

static void populate_attrs(SK_ATTRIBUTE *attrs)
{
	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &obj;
	attrs[0].valueLen = sizeof(obj);
	attrs[1].type = SK_ATTR_OBJECT_INDEX;
	attrs[1].value = &obj_id;
	attrs[1].valueLen = sizeof(obj_id);
	attrs[2].type = SK_ATTR_KEY_TYPE;
	attrs[2].value = &key;
	attrs[2].valueLen = sizeof(key);
	attrs[3].type = SK_ATTR_LABEL;
	attrs[3].value = label;
	attrs[3].valueLen = sizeof(label);
	attrs[4].type = SK_ATTR_MODULUS_BITS;
	attrs[4].value = &key_len;
	attrs[4].valueLen = sizeof(key_len);
	attrs[5].type = SK_ATTR_MODULUS;
	attrs[5].value = (void *)rsa_modulus;
	attrs[5].valueLen = sizeof(rsa_modulus);
	attrs[6].type = SK_ATTR_PUBLIC_EXPONENT;
	attrs[6].value = (void *)rsa_pub_exp;
	attrs[6].valueLen = sizeof(rsa_pub_exp);
	attrs[7].type = SK_ATTR_PRIVATE_EXPONENT;
	attrs[7].value = (void *)rsa_priv_exp;
	attrs[7].valueLen = sizeof(rsa_priv_exp);
	attrs[8].type = SK_ATTR_PRIME_1;
	attrs[8].value = (void *)rsa_prime1;
	attrs[8].valueLen = sizeof(rsa_prime1);
	attrs[9].type = SK_ATTR_PRIME_2;
	attrs[9].value = (void *)rsa_prime2;
	attrs[9].valueLen = sizeof(rsa_prime2);
	attrs[10].type = SK_ATTR_EXPONENT_1;
	attrs[10].value = (void *)rsa_exp1;
	attrs[10].valueLen = sizeof(rsa_exp1);
	attrs[11].type = SK_ATTR_EXPONENT_2;
	attrs[11].value = (void *)rsa_exp2;
	attrs[11].valueLen = sizeof(rsa_exp2);
	attrs[12].type = SK_ATTR_COEFFICIENT;
	attrs[12].value = (void *)rsa_coeff;
	attrs[12].valueLen = sizeof(rsa_coeff);
}

static SK_OBJECT_HANDLE do_CreateObject(void)
{
	int ret;
	SK_ATTRIBUTE *attrs;
	SK_OBJECT_HANDLE hObject;

	attrs = (SK_ATTRIBUTE *)malloc(sizeof(SK_ATTRIBUTE) * MAX_RSA_ATTRIBUTES);
	if (attrs == NULL) {
		printf("malloc failed\n");
		return SKR_ERR_OBJECT_HANDLE_INVALID;
	}

	populate_attrs(attrs);

	ret = SK_CreateObject(attrs, MAX_RSA_ATTRIBUTES, &hObject);
	if (ret != SKR_OK)
		printf("SK_CreateObject failed wit err code = 0x%x\n", ret);
	else
		printf("SK_CreateObject successful handle = 0x%x\n", hObject);

	free(attrs);
	return hObject;
}

static void do_EraseObject(SK_OBJECT_HANDLE hObject)
{
	int ret, i = 0;

	ret = SK_EraseObject(hObject);

	if (ret != SKR_OK)
		printf("SK_EraseObject failed with code = 0x%x\n", ret);
	else
		printf("SK_EraseObject successful\n");
}
static void do_EnumerateObject(void)
{
	int ret, i = 0;
	SK_ATTRIBUTE attrs[2];
	SK_OBJECT_HANDLE hObject[MAX_FIND_OBJ_SIZE];
	uint32_t objCount;

	/* Getting only RSA Keypair objects */
	printf("Getting only RSA Keypair objects\n");
	SK_OBJECT_TYPE key = SK_KEY_PAIR;
	attrs[0].type = SK_ATTR_OBJECT_TYPE;
	attrs[0].value = &key;
	attrs[0].valueLen = sizeof(SK_OBJECT_TYPE);

	SK_KEY_TYPE key_type = SKK_RSA;
	attrs[1].type = SK_ATTR_KEY_TYPE;
	attrs[1].value = &key_type;
	attrs[1].valueLen = sizeof(SK_KEY_TYPE);

	ret = SK_EnumerateObjects(NULL, 0, hObject, MAX_FIND_OBJ_SIZE,
		&objCount);
	if (ret != SKR_OK)
		printf("SK_EnumerateObjects failed with code = 0x%x\n", ret);
	else {
		printf("SK_EnumerateObjects successful\n");
		for (i = 0; i < objCount; i++)
			printf("hObject[%d] = 0x%x\n", i, hObject[i]);
	}
}

static void do_GetObjectAttributes(SK_OBJECT_HANDLE hObject)
{
	int ret, i = 0, n = 0;
	SK_ATTRIBUTE attrs[2];
	uint32_t attrCount = 2;
	SK_OBJECT_TYPE obj_type;
	SK_KEY_TYPE key_type;

	/* Getting only RSA Keypair objects */
	memset(attrs, 0, sizeof(SK_ATTRIBUTE) * 2);

	attrs[0].type = SK_ATTR_LABEL;
	attrs[1].type = SK_ATTR_OBJECT_INDEX;

	ret = SK_GetObjectAttribute(hObject, attrs, attrCount);
	if (ret != SKR_OK)
		printf("SK_GetObjectAttribute failed with code = 0x%x\n", ret);
	else {
		printf("SK_GetObjectAttribute successful\n");
		printf("attrCount = %d\n", attrCount);
		for (n = 0; n < attrCount; n++) {
			printf("Attr[%d].type: 0x%x\n", n, attrs[n].type);
			printf("Attr[%d].valueLen: 0x%x\n", n, attrs[n].valueLen);
#if 0
			printf("Attr[%d].value: 0x", n);
			for (i = 0; i < attrs[n].valueLen; i++)
				printf("%x", *(((uint8_t *)attrs[n].value) + i));
			printf("\n");
#endif
		}
	}
}


int main(int argc, char *argv[])
{
	SK_OBJECT_HANDLE obj1;

	obj1 = do_CreateObject();
	if (obj1 == SKR_ERR_OBJECT_HANDLE_INVALID)
		return -1;

	do_GetObjectAttributes(obj1);
	do_EnumerateObject();
	do_EraseObject(obj1);
	do_EnumerateObject();
	return 0;
}
