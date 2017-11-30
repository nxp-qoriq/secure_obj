#include <stdio.h>
#include <securekey_api.h>
#include "rsa_data.h"

#define MAX_RSA_ATTRIBUTES	13

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

static void do_CreateObject(void)
{
	int ret;
	SK_ATTRIBUTE attrs[MAX_RSA_ATTRIBUTES] = {0};
	SK_OBJECT_HANDLE hObject;

	populate_attrs(attrs);

	ret = SK_CreateObject(attrs, MAX_RSA_ATTRIBUTES, &hObject);
	if (ret != SKR_OK)
		printf("SK_CreateObject failed\n");
	else
		printf("SK_CreateObject successful handle = 0x%x\n", hObject);
}

int main(int argc, char *argv[])
{
	do_CreateObject();
	return 0;
}
