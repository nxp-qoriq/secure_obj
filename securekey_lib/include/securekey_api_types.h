/*
 * securekey_api_types.h
 */
#ifndef _SECUREKEY_API_TYPES_H_
#define _SECUREKEY_API_TYPES_H_

#include <stdint.h>
/*
 * Return Codes.
 */

typedef uint16_t SK_RET_CODE;

/* Error/status word */
#define SKR_OK				(0x9000) /* Operation successful */

#define SKR_ERR_NOT_SUPPORTED		(0x7080) /* The function and/or parameters are not supported by the library */

#define SKR_ERR_GENERAL_ERROR		(0x7021) /* Non-specific error code */
#define SKR_ERR_SHORT_BUFFER		(0x7026) /* Buffer provided is too small */
#define SKR_ERR_CRYPTO_ENGINE_FAILED	(0x7027) /* The crypto engine (implemented underneath a crypto abstraction layer) failed to provide a crypto service. */
#define SKR_ERR_IDENT_IDX_RANGE		(0x7032) /* Identifier or Index of Reference Key is out of bounds */

#define SKR_ERR_INIT_FAILED		(0x6001) /* If anything related to underlying component initialization failed */
#define SKR_ERR_TEE_API			(0x6002) /* The return code is an error that originated within the TEE Client API implementation */
#define SKR_ERR_TEE_COMM		(0x6003) /* Some error occured in communication stack b/w Rich OS and TEE */
#define SKR_ERR_TEE_OS			(0x6004) /* The return code is an error that originated within the common TEE code. */

#define SKR_ERR_ACCESS_DENIED		(0x6005) /* Access privileges are not sufficient */ 
#define SKR_ERR_CANCEL			(0x6006) /* The operation was cancelled */
#define SKR_ERR_ACCESS_CONFLICT		(0x6007) /* Concurrent accesses caused conflict*/
#define SKR_ERR_EXCESS_DATA		(0x6008) /* Too much data for the requested operation was passed.*/
#define SKR_ERR_BAD_FORMAT		(0x6009) /* Input data was of invalid format.*/
#define SKR_ERR_BAD_PARAMETERS		(0x6010) /* Input parameters were invalid.*/
#define SKR_ERR_BAD_STATE		(0x6011) /* Operation is not valid in the current state.*/
#define SKR_ERR_ITEM_NOT_FOUND		(0x6012) /* The requested data item is not found.*/
#define SKR_ERR_NOT_IMPLEMENTED	(0x6013) /* The requested operation should exist but is not yet implemented.*/
#define SKR_ERR_NO_DATA			(0x6015) /* Expected data was missing.*/
#define SKR_ERR_OUT_OF_MEMORY		(0x6016) /* System ran out of resources. */
#define SKR_ERR_BUSY			(0x6017) /* The system is busy working on something else.*/
#define SKR_ERR_COMMUNICATION 		(0x6018) /* Communication with a remote party failed.*/
#define SKR_ERR_SECURITY		(0x6019) /* A security fault was detected.*/

/*
 * A type for all the defines.
 */
typedef uint32_t SK_TYPE;

/*
 * An Object Type definition.
 */
typedef SK_TYPE SK_OBJECT_TYPE;

/*
 * Enumerates the various logical objects existing on the Secure Element.
 */
#define SK_ANY_TYPE		0x00000000 /* For the Enumeration of all the objects */
#define SK_KEY_PAIR		0x00010000 /* Asymmetric Key Pairs */
#define SK_PUBLIC_KEY		0x00020000 /* Asymmetric Public Key in Uncompressed format */


typedef SK_TYPE SK_KEY_TYPE;

#define SKK_RSA			0x00000000U
#define SKK_EC			0x00000001U

/*
 * An Object Handle.
 */
typedef SK_TYPE SK_OBJECT_HANDLE;

/*
 * An Attribute Type.
 */
typedef SK_TYPE SK_ATTRIBUTE_TYPE;

#define SK_ATTR_OBJECT_TYPE		0 /* The object type (Mandatory in Create) */
#define SK_ATTR_OBJECT_INDEX		1 /* The object index (Mandatory in Create) */
#define SK_ATTR_LABEL			2 /* The object label (Mandatory in Create) */
#define SK_ATTR_KEY_TYPE		5 /* Key Type RSA/EC (Mandatory with key type objects) */

/* Attributes For RSA Key Pair */
#define SK_ATTR_MODULUS_BITS		30 /* Length in bits of modulus n */
#define SK_ATTR_MODULUS			31 /* Big integer Modulus n */
#define SK_ATTR_PUBLIC_EXPONENT		32 /* Big integer Public exponent e */

#define SK_ATTR_PRIVATE_EXPONENT	33 /* Big integer Private exponent e */
#define SK_ATTR_PRIME_1			34 /* Big Integer Prime p */
#define SK_ATTR_PRIME_2			35 /* Big Integer Prime q */
#define SK_ATTR_EXPONENT_1		36 /* Big integer Private exponent d modulo p-1 */
#define SK_ATTR_EXPONENT_2		37 /* Big integer Private exponent d modulo q-1 */
#define SK_ATTR_COEFFICIENT		38 /* Big integer CRT coefficient q-1 mod p */

/*
 * Stores all the information required for an object's attribute - its type, value and value length.
 */
typedef struct SK_ATTRIBUTE{
	SK_ATTRIBUTE_TYPE	type;		/* The attribute's type */
	void			*value;		/* The attribute's value */
	uint16_t		valueLen;	/* The length in bytes of \p value. */
} SK_ATTRIBUTE;

/*******************************************************************
 * Cryptographic Operations TBD
 *******************************************************************/

typedef SK_TYPE SK_MECHANISM_TYPE;

/*
 * Mechanism Type enum.
 * Enumerates the various Cryptographic Mechanisms that may be supported by the library.
 */

/*******************************************************************
 * For now we need only one Mechanism
 *******************************************************************/
#define		SKM_RSA_PKCS		20

/*
 * Specifying the required information in order to use a mechanism,
 */
typedef struct SK_MECHANISM_INFO {
	/* The Mechanism type (see MechanismType). */
	SK_MECHANISM_TYPE	mechanism;
	/* An additional optional parameter required in using this mechanism. */
	void			*pParameter;
	/* The length in bytes of parameter */
	uint16_t		ulParameterLen;
} SK_MECHANISM_INFO;

#endif /* _SECUREKEY_API_TYPES_H_ */
