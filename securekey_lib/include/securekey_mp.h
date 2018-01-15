/*
 * Copyright 2017 NXP
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef __HEADER_SECUREKEY_MP_H__
#define __HEADER_SECUREKEY_MP_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "securekey_api_types.h"

/*
 * Defines error codes returned to application.
*/
enum sk_status_code {
	SK_SUCCESS = 0,	/*!<  = 0  */
	SK_FAILURE = -1,	/*!<  = -1 */
};

/*
 * Initialize the Securekey library.
 * This function must be called before using any other library function.
 */
enum sk_status_code sk_lib_init(void);

/*
 * Clean up the Securekey library resources.
 * This function must be called when application done using library function.
 */
void sk_lib_exit(void);

/*
 * Translates the error codes.
 * This wil return error string corresponding to the error code.
 */
const char *sk_translate_error_code(enum sk_status_code error);

/* ================= MP Structure and APIS START=============*/
/*
  * ECC Public Key
  * sk_EC_point consists of 2 coordinates x & y.
  * Both these coordinates have equal length.
  * len represents length of one of the parts.
  */
struct sk_EC_point {
	uint8_t *x;
	uint8_t *y;
	uint8_t len;
};

/*
  * ECC Signature
  * sk_EC_sig consists of 2 parts r & s.
  * Both these parts  have equal length.
  * len represents length of one of the parts.
  */
struct sk_EC_sig {
	uint8_t *r;
	uint8_t *s;
	uint8_t len;	/* r & s is of equal length */
};

/*
  * This function returns the length of one coordinate of MP Public key.
  * Both the coordinates have equal length
  */
uint8_t sk_mp_get_pub_key_len(void);

/*
  * This function will return the Digest len generated during MP Sign operation.
  * For MP Sign SHA256 is used.
  */
uint8_t sk_mp_get_digest_len(void);

/*
  * This function returns the length of one part of MP Signature.
  * Both the parts have equal length
  */
uint8_t sk_mp_get_sig_len(void);

/*
  * This function will return the MP Message len.
  */
uint8_t sk_mp_get_tag_len(void);

/*! @fn enum sk_status_code sk_mp_get_pub_key(struct sk_EC_point *pub_key)
 *  @brief Get Manufacturing Protection(MP) Public Key(ECC P256 Key).
 *  @param[in,out] pub_key This is MP Public Key to be returned.
 *	Application need to allocate memory for sk_EC_point.
 *	Each of the coordinate x & y need to be allocate sk_EC_point.len memory.
 *	sk_EC_point.len can be obtained using sk_mp_get_pub_key_len().
 *   *  @return #SK_SUCCESS on success, error value otherwise.
 */
enum sk_status_code sk_mp_get_pub_key(struct sk_EC_point *pub_key);

/*! @fn enum sk_status_code sk_mp_sign(unsigned char * msg, uint8_t msglen,
		struct sk_EC_sig * sig, uint8_t * digest, uint8_t digest_len)
 *  @brief Sign the msg using MP Priv Key
 *	While signing MP Message will be prepended to message.
 *	Msg over which signature will be calculated = MP message + msg.
 *  @param[in] msg Pointer to the message to be signed.
 *  @param[in] msglen Length of the message to be signed.
 *  @param[in,out] sig This is Signature calculated.
 *	Application need to allocate memory for sk_EC_sig.
 *	Each of the parts r & s need to be allocate sk_EC_sig.len memory.
 *	sk_EC_sig.len can be obtained using sk_mp_get_sig_len().
 *  @param[out] digest Digest(SHA256) of the message to be signed.
 *	Digest is calculated by prepending MP Message to the msg.
 *  @param[out] digest_len Length of digest.
 *	Application need to allocate memory for sk_EC_point.
 *	Each of the coordinate x & y need to be allocate sk_EC_point.len memory.
 *	sk_EC_point.len can be obtained using sk_mp_get_pub_key_len().
 *  @return #SK_SUCCESS on success, error value otherwise.
 */
enum sk_status_code sk_mp_sign(unsigned char * msg, uint8_t msglen,
		struct sk_EC_sig * sig, uint8_t * digest, uint8_t digest_len);

/*! @fn enum sk_status_code sk_mp_get_mp_tag(uint8_t *mp_tag_ptr,
		uint8_t mp_tag_len)
 *  @brief Get the MP Message
 *	While signing MP Message is prepended to message automatically
 *	User can call this function to get MP mesage tag during verification operation
 *  @param[in] mp_tag_ptr Pointer to the message to be signed.
 *	Application need to allocate memory of length returned by sk_mp_get_tag_len().
 *  @param[in] mp_tag_len Length of the mp_tag_ptr buffer
 *  @return #SK_SUCCESS on success, error value otherwise.
 */
enum sk_status_code sk_mp_get_mp_tag(uint8_t *mp_tag_ptr,
		uint8_t mp_tag_len);

/* ================= MP Structure and APIS END=============*/

/*
  * This function will return the FUID len.
  */
uint8_t sk_get_fuid_len(void);

/*! @fn enum sk_status_code sk_get_fuid(uint8_t *fuid)
 *  @brief Get the FUID(Factory Unique ID)
 *  @param[in,out] fuid Pointer to buffer to be filled with FUID.
 *	Application need to allocate buffer of 16bytes and pass pointer
 *	of that memory in fuid..
 *  @return #SK_SUCCESS on success, error value otherwise.
 */
enum sk_status_code sk_get_fuid(uint8_t *fuid);

/*! @fn enum sk_status_code sk_get_oemid(uint8_t *oem_id,
		uint8_t* oem_id_len)
 *  @brief Get the OEMUID(Original Equipment Manufacturer ID)
 *  @param[in,out] oem_id Pointer to buffer to be filled with OEMID.
 *	Application need to allocate buffer of 64 bytes and pass pointer
 *	of that memory in oem_id.
 *  @param[out] oem_id_len This will be filled with length of OEMID filled in
 *	provided buffer.
 *  @return #SK_SUCCESS  and oem_id_len > 0 on success
 *	error value and oem_id_len = 0 otherwise.
 */
enum sk_status_code sk_get_oemid(uint8_t *oem_id,
		uint8_t *oem_id_len);

#endif /* __HEADER_SECUREKEY_MP_H__ */
