#define STR_TRACE_USER_TA "SECURE_STORAGE"

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include "string.h"
#include "secure_storage_common.h"

/* Round up the even multiple of size, size has to be a multiple of 2 */
#define ROUNDUP(v, size) (((v) + (size - 1)) & ~(size - 1))

struct attr_packed {
	uint32_t id;
	uint32_t a;
	uint32_t b;
};

TEE_Result pack_sk_attrs(const SK_ATTRIBUTE *attrs, uint32_t attr_count,
			 uint8_t **buf, size_t *blen)
{
	struct attr_packed *a;
	uint8_t *b;
	size_t bl;
	size_t n;
	uint32_t attr_pack = 0;

	*buf = NULL;
	*blen = 0;
	if (attr_count == 0)
		return TEE_SUCCESS;

	bl = sizeof(uint32_t);
	for (n = 0; n < attr_count; n++) {
		switch (attrs[n].type) {
		case SK_ATTR_OBJECT_TYPE:
		case SK_ATTR_OBJECT_INDEX:
		case SK_ATTR_KEY_TYPE:
		case SK_ATTR_LABEL:
		case SK_ATTR_MODULUS_BITS:
			bl += sizeof(struct attr_packed);
			/* Make room for padding */
			bl += ROUNDUP(attrs[n].valueLen, 4);
			attr_pack++;
			break;
		default:
			break;
		}
	}

	b = TEE_Malloc(bl, 0);
	if (!b)
		return TEE_ERROR_OUT_OF_MEMORY;

	*buf = b;
	*blen = bl;

	*(uint32_t *)(void *)b = attr_pack;
	b += sizeof(uint32_t);
	a = (struct attr_packed *)(void *)b;
	b += sizeof(struct attr_packed) * attr_pack;

	for (n = 0; n < attr_count; n++) {
		switch (attrs[n].type) {
		case SK_ATTR_OBJECT_TYPE:
		case SK_ATTR_OBJECT_INDEX:
		case SK_ATTR_KEY_TYPE:
		case SK_ATTR_LABEL:
		case SK_ATTR_MODULUS_BITS:
			a[n].id = attrs[n].type;
			a[n].b = attrs[n].valueLen;

			if (attrs[n].valueLen == 0) {
				a[n].a = 0;
				continue;
			}

			memcpy(b, attrs[n].value, attrs[n].valueLen);

			/* Make buffer pointer relative to *buf */
			a[n].a = (uint32_t)(uintptr_t)(b - *buf);

			/* Round up to good alignment */
			b += ROUNDUP(attrs[n].valueLen, 4);
			DMSG("SK Attribute - value: %p, valueLen: %08x!\n",
				attrs[n].value, attrs[n].valueLen);
			break;
		default:
			break;
		}
	}

	return TEE_SUCCESS;
}

TEE_Result unpack_sk_attrs(const uint8_t *buf, size_t blen,
			   SK_ATTRIBUTE **attrs, uint32_t *attr_count)
{
	TEE_Result res = TEE_SUCCESS;
	SK_ATTRIBUTE *a = NULL;
	const struct attr_packed *ap;
	size_t num_attrs = 0;
	const size_t num_attrs_size = sizeof(uint32_t);

	if (blen == 0)
		goto out;

	if (((uintptr_t)buf & 0x3) != 0 || blen < num_attrs_size)
		return TEE_ERROR_BAD_PARAMETERS;
	num_attrs = *(uint32_t *) (void *)buf;
	if ((blen - num_attrs_size) < (num_attrs * sizeof(*ap)))
		return TEE_ERROR_BAD_PARAMETERS;
	ap = (const struct attr_packed *)(const void *)(buf + num_attrs_size);

	if (num_attrs > 0) {
		size_t n;

		a = TEE_Malloc(num_attrs * sizeof(SK_ATTRIBUTE), 0);
		if (!a)
			return TEE_ERROR_OUT_OF_MEMORY;
		for (n = 0; n < num_attrs; n++) {
			uintptr_t p;

			a[n].type = ap[n].id;
			a[n].valueLen = ap[n].b;
			p = (uintptr_t)ap[n].a;
			if (p) {
				if ((p + a[n].valueLen) > blen) {
					res = TEE_ERROR_BAD_PARAMETERS;
					goto out;
				}
				p += (uintptr_t)buf;
			}
			a[n].value = (void *)p;
			DMSG("SK Attribute - value: %p, valueLen: %08x!\n",
				a[n].value, a[n].valueLen);
		}
	}

	res = TEE_SUCCESS;
out:
	if (res == TEE_SUCCESS) {
		*attrs = a;
		*attr_count = num_attrs;
	} else {
		TEE_Free(a);
	}
	return res;
}

SK_ATTRIBUTE *TA_GetSKAttr(SK_ATTRIBUTE_TYPE type, SK_ATTRIBUTE *attrs,
			   uint32_t attr_count)
{
	size_t i;
	SK_ATTRIBUTE *match_attr = NULL;

	for (i = 0; i < attr_count; i++) {
		if (type == attrs[i].type) {
			match_attr = &attrs[i];
			break;
		}
	}

	if (match_attr)
		DMSG("Match Attribute - value: %p, valueLen: %08x!\n",
			match_attr->value, match_attr->valueLen);

	return match_attr;
}
