/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:    GPL-2.0+
*/

#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/completion.h>

#include <caam/jr.h>
#include <caam/error.h>

#include "securekey_desc.h"
#include "securekey_driver_pvt.h"
#include "securekey_caam.h"

struct completion comp;
int job_comp_status;

static inline void print_desc(uint32_t *buff, int size)
{
	int i;

	if (size < 0) {
		pr_err("Invalid descriptor size (%d)\n", size);
		return;
	}

	for (i = 0; i < size; i++)
		pr_err("%08x\n", buff[i]);
}

/*
 *  Callback function to be called when descriptor executed.
 */
static void caam_op_done(struct device *dev, u32 *desc, u32 ret,
		void *context)
{
	if (ret) {
		dev_err(dev, "caam op done err: %x\n", ret);
		/* print the error source name. */
		caam_jr_strstatus(dev, ret);
	}

	job_comp_status = ret;
	complete(&comp);
	return;
}


/*
 *  Enqueue a Job descriptor to Job ring and wait until SEC returns.
 */
static int submit_job(struct device *jrdev, uint32_t *desc)
{
	int ret;

	init_completion(&comp);

	/* Call caam_jr_enqueue function for Enqueue a job descriptor head. */
	ret = caam_jr_enqueue(jrdev, desc, caam_op_done, NULL);
	if (!ret)
		wait_for_completion_interruptible(&comp);
	else
		return ret;

	ret = job_comp_status;
	return ret;
}

/* Function caam_submit_mp_get_pub_key_op generates the
 * MP Public corresponding to the MPPrivK already stored in the CAAM
 */
static int32_t caam_submit_mp_get_pub_key_op(struct device *dev,
		struct caam_mp_pub_key_req *req)
{
	int32_t ret = -1;
	uint32_t *desc;
	struct caam_mp_pub_key_req *mp_req = req;

	/*Prepare a SEC descriptor for RSA private key decryption*/
	desc = kmalloc(CAAM_DESC_BYTES_MAX, GFP_DMA);
	if (desc == NULL) {
		pr_err("\n desc kmalloc failed\n");
		goto desc_kmalloc_fail;
	}

	memset(desc, 0, CAAM_DESC_BYTES_MAX);
	ret = build_mp_get_pubkey_desc(desc, mp_req->pub_key);
	if (!ret) {
		pr_err("error: %s: build_mp_get_pubkey_desc\n",
			__func__);
		ret = -1;
		goto cleanall;
	}

#if 0
	pr_err("public key desc\n");
	print_desc(desc, 64);
#endif

	ret = submit_job(dev, desc);
	if (ret)
		pr_err("error: %s: submit_job\n", __func__);

cleanall:
	kfree(desc);
desc_kmalloc_fail:
	return ret;
}

/* Function caam_submit_mp_gen_pub_key_op generates the
 * MP Public corresponding to the MPPrivK already stored in the CAAM
 */
static int32_t caam_submit_mp_sign_op(struct device *dev,
		struct caam_mp_sign_req *req)
{
	int32_t ret = -1;
	uint32_t *desc;
	struct caam_mp_sign_req *mp_req = req;

	/*Prepare a SEC descriptor for RSA private key decryption*/
	desc = kmalloc(CAAM_DESC_BYTES_MAX, GFP_DMA);
	if (desc == NULL) {
		pr_err("\n desc kmalloc failed\n");
		goto desc_kmalloc_fail;
	}

	memset(desc, 0, CAAM_DESC_BYTES_MAX);
	ret = build_mp_sign_desc(desc, mp_req->msg, mp_req->msg_len,
		mp_req->hash, mp_req->r, mp_req->s);
	if (!ret) {
		pr_err("error: %s: build_mp_sign_desc\n", __func__);
		goto cleanall;
	}

#if 0
	pr_err("signing desc\n");
	print_desc(desc, 64);
#endif

	ret = submit_job(dev, desc);
	if (ret)
		pr_err("error: %s: submit_job\n", __func__);

cleanall:
	kfree(desc);
desc_kmalloc_fail:
	return ret;
}

int caam_job_submit(struct device *jrdev, void *ptr)
{
	struct caam_req *req = (struct caam_req *)ptr;
	int ret = 0;

	switch (req->type) {
		case mp_get_pub_key:
		{
			ret = caam_submit_mp_get_pub_key_op(jrdev,
				&req->req_u.mp_pub_key_req);
			if (ret)
				pr_err("caam_submit_mp_get_pub_key_op failed\n");
		}
		break;
		case mp_sign:
		{
			ret = caam_submit_mp_sign_op(jrdev,
				&req->req_u.mp_sign_req);
			if (ret)
				pr_err("caam_submit_mp_sign_op failed\n");
		}
		break;
		default:
			pr_err("Unknown request type\n");
	}

	return ret;
}
