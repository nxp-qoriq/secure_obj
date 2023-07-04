/*
  * Copyright 2017 NXP
  * SPDX-License-Identifier:    GPL-2.0+
*/

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ioctl.h>

#include <linux/random.h>
#include <linux/syscalls.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/version.h>

#include <caam/jr.h>
#include <caam/error.h>

#include "securekey_driver.h"
#include "securekey_driver_pvt.h"
#include "securekey_caam.h"

MODULE_AUTHOR("NXP Semiconductor");
MODULE_DESCRIPTION("Securekey driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0");

/* ====== Module parameters ====== */
int securekeydev_verbosity;
module_param(securekeydev_verbosity, int, 0644);
MODULE_PARM_DESC(securekeydev_verbosity, "0: normal, 1: verbose, 2: debug");


/* static int sk_copy_data_to_user(struct sk_req *req, void *arg)
 *  Copy output data to user space buffers.
 *  req - Pointer to Securekey request structure.
 *  arg - Poniter to user space structure.
 *  return 0 on success, error value otherwise.
 */
static int sk_copy_data_to_user(struct sk_req *req, void *arg)
{
	struct sk_req *request = req;

	switch (request->type) {
		case sk_mp_get_pub_key:
			{
				struct sk_mp_pub_key_info *mp_req_u;
				struct sk_mp_pub_key_info_k *mp_req_k;

				mp_req_u = (struct sk_mp_pub_key_info *)arg;
				mp_req_k = &(request->req_u.mp_pub_key_req);

				if (copy_to_user(mp_req_u->x, mp_req_k->pub_key,
							mp_req_u->x_len) != 0) {
					print_error("mp_req_u->x copy to user failed\n");
					return -EFAULT;
				}

				if (copy_to_user(mp_req_u->y, mp_req_k->pub_key + mp_req_u->x_len,
							mp_req_u->y_len) != 0) {
					print_error("mp_req_u->y copy to user failed\n");
					return -EFAULT;
				}
			}
			break;
		case sk_mp_sign:
			{
				struct sk_mp_sign_req_info *mp_req_u;
				struct sk_mp_sign_req_info_k *mp_req_k;

				mp_req_u = (struct sk_mp_sign_req_info *)arg;
				mp_req_k = &(request->req_u.mp_sign_req);

				if (copy_to_user(mp_req_u->hash, mp_req_k->hash,
							mp_req_k->hash_len) != 0) {
					print_error("mp_req_u->hash copy to user failed\n");
					return -EFAULT;
				}
				if (copy_to_user(mp_req_u->r, mp_req_k->r,
							mp_req_k->r_len) != 0) {
					print_error("mp_req_u->r copy to user failed\n");
					return -EFAULT;
				}
				if (copy_to_user(mp_req_u->s, mp_req_k->s,
							mp_req_k->s_len) != 0) {
					print_error("mp_req_u->s copy to user failed\n");
					return -EFAULT;
				}
			}
			break;
		default:
			print_error("Some error has occurred\n");
			return -EINVAL;
	}
	return 0;
}

/*  static int sk_copy_data_from_user(struct sk_req *req, void *arg)
 *  Copy input buffer data from user space buffers to kernel space buffers..
 *  req - Pointer to SK req request structure
 *  arg - Poniter to user space structure
 *  return 0 on success, error value otherwise.
 */
static int sk_copy_data_from_user(struct sk_req *req, void *arg)
{
	struct sk_req *request = req;
	uint8_t *temp;

	switch (request->type) {
		case sk_mp_get_pub_key:
			{
				struct sk_mp_pub_key_info *mp_req_u;
				struct sk_mp_pub_key_info_k *mp_req_k;

				mp_req_u = (struct sk_mp_pub_key_info *)arg;
				mp_req_k = &(request->req_u.mp_pub_key_req);

				mp_req_k->pub_key_len = mp_req_u->x_len + mp_req_u->y_len;

				temp = kmalloc(mp_req_k->pub_key_len, GFP_DMA);
				if (!temp) {
					print_error("allocation failed\n");
					return -ENOMEM;
				}
				req->mem_pointer = temp;

				memset(temp, 0, mp_req_k->pub_key_len);
				print_info("pub_key_size = %u, pub_key = %p",
					mp_req_k->pub_key_len, mp_req_k->pub_key);

				mp_req_k->pub_key = temp;
			}
			break;
		case sk_mp_sign:
			{
				struct sk_mp_sign_req_info *mp_req_u;
				struct sk_mp_sign_req_info_k *mp_req_k;
				int total_sz;

				mp_req_u = (struct sk_mp_sign_req_info *)arg;
				mp_req_k = &(request->req_u.mp_sign_req);

				print_info("mp_req_u->hash_len = %lu, mp_req_u->msg_len = %lu, mp_req_u->r_len = %lu, mp_req_u->s_len = %lu",
						mp_req_u->hash_len, mp_req_u->msg_len, mp_req_u->r_len, mp_req_u->s_len);

				mp_req_k->hash_len = mp_req_u->hash_len;
				mp_req_k->msg_len= mp_req_u->msg_len;
				mp_req_k->r_len = mp_req_u->r_len;
				mp_req_k->s_len = mp_req_u->s_len;

				print_info("mp_req_k->hash_len = %lu, mp_req_k->msg_len = %lu, mp_req_k->r_len = %lu, mp_req_k->s_len = %lu",
						mp_req_k->hash_len, mp_req_k->msg_len, mp_req_k->r_len, mp_req_k->s_len);

				total_sz = mp_req_k->hash_len + mp_req_k->msg_len +
					mp_req_k->r_len + mp_req_k->s_len;

				temp = kmalloc(total_sz, GFP_DMA);
				if (!temp) {
					print_error("allocation failed\n");
					return -ENOMEM;
				}
				req->mem_pointer = temp;

				memset(temp, 0, total_sz);
				mp_req_k->msg = temp;
				mp_req_k->hash = mp_req_k->msg + mp_req_k->msg_len;
				mp_req_k->r = mp_req_k->hash + mp_req_k->hash_len;
				mp_req_k->s = mp_req_k->r + mp_req_k->r_len;

				print_info("mp_req_k->hash = %p, mp_req_k->msg = %p, mp_req_k->r = %p, mp_req_k->s = %p",
						mp_req_k->hash, mp_req_k->msg, mp_req_k->r, mp_req_k->s);
				if (copy_from_user(mp_req_k->msg, mp_req_u->msg,
							mp_req_k->msg_len) != 0) {
					print_error("Copying msg failed\n");
					return -EFAULT;
				}
			}
			break;
		default:
			print_error("Some error has occurred\n");
			return -EINVAL;
	}
	return 0;
}

/* static int sk_unmap(struct device *dev, struct caam_req *ptr,
		struct sk_req *req)
 *  unmap the Physical address of virtual memory pointers of SK request.
 */
void sk_unmap(struct device *dev, struct caam_req *ptr,
		struct sk_req *req)
{
	switch (req->type) {
		case sk_mp_get_pub_key:
			{
				struct sk_mp_pub_key_info_k *sk_mp_pub_key_req;
				struct caam_mp_pub_key_req *c_req;

				sk_mp_pub_key_req = &req->req_u.mp_pub_key_req;
				c_req = &ptr->req_u.mp_pub_key_req;

				dma_unmap_single(dev, c_req->pub_key, sk_mp_pub_key_req->pub_key_len, DMA_BIDIRECTIONAL);

				break;
			}
		case sk_mp_sign:
			{
				struct sk_mp_sign_req_info_k *sk_mp_sign_req;
				struct caam_mp_sign_req *c_req;

				sk_mp_sign_req = &req->req_u.mp_sign_req;
				c_req = &ptr->req_u.mp_sign_req;

				dma_unmap_single(dev, c_req->msg, sk_mp_sign_req->msg_len, DMA_BIDIRECTIONAL);
				dma_unmap_single(dev, c_req->hash, sk_mp_sign_req->hash_len, DMA_BIDIRECTIONAL);
				dma_unmap_single(dev, c_req->r, sk_mp_sign_req->r_len, DMA_BIDIRECTIONAL);
				dma_unmap_single(dev, c_req->s, sk_mp_sign_req->s_len, DMA_BIDIRECTIONAL);

				break;
			}
		default:
			dev_err(dev, "Unable to find request type\n");
			break;
	}
	kfree(ptr);
}

static int sk_mp_get_pub_key_map(struct device *dev, struct sk_req *req,
		struct caam_req *ptr)
{
	struct sk_mp_pub_key_info_k *sk_mp_pub_key_req;
	struct caam_mp_pub_key_req *c_req;

	sk_mp_pub_key_req = &req->req_u.mp_pub_key_req;
	c_req = &ptr->req_u.mp_pub_key_req;

	c_req->pub_key_size = sk_mp_pub_key_req->pub_key_len;

	c_req->pub_key = dma_map_single(dev, sk_mp_pub_key_req->pub_key,
			sk_mp_pub_key_req->pub_key_len, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, c_req->pub_key)) {
		dev_err(dev, "Unable to map memory\n");
		return -ENOMEM;
	}

	return 0;
}

static int sk_mp_sign_map(struct device *dev, struct sk_req *req,
		struct caam_req *ptr)
{
	struct sk_mp_sign_req_info_k *sk_mp_sign_req;
	struct caam_mp_sign_req *c_req;

	sk_mp_sign_req = &req->req_u.mp_sign_req;
	c_req = &ptr->req_u.mp_sign_req;

	c_req->msg_len = sk_mp_sign_req->msg_len;
	c_req->hash_len = sk_mp_sign_req->hash_len;
	c_req->r_len = sk_mp_sign_req->r_len;
	c_req->s_len = sk_mp_sign_req->s_len;

	c_req->msg = dma_map_single(dev, sk_mp_sign_req->msg,
			sk_mp_sign_req->msg_len, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, c_req->msg)) {
		dev_err(dev, "Unable to map memory\n");
		goto msg_map_fail;
	}

	c_req->hash = dma_map_single(dev, sk_mp_sign_req->hash,
			sk_mp_sign_req->hash_len, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, c_req->hash)) {
		dev_err(dev, "Unable to map memory\n");
		goto hash_map_fail;
	}

	c_req->r = dma_map_single(dev, sk_mp_sign_req->r,
			sk_mp_sign_req->r_len, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, c_req->r)) {
		dev_err(dev, "Unable to map memory\n");
		goto r_map_fail;
	}

	c_req->s = dma_map_single(dev, sk_mp_sign_req->s,
			sk_mp_sign_req->s_len, DMA_BIDIRECTIONAL);
	if (dma_mapping_error(dev, c_req->s)) {
		dev_err(dev, "Unable to map memory\n");
		goto s_map_fail;
	}
	return 0;

s_map_fail:
	dma_unmap_single(dev, c_req->r, sk_mp_sign_req->r_len, DMA_BIDIRECTIONAL);
r_map_fail:
	dma_unmap_single(dev, c_req->hash, sk_mp_sign_req->hash_len, DMA_BIDIRECTIONAL);
hash_map_fail:
	dma_unmap_single(dev, c_req->msg, sk_mp_sign_req->msg_len, DMA_BIDIRECTIONAL);
msg_map_fail:
	return -ENOMEM;
}

uint32_t sk_map_caam_req(struct device *dev, struct sk_req *req)
{
	struct caam_req *c_req = NULL;

	c_req = kmalloc(sizeof(struct caam_req), GFP_DMA);
	if (!c_req) {
		dev_err(dev, "kmalloc failed\n");
		return -ENOMEM;
	}

	switch (req->type) {
		case sk_mp_get_pub_key:
			{
				c_req->type = mp_get_pub_key;
				if (sk_mp_get_pub_key_map(dev, req, c_req)) {
					dev_err(dev, "sk_mp_get_pub_key_map failed !\n");
					kfree(c_req);
					return -ENOMEM;
				}

				break;
			}
		case sk_mp_sign:
			{
				c_req->type = mp_sign;
				if (sk_mp_sign_map(dev, req, c_req)) {
					dev_err(dev, "sk_mp_sign_map failed !\n");
					kfree(c_req);
					return -ENOMEM;
				}

				break;
			}
		default:
			print_error("Unknown request type\n");
			return -EINVAL;
	}

	req->ptr = (void *)c_req;
	return 0;
}

/*
 *  Open the /dev/securekeydev device and allocate job ring.
 */
static int
securekeydev_open(struct inode *inode, struct file *filp)
{
	struct device *dev = NULL;

	/*! Call caam_jr_alloc function to allocate a job ring. */
	dev = caam_jr_alloc();
	if (!dev) {
		print_error("caam_jr_alloc failed\n");
		return -ENODEV;
	}

	filp->private_data = dev;
	return 0;
}

/*
 *  Close the /dev/securekeydev device and free job ring.
 */
static int
securekeydev_release(struct inode *inode, struct file *filp)
{
	struct device *dev = NULL;

	dev = filp->private_data;
	/*! Call caam_jr_free function to free the job ring. */
	caam_jr_free(dev);

	return 0;
}

#if 0
/*! @fn static int sk_translate_caam_error(int ret)
 *  @brief Translates the Caam error codes.
 *  @param[in] ret return value of CAAM job ring
 *  @return translated error code.
 */
static int sk_translate_caam_error(int ret)
{
	switch (ret) {
		case BLK_BLOB_ICV_ERROR:
			return BAD_BLACK_BLOB;
		case BLK_KEY_ERROR:
			return BAD_BLACK_KEY;
		case AES_CCM_ICV_ERROR:
			return AES_CCM_AUTH_FAILED;
		default:
			return UNKNOWN_ERROR;
	}
}
#endif

/*
 *  prints the error string.
 */
static void sk_print_error(struct sk_req *req)
{
	switch (req->type) {
		case sk_mp_get_pub_key:
			print_error("MP Get Public key failed\n");
			break;
		case sk_mp_sign:
			print_error("MP Sign failed\n");
			break;
		default:
			print_error("Invalid type\n");
	}
}

/*
 *  Ioctl function called from Securekeylibrary.
 */
static long
securekeydev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg_)
{
	void *arg = (void *)arg_;
	struct sk_req *req = NULL;
	struct device *jrdev = filp->private_data;
	int ret;

	req = kmalloc(sizeof(struct sk_req), GFP_DMA);
	if (req == NULL) {
		print_error("Allocation failed\n");
		return -ENOMEM;
	}

	switch (cmd) {
		case SK_MP_GET_PUB_KEY:
			req->type = sk_mp_get_pub_key;
			req->arg = arg;

			break;
		case SK_MP_SIGN:
			req->type = sk_mp_sign;
			req->arg = arg;

			break;
		default:
			print_error("IOCTL command does not match with any supported.\n");
			kfree(req);
			return -EINVAL;
	}

	/*!1. Copy data from User space buffer. */
	ret = sk_copy_data_from_user(req, req->arg);
	if (ret) {
		print_error("Copy failed\n");
		goto error;
	}

	/*!2. Call sk_map_caam_req function to create caam structure. */
	ret = sk_map_caam_req(jrdev, req);
	if (ret) {
		print_error("sk_map_caam_req failed\n");
		goto desc_init_error;
	}

	/*!3. Call caam_job_submit function to build and submit a
	  *    Job descriptor to Job ring. */
	ret = caam_job_submit(jrdev, req->ptr);
	if (!ret) {
		/*!4. Copy output to User space buffer. */
		ret = sk_copy_data_to_user(req, arg);
	} else {
		sk_print_error(req);
		ret = -1;
	}

	sk_unmap(jrdev, req->ptr, req);

desc_init_error:
	kfree(req->mem_pointer);
error:
	kfree(req);
	return ret;
}

/* compatibility code for 32bit userlands */
#ifdef CONFIG_COMPAT
static long
securekeydev_compat_ioctl(struct file *file, unsigned int cmd,
		unsigned long arg_)
{
	return 0;
}

#endif /* CONFIG_COMPAT */

/*
 *  Poll function for securekeydev device.
 */
static unsigned int securekeydev_poll(struct file *file, poll_table *wait)
{
	return 0;
}

/*
  * Securekeydev file operation object.
 */
static const struct file_operations securekeydev_fops = {
	.owner = THIS_MODULE,
	.open = securekeydev_open,
	.release = securekeydev_release,
	.unlocked_ioctl = securekeydev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = securekeydev_compat_ioctl,
#endif /* CONFIG_COMPAT */
	.poll = securekeydev_poll,
};

/*
  * Securekeydev device object.
  */
static struct miscdevice securekeydev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "securekeydev",
	.fops = &securekeydev_fops,
	.mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH,
};

/*
 * Register the /dev/securekeydev device.
 */
static int __init
securekeydev_register(void)
{
	int rc;

	rc = misc_register(&securekeydev);
	if (unlikely(rc)) {
		print_error("registration of /dev/securekeydev failed\n");
		return rc;
	}

	return 0;
}

/*
 * Deregister the /dev/securekeydev device.
 */
static void __exit
securekeydev_deregister(void)
{
	misc_deregister(&securekeydev);
}

/* ====== Module init/exit ====== */
static struct ctl_table verbosity_ctl_dir[] = {
	{
		.procname       = "securekeydev_verbosity",
		.data           = &securekeydev_verbosity,
		.maxlen         = sizeof(int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{},
};

static struct ctl_table verbosity_ctl_root[] = {
	{
		.procname       = "ioctl",
		.mode           = 0555,
#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
		.child          = verbosity_ctl_dir,
#endif
	},
	{},
};
static struct ctl_table_header *verbosity_sysctl_header;

/*
 * Securekeydev module_init function.
 */
static int __init init_securekeydev(void)
{
	int rc;

	/* Call securekeydev_register function to register /dev/securekeydev device. */
	rc = securekeydev_register();
	if (unlikely(rc)) {
		print_error("Driver load failed\n");
		return rc;
	}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0))
	verbosity_sysctl_header = register_sysctl_table(verbosity_ctl_root);
#else
	verbosity_sysctl_header = register_sysctl(verbosity_ctl_root->procname,
						  verbosity_ctl_dir);
#endif

	printk("Securekey Driver Module inserted successfully\n");
	return 0;
}

/*
 * Securekeydev module_exit function.
 */
static void __exit exit_securekeydev(void)
{
	if (verbosity_sysctl_header)
		unregister_sysctl_table(verbosity_sysctl_header);

	/* Call securekeydev_deregister function to deregister /dev/securekeydev device. */
	securekeydev_deregister();
}

/*
 * Specifies the module init function.
 */
module_init(init_securekeydev);

/*
 *  Specifies the module exit function.
 */
module_exit(exit_securekeydev);


