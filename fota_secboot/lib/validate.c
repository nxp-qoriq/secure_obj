// SPDX-License-Identifier: BSD-3-Clause OR GPL-2.0
/*
 * Copyright 2020 NXP
 */
#include "validate.h"
#include "common.h"

static const u8 barker_code[ESBC_BARKER_LEN] = { 0x68, 0x39, 0x27, 0x81 };

/***************************************************************************
 * Function     :	get_key_revoc
 * Arguments    :	void
 * Return       :	WIll return the revoked key register value
 * Description  :	Read and return the Key_revoc register of SFP
 ***************************************************************************/
#ifdef CONFIG_SRK
static struct ccsr_sfp_regs *g_sfp_addr;
static u32 get_key_revoc(void)
{
	return (sfp_in32(&g_sfp_addr->ospr) & OSPR_KEY_REVOC_MASK) >>
		OSPR_KEY_REVOC_SHIFT;
}

/***************************************************************************
 * Function     :	is_key_revoked
 * Arguments    :	img: base address of allocated struct
 *			fsl_secboot_img
 * Return       :	0 - Success, Else 1
 * Description  :	This function checks if selected key is revoked or not
 ***************************************************************************/
static u32 is_key_revoked(u32 keynum, u32 rev_flag)
{
	if (keynum == UNREVOCABLE_KEY)
		return 0;

	if ((u32)(1 << (ALIGN_REVOC_KEY - keynum)) & rev_flag)
		return 1;

	return 0;
}
#endif

/***************************************************************************
 * Function     :	read_validate_srk_tbl
 * Arguments    :	img_hdr: base address of allocated struct
 *			fsl_secboot_img
 * Return       :	0 - Success, Else error code on failure
 * Description  :	This function will read and validate the srk keys.
 ***************************************************************************/
static u32 read_validate_srk_tbl(struct fsl_secboot_img *img)
{
	int i = 0;
	u32 key_num, size;
	struct fsl_secboot_img_hdr *hdr = &img->hdr;
#ifdef DEBUG
	printf("key_num: %d key_Sel: %d\n", hdr->len_kr.num_srk,
					hdr->len_kr.srk_sel);
#endif
	if ((hdr->len_kr.num_srk == 0) ||
			(hdr->len_kr.num_srk > MAX_KEY_ENTRIES))
		return ERROR_ESBC_CLIENT_HEADER_INVALID_SRK_NUM_ENTRY;

	key_num = hdr->len_kr.srk_sel;
	if (key_num == 0 || key_num > hdr->len_kr.num_srk)
		return ERROR_ESBC_CLIENT_HEADER_INVALID_KEY_NUM;

#ifdef CONFIG_SRK
	u32 key_revoc_flag = 0, ret = 0;
	/* Get revoc key from sfp */
	key_revoc_flag = get_key_revoc();
	ret = is_key_revoked(key_num, key_revoc_flag);
	if (ret)
		return ERROR_ESBC_CLIENT_HEADER_KEY_REVOKED;
#endif
	size = hdr->len_kr.num_srk * sizeof(struct srk_table);
#ifdef DEBUG
	printf("Key table size: %d\n", size);
#endif
	/*
	 * Set the curser position at srk tbl offset
	 */
	fseek(img->fp, hdr->srk_tbl_off, SEEK_SET);
	/*
	 * Read the values key value from the header to
	 * local structure
	 */
	fread(&img->srk_tbl, size, 1, img->fp);

#ifdef DEBUG
	u8 *p1 = (u8 *)&img->srk_tbl;

	printf("SRK table keys:\n");
	for (i = 0; i < size; i++)
		printf("%02x", p1[i]);
	printf("\n");
#endif
	for (i = 0; i < hdr->len_kr.num_srk; i++) {
		if (!CHECK_KEY_LEN(img->srk_tbl[i].key_len))
			return ERROR_ESBC_CLIENT_HEADER_INV_SRK_ENTRY_KEYLEN;
	}

	img->key_len = img->srk_tbl[key_num - 1].key_len;

	memcpy(&img->img_key, &(img->srk_tbl[key_num - 1].pkey),
			img->key_len);

	return 0;
}
/***************************************************************************
 * Function     :	read_validate_single_key
 * Arguments    :	img_hdr: base address of allocated struct
 *			fsl_secboot_img
 * Return       :	0 - Success, Else error code on failure
 * Description  :	This function will read the public key from
 *			ESBC header
 ***************************************************************************/
static int read_validate_single_key(struct fsl_secboot_img *img)
{
	struct fsl_secboot_img_hdr *hdr = &img->hdr;
	struct srk_table key = {0};

	if (!CHECK_KEY_LEN(hdr->key_len))
		return ERROR_ESBC_CLIENT_HEADER_KEY_LEN;

	fseek(img->fp, hdr->pkey, SEEK_SET);
	fread(&key, (hdr->key_len + sizeof(u32)), 1, img->fp);
	img->key_len = key.key_len;

	memcpy(&img->img_key, &key.pkey, img->key_len);
#ifdef DEBUG
	int i;
	u8  *p1 = (u8 *)&key.pkey;

	printf("Public key value\n");
	for (i = 0; i < img->key_len; i++)
		printf("%02x", p1[i]);
	printf("\n");
#endif
	return 0;
}

/***************************************************************************
 * Function     :	hdr_read_validate
 * Arguments    :	img_hdr: base address of allocated struct
 *			fsl_secboot_img
 * Return       :	0 - Success, Else error code on failure
 * Description  :	This function will read and validate the content of
 *			the esbc header.
 ***************************************************************************/
static int hdr_read_validate(struct fsl_secboot_img *img_hdr)
{
	struct fsl_secboot_img_hdr *hdr = &img_hdr->hdr;
	u8 *k, *s;
	int key_found = 0, ret = 0;

	/* check barker code */
	if (memcmp(hdr->barker, barker_code, ESBC_BARKER_LEN))
		return ERROR_ESBC_CLIENT_HEADER_BARKER;
	if (hdr->len_kr.srk_flag & SRK_FLAG) {
		ret = read_validate_srk_tbl(img_hdr);
		if (ret)
			return ret;
		key_found = 1;
	}
	if (!key_found) {
		ret = read_validate_single_key(img_hdr);
		if (ret)
			return ret;
		key_found = 1;
	}

	if (!key_found)
		return ERROR_KEY_TABLE_NOT_FOUND;

	/* check signaure */
#ifdef DEBUG
	printf("hdr sign len %d\n", hdr->sign_len);
#endif
	if (get_key_len(img_hdr) == 2 * hdr->sign_len) {
		/* check signature length */
		if (!((hdr->sign_len == KEY_SIZE_BYTES / 4) ||
					(hdr->sign_len == KEY_SIZE_BYTES / 2) ||
					(hdr->sign_len == KEY_SIZE_BYTES)))
			return ERROR_ESBC_CLIENT_HEADER_SIG_LEN;
	} else {
		return ERROR_ESBC_CLIENT_HEADER_KEY_LEN_NOT_TWICE_SIG_LEN;
	}

	/*
	 * Set the curser position at signature
	 */
	fseek(img_hdr->fp, hdr->psign, SEEK_SET);
	fread(&img_hdr->img_sign, hdr->sign_len, 1, img_hdr->fp);
#ifdef DEBUG
	int i;
	u8 *p1 = (u8 *)&img_hdr->img_sign;

	printf("Signature value:\n");
	for (i = 0; i < hdr->sign_len; i++)
		printf("%02x", p1[i]);
	printf("\n");
#endif
	/* modulus most significant bit should be set */
	k = (u8 *)&img_hdr->img_key;

	if ((k[0] & 0x80) == 0)
		return ERROR_ESBC_CLIENT_HEADER_KEY_MOD_1;

	/* modulus value should be odd */
	if ((k[get_key_len(img_hdr) / 2 - 1] & 0x1) == 0)
		return ERROR_ESBC_CLIENT_HEADER_KEY_MOD_2;

	/* Check signature value < modulus value */
	s = (u8 *)&img_hdr->img_sign;

	if (!(memcmp(s, k, hdr->sign_len) < 0))
		return ERROR_ESBC_CLIENT_HEADER_SIG_KEY_MOD;

	return 0;
}
/***************************************************************************
 * Function     :	fota_secboot_validate
 * Arguments	:	hdr_path: path of patched ESBC header
 *			bin_path: Path of patched kenel.itb
 * Return       :	0 - Success, Else error code on failure
 * Description  :	This function will validate the authenticity of
 *			updated kernel.itb file.
 ***************************************************************************/
int fota_secboot_validate(const char *hdr_path, const char *bin_path)
{
#ifdef DEBUG
	printf("In FSL Fota_Secboot_validate()\nhdr_path: %s\n:bin_path: %s\n",
			hdr_path, bin_path);
#endif

	int ret;
	/*check whether Header path and binary path is valid?*/
	if (hdr_path == NULL ||  bin_path == NULL) {
		ret = ERROR_INVALID_BIN_HDR_PATH;
		goto exit;
	}
	int size = 0;
	u8 *bin = NULL;
	FILE *hdr_file = NULL, *bin_file = NULL;
	struct fsl_secboot_img *img = NULL;
#ifdef CONFIG_SRK
	u32 srk_hash[NUM_SRKH_REGS];
	u8 *mmap_addr = NULL;
	int fd = 0;
	/*
	 * Open the ddr dev node to map the sfp register
	 * of the system
	 */
	fd = open(DDR_FILE_NAME, O_RDWR|O_SYNC);
	if (-1 == fd) {
		ret = DEV_FILE_OPENING_FAILURE;
		goto exit;
	}
	/*Map the SFP registers into ddr and return the base address
	 *AS MMAP accept size variable in the multiple of page size
	 *hence given 4096 as size.
	 */
	mmap_addr = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED,
			fd, CONFIG_SYS_SFP_ADDR);

	/*
	 * Map sfp_address to the base address of the sfp register in the
	 * system.
	 */
	g_sfp_addr = (struct ccsr_sfp_regs *)(mmap_addr + CCSR_SFP_BASEADDR);

#ifdef DEBUG
	printf(" SFP_registers mapped at 0x%p\n",  g_sfp_addr);
#endif
#endif
	/*
	 * Open the ESBC header file and read the content
	 */
	hdr_file = fopen(hdr_path, "r+b");
	if (NULL == hdr_file) {
		ret = FILE_OPENING_FAILURE;
		goto exit;
	}
	/*
	 * Set the curser position at begnning
	 */
	fseek(hdr_file, 0L, SEEK_SET);

#ifdef DEBUG
	/*
	 * Debug print for barker code checking
	 */
	char num[4];

	ret =  fread(&num, sizeof(num), 1, hdr_file);
	printf("barker code\n");
	printf("%02x %02x %02x %02x\n", num[0], num[1], num[2], num[3]);
	fseek(hdr_file, 0L, SEEK_SET);
#endif

	/*
	 * Allocate memory to img of type struct fsl_secboot_img
	 */
	img = (struct fsl_secboot_img *)malloc(sizeof(struct fsl_secboot_img));
	if (NULL == img) {
		ret = ERROR_MEMORY_ALLOCATION_FAIL;
		goto exit;
	}
	img->fp = hdr_file;
	/*
	 * read the content of esbc header file and keep that locally
	 */
	ret =  fread(&img->hdr, sizeof(struct fsl_secboot_img_hdr),
					1, hdr_file);
	if (!ret) {
		ret = ERROR_FILE_READ_FAILURE;
		goto exit;
	}
	/*
	 * read and validate the ESBC header received
	 */
	ret = hdr_read_validate(img);
	if (ret)
		goto exit;
	/*
	 * Calculate the SRK image key hash
	 */
	ret = calc_img_key_hash(img);
	if (ret) {
		printf("Failed to calculate image hash\n");
		goto exit;
	}
#ifdef DEBUG
	int i;

	printf("calculated hash\n");
	for (i = 0; i < 32; i++)
		printf("%02x", img->img_key_hash[i]);
	printf("\n");
#endif
#ifdef CONFIG_SRK
	/*
	 * Read the stored SRK hash in SFP registers
	 */
#ifdef DEBUG
	printf("SRK HASH:\n");
#endif
	for (i = 0; i < NUM_SRKH_REGS; i++) {
		srk_hash[i] = sfp_in32(&g_sfp_addr->srk_hash[i]);
#ifdef DEBUG
		printf("%08x", srk_hash[i]);
#endif
	}
	printf("\n");

	ret = memcmp((u8 *)srk_hash, img->img_key_hash, SHA256_BYTES);
	if (ret != 0) {
		ret = ERROR_ESBC_CLIENT_HASH_COMPARE_KEY;
		goto exit;
	}
#endif
	/*
	 * Open the Kernel.itb file
	 */
	bin_file = fopen(bin_path, "r");
	if (NULL == bin_file) {
		ret = FILE_OPENING_FAILURE;
		goto exit;
	}
	fseek(bin_file, 0L, SEEK_SET);
	/*
	 * Get the size of the file
	 */
	char ch;

	while ((ch = fgetc(bin_file)) != EOF)
		size++;

#ifdef DEBUG
	printf("size of kernel.itb: %d bytes\n", size);
#endif
	if (!size) {
		ret = ERROR_INVALID_BIN_SIZE;
		goto exit;
	}
	/*
	 * Allocate the buffer of size kernel.itb
	 */
	bin = (u8 *)malloc(size);
	if (bin == NULL) {
		ret = ERROR_MEMORY_ALLOCATION_FAIL;
		goto exit;
	}
	/* Seek the curser location at the beginning
	 * and read the content of the file in buffer
	 * allocated.
	 */
	fseek(bin_file, 0L, SEEK_SET);
	ret =  fread(bin, size, 1, bin_file);
	if (!ret) {
		ret = ERROR_FILE_READ_FAILURE;
		goto exit;
	}
#ifdef DEBUG
	u8 *p1 = (u8 *)bin;

	printf("Bin file initial bytes:\n");
	for (i = 0; i < 16; i++)
		printf("%x", p1[i]);
	printf("\n");
#endif
	/*
	 * calculate collective hash over esbc_hdr,
	 * srk_keys, kernel.itb. Decrypt the signature
	 * and match with calcuated hash
	 */
	ret = calculate_cmp_img_sig(img, bin, size);
	if (ret)
		goto exit;
exit:
	if (bin) {
		free(bin);
		bin = NULL;
	}
	if (img) {
		free(img);
		img = NULL;
	}
	if (bin_file)
		fclose(bin_file);
	if (hdr_file)
		fclose(hdr_file);
#ifdef CONFIG_SRK
	if (fd) {
		if (g_sfp_addr) {
			munmap(mmap_addr, 4096);
			g_sfp_addr = NULL;
			mmap_addr = NULL;
		}
		close(fd);
	}
#endif

	fota_handle_error(ret);
	return ret;
} //function close
