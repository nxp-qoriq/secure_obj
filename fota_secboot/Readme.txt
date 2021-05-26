*********************************************************************************************************
Steps to build the fsl_validate library.
*********************************************************************************************************
1. Export the cross-compiled openssl library path (OPENSSL_PATH).
	for example: Cross -Compiled openssl library present at path "/home/munish/Munish_work/secure_boot/
	fota_secboot/openssl/include"

	Command:
		export OPENSSL_PATH=/home/munish/Munish_work/secure_boot/fota_secboot/openssl

2. Export the CROSS_COMIPLE. by default Make utility takes "aarch64-linux-gnu-" as cross-compile tool.
	Command:
		export CROSS_COMPILE=aarch64-linux-gnu-

3. After performing above step issue below command to build the library.
	make CONFIG_SRK=1 PLATFORM=1043 DEBUG=1 ENDIAN=1

*********************************************************************************************************
Steps to build and Run the utility
*********************************************************************************************************
1. Create a dynamic library (libfsl_validate.so) by using the steps mentioned in Redme present in lib directory.
2. After successfully build of library export the Cross-compiled openssl library path (OPENSSL_PATH).
        for example: Cross -Compiled openssl library present at path "/home/munish/Munish_work/secure_boot/
        fota_secboot/openssl"

        Command:
                export OPENSSL_PATH=/home/munish/Munish_work/secure_boot/fota_secboot/openssl

3. Export the CROSS_COMIPLE. by default Make utility takes "aarch64-linux-gnu-" as cross-compile tool.
        Command:
                export CROSS_COMPILE=aarch64-linux-gnu-
4. Export the LD_LIBRARY_PATH. As the Library is present in the lib directory.
        Command:
                export LD_LIBRARY_PATH=/home/munish/Munish_work/secure_boot/fota_secboot/secure_obj_fota_secboot/fota_secboot/lib
5. After performing above step issue command "make" to build the utiity.

To run this utility:
        ./validate <path of ESBC header> <patched kernel.itb path>
        for example:
        ./validate hdr_ppa.out kernel.itb
