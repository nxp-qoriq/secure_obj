#
# Since version 1.6 the asynchronous mode has been
# disabled by default. To re-enable it uncomment the
# corresponding CFLAG.
#
KBUILD_CFLAGS += -I${KERNEL_SRC}/include/
KBUILD_CFLAGS += -I$(src) -I${KERNEL_SRC}/drivers/crypto

.SILENT:
securekeydev-objs = securekey_caam.o ioctl.o

obj-m += securekeydev.o
ifneq ($(KERNEL_BUILD),)
	KERNEL_MAKE_OPTS := -C ${KERNEL_BUILD} M=$(shell pwd)
else
	KERNEL_MAKE_OPTS := -C $(KERNEL_SRC) M=$(shell pwd)
endif


all:
	$(MAKE) $(KERNEL_MAKE_OPTS) modules

modules_install:
	$(MAKE) $(KERNEL_MAKE_OPTS) modules_install

clean:
	rm -f *.o *~ core .depend .*.cmd *.ko *.mod.c
	rm -f Module.markers Module.symvers modules.order
	rm -rf .tmp_versions Modules.symvers
