# Default out dir.
O               ?= out

include flags.mk

#########################################################################
# Set Internal Variables						#
#########################################################################
BUILD_VERBOSE	?= 0
VPREFIX		?= @
ifeq ($(BUILD_VERBOSE),1)
VPREFIX:=
endif

EXPORT_DIR ?= $(O)/export
OUT_DIR ?= $(O)/securekey_lib

.PHONY: all securekey_lib install \
	clean distclean app

all: securekey_lib securekey_static_lib app install

LIB_NAME	:= libsecurekey.so
STATIC_LIB_NAME        := libsecurekey.a

SECUREKEY_SRCS	:= securekey.c

SECUREKEY_SRC_DIR	:= src
SECUREKEY_OBJ_DIR	:= $(OUT_DIR)
SECUREKEY_OBJS		:= $(patsubst %.c,$(SECUREKEY_OBJ_DIR)/%.o, $(SECUREKEY_SRCS))
SECUREKEY_INCLUDES	:= $(OPTEE_CLIENT_EXPORT)/include \
			   ${CURDIR}/include \
			   $(SECURE_STORAGE_PATH)/include

SECUREKEY_CFLAGS	:= $(addprefix -I, $(SECUREKEY_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE

SECUREKEY_LFLAGS	:= -L$(OPTEE_CLIENT_EXPORT)/lib -lteec

SECUREKEY_LIBRARY	:= $(OUT_DIR)/$(LIB_NAME)
SECUREKEY_STATIC_LIBRARY	:= $(OUT_DIR)/$(STATIC_LIB_NAME)

securekey_lib: $(SECUREKEY_LIBRARY)

$(SECUREKEY_LIBRARY): $(SECUREKEY_OBJS)
	@echo "  LD      $@"
	$(VPREFIX)$(CC) -shared -Wl,-soname,$(LIB_NAME) -o $@ $+ $(SECUREKEY_LFLAGS)

securekey_static_lib: $(SECUREKEY_STATIC_LIBRARY)

$(SECUREKEY_STATIC_LIBRARY): $(SECUREKEY_OBJS)
	@echo "  LD      $@"
	$(VPREFIX)$(AR) -rcs ${OUT_DIR}/$(STATIC_LIB_NAME) -o $+
	@echo ""

$(SECUREKEY_OBJ_DIR)/%.o: ${SECUREKEY_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(SECUREKEY_OBJ_DIR)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(SECUREKEY_CFLAGS) -c $< -o $@

app:
	@echo "Building securekey app"
	$(VPREFIX)$(CC) -Iinclude/ -o app/test app/test.c -lsecurekey -Lout/securekey_lib/ $(SECUREKEY_LFLAGS)

install:
	mkdir -p ${EXPORT_DIR}/lib ${EXPORT_DIR}/include ${EXPORT_DIR}/app
	cp ${OUT_DIR}/libsecurekey.so ${EXPORT_DIR}/lib
	cp ${OUT_DIR}/libsecurekey.a ${EXPORT_DIR}/lib
	cp ${CURDIR}/include/*.h ${EXPORT_DIR}/include
	mv app/test ${EXPORT_DIR}/app

################################################################################
# Cleaning up configuration
################################################################################
clean:
	$(RM) $(O)

distclean: clean
