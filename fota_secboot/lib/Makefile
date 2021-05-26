CROSS_COMPILE ?= aarch64-linux-gnu-

CC = $(CROSS_COMPILE)gcc
ifeq ($(CONFIG_SRK),1)
CFLAGS += -DCONFIG_SRK
endif

ifeq ($(PLATFORM),1043)
CFLAGS += -DLA1043A
endif

ifeq ($(DEBUG),1)
CFLAGS += -DDEBUG
endif

ifeq ($(ENDIAN),1)
CFLAGS += -DBIG_ENDIAN
endif

CFLAGS += -Wall
LDFLAGS =
FLAGS = -shared
LIB_PATH = include
INCLUDES = -I $(LIB_PATH) -I $(OPENSSL_PATH)/include
SRCFILES = *.c
OBJFILES = *.o
TARGET = libfsl_validate.so

all:
	@echo "-----------------------------"
	@echo "- CC =		$(CC)"
	@echo "- CFLAGS =	$(CFLAGS)"
	@echo "- INCLUDES =	$(INCLUDES)"
	@echo "- LDFLAGS =	$(LDFLAGS)"
	@echo "- TARGET =	$(TARGET)"
	@echo "-----------------------------"

	$(CC) $(CFLAGS) $(INCLUDES) -c *$(SRCFILES)  -lssl -lcrypto
	$(CC) $(CFLAGS) $(INCLUDES) $(FLAGS) -o $(TARGET) $(OBJFILES)

clean:
	rm -f $(OBJFILES)
	rm -f $(TARGET)
