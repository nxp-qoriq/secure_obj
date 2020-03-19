CROSS_COMPILE ?= aarch64-linux-gnu-
LD_LIBRARY_PATH ?= ../lib
CC = $(CROSS_COMPILE)gcc

LIB_NAME = fsl_validate

CFLAGS += -Wall
LDFLAGS =
LIB_PATH = ../lib/include
INCLUDES = -I $(LIB_PATH)
SRCFILES = main.c
TARGET = validate

all:
	@echo "-----------------------------"
	@echo "- CC =		$(CC)"
	@echo "- CFLAGS =	$(CFLAGS)"
	@echo "- INCLUDES =	$(INCLUDES)"
	@echo "- LD_PATH =	$(LDFLAGS)"
	@echo "- TARGET =	$(TARGET)"
	@echo "-----------------------------"

	$(CC) $(CFLAGS) $(INCLUDES) $(SRCFILES) -L $(LD_LIBRARY_PATH) -l $(LIB_NAME) -o $(TARGET) -lssl -lcrypto -L $(OPENSSL_PATH)

clean:
	rm -f $(TARGET)
