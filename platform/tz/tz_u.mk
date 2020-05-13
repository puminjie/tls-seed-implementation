TIME_LOG ?= 1
SEED_DEBUG ?= 1
COMMON_DIR=$(ROOT)/src/common
COMMON_INC=$(ROOT)/include
UNTRUSTED_INC=$(ROOT)/platform/include/untrusted
UNTRUSTED_DIR=host
UNTRUSTED_COMMON_DIR=$(ROOT)/src/untrusted
LOGGER_DIR=$(ROOT)/src/logger

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump:wq
READELF = $(CROSS_COMPILE)readelf

EDGE=tz_seed
EDGE_SRC := $(wildcard $(COMMON_DIR)/*.c $(UNTRUSTED_COMMON_DIR)/*.c $(UNTRUSTED_DIR)/*.c $(LOGGER_DIR)/*.c)
EDGE_OBJ := $(EDGE_SRC:.c=.o)

BINS=$(EDGE)
OBJS=$(EDGE_OBJ)

ROOT_DIR=../..

CFLAGS=-Wall -Ita/include -I$(TEEC_EXPORT)/include -I$(PACKAGE_INC) -I$(COMMON_INC) -I$(UNTRUSTED_INC)

ifeq ($(TIME_LOG), 1)
	CFLAGS += -DTIME_LOG
endif

ifeq ($(SEED_DEBUG), 1)
	CFLAGS += -DDEBUG
endif

CFLAGS += -DPLATFORM_OPTEE

LDFLAGS=-L$(TEEC_EXPORT)/lib -L$(PACKAGE_LIB)/host -lteec -lssl -lcrypto -levent -lsimple_http

HOST=www.bob.com
PORT=5555

all: edge

edge: $(EDGE_OBJ)
	$(CC) -o $(EDGE) $(EDGE_OBJ) $(LDFLAGS)

.c.o:
	$(CC) $(FLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm $(BINS) $(OBJS)
