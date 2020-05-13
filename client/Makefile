CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

TIME_LOG ?= 1
PWD= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT=$(PWD)..
LOGGER_DIR=$(ROOT)/src/logger

CLIENT=client
CLIENT_SRC=$(wildcard $(PWD)/*.c)
CLIENT_OBJ=$(CLIENT_SRC:.c=.o)
LOGGER_SRC=$(LOGGER_DIR)/seed_logger.c
LOGGER_OBJ=$(LOGGER_SRC:.c=.o)

BINS=${CLIENT}
OBJS=${CLIENT_OBJ} ${LOGGER_OBJ}

ifeq ($(TIME_LOG), 1)
	CFLAGS += -DTIME_LOG
endif

CFLAGS+=-I$(ROOT)/include
LDFLAGS=-L$(ROOT)/lib -lssl -lcrypto -ldl -lpthread -lsimple_http

all: client

client: ${CLIENT_OBJ} ${LOGGER_OBJ}
	${CC} -o ${CLIENT} ${OBJS} ${LDFLAGS}
	@echo "LINK  =>  $@"

client.o: ${CLIENT_SRC}
	${CC} ${FLAGS} ${CFLAGS} -c $<
	@echo "CC  <=  $<"

$(LOGGER_DIR)%.o: $(LOGGER_DIR)*.c
	$(CC) $(CFLAGS) -c $< -o $@
	@echo "CC  <=  $<"

clean:
	rm ${BINS} ${OBJS}
