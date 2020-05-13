CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

GCC=gcc
PWD= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR=$(PWD)../..

GENERATE_DC=generate_dc
GENERATE_DC_SRC=generate_dc.c
GENERATE_DC_OBJ=generate_dc.o

BINS=${GENERATE_DC}
OBJS=${GENERATE_DC_OBJ}

CFLAGS=-I$(ROOT_DIR)/etc/include
LDFLAGS=-L$(ROOT_DIR)/etc/lib -lcrypto -lssl -ldl -lpthread

all: generate_dc

generate_dc: ${GENERATE_DC_OBJ}
	${GCC} -o ${GENERATE_DC} ${GENERATE_DC_OBJ} ${LDFLAGS}

generate_dc.o: ${GENERATE_DC_SRC}
	${GCC} -g ${FLAGS} ${CFLAGS} -c $< -include ../../include/debug.h

clean:
	rm -rf $(BINS) $(OBJS) 
