PWD= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR=$(PWD)../..
SRC_DIRECTORY = $(PWD)

AARCH64_COMPILER_PREFIX=$(ROOT_DIR)/../toolchains/aarch64/bin/aarch64-linux-gnu-

COMMON_SRCS=$(wildcard $(SRC_DIRECTORY)*.c)
COMMON_OBJS=$(COMMON_SRCS:.c=.o)

COMMON_CFLAGS=-I$(ROOT_DIR)/include
COMMON_LDFLAGS=-lssl -lcrypto -lsimple_http -ldl -levent

HOST=www.bob.com
PORT=5555
