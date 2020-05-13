GCC=gcc
RM=rm
OPTS=-g -Wall -o

PWD= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR=$(PWD)../..

BIN=cc_server
SRCS=$(wildcard $(PWD)*.c)
OBJS=$(SRCS:.c=.o)

CFLAGS=-I$(ROOT_DIR)/include
LDFLAGS=-L$(ROOT_DIR)/lib -lssl -lcrypto -ldl -lsimple_http

all: cc_server

cc_server: cc_server.o cc_func.o
	${GCC} ${OPTS} $@ $^ ${LDFLAGS}

cc_server.o: cc_server.c 
	${GCC} ${CFLAGS} -c $<

cc_func.o: cc_func.c
	${GCC} ${CFLAGS} -c $<

clean:
	$(RM) $(BIN) $(OBJS)
