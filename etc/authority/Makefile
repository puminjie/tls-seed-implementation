CERT_FILE=carol_cert.pem
CA_CERT_FILE=ca_carol.pem
KEY_FILE=carol_priv.key
ORIG_CERT_FILE=orig_ecc_256_cert.der

GCC=gcc
PWD= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
ROOT_DIR=$(PWD)../..

CFLAGS=-I$(ROOT_DIR)/include
LDFLAGS=-L$(ROOT_DIR)/lib -lssl -lcrypto -ldl -lsimple_http

AUTH=authority
AUTH_SRC=authority.c
AUTH_OBJ=authority.o

PORT=1234

all: authority 

authority: authority.o
	${GCC} -o $@ $< ${LDFLAGS}

authority.o: authority.c
	${GCC} ${CFLAGS} -c $<

sstart:
	./${AUTH} ${PORT} ${CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE}

clean:
	rm ${AUTH} ${AUTH_OBJ} $(TEST_CLIENT) $(TEST_CLIENT_OBJ)
