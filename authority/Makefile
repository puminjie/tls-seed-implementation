CERT_FILE=carol_cert.pem
CA_CERT_FILE=ca_carol.pem
KEY_FILE=carol_priv.key
ORIG_CERT_FILE=orig_ecc_256_cert.der

GCC=gcc
CFLAGS=-DDEBUG -I/home/hwlee/devel/rpi/edge/boringssl/include
LDFLAGS=-L/home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64 -lssl -lcrypto -ldl -lpthread

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
	rm ${AUTH} ${AUTH_OBJ}
