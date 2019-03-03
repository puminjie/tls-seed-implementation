CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

CERT_FILE=orig_ecc_256_cert.der
CA_CERT_FILE=ca_ecc_alice.pem
KEY_FILE=orig_ecc_256_priv.der

GCC=gcc

CLIENT=client
VANILA=vanila
SERVER=server
CLIENT_SRC=client.c
CLIENT_OBJ=client.o
VANILA_SRC=vanila.c
VANILA_OBJ=vanila.o
SERVER_SRC=server.c
SERVER_OBJ=server.o

BINS=${CLIENT} ${SERVER} ${VANILA} ${VANILA_CACHE}
OBJS=${CLIENT_OBJ} ${SERVER_OBJ} ${VANILA_OBJ} ${VANILA_CACHE_OBJ}

#CFLAGS=-DTIME_LOG -DNO_PRINT -I/home/hwlee/devel/rpi/edge/boringssl/include
CFLAGS=-DDEBUG -DTIME_LOG -I/home/hwlee/devel/rpi/edge/boringssl/include

LDFLAGS=-L/home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64 -lcrypto -lssl -ldl -lpthread
GDB=gdb

HOST=www.bob.com
PORT=5555
NUM_OF_THREADS=1

all: client server vanila 

client: ${CLIENT_OBJ}
	${GCC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

vanila: ${VANILA_OBJ}
	${GCC} -o ${VANILA} ${VANILA_OBJ} ${LDFLAGS}

server: ${SERVER_OBJ}
	${GCC} -o ${SERVER} ${SERVER_OBJ} ${LDFLAGS}

client.o: ${CLIENT_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

vanila.o: ${VANILA_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

vanila_cache.o: ${VANILA_CACHE_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

server.o: ${SERVER_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

cstart:
	./${CLIENT} ${HOST} ${PORT} ${NUM_OF_THREADS} ${LOG_FILE}

sstart:
	./${SERVER} ${PORT} ${LABEL}

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${BINS} ${OBJS}
