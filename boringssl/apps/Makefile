CERT_FILE=alice_ecc_256_cert.crt
CA_CERT_FILE=ca_ecc_alice.pem
KEY_FILE=alice_ecc_256_priv.key

GCC=gcc

CLIENT=client
SERVER=server
CLIENT_SRC=client.c
CLIENT_OBJ=client.o
SERVER_SRC=server.c
SERVER_OBJ=server.o

BINS=${CLIENT} ${SERVER}
OBJS=${CLIENT_OBJ} ${SERVER_OBJ}

CFLAGS=-DDEBUG -DLOGGER -I/home/hwlee/devel/rpi/edge/boringssl/include
LDFLAGS=-L/home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64 -lcrypto -lssl -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=5555
NUM_OF_THREADS=1

all: client server

client: ${CLIENT_OBJ}
	${GCC} -o ${CLIENT} ${CLIENT_OBJ} ${LDFLAGS}

server: ${SERVER_OBJ}
	${GCC} -o ${SERVER} ${SERVER_OBJ} ${LDFLAGS}

client.o: ${CLIENT_SRC}
	${GCC} ${CFLAGS} -c $<

server.o: ${SERVER_SRC}
	${GCC} ${CFLAGS} -c $<

cstart:
	./${CLIENT} ${HOST} ${PORT} ${NUM_OF_THREADS} ${LOG_FILE}

sstart:
	./${SERVER} ${PORT}


debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${BINS} ${OBJS}
