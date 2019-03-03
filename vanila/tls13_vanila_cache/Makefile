CC      = gcc
LD      = ld
AR      = ar
NM      = nm
OBJCOPY = objcopy
OBJDUMP = objdump
READELF = readelf

GCC=gcc

VANILA_CACHE=vanila_cache
VANILA_CACHE_SRC=vanila_cache.c cc_client_func.c cc_func.c
VANILA_CACHE_OBJ=vanila_cache.o cc_client_func.o cc_func.o

BINS=${VANILA_CACHE}
OBJS=${VANILA_CACHE_OBJ}

#CFLAGS=-DTIME_LOG -DNO_PRINT -I/home/hwlee/devel/rpi/edge/boringssl/include
CFLAGS=-DTLS13 -DTIME_LOG -I/home/hwlee/devel/rpi/edge/boringssl/include

LDFLAGS=-L/home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64 -lcrypto -lssl -ldl -lpthread
GDB=gdb

HOST=www.bob.com
PORT=5555
NUM_OF_THREADS=1

all: vanila_cache

vanila_cache: ${VANILA_CACHE_OBJ}
	${GCC} -o ${VANILA_CACHE} ${VANILA_CACHE_OBJ} ${LDFLAGS}

vanila_cache.o: ${VANILA_CACHE_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

clean:
	rm ${BINS} ${OBJS}
