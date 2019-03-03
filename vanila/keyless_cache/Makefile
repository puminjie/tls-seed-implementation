CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

GCC=$(CROSS_COMPILE)gcc

KEYLESS_SSL_CACHE=keyless_ssl_cache
KEYLESS_SSL_CACHE_SRC=keyless_ssl_cache.c keyless.c keyless_kssl_helpers.c keyless_kssl_log.c
KEYLESS_SSL_CACHE_OBJ=keyless_ssl_cache.o keyless.o keyless_kssl_helpers.o keyless_kssl_log.o

BINS=${KEYLESS_SSL_CACHE}
OBJS=${KEYLESS_SSL_CACHE_OBJ}

CFLAGS=-DKEYLESS_SSL -DTIME_LOG -DNO_PRINT -I/home/hwlee/devel/rpi/edge/boringssl/include
#CFLAGS=-DDEBUG -DKEYLESS_SSL -DTIME_LOG -I/home/hwlee/devel/rpi/edge/boringssl/include

LDFLAGS=-L/home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64 -lcrypto -lssl -ldl -lpthread
GDB=gdb

HOST=www.bob.com
PORT=5555
NUM_OF_THREADS=1

all: keyless_ssl_cache

keyless_ssl_cache: ${KEYLESS_SSL_CACHE_OBJ}
	${GCC} -o ${KEYLESS_SSL_CACHE} ${KEYLESS_SSL_CACHE_OBJ} ${LDFLAGS}

keyless_ssl_cache.o: ${KEYLESS_SSL_CACHE_SRC}
	${GCC} ${FLAGS} ${CFLAGS} -c $<

clean:
	rm ${BINS} ${OBJS}
