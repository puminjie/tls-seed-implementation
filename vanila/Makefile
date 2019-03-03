CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

VANILA=vanila_cache
VANILA_SRC=vanila_cache.c
VANILA_OBJ=vanila_cache.o

SPLITTLS12_CACHE=splittls12_cache
SPLITTLS12_CACHE_SRC=splittls12_cache.c cc_client_func.c cc_func.c
SPLITTLS12_CACHE_OBJ=splittls12_cache.o cc_client_func.o cc_func.o

SPLITTLS13_CACHE=splittls13_cache
SPLITTLS13_CACHE_SRC=splittls13_cache.c cc_client_func.c cc_func.c
SPLITTLS13_CACHE_OBJ=splittls13_cache.o cc_client_func.o cc_func.o

KEYLESS12_SSL_CACHE=keyless12_ssl_cache
KEYLESS12_SSL_CACHE_SRC=keyless12_ssl_cache.c keyless.c keyless_kssl_helpers.c keyless_kssl_log.c
KEYLESS12_SSL_CACHE_OBJ=keyless12_ssl_cache.o keyless.o keyless_kssl_helpers.o keyless_kssl_log.o

KEYLESS13_SSL_CACHE=keyless13_ssl_cache
KEYLESS13_SSL_CACHE_SRC=keyless13_ssl_cache.c keyless.c keyless_kssl_helpers.c keyless_kssl_log.c
KEYLESS13_SSL_CACHE_OBJ=keyless13_ssl_cache.o keyless.o keyless_kssl_helpers.o keyless_kssl_log.o

TLSSEC_WO_TZ_CACHE=tlssec_wo_tz_cache
TLSSEC_WO_TZ_CACHE_SRC=tlssec_wo_tz_cache.c cc_client_func.c cc_func.c
TLSSEC_WO_TZ_CACHE_OBJ=tlssec_wo_tz_cache.o cc_client_func.o cc_func.o

BINS=${VANILA} ${KEYLESS_SSL_CACHE}
OBJS=${VANILA_OBJ} ${KEYLESS_SSL_CACHE_OBJ}

#CFLAGS=-I/home/hwlee/devel/rpi/edge/boringssl/include
CFLAGS=-DTIME_LOG -DNO_PRINT -I/home/hwlee/devel/rpi/edge/boringssl/include
#CFLAGS=-DNO_CACHE -DTIME_LOG -DNO_PRINT -I/home/hwlee/devel/rpi/edge/boringssl/include
#CFLAGS=-DDEBUG -DTIME_LOG -DNO_PRINT -I/home/hwlee/devel/rpi/edge/boringssl/include
#CFLAGS=-DDEBUG -DNO_CACHE -DNO_PRINT -DTIME_LOG -I/home/hwlee/devel/rpi/edge/boringssl/include
LDFLAGS=-L/home/hwlee/devel/rpi/edge/boringssl/lib64 -lcrypto -lssl -ldl -lpthread
GDB=gdb

HOST=127.0.0.1
PORT=5555
NUM_OF_THREADS=1

all: vanila_cache splittls12_cache splittls13_cache tlssec_wo_tz_cache keyless12_ssl_cache keyless13_ssl_cache

vanila_cache: ${VANILA_OBJ}
	${CC} -o ${VANILA} ${VANILA_OBJ} ${LDFLAGS}

vanila_cache.o: ${VANILA_SRC}
	${CC} ${CFLAGS} -c $<

splittls12_cache: ${SPLITTLS12_CACHE_OBJ}
	${CC} -o ${SPLITTLS12_CACHE} ${SPLITTLS12_CACHE_OBJ} ${LDFLAGS}

splittls12_cache.o: ${SPLITTLS12_CACHE_SRC}
	${CC} ${CFLAGS} -c $<

splittls13_cache: ${SPLITTLS13_CACHE_OBJ}
	${CC} -o ${SPLITTLS13_CACHE} ${SPLITTLS13_CACHE_OBJ} ${LDFLAGS}

splittls13_cache.o: ${SPLITTLS13_CACHE_SRC}
	${CC} ${CFLAGS} -DTLS13 -c $<

tlssec_wo_tz_cache: ${TLSSEC_WO_TZ_CACHE_OBJ}
	${CC} -o ${TLSSEC_WO_TZ_CACHE} ${TLSSEC_WO_TZ_CACHE_OBJ} ${LDFLAGS}

tlssec_wo_tz_cache.o: tlssec_wo_tz_cache.c
	${CC} ${CFLAGS} -DTLS13 -DTLS_SEC -c $<

keyless12_ssl_cache: ${KEYLESS12_SSL_CACHE_OBJ}
	${CC} -o ${KEYLESS12_SSL_CACHE} ${KEYLESS12_SSL_CACHE_OBJ} ${LDFLAGS}

keyless12_ssl_cache.o: keyless12_ssl_cache.c
	${CC} ${CFLAGS} -DKEYLESS_SSL -c $<

keyless13_ssl_cache: ${KEYLESS13_SSL_CACHE_OBJ}
	${CC} -o ${KEYLESS13_SSL_CACHE} ${KEYLESS13_SSL_CACHE_OBJ} ${LDFLAGS}

keyless13_ssl_cache.o: keyless13_ssl_cache.c 
	${CC} ${CFLAGS} -DKEYLESS_SSL -DTLS13 -c $<

keyless.o: keyless.c
	${CC} ${CFLAGS} -c $<

keyless_kssl_helpers.o: keyless_kssl_helpers.c
	${CC} ${CFLAGS} -c $<

keyless_kssl_log.o: keyless_kssl_log.c
	${CC} ${CFLAGS} -c $<

cc_func.o: cc_func.c
	${CC} ${CFLAGS} -c $<

cc_client_func.o: cc_client_func.c
	${CC} ${CFLAGS} -c $<

sstart:
	./${VANILA} ${PORT} 

debug:
	${GDB} ./${EXEC} ${PORT} ${CERT_FILE} ${CA_CERT_FILE} ${KEY_FILE} ${ORIG_CERT_FILE} ${WARRANT_FILE} -tui

clean:
	rm ${VANILA} ${VANILA_OBJ} ${SPLITTLS12_CACHE} ${SPLITTLS12_CACHE_OBJ} ${SPLITTLS13_CACHE} ${SPLITTLS13_CACHE_OBJ} ${KEYLESS12_SSL_CACHE} ${KEYLESS12_SSL_CACHE_OBJ} ${KEYLESS13_SSL_CACHE} ${KEYLESS13_SSL_CACHE_OBJ} ${TLSSEC_WO_TZ_CACHE} ${TLSSEC_WO_TZ_CACHE_OBJ}
