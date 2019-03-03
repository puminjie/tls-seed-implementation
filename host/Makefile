CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf

OBJS = debug.o init.o session.o hio.o ec_func.o file_io_manager.o

BASE = edge_cache.o
ONE = edge_cache_1.o

CFLAGS += -DTEST -DTIME_LOG -DNO_PRINT -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I$(NORMAL_ROOT)/usr/include
#CFLAGS += -DDEBUG -DTEST -DTIME_LOG -Wall -I../ta/include -I$(TEEC_EXPORT)/include -I$(NORMAL_ROOT)/usr/include
LDADD += -L$(TEEC_EXPORT)/lib -lteec -L$(NORMAL_ROOT)/usr/lib -lssl -lcrypto -lpthread

.PHONY: all
all: edge_cache

edge_cache: $(OBJS) $(BASE)
	$(CC) $(LDADD) -o $@ $(BASE) $(OBJS)

one: $(OBJS) $(ONE)
	$(CC) $(LDADD) -o $@ $(ONE) $(OBJS)

.PHONY: clean
clean:
	rm -f $(OBJS) edge_cache
