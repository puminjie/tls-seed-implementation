include ../../src/common/buildenv.mk

ARCH ?= X86_64
PLATFORM ?= VANILA
TIME_LOG ?= 1
DEBUG ?= 1

ifeq ($(ARCH), AARCH64)
	CROSS_COMPILE := $(AARCH64_COMPILER_PREFIX)
endif

CC      = $(CROSS_COMPILE)gcc
LD      = $(CROSS_COMPILE)ld
AR      = $(CROSS_COMPILE)ar
NM      = $(CROSS_COMPILE)nm
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
READELF = $(CROSS_COMPILE)readelf
RM			= rm

BIN=seed
LOGGER_OBJS=../../src/logger/seed_logger.o

PWD= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

CFLAGS = $(COMMON_CFLAGS)
ifeq ($(TIME_LOG), 1)
	CFLAGS += -DTIME_LOG -include $(ROOT_DIR)/src/logger/seed_names.h -include $(ROOT_DIR)/src/logger/seed_logger.h -include $(ROOT_DIR)/src/logger/seed_flags.h
endif

ifeq ($(DEBUG), 1)
	CFLAGS += -DDEBUG
endif

ifeq ($(PLATFORM), VANILA)
	CFLAGS += -DPLATFORM_VANILA
endif 

ifeq ($(PLATFORM), OPTEE)
	CFLAGS += -DPLATFORM_OPTEE
endif

ifeq ($(PLATFORM), SGX)
	CFLAGS += -DPLATFORM_SGX
endif

ifeq ($(ARCH), X86_64)
ifeq ($(DEBUG), 1)
	LDFLAGS = -L../../lib
else
	LDFLAGS = -L../../lib
endif
endif

ifeq ($(ARCH), AARCH64)
	LDFLAGS = -L../tz/lib/host
endif

LDFLAGS += $(COMMON_LDFLAGS)
ifeq ($(ARCH), X86_64)
	LDFLAGS += -ldl -lpthread
endif

ifeq ($(ARCH), AARCH64)
	LDFLAGS += -lpthread
endif

all: seed

seed: $(COMMON_OBJS) $(LOGGER_OBJS)
	$(CC) -o $(BIN) $(COMMON_OBJS) $(LOGGER_OBJS) $(LDFLAGS)

.c.o:
	$(CC) $(FLAGS) $(CFLAGS) -c $< -o $@

clean:
	$(RM) $(BIN) $(COMMON_OBJS) $(LOGGER_OBJS)
