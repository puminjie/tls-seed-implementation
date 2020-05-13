ARCH ?= aarch64
DEBUG ?= 0
ROOT := /home/hwlee/devel/rpi
OPTEE_INC := $(ROOT)/optee_os/out/arm/export-ta_arm64/include
OPTEE_LIB := $(ROOT)/optee_os/out/arm/export-ta_arm64/lib
TEEC_EXPORT := $(ROOT)/optee_client/out/export
NORMAL_ROOT := $(ROOT)/out-br/target

ifeq ($(ARCH), aarch64)
	CROSS_COMPILE=$(ROOT)/toolchains/aarch64/bin/aarch64-linux-gnu-
else
	CROSS_COMPILE=$(ROOT)/toolchains/aarch32/bin/arm-linux-gnueabihf-
endif

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
AR := $(CROSS_COMPILE)ar
NM := $(CROSS_COMPILE)nm
OBJCOPY := $(CROSS_COMPILE)objcopy
OBJDUMP := $(CROSS_COMPILE)objdump
READELF := $(CROSS_COMPILE)readelf
RM := rm

PACKAGE_LIB := ../lib
TRUSTED_LIB := libtz_ttzssl.a

ifeq ($(DEBUG), 1)
	CFLAGS += -O0 -g -DDEBUG
else
	CFLAGS += -O2
endif

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)

CFLAGS += -I$(ROOT)/edge-libevent/include -I$(ROOT)/optee_os/out/arm/export-ta_arm64/include

all: $(TRUSTED_LIB)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TRUSTED_LIB): $(OBJS)
	$(AR) rcs $(TRUSTED_LIB) $(OBJS)
	mv $@ $(PACKAGE_LIB)/$(TRUSTED_LIB)

install: $(PACKAGE_LIB)/$(TRUSTED_LIB)
	cp $(PACKAGE_LIB)/$(TRUSTED_LIB) $(OPTEE_LIB)

clean:
	$(RM) $(PACKAGE_LIB)/$(TRUSTED_LIB) $(OBJS)
