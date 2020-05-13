include ../buildenv.mk
TIME_LOG ?= 1
SEED_DEBUG ?= 1
SEED_TEST ?= 0

CFG_TEE_TA_LOG_LEVEL=3
CFG_TEE_CORE_LOG_LEVEL=3
CFG_SCTLR_ALIGNMENT_CHECK=n
CFLAGS_ta_arm64=-pg 
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL) -DCFG_SCTLR_ALIGNMENT_CHECK=$(CFG_SCTLR_ALIGNMENT_CHECK)

TRUSTED_DIRECTORY=../../../src/trusted

ifeq ($(TIME_LOG), 1)
	CPPFLAGS += -DTIME_LOG
endif

ifeq ($(SEED_DEBUG), 1)
	CPPFLAGS += -DDEBUG
endif

ifeq ($(SEED_TEST), 1)
	CPPFLAGS += -DTEST
endif

CPPFLAGS += -DTIME_LOG -DPLATFORM_OPTEE -I../include -include ../../../src/logger/seed_names.h

BINARY=4b2f44a9-b840-448f-90a4-170930dffb75
LDADD += -L$(PACKAGE_LIB)/ta -lssl -lcrypto -ltz_ttzssl

include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: $(BINARY).ta

clean: 
	rm -f $(BINARY).* *.o .ta* .user* $(TRUSTED_DIRECTORY)/*.o
