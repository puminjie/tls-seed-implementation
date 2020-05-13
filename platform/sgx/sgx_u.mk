#
# Copyright (C) 2011-2017 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#



######## SGX SDK Settings ########
SGX_MODE ?= HW
SGX_ARCH ?= x64
TIME_LOG ?= 1
SEED_DEBUG ?= 1
COMMON_DIR=$(ROOT)/src/common
COMMON_INC=$(ROOT)/include
COMMON_LIB=$(ROOT)/lib
UNTRUSTED_INC=$(ROOT)/platform/include/untrusted
UNTRUSTED_DIR=untrusted
UNTRUSTED_COMMON_DIR=$(ROOT)/src/untrusted
LOGGER_DIR=$(ROOT)/src/logger

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	ifeq ($(LINUX_SGX_BUILD), 1)
		include ../../../../../buildenv.mk
		SGX_LIBRARY_PATH := $(BUILD_DIR)
		SGX_EDGER8R := $(BUILD_DIR)/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
		SGX_SSL_INC := $(ROOT)/include
		SGX_SHARED_LIB_FLAG := -Wl,-rpath,${SGX_LIBRARY_PATH}
	else
		SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
		SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
		SGX_SDK_INC := $(SGX_SDK)/include
		SGX_SSL_INC := $(ROOT)/include
	endif
endif

ifeq ($(DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

OPENSSL_LIBRARY_PATH := $(SGX_SSL)/lib64
ifeq ($(DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
		SgxSSL_Link_Libraries := sgx_usgxssld
else
        SGX_COMMON_CFLAGS += -O2 -D_FORTIFY_SOURCE=2
		SgxSSL_Link_Libraries := sgx_usgxssl
endif


######## App Settings ########


App_C_Files := $(wildcard $(COMMON_DIR)/*.c $(UNTRUSTED_COMMON_DIR)/*.c $(UNTRUSTED_DIR)/*.c)

ifeq ($(TIME_LOG), 1)
	App_C_Files += $(LOGGER_DIR)/*.c
endif

App_C_Objects := $(App_C_Files:.c=.o)

App_Include_Paths := -I$(SGX_SDK_INC) -I$(SGX_SSL_INC) -I$(PACKAGE_INC) -I$(ROOT_INC) -I$(COMMON_INC) -I$(UNTRUSTED_INC)

App_C_Flags := $(SGX_COMMON_CFLAGS) -fpic -fpie -fstack-protector -Wformat -Wformat-security -Wno-attributes $(App_Include_Paths) -DPLATFORM_SGX -include ../../src/logger/seed_names.h

ifeq ($(TIME_LOG), 1)
	App_C_Flags += -DTIME_LOG
endif

ifeq ($(SEED_DEBUG), 1)
	App_C_Flags += -DDEBUG
endif

App_C_Flags += -DPLATFORM_SGX

App_Cpp_Flags := $(App_C_Flags) -std=c++11

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
	UaeService_Library_Name := sgx_uae_service_sim
else
	Urts_Library_Name := sgx_urts
	UaeService_Library_Name := sgx_uae_service
endif


Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie

App_Link_Flags := $(SGX_COMMON_CFLAGS) $(Security_Link_Flags) $(SGX_SHARED_LIB_FLAG) -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -l$(UaeService_Library_Name) -L$(OPENSSL_LIBRARY_PATH) -l$(SgxSSL_Link_Libraries) -lpthread -levent -L$(COMMON_LIB) -lssl -lcrypto -lsimple_http -L$(PACKAGE_LIB)


.PHONY: all test

all: sgx_seed

edge: all
	@echo "Compile SGX-based edge"
	@echo "RUN  =>  sgx_edge [$(SGX_MODE)|$(SGX_ARCH), OK]"

######## App Objects ########

$(UNTRUSTED_DIR)/enclave_u.c: $(SGX_EDGER8R) trusted/enclave.edl
	@cd $(UNTRUSTED_DIR) && $(SGX_EDGER8R) --untrusted ../trusted/enclave.edl --search-path $(PACKAGE_INC) --search-path $(SGX_SDK_INC) --search-path $(SGX_SSL_INC)
	@echo "GEN  =>  $@"

$(UNTRUSTED_DIR)/enclave_u.o: $(UNTRUSTED_DIR)/enclave_u.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

$(UNTRUSTED_DIR)/%.o: $(UNTRUSTED_DIR)/%.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(LOGGER_DIR)/%.o: $(LOGGER_DIR)/%.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(UNTRUSTED_COMMON_DIR)/%.o: $(UNTRUSTED_COMMON_DIR)/%.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

$(COMMON_DIR)/%.o: $(COMMON_DIR)/%.c
	$(VCC) $(App_C_Flags) -c $< -o $@
	@echo "CC  <=  $<"

sgx_seed: $(UNTRUSTED_DIR)/enclave_u.o $(App_C_Objects)
	$(VCC) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"


.PHONY: clean

clean:
	@rm -f sgx_seed  $(App_C_Objects) $(UNTRUSTED_DIR)/enclave_u.* 
	
