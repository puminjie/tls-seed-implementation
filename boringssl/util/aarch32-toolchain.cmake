set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR "arm")

set(CMAKE_C_COMPILER  /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc)
set(CMAKE_CXX_COMPILER  /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-g++)
set(CMAKE_STRIP  /home/hwlee/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-strip)

set(CMAKE_FIND_ROOT_PATH /home/hwlee/devel/optee/toolchains/aarch32)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY  /home/hwlee/devel/optee/toolchains/aarch32/lib)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE  /home/hwlee/devel/optee/toolchains/aarch32/include)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_FLAGS  "-mno-unaligned-access")
set(CMAKE_STATIC_LINKER_FLAGS  "-static")
