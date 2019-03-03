set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_VERSION 1)
set(CMAKE_SYSTEM_PROCESSOR "aarch64")

set(CMAKE_C_COMPILER /home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER /home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-g++)
set(CMAKE_STRIP /home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-strip)

set(CMAKE_FIND_ROOT_PATH /home/hwlee/devel/rpi/toolchains/aarch64)
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM ONLY)

set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY  /home/hwlee/devel/rpi/toolchains/aarch64/lib)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE  /home/hwlee/devel/rpi/toolchains/aarch64/include)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_FLAGS  "-mno-unaligned-access")
set(CMAKE_STATIC_LINKER_FLAGS  "-static")
