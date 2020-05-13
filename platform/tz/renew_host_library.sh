#!/bin/bash

export CROSS_COMPILE=/home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-
export ARCH=aarch64

cd ~/drive/openssl-1.1.1-stable
make clean
./Configure linux-aarch64 --cross-compile-prefix=${CROSS_COMPILE} --prefix=/home/hwlee/drive/openssl-1.1.1-host-aarch64 -fPIC -mcpu=cortex-a73.cortex-a53+crypto -mtune=cortex-a73.cortex-a53 -march=armv8-a+crc+simd+crypto no-dso -include /home/hwlee/devel/rpi/edge-libevent/include/debug.h -include /home/hwlee/devel/rpi/edge-libevent/src/logger/seed_names.h -include /home/hwlee/devel/rpi/edge-libevent/src/logger/seed_flags.h -DTIME_LOG
make depend
make -j5 && make install_sw
cd ~/drive/openssl-1.1.1-host-aarch64/lib
cp * ~/devel/rpi/edge-libevent/platform/tz/lib/host
