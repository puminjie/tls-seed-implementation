#!/bin/bash

export CROSS_COMPILE=/home/hwlee/devel/rpi/toolchains/aarch64/bin/aarch64-linux-gnu-
export ARCH=aarch64

cd ~/drive/openssl-1.1.1-stable
make clean
#cp Makefile.aarch64 Makefile
./Configure linux-aarch64 --cross-compile-prefix=${CROSS_COMPILE} --prefix=/home/hwlee/drive/openssl-1.1.1-aarch64 -fPIC -DOPENSSL_NO_SOCK -DOPENSSL_NO_DGRAM -DOPENSSL_NO_UI_CONSOLE -mcpu=cortex-a73.cortex-a53+crypto -mtune=cortex-a73.cortex-a53 -march=armv8-a+crc+simd+crypto no-threads no-cms no-dsa no-filenames no-rdrand -DOPENSSL_SMALL_FOOTPRINT no-err no-dso -fdata-sections -ffunction-sections -Wl,--gc-sections -Os -include /home/hwlee/devel/rpi/edge-libevent/include/debug.h -include /home/hwlee/devel/rpi/edge-libevent/src/logger/seed_names.h -include /home/hwlee/devel/rpi/edge-libevent/src/logger/seed_flags.h -DTIME_LOG no-shared no-aria no-bf no-blake2 no-camellia no-cast no-comp no-md2 no-md4 no-seed no-rc2 no-rc4 no-rc5 no-ripemd no-srp no-sm2 no-sm3 no-sm4 no-idea no-mdc2 no-siphash no-ec2m no-dtls no-dtls1 no-tls1 no-egd no-nextprotoneg no-weak-ssl-ciphers -DOPENSSL_USE_IPV6=0 no-ssl2 no-ssl3 -DTZSSL
make depend
make -j5 && make install_sw
cd ~/drive/openssl-1.1.1-aarch64/lib
cp * ~/devel/rpi/edge-libevent/platform/tz/lib/ta
cd ~/drive/openssl-1.1.1-aarch64/include
cp openssl/* ~/devel/rpi/edge-libevent/platform/tz/include/openssl
