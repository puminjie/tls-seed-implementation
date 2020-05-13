#!/bin/bash

cp Makefile.x86_64 ~/drive/openssl-1.1.1-stable
cd ~/drive/openssl-1.1.1-stable
./config --prefix=/home/hwlee/drive/openssl-1.1.1-x86_64 no-dso -include /home/hwlee/devel/rpi/edge-libevent/include/debug.h -include /home/hwlee/devel/rpi/edge-libevent/src/logger/seed_names.h -include /home/hwlee/devel/rpi/edge-libevent/src/logger/seed_flags.h -DTIME_LOG
make clean
cp Makefile.x86_64 Makefile
make && make install_sw
cd ~/drive/openssl-1.1.1-x86_64/lib
cp * ~/devel/rpi/edge-libevent/lib
cd ~/drive/openssl-1.1.1-x86_64/include
cp openssl/* ~/devel/rpi/edge-libevent/include/openssl
