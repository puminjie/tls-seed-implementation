#!/bin/bash
PWD=`pwd`

cd ~/drive/intel-sgx-ssl/Linux
make clean
make && make install
