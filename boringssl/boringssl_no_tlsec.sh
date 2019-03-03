echo "[boringssl] Delete build_x86_64"
rm -rf build_x86_64

echo "[boringssl] Make build_x86_64"
mkdir build_x86_64

echo "[boringssl] Enter into build_x86_64"
cd build_x86_64

echo "[boringssl] Start to generate shared objects for x86_64"
echo "[boringssl] Execute cmake"
cmake -DCMAKE_TOOLCHAIN_FILE=../util/64-bit-toolchain.cmake  \
-DPERL_EXECUTABLE=/usr/bin/perl -DGO_EXECUTABLE=/usr/bin/go   \
-DCMAKE_CXX_FLAGS="-DOPENSSL_NO_TLSEC -fPIC -DTIME_LOG -DNO_PRINT"                  \
-DCMAKE_C_FLAGS="-DOPENSSL_NO_TLSEC -fPIC -DTIME_LOG -DNO_PRINT"                      \
-DBUILD_SHARED_LIBS=1 -DOPENSSL_TIMELOG=1 ..

echo "[boringssl] Make"
make

echo "[boringssl] Copy libssl.so and libcrypto.so to git repo"
cp ssl/libssl.so* crypto/libcrypto.so* /home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64/no_tlsec

echo "[boringssl] Copy include files to git repo"
cd ..
cp include/openssl/* /home/hwlee/devel/rpi/edge/boringssl/include/openssl

