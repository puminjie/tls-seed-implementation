echo "[boringssl] Remove build64"
rm -rf build64

echo "[boringssl] Make build64"
mkdir build64

echo "[boringssl] Enter into build64"
cd build64

echo "[boringssl] Start to generate shared objects"

echo "[boringssl] Execute cmake"
cmake -DCMAKE_TOOLCHAIN_FILE=../util/aarch64-toolchain.cmake  \
-DPERL_EXECUTABLE=/usr/bin/perl -DGO_EXECUTABLE=/usr/bin/go   \
-DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS} -fPIC -DTIME_LOG -DNO_PRINT"                  \
-DCMAKE_C_FLAGS="${CMAKE_C_FLAGS} -fPIC -DTIME_LOG -DNO_PRINT"                      \
-DOPENSSL_NO_THREADS=1 -DBUILD_SHARED_LIBS=1 ..

echo "[boringssl] Copy include files to ec"
cp -rf ../include/openssl/* /home/hwlee/devel/rpi/edge/boringssl/include/openssl

echo "[boringssl] Make"
make

echo "[boringssl] Copy libssl.a to export-ta_arm64"
cp ssl/libssl.so* /home/hwlee/devel/rpi/edge/boringssl/lib64/asm

echo "[boringssl] Copy libcrypto.a to export-ta_arm64"
cp crypto/libcrypto.so* /home/hwlee/devel/rpi/edge/boringssl/lib64/asm

echo "[boringssl] Start to generate static libraries"
rm -rf *

echo "[boringssl] Execute cmake"
cmake -DCMAKE_TOOLCHAIN_FILE=../util/aarch64-toolchain.cmake  \
-DPERL_EXECUTABLE=/usr/bin/perl -DGO_EXECUTABLE=/usr/bin/go   \
-DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS} -fPIC -DTIME_LOG -DNO_PRINT"                  \
-DCMAKE_C_FLAGS="${CMAKE_C_FLAGS} -fPIC -DTIME_LOG -DNO_PRINT"                      \
-DOPENSSL_NO_THREADS=1 -DBUILD_SHARED_LIBS=0 ..

echo "[boringssl] Make"
make

echo "[boringssl] Copy libssl.a to export-ta_arm64"
cp ssl/libssl.a /home/hwlee/devel/rpi/edge/boringssl/lib64/asm

echo "[boringssl] Copy libcrypto.a to export-ta_arm64"
cp crypto/libcrypto.a /home/hwlee/devel/rpi/edge/boringssl/lib64/asm

echo "[boringssl] Delete build_x86_64"
cd ..
rm -rf build_x86_64

echo "[boringssl] Make build_x86_64"
mkdir build_x86_64

echo "[boringssl] Enter into build_x86_64"
cd build_x86_64

echo "[boringssl] Start to generate shared objects for x86_64"
echo "[boringssl] Execute cmake"
cmake -DCMAKE_TOOLCHAIN_FILE=../util/64-bit-toolchain.cmake  \
-DPERL_EXECUTABLE=/usr/bin/perl -DGO_EXECUTABLE=/usr/bin/go   \
-DCMAKE_CXX_FLAGS="-fPIC -DTIME_LOG -DNO_PRINT"                  \
-DCMAKE_C_FLAGS="-fPIC -DTIME_LOG -DNO_PRINT"                      \
-DBUILD_SHARED_LIBS=1 -DOPENSSL_TIMELOG=1 ..

echo "[boringssl] Make"
make

echo "[boringssl] Copy libssl.so and libcrypto.so to git repo"
cp ssl/libssl.so* crypto/libcrypto.so* /home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64/no_debug

echo "[boringssl] Copy include files to git repo"
cd ..
cp include/openssl/* /home/hwlee/devel/rpi/edge/boringssl/include/openssl
