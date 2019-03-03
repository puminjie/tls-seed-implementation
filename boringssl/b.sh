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
-DCMAKE_CXX_FLAGS="${CMAKE_CXX_FLAGS} -fPIC"                  \
-DCMAKE_C_FLAGS="${CMAKE_C_FLAGS} -fPIC"                      \
-DBUILD_SHARED_LIBS=1 ..

echo "[boringssl] Make"
make

echo "[boringssl] Copy libssl.so and libcrypto.so to git repo"
cp ssl/libssl.so* crypto/libcrypto.so* /home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64
