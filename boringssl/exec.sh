echo "[boringssl] Remove build64"
rm -rf build64

echo "[boringssl] Make build64"
mkdir build64

echo "[boringssl] Enter into build64"
cd build64

echo "[boringssl] Execute cmake"
cmake -DCMAKE_TOOLCHAIN_FILE=../util/aarch64-toolchain.cmake  \
-DPERL_EXECUTABLE=/usr/bin/perl -DGO_EXECUTABLE=/usr/bin/go   \
-DOPENSSL_NO_ASM=1 -DOPENSSL_NO_THREADS=1

echo "[boringssl] Make"
make

echo "[boringssl] Copy libssl.a to export-ta_arm64"
cp ssl/libssl.a /home/hwlee/devel/rpi/optee_os/out/arm/export-ta_arm64/lib

echo "[boringssl] Copy libcrypto.a to export-ta_arm64"
cp crypto/libcrypto.a /home/hwlee/devel/rpi/optee_os/out/arm/export-ta_arm64/lib
