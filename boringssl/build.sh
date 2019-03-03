cd build_x86_64

echo "[boringssl] Make"
make

echo "[boringssl] Copy libssl.so and libcrypto.so to git repo"
cp ssl/libssl.so* crypto/libcrypto.so* /home/hwlee/devel/rpi/edge/boringssl/lib64_x86_64
