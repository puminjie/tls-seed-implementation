#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/aes.h>
#include <openssl/ecdsa.h>
#include <openssl/logs.h>

#define BUF_SIZE 16384
#define MAX_BLOCK_SIZE 128

static const unsigned char key[32] = {
  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
  0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0
};

unsigned int get_current_millis()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return ((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
}

int main()
{
  int i, ret, len;
  unsigned char *buf = NULL;
  unsigned char iv[2 * MAX_BLOCK_SIZE / 8];
  unsigned int start, end;
  unsigned char ciph[BUF_SIZE];
  memset(iv, 0x0, sizeof(iv));

  AES_KEY aes_ks;
  AES_set_encrypt_key(key, 256, &aes_ks);

  buf = (unsigned char *)malloc(BUF_SIZE);
  memset(buf, 0x0, BUF_SIZE);

  for (i=0; i<10; i++)
  {
    start = get_current_millis();
    AES_cbc_encrypt(buf, buf, BUF_SIZE, &aes_ks, iv, AES_ENCRYPT);
    end = get_current_millis();
    printf("%dth trial: %u ms\n", i, end - start);
  }

  for (i=0; i<10; i++)
  {
    EVP_CIPHER_CTX *ctx;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    start = get_current_millis();
    EVP_EncryptUpdate(ctx, ciph, &len, buf, BUF_SIZE);
    end = get_current_millis();
    EVP_EncryptFinal_ex(ctx, ciph + len, &len);
    EVP_CIPHER_CTX_free(ctx);
    printf("%dth trial: %u ms\n", i, end - start);
  }

  unsigned char ecdsasig[256];
  unsigned int ecdsasiglen;
  EC_KEY *ecdsa;
  long ecdsa_c[2];
  ecdsa = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  for (i=0; i<10; i++)
  {
    start = get_current_millis();
    ret = ECDSA_sign(0, buf, 20, ecdsasig, &ecdsasiglen, ecdsa);
    end = get_current_millis();
    printf("%dth trial (ret: %d): %u ms\n", i, ret, end - start);
  }

  EC_KEY_free(ecdsa);
  free(buf);

  return 0;
}
