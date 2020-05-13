#ifndef __KEYLESS_SSL_H__
#define __KEYLESS_SSL_H__

#include "kssl.h"
#include "keyless_kssl_helpers.h"
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#define ALGS_COUNT 6
#define CA_PATH "www.bob.com/ca.pem"
#define CERT_PATH "www.bob.com/cert.pem"
#define KEY_PATH "www.bob.com/priv.pem"
#define PUBKEY_PATH "www.bob.com/pubkey.pem"

// RSA signing algorithm opcodes
static int rsa_algs[ALGS_COUNT] = {
  KSSL_OP_RSA_SIGN_MD5SHA1,
  KSSL_OP_RSA_SIGN_SHA1,
  KSSL_OP_RSA_SIGN_SHA224,
  KSSL_OP_RSA_SIGN_SHA256,
  KSSL_OP_RSA_SIGN_SHA384,
  KSSL_OP_RSA_SIGN_SHA512,
};

// ECDSA signing algorithm opcodes
static int ecdsa_algs[ALGS_COUNT] = {
  KSSL_OP_ECDSA_SIGN_MD5SHA1,
  KSSL_OP_ECDSA_SIGN_SHA1,
  KSSL_OP_ECDSA_SIGN_SHA224,
  KSSL_OP_ECDSA_SIGN_SHA256,
  KSSL_OP_ECDSA_SIGN_SHA384,
  KSSL_OP_ECDSA_SIGN_SHA512,
};

// OpenSSL digest NIDs 
static int nid[ALGS_COUNT] = {
  NID_md5_sha1,
  NID_sha1,
  NID_sha224,
  NID_sha256,
  NID_sha384,
  NID_sha512,
};

typedef struct {
  SSL *ssl;
  int fd;
} connection;

void digest_public_ec(EC_KEY *ec_key, BYTE *digest);
void ssl_error(void);
void fatal_error(const char *fmt, ...);
void digest_public_rsa(RSA *key, BYTE *digest);
void ok(kssl_header *h);
kssl_header *kssl(SSL *ssl, kssl_header *k, kssl_operation *r);
int kssl_op_rsa_decrypt(connection *c, int flen, unsigned char *from,
			unsigned char *to, RSA *rsa_pubkey);
void kssl_op_ecdsa_sign(connection *c, BYTE *in, int ilen, uint8_t * out, size_t *olen, 
    int opcode);
connection *ssl_connect(SSL_CTX *ctx, const char *domain, int port);
void ssl_disconnect(connection *c);

#endif /* __KEYLESS_SSL_H__ */
