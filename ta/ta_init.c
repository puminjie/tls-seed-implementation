#include "ta_init.h"
#include "ta_edge_cache.h"
//#include "log_client.h"
#include "keypair.h"
#include "ta_tls_context_ops.h"
#include "ta_software_assertion.h"
#include "test_message.h"

TEE_Result init_tls_manager(struct tls_manager_st **mngr, struct file_manager_st *fmngr, 
    int role)
{
  EDGE_LOG("Start: init_tls_manager: mngr: %p, fmngr: %p, role: %d", mngr, fmngr, role);

  uint8_t *buf;
  uint16_t ht;
  uint32_t len;

  (*mngr) = (struct tls_manager_st *)malloc(sizeof(struct tls_manager_st));
  if (!(*mngr)) goto err;
  memset((*mngr), 0x0, sizeof(struct tls_manager_st));

  if (role == TA_FRONTEND_MANAGER)
    (*mngr)->cops = &frontend_ops;
  else if (role == TA_BACKEND_MANAGER)
    (*mngr)->cops = &backend_ops;

  (*mngr)->tops = &tbl_ops;
  (*mngr)->ctx = (*mngr)->cops->init_ctx(fmngr);
  if (!((*mngr)->ctx)) goto err;

  buf = (uint8_t *)malloc(EVP_MAX_MD_SIZE);
  if (!buf) goto err;

  get_ec_digest(buf, &ht, &len);
  (*mngr)->ec_digest = buf;
  (*mngr)->ht = ht;
  (*mngr)->len = len;

  (*mngr)->tops->init_tls_context_table(&((*mngr)->tbl), (*mngr));
  (*mngr)->fmngr = fmngr;

  return TEE_SUCCESS;

err:
  if (*mngr)
  {
    if ((*mngr)->ec_digest) free((*mngr)->ec_digest);
    buf = NULL;
    if ((*mngr)->ctx) SSL_CTX_free((*mngr)->ctx);
    (*mngr)->ctx = NULL;
    free(*mngr);
    (*mngr) = NULL;
  }

  return TEE_ERROR_OUT_OF_MEMORY;
}

void init_test(void *tlog)
{
  log_t *time_log = (log_t *)tlog;
  RECORD_LOG(time_log, SW_0);
  EVP_PKEY *priv, *pub;
  const uint8_t msg[] = "Test String for TrustZone I/O";
  const uint8_t *sig;
  const uint8_t key[32] = "01234567890123456789012345678901";
  const uint8_t iv[16] = "0123456789012345";
  const uint8_t plain[16384];
  const uint8_t ciph[16384];
  size_t privlen, crtlen;
  uint32_t len, mlen, slen, plen, clen;
  uint32_t ret1, ret2, ret3, ret4, ret5, ret6, ret7, ret8, ret9, ret10;
  mlen = strlen(msg);
  len = 0; slen = 0; plen = 0; clen = 0;
  privlen = sizeof(pbuf);
  crtlen = sizeof(cbuf);

  SSL_CTX *sctx;
  SSL *ssl;
  sctx = SSL_CTX_new(TLSv1_2_server_method());

  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, sctx, pbuf, privlen) != 1)
  {
    EDGE_LOG("Error in loading private key");
  }

  if (SSL_CTX_use_certificate_ASN1(sctx, crtlen, cbuf) != 1)
  {
    EDGE_LOG("Error in loading cert");
  }

  if (SSL_CTX_check_private_key(sctx) != 1)
  {
    EDGE_LOG("Error in keypair");
		return TEE_ERROR_BAD_PARAMETERS;
  }

  priv = SSL_CTX_get0_privatekey(sctx);
  pub = X509_get_pubkey(SSL_CTX_get0_certificate(sctx));

  RECORD_LOG(time_log, SW_1);
  // ECC Signature Operation
  EVP_MD_CTX *ctx1;
  ctx1 = EVP_MD_CTX_create();
  EVP_DigestSignInit(ctx1, NULL, EVP_sha256(), NULL, priv);
  EVP_DigestSignUpdate(ctx1, msg, mlen);
  EVP_DigestSignFinal(ctx1, NULL, &slen);
  sig = OPENSSL_malloc(sizeof(unsigned char) * slen);
  ret1 = EVP_DigestSignFinal(ctx1, sig, &slen);
  EVP_MD_CTX_free(ctx1);

  RECORD_LOG(time_log, SW_2);
  // ECC Verification Operation
  EVP_MD_CTX *ctx2;
  ctx2 = EVP_MD_CTX_create();
  EVP_DigestVerifyInit(ctx2, NULL, EVP_sha256(), NULL, pub);
  EVP_DigestVerifyUpdate(ctx2, msg, mlen);
  ret2 = EVP_DigestVerifyFinal(ctx2, sig, slen);
  EVP_MD_CTX_free(ctx2);

  RECORD_LOG(time_log, SW_3);
  // AES Encryption (30B)
  EVP_CIPHER_CTX *ctx3;
  ctx3 = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx3, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx3, ciph, &len, msg, mlen);
  clen = len;
  ret3 = EVP_EncryptFinal_ex(ctx3, ciph + len, &len);
  clen += len;
  EVP_CIPHER_CTX_free(ctx3);

  RECORD_LOG(time_log, SW_4);
  // AES Decryption (30B)
  EVP_CIPHER_CTX *ctx4;
  ctx4 = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx4, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx4, plain, &len, ciph, clen);
  plen = len;
  ret4 = EVP_DecryptFinal_ex(ctx4, plain + len, &len);
  plen += len;
  EVP_CIPHER_CTX_free(ctx4);
/*
  RECORD_LOG(time_log, SW_5);
  // AES Encryption (16K)
  EVP_CIPHER_CTX *ctx5;
  ctx5 = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx5, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx5, ciph, &len, msgd, strlen(msgd));
  clen = len;
  ret5 = EVP_EncryptFinal_ex(ctx5, ciph + len, &len);
  clen += len;
  EVP_CIPHER_CTX_free(ctx5);

  RECORD_LOG(time_log, SW_6);
  // AES Decryption (16K)
  EVP_CIPHER_CTX *ctx6;
  ctx6 = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx6, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx6, plain, &len, ciph, clen);
  plen = len;
  ret6 = EVP_DecryptFinal_ex(ctx6, plain + len, &len);
  plen += len;
  EVP_CIPHER_CTX_free(ctx6);
*/
  RECORD_LOG(time_log, SW_7);

  INTERVAL(time_log, SW_3, SW_4); // AES encryption (about 30B)
  INTERVAL(time_log, SW_4, SW_5); // AES decryption (about 30B)
  INTERVAL(time_log, SW_5, SW_6); // AES encryption (4K)
  INTERVAL(time_log, SW_6, SW_7); // AES decryption (4K)

	EDGE_LOG(">> Results of Operations");
  EDGE_LOG(">> ECC Signature: %d", ret1);
  EDGE_PRINT(">> Result Signature", sig, 0, slen, 10);
  EDGE_LOG(">> ECC Verification: %d", ret2);
  EDGE_PRINT(">> Test Message", msg, 0, mlen, 10);
  EDGE_LOG(">> AES Encryption: %d", ret3);
  EDGE_PRINT(">> Result Encryption", ciph, 0, clen, 10);
  EDGE_LOG(">> AES Decryption: %d", ret4);
  EDGE_PRINT(">> Result Decryption", plain, 0, plen, 10);

  RECORD_LOG(time_log, SW_8);
}
