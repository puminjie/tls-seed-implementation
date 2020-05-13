#include "ta_init.h"
#include "ta_tls_context_ops.h"
#include "ta_file_manager_ops.h"

#ifdef PLATFORM_OPTEE
  #include "ta_software_assertion.h"
#endif /* PLATFORM_OPTEE */

#include "keypair.h"
#include "test_message.h"

#include <debug.h>

SEED_Result init_file_manager(file_manager_t **mngr, cctx_t *cctx, void *logger)
{
  efstart("mngr: %p, cctx: %p, logger: %p", mngr, cctx, logger);

  (*mngr) = (file_manager_t *)malloc(sizeof(file_manager_t));
  DEFAULT_PARENT_INIT_FUNC(file_manager, (*mngr));
  (*mngr)->vops = &vops;
  (*mngr)->pair = (keypair_t *)malloc(sizeof(keypair_t));
  memset((*mngr)->pair, 0x0, sizeof(keypair_t));

  (*mngr)->pair->priv_len = sizeof(pbuf);
  assert((*mngr)->pair->priv_len < MAX_PRIVKEY_SIZE);
  memcpy((*mngr)->pair->priv, pbuf, (*mngr)->pair->priv_len);
  
  (*mngr)->pair->crt_len = sizeof(cbuf);
  assert((*mngr)->pair->crt_len < MAX_CERT_SIZE);
  memcpy((*mngr)->pair->crt, cbuf, (*mngr)->pair->crt_len);

#ifdef TIME_LOG
  (*mngr)->logger = logger;
#endif /* TIME_LOG */

  effinish();
  return SEED_SUCCESS;
}

SEED_Result init_tls_manager(tls_manager_t **mngr, file_manager_t *fmngr, int resumption, 
    int role)
{
  efstart("mngr: %p, fmngr: %p, resumption: %d, role: %d", mngr, fmngr, resumption, role);

  uint8_t *buf;
  uint16_t ht;
  size_t len;

  (*mngr) = (tls_manager_t *)malloc(sizeof(tls_manager_t));
  if (!(*mngr)) goto err;
  memset((*mngr), 0x0, sizeof(tls_manager_t));

  if (role == TA_FRONTEND_MANAGER)
    (*mngr)->cops = &frontend_ops;
  else if (role == TA_BACKEND_MANAGER)
    (*mngr)->cops = &backend_ops;

  (*mngr)->tops = &tbl_ops;
  (*mngr)->ctx = (*mngr)->cops->init_ctx(fmngr, resumption);
  if (!((*mngr)->ctx)) goto err;

  buf = (uint8_t *)malloc(EVP_MAX_MD_SIZE);
  if (!buf) goto err;

#ifdef PLATFORM_OPTEE
  get_optee_seed_digest(buf, &ht, &len);
#elif PLATFORM_SGX
  get_sgx_seed_digest(buf, &ht, &len);
#endif /* PLATFORM_SGX */
  (*mngr)->seed_digest = buf;
  (*mngr)->ht = ht;
  (*mngr)->len = (uint32_t)len;

  (*mngr)->tops->init_tls_context_table(&((*mngr)->tbl), (*mngr));
  (*mngr)->fmngr = fmngr;

  effinish();
  return SEED_SUCCESS;

err:
  if (*mngr)
  {
    if ((*mngr)->seed_digest) free((*mngr)->seed_digest);
    if ((*mngr)->ctx) SSL_CTX_free((*mngr)->ctx);
    (*mngr)->ctx = NULL;
    free(*mngr);
    (*mngr) = NULL;
#ifdef PLATFORM_OPTEE
    buf = NULL;
#endif /* PLATFORM_OPTEE */
  }

  eferr();
  return SEED_ERROR_OUT_OF_MEMORY;
}

/*
void init_test(void *tlog)
{
  logger_t *logger = (logger_t *)tlog;
  //RECORD_LOG(time_log, SW_0, get_current_time());
  EVP_PKEY *priv, *pub;
  const char msg[] = "Test String for TrustZone I/O";
  const uint8_t key[32] = "01234567890123456789012345678901";
  const uint8_t iv[16] = "0123456789012345";
  uint8_t plain[16384];
  uint8_t ciph[16384];
  uint8_t *sig;
  size_t privlen, crtlen, slen;
  int len;
  uint32_t mlen, plen, clen;
  mlen = strlen(msg);
  len = 0; slen = 0; plen = 0; clen = 0;
  privlen = sizeof(pbuf);
  crtlen = sizeof(cbuf);

  SSL_CTX *sctx;
  sctx = SSL_CTX_new(TLS_server_method());

  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, sctx, pbuf, privlen) != 1)
  {
    dmsg("Error in loading private key");
  }

  if (SSL_CTX_use_certificate_ASN1(sctx, crtlen, cbuf) != 1)
  {
    dmsg("Error in loading cert");
  }

  if (SSL_CTX_check_private_key(sctx) != 1)
  {
    dmsg("Error in keypair");
    abort();
  }

  priv = SSL_CTX_get0_privatekey(sctx);
  pub = X509_get_pubkey(SSL_CTX_get0_certificate(sctx));

  //RECORD_LOG(time_log, SW_1, get_current_time());
  // ECC Signature Operation
  EVP_MD_CTX *ctx1;
  ctx1 = EVP_MD_CTX_create();
  EVP_DigestSignInit(ctx1, NULL, EVP_sha256(), NULL, priv);
  EVP_DigestSignUpdate(ctx1, msg, mlen);
  EVP_DigestSignFinal(ctx1, NULL, &slen);
  sig = OPENSSL_malloc(slen);
  EVP_DigestSignFinal(ctx1, sig, &slen);
  EVP_MD_CTX_free(ctx1);

  //RECORD_LOG(time_log, SW_2, get_current_time());
  // ECC Verification Operation
  EVP_MD_CTX *ctx2;
  ctx2 = EVP_MD_CTX_create();
  EVP_DigestVerifyInit(ctx2, NULL, EVP_sha256(), NULL, pub);
  EVP_DigestVerifyUpdate(ctx2, msg, mlen);
  EVP_DigestVerifyFinal(ctx2, sig, slen);
  EVP_MD_CTX_free(ctx2);

  //RECORD_LOG(time_log, SW_3, get_current_time());
  // AES Encryption (30B)
  EVP_CIPHER_CTX *ctx3;
  ctx3 = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx3, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx3, ciph, &len, (const unsigned char *)msg, mlen);
  clen = len;
  EVP_EncryptFinal_ex(ctx3, ciph + len, &len);
  clen += len;
  EVP_CIPHER_CTX_free(ctx3);

  //RECORD_LOG(time_log, SW_4, get_current_time());
  // AES Decryption (30B)
  EVP_CIPHER_CTX *ctx4;
  ctx4 = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx4, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx4, plain, &len, ciph, clen);
  plen = len;
  EVP_DecryptFinal_ex(ctx4, plain + len, &len);
  plen += len;
  EVP_CIPHER_CTX_free(ctx4);

  //RECORD_LOG(time_log, SW_5, get_current_time());
  // AES Encryption (16K)
  EVP_CIPHER_CTX *ctx5;
  ctx5 = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx5, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx5, ciph, &len, msgd, strlen(msgd));
  clen = len;
  EVP_EncryptFinal_ex(ctx5, ciph + len, &len);
  clen += len;
  EVP_CIPHER_CTX_free(ctx5);

  //RECORD_LOG(time_log, SW_6, get_current_time());
  // AES Decryption (16K)
  EVP_CIPHER_CTX *ctx6;
  ctx6 = EVP_CIPHER_CTX_new();
  EVP_DecryptInit_ex(ctx6, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_DecryptUpdate(ctx6, plain, &len, ciph, clen);
  plen = len;
  EVP_DecryptFinal_ex(ctx6, plain + len, &len);
  plen += len;
  EVP_CIPHER_CTX_free(ctx6);

  //RECORD_LOG(time_log, SW_7, get_current_time());

//  INTERVAL(time_log, SW_3, SW_4); // AES encryption (about 30B)
//  INTERVAL(time_log, SW_4, SW_5); // AES decryption (about 30B)
//  INTERVAL(time_log, SW_5, SW_6); // AES encryption (4K)
//  INTERVAL(time_log, SW_6, SW_7); // AES decryption (4K)

//	dmsg(">> Results of Operations");
//  dmsg(">> ECC Signature: %d", ret1);
  //EDGE_PRINT(">> Result Signature", sig, 0, slen, 10);
//  dmsg(">> ECC Verification: %d", ret2);
  //EDGE_PRINT(">> Test Message", msg, 0, mlen, 10);
//  dmsg(">> AES Encryption: %d", ret3);
  //EDGE_PRINT(">> Result Encryption", ciph, 0, clen, 10);
//  dmsg(">> AES Decryption: %d", ret4);
  //EDGE_PRINT(">> Result Decryption", plain, 0, plen, 10);

  //RECORD_LOG(time_log, SW_8, get_current_time());
}
*/
