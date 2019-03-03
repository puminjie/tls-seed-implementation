#include "init.h"
#include "debug.h"

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/logs.h>
#include <openssl/evp.h>

#include <time.h>
#include <sys/time.h>

#include <tee_client_api.h>
#include "sys_timer.h"
//#include "log_client.h"
#include "keypair.h"
#include "hio.h"
#include "ec_func.h"
#include "test_message.h"

#define KEY_PATH    "/root/key"           // the path of the sealing key.
#define META_PATH   "/root/meta_info"     // the meta info of the first table.
#define PKEY_PATH   "/root/pkey"          // the path of the private key.
#define CERT_PATH   "/root/cert"          // the path of the EC certificate.

TEEC_Result forward_default_key_setting(struct ec_ctx *ctx, struct hiom_st *iom, 
    TEEC_Operation *op);
TEEC_Result get_domain_list(struct ec_ctx *ctx, struct hiom_st *iom, TEEC_Operation *op);
TEEC_Result get_cc_from_origin(struct ec_ctx *ctx, struct hiom_st *iom, TEEC_Operation *op);
void init_test(struct ec_ctx *ctx, TEEC_Operation *op, void *tlog);

/**
 * @brief Initialize EC settings
 * @param ctx Context of EC
 * @param time_log Log structure
 */
void init(struct ec_ctx *ctx, void *time_log)
{
  struct hiom_st *iom;
  struct cmd_st *cctx;
  TEEC_Context *tctx;
  TEEC_Operation op;
  uint8_t init;
#ifdef TIME_LOG
  log_t *tlog;
  tlog = (log_t *)time_log;
#endif /* TIME_LOG */

  // Setting the I/O module with the secure world.
  iom = NULL;
  tctx = &(ctx->ctx);

  init_commands();

  EDGE_LOG("before initialize I/O module");
  init_iom(&iom, tctx, INITIALIZER);
  EDGE_LOG("after initialize I/O module: %p", iom);

  EDGE_LOG("before set operations");
  set_op(&op, iom, tlog);

  init = 1;

#if defined(TIME_LOG) && defined(TEST)
  init_test(ctx, &op, tlog);
#endif /* TIME_LOG && TEST */

  forward_default_key_setting(ctx, iom, &op);
  cctx = get_cmd_ctx(iom);

  while (init)
  {
    client_operation(ctx, iom, &op, cctx->flags, BACKEND);

    if (cctx->flags == TA_EDGE_CACHE_NXT_EXIT)
      init = 0;
  }

  EDGE_LOG("after invoke command");
  free_iom(iom, tctx);
  EDGE_LOG("init out");
}

/**
 * @brief Forward the sealing key and asymmetric keypair to the secure world
 * @param Context of the shared communication channel
 * @param I/O module
 * @return error code
 */
TEEC_Result forward_default_key_setting(struct ec_ctx *ctx, struct hiom_st *iom, 
    TEEC_Operation *op)
{
  // Sealing key length (2 bytes) || encrypted sealing key ||
  // Metainfo length (2 bytes) || encrypted meta info ||
  // Private key length (2 bytes) || encrypted private key ||
  // Certificate length (2 bytes) || encrypted certificate

  FILE *fp;
  const char *fname[] = { KEY_PATH, META_PATH, PKEY_PATH, CERT_PATH };
  TEEC_Result res;
  struct cmd_st *cctx;
  uint32_t i, origin, offset;
  size_t sz;

  offset = 0;

  for (i=0; i<4; i++)
  {
    fp = fopen(fname[i], "rb");
    fseek(fp, 0L, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0L, SEEK_SET);
    cctx = (struct cmd_st *)(iom->cctx->buffer);
    cctx->flags = TA_EDGE_CACHE_CMD_INIT;
    cctx->arg[offset++] = (sz >> 8) & 0xFF;
    cctx->arg[offset++] = sz & 0xFF;
    fread(cctx->arg + offset, 1, sz, fp);
    offset += sz;
    cctx->alen += sz;
    fclose(fp);
  }

  EDGE_LOG("forward default key setting ");
  res = TEEC_InvokeCommand(&ctx->sess, cctx->flags, op, &origin);

  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand Test failed 0x%x origin 0x%x", res, origin);

  return res;
}

/**
 * @brief Test the basic operations between the normal world and the secure
 * world
 * @param ctx Context of EC
 * @param op TEEC_Operation
 * @param tlog Log structure
 */
void init_test(struct ec_ctx *ctx, TEEC_Operation *op, void *tlog)
{
  EDGE_MSG("init_test start");
  log_t *time_log = (log_t *)tlog;
  EDGE_LOG("before starting the experiment");
  RECORD_LOG(time_log, NW_0);
  EVP_PKEY *priv, *pub;
  const char msg[] = "Test String for TrustZone I/O";
  const uint8_t key[32] = "01234567890123456789012345678901";
  const uint8_t iv[16] = "0123456789012345";
  uint8_t ciph[BUF_SIZE], plain[BUF_SIZE];
  uint8_t *sig;
  size_t privlen, crtlen;
  size_t slen;
  int len;
  uint32_t mlen, plen, clen, origin;
  uint32_t ret1, ret2, ret3, ret4;
  mlen = strlen(msg);
  len = 0; slen = 0; plen = 0; clen = 0;
  privlen = sizeof(pbuf);
  crtlen = sizeof(cbuf);

  SSL_CTX *sctx;
  sctx = SSL_CTX_new(TLSv1_2_server_method());

  if (SSL_CTX_use_certificate_ASN1(sctx, crtlen, cbuf) != 1)
  {
    EDGE_LOG("Error in loading cert");
  }

  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, sctx, pbuf, privlen) != 1)
  {
    EDGE_LOG("Error in loading privkey");
  }

  priv = SSL_CTX_get0_privatekey(sctx);
  pub = X509_get_pubkey(SSL_CTX_get0_certificate(sctx));

  RECORD_LOG(time_log, NW_1);
  // ECC Signature Operation
  EVP_MD_CTX *ctx1;
  ctx1 = EVP_MD_CTX_create();
  EVP_DigestSignInit(ctx1, NULL, EVP_sha256(), NULL, priv);
  EVP_DigestSignUpdate(ctx1, msg, mlen);
  EVP_DigestSignFinal(ctx1, NULL, &slen);
  sig = OPENSSL_malloc(sizeof(unsigned char) * slen);
  ret1 = EVP_DigestSignFinal(ctx1, sig, &slen);
  EVP_MD_CTX_free(ctx1);

  RECORD_LOG(time_log, NW_2);
  // ECC Verification Operation
  EVP_MD_CTX *ctx2;
  ctx2 = EVP_MD_CTX_create();
  EVP_DigestVerifyInit(ctx2, NULL, EVP_sha256(), NULL, pub);
  EVP_DigestVerifyUpdate(ctx2, msg, mlen);
  ret2 = EVP_DigestVerifyFinal(ctx2, sig, slen);
  EVP_MD_CTX_free(ctx2);

  RECORD_LOG(time_log, NW_3);
  // AES Encryption (16K)
  EVP_CIPHER_CTX *ctx3;
  ctx3 = EVP_CIPHER_CTX_new();
  EVP_EncryptInit_ex(ctx3, EVP_aes_256_gcm(), NULL, key, iv);
  EVP_EncryptUpdate(ctx3, ciph, &len, msgd, strlen(msgd));
  clen = len;
  ret3 = EVP_EncryptFinal_ex(ctx3, ciph + len, &len);
  clen += len;
  EVP_CIPHER_CTX_free(ctx3);

  RECORD_LOG(time_log, NW_4);
  // AES Decryption (16K)
  EVP_CIPHER_CTX *ctx4;
  RECORD_LOG(time_log, LOG_23);
  ctx4 = EVP_CIPHER_CTX_new();
  RECORD_LOG(time_log, LOG_24);
  EVP_DecryptInit_ex(ctx4, EVP_aes_256_gcm(), NULL, key, iv);
  RECORD_LOG(time_log, LOG_25);
  EVP_DecryptUpdate(ctx4, plain, &len, ciph, clen);
  RECORD_LOG(time_log, LOG_26);
  plen = len;
  ret4 = EVP_DecryptFinal_ex(ctx4, plain + len, &len);
  plen += len;
  RECORD_LOG(time_log, LOG_27);
  EVP_CIPHER_CTX_free(ctx4);
  RECORD_LOG(time_log, LOG_28);

  RECORD_LOG(time_log, NW_5);
  EDGE_LOG(">> Results of Operations");
  EDGE_LOG(">> ECC Signature: %d", ret1);
  EDGE_PRINT(">> Result Signature", sig, 0, slen, 10);
  EDGE_LOG(">> ECC Verification: %d", ret2);
  EDGE_PRINT(">> Test Message", msg, 0, mlen, 10);
  EDGE_LOG(">> AES Encryption: %d", ret3);
  EDGE_PRINT(">> Result Encryption", ciph, 0, clen, 10);
  EDGE_LOG(">> AES Decryption: %d", ret4);
  EDGE_PRINT(">> Result Decryption", plain, 0, plen, 10);

  RECORD_LOG(time_log, NW_6);
  TEEC_InvokeCommand(&ctx->sess, TA_EDGE_CACHE_CMD_TEST, op, &origin);
  RECORD_LOG(time_log, NW_7);

  EDGE_LOG("==================");
  EDGE_LOG(">> I/O total time");
  INTERVAL(time_log, NW_6, NW_7); // total time
  EDGE_LOG(">> From NW to SW");
  INTERVAL(time_log, NW_6, SW_0); // from nw to sw
  EDGE_LOG(">> From SW to NW");
  INTERVAL(time_log, SW_6, NW_7); // from sw to nw
  EDGE_LOG(">> Init Context in NW");
  INTERVAL(time_log, NW_0, NW_1);
  EDGE_LOG(">> Init Context in SW");
  INTERVAL(time_log, SW_0, SW_1);
  EDGE_LOG(">> ECC Sign in NW");
  INTERVAL(time_log, NW_1, NW_2);
  EDGE_LOG(">> ECC Sign in SW");
  INTERVAL(time_log, SW_1, SW_2);
  EDGE_LOG(">> ECC Verify in NW");
  INTERVAL(time_log, NW_2, NW_3);
  EDGE_LOG(">> ECC Verify in SW");
  INTERVAL(time_log, SW_2, SW_3);
  EDGE_LOG(">> AES Encrypt in NW");
  INTERVAL(time_log, NW_3, NW_4);
  EDGE_LOG(">> AES_Encrypt in SW");
  INTERVAL(time_log, SW_3, SW_4);
  EDGE_LOG(">> AES_Decrypt in NW");
  INTERVAL(time_log, NW_4, NW_5);
  EDGE_LOG(">> AES_Decrypt in SW");
  INTERVAL(time_log, SW_4, SW_5);
  EDGE_LOG("==================");

  SSL_CTX_free(sctx);
  EDGE_LOG("Num of logs: %d", NUM_OF_LOGS);
  EDGE_MSG("init_test finished");
}
