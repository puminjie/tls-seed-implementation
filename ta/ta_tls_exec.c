#include <ta_edge_cache.h>
#include "ta_tls_manager.h"
#include "ta_tls_table.h"
#include "ta_fetch_broker.h"
#include "ta_tls_exec.h"
#include "ta_ec_func.h"
#include "ta_software_assertion.h"
#include "ta_simple_http.h"
#include "ta_cc.h"
#include "orig_cert.h"
#include "ta_debug.h"

static struct io_status_ops cc_ops =
{
  .send_request = cc_send_request,
  .parse_data = cc_parse_data,
  .update_data = update_data,
  .process_data = cc_process_data,
};

static struct io_status_ops http_ops =
{
  .send_request = http_send_request,
  .send_response = http_send_response,
  .parse_data = http_parse_response,
  .update_data = update_data,
  .process_data = http_process_data,
};

struct io_status_ops *get_ops(uint8_t flag)
{
  struct io_status_ops *ret;

  switch(flag)
  {
  case TA_EDGE_CACHE_CMD_GET_DOMAIN:
  case TA_EDGE_CACHE_CMD_GET_DATA:
    ret = &http_ops;
    break;
  case TA_EDGE_CACHE_CMD_GET_CC:
    ret = &cc_ops;
    break;
  default:
    ret = &http_ops;
  }

  return ret;
}

static int check_integrity(uint8_t *buf, uint32_t plen, uint8_t *hash, uint32_t hlen,
    uint8_t *salt, uint32_t slen);

TEE_Result check_next_command(struct cmd_st *cctx, struct file_manager_st *mngr);

static inline TEE_Result tls_server_process(struct tls_context_record_st *sctx, struct cmd_st *cctx,
    struct tls_manager_st *mngr)
{
  int ret;
  uint32_t len;
  int recv, plen;
  int8_t finished;
  uint8_t buf[BUF_SIZE];
  struct io_status_st *io;
  struct key_manager_st *kst;
  struct content_st *cinfo;
  struct rinfo *r;
  SSL *ssl;

  ssl = sctx->ssl;
  io = NULL;
  len = BUF_SIZE;
  finished = 0;

  io = sctx->status;

  if (!io)
  {
    RECORD_LOG(SSL_get_time_log(ssl), LOG_1);
    io = init_io_status(&io, get_ops(cctx->flags));
    RECORD_LOG(SSL_get_time_log(ssl), LOG_2);
    sctx->status = io;
  }

  if (!(io->flags & TA_EC_FLAG_REQUEST_RCVD))
  {
    RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START);
    RECORD_LOG(SSL_get_time_log(ssl), SERVER_RECV_HTTP_REQUEST_START);
    RECORD_LOG(SSL_get_time_log(ssl), LOG_3);
    recv = SSL_read(ssl, buf, len);
    if (recv > 0)
    {
      RECORD_LOG(SSL_get_time_log(ssl), LOG_4);
      RECORD_LOG(SSL_get_time_log(ssl), SERVER_RECV_HTTP_REQUEST_END);
      buf[recv] = 0;
      EDGE_LOG("[Frontend] Read message (%d bytes) : [%s]", recv, buf);
      RECORD_LOG(SSL_get_time_log(ssl), SERVER_PARSE_HTTP_REQUEST_START);
      http_parse_request(buf, recv, &r);
      RECORD_LOG(SSL_get_time_log(ssl), SERVER_PARSE_HTTP_REQUEST_END);
      io->flags |= TA_EC_FLAG_REQUEST_RCVD;
      io->rinfo = r;

      RECORD_LOG(SSL_get_time_log(ssl), SERVER_CHECK_CACHE_START);
#ifndef NO_CACHE
      cinfo = mngr->fmngr->vops->get(mngr->fmngr, io->rinfo);
#else
      cinfo = NULL;
#endif /* NO_CACHE */
      RECORD_LOG(SSL_get_time_log(ssl), SERVER_CHECK_CACHE_END);
      
      if (cinfo) // If the content is cached, load the content from NW
      {
        EDGE_MSG("Found content info");
        RECORD_LOG(SSL_get_time_log(ssl), LOG_5);
        io->rinfo = mngr->broker->ops->push_into_queue(mngr->broker, cinfo, 
            io->rinfo, sctx, NULL, FILE_LOAD);
        RECORD_LOG(SSL_get_time_log(ssl), LOG_6);
      }
      else // If the content is not cached, request the broker to fetch it
      {
        EDGE_MSG("Cannot found content info. We should fetch from the backend");
        io->rinfo = mngr->broker->ops->push_into_queue(mngr->broker, NULL, 
            io->rinfo, sctx, NULL, FETCH_FROM_ORIGIN);
      }
      if (io->rinfo != r)
        free_rinfo(r);

      cctx->flags = TA_EDGE_CACHE_NXT_POLL_DATA;
      EDGE_MSG("[Frontend] Request is fulfilled");
    }
  }
}

/**
 * @brief TLS execution with regard to the server state
 * @param ssl The TLS session context which contains the state and other materials
 * @param cctx The context of the command
 * @return Error code
 */
TEE_Result tls_server_execution(struct tls_context_record_st *sctx, struct cmd_st *cctx, 
    struct tls_manager_st *mngr)
{
  EDGE_LOG("Start: tls_server_execution: sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);
  int ret;
  uint32_t len;
  int recv, plen;
  int8_t finished;
  uint8_t buf[BUF_SIZE];
  struct io_status_st *io;
  struct key_manager_st *kst;
  struct content_st *cinfo;
  struct rinfo *r;
  SSL *ssl;

  ssl = sctx->ssl;
  io = NULL;
  len = BUF_SIZE;
  finished = 0;

  if (SSL_is_init_finished(ssl))
  {
    tls_server_process(sctx, cctx, mngr);
  }
  else
  {
    EDGE_LOG("[Frontend] TLS handshake on going with ssl %p", (void *)ssl);
    ret = SSL_do_handshake(ssl);
    if (ret < 0)
    {
      EDGE_MSG("[Frontend] TLS handshake is not finished yet");
    }
    else if (ret == 1)
    {
      RECORD_LOG(SSL_get_time_log(ssl), SERVER_AFTER_TLS_ACCEPT);
      RECORD_LOG(SSL_get_time_log(ssl), LOG_0);
      EDGE_MSG("[Frontend] TLS handshake is finished");
      io = sctx->status;

      if (!io)
      {
        RECORD_LOG(SSL_get_time_log(ssl), LOG_1);
        io = init_io_status(&io, get_ops(cctx->flags));
        RECORD_LOG(SSL_get_time_log(ssl), LOG_2);
        sctx->status = io;
      }
    }
  }

  EDGE_LOG("[Frontend] Next Command: cctx->flags: %s", cmd_to_str(cctx->flags));
  EDGE_LOG("Finished: tls_server_execution");
  return TEE_SUCCESS;
}

/**
 * @brief TLS execution with regard to the client state
 * @param ssl The TLS session context which contains the state and other materials
 * @param cctx The context of the command
 * @return Error code
 */

TEE_Result tls_client_execution(struct tls_context_record_st *sctx, struct cmd_st *cctx, 
    struct tls_manager_st *mngr)
{
  EDGE_LOG("Start: tls_client_execution: sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);
  int ret;
  uint32_t len, blen;
  int32_t recv, sent;
  uint8_t buf[BUF_SIZE] = {0};
  struct buf_st *body;
  struct io_status_st *io;
  SSL *ssl, *req;

  ssl = sctx->ssl;
  io = NULL;
  len = BUF_SIZE;

  if (SSL_is_init_finished(ssl))
  {
    io = sctx->status;
    if (!io)
    {
      io = init_io_status(&io, get_ops(cctx->flags));
      sctx->status = io;
    }

    if (!(io->flags & TA_EC_FLAG_REQUEST_SENT))
    {
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_START);
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_SEND_HTTP_REQUEST_START);
      io->ops->send_request(io, sctx, cctx, mngr->fmngr);
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_SEND_HTTP_REQUEST_END);
      io->flags |= TA_EC_FLAG_REQUEST_SENT;
    }
    else
    {
      recv = SSL_read(ssl, buf, len);
      if (recv > 0)
      {
        RECORD_LOG(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_END);
        io->flags |= TA_EC_FLAG_RESPONSE_RCVD;
        EDGE_LOG("[Backend] Received: %d", recv);

        if (io->flags & TA_EC_FLAG_NEED_PARSE)
        {
          RECORD_LOG(SSL_get_time_log(ssl), CLIENT_PARSE_DATA_START);
          io->ops->parse_data(io, buf, recv);
          RECORD_LOG(SSL_get_time_log(ssl), CLIENT_PARSE_DATA_END);
          io->flags &= ~TA_EC_FLAG_NEED_PARSE;
        }

        RECORD_LOG(SSL_get_time_log(ssl), CLIENT_UPDATE_DATA_START);
        io->ops->update_data(io, buf, recv);
        RECORD_LOG(SSL_get_time_log(ssl), CLIENT_UPDATE_DATA_END);
      }
    }

    if (io && (io->flags & TA_EC_FLAG_NEED_PROCESS))
    {
      EDGE_LOG("[Backend] Received all content: io->buf->len: %d", io->buf->len);
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_PROCESS_DATA_START);
      io->ops->process_data(io, sctx, mngr->fmngr, cctx);
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_PROCESS_DATA_END);
      io->flags &= ~TA_EC_FLAG_NEED_PROCESS;
      EDGE_MSG("[Backend] After process");
    }

    if (io->flags & TA_EC_FLAG_RESPONSE_RCVD)
    {
      if (io->flags & TA_EC_FLAG_RESPONSE_FORWARD)
      {
        RECORD_LOG(SSL_get_time_log(ssl), CLIENT_SEND_RESPONSE_START);
        mngr->broker->ops->send_response(mngr->broker, io, cctx);
        RECORD_LOG(SSL_get_time_log(ssl), CLIENT_SEND_RESPONSE_END);
      }

      // Check whether receiving the data is complete
      if (io->last >= io->size)
      {
        // Check the next command
        check_next_command(cctx, mngr->fmngr);
      }
    }
  }
  else
  {
    EDGE_LOG("[Backend] TLS handshake on going with ssl %p", (void *)ssl);
    ret = SSL_do_handshake(ssl);

    if (ret < 0)
    {
      EDGE_MSG("[Backend] TLS handshake is not finished yet");
    }
    else if (ret == 1)
    {
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_HANDSHAKE_END);
      if(sctx->status)
        io = sctx->status;
      else
      {
        io = init_io_status(&io, get_ops(cctx->flags));
        sctx->status = io;
      }

      EDGE_LOG("[Backend] The TLS session is established: %p", io->ops->send_request);
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_START);
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_SEND_HTTP_REQUEST_START);
      io->ops->send_request(io, sctx, mngr, cctx);
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_SEND_HTTP_REQUEST_END);
      EDGE_MSG("[Backend] HTTP Request is sent");
    }
  }

  EDGE_LOG("[Backend] Next Command: cctx->flags: %s", cmd_to_str(cctx->flags));
  EDGE_LOG("Finished: tls_client_execution");
  return TEE_SUCCESS;
}

/**
 * @brief Check the integrity of the loaded content
 * @param buf the content
 * @param plen the length of the content
 * @param hash the hash value of the content
 * @param hlen the length of the hash
 * @return Error code (success: 1, failure: 0)
 */
static int check_integrity(uint8_t *buf, uint32_t plen, uint8_t *hash, uint32_t hlen,
    uint8_t *salt, uint32_t slen)
{
  int shalen;
  uint8_t h[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *ctx;
  ctx = EVP_MD_CTX_create();

  EVP_DigestInit(ctx, EVP_sha256());
  EVP_DigestUpdate(ctx, salt, slen);
  EVP_DigestUpdate(ctx, buf, plen);
  EVP_DigestFinal(ctx, h, &shalen);

  EVP_MD_CTX_free(ctx);

  if ((shalen == hlen) && (!CRYPTO_memcmp(h, hash, hlen)))
    return 1;
  return 0;
}

/**
 * @brief Check the next command to be executed
 * @param cmd The current command
 * @return The next command
 */
TEE_Result check_next_command(struct cmd_st *cctx, struct file_manager_st *mngr)
{
  EDGE_MSG("check_next_command");
  switch (cctx->flags)
  {
  case TA_EDGE_CACHE_CMD_GET_DOMAIN:
    EDGE_MSG("current: TA_EDGE_CACHE_CMD_GET_DOMAIN");
    mngr->vops->check_need_cross_credential(mngr, cctx);
    break;
  case TA_EDGE_CACHE_CMD_GET_CC:
    EDGE_MSG("current: TA_EDGE_CACHE_CMD_GET_CC");
    mngr->vops->check_need_cross_credential(mngr, cctx);
    break;
  case TA_EDGE_CACHE_CMD_GET_DATA:
    EDGE_MSG("current: TA_EDGE_CACHE_CMD_GET_DATA");
    cctx->flags = TA_EDGE_CACHE_NXT_EXIT;
    break;
  default:
    cctx->flags = TA_EDGE_CACHE_NXT_EXIT;
  }

  if (cctx->flags == TA_EDGE_CACHE_NXT_GET_CC)
    EDGE_MSG("next: TA_EDGE_CACHE_NXT_GET_CC");
  else if (cctx->flags == TA_EDGE_CACHE_NXT_EXIT)
    EDGE_MSG("next: TA_EDGE_CACHE_NXT_EXIT");
  else if (cctx->flags == TA_EDGE_CACHE_NXT_GET_DOMAIN)
    EDGE_MSG("next: TA_EDGE_CACHE_NXT_GET_DOMAIN");
  else
    EDGE_MSG("other command");

  return TEE_SUCCESS;
}

/** 
 * @brief Initialize the context of the TLS server
 * @param mngr The file manager which has the EC keypair
 * @return The TLS server context
 */
SSL_CTX *init_server_ctx(struct file_manager_st *mngr)
{
  SSL_METHOD *method;
  SSL_CTX *ret;
  EC_KEY *ecdh;
  uint32_t ca_sz;
#ifdef RSA
  DH *dh;
  BIO *b;
  uint32_t dh_sz;
#endif /* RSA */

  EDGE_MSG("[TA] init_server_ctx");
  ret = NULL;
  method = (SSL_METHOD *) TLS_server_method();

  ret = SSL_CTX_new(method);

#ifdef TLS13
  SSL_CTX_set_max_proto_version(ret, TLS1_3_VERSION);
  SSL_CTX_set_cipher_list(ret, "AEAD-AES128-GCM-SHA256");
#else
  SSL_CTX_set_max_proto_version(ret, TLS1_2_VERSION);
#endif /* TLS13 */

  EDGE_LOG("[TA] initialize ssl_ctx finished: %p", (void *)ret);

  ca_sz = sizeof(ca_buf);
#ifdef RSA
  dh_sz = sizeof(dh_buf);
#endif /* RSA */

  SSL_CTX_enable_ec(ret);

  // TODO: How does the EC validate the certificates?
  /*
  EDGE_LOG("[TA] Before load CA certificate");
  if (SSL_CTX_load_verify_locations(ret, ca_buf, NULL) != 1)
  {
    EDGE_LOG("[TA] load CA certificate error");
  }
  */

  EDGE_MSG("[TA] Before load certificate");
  if (SSL_CTX_use_certificate_ASN1(ret, mngr->pair->crt_len, mngr->pair->crt) != 1)
  {
    EDGE_MSG("[TA] load certificate error");
  }
  else
  {
    EDGE_MSG("[TA] load certificate success");
  }

#ifndef RSA
  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, ret, mngr->pair->priv, mngr->pair->priv_len) != 1)
  {
    EDGE_MSG("[TA] load private key error");
  }
  else
  {
    EDGE_MSG("[TA] load private key success");
  }
#else
  if (SSL_CTX_use_RSAPrivateKey_ASN1(ret, priv_buf, priv_sz) != 1)
  {
    EDGE_MSG("[TA] load private key error");
  }
  else
  {
    EDGE_MSG("[TA] load private key success");
  }
#endif /* RSA */

  if (SSL_CTX_check_private_key(ret) != 1)
  {
    EDGE_MSG("[TA] check private key failed");
  }
  else
  {
    EDGE_MSG("[TA] check private key success");
  }

#ifndef RSA
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
  {
    EDGE_MSG("[TA] initialize ecdh error");
  }

  if (SSL_CTX_set_tmp_ecdh(ret, ecdh) != 1)
  {
    EDGE_MSG("[TA] set ecdh error");
  }
#else 
  b = BIO_new_mem_buf(dh_buf, dh_sz);
  EDGE_LOG("[TA] read dh buf: %p", b);
  dh = PEM_read_bio_DHparams(b, NULL, NULL, NULL);
  EDGE_LOG("[TA] construct dh object: %p", dh);

  if (SSL_CTX_set_tmp_dh(ret, dh))
  {
    EDGE_MSG("[TA] set dh success");
  }
  else
  {
    EDGE_MSG("[TA] set dh failure");
  }
#endif /* RSA */

  EDGE_MSG("[TA] init server ctx complete");
  return ret;
}

/**
 * @brief Initialize the context of the TLS client
 * @param mngr The file manager which has the EC keypair
 * @return The context of the TLS client
 */
SSL_CTX *init_client_ctx(struct file_manager_st *mngr)
{
  SSL_METHOD *method;
  SSL_CTX *ret;
  EC_KEY *ecdh;

  method = (SSL_METHOD *)TLS_client_method();
  ret = SSL_CTX_new(method);

  if (!ret)
    return NULL;

#ifdef TLS13
  SSL_CTX_set_max_proto_version(ret, TLS1_3_VERSION);
#else
  SSL_CTX_set_max_proto_version(ret, TLS1_2_VERSION);
#endif /* TLS13 */

#ifdef SESSION_RESUMPTION
  SSL_CTX_set_session_cache_mode(ret, SSL_SESS_CACHE_BOTH);
#else
  SSL_CTX_set_session_cache_mode(ret, SSL_SESS_CACHE_OFF);
#endif /* SESSION_RESUMPTION */


  // TODO: I should implement the validation of the certificates
  /*
  EDGE_LOG("[TA] before load CA certificate");
  if (SSL_CTX_load_verify_locations(ret, ca_buf, NULL) != 1)
  {
    EDGE_LOG("[TA] load CA certificate failed");
  }
  */

  EDGE_MSG("[TA] before EC certificate");
  if (SSL_CTX_use_certificate_ASN1(ret, mngr->pair->crt_len, mngr->pair->crt) != 1)
  {
    EDGE_MSG("[TA] load certificate error");
  }
  else
  {
    EDGE_MSG("[TA] load certificate success");
  }

#ifndef RSA
  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, ret, mngr->pair->priv, mngr->pair->priv_len) != 1)
    EDGE_MSG("[TA] load private key error");
  else
    EDGE_MSG("[TA] load private key success");
#else
  if (SSL_CTX_use_RSAPrivateKey_ASN1(ret, priv_buf, priv_sz) != 1)
    EDGE_MSG("[TA] load private key error");
  else
    EDGE_MSG("[TA] load private key success");
#endif /* RSA */

  if (SSL_CTX_check_private_key(ret) != 1)
    EDGE_MSG("[TA] check private key failed");
  else
    EDGE_MSG("[TA] check private key success");

#ifndef RSA
  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    EDGE_MSG("[TA] initialize ecdh error");

  if (SSL_CTX_set_tmp_ecdh(ret, ecdh) != 1)
    EDGE_MSG("[TA] set ecdh error");
#else 
  b = BIO_new_mem_buf(dh_buf, dh_sz);
  EDGE_LOG("[TA] read dh buf: %p", b);
  dh = PEM_read_bio_DHparams(b, NULL, NULL, NULL);
  EDGE_LOG("[TA] construct dh object: %p", dh);

  if (SSL_CTX_set_tmp_dh(ret, dh))
    EDGE_MSG("[TA] set dh success");
  else
    EDGE_MSG("[TA] set dh failure");
#endif /* RSA */

  EDGE_MSG("[TA] init client ctx complete");
  return ret;
}

/**
 * @brief Free the memory allocated for the TLS context
 */
void free_ctx(SSL_CTX *ctx)
{
  SSL_CTX_free(ctx);
  ctx = NULL;
}

/**
 * @brief Initialize the TLS session context of the TLS server
 * @param ctx The base context of the TLS server
 * @param time_log The log structure
 */
SSL *init_tls_server_context(struct tls_manager_st *mngr, log_t *time_log)
{
  EDGE_MSG("[Frontend] init_tls_server_context");
  SSL *ssl;
  BIO *rbio, *wbio;

///// Test
  struct buf_st *name;
  struct domain_table_st *dom;
  const uint8_t domain[] = "www.bob.com";
  uint32_t dlen;
  dlen = strlen(domain);
  init_buf_mem(&name, domain, dlen);

  dom = mngr->fmngr->ops->get(mngr->fmngr, name);
  EDGE_LOG("Fetched Domain Name: %s", dom->get_name(dom)->data);
  EDGE_LOG("Orig Certificate Length: %d", dom->cert->len);
  EDGE_LOG("Orig CC Length: %d", dom->cc->len);
/////

  ssl = SSL_new(mngr->ctx);

  if (!ssl) goto exit;

  rbio = BIO_new(BIO_s_mem());
  if (!rbio) goto exit;

  wbio = BIO_new(BIO_s_mem());
  if (!wbio) goto exit;

  SSL_set_bio(ssl, rbio, wbio);
  SSL_set_accept_state(ssl);

  SSL_enable_ec(ssl);
  SSL_disable_keyless_ssl(ssl);
  SSL_set_ec_digest_buf(ssl, mngr->ec_digest, mngr->ht, mngr->len);
//  SSL_set_get_ec_digest(ssl, get_ec_digest);
//  SSL_set_ec_digest(ssl);
  EDGE_MSG("load ec digest success");

///// Test

  //EDGE_PRINT("Certificate", dom->cert->data, 0, dom->cert->len, 10);

  if (SSL_use_orig_certificate_ASN1(ssl, dom->cert->data, dom->cert->len) != 1)
  {
    EDGE_MSG("Error in loading origin's certificate");
    abort();
  }
  EDGE_MSG("Loading origin's certificate");

  if (SSL_use_cc_mem(ssl, dom->cc->data, dom->cc->len) != 1)
  {
    EDGE_MSG("Error in loading CC");
    abort();
  }
  EDGE_MSG("Loading CC succeed");
/////

#ifdef TIME_LOG
  SSL_set_time_log(ssl, time_log);
#endif /* TIME_LOG */

  return ssl;

exit:
  EDGE_MSG("[TA] Error in setting ssl");
  if (ssl)
    SSL_free(ssl);
  ssl = NULL;

  return ssl;
}

/**
 * @brief Initialize the TLS session context of the TLS client
 * @param ctx The base context of the TLS client
 * @param time_log The log structure
 * @return The TLS session context
 */
SSL *init_tls_client_context(struct tls_manager_st *mngr, log_t *time_log)
{
  EDGE_MSG("[Backend] init_tls_client_context");
  SSL *ssl;
  BIO *rbio, *wbio;
  ssl = SSL_new(mngr->ctx);

  if (!ssl) goto exit;

  rbio = BIO_new(BIO_s_mem());
  if (!rbio) goto exit;

  wbio = BIO_new(BIO_s_mem());
  if (!wbio) goto exit;

  SSL_set_bio(ssl, rbio, wbio);
  SSL_set_connect_state(ssl);

  SSL_enable_ec(ssl);
  SSL_disable_keyless_ssl(ssl);
  SSL_set_ec_digest_buf(ssl, mngr->ec_digest, mngr->ht, mngr->len);
//  SSL_set_get_ec_digest(ssl, get_ec_digest);
//  SSL_set_ec_digest(ssl);
  EDGE_MSG("load ec digest success");
#ifdef TIME_LOG
  SSL_set_time_log(ssl, time_log);
#endif /* TIME_LOG */

  return ssl;

exit:
  EDGE_MSG("Error in setting client session context");
  if (ssl)
    SSL_free(ssl);
  ssl = NULL;

  return ssl;
}

/**
 * @brief Free the memory space allocated for the TLS session context
 * @param the TLS session context to be freed
 */
void free_tls_context(SSL *ssl)
{
  SSL_free(ssl);
  ssl = NULL;
}
