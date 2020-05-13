#include <cmds.h>

#include "ta_cc.h"
#include "ta_ec_func.h"
#include "ta_tls_manager.h"
#include "ta_tls_table.h"
#include "ta_tls_exec.h"

#include "dc.h"

#include <debug.h>
#include <mode.h>
#include "ta_simple_http.h"

/**
 * @brief Check whether the requested domain is a contractor
 * @param ssl The TLS session context
 * @param ad alert
 * @param arg argument
 * @return error code
 */
int check_contractor(SSL *ssl, int *ad, void *arg)
{
  efstart("ssl: %p, ad: %p, arg: %p", ssl, ad, arg);
  assert(ssl != NULL);

  int ret, tmp;
  const char *sname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  buf_t *name;
  domain_table_t *dom;
  file_manager_t *fmngr;
  X509 *x;
  BIO *in;

  name = init_memcpy_buf_mem(NULL, sname, strlen(sname));
  fmngr = (file_manager_t *)arg;
  x = NULL;
  in = NULL;

  dom = fmngr->ops->get(fmngr, name);
  ret = SSL_TLSEXT_ERR_OK;

  if (!dom)
  {
    edmsg("This is not a service provider: %s", name->data);
    edmsg("Now the fallback mechanism should be executed");
    ret = SSL_TLSEXT_ERR_ALERT_FATAL;
    SSL_set_fallback(ssl, 1);
  }
  else
  {
    SSL_set_fallback(ssl, 0);
    if (SSL_is_server(ssl))
    {
      edmsg("This is a service provider: %s", name->data);
      edmsg("Now the CC and the certificate of service provider's should be loaded");

      if (SSL_check_seed_enabled(ssl))
      {
        if (dom->cert)
        {
          in = BIO_new(BIO_s_mem());
          BIO_write(in, dom->cert->data, dom->cert->max);
          if (!PEM_read_bio_X509(in, &x, NULL, NULL))
            emsg("PEM_read_bio_X509_error()");
          tmp = SSL_use_orig_certificate(ssl, x);
          if (tmp != 1)
          {
            emsg("Load the service provider's certificate failed");
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
            goto out;
          }
          else
          {
            dmsg("Load the service provider's certificate succeed");
          }
        }
        else
        {
          emsg("Loading the service provider %s's certificate error", name->data);
          emsg("Now the fallback mechanism should be executed");
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }

        if (dom->cc)
        {
          SSL_use_cc_mem(ssl, dom->cc->data, (size_t)dom->cc->max);
          dmsg("Load the CC succeed");
        }
        else
        {
          emsg("Loading the cross credential with %s error", name->data);
          emsg("Now the fallback mechanism should be executed");
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }
      }
      else if (SSL_check_dc_enabled(ssl))
      {
        if (SSL_use_PrivateKey_dc_mem(ssl, dc_priv, sizeof(dc_priv), SSL_FILETYPE_ASN1) != 1)
        {
          emsg("Loading the DC private key error");
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }
        dmsg("Loading the DC private key success");

        if (SSL_use_delegated_credential_mem(ssl, dc, sizeof(dc)) != 1)
        {
          emsg("Loading the DC error");
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }
        dmsg("Loading the DC success");
      }
    }

    // SSL_
    ret = SSL_TLSEXT_ERR_OK;
  }

out:
  effinish("ret: %d", ret);
  return ret;
}

/**
 * @brief TLS execution with regard to the server state
 * @param ssl The TLS session context which contains the state and other materials
 * @param cctx The context of the command
 * @param mngr TLS manager
 * @return Error code
 */
SEED_Result tls_server_execution(tls_context_record_t *sctx, cctx_t *cctx, tls_manager_t *mngr)
{
  efstart("sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);
  assert(sctx != NULL);
  assert(cctx != NULL);
  assert(mngr != NULL);

  int ret, hret, offset, total, written, rlen, wlen;
  SSL *ssl;
  uint8_t rbuf[BUF_SIZE] = {0, };
  uint8_t wbuf[BUF_SIZE] = {0, };
#ifdef TIME_LOG
  logger_t *logger;
#endif /* TIME_LOG */

  ret = SEED_SUCCESS;
  ssl = sctx->ssl;
#ifdef TIME_LOG
  logger = SSL_get_time_logger(ssl);
#endif /* TIME_LOG */

  if (SSL_is_init_finished(ssl))
  {
    edmsg("The TLS session is established");
#ifdef TIME_LOG
    if (logger->trusted_cpu_func)
      logger->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].cpu = logger->trusted_cpu_func();
    if (logger->trusted_time_func)
      logger->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].time = logger->trusted_time_func();
#endif /* TIME_LOG */

    if (cctx->flags == TA_EDGE_CMD_TLS)
    {
      http_t *req, *resp;
      req = init_http_message(HTTP_TYPE_REQUEST);
      resp = init_http_message(HTTP_TYPE_RESPONSE);
      sctx->msg = (void *)resp;
      http_set_default_attributes(resp);

      rlen = SSL_read(ssl, rbuf, BUF_SIZE);
      if (rlen > 0)
        hret = http_deserialize(rbuf, rlen, req, NULL);


      cctx->flags = TA_EDGE_NXT_GET_DATA;
      cctx->stage = TA_EDGE_GET_DATA_INIT;
      set_address(cctx, name, 0);
    }

    if (cctx->flags == TA_EDGE_CMD_GET_DATA)
    {
      offset = 0;
      total = cctx->alen;
      while (offset < total)
      {
        written = SSL_write(ssl, cctx->arg + offset, cctx->alen - offset);
        if (written > 0)
          offset += written;
      }

      if (cctx->stage == TA_EDGE_GET_DATA_FINISH)
        cctx->flags = TA_EDGE_NXT_EXIT;
      cctx->stage = TA_EDGE_GET_DATA_NEXT;
    }
  }
  else
  {
    edmsg("before the TLS session is established");
    if (!sctx->start)
    {
#ifdef TIME_LOG
//      if (logger->log[SEED_LT_SERVER_BEFORE_TLS_ACCEPT].time == 0
//          || logger->log[SEED_LT_SERVER_BEFORE_TLS_ACCEPT].cpu == 0)
//      {
        if (logger->trusted_cpu_func)
          logger->log[SEED_LT_SERVER_BEFORE_TLS_ACCEPT].cpu = logger->trusted_cpu_func();
        if (logger->trusted_time_func)
          logger->log[SEED_LT_SERVER_BEFORE_TLS_ACCEPT].time = logger->trusted_time_func();
//      }
#endif /* TIME_LOG */
    }
    ret = SSL_do_handshake(ssl);
    edmsg("after SSL_do_handshake()");
    if (ret < 0)
    {
      edmsg("TLS handshake is not finished yet");
    }
  }

  //edmsg("Next Command: cctx->flags: %s", cmd_to_str(cctx->flags));
  effinish();
  return ret;
}

SEED_Result send_request_to_authority(tls_context_record_t *sctx, cctx_t *cctx, 
    tls_manager_t *mngr)
{
  efstart("sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);

  int ret, sent, len;
  uint8_t tmp[BUF_SIZE] = {0, };
  SSL *ssl;
  http_t *req;

  ret = SEED_SUCCESS;
  ssl = sctx->ssl;

  if (!sctx->msg)
  {
    req = init_http_message(HTTP_TYPE_REQUEST);
    if (!req) goto err;

    http_set_version(req, HTTP_VERSION_1_1);
    http_set_method(req, HTTP_METHOD_GET);
    http_set_domain(req, AUTHORITY_NAME, (int)strlen(AUTHORITY_NAME));
    http_set_default_attributes(req);
    http_set_abs_path(req, AUTHORITY_ABS_PATH, (int) strlen(AUTHORITY_ABS_PATH));
    sctx->msg = (void *)req;
  }
  req = (http_t *)(sctx->msg);

  http_serialize(req, tmp, BUF_SIZE, &len);
  dmsg("HTTP Request (%d bytes):\n%s", len, tmp);
  sent = SSL_write(ssl, tmp, len);
  if (sent > 0)
    http_update_resource(req, sent);

  if (sent != len) goto err;

  cctx->stage = TA_EDGE_GET_DOMAIN_REQUEST_SENT;
  free_http_message(req);
  sctx->msg = NULL;

  effinish();
  return ret;

err:
  if (req)
    free_http_message(req);

  eferr();
  return SEED_FAILURE;
}

SEED_Result recv_response_from_authority(tls_context_record_t *sctx, cctx_t *cctx, 
    tls_manager_t *mngr)
{
  efstart("sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);
  assert(cctx->flags == TA_EDGE_CMD_GET_DOMAIN);
  assert(cctx->stage == TA_EDGE_GET_DOMAIN_REQUEST_SENT);

  int ret, recv, retval, dlen, clen;
  uint8_t tmp[BUF_SIZE] = {0, };
  uint8_t *p;
  buf_t *buf, *name;
  resource_t *resource;
  domain_table_t *dom;
  http_t *resp;
  SSL *ssl;

  buf = NULL;
  name = NULL;
  ssl = sctx->ssl;

  if (!sctx->msg)
  {
    resp = init_http_message(HTTP_TYPE_RESPONSE);
    if (!resp) goto err;
    sctx->msg = (void *)resp;
  }
  resp = (http_t *)(sctx->msg);

  ret = SEED_SUCCESS;
  recv = SSL_read(ssl, tmp, BUF_SIZE);
  dmsg("recv: %d", recv);
  if (recv > 0)
  {
    retval = http_deserialize(tmp, recv, resp, NULL);
    if (retval == HTTP_FAILURE) goto err;
  }
  else
  {
    goto err;
  }

  if (resp->resource)
  {
    if (resp->resource->offset == resp->resource->size)
    {
      cctx->stage = TA_EDGE_GET_DOMAIN_RESPONSE_RCVD;
    }
  }

  if (cctx->stage == TA_EDGE_GET_DOMAIN_RESPONSE_RCVD)
  {
    dmsg("make domain list");
    resource = http_get_resource(resp);
    buf = init_memcpy_buf_mem(buf, (uint8_t *)resource->ptr, resource->size);

    while (get_buf_remaining(buf))
    {
      p = get_next_token(buf, DOMAIN_DELIMITER, &dlen);
      name = init_memcpy_buf_mem(NULL, p, dlen);
      
      dmsg("domain (%d bytes): %s", name->max, name->data);
      dom = mngr->fmngr->ops->get(mngr->fmngr, name);
      if (!dom)
      {
        dom = mngr->fmngr->ops->create(mngr->fmngr, name, NULL);
      }

      p = get_next_token(buf, DOMAIN_DELIMITER, &clen);
      dom->vops->set_certificate(dom, p, clen);
    }
  }

  effinish();
  return ret;

err:
  eferr();
  return SEED_FAILURE;
}

SEED_Result send_request_to_cc_server(tls_context_record_t *sctx, cctx_t *cctx, 
    tls_manager_t *mngr)
{
  efstart("sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);

  int ret;
  ret = SEED_SUCCESS;

  ret = cc_send_request(sctx, cctx, mngr->fmngr);

  effinish();
  return ret;
}

SEED_Result recv_response_from_cc_server(tls_context_record_t *sctx, cctx_t *cctx, 
    tls_manager_t *mngr)
{
  efstart("sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);

  int ret;
  ret = SEED_SUCCESS;

  ret = cc_process_data(sctx, cctx, mngr->fmngr);

  effinish();
  return ret;
}

/**
 * @brief TLS execution with regard to the client state
 * @param ssl The TLS session context which contains the state and other materials
 * @param cctx The context of the command
 * @param mngr TLS manager
 * @return Error code
 */
SEED_Result tls_client_execution(tls_context_record_t *sctx, cctx_t *cctx, tls_manager_t *mngr)
{
  efstart("sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);
  assert(sctx != NULL);
  assert(cctx != NULL);
  assert(mngr != NULL);

  int ret;
  SSL *ssl;

  ret = SEED_SUCCESS;
  ssl = sctx->ssl;

  if (SSL_is_init_finished(ssl))
  {
    edmsg("The TLS session is established");
    if (cctx->flags == TA_EDGE_CMD_GET_DOMAIN)
    {
      switch(cctx->stage)
      {
        case TA_EDGE_GET_DOMAIN_INIT:
          ret = send_request_to_authority(sctx, cctx, mngr);
          break;
        case TA_EDGE_GET_DOMAIN_REQUEST_SENT:
          ret = recv_response_from_authority(sctx, cctx, mngr);
          if (ret == SEED_SUCCESS)
            ret = mngr->fmngr->vops->check_need_cross_credential(mngr->fmngr, cctx);
          break;
        case TA_EDGE_GET_DOMAIN_RESPONSE_RCVD:
          emsg("Should not be happened");
          ret = mngr->fmngr->vops->check_need_cross_credential(mngr->fmngr, cctx);
          break;
        default:
          break;
      }
    }
    else if (cctx->flags == TA_EDGE_CMD_GET_CC)
    {
      edmsg("Current Command: cctx->flags: %d", cctx->flags);
      switch(cctx->stage)
      {
        case TA_EDGE_GET_CC_INIT:
          ret = send_request_to_cc_server(sctx, cctx, mngr);
          break;
        case TA_EDGE_GET_CC_REQUEST_SENT:
          ret = recv_response_from_cc_server(sctx, cctx, mngr);
          if (ret == SEED_SUCCESS)
            ret = mngr->fmngr->vops->check_need_cross_credential(mngr->fmngr, cctx);
          edmsg("Next Command: cctx->flags: %d", cctx->flags);
          break;                                                        
        case TA_EDGE_GET_CC_RESPONSE_RCVD:
          emsg("Should not be happened");
          break;
        default:
          break;
      }
    }
  }
  else
  {
    edmsg("before the TLS session is established");
    edmsg("ssl: %p, SSL_do_handshake: %p", ssl, SSL_do_handshake);
    ret = SSL_do_handshake(ssl);
    edmsg("after SSL_do_handshake()");
    if (ret < 0)
    {
      edmsg("TLS handshake is not finished yet");
    }
  }

  //edmsg("Next Command: cctx->flags: %s", cmd_to_str(cctx->flags));
  effinish();
  return ret;
}

/** 
 * @brief Initialize the context of the TLS server
 * @param mngr The file manager which has the EC keypair
 * @return The TLS server context
 */
SSL_CTX *init_server_ctx(file_manager_t *mngr, int resumption)
{
  efstart("mngr: %p", mngr);
  assert(mngr != NULL);

  SSL_METHOD *method;
  SSL_CTX *ret;
  EC_KEY *ecdh;
  const uint8_t http1_1[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

  ret = NULL;
  method = (SSL_METHOD *) TLS_server_method();
  ret = SSL_CTX_new(method);

  SSL_CTX_set_max_proto_version(ret, TLS1_3_VERSION);
  //SSL_CTX_set_ciphersuites(ret, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_AES_WITH_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
  SSL_CTX_set_ciphersuites(ret, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
  SSL_CTX_set_alpn_protos(ret, http1_1, sizeof(http1_1));

  if (resumption)
  {
    dmsg("Session cache");
    SSL_CTX_set_session_cache_mode(ret, SSL_SESS_CACHE_BOTH);
  }
  else
  {
    dmsg("No session cache");
    SSL_CTX_set_session_cache_mode(ret, SSL_SESS_CACHE_OFF);
  }

  edmsg("initialize ssl_ctx finished: %p", (void *)ret);

  // TODO: implement the list of the trusted CA certificate

  //SSL_CTX_set_file_manager(ret, (void *)mngr);
  SSL_CTX_set_fallback(ret, 1);
#ifdef PLATFORM_OPTEE
  SSL_CTX_set_get_seed_digest(ret, get_optee_seed_digest);
#elif PLATFORM_SGX
  SSL_CTX_set_get_seed_digest(ret, get_sgx_seed_digest); // This is the test function.
#endif /* PLATFORM DIGEST */

  edmsg("Before load certificate");
  if (SSL_CTX_use_certificate_ASN1(ret, mngr->pair->crt_len, mngr->pair->crt) != 1)
  {
    eemsg("load certificate error");
    abort();
  }
  edmsg("load certificate success");

  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, ret, mngr->pair->priv, mngr->pair->priv_len) != 1)
  {
    eemsg("load private key error");
    abort();
  }
  edmsg("load private key success");

  if (SSL_CTX_check_private_key(ret) != 1)
  {
    eemsg("check private key failed");
  }
  edmsg("check private key success");

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
  {
    eemsg("initialize ecdh error");
  }

  if (SSL_CTX_set_tmp_ecdh(ret, ecdh) != 1)
  {
    eemsg("set ecdh error");
  }

  SSL_CTX_set_tlsext_servername_callback(ret, check_contractor);
  SSL_CTX_set_tlsext_servername_arg(ret, (void *)mngr);

  effinish("ret: %p", ret);
  return ret;
}

/** 
 * @brief Initialize the context of the TLS server
 * @param mngr The file manager which has the EC keypair
 * @return The TLS server context
 */
SSL_CTX *init_client_ctx(file_manager_t *mngr, int resumption)
{
  efstart("mngr: %p", mngr);
  assert(mngr != NULL);

  (void) resumption;

  SSL_METHOD *method;
  SSL_CTX *ret;
  EC_KEY *ecdh;
  const uint8_t http1_1[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

  ret = NULL;
  method = (SSL_METHOD *) TLS_client_method();
  ret = SSL_CTX_new(method);

  if (!ret) 
    return NULL;

  SSL_CTX_set_max_proto_version(ret, TLS1_3_VERSION);
  //SSL_CTX_set_ciphersuites(ret, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
  SSL_CTX_set_ciphersuites(ret, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
  SSL_CTX_set_alpn_protos(ret, http1_1, sizeof(http1_1));

  edmsg("initialize ssl_ctx finished: %p", (void *)ret);

  // TODO: implement the list of the trusted CA certificate

  edmsg("Before load certificate");
  if (SSL_CTX_use_certificate_ASN1(ret, mngr->pair->crt_len, mngr->pair->crt) != 1)
  {
    eemsg("load certificate error");
    abort();
  }
  edmsg("load certificate success");

  if (SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, ret, mngr->pair->priv, mngr->pair->priv_len) != 1)
  {
    eemsg("load private key error");
    abort();
  }
  edmsg("load private key success");

  if (SSL_CTX_check_private_key(ret) != 1)
  {
    eemsg("check private key failed");
  }
  edmsg("check private key success");

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
  {
    eemsg("initialize ecdh error");
  }

  if (SSL_CTX_set_tmp_ecdh(ret, ecdh) != 1)
  {
    eemsg("set ecdh error");
  }

  effinish("ret: %p", ret);
  return ret;
}


/**
 * @brief Free the memory allocated for the TLS context
 */
void free_ctx(SSL_CTX *ctx)
{
  efstart("ctx: %p", ctx);
  
  if (ctx)
  {
    SSL_CTX_free(ctx);
    ctx = NULL;
  }

  effinish();
}

/**
 * @brief Initialize the TLS session context of the TLS server
 * @param ctx The base context of the TLS server
 * @param time_log The log structure
 */
// TODO: Add the domain name to fetch the certificate as well as CC
SSL *init_tls_server_context(tls_manager_t *mngr, cctx_t *cctx, void *logger)
{
  efstart("mngr: %p, cctx: %p, logger: %p", mngr, cctx, logger);
  assert(mngr != NULL);

  SSL *ssl;
  BIO *rbio, *wbio;
  int mode;

  ssl = SSL_new(mngr->ctx);
  if (!ssl) goto exit;

  rbio = BIO_new(BIO_s_mem());
  if (!rbio) goto exit;

  wbio = BIO_new(BIO_s_mem());
  if (!wbio) goto exit;

  mode = cctx->mode;

  SSL_set_bio(ssl, rbio, wbio);
  SSL_set_accept_state(ssl);
#ifdef TIME_LOG
  SSL_set_time_logger(ssl, (logger_t *)logger);
#endif /* TIME_LOG */

  if (mode == EDGE_MODE_SEED)
    SSL_enable_seed(ssl);
  else if (mode == EDGE_MODE_DC)
    SSL_enable_dc(ssl);
  else if (mode == EDGE_MODE_KEYLESS)
    SSL_enable_keyless_ssl(ssl);
  else if (mode == EDGE_MODE_MBTLS)
    SSL_enable_mbtls(ssl);
  else if (mode == EDGE_MODE_SPX)
    SSL_enable_spx(ssl);

  SSL_set_seed_digest_buf(ssl, mngr->seed_digest, mngr->ht, mngr->len);
  ffinish("ssl: %p", ssl);
  return ssl;

exit:
  eemsg("Error in setting ssl");
  if (ssl)
    SSL_free(ssl);
  ssl = NULL;

  effinish();
  return ssl;
}

/**
 * @brief Initialize the TLS session context of the TLS server
 * @param ctx The base context of the TLS server
 * @param time_log The log structure
 */
// TODO: Add the domain name to fetch the certificate as well as CC
SSL *init_tls_client_context(tls_manager_t *mngr, cctx_t *cctx, void *logger)
{
  efstart("mngr: %p, cctx: %p, logger: %p", mngr, cctx, logger);
  assert(mngr != NULL);

  SSL *ssl;
  BIO *rbio, *wbio;
  buf_t *name;
  name = NULL;

  ssl = SSL_new(mngr->ctx);
  if (!ssl) goto exit;

  rbio = BIO_new(BIO_s_mem());
  if (!rbio) goto exit;

  wbio = BIO_new(BIO_s_mem());
  if (!wbio) goto exit;

  get_address(cctx, &name, NULL);

  SSL_set_bio(ssl, rbio, wbio);
  SSL_set_connect_state(ssl);
  SSL_set_seed_digest_buf(ssl, mngr->seed_digest, mngr->ht, mngr->len);
  dmsg("name (%d bytes): %s", name->max, name->data);
  SSL_set_tlsext_host_name(ssl, name->data);

#ifdef TIME_LOG
  SSL_set_time_logger(ssl, (logger_t *)logger);
#endif /* TIME_LOG */

  ffinish("ssl: %p", ssl);
  return ssl;

exit:
  eemsg("Error in setting ssl");
  if (ssl)
    SSL_free(ssl);
  ssl = NULL;

  effinish();
  return ssl;
}

/**
 * @brief Free the memory space allocated for the TLS session context
 * @param the TLS session context to be freed
 */
void free_tls_context(tls_context_record_t *sctx)
{
  efstart("sctx: %p", sctx);

  if (sctx)
  {
    if (sctx->ssl)
    {
      SSL_free(sctx->ssl);
      sctx->ssl = NULL;
    }

    if (sctx->ch)
    {
      free(sctx->ch);
      sctx->ch = NULL;
    }
  }

  effinish();
}
