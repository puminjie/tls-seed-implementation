#include <openssl/err.h>
#include <edge.h>
#include <err.h>
#include <debug.h>
#include <string.h>
#include <defines.h>
#include <cc.h>
#if (defined PLATFORM_OPTEE || defined PLATFORM_SGX)
  #include <cmds.h>
#endif /* PLATFORM COMMANDS */

#ifdef TIME_LOG
#include "../logger/seed_names.h"
#endif /* TIME_LOG */

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <simple_http/simple_https.h>

#include "keyless.h"
#include "keyless_kssl_helpers.h"
#include "keyless_kssl_log.h"

void initialization(void)
{
  fstart();
  int i;
  for (i=0; i<MAX_THREADS; i++)
  {
    g_ebase[i] = event_base_new();
    occupied[i] = 0;
  }
  ffinish();
}

void finalization(void)
{
  fstart();
  int i;
  for (i=0; i<MAX_THREADS; i++)
  {
    if (g_ebase[i])
      event_base_free(g_ebase[i]);
    occupied[i] = 0;
    g_ebase[i] = NULL;
  }
  ffinish();
}

struct event_base *get_event_base(int *idx)
{
  fstart("idx: %p", idx);
  int i;
  struct event_base *ret;
  for (i=0; i<MAX_THREADS; i++)
  {
    if (occupied[i] == 0)
      break;
  }
  *idx = i;

  if (i < MAX_THREADS)
  {
    ret = g_ebase[i];
    occupied[i] = 1;
  }
  else
    ret = NULL;

  ffinish("ret: %p", ret);
  return ret;
}

arg_t *init_arg(void)
{
  fstart();
  arg_t *ret;
  ret = (arg_t *)malloc(sizeof(arg_t));
  memset(ret, 0x0, sizeof(arg_t));

  ffinish();
  return ret;
}

#ifdef PLATFORM_VANILA
void arg_set_cert(arg_t *arg, const char *cert)
{
  fstart("arg: %p, cert: %s", arg, cert);
  assert(arg != NULL);
  assert(cert != NULL);

  arg->cert = cert;
  ffinish();
}

void arg_set_key(arg_t *arg, const char *key)
{
  fstart("arg: %p, key: %s", arg, key);
  assert(arg != NULL);
  assert(key != NULL);

  arg->key = key;
  ffinish();
}
#elif PLATFORM_SGX
void arg_set_enclave(arg_t *arg, const char *enclave)
{
  fstart("arg: %p, enclave: %s", arg, enclave);
  assert(arg != NULL);
  assert(enclave != NULL);

  arg->enclave = enclave;
  ffinish();
}
#endif /* PLATFORM ARGUMENT FUNCTIONS */

void arg_set_mode(arg_t *arg, int mode)
{
  fstart("arg: %p, mode: %d", arg, mode);
  arg->mode = mode;
  ffinish();
}

void arg_set_resumption(arg_t *arg, int resumption)
{
  fstart("arg: %p, resumption: %d", arg, resumption);
  arg->resumption = resumption;
  ffinish();
}

void free_arg(arg_t *arg)
{
  fstart("arg: %p", arg);
  if (arg)
    free(arg);
  ffinish();
}

#ifdef PLATFORM_VANILA
int check_contractor(SSL *ssl, int *ad, void *arg)
{
  fstart("ssl: %p, ad: %p, arg: %p", ssl, ad, arg);

  int ret, tmp;
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  FILE *fp;
  ec_ctx_t *ctx;
  domain_t *dom;
  X509 *x;
  BIO *in;

  ret = SSL_TLSEXT_ERR_OK;
  ctx = (ec_ctx_t *)arg;
  x = NULL;
  in = NULL;

  dmsg("Requested name: %s", name);
  dom = find_domain(ctx->list, (uint8_t *)name, (int)strlen(name));

  if (!dom)
  {
    emsg("This is not a service provider: %s", name);
    emsg("Now the fallback mechanism should be executed");
    SSL_set_fallback(ssl, 1);
    ret = SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  else
  {
    if (SSL_is_server(ssl))
    {
      dmsg("dom->domain: %s, dom->clen: %d, dom->cert: %p", dom->domain, dom->clen, dom->cert);
      if (SSL_check_seed_enabled(ssl))
      {
        if (dom->clen > 0 && dom->cert)
        {
          in = BIO_new(BIO_s_mem());
          tmp = BIO_write(in, dom->cert, dom->clen);
          SSL_load_error_strings();
          ERR_print_errors_fp(stderr);
          if (!PEM_read_bio_X509(in, &x, NULL, NULL))
            emsg("PEM_read_bio_X509 error()");
          tmp = SSL_use_orig_certificate(ssl, x);
        }
        else
        {
          emsg("Loading the service provider %s's certificate error", name);
          emsg("Now the fallback mechanism should be executed");
          SSL_set_fallback(ssl, 1);
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }

        if (dom->cclen > 0 && dom->cc)
        {
          SSL_use_cc_mem(ssl, dom->cc, (size_t)dom->cclen);
        }
        else
        {
          emsg("Loading the cross credential with %s error", name);
          emsg("Now the fallback mechanism should be executed");
          SSL_set_fallback(ssl, 1);
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }
      }
      else if (SSL_check_dc_enabled(ssl))
      {
        char dc_priv_file_path[MAX_FILE_NAME_LEN] = {0, };
        char dc_file_path[MAX_FILE_NAME_LEN] = {0, };

        snprintf(dc_priv_file_path, MAX_FILE_NAME_LEN, "%s/%s", name, DEFAULT_DC_PRIV_NAME);
        snprintf(dc_file_path, MAX_FILE_NAME_LEN, "%s/%s", name, DEFAULT_DC_NAME);

        if (access(dc_priv_file_path, F_OK) == -1)
        {
          emsg("DC private file not found");
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }
        else if (access(dc_file_path, F_OK) == -1)
        {
          emsg("DC file not found");
          ret = SSL_TLSEXT_ERR_ALERT_FATAL;
          goto out;
        }
        else
        {
          if (SSL_use_PrivateKey_dc_file(ssl, dc_priv_file_path, SSL_FILETYPE_ASN1) != 1)
          {
            emsg("Loading the delegated credential private key error");
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
            goto out;
          }
          dmsg("Loading the DC private key success");

          if (SSL_use_delegated_credential_file(ssl, dc_file_path) != 1)
          {
            emsg("Loading the DC error");
            ret = SSL_TLSEXT_ERR_ALERT_FATAL;
            goto out;
          }
          dmsg("Loading the DC success");
        }
      }
    }
  }

out:
  ffinish("ret: %d", ret);
  return ret;
}

int get_vanila_seed_digest(uint8_t *buf, uint16_t *ht, size_t *len)
{
  fstart("buf: %p, ht: %p, len: %p", buf, ht, len);

  int ret;

  *ht = NID_sha256;
  *len = SHA256_DIGEST_LENGTH;
  memcpy(buf, "2", *len);

  ret = SEED_SUCCESS;
  ffinish("ret: %d", ret);
  return ret;
}

int keyless_ssl_callback(SSL *ssl, uint8_t *out, uint8_t *in, uint32_t ilen, size_t *slen)
{
  fstart("ssl: %p, out: %p, in: %p, ilen: %d, slen: %p", ssl, out, in, ilen, slen);

  int ret, nid;
  connection *c;
  c = (connection *)(SSL_get_keyless_ssl_arg(ssl));

  kssl_op_ecdsa_sign(c, in ,ilen, out, slen, 3);

  ffinish();
  return SEED_SUCCESS;
}

connection *prepare_keyless_ssl(void)
{
  fstart();

  SSL_CTX *kctx;
  connection *c;
  const SSL_METHOD *method;
  const char *cipher_list = "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";

  method = TLS_client_method();
  kctx = SSL_CTX_new(method);
  
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (NULL == ecdh) {
    SSL_CTX_free(kctx);
    fatal_error("ECDSA new curve error");
  }

  if(SSL_CTX_set_tmp_ecdh(kctx, ecdh) != 1) {
    SSL_CTX_free(kctx);
    fatal_error("Call to SSL_CTX_set_tmp_ecdh failed");
  }
  
  if (SSL_CTX_set_ciphersuites(kctx, cipher_list) == 0) {
    SSL_CTX_free(kctx);
    fatal_error("Failed to set cipher list: %s", cipher_list);
  }

  //SSL_CTX_set_verify(kctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
  //SSL_CTX_set_verify(kctx, SSL_VERIFY_PEER, 0);

  if (SSL_CTX_load_verify_locations(kctx, CA_PATH, 0) != 1) {
    SSL_CTX_free(kctx);
    fatal_error("Failed to load CA file %s", CA_PATH);
  }

  if (SSL_CTX_set_default_verify_paths(kctx) != 1) {
    SSL_CTX_free(kctx);
    fatal_error("Call to SSL_CTX_set_default_verify_paths failed");
  }

  if (SSL_CTX_use_certificate_file(kctx, CERT_PATH, SSL_FILETYPE_PEM) != 1) {
    SSL_CTX_free(kctx);
    fatal_error("Failed to load client certificate from %s", CERT_PATH);
  }

  if (SSL_CTX_use_PrivateKey_file(kctx, KEY_PATH, SSL_FILETYPE_PEM) != 1) {
    SSL_CTX_free(kctx);
    fatal_error("Failed to load client private key from %s", KEY_PATH);
  }

  if (SSL_CTX_check_private_key(kctx) != 1) {
    SSL_CTX_free(kctx);
    fatal_error("SSL_CTX_check_private_key failed");
  }

  c = ssl_connect(kctx, KEY_SERVER_NAME, KEY_SERVER_PORT);

  ffinish("c: %p", c);
  return c;
}

ec_ctx_t *init_vanila_edge_ctx(arg_t *arg)
{
  fstart("arg: %p", arg);
  ec_ctx_t *ret;
  SSL_METHOD *method;
  EC_KEY *ecdh;
  const uint8_t http1_1[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
  FILE *fp;
  uint8_t cname[MAX_FILE_NAME_LEN] = {0, };
  uint8_t *cert;
  int clen, tmp;

  ret = (ec_ctx_t *)malloc(sizeof(ec_ctx_t));
  method = (SSL_METHOD *) TLS_method();
  ret->ctx = SSL_CTX_new(method);
  ret->list = init_domain_list();

  snprintf((char *)cname, MAX_FILE_NAME_LEN, "%s/auth_cert.pem", AUTHORITY_NAME);
  if (access(cname, F_OK) == -1)
  {
    emsg("The certificate of the authority is wrong: %s", cname);
    abort();
  }
  fp = fopen(cname, "r");
  fseek(fp, 0L, SEEK_END);
  clen = (int)ftell(fp);
  fseek(fp, 0L, SEEK_SET);
  cert = (uint8_t *)malloc(clen);
  memset(cert, 0x0, clen);
  tmp = fread(cert, 1, clen - 1, fp);
  dmsg("tmp: %d, clen: %d", tmp, clen);
  dmsg("Edge platform ceritificate:\n%s", cert);
  add_domain_cert(ret->list, AUTHORITY_NAME, strlen(AUTHORITY_NAME), cert, clen);

  SSL_CTX_set_max_proto_version(ret->ctx, TLS1_3_VERSION);
  //SSL_CTX_set_ciphersuites(ret->ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
  SSL_CTX_set_ciphersuites(ret->ctx, "TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
  SSL_CTX_set_alpn_protos(ret->ctx, http1_1, sizeof(http1_1));
  if (arg->mode != SERVER_MODE_VANILA)
  {
    SSL_CTX_set_tlsext_servername_callback(ret->ctx, check_contractor);
    SSL_CTX_set_tlsext_servername_arg(ret->ctx, ret);
  }

  if (arg->resumption)
  {
    dmsg("Session cache");
    SSL_CTX_set_session_cache_mode(ret->ctx, SSL_SESS_CACHE_BOTH);
  }
  else
  {
    dmsg("No session cache");
    SSL_CTX_set_session_cache_mode(ret->ctx, SSL_SESS_CACHE_OFF);
  }

  if (SSL_CTX_use_certificate_file(ret->ctx, arg->cert, SSL_FILETYPE_ASN1) <= 0)
  {
    emsg("SSL_CTX_use_certificate_file() error");
    abort();
  }
  imsg("SSL_CTX_use_certificate_file() success");

  if (SSL_CTX_use_PrivateKey_file(ret->ctx, arg->key, SSL_FILETYPE_ASN1) <= 0)
  {
    emsg("SSL_CTX_use_PrivateKey_file() error");
    abort();
  }
  imsg("SSL_CTX_use_PrivateKey_file() success");

  if (!SSL_CTX_check_private_key(ret->ctx))
  {
    emsg("SSL_CTX_check_private_key() error");
    abort();
  }
  imsg("SSL_CTX_check_private_key() success");

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ecdh)
  {
    emsg("Set ECDH error");
    abort();
  }
  imsg("Set ECDH success");

  if (SSL_CTX_set_tmp_ecdh(ret->ctx, ecdh) != 1)
  {
    emsg("SSL_CTX_set_tmp_ecdh error");
    abort();
  }

  ffinish("ret: %p", ret);
  return ret;
}

int init_vanila_domains(ec_ctx_t *ctx)
{
  fstart("ctx: %p", ctx);
  int ret, sock, err, dlen, clen;
  uint8_t domain[BUF_SIZE + 1] = {0, };
  uint8_t cert[BUF_SIZE + 1] = {0, };
  uint8_t *p;
  http_t *req, *resp;
  buf_t *buf;
  resource_t *resource;
  SSL *ssl;

  ret = SUCCESS;
  ssl = SSL_new(ctx->ctx);
  err = 0;
  buf = NULL;

  // Make HTTP Request
  req = init_http_message(HTTP_TYPE_REQUEST);
  if (!req) goto err;
  http_set_version(req, HTTP_VERSION_1_1);
  http_set_method(req, HTTP_METHOD_GET);
  http_set_domain(req, AUTHORITY_NAME, (int) strlen(AUTHORITY_NAME));
  http_set_default_attributes(req);
  http_set_abs_path(req, AUTHORITY_ABS_PATH, (int) strlen(AUTHORITY_ABS_PATH));

  // Make HTTP Response
  resp = init_http_message(HTTP_TYPE_RESPONSE);
  if (!resp) goto err;

  sock = open_connection(AUTHORITY_NAME, AUTHORITY_PORT, 1); 
  if (sock < 0)
    abort();
  dmsg("sock: %d", sock);
  SSL_set_fd(ssl, sock);
  SSL_set_connect_state(ssl);
  SSL_set_tlsext_host_name(ssl, AUTHORITY_NAME);

  while (!err)
  {
    ret = SSL_do_handshake(ssl);
    err = process_error(ssl, ret);

    if (err < 0) 
    {
      emsg("Failed to SSL connect()");
      ERR_print_errors_fp(stderr);
      goto err;
    }
  }
  dmsg("TLS session is established with %s", SSL_get_cipher(ssl));

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = send_https_message(ssl, req);
  if (ret != HTTP_SUCCESS) goto err;

  ret = HTTP_NOT_FINISHED;
  while (ret == HTTP_NOT_FINISHED)
    ret = recv_https_message(ssl, resp, NULL);
  if (ret != HTTP_SUCCESS) goto err;

  resource = http_get_resource(resp);
  buf = init_memcpy_buf_mem(buf, (uint8_t *)resource->ptr, resource->size);

  while (get_buf_remaining(buf))
  {
    // Domain
    p = get_next_token(buf, DOMAIN_DELIMITER, &dlen);
    memcpy(domain, p, dlen);

    // Certificate
    p = get_next_token(buf, DOMAIN_DELIMITER, &clen);
    memcpy(cert, p, clen);

    add_domain_cert(ctx->list, domain, dlen, cert, clen);
  }

  print_domain_list(ctx->list);

  ffinish();
  return ret;

err:
  ferr();
  return ret;
}

int init_vanila_cross_credentials(ec_ctx_t *ctx)
{
  fstart("ctx: %p", ctx);

  SSL *ssl;
  int ret, cc_server, err, rcvd;
  uint8_t buf[BUF_SIZE + 1] = {0, };
  domain_t *curr;

  ssl = NULL;
  ret = SUCCESS;
  err = 0;
  curr = ctx->list->head;

  while (curr)
  {
    if (curr->dlen == strlen(AUTHORITY_NAME) 
        && !strncmp(curr->domain, AUTHORITY_NAME, curr->dlen))
    {
      curr = curr->next;
      continue;
    }

    if (curr->dlen == strlen(FALLBACK_TEST_NAME)
        && !strncmp(curr->domain, FALLBACK_TEST_NAME, curr->dlen))
    {
      curr = curr->next;
      continue;
    }

    dmsg("CC Generation: %s", curr->domain);
    cc_server = open_connection(curr->domain, DEFAULT_CC_SERVER_PORT, 1);
    dmsg("TCP established: %d", cc_server);
    ssl = SSL_new(ctx->ctx);
    if (!ssl)
    {
      emsg("Out of memory");
      goto err;
    }
    SSL_set_fd(ssl, cc_server);
    SSL_set_get_seed_digest(ssl, get_vanila_seed_digest);
    SSL_set_seed_digest(ssl);
    SSL_set_connect_state(ssl);
    SSL_set_tlsext_host_name(ssl, curr->domain);

    err = 0;
    while (!err)
    {
      ret = SSL_do_handshake(ssl);
      err = process_error(ssl, ret);

      if (err < 0)
      {
        emsg("Failed to SSL_connect()");
        ERR_print_errors_fp(stderr);
        abort();
      }
    }
    dmsg("The TLS session is established with the CC server");

    dmsg(">>>>> before CC send request");
    cc_send_request(ssl);
    dmsg(">>>>> after CC send request");
    rcvd = -1;

    while (rcvd < 0)
      rcvd = SSL_read(ssl, buf, BUF_SIZE);
    dmsg(">>>>> before CC process data");
    cc_process_data(ssl, buf, rcvd);
    dmsg(">>>>> after CC process data");

    curr->cclen = rcvd;
    curr->cc = (uint8_t *)malloc(curr->cclen);
    if (!curr->cc) 
    {
      emsg("Out of memory");
      goto err;
    }
    memcpy(curr->cc, buf, curr->cclen);

    dprint("Received CC", curr->cc, 0, curr->cclen, 16);
    SSL_shutdown(ssl);

    if (ssl)
    {
      SSL_free(ssl);
      ssl = NULL;
    }
    close(cc_server);
    cc_server = -1;

    curr = curr->next;
  }

  dmsg("after fetching CCs");
  print_domain_list(ctx->list);

  ffinish();
  return ret;

err:
  ferr();
  return FAILURE;
}
#endif /* PLATFORM_VANILA */

#ifdef PLATFORM_OPTEE
// TODO: implement the following functions
ec_ctx_t *init_optee_edge_ctx(arg_t *arg)
{
  fstart("arg: %p", arg);
  ec_ctx_t *ret;
  cctx_t *cctx;
  uint32_t origin;
  TEEC_UUID uuid = TA_EDGE_UUID;
  TEEC_Result res;
  TEEC_Operation op;

  ret = (ec_ctx_t *)malloc(sizeof(ec_ctx_t));
  memset(ret, 0x0, sizeof(ec_ctx_t));
  res = TEEC_InitializeContext(NULL, &(ret->ctx));
  ret->init = (forwarder_t *)malloc(sizeof(forwarder_t));
  init_iom(&(ret->init->iom), &(ret->ctx), INITIALIZER);
  cctx = get_cmd_ctx(ret->init->iom);

  if (res != TEEC_SUCCESS)
  {
    emsg("TEEC_InitializeContext failed with code 0x%x", res);
  }
  dmsg("after initialize context: ret->ctx");

  res = TEEC_OpenSession(&(ret->ctx), &(ret->sess), &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &origin);
  if (res != TEEC_SUCCESS)
  {
    emsg("TEEC_OpenSession failed with code 0x%x origin 0x%x", res, origin);
  }
  dmsg("after open session: ret->sess: %p", ret->sess);

  set_op(&op, ret->init->iom, NULL);
  res = TEEC_InvokeCommand(&ret->sess, cctx->flags, &op, &origin);

  assert(ret != NULL);
  ffinish("ret: %p", ret);
  return ret;
}
#endif /* PLATFORM_OPTEE */

#ifdef PLATFORM_SGX
// TODO: implement the following functions
ec_ctx_t *init_sgx_edge_ctx(arg_t *arg)
{
  fstart("arg: %p", arg);
  ec_ctx_t *ret;
  int retval, val;
  int updated;
  int debug;
  cctx_t *cctx;

  ret = (ec_ctx_t *)malloc(sizeof(ec_ctx_t));
  memset(ret, 0x0, sizeof(ec_ctx_t));
  ret->init = (forwarder_t *)malloc(sizeof(forwarder_t));
  init_iom(&(ret->init->iom), NULL, INITIALIZER);
  cctx = get_cmd_ctx(ret->init->iom);

#ifdef DEBUG
  debug = 1;
#else
  debug = 0;
#endif /* DEBUG */
  dmsg("Enclave path: %s", arg->enclave);
  retval = sgx_create_enclave(arg->enclave, debug, &(ret->token), &updated, &(ret->id), NULL);
  if (retval != SGX_SUCCESS)
  {
    emsg("Failed to create enclave: %d - %#x", retval, retval);
    abort();
  }
  dmsg("Succeed to create enclave: id: %lu", ret->id);

  retval = t_sgxssl_invoke_command(ret->id, &val, cctx->flags, ret->init->iom);
  if (retval != SGX_SUCCESS)
  {
    emsg("Failed to invoke commands: %d - %#x", retval, retval);
    abort();
  }

  ffinish("ret: %p", ret);
  return ret;
}
#endif /* PLATFORM_SGX */

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
int tee_client_operation(ec_ctx_t *ctx)
{
  fstart("ctx: %p", ctx);
  int sock, sent, recv, slen, rlen, offset, flag;
  struct sockaddr_in local;
  socklen_t len;
  cctx_t *cctx;
  hiom_t *hiom;
  uint8_t rbuf[BUF_SIZE], wbuf[BUF_SIZE];
  uint8_t host[MAX_HOST_LEN];
  uint16_t port;
  int val;
#ifdef PLATFORM_OPTEE 
  uint32_t origin;
  TEEC_Result ret;
  TEEC_Operation op;
#elif PLATFORM_SGX
  int ret;
#endif /* PLATFORM_TEE */

  hiom = ctx->init->iom;
  cctx = get_cmd_ctx(hiom);

  if (cctx->flags != TA_EDGE_CMD_GET_DOMAIN && cctx->flags != TA_EDGE_CMD_GET_CC)
  {
    emsg("Incorrect command: %d", cctx->flags);
    abort();
  }

  flag = cctx->flags;
  get_address(cctx->arg, cctx->alen, host, &port);
  dmsg("host: %s, port: %d", host, port);
  sock = open_connection((uint8_t *)host, port, 1);
  if (sock < 0) 
  {
    emsg("socket error");
    goto err;
  }
  dmsg("sock: %d", sock);

  memset(&local, 0x0, sizeof(local));
  len = sizeof(local);
  getsockname(sock, (struct sockaddr *)&local, &len);
  set_client(hiom, (uint32_t) local.sin_addr.s_addr, (uint16_t) ntohs(local.sin_port));

#ifdef PLATFORM_OPTEE
  set_op(&op, ctx->init->iom, NULL);
#endif /* PLATFORM_OPTEE */

  while (1)
  {
    if ((rlen = read(sock, rbuf, BUF_SIZE)) >= 0)
    {
      dmsg("rlen: %d", rlen);
      if (rlen == 0)
      {
        emsg("socket is closed by peer");
        break;
      }
      offset = 0;
      while (offset < rlen)
      {
        recv = forward_to_secure_world(hiom, rbuf + offset, rlen - offset);
        if (recv > 0)
        {
          dmsg("Receive %d bytes from out world", recv);
          offset += recv;
        }
      }
    }

#ifdef PLATFORM_OPTEE
    ret = TEEC_InvokeCommand(&ctx->sess, cctx->flags, &op, &origin);
#elif PLATFORM_SGX
    val = t_sgxssl_invoke_command(ctx->id, &ret, cctx->flags, ctx->init->iom);
#endif /* PLATFORM_TEE */

    if ((slen = forward_to_out_world(hiom, wbuf, BUF_SIZE)) > 0)
    {
      dmsg("slen: %d", slen);
      offset = 0;
      while (offset < slen)
      {
        sent = write(sock, wbuf + offset, slen - offset);
        if (sent > 0)
        {
          dmsg("Send %d bytes to out world", sent);
          offset += sent;
        }
      }
    }

    dmsg("cctx->flags: %d, cctx->stage: %d", cctx->flags, cctx->stage);
    if (cctx->flags != flag) 
    {
      dmsg("Now close the session");
      break;
    }
  }

#ifdef PLATFORM_OPTEE
  ret = TEEC_InvokeCommand(&ctx->sess, TA_EDGE_CMD_FINISH, &op, &origin);
#elif PLATFORM_SGX
  val = t_sgxssl_invoke_command(ctx->id, &ret, TA_EDGE_CMD_FINISH, ctx->init->iom);
#endif /* PLATFORM_TEE */

  close(sock);
  ffinish();
  return ret;

err:
  ferr();
  return SEED_FAILURE;
}

int init_tee_domains(ec_ctx_t *ctx)
{
  fstart("ctx: %p", ctx);
  int ret;
  ret = tee_client_operation(ctx);
  ffinish();
  return ret;
}

int init_tee_cross_credentials(ec_ctx_t *ctx)
{
  fstart("ctx: %p", ctx);
  int ret;
  hiom_t *hiom;
  cctx_t *cctx;

  ret = SEED_SUCCESS;

  hiom = ctx->init->iom;
  cctx = get_cmd_ctx(hiom);

  while (cctx->flags != TA_EDGE_NXT_EXIT)
    ret = tee_client_operation(ctx);

  free_iom(hiom);

  ffinish();
  return ret;
}

#endif /* PLATFORM_TEE */

ec_ctx_t *init_edge_ctx(arg_t *arg)
{
  fstart("arg: %p", arg);
  ec_ctx_t *ret;

  init_http_module();
#ifdef PLATFORM_VANILA
  ret = init_vanila_edge_ctx(arg);
  init_vanila_domains(ret);
  if (arg->mode == EDGE_MODE_SEED)
    init_vanila_cross_credentials(ret);
#elif PLATFORM_OPTEE
  ret = init_optee_edge_ctx(arg);
#elif PLATFORM_SGX
  ret = init_sgx_edge_ctx(arg);
#else
  ret = NULL;
#endif /* PLATFORM INIT */

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  init_tee_domains(ret);
  init_tee_cross_credentials(ret);
#endif /* PLATFORM_TEE */

  assert(ret != NULL);
  ffinish("ret: %p", ret);
  return ret;
}

void free_edge_ctx(ec_ctx_t *ctx)
{
  fstart("ctx: %p", ctx);

  if (ctx)
  {
#ifdef PLATFORM_VANILA
    dmsg("ctx->ctx: %p", ctx->ctx);
    if (ctx->ctx)
    {
      SSL_CTX_free(ctx->ctx);
      ctx->ctx = NULL;
    }

    if (ctx->list)
    {
      free_domain_list(ctx->list);
      ctx->list = NULL;
    }
#endif /* PLATFORM_VANILA */
  }

  ffinish();
}

#ifdef PLATFORM_VANILA
client_t *init_vanila_client_ctx(info_t *info)
{
  fstart("info: %p", info);

  client_t *ret;
  ec_ctx_t *ctx;
  BIO *rbio;
  BIO *wbio;

  ret = (client_t *)malloc(sizeof(client_t));
  memset(ret, 0x0, sizeof(client_t));
  ctx = info->ctx;
  rbio = NULL;
  wbio = NULL;

#ifdef TIME_LOG
  ret->logger = init_logger(info->log_directory, info->log_prefix, info->msgs, info->flags, 
      info->context);
#endif /* TIME_LOG */

  ret->ssl = SSL_new(ctx->ctx);
  if (!ret->ssl)
  {
    emsg("SSL initialization error");
    abort();
  }
  imsg("SSL initialization success");

  rbio = BIO_new(BIO_s_mem());
  if (!rbio)
  {
    emsg("read BIO initialization error");
    abort();
  }
  imsg("read BIO initialization success");

  wbio = BIO_new(BIO_s_mem());
  if (!wbio)
  {
    emsg("write BIO initialization error");
    abort();
  }
  imsg("write BIO initialization success");

  SSL_set_bio(ret->ssl, rbio, wbio);
  SSL_set_accept_state(ret->ssl);
#ifdef TIME_LOG
  SSL_set_time_logger(ret->ssl, ret->logger);
#endif /* TIME_LOG */

  if (info->mode == EDGE_MODE_SEED)
  {
    SSL_enable_seed(ret->ssl);
    SSL_set_get_seed_digest(ret->ssl, get_vanila_seed_digest);
    SSL_set_seed_digest(ret->ssl);
  }
  else if (info->mode == EDGE_MODE_DC)
    SSL_enable_dc(ret->ssl);
  else if (info->mode == EDGE_MODE_KEYLESS)
  {
    connection *c;
    SSL_enable_keyless_ssl(ret->ssl);
    SSL_set_keyless_ssl_callback(ret->ssl, keyless_ssl_callback);
    c = prepare_keyless_ssl();
    dmsg("c: %p", c);
    SSL_set_keyless_ssl_arg(ret->ssl, (void *)c);
  }
  else if (info->mode == EDGE_MODE_MBTLS)
    SSL_enable_mbtls(ret->ssl);
  else if (info->mode == EDGE_MODE_SPX)
    SSL_enable_spx(ret->ssl);
  else if (info->mode == SERVER_MODE_MBTLS)
    SSL_enable_mbtls(ret->ssl);
  else if (info->mode == SERVER_MODE_SPX)
    SSL_enable_spx(ret->ssl);

  ffinish("ret: %p", ret);
  return ret;
}
#endif /* PLATFORM_VANILA */

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
client_t *init_tee_client_ctx(info_t *info)
{
  fstart("info: %p", info);
  client_t *ret;

  ret = (client_t *)malloc(sizeof(client_t));
  memset(ret, 0x0, sizeof(client_t));
  ret->ctx = info->ctx;
#ifdef TIME_LOG
  ret->logger = init_logger(info->log_directory, info->log_prefix, 
      info->msgs, info->flags, info->context);
#endif /* TIME_LOG */
  ret->frontend = (forwarder_t *)malloc(sizeof(forwarder_t));
  memset(ret->frontend, 0x0, sizeof(forwarder_t));
#ifdef PLATFORM_OPTEE
  init_iom(&(ret->frontend->iom), &(info->ctx->ctx), FRONTEND);
#elif PLATFORM_SGX
  init_iom(&(ret->frontend->iom), ret->logger, FRONTEND);
#endif /* PLATFORM_TEE */
  set_mode(ret->frontend->iom, info->mode);

  ret->backend = (forwarder_t *)malloc(sizeof(forwarder_t));
  memset(ret->backend, 0x0, sizeof(forwarder_t));
#ifdef PLATFORM_OPTEE
  init_iom(&(ret->backend->iom), &(info->ctx->ctx), BACKEND);
#elif PLATFORM_SGX
  init_iom(&(ret->backend->iom), ret->logger, BACKEND);
#endif /* PLATFORM_TEE */
  
  assert(ret != NULL);
  ffinish("ret: %p", ret);
  return ret;
}
#endif /* PLATFORM_TEE */

client_t *init_client_ctx(info_t *info, struct sockaddr *sa, int idx)
{
  fstart("info: %p, sa: %p", info, sa);
  assert(info != NULL);

  client_t *ret;
  ret = NULL;
#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  struct sockaddr_in *addr;
  addr = (struct sockaddr_in *)sa;
#endif /* PLATFORM ADDRESS */

#ifdef PLATFORM_VANILA
  ret = init_vanila_client_ctx(info);
#elif defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  ret = init_tee_client_ctx(info);
#endif /* PLATFORM CLIENT */
  ret->idx = idx;
  ret->bidx = -1;
  ret->mode = info->mode;
  ret->fb_server = info->fb_server;

#if defined(PLATFORM_OPTEE) || defined(PLATFORM_SGX)
  set_client(ret->frontend->iom, (uint32_t) addr->sin_addr.s_addr, 
      (uint16_t) ntohs(addr->sin_port));
#endif /* PLATFORM ADDRESS */

  assert(ret != NULL);
  ffinish("ret: %p", ret);
  return ret;
}

void free_client_ctx(client_t *ctx)
{
  fstart("ctx: %p", ctx);
  int idx, ret;
#ifdef PLATFORM_SGX
  int retval, val;
#elif PLATFORM_OPTEE
  uint32_t origin;
  TEEC_Operation op;
#endif /* PLATFORM_SGX */
  if (ctx)
  {
#ifdef PLATFORM_VANILA
    if (ctx->ssl)
    {
      SSL_free(ctx->ssl);
      ctx->ssl = NULL;
    }
#elif PLATFORM_SGX
    if (ctx->frontend)
    {
      retval = t_sgxssl_invoke_command(ctx->ctx->id, &val, TA_EDGE_CMD_FINISH, 
        ctx->frontend->iom);
    
      if (retval != SGX_SUCCESS)
      {
        emsg("Failed to invoke commands: %d - %#x", retval, retval);
        abort();
      }

      free_iom(ctx->frontend->iom);
    }
#elif PLATFORM_OPTEE
    if (ctx->frontend)
    {
      set_op(&op, ctx->frontend->iom, NULL);
      ret = TEEC_InvokeCommand(&(ctx->ctx->sess), TA_EDGE_CMD_FINISH, &op, &origin);
    
      if (ret != SEED_SUCCESS)
      {
        emsg("Failed to invoke commands: %d - %#x", ret, ret);
        abort();
      }

      free_iom(ctx->frontend->iom);
    }

#endif /* PLATFORM FREE */

#ifdef TIME_LOG
    if (ctx->logger)
      fin_logger(ctx->logger);
#endif /* TIME_LOG */

    if (ctx->idx >= 0)
    {
      idx = ctx->idx;
      if (g_ebase[idx] && occupied[idx])
      {
        ret = event_base_loopbreak(g_ebase[idx]);
        //event_base_free(g_ebase[idx]);
        occupied[idx] = 0;
        //g_ebase[idx] = event_base_new();
      }
    }

    free(ctx);
    ctx = NULL;
  }
  ffinish();
}

info_t *init_info_ctx(ec_ctx_t *ctx, const char *log_directory, char *log_prefix, 
    const char *label, struct event_base *base, const char *msgs, int flags, int context, 
    int mode, const char *code, const char *fb_server)
{
  fstart("ctx: %p, log_direcctory: %s, log_prefix: %s, label: %s, base: %p, msgs: %s, flags: %d, context: %d, mode: %d, code: %s, fallback: %s", ctx, log_directory, log_prefix, label, base, msgs, flags, context, mode, code, fb_server);
  info_t *ret;

  ret = (info_t *)malloc(sizeof(info_t));
  memset(ret, 0x0, sizeof(info_t));
  ret->ctx = ctx;
  ret->log_directory = log_directory;
  ret->log_prefix = log_prefix;
  ret->msgs = msgs;
  ret->flags = flags;
  ret->base = base;
  ret->context = context;
  ret->mode = mode;
  ret->code = code;
  ret->fb_server = fb_server;

  ffinish("ret: %p", ret);
  return ret;
}

void free_info_ctx(info_t *info)
{
  fstart("info: %p", info);
  if (info)
  {
    free(info);
  }
  ffinish();
}

unsigned int get_current_seconds(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec;
}

unsigned long get_current_time(void)
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

unsigned long get_current_cpu(void)
{
  struct timespec tp;
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp);
  return tp.tv_sec * 1000 + tp.tv_nsec / 1000000;
}

#ifdef PLATFORM_VANILA
int pre_read_operation(client_t *client, uint8_t *rbuf, size_t rlen)
{
  fstart("client: %p, rbuf: %p, rlen: %ld", client, rbuf, rlen);

  SSL *ssl;
  ssl = client->ssl;

  if (client->chlen < 0) 
    goto out;

  client->chlen = rlen;
  client->ch = (uint8_t *)malloc(rlen);
  memcpy(client->ch, rbuf, rlen);

  if (client->chlen > 0)
  {
    uint8_t *p;
    p = client->ch;
    dmsg("Client hello length: %d", client->chlen);
    dmsg("Verify content type: 0x%02x (should be 0x16)", *p++);
    dmsg("Verify version: 0x%02x%02x (should be 0x0301)", *p++, *p++);
    int len;
    PTR_TO_VAR_2BYTES(p, len);
    dmsg("Length: %d (should be chlen - 5)", len);
    dmsg("Handshake type: %d (should be 1)", *p++);
  }

out:
  ffinish();
  return 1;
}

int pre_write_operation(client_t *client)
{
  fstart("client: %p", client);

  SSL *ssl;
  if (client->chlen < 0) goto out;

  ssl = client->ssl;

  if (SSL_check_fallback(ssl))
  {

  }
  else
  {
    client->chlen = -1;
    if (client->ch)
    {
      free(client->ch);
      client->ch = NULL;
    }
    goto out;
  }

  ffinish();
  return 1;

out:
  ffinish();
  return -1;
}

int vanila_seed_execution(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %ld, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);
  assert(client != NULL);
  assert(rbuf != NULL);
  assert(rlen > 0);
  assert(wbuf != NULL);
  assert(wlen != NULL);
 
  int ret, tmp;
  SSL *ssl;
#ifdef TIME_LOG 
  logger_t *logger;
#endif /* TIME_LOG */

  ret = SEED_SUCCESS;
  tmp = -1;
  ssl = client->ssl;
#ifdef TIME_LOG
  logger = SSL_get_time_logger(ssl);
#endif /* TIME_LOG */

  if (SSL_is_init_finished(ssl))
  {
    dmsg("after the TLS session is established");
    if (logger->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].time == 0
        || logger->log[SEED_LT_SERVER_AFTER_TLS_ACCEPT].cpu == 0)
      client->logger->ops->add(client->logger, SEED_LT_SERVER_AFTER_TLS_ACCEPT, UNTRUSTED);
  }
  else
  {
    dmsg("before the TLS session is established");
    if (!client->start && (SSL_in_init(ssl) || SSL_in_before(ssl)))
    {
      logger->ops->add(client->logger, SEED_LT_SERVER_BEFORE_TLS_ACCEPT, UNTRUSTED);
      client->start = 1;
    }
    pre_read_operation(client, rbuf, rlen);
    BIO_write(SSL_get_rbio(ssl), rbuf, rlen);
    tmp = SSL_do_handshake(ssl);
    dmsg("tmp: %d", tmp);
    if (tmp == 1)
    {
      client->logger->ops->add(client->logger, SEED_LT_SERVER_AFTER_TLS_ACCEPT, UNTRUSTED);
    }
    else if (tmp == 0)
    {
      // TODO: This is the error state. How to deal with this?
      //client->logger->ops->add(client->logger, SEED_LT_SERVER_ERR, UNTRUSTED);
      ERR_print_errors_fp(stderr);
    }

    tmp = pre_write_operation(client);
    if (tmp < 0)
    {
      *wlen = BIO_read(SSL_get_wbio(ssl), wbuf, BUF_SIZE);
      if (*wlen > 0)
        ret = SEED_NEED_WRITE;
    }
    else
    {
      ret = SEED_NEED_FALLBACK;
    }
  }

  ffinish("ret: %d", ret);
  return ret;
}
#endif /* PLATFORM_VANILA */

int tee_get_data(client_t *client)
{
  fstart("client: %p", client);

  cctx_t *cctx;
  FILE *fp;
  int offset;
  int ret, retval, val;
#ifdef PLATFORM_OPTEE
  uint32_t origin;
  TEEC_Operation op;
#endif /* PLATFORM_OPTEE */
  size_t size;
  uint8_t *p;
  uint8_t name[BUF_LEN] = {0, };
  uint8_t path[BUF_LEN] = {0, };
  const uint8_t *index = "index.html";


  fp = NULL; p = NULL;
  ret = SUCCESS;
  cctx = get_cmd_ctx(client->frontend->iom);
  get_address(cctx->arg, cctx->alen, name, NULL);
  snprintf(path, BUF_LEN, "%s/%s", name, index);
  fp = fopen(path, "r");
  offset = 0;
  fseek(fp, 0L, SEEK_END);
  size = (int)ftell(fp);
  fseek(fp, 0L, SEEK_SET);
#ifdef PLATFORM_OPTEE
  set_op(&op, client->frontend->iom, client->logger);
#endif /* PLATFORM_OPTEE */

  while (cctx->flags == TA_EDGE_NXT_GET_DATA)
  {
    p = cctx->arg;
    if (cctx->stage == TA_EDGE_GET_DATA_INIT)
    {
      VAR_TO_PTR_4BYTES(size, p);
    }
    cctx->alen = fread(p, 1, BUF_SIZE, fp);
    offset += cctx->alen;
    if (offset >= size)
      cctx->stage = TA_EDGE_GET_DATA_FINISH;
#ifdef PLATFORM_OPTEE
    retval = TEEC_InvokeCommand(&client->ctx->sess, cctx->flags, &op, &origin);
#elif PLATFORM_SGX
    retval = t_sgxssl_invoke_command(client->ctx->id, &val, cctx->flags, 
      client->frontend->iom);
#endif /* PLATFORM_TEE */
  }

  ffinish();
  return ret;
}

#ifdef PLATFORM_OPTEE
int optee_seed_execution(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %ld, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);
  
  int ret, retval;
  uint32_t origin;
  TEEC_Operation op;
  cctx_t *cctx;
  ret = SEED_SUCCESS;

  set_op(&op, client->frontend->iom, client->logger);
  forward_to_secure_world(client->frontend->iom, rbuf, rlen);
  retval = TEEC_InvokeCommand(&client->ctx->sess, TA_EDGE_CMD_TLS, &op, &origin);
  if (retval != SEED_SUCCESS)
  {
    emsg("Failed to invoke commands: %d - %#x", retval, retval);
    abort();
  }
  *wlen = forward_to_out_world(client->frontend->iom, wbuf, BUF_SIZE);
  if (*wlen > 0)
    ret = SEED_NEED_WRITE;

  cctx = get_cmd_ctx(client->frontend->iom);
  if (cctx->flags == TA_EDGE_NXT_FALLBACK_INIT)
    ret = SEED_NEED_FALLBACK;

  if (cctx->flags == TA_EDGE_NXT_GET_DATA)
    tee_get_data(client);

  ffinish("ret: %d", ret);
  return ret;
}
#endif /* PLATFORM_OPTEE */

#ifdef PLATFORM_SGX
int sgx_seed_execution(client_t *client, uint8_t *rbuf, size_t rlen, 
    uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %ld, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);

  int ret, val, retval;
  cctx_t *cctx;
  ret = SEED_SUCCESS;
  val = 0;
  retval = 0;

  forward_to_secure_world(client->frontend->iom, rbuf, rlen);
  retval = t_sgxssl_invoke_command(client->ctx->id, &val, TA_EDGE_CMD_TLS, 
      client->frontend->iom);
  if (retval != SGX_SUCCESS)
  {
    emsg("Failed to invoke commands: %d - %#x", retval, retval);
    abort();
  }

  *wlen = forward_to_out_world(client->frontend->iom, wbuf, BUF_SIZE);
  if (*wlen > 0)
    ret = SEED_NEED_WRITE;

  cctx = get_cmd_ctx(client->frontend->iom);
  if (cctx->flags == TA_EDGE_NXT_FALLBACK_INIT)
    ret = SEED_NEED_FALLBACK;

  if (cctx->flags == TA_EDGE_NXT_GET_DATA)
    tee_get_data(client);

  ffinish("ret: %d", ret);
  return ret;
}
#endif /* PLATFORM_SGX */

int seed_execution(client_t *client, uint8_t *rbuf, size_t rlen, uint8_t *wbuf, size_t *wlen)
{
  fstart("client: %p, rbuf: %p, rlen: %ld, wbuf: %p, wlen: %p", client, rbuf, rlen, wbuf, wlen);
  assert(client != NULL);
  assert(rbuf != NULL);
  assert(rlen > 0);
  assert(wbuf != NULL);
  assert(wlen != NULL);

  int ret;

#ifdef PLATFORM_VANILA
  ret = vanila_seed_execution(client, rbuf, rlen, wbuf, wlen);
#elif PLATFORM_OPTEE
  ret = optee_seed_execution(client, rbuf, rlen, wbuf, wlen);
#elif PLATFORM_SGX
  ret = sgx_seed_execution(client, rbuf, rlen, wbuf, wlen);
#else
  ret = SEED_INVALID_PLATFORM;
#endif /* PLATFORM EXECUTION */

  ffinish("ret: %d", ret);
  return ret;
}

int get_address(uint8_t *buf, int len, uint8_t *host, uint16_t *port)
{
  fstart("buf: %p, len: %d, host: %p, port: %p", buf, len, host, port);

  uint8_t hlen;
  uint8_t *p;

  p = buf;
  hlen = (*p++);
  memcpy(host, p, hlen);
  host[hlen] = 0;
  p += hlen;
  *port = ((p[0]) << 8) | p[1];

  dmsg("address: %s / port: %d", host, *port);
  ffinish();
  return SUCCESS;
}

int get_fallback(client_t *client, uint8_t *buf, int len, uint8_t *host, uint16_t *port)
{
  fstart("client: %p, buf: %p, len: %d, host: %p, port: %p", client, buf, len, host, port);

  uint8_t hlen;
  uint8_t *p;

  p = buf;
  hlen = (*p++);
  host = p;
//  memcpy(host, p, hlen);
  host[hlen] = 0;
  p += hlen;
  PTR_TO_VAR_2BYTES(p, (*port));

  PTR_TO_VAR_2BYTES(p, (client->chlen));
  client->ch = p;
//  client->ch = (uint8_t *)malloc(client->chlen);
//  memcpy(client->ch, p, client->chlen);

  ffinish();
  return SUCCESS;
}
