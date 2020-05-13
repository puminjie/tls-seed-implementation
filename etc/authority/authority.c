#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>
#include <unistd.h>
#include <debug.h>
#include <getopt.h>
#include <dirent.h>
#include <sys/stat.h>

#include <simple_http/simple_https.h>
#include <simple_http/simple_http_callbacks.h>

#define DEFAULT_PORT_NUMBER 1234
#define DEFAULT_CERT_NAME "cert.pem"

SSL_CTX *init_auth_ctx(const char *skname, const char *pkname, const uint8_t *http);
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
int process_list(http_t *req, http_t *resp);

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -k, --key     private key");
  emsg("  -c, --cert    certificate");
  emsg("  -p, --port    port");
  exit(1);
}

int main(int argc, char *argv[])
{
  http_cbs_t *cbs;
  http_t *req, *resp;

  SSL_CTX *ctx;
  SSL_METHOD *method;
  SSL *ssl;

  const char *pname, *opt, *skname, *pkname;

  int c, server, client, err, port, ret;
  const uint8_t http1_1[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

  struct sockaddr_in addr;
  socklen_t len = sizeof(addr);

  ctx = NULL;
  pname = argv[0];
  skname = NULL;
  pkname = NULL;
  port = DEFAULT_PORT_NUMBER;
  err = 0;

  while (1)
  {
    int idx = 0;
    static struct option long_options[] = {
      {"key", required_argument, 0, 'k'},
      {"cert", required_argument, 0, 'c'},
      {"port", required_argument, 0, 'p'},
      {0, 0, 0, 0}
    };

    opt = "k:c:p:0";

    c = getopt_long(argc, argv, opt, long_options, &idx);

    if (c == -1) break;

    switch (c)
    {
      case 'k':
        skname = optarg;
        break;
      case 'c':
        pkname = optarg;
        break;
      case 'p':
        port = atoi(optarg);
        break;
      default:
        usage(pname);
    }
  }

  if (!skname)
  {
    emsg("Please select the private key of the edge platform");
    usage(pname);
  }

  if (!pkname)
  {
    emsg("Please insert the certificate file name of the edge platform");
    usage(pname);
  }

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  init_http_module();

  ctx = init_auth_ctx(skname, pkname, http1_1);
  if (!ctx) goto err;
  
  cbs = init_http_callbacks();
  if (!cbs) goto err;

  ret = register_callback(cbs, HTTP_METHOD_GET, "/list", 5, process_list);
  if (ret != HTTP_SUCCESS) goto err;

  print_callbacks(cbs);

  server = open_listener(port, 1);
  if (server < 0)
    abort();

  while(1)
  {
    if((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      dmsg("New connection is accepted: %d", client);
      ssl = SSL_new(ctx);
      ERR_print_errors_fp(stderr);
      SSL_set_fd(ssl, client);
      ERR_print_errors_fp(stderr);
      SSL_set_accept_state(ssl);
      ERR_print_errors_fp(stderr);

      req = init_http_message(HTTP_TYPE_REQUEST);
      if (!req) goto err;

      ERR_print_errors_fp(stderr);
      resp = init_http_message(HTTP_TYPE_RESPONSE);
      if (!resp) goto err;
      http_set_default_attributes(resp);

      ERR_print_errors_fp(stderr);
      while (!err)
      {
        ret = SSL_do_handshake(ssl);
        err = process_error(ssl, ret);

        if (err < 0)
        {
          emsg("Failed to SSL_accept()");
          ERR_print_errors_fp(stderr);
          abort();
        }
      }
      ERR_print_errors_fp(stderr);
      dmsg("TLS session is established with %s", SSL_get_cipher(ssl));

      ret = HTTP_NOT_FINISHED;
      ret = recv_https_message(ssl, req, NULL);
      if (ret != HTTP_SUCCESS) goto err;
      print_header(req);

      process_request(cbs, req, resp);

      print_header(resp);
      ret = HTTP_NOT_FINISHED;
      ret = send_https_message(ssl, resp);
      if (ret != HTTP_SUCCESS) goto err;

      SSL_free(ssl);
      close(client);
      client = -1;
    }
  }

  if (ctx)
    SSL_CTX_free(ctx);
  ctx = NULL;
  close(server);

  return 0;

err:
  if (ssl)
    SSL_free(ssl);
  if (ctx)
    SSL_CTX_free(ctx);
  close(server);
  return 1;
}

SSL_CTX *init_auth_ctx(const char *skname, const char *pkname, const uint8_t *http)
{
  fstart("skname: %s, pkname: %s, http: %s", skname, pkname, http);

  SSL_METHOD *method;
  SSL_CTX *ctx;
  EC_KEY *ecdh;

  method = (SSL_METHOD *)TLS_server_method();
  ctx = SSL_CTX_new(method);

  if (!ctx)
  {
    emsg("SSL_CTX init failed");
    abort();
  }
  SSL_CTX_set_alpn_protos(ctx, http, sizeof(http));

  if (SSL_CTX_load_verify_locations(ctx, "ca_ecc.pem", "/etc/ssl/certs") != 1)
  {
    ERR_print_errors_fp(stderr);
    abort();
  }

  if (SSL_CTX_use_certificate_file(ctx, pkname, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_certificate_file() error");
    abort();
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, skname, SSL_FILETYPE_PEM) <= 0)
  {
    emsg("SSL_CTX_use_PrivateKey_file() error");
    abort();
  }

  if (!SSL_CTX_check_private_key(ctx))
  {
    emsg("SSL_CTX_check_private_key() error");
    abort();
  }

  ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!ecdh)
  {
    emsg("Set ECDH error");
    abort();
  }

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
  {
    emsg("SSL_CTX_set_tmp_ecdh() error");
    abort();
  }

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

  ffinish("ctx: %p", ctx);
  return ctx;
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
  fstart("preverify_ok: %d, x509_ctx: %p", preverify_ok, x509_ctx);
  
  dmsg("The verify callback function is invoked");
  
  ffinish();
  return 1;
}

int process_list(http_t *req, http_t *resp)
{
  fstart("req: %p, resp: %p", req, resp);
  assert(req != NULL);
  assert(resp != NULL);

  resource_t *resource;
  buf_t *buf;
  uint8_t *zero;
  uint8_t tmp[BUF_LEN];
  uint8_t cert[BUF_SIZE];
  int size, clen, zlen;
  struct dirent *dent;
  DIR *srcdir;
  FILE *fp;
  
  zero = "0";
  zlen = 1;
  if (!resp->resource)
    resource = http_init_resource(resp);
  buf = init_alloc_buf_mem(&buf, BUF_SIZE);
  size = 0;
  srcdir = opendir(".");

  if (srcdir == NULL)
  {
    perror("opendir()");
    goto err;
  }

  while ((dent = readdir(srcdir)) != NULL)
  {
    struct stat st;

    if (strcmp(dent->d_name, ".") == 0 || strcmp(dent->d_name, "..") == 0)
      continue;

    if (fstatat(dirfd(srcdir), dent->d_name, &st, 0) < 0)
    {
      perror(dent->d_name);
      continue;
    }

    if (S_ISDIR(st.st_mode))
    {
      update_buf_mem(buf, dent->d_name, (int)strlen(dent->d_name));
      add_buf_char(buf, '\n');
      add_buf_char(buf, '\n');

      snprintf(tmp, BUF_LEN, "%s/%s", dent->d_name, DEFAULT_CERT_NAME);
      dmsg("cert path: %s", tmp);

      fp = fopen(tmp, "r");
      if (!fp) goto err;
      clen = (int)fread(cert, 1, BUF_SIZE, fp);
      if (clen > 1)
        update_buf_mem(buf, cert, clen - 1);
      add_buf_char(buf, '\n');
      add_buf_char(buf, '\n');
      fclose(fp);
    }
    memset(tmp, 0x0, BUF_LEN);
    memset(cert, 0x0, BUF_SIZE);
  }

  closedir(srcdir);

  resource->type = HTTP_RESOURCE_MEM;
  resource->ptr = get_buf_data(buf);
  resource->size = get_buf_offset(buf);

  ffinish();
  return HTTP_SUCCESS;

err:
  ferr();
  return HTTP_FAILURE;
}
