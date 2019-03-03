#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/logs.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>
#include "keyless.h"
#include "keyless_kssl_helpers.h"
#include "keyless_kssl_log.h"

#define FAIL            -1
#define BUF_SIZE        16384
#define MAX_HOST_LEN    256
#define DHFILE          "dh1024.pem"

#define DELIMITER       "\r\n"
#define DELIMITER_LEN   2

#define INDEX_FILE      "/index.html"
#define INDEX_FILE_LEN  12
#define MAX_THREADS     10
#define MAX_FILE_NAME_LEN   256

#define DEFAULT_LOG_DIRECTORY "log"
#define DEFAULT_ORIGIN_PORT 5555

#define KEY_SERVER_NAME "www.bob.com"
#define KEY_SERVER_PORT 5557

SSL_CTX *kctx;
connection *c;

struct info
{
  int fd;
  SSL_CTX *ctx;
#ifdef TIME_LOG
  log_t *time_log;
  uint8_t *fname;
#endif /* TIME_LOG */
};

struct rinfo
{
  FILE *fp;
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  uint32_t clen;
  uint32_t size;
  uint32_t sent;
};

int open_listener(int port);
int open_connection(char *name, uint16_t port, void *time_log);
SSL_CTX* init_ctx(void);
void load_certificates(SSL_CTX* ctx);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r);
int http_parse_response(uint8_t *msg, uint32_t mlen, struct rinfo *r);
log_t time_log[NUM_OF_LOGS];
int process_error(SSL *ssl, int ret);
int fetch_cert(SSL *ssl, int *ad, void *arg);
size_t fetch_content(uint8_t *buf, struct rinfo *r);
size_t fetch_from_origin(uint8_t *buf, struct rinfo *r);
SSL *init_origin(SSL *ssl, SSL *edge, SSL_CTX *ctx, int *sd, struct rinfo *r,
    void *time_log);
int cache_content(uint8_t *buf, uint32_t len, struct rinfo *r);
int char_to_int(uint8_t *str, uint32_t slen);
void prepare_keyless_ssl(void);

int running = 1;
pthread_t threads[MAX_THREADS];
pthread_attr_t attr;
int get_thread_index(void);
void *status;
void *run(void *data);
#ifdef KEYLESS_SSL
void keyless_ssl_callback(SSL *ssl, uint8_t *out, uint8_t *in, uint32_t ilen, size_t *sig_len);
#endif /* KEYLESS_SSL */

void int_handler(int dummy)
{
  EDGE_LOG("End of experiment");
  running = 0;
  exit(0);
}

int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	int i, server, client, sent = 0, rcvd = 0;
	char *portnum, *cert, *key;
  char buf[BUF_SIZE];
	const char *response = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: 72\r\n"
		"\r\n"
		"<html><title>Test</title><body><h1>Test Alice's Page!</h1></body></html>";
	int response_len = strlen(response);
  int tidx, rc;

#ifdef TIME_LOG
  log_t init_log[NUM_OF_LOGS];
  int sequence = 0;
  uint32_t exp_no;
  uint8_t fname[MAX_FILE_NAME_LEN] = {0};
  uint8_t *type;

  INITIALIZE_LOG(init_log);
#endif /* TIME_LOG */

#ifndef TIME_LOG 
	if (count != 2)
	{
		printf("Usage: %s <port>\n", strings[0]);
		exit(0);
	}
#else
  if (count != 4)
  {
    printf("Usage: %s <port> <type> <exp no.>\n", strings[0]);
    exit(1);
  }

  type = strings[2];
  exp_no = atoi(strings[3]);
#endif /* TIME_LOG */

  for (i=0; i<MAX_THREADS; i++)
    threads[i] = 0;

  signal(SIGINT, int_handler);
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];

	ctx = init_ctx();
  load_dh_params(ctx, DHFILE);
  load_ecdh_params(ctx);
	load_certificates(ctx);

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
  struct info *info;
	socklen_t len = sizeof(addr);
  
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

#ifdef KEYLESS_SSL
  prepare_keyless_ssl();
#endif /* KEYLESS_SSL */

	while (running)
	{
    RECORD_LOG(time_log, SERVER_TCP_START);
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      RECORD_LOG(time_log, SERVER_TCP_END);
      INTERVAL(time_log, SERVER_TCP_START, SERVER_TCP_END);
      printf("New Connection is accepted\n");

      info = (struct info *)malloc(sizeof(struct info));
      info->fd = client;
      info->ctx = ctx;
#ifdef TIME_LOG
      sequence += 1;
      snprintf(fname, MAX_FILE_NAME_LEN, "%s/%d/%s_%d.csv", 
          DEFAULT_LOG_DIRECTORY, exp_no, type, sequence);
      printf("Log file name: %s\n", fname);
      info->time_log = time_log;
      info->fname = fname;
#endif /* TIME_LOG */
      tidx = get_thread_index();
      rc = pthread_create(&threads[tidx], &attr, run, info);

      if (rc < 0)
        exit(1);
    }
	}

  for (i=0; i<MAX_THREADS; i++)
  {
    rc = pthread_join(threads[i], &status);
    threads[i] = 0;

    if (rc)
    {
      return 1;
    }
  }

	SSL_CTX_free(ctx);         /* release context */
	close(server);          /* close server socket */

	return 0;
}

void *run(void *data)
{
  int ret, err, process, rcvd, sent, total, sd, mlen;
  struct info *info;
  struct rinfo r;
  uint8_t rbuf[BUF_SIZE], wbuf[BUF_SIZE];
  SSL *ssl, *origin;
  int len;

  origin = NULL;
  total = 0;
  info = (struct info *)data;
  memset(&r, 0x0, sizeof(struct rinfo));
  ssl = SSL_new(info->ctx);
  SSL_set_fd(ssl, info->fd);
#ifdef TIME_LOG
  SSL_set_time_log(ssl, info->time_log);
#else
  SSL_set_time_log(ssl, NULL);
#endif /* TIME_LOG */
  SSL_set_accept_state(ssl);
  SSL_disable_ec(ssl);

#ifdef KEYLESS_SSL
  SSL_enable_keyless_ssl(ssl);
  SSL_set_keyless_ssl_callback(ssl, keyless_ssl_callback);
#else
  SSL_disable_keyless_ssl(ssl);
#endif /* KEYLESS_SSL */

  process = 1;
  err = 0;
  len = 0;
  memset(&r, 0x0, sizeof(struct rinfo));

  EDGE_LOG("Start client loop");

  // TLS handshake
  RECORD_LOG(SSL_get_time_log(ssl), SERVER_BEFORE_TLS_ACCEPT);
  while (!err)
  {
    EDGE_MSG("Before handshake");
		ret = SSL_do_handshake(ssl);
    err = process_error(ssl, ret);

    EDGE_LOG("err: %d, ret: %d", err, ret);
    if (err < 0)
      abort();
  }
  RECORD_LOG(SSL_get_time_log(ssl), SERVER_AFTER_TLS_ACCEPT);
  INTERVAL(SSL_get_time_log(ssl), SERVER_BEFORE_TLS_ACCEPT, SERVER_AFTER_TLS_ACCEPT);

  // HTTP process + Content fetching
  RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START);
  RECORD_LOG(SSL_get_time_log(ssl), SERVER_RECV_HTTP_REQUEST_START);
  rcvd = -1;

  while (rcvd < 0)
    rcvd = SSL_read(ssl, rbuf, BUF_SIZE);

  // When Receiving an HTTP Request
  if (rcvd > 0)
  {
    RECORD_LOG(SSL_get_time_log(ssl), SERVER_RECV_HTTP_REQUEST_END);
    RECORD_LOG(SSL_get_time_log(ssl), SERVER_PARSE_HTTP_REQUEST_START);
    http_parse_request(rbuf, rcvd, &r);
    RECORD_LOG(SSL_get_time_log(ssl), SERVER_PARSE_HTTP_REQUEST_END);

    RECORD_LOG(SSL_get_time_log(ssl), SERVER_CHECK_CACHE_START);
#ifndef NO_CACHE
    len = fetch_content(wbuf, &r);
#else
    len = -1;
#endif /* NO_CACHE */
    RECORD_LOG(SSL_get_time_log(ssl), SERVER_CHECK_CACHE_END);

    if (len < 0) /* If not cached */
    {
      if (!origin)
      {
#ifdef TIME_LOG
        origin = init_origin(origin, ssl, info->ctx, &sd, &r, time_log);
#else
        origin = init_origin(origin, ssl, info->ctx, &sd, &r, NULL);
#endif /* TIME_LOG */
        RECORD_LOG(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_START);
        total = 0;
        while (rcvd > total)
        {
          sent = SSL_write(origin, rbuf + total, rcvd - total);

          if (sent > 0)
            total += sent;
        }
      }
      
      do {
        len = SSL_read(origin, wbuf, BUF_SIZE);
      } while (len < 0);

      http_parse_response(wbuf, len, &r);
#ifndef NO_CACHE
      cache_content(wbuf, len, &r);
#endif /* NO_CACHE */
      total = 0;
      while (len > total)
      {
        sent = SSL_write(ssl, wbuf + total, len - total);

        if (sent > 0)
          total += sent;
      }
      r.sent += len;

      while (r.size > r.sent)
      {
        len = SSL_read(origin, wbuf, BUF_SIZE);
        if (len > 0)
        {
          total = 0;
          while (len > total)
          {
            sent = SSL_write(ssl, wbuf + total, len - total);

            if (sent > 0)
              total += sent;
          }
#ifndef NO_CACHE
          cache_content(wbuf, len, &r);
#endif /* NO_CACHE */
          r.sent += len;
        }
      }
#ifndef NO_CACHE
      fclose(r.fp);
#endif /* NO_CACHE */
      RECORD_LOG(SSL_get_time_log(ssl), CLIENT_FETCH_HTML_END);
    }
    else /* If cached */
    {
      do {
        total = 0;
        while (len > total)
        {
          sent = SSL_write(ssl, wbuf + total, len - total);
          if (sent > 0)
            total += sent;
        }

        r.sent += len;
        len = fetch_content(wbuf, &r);
      } while (len > 0);
    }
  }
  RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_END);
  INTERVAL(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START, SERVER_SERVE_HTML_END);

  SSL_free(ssl);
  close(info->fd);
  if (r.domain)
  {
    free(r.domain);
    r.domain = NULL;
  }
  if (r.content)
  {
    free(r.content);
    r.content = NULL;
  }
  PRINT_LOG(time_log);
  FINALIZE(time_log, info->fname);

  if (info)
  {
    free(info);
    info = NULL;
  }

  return NULL;
}

SSL *init_origin(SSL *ssl, SSL *edge, SSL_CTX *ctx, int *sd, struct rinfo *r,
    void *time_log)
{
  EDGE_MSG("Start: init_origin");
  EDGE_LOG("ssl: %p, edge: %p, ctx: %p, sd: %p, r: %p, time_log: %p", ssl, edge, ctx, sd, r, time_log);

  int err, ret;

  RECORD_LOG((log_t *)time_log, CLIENT_TCP_START);
  *sd = open_connection(r->domain, DEFAULT_ORIGIN_PORT, time_log);
  RECORD_LOG((log_t *)time_log, CLIENT_TCP_END);
  INTERVAL((log_t *)time_log, CLIENT_TCP_START, CLIENT_TCP_END);

  ssl = SSL_new(ctx);
  SSL_set_fd(ssl, *sd);
#ifdef TIME_LOG
  SSL_set_time_log(ssl, (log_t *)time_log);
#else
  SSL_set_time_log(ssl, NULL);
#endif /* TIME_LOG */
  SSL_disable_ec(ssl);
  SSL_set_connect_state(ssl);
  SSL_set_tlsext_host_name(ssl, SSL_get_servername(edge, TLSEXT_NAMETYPE_host_name));

  err = 0;
  RECORD_LOG(SSL_get_time_log(ssl), CLIENT_BEFORE_TLS_CONNECT);
  while (!err)
  {
		ret = SSL_do_handshake(ssl);
    err = process_error(ssl, ret);

    if (err < 0)
      abort();
  }
  RECORD_LOG(SSL_get_time_log(ssl), CLIENT_AFTER_TLS_CONNECT);
  INTERVAL(SSL_get_time_log(ssl), CLIENT_BEFORE_TLS_CONNECT, CLIENT_AFTER_TLS_CONNECT);

  EDGE_MSG("Finished: init_origin");
  return ssl;
}

int process_error(SSL *ssl, int ret)
{
  int err, ad;
  err = SSL_get_error(ssl, ret);

  switch (err)
  {
    case SSL_ERROR_NONE:
      EDGE_LOG("SSL_ERROR_NONE");
      ret = 1;
      break;

    case SSL_ERROR_ZERO_RETURN:
      EDGE_LOG("SSL_ERROR_ZERO_RETURN");
      ret = -1;
      break;
  
    case SSL_ERROR_WANT_X509_LOOKUP:
      EDGE_LOG("SSL_ERROR_WANT_X509_LOOKUP");
      fetch_cert(ssl, &ad, NULL);
      ret = 0;
      break;
    
    case SSL_ERROR_SYSCALL:
      EDGE_LOG("SSL_ERROR_SYSCALL");
      ret = -1;
      break;
  
    case SSL_ERROR_SSL:
      EDGE_LOG("SSL_ERROR_SSL");
      ret = -1;
      break;

    default:
      ret = 0;
  }

  return ret;
}

int fetch_cert(SSL *ssl, int *ad, void *arg)
{
  EDGE_MSG("Start: fetch_cert");
  EDGE_LOG("ssl: %p, ad: %p, arg: %p", ssl, ad, arg);
  (void) ad;
  (void) arg;

  int ret;
  uint8_t crt_path[MAX_HOST_LEN] = {0,};
  uint8_t priv_path[MAX_HOST_LEN] = {0,};
  uint8_t *p;
  uint32_t len;

  if (!ssl)
    return SSL_TLSEXT_ERR_NOACK;

  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (!name || name[0] == '\0')
    return SSL_TLSEXT_ERR_NOACK;

  p = crt_path;
  len = strlen(name);
  memcpy(p, name, len);

  ret = mkdir(p, 0775);
  if (ret < 0)
  {
    if (errno == EEXIST)
    {
      EDGE_MSG("The directory exists");
    }
    else
    {
      EDGE_MSG("Other error");
    }
  }

  p += len;
  memcpy(p, "/cert.pem", 9);

  p = priv_path;
  len = strlen(name);
  memcpy(p, name, len);

  p += len;
  memcpy(p, "/priv.pem", 9);

  EDGE_LOG("crt_path: %s", crt_path);
  EDGE_LOG("priv_path: %s", priv_path);

  if (SSL_use_certificate_file(ssl, crt_path, SSL_FILETYPE_PEM) != 1)
  {
    EDGE_LOG("Loading the certificate error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  EDGE_MSG("Loading the certificate success");

  if (SSL_use_orig_certificate_file(ssl, crt_path, SSL_FILETYPE_PEM) != 1)
  {
    EDGE_LOG("Loading the origin certificate error");
    return SSL_TLSEXT_ERR_NOACK;
  }
  EDGE_MSG("Loading the origin certificate success");

  if (SSL_use_PrivateKey_file(ssl, priv_path, SSL_FILETYPE_PEM) != 1)
  {
    EDGE_LOG("Loading the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }
  
  EDGE_MSG("Loading the private key success");

  if (SSL_check_private_key(ssl) != 1)
  {
    EDGE_LOG("Checking the private key error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  EDGE_MSG("Checking the private key success");

  EDGE_MSG("Finished: fetch_cert");
  return SSL_TLSEXT_ERR_OK;
}

size_t fetch_content(uint8_t *buf, struct rinfo *r)
{
  EDGE_LOG("Start: fetch_content: buf: %p, r->size: %d, r->sent: %d", buf, r->size, r->sent);

  size_t total, sz;
  uint8_t path[MAX_HOST_LEN];
  uint8_t *p;
  int rlen;
  rlen = 0;

  if (r->fp && (r->size <= r->sent))
  {
    fclose(r->fp);
    sz = -1;
    goto ret;
  }

  if (!(r->fp))
  {
    memset(path, 0x0, MAX_HOST_LEN);
    p = path;

    memcpy(p, r->domain, r->dlen);
    p += r->dlen;
  
    memcpy(p, r->content, r->clen);
    EDGE_LOG("path: %s", path);

    r->fp = fopen(path, "rb");

    if (!(r->fp))
    {
      EDGE_LOG("Error in opening the file");
      r->size = sz = -1;
      goto ret;
    }
  }

  if (r->size == 0)
  {
    fseek(r->fp, 0L, SEEK_END);
    r->size = total = ftell(r->fp);
    sz = total - r->sent;
    EDGE_LOG("sz: %ld, r->sent: %u", sz, r->sent);
  }

  EDGE_LOG("r->size: %u, r->sent: %u", r->size, r->sent);

  memset(buf, 0x0, BUF_SIZE);
  p = buf;

  fseek(r->fp, r->sent, SEEK_SET);

  if (r->size - r->sent > BUF_SIZE)
  {
    sz = BUF_SIZE;
  }
  else
  {
    sz = r->size - r->sent;
  }
  fread(p, 1, sz, r->fp);

  EDGE_LOG("sz: %ld", sz);
ret:
  EDGE_MSG("Finished: fetch_content");

  return sz;
}

int cache_content(uint8_t *buf, uint32_t len, struct rinfo *r)
{
  EDGE_LOG("Start: cache_content");
  uint8_t path[MAX_HOST_LEN] = {0};
  uint8_t *p;

  if (!(r->fp))
  {
    p = path;

    memcpy(p, r->domain, r->dlen);
    p += r->dlen;
    memcpy(p, r->content, r->clen);
    p += r->clen;

    r->fp = fopen(path, "wb");

    if (!(r->fp))
    {
      EDGE_LOG("Error in opening the file");
      len = -1;
      goto ret;
    }

  }
  EDGE_LOG("path: %s", path);
  fwrite(buf, 1, len, r->fp);

  EDGE_LOG("Finished: cache_content");
ret:
  return len;
}

int open_connection(char *name, uint16_t port, void *tlog)
{
  int sd, option;
  struct hostent *host;
  struct sockaddr_in addr;
  option = 1;
#ifdef TIME_LOG
  log_t *time_log;
  time_log = (log_t *)tlog;
#endif /* TIME_LOG */

  if ((host = gethostbyname(name)) == NULL)
  {
    EDGE_LOG("gethostbyname() error");
  }

  sd = socket(PF_INET, SOCK_STREAM, 0);
  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
  if (sd < 0)
    EDGE_LOG("client socket() error");
  EDGE_LOG("client socket() success");
  
  memset(&addr, 0x0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = *(long *)(host->h_addr);

  RECORD_LOG(time_log, CLIENT_TCP_START);
  if (connect(sd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    close(sd);
    abort();
    return -1;
  }
  RECORD_LOG(time_log, CLIENT_TCP_END);
  fcntl(sd, F_SETFL, O_NONBLOCK);
  EDGE_LOG("connect to %s:%d succeed", name, port);

  return sd;
}

int open_listener(int port)
{   
  EDGE_MSG("Start: open_listener");
  EDGE_LOG("port: %d", port);
  int sd, option;
	struct sockaddr_in addr;
  option = 1;

	sd = socket(PF_INET, SOCK_STREAM, 0);
  setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));
  fcntl(sd, F_SETFL, O_NONBLOCK);
	
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;
	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
	{
		perror("can't bind port");
		abort();
	}
	if ( listen(sd, 10) != 0 )
	{
		perror("Can't configure listening port");
		abort();
	}
  EDGE_MSG("Finished: open_listener");
	return sd;
}

SSL_CTX* init_ctx(void)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLSv1_2_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		EDGE_LOG("SSL_CTX init failed!");
		abort();
	}

#ifdef TLS13
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
#else
  SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
#endif /* TLS13 */

	return ctx;
}

void load_certificates(SSL_CTX* ctx)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

  SSL_CTX_set_tlsext_servername_callback(ctx, fetch_cert);
}

void load_dh_params(SSL_CTX *ctx, char *file)
{
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL)
  {
    perror("Couldn't open DH file");
  }

  BIO_free(bio);

  if (SSL_CTX_set_tmp_dh(ctx, ret) < 0)
  {
    perror("Couldn't set DH parameters");
  }
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}

int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r)
{
  EDGE_LOG("Start: http_parse_request");
  (void) mlen;
  int l;
  uint8_t *cptr, *nptr, *p, *q;
  struct rinfo *info;

#ifdef DEBUG
  uint8_t buf[MAX_HOST_LEN] = {0};
#endif /* DEBUG */
  
  info = r;
  cptr = msg;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;

#ifdef DEBUG
    memcpy(buf, cptr, l);
    buf[l+1] = 0;
    EDGE_LOG("Token (%d bytes): %s", l, buf);
#endif /* DEBUG */

    p = cptr;
    
    while (*p == ' ')
      p++;

    if ((l > 0) && (strncmp((const char *)p, "GET", 3) == 0))
    {
      p += 3;

      while (*p != '/')
        p++;

      q = p;

      while (*q != ' ')
        q++;

      if (q - p == 1)
      {
        info->content = (uint8_t *)malloc(INDEX_FILE_LEN);
        memset(info->content, 0x0, INDEX_FILE_LEN);
        memcpy(info->content, INDEX_FILE, INDEX_FILE_LEN);
        info->clen = INDEX_FILE_LEN;
      }
      else
      {
        info->content = (uint8_t *)malloc(q - p);
        memcpy(info->content, p, q - p);
        info->clen = q - p;
      }
    }

    if ((l > 0) && (strncmp((const char *)p, "Host:", 5) == 0))
    {
      p += 5;

      while (*p == ' ')
        p++;

      info->domain = (uint8_t *)malloc(nptr - p);
      memcpy(info->domain, p, nptr - p);
      info->dlen = nptr - p;
    }

    cptr = nptr + DELIMITER_LEN;

#ifdef DEBUG
    memset(buf, 0x0, MAX_HOST_LEN);
#endif /* DEBUG */
  }

  EDGE_LOG("[TA] Domain name in parser (%d bytes): %s", info->dlen, info->domain);
  EDGE_LOG("[TA] Content name in parser (%d bytes): %s", info->clen, info->content);
  EDGE_LOG("Finished: http_parse_request");

  return 1;
}

int get_thread_index(void)
{
  int i, ret = -1;

  for (i=0; i<MAX_THREADS; i++)
    if (!threads[i])
    {
      ret = i;
      break;
    }

  return ret;
}

int http_parse_response(uint8_t *msg, uint32_t mlen, struct rinfo *r)
{
  EDGE_LOG("Start: http_parse_response: msg: %p, mlen: %d, r: %p", msg, mlen, r);
  uint32_t i, j, l;
  uint32_t hdrlen;
  uint8_t *cptr, *nptr, *p;
  cptr = msg;
  hdrlen = 0;

  while ((nptr = strstr(cptr, DELIMITER)))
  {
    l = nptr - cptr;

    hdrlen += (l + 2);
    if (l == 0)
      break;

    p = cptr;

    for (i=0; i<l; i++)
    {
      if (p[i] == ' ')
        break;
    }

    if ((l > 0) && (strncmp((const char *)p, "Content-Length:", i) == 0))
    {
      for (j=i+1; j<l; j++)
      {
        if (p[j] == ' ')
          break;
      }
      r->size = char_to_int(p + i + 1, j - i);
    }

    cptr = nptr + DELIMITER_LEN;
  }

  r->size += hdrlen;
  EDGE_LOG("Finished: http_parse_response: hdrlen: %d, r->size: %d", hdrlen, r->size);
  return r->size;
}

int char_to_int(uint8_t *str, uint32_t slen)
{
  int i;
  int ret = 0;
  uint8_t ch;

  for (i=0; i<slen; i++)
  {
    ch = str[i];
    if (ch == ' ')
      break;

    switch(ch)
    {
      case '0':
        ret *= 10;
        continue;
      case '1':
        ret = ret * 10 + 1;
        continue;
      case '2':
        ret = ret * 10 + 2;
        continue;
      case '3':
        ret = ret * 10 + 3;
        continue;
      case '4':
        ret = ret * 10 + 4;
        continue;
      case '5':
        ret = ret * 10 + 5;
        continue;
      case '6':
        ret = ret * 10 + 6;
        continue;
      case '7':
        ret = ret * 10 + 7;
        continue;
      case '8':
        ret = ret * 10 + 8;
        continue;
      case '9':
        ret = ret * 10 + 9;
        continue;
    }
  }

  EDGE_LOG("Content-Length: %d", ret);
  return ret;
}

#ifdef KEYLESS_SSL
void keyless_ssl_callback(SSL *ssl, uint8_t *out, uint8_t *in, uint32_t ilen, size_t *sig_len)
{
  EDGE_LOG("Start: keyless_ssl_callback");

  EDGE_PRINT("Message to be signed (callback)", in, 0, ilen, 10);
  kssl_op_ecdsa_sign(c, in, ilen, out, sig_len, 3);
  EDGE_PRINT("Signature get from the key server in the callback", out, 0, *sig_len, 10);

  EDGE_LOG("Finished: keyless_ssl_callback");
}
#endif /* KEYLESS_SSL */

void prepare_keyless_ssl(void)
{
  EDGE_LOG("Start: prepare_keyless_ssl");
  const SSL_METHOD *method;
  const char *cipher_list = "ECDHE-ECDSA-AES128-GCM-SHA256";

  method = TLSv1_2_client_method();
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
  
  /*
  if (SSL_CTX_set_cipher_list(kctx, cipher_list) == 0) {
    SSL_CTX_free(kctx);
    fatal_error("Failed to set cipher list: %s", cipher_list);
  }
  */

  SSL_CTX_set_verify(kctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

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

  EDGE_LOG("Finished: prepare_keyless_ssl");
}
