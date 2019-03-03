#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/logs.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

//#include "log_client.h"

#define FAIL          -1
#define BUF_SIZE      16384
#define DHFILE        "dh1024.pem"
#define MAX_HOST_LEN  256

#define DELIMITER     "\r\n"
#define DELIMITER_LEN 2

#define INDEX_FILE      "/index.html"
#define INDEX_FILE_LEN  12

struct rinfo
{
  uint8_t *domain;
  uint32_t dlen;
  uint8_t *content;
  uint32_t clen;
  uint32_t size;
  uint32_t sent;
};

int open_listener(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
log_t time_log[NUM_OF_LOGS];
int running = 1;
int http_parse_request(uint8_t *msg, uint32_t mlen, struct rinfo *r);
size_t fetch_content(uint8_t *buf, struct rinfo *r);
int fetch_cert(SSL *ssl, int *ad, void *arg);

void int_handler(int dummy)
{
  EDGE_LOG("End of experiment");
  running = 0;
  exit(0);
}

// Origin Server Implementation
int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	int server, client, sent = -1, rcvd = -1;
	char *portnum;

	if ( count != 2 )
	{
		printf("Usage: %s <portnum>\n", strings[0]);
		exit(0);
	}

  signal(SIGINT, int_handler);
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];

	ctx = init_server_ctx();
  load_ecdh_params(ctx);
	load_certificates(ctx);
	EDGE_LOG("load_certificates success");

  INITIALIZE_LOG(time_log);

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (running)
	{
    RECORD_LOG(time_log, SERVER_TCP_START);
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      struct rinfo r;
      char rbuf[BUF_SIZE] = {0};
      char wbuf[BUF_SIZE] = {0};

      RECORD_LOG(time_log, SERVER_TCP_END);
      INTERVAL(time_log, SERVER_TCP_START, SERVER_TCP_END);
      EDGE_LOG("New Connection is accepted");
		  ssl = SSL_new(ctx);
		  SSL_set_fd(ssl, client);      
      SSL_set_time_log(ssl, time_log);

      RECORD_LOG(SSL_get_time_log(ssl), SERVER_BEFORE_TLS_ACCEPT);
		  if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
			  ERR_print_errors_fp(stderr);
      RECORD_LOG(SSL_get_time_log(ssl), SERVER_AFTER_TLS_ACCEPT);
      INTERVAL(SSL_get_time_log(ssl), SERVER_BEFORE_TLS_ACCEPT, SERVER_AFTER_TLS_ACCEPT);

      while (rcvd < 0)
        rcvd = SSL_read(ssl, rbuf, BUF_SIZE);

      RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START);
      EDGE_LOG("rcvd: %d", rcvd);
      if (rcvd > 0)
      {
        EDGE_LOG("before http parse requeset");
        http_parse_request(rbuf, rcvd, &r);
        len = fetch_content(wbuf, &r);
        EDGE_LOG("len: %d", len);
      }

      if (len > 0)
  		  sent = SSL_write(ssl, wbuf, len);

      RECORD_LOG(SSL_get_time_log(ssl), SERVER_SERVE_HTML_END);
      INTERVAL(SSL_get_time_log(ssl), SERVER_SERVE_HTML_START, SERVER_SERVE_HTML_END);
      EDGE_LOG("HTTP Request Length: %d, HTTP Response Length: %d", rcvd, sent);

		  if (sent != len)
		  {
			  EDGE_LOG("SERVER: Send the HTTP Test Page Failed: %d", sent);
			  abort();
		  } 
		  EDGE_LOG("SERVER: Send the HTTP HTTP Test Page Success: %d", sent);
      
      close(client);
      SSL_free(ssl);

      memset(rbuf, 0x0, BUF_SIZE);
      memset(wbuf, 0x0, BUF_SIZE);
    }
	}

	SSL_CTX_free(ctx);         /* release context */
	close(server);          /* close server socket */

	return 0;
}

int open_listener(int port)
{   int sd;
	struct sockaddr_in addr;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	
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
	return sd;
}

SSL_CTX* init_server_ctx(void)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLS_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		EDGE_LOG("SSL_CTX init failed!");
		abort();
	}

  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

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

int fetch_cert(SSL *ssl, int *ad, void *arg)
{
  EDGE_MSG("Start: fetch_cert");
  EDGE_LOG("ssl: %p, ad: %p, arg: %p", ssl, ad, arg);
  (void) ad;
  (void) arg;

  int ret;
  uint8_t crt_path[MAX_HOST_LEN];
  uint8_t priv_path[MAX_HOST_LEN];
  uint8_t *p;
  uint32_t len;

  if (!ssl)
    return SSL_TLSEXT_ERR_NOACK;

  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  if (!name || name[0] == '\0')
    return SSL_TLSEXT_ERR_NOACK;

  memset(crt_path, 0x0, MAX_HOST_LEN);
  memset(priv_path, 0x0, MAX_HOST_LEN);

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
  memcpy(p, "/cert.der", 9);

  p = priv_path;
  len = strlen(name);
  memcpy(p, name, len);

  p += len;
  memcpy(p, "/priv.der", 9);

  EDGE_LOG("crt_path: %s", crt_path);
  EDGE_LOG("priv_path: %s", priv_path);

  if (SSL_use_certificate_file(ssl, crt_path, SSL_FILETYPE_ASN1) != 1)
  {
    EDGE_LOG("Loading the certificate error");
    return SSL_TLSEXT_ERR_NOACK;
  }

  EDGE_MSG("Loading the certificate success");

  if (SSL_use_PrivateKey_file(ssl, priv_path, SSL_FILETYPE_ASN1) != 1)
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
  EDGE_MSG("Start: fetch_content");
  EDGE_LOG("buf: %p, r: %p", buf, r);

	const char *resp = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %ld\r\n"
		"\r\n";

  FILE *fp;
  size_t total, sz;
  uint8_t path[MAX_HOST_LEN];
  uint8_t *p;
  int rlen;
  rlen = 0;

  memset(path, 0x0, MAX_HOST_LEN);
  p = path;

  memcpy(p, r->domain, r->dlen);
  p += r->dlen;
  
  memcpy(p, r->content, r->clen);

  EDGE_LOG("path: %s", path);

  fp = fopen(path, "rb");

  if (!fp)
  {
    EDGE_LOG("Error in opening the file");
    return -1;
  }

  fseek(fp, 0L, SEEK_END);
  total = ftell(fp);
  sz = total - r->sent;
  EDGE_LOG("sz: %ld, r->sent: %u", sz, r->sent);

  if (sz > BUF_SIZE)
    sz = BUF_SIZE;

  fseek(fp, r->sent, SEEK_SET);

  memset(buf, 0x0, BUF_SIZE);
  p = buf;
  snprintf(p, BUF_SIZE, resp, sz);
  rlen = strlen(buf);
  p += rlen;
  fread(p, 1, sz, fp);
  fclose(fp);

  EDGE_LOG("sz: %ld, rlen: %d", sz, rlen);
  EDGE_MSG("Finished: fetch_content");
  return sz + rlen;
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

