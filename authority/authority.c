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
#include <sys/time.h>
#include <sys/socket.h>

#define FAIL    -1
#define DHFILE  "dh1024.pem"
#define BUF_SIZE 4096

int open_listener(int port);
SSL_CTX* init_server_ctx(void);
void load_certificates(SSL_CTX* ctx, char* cert, char* key);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);

// Origin Server Implementation
int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
  FILE *orig_fp;
	int server, client;
	char *portnum, *cert, *key, *cacert, *orig_cert;
	const char *response = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: %d\r\n"
		"\r\n";
	int response_len = strlen(response);
  int sent, rcvd;
  unsigned char buf[BUF_SIZE], resp[BUF_SIZE], content[BUF_SIZE], orig_buf[BUF_SIZE];
  unsigned char *p;
  size_t sz;

  const char *domains =
    "www.bob.com\n\n";
  int dlen;

	if ( count != 5 )
	{
		printf("Usage: %s <portnum> <cert_file> <key_file> <orig cert>\n", strings[0]);
		exit(0);
	
  }
  
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
	cert = strings[2];
	key = strings[3];
  orig_cert = strings[4];

  memset(buf, 0x0, BUF_SIZE);
  memset(resp, 0x0, BUF_SIZE);
  memset(content, 0x0, BUF_SIZE);
  memset(orig_buf, 0x0, BUF_SIZE);

  orig_fp = fopen(orig_cert, "rb");
  fseek(orig_fp, 0L, SEEK_END);
  sz = ftell(orig_fp);
  fseek(orig_fp, 0L, SEEK_SET);
  fread(orig_buf, 1, sz, orig_fp);
  fclose(orig_fp);

  dlen = strlen(domains);
  p = content;
  memset(p, 0x0, BUF_SIZE);
  memcpy(p, domains, dlen);
  p += dlen;

  (*p++) = (sz >> 8) & 0xff;
  (*p++) = sz & 0xff;
  dlen += 2;
  memcpy(p, orig_buf, sz);
  p += sz;
  dlen += sz;
  (*p++) = '\n';
  (*p++) = '\n';
  dlen += 2;
  snprintf(resp, BUF_SIZE, response, dlen);
  response_len = strlen(resp);
  memcpy(resp + response_len, content, dlen);
  response_len += dlen;
  printf("Data Length: %d\n", dlen);
  printf("Response Length: %d\n", response_len);

	ctx = init_server_ctx();
  load_dh_params(ctx, DHFILE);
  load_ecdh_params(ctx);
	load_certificates(ctx, cert, key);
	printf("load_certificates success\n");

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while (1)
	{
    if ((client = accept(server, (struct sockaddr *)&addr, &len)) > 0)
    {
      printf("accept the client\n");
		  ssl = SSL_new(ctx);
		  SSL_set_fd(ssl, client);
      SSL_set_time_log(ssl, NULL);
      SSL_disable_ec(ssl);
      SSL_disable_keyless_ssl(ssl);

		  printf("PROGRESS: TLS Handshake Start\n");
		  if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
			  ERR_print_errors_fp(stderr);
		  printf("PROGRESS: TLS Handshake Complete!\n");

      rcvd = -1;
      while (rcvd < 0)
        rcvd = SSL_read(ssl, buf, BUF_SIZE);
      if (rcvd == 0)
      {
        printf("Error in the client\n");
        break;
      }
      printf("Received: %d\n", rcvd);
      buf[rcvd] = 0;
      printf("Request: %s\n", buf);
		  sent = SSL_write(ssl, resp, response_len);

		  if (sent != response_len)
		  {
			  printf("SERVER: Send the HTTP Test Page Failed: %d\n", sent);
			  abort();
		  }
		  printf("SERVER: Send the HTTP Test Page Success: %d\n", sent);
      SSL_free(ssl);
      close(client);
    }
	}

	SSL_CTX_free(ctx);         /* release context */
	close(server);          /* close server socket */

	return 0;
}

int open_listener(int port)
{   
  int sd, option;
	struct sockaddr_in addr;
  option = 1;

	sd = socket(PF_INET, SOCK_STREAM, 0);
	setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

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
	method = (SSL_METHOD *) TLSv1_2_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		printf("SSL_CTX init failed!");
		abort();
	}

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	return ctx;
}

void load_certificates(SSL_CTX* ctx, char* cert, char* key)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, "ca_ecc_alice.pem", "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_load_verify_locations success\n");

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_set_default_verify_paths success\n");

	/* Set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_use_certificate_file success\n");

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_use_PrivateKey_file success\n");

	/* Verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		printf("SSL_CTX_check_private_key success\n");

	ERR_print_errors_fp(stderr);
	ERR_print_errors_fp(stderr);
}

void load_dh_params(SSL_CTX *ctx, char *file)
{
  DH *ret = 0;
  BIO *bio;

  if ((bio = BIO_new_file(file, "r")) == NULL)
    perror("Couldn't open the DH file");

  ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
  BIO_free(bio);

  if (SSL_CTX_set_tmp_dh(ctx, ret) != 1)
    perror("Couldn't set the DH parameter");
}

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the ec key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}
