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

int open_listener(int port);
SSL_CTX* init_server_CTX(BIO *outbio);
void load_certificates(BIO *outbio, SSL_CTX* ctx, char* cacert_file, char* cert_file, char* key_file);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
void print_pubkey(BIO *outbio, EVP_PKEY *pkey);
void msg_callback(int, int, int, const void *, size_t, SSL *, void *);
BIO *bio_err;

// Origin Server Implementation
int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	BIO *outbio = NULL;
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
  unsigned char buf[128], resp[512], content[1024], orig_buf[1024];
  unsigned char *p;
  size_t sz;
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);

  const char *domains =
    "www.bob.com\n\n";
  int dlen;

	if ( count != 6 )
	{
		BIO_printf(outbio, "Usage: %s <portnum> <cert_file> <ca_cert_file> <key_file> <orig cert>\n", strings[0]);
		exit(0);
	
  }
  
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];
	cert = strings[2];
	cacert = strings[3];
	key = strings[4];
  orig_cert = strings[5];

  memset(orig_buf, 0x0, 1024);
  orig_fp = fopen(orig_cert, "rb");
  fseek(orig_fp, 0L, SEEK_END);
  sz = ftell(orig_fp);
  fseek(orig_fp, 0L, SEEK_SET);
  fread(orig_buf, 1, sz, orig_fp);
  fclose(orig_fp);

  dlen = strlen(domains);
  p = content;
  memset(p, 0x0, 1024);
  memcpy(p, domains, dlen);
  p += dlen;

  (*p++) = (sz >> 8) & 0xff;
  (*p++) = sz & 0xff;
  memcpy(p, orig_buf, sz);
  p += sz;
  dlen += sz;
  (*p++) = '\n';
  (*p++) = '\n';
  dlen += 2;
  snprintf(resp, 512, response, dlen);
  response_len = strlen(resp);
  memcpy(resp + response_len, content, dlen);
  response_len += dlen;
  printf("Data Length: %d\n", dlen);
  printf("Response Length: %d\n", response_len);

	ctx = init_server_CTX(outbio);
  load_dh_params(ctx, DHFILE);
  load_ecdh_params(ctx);
	load_certificates(outbio, ctx, cacert, cert, key);
	BIO_printf(outbio, "load_certificates success\n");

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

	while ((client = accept(server, (struct sockaddr *)&addr, &len)))
	{
    printf("accept the client\n");
		ssl = SSL_new(ctx);/* get new SSL state with context */
		SSL_set_msg_callback(ssl, msg_callback);
		BIO_printf(outbio, "SSL_new() Success\n");
		SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
		BIO_printf(outbio, "SSL_set_fd() Success\n");

		BIO_printf(outbio, "PROGRESS: TLS Handshake Start\n");
		if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
			ERR_print_errors_fp(stderr);
		BIO_printf(outbio, "PROGRESS: TLS Handshake Complete!\n");

    rcvd = -1;
    while (rcvd < 0)
      rcvd = SSL_read(ssl, buf, 128);
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
			BIO_printf(outbio, "SERVER: Send the HTTP Test Page Failed: %d\n", sent);
			abort();
		}
		BIO_printf(outbio, "SERVER: Send the HTTP Test Page Success: %d\n", sent);

		//close(client);
	}

	SSL_free(ssl);
	SSL_CTX_free(ctx);         /* release context */
	close(client);
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

void msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
	if (write_p == 2)
		printf("buf: %s\n", (unsigned char *)buf);
	else
	{
	}
}

void apps_ssl_info_callback(const SSL *s, int where, int ret)
{
	const char *str;
	int w;

	w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT) str = "SSL_connect";
	else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
	else str = "Undefined";

	if (where & SSL_CB_LOOP)
	{
		BIO_printf(bio_err, "%s:%s\n", str, SSL_state_string_long(s));
	}
	else if (where & SSL_CB_ALERT)
	{
		str = (where & SSL_CB_READ)? "read" : "write";
		BIO_printf(bio_err, "SSL3 alert %s:%s:%s\n",
				str,
				SSL_alert_type_string_long(ret),
				SSL_alert_desc_string_long(ret));
	}
	else if (where & SSL_CB_EXIT)
	{
		if (ret == 0)
			BIO_printf(bio_err, "%s:failed in %s\n",
				str, SSL_state_string_long(s));
		else if (ret < 0)
		{
			BIO_printf(bio_err, "%s:error in %s\n",
				str, SSL_state_string_long(s));
		}
	}
}

SSL_CTX* init_server_CTX(BIO *outbio)
{   
	SSL_METHOD *method;
	SSL_CTX *ctx;

	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD *) TLSv1_2_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		BIO_printf(outbio, "SSL_CTX init failed!");
		abort();
	}

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
	SSL_CTX_set_msg_callback(ctx, msg_callback);

	return ctx;
}

void load_certificates(BIO *outbio, SSL_CTX* ctx, char* cacert_file, char* cert_file, char* key_file)
{
	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, "ca_ecc_alice.pem", "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_load_verify_locations success\n");

	/* Set default paths for certificate verifications */
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_set_default_verify_paths success\n");

	/* Set the local certificate from CertFile */
	if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_use_certificate_file success\n");

	/* Set the private key from KeyFile (may be the same as CertFile) */
	if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_use_PrivateKey_file success\n");

	/* Verify private key */
	if ( !SSL_CTX_check_private_key(ctx) )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_check_private_key success\n");

	ERR_print_errors_fp(stderr);
	ERR_print_errors_fp(stderr);
}

// Print the public key from the certificate
void print_pubkey(BIO *outbio, EVP_PKEY *pkey)
{
	if (pkey)
	{
		switch (EVP_PKEY_id(pkey))
		{
			case EVP_PKEY_RSA:
				BIO_printf(outbio, "%d bit RSA Key\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_DSA:
				BIO_printf(outbio, "%d bit DSA Key\n", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_EC:
				BIO_printf(outbio, "%d bit EC Key\n", EVP_PKEY_bits(pkey));
				break;
			default:
				BIO_printf(outbio, "%d bit non-RSA/DSA/EC Key\n", EVP_PKEY_bits(pkey));
				break;
		}
	}

	if (!PEM_write_bio_PUBKEY(outbio, pkey))
		BIO_printf(outbio, "Error writing public key data in PEM format\n");
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
