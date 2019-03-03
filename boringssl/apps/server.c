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
#include <openssl/sha.h>
#include <sys/time.h>
#include <sys/socket.h>

#include "log_client.h"
#include "cert.h"
#include "digest.h"

#define FAIL    -1
#define DHFILE  "dh1024.pem"

int open_listener(int port);
SSL_CTX* init_server_CTX(BIO *outbio);
void load_certificates(BIO *outbio, SSL_CTX* ctx);
void load_dh_params(SSL_CTX *ctx, char *file);
void load_ecdh_params(SSL_CTX *ctx);
void print_pubkey(BIO *outbio, EVP_PKEY *pkey);
void msg_callback(int, int, int, const void *, size_t, SSL *, void *);
int get_ec_digest(uint8_t *digest, uint16_t *ht, size_t *len);
BIO *bio_err;
log_t time_log[NUM_OF_LOGS];

// Origin Server Implementation
int main(int count, char *strings[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	BIO *outbio = NULL;
	int server, client;
	char *portnum, *cert, *key, *cacert;
	const char *response = 	
		"HTTP/1.1 200 OK\r\n"
		"Content-Type: text/html\r\n"
		"Content-Length: 72\r\n"
		"\r\n"
		"<html><title>Test</title><body><h1>Test Alice's Page!</h1></body></html>";
	int response_len = strlen(response);
	outbio = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);

	if ( count != 2 )
	{
		BIO_printf(outbio, "Usage: %s <portnum> <cert_file> <ca_cert_file> <key_file>\n", strings[0]);
		exit(0);
	}
	SSL_library_init();
	OpenSSL_add_all_algorithms();

	portnum = strings[1];

	ctx = init_server_CTX(outbio);
  load_dh_params(ctx, DHFILE);
  load_ecdh_params(ctx);
	load_certificates(outbio, ctx);
	BIO_printf(outbio, "load_certificates success\n");

	server = open_listener(atoi(portnum));    /* create server socket */

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

  INITIALIZE_LOG(time_log);

	while ((client = accept(server, (struct sockaddr *)&addr, &len)))
	{
		ssl = SSL_new(ctx);/* get new SSL state with context */
    SSL_set_get_ec_digest(ssl, get_ec_digest);
    SSL_set_ec_digest(ssl);
    if (SSL_use_cc_mem(ssl, cc_buf, sizeof(cc_buf)) != 1)
    {
      BIO_printf(outbio, "SSL_use_cc_mem() Error");
      break;
    }
    SSL_set_time_log(ssl, time_log);
		//SSL_set_msg_callback(ssl, msg_callback);
		BIO_printf(outbio, "SSL_new() Success\n");
		SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
		BIO_printf(outbio, "SSL_set_fd() Success\n");

		unsigned long hs_start, hs_end;
		BIO_printf(outbio, "PROGRESS: TLS Handshake Start\n");
		hs_start = get_current_microseconds();

    RECORD_LOG(SSL_get_time_log(ssl), SERVER_HANDSHAKE_START);
		if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
			ERR_print_errors_fp(stderr);
    RECORD_LOG(SSL_get_time_log(ssl), SERVER_HANDSHAKE_END);
    INTERVAL(SSL_get_time_log(ssl), SERVER_HANDSHAKE_START, SERVER_HANDSHAKE_END);
		hs_end = get_current_microseconds();
		BIO_printf(outbio, "PROGRESS: TLS Handshake Complete!\n");

		BIO_printf(outbio, "ELAPSED TIME: %lu us\n", hs_end - hs_start);

		int sent = 0;

		sent = SSL_write(ssl, response, response_len);

		if (sent != response_len)
		{
			BIO_printf(outbio, "SERVER: Send the HTTP Test Page Failed: %d\n", sent);
			abort();
		}
		BIO_printf(outbio, "SERVER: Send the HTTP HTTP Test Page Success: %d\n", sent);

	}

  PRINT_LOG(SSL_get_time_log(ssl));
  FINALIZE(SSL_get_time_log(ssl), "server_log.csv");
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
	method = (SSL_METHOD *) TLS_server_method();  /* create new server-method instance */
	ctx = SSL_CTX_new(method);   /* create new context from method */
	if ( ctx == NULL )
	{
		BIO_printf(outbio, "SSL_CTX init failed!");
		abort();
	}

  SSL_CTX_set_get_ec_digest(ctx, get_ec_digest);

	//SSL_CTX_set_info_callback(ctx, apps_ssl_info_callback);
	//SSL_CTX_set_msg_callback(ctx, msg_callback);

	return ctx;
}

void load_certificates(BIO *outbio, SSL_CTX* ctx)
{
  int crt_sz, priv_sz, orig_sz;
  crt_sz = sizeof(crt_buf);
  priv_sz = sizeof(priv_buf);
  orig_sz = sizeof(orig_buf);

	/* Load certificates for verification purpose*/
	if (SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ssl/certs") != 1)
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
	//if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
	if ( SSL_CTX_use_certificate_ASN1(ctx, crt_sz, crt_buf) != 1 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_use_certificate_ASN1 success\n");

  if ( SSL_CTX_use_orig_certificate_ASN1(ctx, orig_sz, orig_buf) != 1 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_use_orig_certificate_ASN1 success\n");

	/* Set the private key from KeyFile (may be the same as CertFile) */
	//if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
	if ( SSL_CTX_use_PrivateKey_ASN1(EVP_PKEY_EC, ctx, priv_buf, priv_sz) != 1 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_use_PrivateKey_ASN1 success\n");

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

int get_ec_digest(uint8_t *digest, uint16_t *ht, size_t *len)
{
  printf("[tls-ec] get_ec_digest\n");
  int ret = 0;
  int i;
  
  printf("\n[tls-ec] ec_digest\n");
  for (i=0; i<sizeof(ec_digest); i++)
  {
    printf("%02X ", ec_digest[i]);
    if (i % 10 == 9)
      printf("\n");
  }
  printf("\n\n");

  memcpy(digest, ec_digest, sizeof(ec_digest));
  *len = sizeof(ec_digest);

  switch(*len)
  {
    case SHA_DIGEST_LENGTH:
      *ht = NID_sha1;
      break;
    case SHA224_DIGEST_LENGTH:
      *ht = NID_sha224;
      break;
    case SHA256_DIGEST_LENGTH:
      *ht = NID_sha256;
      break;
    case SHA384_DIGEST_LENGTH:
      *ht = NID_sha384;
      break;
    case SHA512_DIGEST_LENGTH:
      *ht = NID_sha512;
      break;
  }

  printf("\n[tls-ec] digest\n");
  for (i=0; i<sizeof(ec_digest); i++)
  {
    printf("%02X ", digest[i]);
    if (i % 10 == 9)
      printf("\n");
  }
  printf("\n\n");

  ret = 1;
  printf("[tls-ec] get_ec_digest is complete\n");
  return 1;
}
