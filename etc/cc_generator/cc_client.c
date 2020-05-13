#include "cc.h"
#include "logger.h"
#include "digest.h"

#define FAIL    -1

int open_connection(const char *hostname, int port);
SSL_CTX* init_client_CTX(void);
void load_certificates(BIO *outbio, SSL_CTX* ctx, char* cert_file, char* key_file, 
    char *ca_file);
void print_pubkey(BIO *outbio, EVP_PKEY *pkey);
void load_ecdh_params(SSL_CTX *ctx);

// cc Client Implementation
int main(int count, char *strings[])
{   
	SSL *ssl;
  SSL_CTX *ctx;
	X509 *orig, *edge;
	EVP_PKEY *edge_priv, *orig_pub, *edge_pub;
	BIO *outbio = NULL, *outfile = NULL;
	int server, sent, recv, total = 0, content_len, request_len, response_len, ec_digest_length;
  char *hostname, *portnum, *cert, *ca, *key, *output;
	unsigned char *content, *request, *response;

  if ( count != 7 )
  {
    BIO_printf(outbio, "usage: %s <hostname> <portnum> <client certificate> <client private key> <ca certificate> <cc output file>\n", strings[0]);
    exit(0);
  }
  SSL_library_init();
  hostname = strings[1];
  portnum = strings[2];
	cert = strings[3];
	key = strings[4];
  ca = strings[5];
	output = strings[6];

  outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

	outfile = BIO_new(BIO_s_file());
	if (!BIO_write_filename(outfile, output))
	{
		BIO_printf(outbio, "CLIENT: Open the output file error\n");
		abort();
	}
	BIO_printf(outbio, "CLIENT: Open the output file success\n");

  ctx = init_client_CTX();
  load_ecdh_params(ctx);
  load_certificates(outbio, ctx, cert, key, ca);
  server = open_connection(hostname, atoi(portnum));
  ssl = SSL_new(ctx);      /* create new SSL connection state */
  SSL_set_fd(ssl, server);    /* attach the socket descriptor */

  struct timeval tv;
  gettimeofday( &tv, 0 );

	unsigned long hs_start, hs_end;
  ec_digest_length = sizeof(ec_digest);

	BIO_printf(outbio, "PROGRESS: TLS Handshake Start\n");
	hs_start = get_current_microseconds();
  if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
    ERR_print_errors_fp(stderr);
  else
  {   
	  hs_end = get_current_microseconds();
    BIO_printf(outbio, "PROGRESS: TLS Handshake Complete!\nConnected with %s encryption\n", 
        SSL_get_cipher(ssl));
		BIO_printf(outbio, "ELAPSED TIME: %lu us\n", hs_end - hs_start);
        
		edge_priv = SSL_get_privatekey(ssl);
		orig = SSL_get_peer_certificate(ssl);
		orig_pub = X509_get_pubkey(orig);
		edge = SSL_get_certificate(ssl);
		edge_pub = X509_get_pubkey(edge);

		BIO_printf(outbio, "Origin's public key >>>\n");
		print_pubkey(outbio, orig_pub);
		BIO_printf(outbio, "Edge's public key >>>\n");
		print_pubkey(outbio, edge_pub);

		if (!make_cc_content_body(&content, orig_pub, edge_pub, ec_digest, ec_digest_length,
          NID_sha256, &content_len))
		{
			BIO_printf(outbio, "CLIENT: Make the cc content failed\n");
			abort();
		}
		BIO_printf(outbio, "CLIENT: Make the cc content success\n");

		if (!make_cc_request_with_verify_cc(&request, content, content_len, ec_digest,
          ec_digest_length, edge_priv, orig_pub, edge_pub, NID_sha256, &request_len))
		{
			BIO_printf(outbio, "CLIENT: Make the cc request message failed\n");
			abort();
		}
		BIO_printf(outbio, "CLIENT: Make the cc request message success\n");

		sent = SSL_write(ssl, request, request_len);

		if (sent != request_len)
		{
			BIO_printf(outbio, "CLIENT: Send the cc request failed: %d\n", sent);
			abort();
		}

		unsigned char buf[2048];

		recv = SSL_read(ssl, buf, 2048);
		total += recv;

		BIO_printf(outbio, "CLIENT: Receive the cc response from SERVER: %d\n", total);

		response_len = total;
		response = OPENSSL_malloc(response_len);
		memcpy(response, buf, response_len);

		if (!verify_cc_response(response, orig_pub, edge_pub, ec_digest, ec_digest_length))
		{
			BIO_printf(outbio, "CLIENT: Verify the cc response failed\n");
			abort();
		}
		BIO_printf(outbio, "CLIENT: Verify the cc response success\n");

		BIO_write(outfile, response, response_len);

		BIO_printf(outbio, "CLIENT: Write the cc into the file: %s\n", strings[5]);

		OPENSSL_free(content);
		OPENSSL_free(request);
		EVP_PKEY_free(orig_pub);
		EVP_PKEY_free(edge_pub);

		SSL_free(ssl);        /* release connection state */
       
		close(server);         /* close socket */
		SSL_CTX_free(ctx);        /* release context */
	}
	return 0;
}

int open_connection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;
            
    if ( (host = gethostbyname(hostname)) == NULL )
    {
          perror(hostname);
          abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
         close(sd);
         perror(hostname);
         abort();
    }
         return sd;
}
 
SSL_CTX* init_client_CTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
        
    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = (SSL_METHOD *)TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
         ERR_print_errors_fp(stderr);
         abort();
    }
    return ctx;
}
 
void load_certificates(BIO *outbio, SSL_CTX* ctx, char* cert_file, char* key_file, char *ca_file)
{
  if ( SSL_CTX_load_verify_locations(ctx, ca_file, "/etc/ssl/certs") != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_load_verify_locations success\n");

	if ( SSL_CTX_set_default_verify_paths(ctx) != 1)
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	else
		BIO_printf(outbio, "SSL_CTX_set_default_verify_paths success\n");

    /* set the local certificate from CertFile */
  if ( SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
	}
  else
		BIO_printf(outbio, "SSL_CTX_use_certificate_file success\n");

	/* set the private key from KeyFile (may be the same as CertFile) */
  if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0 )
  {
    ERR_print_errors_fp(stderr);
    abort();
  }
	else
		BIO_printf(outbio, "SSL_CTX_use_PrivateKey_file success\n");
    
	/* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
       	ERR_print_errors_fp(stderr);
       	abort();
    }
	else
	   	BIO_printf(outbio, "Private key matches the public certificate\n");

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	ERR_print_errors_fp(stderr);
	SSL_CTX_set_verify_depth(ctx, 4);
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

void load_ecdh_params(SSL_CTX *ctx)
{
  EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

  if (!ecdh)
    perror("Couldn't load the EC key");

  if (SSL_CTX_set_tmp_ecdh(ctx, ecdh) != 1)
    perror("Couldn't set the ECDH parameter (NID_X9_62_prime256v1)");
}
