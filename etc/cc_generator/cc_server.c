#include <cc.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <simple_http/simple_https.h>
#include <getopt.h>
#include <unistd.h>
#include <debug.h>
#include <defines.h>
#include <setting.h>

#define DEFAULT_CERTIFICATE_NAME "cert.der"
#define DEFAULT_PRIVATE_KEY_NAME "priv.der"
#define DEFAULT_CA_CERTIFICATE "ca.pem"

SSL_CTX* init_server_ctx(const char *cacert, const uint8_t *http);
void print_pubkey(EVP_PKEY *pkey);
void load_ecdh_params(SSL_CTX *ctx);
int load_certs(SSL *ssl, int *ad, void *arg);
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);

int usage(const char *pname)
{
  emsg(">> Usage: %s [options]", pname);
  emsg("Options");
  emsg("  -p, --port     port");
  emsg("  -c, --cacert   CA certificate");
  exit(1);
}

// cc Server Implementation
int main(int argc, char *argv[])
{  
	SSL *ssl;
	SSL_CTX *ctx;
	X509 *orig, *edge;
	EVP_PKEY *orig_priv, *orig_pub, *edge_pub;
	int i, c, ret, err, server, client, request_len, response_len, seed_digest_length, sa_len;
  int port, sent, rcvd, offset, total;
  const char *pname, *cacert, *opt;
  uint8_t *p;
  uint8_t *seed_digest;
	unsigned char *request, *response, *sa;
	unsigned char buf[BUF_SIZE];
  const uint8_t http1_1[] = {0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};

  ctx = NULL;
  pname = argv[0];
  port = DEFAULT_CC_SERVER_PORT;
  cacert = DEFAULT_CA_CERTIFICATE;
  err = 0;

  while (1)
  {
    int idx = 0;
    static struct option long_options[] = {
      {"port", required_argument, 0, 'p'},
      {"cacert", required_argument, 0, 'c'},
      {0, 0, 0, 0}
    };

    opt = "p:c:0";
    c = getopt_long(argc, argv, opt, long_options, &idx);
    if (c == -1) break;

    switch (c)
    {
      case 'p':
        port = atoi(optarg);
        break;
      case 'c':
        cacert = optarg;
        break;
      default:
        usage(pname);
    }
  }

	SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  ctx = init_server_ctx(cacert, http1_1);
	server = open_listener(port, 1);
  if (server < 0)
  {
    emsg("socket error happened");
    usage(pname);
  }

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);

  dmsg("before waiting accept");

  while (1)
  {
    err = 0;
	  if((client = accept(server, (struct sockaddr*)&addr, &len)) > 0)
    {
	    dmsg("Accept a new connection");
	    ssl = SSL_new(ctx);

      if (!ssl)
      {
        emsg("Out of memory");
        abort();
      }

	    dmsg("SSL_new() Success\n");
	    SSL_set_fd(ssl, client);
      SSL_set_accept_state(ssl);

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
      dmsg("TLS session is established with %s", SSL_get_cipher(ssl));

	    orig_priv = SSL_get_privatekey(ssl);
	    orig = SSL_get_certificate(ssl);
	    orig_pub = X509_get_pubkey(orig);
	    edge = SSL_get_peer_certificate(ssl);
	    edge_pub = X509_get_pubkey(edge);

      rcvd = -1;
      while (rcvd < 0)
  	    rcvd = SSL_read(ssl, buf, BUF_SIZE);
      total = rcvd;

	    dmsg("SERVER: Receive the cc request from CLIENT: %d", total);

      p = buf;
      PTR_TO_VAR_2BYTES(p, sa_len);
      dmsg("SERVER: Received length of the sa: %d\n", sa_len);
      sa = (uint8_t *)malloc(sa_len);
      if (!sa) 
      {
        emsg("Out of memory");
        abort();
      }
      memcpy(sa, p, sa_len);
      p += sa_len;

      dprint("Received SA", sa, 0, sa_len, 16);

	    request_len = total - (2 + sa_len);
	    request = OPENSSL_malloc(request_len);
      if (!request)
      {
        emsg("Out of memory");
        abort();
      }
	    memcpy(request, p, request_len);

      if (!verify_software_assertion(ssl, sa, edge_pub, &seed_digest, &seed_digest_length))
      {
        emsg("SERVER: Verify the sa failed");
        abort();
      }
      dmsg("SERVER: Verify the sa success");

	    if (!verify_cc_request(request, orig_pub, edge_pub, seed_digest, seed_digest_length))
	    {
		    emsg("SERVER: Verify the cc request failed");
		    abort();
	    }
	    dmsg("SERVER: Verify the cc request success");

	    if (!make_cc_response(&response, request, request_len, orig_priv, NID_sha256, &response_len))
	    {
		    emsg("SERVER: Make the cc response failed");
		    abort();
	    }
      dprint("CC Response", response, 0, response_len, 16);

      offset = 0;
      while (offset < response_len)
      {
	      sent = SSL_write(ssl, response + offset, response_len - offset);
        if (sent > 0)
          offset += sent;
      }

	    dmsg("SERVER: Send the cc response success: %d\n", total);

	    EVP_PKEY_free(orig_pub);
	    EVP_PKEY_free(edge_pub);

	    OPENSSL_free(request);

	    SSL_free(ssl);
      close(client);
    }
  }

	SSL_CTX_free(ctx);
	close(server);

	return 0;
}

SSL_CTX* init_server_ctx(const char *cacert, const uint8_t *http)
{   
  fstart();
	SSL_METHOD *method;
	SSL_CTX *ctx;
  EC_KEY *ecdh;

	method = (SSL_METHOD *) TLS_server_method();
	ctx = SSL_CTX_new(method);
	if (!ctx)
	{
		emsg("SSL_CTX init failed!");
		abort();
	}
  SSL_CTX_set_alpn_protos(ctx, http, sizeof(http));

  if (SSL_CTX_load_verify_locations(ctx, cacert, "/etc/ssl/certs") != 1)
  {
    ERR_print_errors_fp(stderr);
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

  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  SSL_CTX_set_verify_depth(ctx, 4);
  SSL_CTX_set_tlsext_servername_callback(ctx, load_certs);

  ffinish("ctx: %p", ctx);
	return ctx;
}

int load_certs(SSL *ssl, int *ad, void *arg)
{
  fstart("ssl: %p, ad: %p, arg: %p", ssl, ad, arg);

  int ret;
  const char *name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  uint8_t cname[MAX_FILE_NAME_LEN] = {0, };
  uint8_t pname[MAX_FILE_NAME_LEN] = {0, };

  ret = SSL_TLSEXT_ERR_OK;

  dmsg("Requested name: %s", name);
  snprintf((char *)cname, MAX_FILE_NAME_LEN, "%s/%s", name, DEFAULT_CERTIFICATE_NAME);
  snprintf((char *)pname, MAX_FILE_NAME_LEN, "%s/%s", name, DEFAULT_PRIVATE_KEY_NAME);

  if (access(cname, F_OK) == -1)
  {
    emsg("No support for %s", name);
    ret = SSL_TLSEXT_ERR_ALERT_FATAL;
  }
  else
  {
    if (SSL_use_certificate_file(ssl, cname, SSL_FILETYPE_ASN1) != 1)
    {
      emsg("Loading the service provider %s's certificate error", name);
      ret = SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (SSL_use_PrivateKey_file(ssl, pname, SSL_FILETYPE_ASN1) != 1)
    {
      emsg("Loading the service provider %s's private key", name);
      ret = SSL_TLSEXT_ERR_ALERT_FATAL;
    }
  }

  dmsg("Succeed to load the certificate and the private key of %s", name);
  ffinish();
  return ret;
}

// Print the public key from the certificate
void print_pubkey(EVP_PKEY *pkey)
{
  fstart("pkey: %p", pkey);
	if (pkey)
	{
		switch (EVP_PKEY_id(pkey))
		{
			case EVP_PKEY_RSA:
				dmsg("%d bit RSA Key", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_DSA:
				dmsg("%d bit DSA Key", EVP_PKEY_bits(pkey));
				break;
			case EVP_PKEY_EC:
				dmsg("%d bit EC Key", EVP_PKEY_bits(pkey));
				break;
			default:
				dmsg("%d bit non-RSA/DSA/EC Key", EVP_PKEY_bits(pkey));
				break;
		}
	}
  ffinish();
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
  fstart("preverify_ok: %d, x509_ctx: %p", preverify_ok, x509_ctx);
  dmsg("The verify_callback function is invoked");
  ffinish();
  return 1;
}
