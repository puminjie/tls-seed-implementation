#include "cc.h"
#include "io_process.h"

#define SUCCESS 1
#define FAIL    -1

struct info
{
  uint8_t *ec_digest;
  uint32_t ec_digest_len;
};

int cc_make_request(SSL *ssl, uint8_t *buf, uint32_t *blen);

int cc_send_request(SSL *ssl)
{
  int res;
  uint8_t buf[BUF_SIZE];
  uint32_t blen;

  res = cc_make_request(ssl, buf, &blen);

  if (blen > 0)
  {
    SSL_write(ssl, buf, blen);
  }

  return res;
}

int cc_make_request(SSL *ssl, uint8_t *buf, uint32_t *blen)
{ 
	EVP_PKEY *edge_priv, *orig_pub, *edge_pub;
  uint32_t content_len, request_len, ec_digest_len, sa_len;
  uint8_t *ec_digest, *content, *request, *p, *sa;

  p = buf;

  ec_digest = SSL_get_ec_digest(ssl, &ec_digest_len);
  EDGE_PRINT("EC Digest from SSL_get_ec_digest", ec_digest, 0, ec_digest_len, 10);
	edge_priv = SSL_get_privatekey(ssl);
	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));

  EDGE_PRINT("EC Digest before make sa function", ec_digest, 0, ec_digest_len, 10);

  if (!make_software_assertion(ssl, ec_digest, ec_digest_len, edge_priv, &sa, &sa_len))
  {
    EDGE_MSG("CLIENT: Make the software assertion failed");
    abort();
  }
  EDGE_MSG("CLIENT: Make the software assertion success");

  EDGE_PRINT("Software Assertion", sa, 0, sa_len, 10);

  s2n(sa_len, p);
  memcpy(p, sa, sa_len);
  p += sa_len;

	if (!make_cc_content_body(&content, orig_pub, edge_pub, ec_digest, ec_digest_len,
    NID_sha256, &content_len))
	{
		EDGE_MSG("CLIENT: Make the cc content failed");
		abort();
	}
	EDGE_MSG("CLIENT: Make the cc content success");

	if (!make_cc_request_with_verify_cc(&request, content, content_len, ec_digest,
    ec_digest_len, edge_priv, orig_pub, edge_pub, NID_sha256, &request_len))
	{
		EDGE_MSG("CLIENT: Make the cc request message failed");
		abort();
	}
	EDGE_MSG("CLIENT: Make the cc request message success");

  memcpy(p, request, request_len);
  p += request_len;

  *blen = 2 + sa_len + request_len;

  return SUCCESS;
}
 
int cc_parse_data(uint8_t *msg, uint32_t len)
{
  return SUCCESS;
}

int cc_process_data(SSL *ssl, uint8_t *buf, uint32_t len)
{
  EVP_PKEY *edge_priv, *orig_pub, *edge_pub;
  uint32_t ec_digest_len;
  uint8_t *ec_digest;

	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));
  ec_digest = SSL_get_ec_digest(ssl, &ec_digest_len);

  EDGE_PRINT("EC Digest in cc process", ec_digest, 0, ec_digest_len, 10);

	if (!verify_cc_response(buf, orig_pub, edge_pub, ec_digest, ec_digest_len))
	{
		EDGE_MSG("CLIENT: Verify the cc response failed\n");
		abort();
	}
	EDGE_MSG("CLIENT: Verify the cc response success\n");
  EDGE_PRINT("Cross Credential Received", buf, 0, len, 10);
  
	return SUCCESS;
}
