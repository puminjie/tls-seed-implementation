#include <cc.h>
#include <defines.h>
#include <debug.h>
#include <setting.h>

struct info
{
  uint8_t *ec_digest;
  uint32_t ec_digest_len;
};

int cc_make_request(SSL *ssl, uint8_t *buf, uint32_t *blen);

int cc_send_request(SSL *ssl)
{
  int res, sent, offset;
  uint8_t buf[BUF_SIZE];
  uint32_t blen;

  res = cc_make_request(ssl, buf, &blen);

  offset = 0;
  do {
    sent = SSL_write(ssl, buf + offset, blen - offset);
    offset += sent;
  } while (offset < blen);

  return res;
}

int cc_make_request(SSL *ssl, uint8_t *buf, uint32_t *blen)
{ 
  fstart("ssl: %p, buf: %p, blen: %p", ssl, buf, blen);
	EVP_PKEY *edge_priv, *orig_pub, *edge_pub;
  uint32_t content_len, request_len, ec_digest_len, sa_len;
  uint8_t *ec_digest, *content, *request, *p, *sa;

  p = buf;

  ec_digest = SSL_get_seed_digest(ssl, &ec_digest_len);
  dprint("EC Digest from SSL_get_ec_digest", ec_digest, 0, ec_digest_len, 16);
	edge_priv = SSL_get_privatekey(ssl);
	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));

  dprint("EC Digest before make sa function", ec_digest, 0, ec_digest_len, 16);

  if (!make_software_assertion(ssl, ec_digest, ec_digest_len, edge_priv, &sa, &sa_len))
  {
    emsg("CLIENT: Make the software assertion failed");
    goto err;
  }
  dmsg("CLIENT: Make the software assertion success");

  dprint("Software Assertion", sa, 0, sa_len, 16);

  VAR_TO_PTR_2BYTES(sa_len, p);
  memcpy(p, sa, sa_len);
  p += sa_len;

	if (!make_cc_content_body(&content, orig_pub, edge_pub, ec_digest, ec_digest_len,
    NID_sha256, (int *)&content_len))
	{
		emsg("CLIENT: Make the cc content failed");
		goto err;
	}
	dmsg("CLIENT: Make the cc content success");

	if (!make_cc_request_with_verify_cc(&request, content, content_len, ec_digest,
    ec_digest_len, edge_priv, orig_pub, edge_pub, NID_sha256, (int *)&request_len))
	{
		emsg("CLIENT: Make the cc request message failed");
		goto err;
	}
	dmsg("CLIENT: Make the cc request message success");

  memcpy(p, request, request_len);
  p += request_len;

  *blen = 2 + sa_len + request_len;

  ffinish();
  return CC_SUCCESS;

err:
  ferr();
  return CC_FAILURE;
}
 
int cc_process_data(SSL *ssl, uint8_t *buf, uint32_t len)
{
  fstart("ssl: %p, buf: %p, len: %d", ssl, buf, len);
  EVP_PKEY *orig_pub, *edge_pub;
  uint32_t ec_digest_len;
  uint8_t *ec_digest;

	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));
  ec_digest = SSL_get_seed_digest(ssl, &ec_digest_len);

  dprint("EC Digest in cc process", ec_digest, 0, ec_digest_len, 16);

	if (!verify_cc_response(buf, orig_pub, edge_pub, ec_digest, ec_digest_len))
	{
		emsg("CLIENT: Verify the cc response failed\n");
    goto err;
	}
	dmsg("CLIENT: Verify the cc response success\n");
  dprint("Cross Credential Received", buf, 0, len, 16);
  
  ffinish();
	return CC_SUCCESS;

err:
  ferr();
  return CC_FAILURE;
}
