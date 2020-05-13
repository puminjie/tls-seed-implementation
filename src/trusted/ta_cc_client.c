#include "ta_cc.h"
#include "ta_software_assertion.h"
#include "ta_file_manager.h"
#include "ta_ec_func.h"
#include <cmds.h>
#ifdef PLATFORM_OPTEE
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#endif /* PLATFORM_OPTEE */

#define FAIL    -1

struct info
{
  uint8_t *seed_digest;
  uint32_t seed_digest_len;
};

SEED_Result cc_make_request(tls_context_record_t *sctx, uint8_t *buf, uint32_t *blen, 
    file_manager_t *mngr, cctx_t *cctx);

SEED_Result cc_send_request(tls_context_record_t *sctx, cctx_t *cctx, file_manager_t *mngr)
{
  efstart("sctx: %p, cctx: %p, mngr: %p", sctx, cctx, mngr);
  SEED_Result res;
  uint8_t buf[BUF_SIZE];
  uint32_t blen, sent, offset;
  SSL *ssl;
  ssl = sctx->ssl;

  res = cc_make_request(sctx, buf, &blen, mngr, cctx);

  if (blen > 0)
  {
    offset = 0;
    while (offset < blen)
    {
      sent = SSL_write(ssl, buf + offset, blen - offset);
      if (sent > 0)
        offset += sent;
    }
    cctx->stage = TA_EDGE_GET_CC_REQUEST_SENT;
  }

  effinish("res: %d", res);
  return res;
}

SEED_Result cc_make_request(tls_context_record_t *sctx, uint8_t *buf, uint32_t *blen, 
    file_manager_t *mngr, cctx_t *cctx)
{ 
  efstart("sctx: %p, buf: %p, blen: %p, mngr: %p, cctx: %p", sctx, buf, blen, mngr, cctx);
  (void) mngr; (void) cctx;
	EVP_PKEY *edge_priv, *orig_pub, *edge_pub;
  int content_len, request_len;
  uint32_t seed_digest_len, sa_len;
  uint8_t *seed_digest, *content, *request, *p, *sa;
  SSL *ssl;

  ssl = sctx->ssl;
  p = buf;

  seed_digest = SSL_get_seed_digest(ssl, &seed_digest_len);
  edprint("EC Digest from SSL_get_seed_digest", seed_digest, 0, seed_digest_len, 16);
	edge_priv = SSL_get_privatekey(ssl);
	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));

  if (!make_software_assertion(ssl, seed_digest, seed_digest_len, edge_priv, &sa, &sa_len))
  {
    eemsg("CLIENT: Make the software assertion failed");
    abort();
  }
  edmsg("CLIENT: Make the software assertion success");

  edprint("Software Assertion", sa, 0, sa_len, 16);

  VAR_TO_PTR_2BYTES(sa_len, p);
  memcpy(p, sa, sa_len);
  p += sa_len;

	if (!make_cc_content_body(&content, orig_pub, edge_pub, seed_digest, seed_digest_len,
    NID_sha256, &content_len))
	{
		eemsg("CLIENT: Make the cc content failed");
		abort();
	}
	edmsg("CLIENT: Make the cc content success");

	if (!make_cc_request_with_verify_cc(&request, content, content_len, seed_digest,
    seed_digest_len, edge_priv, orig_pub, edge_pub, NID_sha256, &request_len))
	{
		eemsg("CLIENT: Make the cc request message failed");
		abort();
	}
	edmsg("CLIENT: Make the cc request message success");

  memcpy(p, request, request_len);
  p += request_len;

  *blen = 2 + sa_len + request_len;

  effinish();
  return SEED_SUCCESS;
}
 
SEED_Result cc_process_data(tls_context_record_t *sctx, cctx_t *cctx, file_manager_t *mngr)
{
  efstart("sctx: %p, mngr: %p, cctx: %p", sctx, mngr, cctx);
  EVP_PKEY *orig_pub, *edge_pub;
  uint32_t seed_digest_len;
  uint8_t *seed_digest;
  uint8_t buf[BUF_SIZE] = {0, };
  int rlen;
  struct buf_st *name;
  //uint16_t ht;
  struct domain_table_st *dom;
  SSL *ssl;

  ssl = sctx->ssl;
  rlen = SSL_read(ssl, buf, BUF_SIZE);
  if (rlen < 0) goto err;

  get_address(cctx, &name, NULL);

	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));
  seed_digest = SSL_get_seed_digest(ssl, &seed_digest_len);

  dprint("EC Digest in cc process", seed_digest, 0, seed_digest_len, 16);

	if (!verify_cc_response(buf, orig_pub, edge_pub, seed_digest, seed_digest_len))
	{
		dmsg("CLIENT: Verify the cc response failed\n");
		return SEED_ERROR_BAD_STATE;
	}
	dmsg("CLIENT: Verify the cc response success\n");
  dprint("Cross Credential Received", buf, 0, rlen, 16);

  dom = mngr->ops->get(mngr, name);
  dom->vops->set_cross_credential(dom, buf, rlen);

  cctx->stage = TA_EDGE_GET_CC_RESPONSE_RCVD;

	return SEED_SUCCESS;

err:
  return SEED_FAILURE;
}
