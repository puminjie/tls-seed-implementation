#include "ta_cc.h"
#include "ta_nio.h"
#include "ta_io_process.h"
#include "ta_software_assertion.h"
#include "ta_file_manager.h"
#include "ta_ec_func.h"
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#define FAIL    -1

struct info
{
  uint8_t *ec_digest;
  uint32_t ec_digest_len;
};

TEE_Result cc_make_request(struct io_status_st *io, struct tls_context_record_st *sctx, 
    uint8_t *buf, uint32_t *blen, struct file_manager_st *mngr, struct cmd_st *cctx);

TEE_Result cc_send_request(struct io_status_st *io, struct tls_context_record_st *sctx, 
    struct file_manager_st *mngr, void *data)
{
  TEE_Result res;
  uint8_t buf[BUF_SIZE];
  uint32_t blen;
  struct cmd_st *cctx;
  SSL *ssl;
  ssl = sctx->ssl;

  cctx = (struct cmd_st *)data;
  res = cc_make_request(io, sctx, buf, &blen, mngr, cctx);

  if (blen > 0)
  {
    SSL_write(ssl, buf, blen);
    io->flags |= TA_EC_FLAG_REQUEST_SENT;
  }

  return res;
}

TEE_Result cc_make_request(struct io_status_st *io, struct tls_context_record_st *sctx, 
    uint8_t *buf, uint32_t *blen, struct file_manager_st *mngr, struct cmd_st *cctx)
{ 
  (void) mngr; (void) cctx;
	EVP_PKEY *edge_priv, *orig_pub, *edge_pub;
  uint32_t content_len, request_len, ec_digest_len, sa_len;
  uint8_t *ec_digest, *content, *request, *p, *sa;
  SSL *ssl;
  //uint16_t ht;

  ssl = sctx->ssl;
  p = buf;

  ec_digest = SSL_get_ec_digest(ssl, &ec_digest_len);
  EDGE_PRINT("EC Digest from SSL_get_ec_digest", ec_digest, 0, ec_digest_len, 10);
	edge_priv = SSL_get_privatekey(ssl);
	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));

  struct info *info = (struct info *)malloc(sizeof(struct info *));
  info->ec_digest = (uint8_t *)malloc(ec_digest_len);
  memcpy(info->ec_digest, ec_digest, ec_digest_len);
  info->ec_digest_len = ec_digest_len;
  io->data = (void *)info;

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

  return TEE_SUCCESS;
}
 
TEE_Result cc_parse_data(struct io_status_st *io, uint8_t *msg, uint32_t len)
{
  return TEE_SUCCESS;
}

TEE_Result cc_process_data(struct io_status_st *io, struct tls_context_record_st *sctx, 
    struct file_manager_st *mngr, struct cmd_st *cctx)
{
  EVP_PKEY *edge_priv, *orig_pub, *edge_pub;
  uint32_t ec_digest_len;

  uint8_t *buf, *ec_digest;
  struct buf_st *name, *cc;
  //uint16_t ht;
  struct info *info;
  struct domain_table_st *dom;
  SSL *ssl;

  ssl = sctx->ssl;

  buf = io->buf->data;
  info = (struct info *)io->data;

  get_address(cctx, &name, NULL);

	orig_pub = X509_get_pubkey(SSL_get_peer_certificate(ssl));
	edge_pub = X509_get_pubkey(SSL_get_certificate(ssl));
  ec_digest = info->ec_digest;
  ec_digest_len = info->ec_digest_len;

  EDGE_PRINT("EC Digest in cc process", ec_digest, 0, ec_digest_len, 10);

	if (!verify_cc_response(buf, orig_pub, edge_pub, ec_digest, ec_digest_len))
	{
		EDGE_MSG("CLIENT: Verify the cc response failed\n");
		return TEE_ERROR_BAD_STATE;
	}
	EDGE_MSG("CLIENT: Verify the cc response success\n");
  EDGE_PRINT("Cross Credential Received", io->buf->data, 0, io->buf->len, 10);
  
  dom = mngr->ops->get(mngr, name);
  dom->vops->set_cross_credential(dom, io->buf->data, io->buf->len);

  cctx->flags = TA_EDGE_CACHE_NXT_EXIT;

	return TEE_SUCCESS;
}
