#include <openssl/ssl.h>
#include "ta_ec_func.h"
#include "ta_buf.h"
#include <debug.h>
#include <cmds.h>
#include <setting.h>

/**
 * @brief Set the address information into the command context
 * @param cctx the command context
 * @param name the domain name
 * @param port the port number
 * @return error code
 */
SEED_Result set_address(cctx_t *cctx, buf_t *name, uint16_t port)
{
  efstart("cctx: %p, name->data: %s, name->offset: %d name->max: %d, port: %u", cctx, name->data, name->offset, name->max, port);
  assert(cctx != NULL);
  assert(name != NULL);

  // hostname length (1 byte) || hostname || port (2 bytes)
  uint8_t *p;
  p = cctx->arg;
  (*p++) = name->max;
  memcpy(p, name->data, name->max);
  p += name->max;
  VAR_TO_PTR_2BYTES(port, p);
  cctx->alen = p - cctx->arg;

  effinish();
  return SEED_SUCCESS;
}

/**
 * @brief Get the address information from the command context
 * @param cctx the command context
 * @param name the pointer to the address name
 * @param port the pointer to the port number
 * @return the length of the header
 */
int get_address(cctx_t *cctx, buf_t **name, uint16_t *port)
{
  efstart("cctx: %p, name: %p, port: %p", cctx, name, port);
  assert(cctx != NULL);
  assert(name != NULL);

  uint8_t hlen;
  uint8_t *p;
  p = cctx->arg;
  hlen = (*p++);
  dmsg("hlen: %d", hlen);
  (*name) = init_memcpy_buf_mem(NULL, p, hlen);
  p += hlen;
  if (port)
    PTR_TO_VAR_2BYTES(p, (*port));

  effinish("hlen: %d", hlen);
  return hlen;
}

int pre_read_operation(tls_context_record_t *sctx, bctx_t *rctx)
{
  efstart("sctx: %p, rctx: %p", sctx, rctx);
  const SSL *ssl = sctx->ssl;
  uint8_t *p;
  int len;

  if (sctx->chlen < 0)
    goto out;

  if (rctx->end != rctx->start || rctx->full == 1)
  {
    if (rctx->end > rctx->start)
      sctx->chlen = rctx->end - rctx->start;
    else if (rctx->full == 1)
      sctx->chlen = BUF_SIZE;
    else
      sctx->chlen = rctx->max - rctx->start + rctx->end;

    edmsg("ClientHello Length: %d", sctx->chlen);
    sctx->ch = (uint8_t *)malloc(sctx->chlen);
    memset(sctx->ch, 0x0, sctx->chlen);

    if (rctx->end > rctx->start)
      memcpy(sctx->ch, rctx->buf + rctx->start, rctx->end - rctx->start);
    else
    {
      memcpy(sctx->ch, rctx->buf + rctx->start, rctx->max - rctx->start);
      memcpy(sctx->ch + rctx->max - rctx->start, rctx->buf, rctx->end);
    }
  }

  p = sctx->ch;
  if (sctx->chlen > 0)
  {
    edmsg("Verify Content Type: 0x%02x (Should be 0x16)", *p++);
    edmsg("Verify Version: 0x%02x%02x (Should be 0x0301)", *p++, *p++);
    PTR_TO_VAR_2BYTES(p, len);
    edmsg("Length: %d (Should be chlen - 5)", len);
    edmsg("Handshake Type: %d (Should be 1)", *p++);
  }

out:
  effinish();
  return 1;
}

int pre_write_operation(tls_context_record_t *sctx, cctx_t *cctx)
{
  efstart("sctx: %p, cctx: %p", sctx, cctx);
  const SSL *ssl = sctx->ssl;

  if (sctx->chlen < 0) goto out;

  if (SSL_check_fallback(ssl))
  {
  }
  else
  {
    sctx->chlen = -1;
    if (sctx->ch)
    {
      free(sctx->ch);
      sctx->ch = NULL;
    }
    goto out;
  }

  effinish("ret: 1");
  return 1;
out:
  effinish("ret: -1");
  return -1;
}

void set_fallback(tls_context_record_t *sctx, cctx_t *cctx)
{
  efstart("sctx: %p, cctx: %p", sctx, cctx);
  const SSL *ssl = sctx->ssl;
  const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
  buf_t *name;
  uint16_t port;
  name = NULL;
  
  // hostname length (1 byte) || hostname || port (2 bytes) 
  // || client hello length (2 bytes) || client hello
  name = init_memcpy_buf_mem(name, servername, strlen(servername));
  port = DEFAULT_PORT_NUMBER;

  uint8_t *p;
  p = cctx->arg;
  (*p++) = name->max;
  memcpy(p, name->data, name->max);
  p += name->max;
  VAR_TO_PTR_2BYTES(port, p);
  VAR_TO_PTR_2BYTES(sctx->chlen, p);
  memcpy(p, sctx->ch, sctx->chlen);
  p += sctx->chlen;
  cctx->alen = p - cctx->arg;

  cctx->flags = TA_EDGE_NXT_FALLBACK_INIT;

  effinish();
}

/*
void set_fallback_backend(struct cctx_st *cctx, struct fetch_record_st *record)
{
  FDEBUG("Start: set_fallback_backend: cctx: %p, record: %p", cctx, record);
  uint8_t *p;

  // hostname length (1 byte) || hostname || port (2 bytes) ||
  // ClientHello length (2 bytes) || ClientHello (chlen bytes)
  set_address(cctx, record->r->domain, DEFAULT_ORIGIN_PORT);
  p = cctx->arg + cctx->alen;
  VAR_TO_PTR_2BYTES(record->data->len, p);
  cctx->alen += 2;
  memcpy(p, record->data->data, record->data->len);
  cctx->alen += record->data->len;

  effinish();
}
*/
