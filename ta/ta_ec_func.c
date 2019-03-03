#include "ta_ec_func.h"
#include "ta_buf.h"

TEE_Result set_address(struct cmd_st *cctx, struct buf_st *name, uint16_t port)
{
  // hostname length (1 byte) || hostname || port (2 bytes)
  uint8_t hlen;
  uint8_t *p;
  p = cctx->arg;
  (*p++) = name->len;
  TEE_MemMove(p, name->data, name->len);
  p += name->len;
  VAR_TO_PTR_2BYTES(port, p);
  cctx->alen = p - cctx->arg;

  return TEE_SUCCESS;
}

int get_address(struct cmd_st *cctx, struct buf_st **name, uint16_t *port)
{
  uint8_t hlen;
  uint8_t *p;
  p = cctx->arg;
  hlen = (*p++);
  (*name) = init_memcpy_buf_mem(name, p, hlen);
  p += hlen;
  if (port)
    PTR_TO_VAR_2BYTES(p, (*port));

  return hlen;
}
