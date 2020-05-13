/**
 * @file sio.c
 * @author Hyunwoo Lee
 * @date 17 July 2018
 * @brief Implementation of I/O functions
 */

#include "ta_sio.h"

/**
 * @brief I/O function between the normal world and the secure world
 * @param ssl TLS context for this session
 * @param rctx Read buffer context
 * @param wctx Write buffer context
 * @return success/fail
 */
SEED_Result execute_io(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx)
{
  efstart("sctx: %p, rctx: %p, wctx: %p", sctx, rctx, wctx);
  BIO *bio;
  SSL *ssl;
  int32_t ret, tmp;
  uint8_t buf[BUF_SIZE];

  ssl = sctx->ssl;

  if (rctx->end != rctx->start || rctx->full == 1)
  {
    ret = 0;
    bio = SSL_get_rbio(ssl);
    if (rctx->end > rctx->start)
    {
      ret = BIO_write(bio, rctx->buf + rctx->start, rctx->end - rctx->start);
    }
    else
    {
      ret += BIO_write(bio, rctx->buf + rctx->start, rctx->max - rctx->start);
      ret += BIO_write(bio, rctx->buf, rctx->end);
    }
    rctx->start = rctx->end;
    rctx->full = 0;
    edmsg("get %d bytes from the normal world", ret);
  }

  bio = SSL_get_wbio(ssl);
  ret = BIO_read(bio, buf, BUF_SIZE);
  edmsg("Return after BIO_read: %d", ret);
  
  if (ret > 0)
  {
    if (wctx->end + ret > wctx->max)
    {
      tmp = wctx->max - wctx->end;
      memcpy(wctx->buf + wctx->end, buf, tmp);
      memcpy(wctx->buf, buf + tmp, ret - tmp);
    }
    else
    {
      memcpy(wctx->buf + wctx->end, buf, ret);
    }
    wctx->end = (wctx->end + ret) % (wctx->max);

    if (wctx->end == wctx->start)
      wctx->full = 1;

    edmsg("send %d bytes to the normal world", ret);
  }

  effinish();
  return SEED_SUCCESS;
}

int read_io(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx)
{
  efstart("sctx: %p, rctx: %p, wctx: %p", sctx, rctx, wctx);
  BIO *bio;
  SSL *ssl;
  int ret;

  ssl = sctx->ssl;
  ret = -1;

  if (rctx->end != rctx->start || rctx->full == 1)
  {
    ret = 0;
    bio = SSL_get_rbio(ssl);
    if (rctx->end > rctx->start)
    {
      ret = BIO_write(bio, rctx->buf + rctx->start, rctx->end - rctx->start);
    }
    else
    {
      ret += BIO_write(bio, rctx->buf + rctx->start, rctx->max - rctx->start);
      ret += BIO_write(bio, rctx->buf, rctx->end);
    }
    rctx->start = rctx->end;
    rctx->full = 0;
    edmsg("get %d bytes from the normal world", ret);
  }

  effinish();
  return ret;
}

int write_io(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx)
{
  efstart("sctx: %p, rctx: %p, wctx: %p", sctx, rctx, wctx);
  BIO *bio;
  SSL *ssl;
  int ret, tmp;
  uint8_t buf[BUF_SIZE];

  ssl = sctx->ssl;

  bio = SSL_get_wbio(ssl);
  ret = BIO_read(bio, buf, BUF_SIZE);
  edmsg("Return after BIO_read: %d", ret);
  
  if (ret > 0)
  {
    if (wctx->end + ret > wctx->max)
    {
      tmp = wctx->max - wctx->end;
      memcpy(wctx->buf + wctx->end, buf, tmp);
      memcpy(wctx->buf, buf + tmp, ret - tmp);
    }
    else
    {
      memcpy(wctx->buf + wctx->end, buf, ret);
    }
    wctx->end = (wctx->end + ret) % (wctx->max);

    if (wctx->end == wctx->start)
      wctx->full = 1;

    edmsg("send %d bytes to the normal world", ret);
  }

  effinish();
  return ret;
}

