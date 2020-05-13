/**
 * @file ta_buf.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define the buffer operation
 */

#ifndef __TA_BUF_OPS_H__
#define __TA_BUF_OPS_H__

#include "ta_buf.h"

static inline SEED_Result serialize(buf_t *buf, uint8_t *msg)
{
  fstart("buf: %p, msg: %p", buf, msg);
  uint8_t *p;
  p = msg;
  VAR_TO_PTR_2BYTES(buf->offset, p);
  memcpy(p, buf->data, buf->offset);

  ffinish();
  return SEED_SUCCESS;
}

static inline SEED_Result deserialize(buf_t **buf, uint8_t *msg)
{
  uint8_t *p;
  (*buf) = (buf_t *)malloc(sizeof(buf_t));
  if (!(*buf))
    goto err;
  p = msg;
  PTR_TO_VAR_2BYTES(p, (*buf)->offset);
  memcpy((*buf)->data, p, (*buf)->offset);
  return SEED_SUCCESS;

err:
  return SEED_ERROR_OUT_OF_MEMORY;
}

#endif /* __TA_BUF_OPS_H__ */
