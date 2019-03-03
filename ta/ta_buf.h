/**
 * @file ta_buf.h
 * @author Hyunwoo Lee
 * @date 1 Nov 2018
 * @brief This file is to define the buffer operation
 */

#ifndef __TA_BUF_H__
#define __TA_BUF_H__

#include <stdlib.h>
#include <tee_api.h>
#include "ta_defines.h"

struct buf_st
{
  uint8_t *data;
  uint16_t len;
  uint16_t max;
};

static inline struct buf_st *init_alloc_buf_mem(struct buf_st **buf, uint32_t len)
{
  (*buf) = (struct buf_st *)malloc(sizeof(struct buf_st));
  if (!(*buf))
    goto err;
  memset((*buf), 0x0, sizeof(struct buf_st));
  (*buf)->data = (uint8_t *)malloc(len + 1);
  if (!(*buf)->data)
    goto err;
  memset((*buf)->data, 0x0, len + 1);
  (*buf)->len = 0;
  (*buf)->max = len;
err:
  return (*buf);
}

static inline struct buf_st *init_memcpy_buf_mem(struct buf_st **buf, uint8_t *data, 
    uint32_t len)
{
  (*buf) = (struct buf_st *)malloc(sizeof(struct buf_st));
  if (!(*buf))
    goto err;
  memset((*buf), 0x0, sizeof(struct buf_st));
  (*buf)->data = (uint8_t *)malloc(len + 1);
  if (!(*buf)->data)
    goto err;
  memset((*buf)->data, 0x0, len + 1);
  memcpy((*buf)->data, data, len);
  (*buf)->len = len;
err:
  return (*buf);
}

static inline struct buf_st *init_buf_mem(struct buf_st **buf, uint8_t *data,
    uint32_t len)
{
  (*buf) = (struct buf_st *)malloc(sizeof(struct buf_st));
  if (!(*buf))
    goto err;
  (*buf)->data = data;
  (*buf)->len = len;
err:
  return (*buf);
}

static inline uint32_t update_buf_mem(struct buf_st *buf, uint32_t offset, 
    uint8_t *data, uint32_t len)
{
  memcpy(buf->data + offset, data, len);
  buf->len = len;

  return len;
}

static inline TEE_Result serialize(struct buf_st *buf, uint8_t *msg)
{
  uint8_t *p;
  p = msg;
  VAR_TO_PTR_2BYTES(buf->len, p);
  memcpy(p, buf->data, buf->len);

  return TEE_SUCCESS;
}

static inline TEE_Result deserialize(struct buf_st **buf, uint8_t *msg)
{
  uint8_t *p;
  (*buf) = (struct buf_st *)malloc(sizeof(struct buf_st));
  if (!(*buf))
    goto err;
  p = msg;
  PTR_TO_VAR_2BYTES(p, (*buf)->len);
  memcpy((*buf)->data, p, (*buf)->len);
  return TEE_SUCCESS;

err:
  return TEE_ERROR_OUT_OF_MEMORY;
}

static inline uint8_t *get_buf_data(struct buf_st *buf)
{
  if (!buf) goto err;
  if (!buf->data) goto err;

  return buf->data;

err:
  return NULL;
}

static inline uint16_t get_buf_len(struct buf_st *buf)
{
  if (!buf) goto err;
  if (!buf->data) goto err;

  return buf->len;

err:
  return -1;
}

static inline void free_buf(struct buf_st *buf)
{
  if (buf)
  {
    if (buf->data)
      free(buf->data);
    buf->len = 0;
    buf->data = NULL;
    free(buf);
    buf = NULL;
  }
}

#endif /* __TA_BUF_H__ */
