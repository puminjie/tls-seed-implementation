/**
 * @file sio.h
 * @author Hyunwoo Lee
 * @date 17 July 2018
 * @brief This file contains data structures and signatures of functions for
 * shared memory I/O
 */

#ifndef __TA_SIO_H__
#define __TA_SIO_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <debug.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "ta_types.h"
#include "ta_defines.h"
#include "ta_tls_table.h"

/**
 * @brief Data structure for read/write buffers
 */
struct bctx_st
{
  uint8_t buf[BUF_SIZE];
  uint32_t start;
  uint32_t end;
  size_t max;
  uint8_t lock;
  uint32_t ip;
  uint16_t port;
  uint8_t full;
};

struct cctx_st
{
  uint8_t flags;
  uint8_t stage;
  uint8_t arg[CBUF_SIZE];
  uint32_t alen;
  uint32_t max;
  int resumption;
  int mode;
};

#ifdef PLATFORM_SGX
struct smem_st
{
  int flags;
  size_t size;
  uint8_t *buffer;
};

struct siom_st
{
  smem_t *rctx;
  smem_t *wctx;
  smem_t *cctx;
  void * logger;
};
#endif /* PLATFORM_SGX */

SEED_Result execute_io(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx);
int read_io(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx);
int write_io(tls_context_record_t *sctx, bctx_t *rctx, bctx_t *wctx);

#endif /* __TA_SIO_H__ */
