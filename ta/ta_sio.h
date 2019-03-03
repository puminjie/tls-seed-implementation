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

#include <tee_api.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include "ta_defines.h"
#include "ta_tls_table.h"

#define SUCCESS 1
#define FAILURE -1

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

struct cmd_st
{
  uint8_t flags;
  uint8_t arg[CBUF_SIZE];
  uint32_t alen;
  uint32_t max;
};

TEE_Result execute_io(struct tls_context_record_st *sctx, struct bctx_st *rctx, 
    struct bctx_st *wctx);
int read_io(struct tls_context_record_st *sctx, struct bctx_st *rctx, 
    struct bctx_st *wctx);
int write_io(struct tls_context_record_st *sctx, struct bctx_st *rctx, 
    struct bctx_st *wctx);

#endif /* __TA_SIO_H__ */
