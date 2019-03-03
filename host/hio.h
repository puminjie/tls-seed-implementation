/**
 * @file io.h
 * @author Hyunwoo Lee
 * @date 17 July 2018
 * @brief This file contains data structures and signatures of functions for
 * shared memory I/O
 */

#ifndef __HIO_H__
#define __HIO_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef TIME_LOG
#include <openssl/logs.h>
#endif /* TIME_LOG */

#include <tee_client_api.h>
#include <ta_edge_cache.h>

#include "host_defines.h"

struct hiom_st
{
  TEEC_SharedMemory *rctx;  /**< Shared memory for read (outside->secure) buffer context **/
  TEEC_SharedMemory *wctx;  /**< Shared memory for write (secure->outside) buffer context **/
  TEEC_SharedMemory *cctx;  /**< Shared memory fore command (secure->outside) buffer context **/
};

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

/**
 * @brief Data structure for command buffers
 */
struct cmd_st
{
  uint8_t flags;
  uint8_t arg[BUF_SIZE];
  uint32_t alen;
  uint32_t max;
};

int init_iom(struct hiom_st **iom, TEEC_Context *tctx, int role);
void free_iom(struct hiom_st *iom, TEEC_Context *tctx);

void set_op(TEEC_Operation *op, struct hiom_st *iom, void *time_log);
void set_client(struct hiom_st *iom, uint32_t ip, uint16_t port);

struct bctx_st *get_read_ctx(struct hiom_st *iom);
struct bctx_st *get_write_ctx(struct hiom_st *iom);
struct cmd_st *get_cmd_ctx(struct hiom_st *iom);
#ifdef TIME_LOG
log_t *get_time_log(TEEC_Operation *op);
#endif /* TIME_LOG */

int forward_to_secure_world(void *ctx, const unsigned char *buf, size_t len);
int forward_to_out_world(void *ctx, unsigned char *buf, size_t len);
#endif /* __HIO_H__ */
