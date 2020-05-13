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
#include <cmds.h>
#include <debug.h>

#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */

#ifdef PLATFORM_OPTEE
  #include <tee_client_api.h>
  #include <ta_edge.h>
#endif /* PLATFORM_OPTEE */

#include <setting.h>

/**
 * @brief Data structure for read/write buffers
 */
typedef struct bctx_st
{
  uint8_t buf[BUF_SIZE];
  uint32_t start;
  uint32_t end;
  size_t max;
  uint8_t lock;
  uint32_t ip;
  uint16_t port;
  uint8_t full;
} bctx_t;

/**
 * @brief Data structure for command buffers
 */
typedef struct cctx_st
{
  uint8_t flags;
  uint8_t stage;
  uint8_t arg[CBUF_SIZE];
  uint32_t alen;
  uint32_t max;
  int resumption;
  int mode;
} cctx_t;

#ifdef PLATFORM_SGX
typedef struct smem_st
{
  int flags;
  size_t size;
  uint8_t *buffer;
} smem_t;
#endif /* PLATFORM_SGX */

typedef struct hiom_st
{
#ifdef PLATFORM_OPTEE
  TEEC_SharedMemory *rctx;  /**< Shared memory for read (outside->secure) buffer context **/
  TEEC_SharedMemory *wctx;  /**< Shared memory for write (secure->outside) buffer context **/
  TEEC_SharedMemory *cctx;  /**< Shared memory fore command (secure->outside) buffer context **/
#elif PLATFORM_SGX
  smem_t *rctx;
  smem_t *wctx;
  smem_t *cctx;
  void *logger;
#endif /* PLATFORM BUFFERS */
} hiom_t;

// In OPTEE, we use t for the shared memory context
// while in SGX, we use t for the time log structure
int init_iom(hiom_t **iom, void *t, int role);
void free_iom(hiom_t *iom);

#ifdef PLATFORM_OPTEE
void set_op(TEEC_Operation *op, hiom_t *iom, void *time_log);
#endif /* PLATFORM_OPTEE */
void set_client(hiom_t *iom, uint32_t ip, uint16_t port);
void set_resumption(hiom_t *iom, int resumption);
void set_mode(hiom_t *iom, int mode);

bctx_t *get_read_ctx(hiom_t *iom);
bctx_t *get_write_ctx(hiom_t *iom);
cctx_t *get_cmd_ctx(hiom_t *iom);
#if defined(PLATFORM_OPTEE) && defined(TIME_LOG)
log_t *get_time_log(TEEC_Operation *op);
#endif /* PLATFORM_OPTEE and TIME_LOG */

int forward_to_secure_world(hiom_t *iom, const unsigned char *buf, size_t len);
int forward_to_out_world(hiom_t *iom, unsigned char *buf, size_t len);
#endif /* __HIO_H__ */
