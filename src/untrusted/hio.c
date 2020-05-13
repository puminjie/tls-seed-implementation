/**
 * @file hio.c
 * @author Hyunwoo Lee
 * @date 17 July 2018
 * @brief Implementation of I/O functions
 */

#include "hio.h"
#include <debug.h>
#include <assert.h>
#ifdef TIME_LOG
  #include <openssl/logger.h>
#endif /* TIME_LOG */

/**
 * @brief initialize a shared memory
 * @param ctx the context for TEE
 * @param shm the pointer to the shared memory object
 * @param size the size of the shared memory
 * @param flags the flags for the shared memory
 * @return Error code (1 for success, -1 for failure)
 */
int init_shared_memory(void *c, void *s, size_t size, uint32_t flags)
{
  fstart("ctx: %p, s: %p, size: %lu, flags: %d", c, s, size, flags);

  int ret, sz;
#ifdef PLATFORM_OPTEE
  TEEC_Context *ctx;
  TEEC_SharedMemory *shm;
#elif PLATFORM_SGX
  smem_t *shm;
#else
  eemsg("Invalid platform");
  abort();
#endif /* PLATFORM */

  ret = FAILURE;
#ifdef PLATFORM_OPTEE
  ctx = (TEEC_Context *)c;
  shm = (TEEC_SharedMemory *)s;
  sz = sizeof(TEEC_SharedMemory);
#elif PLATFORM_SGX
  shm = (smem_t *)s;
  sz = sizeof(smem_t);
#endif /* PLATFORM */

  memset(shm, 0, sz);
  shm->flags = flags;
  shm->size = size;
  shm->buffer = malloc(size);

  if (!(shm->buffer)) 
  {
    eemsg("Failed in malloc");
    goto err;
  }

#ifdef PLATFORM_OPTEE
  if (TEEC_RegisterSharedMemory(ctx, shm) != TEEC_SUCCESS)
  {
    eemsg("Failed to register shared memory");
    free(shm->buffer);
    goto err;
  }
#endif /* PLATFORM_OPTEE */

  ret = SUCCESS;

err:
  ffinish();
  return ret;
}

/**
 * @brief free a shared memory
 * @param ctx the context for TEE
 * @param shm the pointer to the shared memory object
 * @return Error code (1 for success, -1 for failure)
 */
void free_shared_memory(void *s)
{
  fstart("s: %p", s);
  assert(s != NULL);

#ifdef PLATFORM_OPTEE
  TEEC_SharedMemory *shm;
#elif PLATFORM_SGX
  smem_t *shm;
#else
  emsg("Invalid platform");
  abort();
#endif /* PLATFORM BUFFERS */

#ifdef PLATFORM_OPTEE
  shm = (TEEC_SharedMemory *)s;
#elif PLATFORM_SGX
  shm = (smem_t *)s;
#endif /* PLATFORM */

  if (shm)
  {
#ifdef PLATFORM_OPTEE
    TEEC_ReleaseSharedMemory(shm);
#endif /* PLATFORM_OPTEE */
    if (shm->buffer)
    {
      shm->buffer = NULL;
      free(shm->buffer);
    }
    free(shm);
  }
  ffinish();
}

/**
 * @brief Initialize abstract I/O buffer
 * @param ctx the context of TEE
 * @param bctx_st the context of the buffer
 * @param bio the shared buffer
 * @return Error code (-1 for failed)
 */
int init_bio(void *c, void *s, size_t size)
{
  fstart("c: %p, s: %p", c, s);
  int ret, sz, flags;
  bctx_t *b;
#ifdef PLATFORM_OPTEE
  TEEC_Context *ctx;
  TEEC_SharedMemory *shm;
#elif PLATFORM_SGX
  void *ctx;
  smem_t *shm;
#else
  emsg("Invalid platform");
  abort();
#endif /* PLATFORM BUFFERS */

  ctx = NULL;
  shm = NULL;

#ifdef PLATFORM_OPTEE
  ctx = (TEEC_Context *)c;
  shm = (TEEC_SharedMemory *)s;
  flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
#elif PLATFORM_SGX
  shm = (smem_t *)s;
  flags = 0;
#endif /* PLATFORM BUFFERS */

  sz = sizeof(bctx_t);
  ret = init_shared_memory(ctx, shm, sz, flags);
  if (ret < 0) 
  {
    emsg("Failed to initialize the shared memory");
    goto err;
  }

  b = (bctx_t *)(shm->buffer);
  b->start = 0;
  b->end = 0;
  b->max = size;
  b->lock = 0;
  b->full = 0;

  ffinish();
  return SUCCESS;

err:
  if (shm && shm->buffer) free_shared_memory(shm);
  ffinish();
  return FAILURE;
}

/**
 * @brief Initialize command I/O buffer
 * @param ctx the context of TEE
 * @param cctx the context of the command buffer
 * @param size the size of the buffer
 * @param role the role of the context holder (initializer, frontend, backend)
 * @return Error code (-1 for failed)
 */
int init_cmd(void *c, void *s, size_t size, int role)
{
  fstart("c: %p, s: %p, size: %lu, role: %d", c, s, size, role);
  int ret, sz, flags;
  cctx_t *b;
#ifdef PLATFORM_OPTEE
  TEEC_Context *ctx;
  TEEC_SharedMemory *shm;
#elif PLATFORM_SGX
  void *ctx;
  smem_t *shm;
#else
  emsg("Invalid platform");
  abort();
#endif /* PLATFORM BUFFERS */

  ctx = NULL;
  shm = NULL;

#ifdef PLATFORM_OPTEE
  ctx = (TEEC_Context *)c;
  shm = (TEEC_SharedMemory *)s;
  flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
#elif PLATFORM_SGX
  shm = (smem_t *)s;
  flags = 0;
#endif /* PLATFORM BUFFERS */

  sz = sizeof(cctx_t);
  ret = init_shared_memory(ctx, shm, sz, flags);
  if (ret < 0) 
  {
    emsg("Failed to initialize the command context");
    goto err;
  }

  b = (cctx_t *)(shm->buffer);

  if (role == INITIALIZER)
    b->flags = TA_EDGE_INIT_INITIALIZER;
  else if (role == FRONTEND)
    b->flags = TA_EDGE_INIT_FRONTEND;
  else if (role == BACKEND)
    b->flags = TA_EDGE_INIT_BACKEND;
  else
  {
    emsg("Error in setting command context");
    abort();
  }

  b->alen = 0;
  b->max = size;

  ffinish();
  return SUCCESS;

err:
  if (shm && shm->buffer) free_shared_memory(shm);
  ffinish();
  return FAILURE;
}

/**
 * @brief Initialize I/O module
 * @param iom I/O module to be initialized
 * @param tctx the context of TEE
 * @param role the role of I/O module holder (initializer / frontend / backend)
 * @return Error code (-1 for failed)
 */
int init_iom(hiom_t **iom, void *t, int role)
{
  fstart("iom: %p, t: %p, role: %d", iom, t, role);
  assert(iom != NULL);
  int ret;
#ifdef PLATFORM_OPTEE
  TEEC_Context *tctx;
#elif PLATFORM_SGX
  void *tctx;
#endif /* PLATFORM CONTEXT */

  (*iom) = (hiom_t *)malloc(sizeof(hiom_t));

#ifdef PLATFORM_OPTEE
  tctx = (TEEC_Context *)t;
  (*iom)->rctx = (TEEC_SharedMemory *)malloc(sizeof(TEEC_SharedMemory));
  (*iom)->wctx = (TEEC_SharedMemory *)malloc(sizeof(TEEC_SharedMemory));
  (*iom)->cctx = (TEEC_SharedMemory *)malloc(sizeof(TEEC_SharedMemory));
#elif PLATFORM_SGX
  tctx = NULL;
  (*iom)->rctx = (smem_t *)malloc(sizeof(smem_t));
  (*iom)->wctx = (smem_t *)malloc(sizeof(smem_t));
  (*iom)->cctx = (smem_t *)malloc(sizeof(smem_t));
  (*iom)->logger = t;
#else
  emsg("Invalid platform");
  abort();
#endif /* PLATFORM BUFFERS */

  ret = init_bio(tctx, (*iom)->rctx, BUF_SIZE);
  if (ret < 0)
  {
    emsg("Error in initializing read bio");
    goto err;
  }

  ret = init_bio(tctx, (*iom)->wctx, BUF_SIZE);
  if (ret < 0)
  {
    emsg("Error in initializing write bio");
    goto err;
  }

  ret = init_cmd(tctx, (*iom)->cctx, CBUF_SIZE, role);
  if (ret < 0)
  {
    emsg("Error in initializing command bio");
    goto err;
  }
  ffinish("ret: %d", ret);
  return ret;
err:
  eemsg("Error happened");
  free_iom(*iom);
  ffinish("ret: %d", ret);
  return ret;
}

#ifdef PLATFORM_OPTEE
/**
 * @brief Set TEEC_Operation
 * @param op pointer to TEEC_Operation
 * @param iom I/O module
 * @param time_log log buffer (if logging is enabled)
 */
void set_op(TEEC_Operation *op, hiom_t *iom, void *logger)
{
  fstart("op: %p, iom: %p, logger: %p", op, iom, logger);
  memset(op, 0, sizeof(TEEC_Operation));

  if (iom)
  {
#ifdef TIME_LOG
    if (logger)
    {
      op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
          TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INOUT);
    }
    else
    {
      op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
          TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE);
    }
#else
    op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
        TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_NONE);
#endif /* TIME_LOG */
    // Read buffer (From Outside to Secure World)
    op->params[0].memref.parent = iom->rctx;
    op->params[0].memref.size = iom->rctx->size;

    // Write buffer (From Secure World to Outside)
    op->params[1].memref.parent = iom->wctx;
    op->params[1].memref.size = iom->wctx->size;

    // Command buffer
    op->params[2].memref.parent = iom->cctx;
    op->params[2].memref.size = iom->cctx->size;

#ifdef TIME_LOG
    // Log buffer
    if (logger)
    {
      op->params[3].tmpref.buffer = logger;
      op->params[3].tmpref.size = sizeof(logger_t);
    }
#endif /* TIME_LOG */
  }
  else
  {
    op->paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  }
  ffinish();
}

#ifdef TIME_LOG
log_t *get_time_log(TEEC_Operation *op)
{
  return (log_t *)op->params[3].tmpref.buffer;
}
#endif /* TIME_LOG */
#endif /* PLATFORM_OPTEE */

/**
 * @brief Set Client's IP/Port in the I/O module
 * @param ip Client's IP address
 * @param port Client's port number
 */
void set_client(hiom_t *iom, uint32_t ip, uint16_t port)
{
  fstart("iom: %p, ip: %d, port: %d", iom, ip, port);
  bctx_t *bctx;

  bctx = (bctx_t *)iom->rctx->buffer;
  bctx->ip = ip;
  bctx->port = port;
  ffinish();
}

void set_resumption(hiom_t *iom, int resumption)
{
  fstart("iom: %p, resumption: %d", iom, resumption);
  cctx_t *cctx; 
  cctx = get_cmd_ctx(iom);
  cctx->resumption = resumption;
  ffinish();
}

void set_mode(hiom_t *iom, int mode)
{
  fstart("iom: %p, mode: %d", iom, mode);
  cctx_t *cctx; 
  cctx = get_cmd_ctx(iom);
  cctx->mode = mode;
  ffinish();
}

/**
 * @brief Get the read BIO context
 * @return Pointer to the read BIO context
 */
bctx_t *get_read_ctx(hiom_t *iom)
{
  return (bctx_t *) iom->rctx->buffer;
}

/**
 * @brief Get the write BIO context
 * @return Pointer to the write BIO context
 */
bctx_t *get_write_ctx(hiom_t *iom)
{
  return (bctx_t *) iom->wctx->buffer;
}

/**
 * @brief Get the command BIO context
 * @return Pointer to the cmd BIO context
 */
cctx_t *get_cmd_ctx(hiom_t *iom)
{
  return (cctx_t *) iom->cctx->buffer;
}

/**
 * @brief Free I/O module
 * @param iom I/O module
 * @param 
 */
void free_iom(hiom_t *iom)
{
  if (iom)
  {
    if (iom->rctx)
    {
      free_shared_memory(iom->rctx);
      iom->rctx = NULL;
    }

    if (iom->wctx)
    {
      free_shared_memory(iom->wctx);
      iom->wctx = NULL;
    }

    if (iom->cctx)
    {
      free_shared_memory(iom->cctx);
      iom->cctx = NULL;
    }

    free(iom);
    iom = NULL;
  }
}

/**
 * @brief Forward the received messages to the secure world for TLS-EC
 * @param ctx I/O structure (struct io *)
 * @param buf Buffer memory containing the message to be sent
 * @param len Length of the message to be sent
 * @return Length of the sent message
 */
int forward_to_secure_world(hiom_t *iom, const unsigned char *buf, size_t len)
{
  fstart("iom: %p, buf: %p, len: %lu", iom, buf, len);
  assert(iom != NULL);
  assert(buf != NULL);
  assert(len > 0);

  int tmp, sent = -1;
  bctx_t *rctx = (bctx_t *)(iom->rctx->buffer);

  if (!(rctx->lock))
  {
    rctx->lock = 1;
    if (rctx->end + len > rctx->max)
    {
      if ((rctx->end + len - rctx->max) <= rctx->start)
        sent = len;
      else
        sent = -1;
    }
    else
      sent = len;

    if (sent > 0)
    {
      if (sent == rctx->max)
        rctx->full = 1;
      if (rctx->end + sent > rctx->max)
      {
        tmp = rctx->max - rctx->end;
        memcpy(rctx->buf + rctx->end, buf, tmp);
        memcpy(rctx->buf, buf + tmp, sent - tmp);
      }
      else
      {
        memcpy(rctx->buf + rctx->end, buf, sent);
      }
      rctx->end = (rctx->end + sent) % (rctx->max);
    }
    rctx->lock = 0;
  }

  ffinish("sent: %d", sent);
  return sent;
}

/**
 * @brief Forward the received messages from the secure world for TLS-EC
 * @param ctx I/O structure (struct io *)
 * @param buf Buffer memory to receive the message
 * @param len Length of the buffer
 * @retrurn Length of the received message
 */
int forward_to_out_world(hiom_t *iom, unsigned char *buf, size_t len)
{
  fstart("iom: %p, buf: %p, len: %lu", iom, buf, len);
  assert(iom != NULL);
  assert(buf != NULL);
  assert(len > 0);

  int tmp, recv = -1;
  bctx_t *wctx = (bctx_t *)(iom->wctx->buffer);

  if (!(wctx->lock))
  {
    wctx->lock = 1;
    if (wctx->start == wctx->end)
    {
      if (wctx->full == 1)
        recv = len;
      else 
        recv = -1;

      wctx->full = 0;
    }
    else if (wctx->start < wctx->end)
    {
      if ((wctx->end - wctx->start) < len)
        recv = wctx->end - wctx->start;
      else
        recv = len;
    }
    else if (wctx->start > wctx->end)
    {
      if ((wctx->end + wctx->max - wctx->start) < len)
        recv = wctx->end + wctx->max - wctx->start;
      else
        recv = len;
    }

    if (recv > 0)
    {
      if (wctx->start < wctx->end)
      {
        memcpy(buf, wctx->buf + wctx->start, recv);
      }
      else
      {
        tmp = wctx->max - wctx->start;
        memcpy(buf, wctx->buf + wctx->start, tmp);
        memcpy(buf + tmp, wctx->buf, recv - tmp);
      }
      wctx->start = (wctx->start + recv) % (wctx->max);
    }
    wctx->lock = 0;
  }

  ffinish("recv: %d", recv);
  return recv;
}
