/**
 * @file hio.c
 * @author Hyunwoo Lee
 * @date 17 July 2018
 * @brief Implementation of I/O functions
 */

#include "hio.h"
//#include "log_client.h"

/**
 * @brief initialize a shared memory
 * @param ctx the context for TEE
 * @param shm the pointer to the shared memory object
 * @param size the size of the shared memory
 * @param flags the flags for the shared memory
 * @return Error code (1 for success, -1 for failure)
 */
int init_shared_memory(TEEC_Context *ctx, TEEC_SharedMemory *shm, 
    size_t size, uint32_t flags)
{
  int ret = FAILURE;

  memset(shm, 0, sizeof(TEEC_SharedMemory));
  shm->flags = flags;
  shm->size = size;
  shm->buffer = malloc(size);

  if (!(shm->buffer)) 
  {
    EDGE_LOG("Failed in malloc");
    goto err;
  }

  if (TEEC_RegisterSharedMemory(ctx, shm) != TEEC_SUCCESS)
  {
    EDGE_LOG("Failed to register shared memory");
    free(shm->buffer);
    goto err;
  }

  ret = SUCCESS;

err:
  return ret;
}

/**
 * @brief free a shared memory
 * @param ctx the context for TEE
 * @param shm the pointer to the shared memory object
 * @return Error code (1 for success, -1 for failure)
 */
void free_shared_memory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
  TEEC_ReleaseSharedMemory(shm);
  free(shm->buffer);
}

/**
 * @brief Initialize abstract I/O buffer
 * @param ctx the context of TEE
 * @param bctx_st the context of the buffer
 * @param bio the shared buffer
 * @return Error code (-1 for failed)
 */
int init_bio(TEEC_Context *ctx, TEEC_SharedMemory *bctx_st, uint32_t size)
{
  int ret;
  struct bctx_st *b;

  ret = init_shared_memory(ctx, bctx_st, sizeof(struct bctx_st), TEEC_MEM_INPUT | TEEC_MEM_OUTPUT);
  if (ret < 0) 
  {
    EDGE_LOG("Failed to initialize bctx_st");
    goto err;
  }

  b = (struct bctx_st *)(bctx_st->buffer);
  b->start = 0;
  b->end = 0;
  b->max = size;
  b->lock = 0;
  b->full = 0;

  return SUCCESS;

err:
  if (bctx_st->buffer) free_shared_memory(ctx, bctx_st);
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
int init_cmd(TEEC_Context *ctx, TEEC_SharedMemory *cctx, uint32_t size, int role)
{
  int ret;
  struct cmd_st *c;

  ret = init_shared_memory(ctx, cctx, sizeof(struct cmd_st), TEEC_MEM_INPUT | TEEC_MEM_OUTPUT);
  if (ret < 0) 
  {
    EDGE_LOG("Failed to initialize bctx_st");
    goto err;
  }

  c = (struct cmd_st *)(cctx->buffer);

  if (role == INITIALIZER)
    c->flags = TA_EDGE_CACHE_INIT_INITIALIZER;
  else if (role == FRONTEND)
    c->flags = TA_EDGE_CACHE_INIT_FRONTEND;
  else if (role == BACKEND)
    c->flags = TA_EDGE_CACHE_INIT_BACKEND;
  else if (role == FILE_IO)
    c->flags = TA_EDGE_CACHE_INIT_FILE_IO;
  else
  {
    EDGE_MSG("Error in setting command context");
    abort();
  }

  c->alen = 0;
  c->max = size;

  return SUCCESS;

err:
  if (cctx->buffer) free_shared_memory(ctx, cctx);
  return FAILURE;
}

/**
 * @brief Initialize I/O module
 * @param iom I/O module to be initialized
 * @param tctx the context of TEE
 * @param role the role of I/O module holder (initializer / frontend / backend)
 * @return Error code (-1 for failed)
 */
int init_iom(struct hiom_st **iom, TEEC_Context *tctx, int role)
{
  int ret;

  (*iom) = (struct hiom_st *)malloc(sizeof(struct hiom_st));
  (*iom)->rctx = (TEEC_SharedMemory *)malloc(sizeof(TEEC_SharedMemory));
  (*iom)->wctx = (TEEC_SharedMemory *)malloc(sizeof(TEEC_SharedMemory));
  (*iom)->cctx = (TEEC_SharedMemory *)malloc(sizeof(TEEC_SharedMemory));

  ret = init_bio(tctx, (*iom)->rctx, BUF_SIZE);
  if (ret < 0)
  {
    EDGE_LOG("Error in initializing read bio");
    goto err;
  }

  ret = init_bio(tctx, (*iom)->wctx, BUF_SIZE);
  if (ret < 0)
  {
    EDGE_LOG("Error in initializing write bio");
    goto err;
  }

  ret = init_cmd(tctx, (*iom)->cctx, CBUF_SIZE, role);
  if (ret < 0)
  {
    EDGE_LOG("Error in initializing command bio");
    goto err;
  }

  return ret;
err:
  EDGE_LOG("Error happened");
  free_iom((*iom), tctx);
  return ret;
}

/**
 * @brief Set TEEC_Operation
 * @param op pointer to TEEC_Operation
 * @param iom I/O module
 * @param time_log log buffer (if logging is enabled)
 */
void set_op(TEEC_Operation *op, struct hiom_st *iom, void *time_log)
{
  memset(op, 0, sizeof(TEEC_Operation));
#ifdef TIME_LOG
  op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE,
      TEEC_MEMREF_WHOLE, TEEC_MEMREF_WHOLE, TEEC_MEMREF_TEMP_INOUT);
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
  op->params[3].tmpref.buffer = time_log;
  op->params[3].tmpref.size = sizeof(log_t) * NUM_OF_LOGS;
#endif /* TIME_LOG */
}

#ifdef TIME_LOG
log_t *get_time_log(TEEC_Operation *op)
{
  return (log_t *)op->params[3].tmpref.buffer;
}
#endif /* TIME_LOG */

/**
 * @brief Set Client's IP/Port in the I/O module
 * @param ip Client's IP address
 * @param port Client's port number
 */
void set_client(struct hiom_st *iom, uint32_t ip, uint16_t port)
{
  EDGE_LOG("Set client with IP: %u, Port: %u", ip, port);
  struct bctx_st *bctx;
  bctx = (struct bctx_st *)iom->rctx->buffer;
  bctx->ip = ip;
  bctx->port = port;
}

/**
 * @brief Get the read BIO context
 * @return Pointer to the read BIO context
 */
struct bctx_st *get_read_ctx(struct hiom_st *iom)
{
  return (struct bctx_st *) iom->rctx->buffer;
}

/**
 * @brief Get the write BIO context
 * @return Pointer to the write BIO context
 */
struct bctx_st *get_write_ctx(struct hiom_st *iom)
{
  return (struct bctx_st *) iom->wctx->buffer;
}

/**
 * @brief Get the command BIO context
 * @return Pointer to the cmd BIO context
 */
struct cmd_st *get_cmd_ctx(struct hiom_st *iom)
{
  return (struct cmd_st *) iom->cctx->buffer;
}

/**
 * @brief Free I/O module
 * @param iom I/O module
 * @param 
 */
void free_iom(struct hiom_st *iom, TEEC_Context *ctx)
{
  if (iom)
  {
    if (iom->rctx)
    {
      free_shared_memory(ctx, iom->rctx);
      iom->rctx = NULL;
    }

    if (iom->wctx)
    {
      free_shared_memory(ctx, iom->wctx);
      iom->wctx = NULL;
    }

    if (iom->cctx)
    {
      free_shared_memory(ctx, iom->cctx);
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
int forward_to_secure_world(void *ctx, const unsigned char *buf, size_t len)
{
  int tmp, sent = -1;
  struct hiom_st *iom = (struct hiom_st *)ctx;
  struct bctx_st *rctx = (struct bctx_st *)(iom->rctx->buffer);

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

  return sent;
}

/**
 * @brief Forward the received messages from the secure world for TLS-EC
 * @param ctx I/O structure (struct io *)
 * @param buf Buffer memory to receive the message
 * @param len Length of the buffer
 * @retrurn Length of the received message
 */
int forward_to_out_world(void *ctx, unsigned char *buf, size_t len)
{
  int tmp, recv = -1;
  struct hiom_st *iom = (struct hiom_st *)ctx;
  struct bctx_st *wctx = (struct bctx_st *)(iom->wctx->buffer);

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

  return recv;
}
